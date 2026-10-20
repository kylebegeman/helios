// Package cli builds the helios command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/daemon"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/ui"
	"github.com/kylebegeman/helios/internal/version"
)

// Main runs the command line with the given arguments and returns the
// process exit code. Output goes to stdout; errors go to stderr, once.
func Main(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root := newRoot(stdout, stderr)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		var quiet quietError
		if errors.As(err, &quiet) {
			return quiet.code
		}
		fmt.Fprintln(stderr, "helios:", err)
		return 1
	}
	return 0
}

// app holds what every command shares.
type app struct {
	stdout, stderr io.Writer
	// narrate is where an operation shows its plan, asks and reports its
	// steps: stdout, unless a command's own result owns stdout, as move
	// out's handoff does.
	narrate          io.Writer
	stateDir         string
	targetName       string
	targetsFile      string
	remoteStateFlags []string
	socket           string
	json             bool
	tty              bool
	yes              bool
	digest           string
}

func (a *app) renderer() *ui.Renderer { return ui.New(a.narrateTo(), a.tty, a.json) }

// narrateTo is where an operation's plan, prompt and steps go.
func (a *app) narrateTo() io.Writer {
	if a.narrate != nil {
		return a.narrate
	}
	return a.stdout
}

// prose is where a command's closing words go: stdout, or stderr under
// --json, which keeps stdout for the objects alone.
func (a *app) prose() io.Writer {
	if a.json {
		return a.stderr
	}
	return a.stdout
}

// runner returns a daemon client when a daemon answers on the socket, and
// otherwise the local kernel over the state directory.
func (a *app) runner(ctx context.Context, owner string) (api.Runner, error) {
	if a.socket != "" {
		client := api.Dial(a.socket)
		if client.Reachable(ctx) {
			return client, nil
		}
		client.Close()
	}
	store, err := state.Open(filepath.Join(a.stateDir, "state.db"))
	if err != nil {
		return nil, err
	}
	return &api.Local{Engine: kernel.New(store, daemon.Registry(store, a.secretsStore(), a.socket, a.stateDir), owner), Store: store}, nil
}

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	a := &app{stdout: stdout, stderr: stderr}
	if f, ok := stdout.(*os.File); ok {
		a.tty = ui.IsTerminal(f)
	}
	root := &cobra.Command{
		Use:           "helios",
		Short:         "One small program that runs your machines.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringVar(&a.stateDir, "state-dir", envOr("BEDROCK_STATE_DIR", defaultStateDir()), "where helios keeps its state")
	root.PersistentFlags().StringVar(&a.socket, "socket", envOr("BEDROCK_SOCKET", daemon.DefaultSocket), "the daemon's socket; the local kernel is used when nothing answers")
	root.PersistentFlags().BoolVar(&a.json, "json", false, "print JSON, one object per line")
	root.AddCommand(newVersion(a), newCapabilities(a), newInit(a), newCheck(a), newDoctor(a), newHost(a), newUpgrade(a), newDeploy(a), newRollback(a), newLs(a), newStatus(a), newExposure(a), newDNS(a), newEdge(a), newPs(a), newLogs(a), newExec(a), newGC(a), newLaunch(a), newMove(a), newPreview(a), newSecret(a), newIntegration(a), newRun(a), newJobs(a), newCron(a), newPsql(a), newBackup(a), newBackups(a), newDrill(a), newRestore(a), newRecover(a), newRehearse(a), newAlerts(a), newWatch(a), newPeer(a), newRemove(a), newGit(a), newReceive(a), newHistory(a), newKernel(a), newDaemon(a))
	configureTargets(root, a)
	return root
}

// quietError ends the program with a code, its message already shown.
type quietError struct{ code int }

func (q quietError) Error() string { return fmt.Sprintf("exit %d", q.code) }

// Helios and the compatibility entrypoint share the legacy storage layout.
// Prefer the new environment spelling; conflicts are rejected before execution.
func envOr(name, fallback string) string {
	if strings.HasPrefix(name, "BEDROCK_") {
		if v := os.Getenv("HELIOS_" + strings.TrimPrefix(name, "BEDROCK_")); v != "" {
			return v
		}
	}
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func validateEnvironmentAliases(cmd *cobra.Command) error {
	for _, setting := range []struct{ suffix, flag string }{
		{"STATE_DIR", "state-dir"}, {"SOCKET", "socket"}, {"TARGETS_FILE", "targets-file"}, {"BOOTSTRAP_DIR", "journal-dir"}, {"SSH", ""},
	} {
		if setting.flag != "" && cmd.Flags().Changed(setting.flag) {
			continue
		}
		current, legacy := "HELIOS_"+setting.suffix, "BEDROCK_"+setting.suffix
		a, b := os.Getenv(current), os.Getenv(legacy)
		if a != "" && b != "" && a != b {
			return fmt.Errorf("%s and %s conflict; set only one or give both the same value", current, legacy)
		}
	}
	return nil
}

// defaultStateDir is /var/lib/bedrock for root on Linux (the machines) and
// ~/.bedrock anywhere else (the Mac).
func defaultStateDir() string {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return daemon.DefaultStateDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".bedrock"
	}
	return filepath.Join(home, ".bedrock")
}

func newVersion(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of this build.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := version.Current()
			if a.json {
				return info.WriteJSON(a.stdout)
			}
			_, err := fmt.Fprintln(a.stdout, info)
			return err
		},
	}
}
