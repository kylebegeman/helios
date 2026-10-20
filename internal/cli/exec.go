package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/ui"
)

// execInteractiveCapability is what a target needs to be told to read
// its standard input; a target without it always reads it.
const execInteractiveCapability = "exec.interactive.v1"

// stdinIsTerminal reports whether someone may be typing at this process.
var stdinIsTerminal = func() bool { return ui.IsTerminal(os.Stdin) }

func newExec(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec <app> [workload] -- <command...>",
		Short: "Run a command inside a workload's container.",
		Long: `Run a command inside a workload's container.

At a terminal, the command reads what is typed there. Anywhere else, as in
a script piped to bash -s, the command's standard input is empty, so the
script keeps its next lines. -i hands the command this standard input.

  helios exec site -- sh
  helios exec -i site -- sh -c 'cat > /data/import.csv' < import.csv`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash < 1 || dash > 2 {
				return fmt.Errorf("give the app, optionally the workload, then -- and the command")
			}
			target, command := args[:dash], args[dash:]
			if len(command) == 0 {
				return fmt.Errorf("nothing to run after --")
			}
			container, err := a.resolveContainer(cmd.Context(), target[0], optional(target, 1))
			if err != nil {
				return err
			}
			dockerBin, err := exec.LookPath("docker")
			if err != nil {
				return err
			}
			argv := []string{"docker", "exec"}
			var stdin io.Reader
			if execReadsStdin(cmd) {
				argv, stdin = append(argv, "-i"), os.Stdin
				// docker's -t is the command's input as well as its output:
				// docker refuses -i -t when this stdin is no terminal, and -t
				// without -i leaves the command waiting on input nobody can
				// type, where it would otherwise read an empty input and go on.
				if a.tty && stdinIsTerminal() {
					argv = append(argv, "-t")
				}
			}
			argv = append(append(argv, container), command...)
			return a.runDataCommand(cmd.Context(), target[0], dockerBin, argv[1:], os.Environ(), stdin)
		},
	}
	cmd.Flags().BoolP("interactive", "i", false, "keep standard input open for the command, as docker exec -i does")
	return cmd
}

// execReadsStdin reports whether exec hands the command this standard
// input: when -i asks, or when someone may be typing it. Otherwise a
// script piped to a shell would lose the lines after the exec.
func execReadsStdin(cmd *cobra.Command) bool {
	interactive, _ := cmd.Flags().GetBool("interactive")
	return interactive || stdinIsTerminal()
}

// Keep the shared backup lock alive for the full operator command. A nil
// stdin gives the command an empty input.
func (a *app) runDataCommand(ctx context.Context, appName, binary string, args, env []string, stdin io.Reader) error {
	unlock, err := apps.AcquireDataAccess(ctx, filepath.Join(a.stateDir, "state.db"), appName)
	if err != nil {
		return err
	}
	defer unlock()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.Env = stdin, a.stdout, a.stderr, env
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return quietError{code: exit.ExitCode()}
	}
	return err
}
