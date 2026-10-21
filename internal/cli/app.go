package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func newDeploy(a *app) *cobra.Command {
	var (
		planOnly        bool
		restorePostgres string
		restoreVolumes  []string
		to              string
		manifestName    string
	)
	cmd := &cobra.Command{
		Use:   "deploy <source-dir>",
		Short: "Deploy the app in a source directory: build, start, check, switch the edge, retire the old revision.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			source, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			selected, err := manifest.ResolveFileName(source, manifestName)
			if err != nil {
				return err
			}
			m, err := manifest.LoadFile(source, selected)
			if err != nil {
				return err
			}
			if to != "" {
				if planOnly || a.digest != "" {
					return fmt.Errorf("--plan and --digest don't cross the wire; run helios deploy --plan on the machine, or send the tree with --to and answer there")
				}
				if restorePostgres != "" || len(restoreVolumes) > 0 {
					return fmt.Errorf("restores read files on the machine; run them there")
				}
				if selected != manifest.FileName && selected != manifest.LegacyFileName {
					return fmt.Errorf("--to sends a default manifest (helios.yaml or bedrock.yaml); deploy another manifest on the machine")
				}
				return deployTo(cmd.Context(), a, source, m.App, to)
			}
			in := apps.DeployInput{Source: source, Revision: apps.NewRevision(time.Now())}
			// Keep an explicit selection explicit, including either default filename.
			// The implicit selection is bound by the source capture, including filenames.
			in.Manifest = manifestName
			if restorePostgres != "" {
				if in.Restore.Postgres, err = filepath.Abs(restorePostgres); err != nil {
					return err
				}
			}
			for _, rv := range restoreVolumes {
				name, file, ok := strings.Cut(rv, "=")
				if !ok {
					return fmt.Errorf("--restore-volume wants name=file, not %q", rv)
				}
				if in.Restore.Volumes == nil {
					in.Restore.Volumes = map[string]string{}
				}
				if in.Restore.Volumes[name], err = filepath.Abs(file); err != nil {
					return err
				}
			}
			return a.operate(cmd.Context(), apps.DeployKind, in, planOnly)
		},
	}
	cmd.Flags().StringVar(&restorePostgres, "restore-postgres", "", "a pg_dump file to load into the app's empty database first")
	cmd.Flags().StringArrayVar(&restoreVolumes, "restore-volume", nil, "name=file.tar.gz to unpack into an empty volume first")
	cmd.Flags().StringVar(&to, "to", "", "send the source to a machine over SSH, such as bedrock@203.0.113.7, and deploy it there ($BEDROCK_SSH replaces ssh)")
	cmd.Flags().StringVar(&manifestName, "manifest", "", "the manifest at the source's root (default: helios.yaml, or bedrock.yaml)")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

func newRun(a *app) *cobra.Command {
	var (
		secretNames []string
		stdin       bool
	)
	var planOnly bool
	cmd := &cobra.Command{
		Use:   "run <app> [workload] -- <command...>",
		Short: "Run a one-off command with a workload's image, environment, secrets and volumes.",
		Long: `Run a one-off command with a workload's image, environment, secrets and volumes.

--secret gives the command more of the app's secrets by name; their values
never leave the machine. --stdin hands this command's standard input to
the command, for a value that must appear in no argument, log or record:
the command then runs here, not in the daemon, and exits with the
command's own exit code.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash < 1 || dash > 2 || dash >= len(args) {
				return fmt.Errorf("give the app, optionally the workload, then -- and the command")
			}
			in := apps.RunInput{App: args[0], Workload: optional(args[:dash], 1), Command: args[dash:], Secrets: secretNames}
			if stdin {
				if planOnly {
					return fmt.Errorf("--stdin runs the command here; there is no plan to show")
				}
				return a.runHere(cmd.Context(), in)
			}
			// The command to run is spelled out in the arguments, so the
			// arguments are the approval and there is nothing a digest could
			// pin that they do not. --plan still shows it first.
			a.yes = true
			return a.operate(cmd.Context(), apps.RunKind, in, planOnly)
		},
	}
	cmd.Flags().StringArrayVar(&secretNames, "secret", nil, "give the command this secret of the app too (repeatable)")
	cmd.Flags().BoolVar(&stdin, "stdin", false, "pass standard input to the command; it runs in this process")
	cmd.Flags().BoolVar(&planOnly, "plan", false, "show what would run and change nothing")
	return cmd
}

// runHere runs a one-off command in this process with its standard input
// attached, and exits with the command's code.
func (a *app) runHere(ctx context.Context, in apps.RunInput) error {
	store, err := a.openState()
	if err != nil {
		return err
	}
	defer store.Close()
	rev, err := store.RevisionWithStatus(ctx, in.App, state.RevisionActive)
	if err != nil {
		return err
	}
	if rev == nil {
		return fmt.Errorf("%s isn't deployed", in.App)
	}
	workload, err := apps.RunWorkload(rev, in.Workload)
	if err != nil {
		return err
	}
	jobs := apps.NewJobs(store, a.secretsStore())
	code, err := jobs.RunWith(ctx, rev, workload, in.Command, apps.JobRun, apps.JobOptions{Secrets: in.Secrets, Stdin: os.Stdin}, a.stdout)
	if err != nil && code > 0 {
		// The command said why on its own output; its code is the answer.
		return quietError{code: code}
	}
	return err
}

func newJobs(a *app) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "jobs <app> [workload]",
		Short: "List recent cron runs and one-off commands.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			runs, err := store.JobRuns(cmd.Context(), args[0], optional(args, 1), limit)
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(runs)
			}
			if len(runs) == 0 {
				fmt.Fprintln(a.stdout, "no runs yet")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tWORKLOAD\tKIND\tSTARTED\tTOOK\tRESULT")
			for _, r := range runs {
				result := "running"
				took := ""
				if r.Kind == state.JobHold {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t\theld until %s: %s\n", r.ID, r.Workload, r.Kind, r.StartedAt.Local().Format("2006-01-02 15:04:05"), apps.OperatorTime(r.FinishedAt), r.Output)
					continue
				}
				if !r.FinishedAt.IsZero() {
					took = r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond).String()
					result = "ok"
					if r.Error != "" {
						result = r.Error
					}
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Workload, r.Kind, r.StartedAt.Local().Format("2006-01-02 15:04:05"), took, result)
			}
			return w.Flush()
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "how many runs to list")
	return cmd
}

func newPsql(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "psql <app> [-- psql arguments]",
		Short: "Open psql on the app's database.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appName := args[0]
			dockerBin, err := exec.LookPath("docker")
			if err != nil {
				return err
			}
			store, err := a.openState()
			if err != nil {
				return err
			}
			rev, err := store.RevisionWithStatus(cmd.Context(), appName, state.RevisionActive)
			store.Close()
			if err != nil {
				return err
			}
			if rev == nil {
				return fmt.Errorf("%s isn't deployed", appName)
			}
			var m manifest.Manifest
			if err := json.Unmarshal(rev.Manifest, &m); err != nil {
				return err
			}
			if m.PostgresVersion() == "" {
				return fmt.Errorf("%s has no database", appName)
			}
			values, _, err := a.secretsStore().LoadCurrent(appName)
			if err != nil {
				return err
			}
			password := values[apps.PostgresPasswordName]
			user, database := m.PostgresIdentity()
			// The password reaches psql through docker's environment,
			// never an argument anyone on the machine could read. A
			// terminal only when someone is typing: docker refuses -t
			// for a dump redirected in.
			argv := []string{"docker", "exec", "-i", "-e", "PGPASSWORD"}
			if a.tty && stdinIsTerminal() {
				argv = append(argv, "-t")
			}
			argv = append(argv, apps.PostgresContainer(appName), "psql", "-h", "127.0.0.1", "-U", user, "-d", database)
			argv = append(argv, args[1:]...)
			return a.runDataCommand(cmd.Context(), appName, dockerBin, argv[1:], append(os.Environ(), "PGPASSWORD="+password), os.Stdin)
		},
	}
}

func newRollback(a *app) *cobra.Command {
	var (
		planOnly    bool
		to          string
		restoreData string
	)
	cmd := &cobra.Command{
		Use:   "rollback <app>",
		Short: "Make the previous revision active again.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.RollbackKind, apps.RollbackInput{App: args[0], Revision: to, RestoreData: restoreData}, planOnly)
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "a specific revision instead of the previous one")
	cmd.Flags().StringVar(&restoreData, "restore-data", "", "replace live data with this exact retained checkpoint; discard writes since it was captured")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

// openState opens the store read-only for commands that only look.
func (a *app) openState() (*state.Store, error) {
	return state.Open(filepath.Join(a.stateDir, "state.db"))
}

func newPs(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "List apps, their workloads and what is running.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			active, err := store.ActiveRevisions(ctx)
			if err != nil {
				return err
			}
			engine, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer engine.Close()
			type row struct {
				App       string `json:"app"`
				Workload  string `json:"workload"`
				Revision  string `json:"revision"`
				Container string `json:"container,omitempty"`
				Status    string `json:"status"`
				Image     string `json:"image,omitempty"`
			}
			var rows []row
			for _, rev := range active {
				var m manifest.Manifest
				if err := json.Unmarshal(rev.Manifest, &m); err != nil {
					return err
				}
				for _, name := range m.WorkloadNames() {
					if kind := m.Workloads[name].Kind; kind == manifest.Cron || kind == manifest.Release {
						status := string(kind) + ", never run"
						if last, err := store.LastJobRun(ctx, rev.App, name); err == nil && last != nil {
							status = string(kind) + ", last run " + last.StartedAt.Local().Format("15:04:05")
							switch {
							case last.FinishedAt.IsZero():
								status += " running"
							case last.Error != "":
								status += " failed"
							default:
								status += " ok"
							}
						}
						if kind == manifest.Cron {
							if hold, err := apps.ActiveCronHold(ctx, store, rev.App, name, time.Now()); err == nil && hold != nil {
								status += ", held until " + apps.OperatorTime(hold.FinishedAt)
							}
						}
						rows = append(rows, row{rev.App, name, rev.ID, "", status, rev.Images[name]})
						continue
					}
					container := rev.Containers[name]
					status := "missing"
					if info, err := engine.Inspect(ctx, container); err == nil {
						status = info.Status
						if info.Health != "" {
							status += ", " + info.Health
						}
					}
					rows = append(rows, row{rev.App, name, rev.ID, container, status, rev.Images[name]})
				}
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(a.stdout, "no apps deployed yet")
			} else {
				w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "APP\tWORKLOAD\tREVISION\tSTATUS\tCONTAINER")
				for _, r := range rows {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.App, r.Workload, r.Revision, r.Status, r.Container)
				}
				w.Flush()
			}
			if unowned, err := engine.Unowned(ctx); err == nil && len(unowned) > 0 {
				fmt.Fprintf(a.stdout, "not managed by helios: %d container(s)\n", len(unowned))
			}
			return nil
		},
	}
}

func newLogs(a *app) *cobra.Command {
	var (
		follow        bool
		tail          string
		revision, job string
	)
	cmd := &cobra.Command{
		Use:   "logs <app> [workload]",
		Short: "Show a workload's output; the app's only workload when there is one.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if revision != "" && job != "" {
				return errors.New("use either --revision or --job")
			}
			if revision != "" || job != "" {
				return a.pastLogs(ctx, pastLogs{appName: args[0], workload: optional(args, 1), revision: revision, job: job, follow: follow, tail: tail})
			}
			container, err := a.resolveContainer(ctx, args[0], optional(args, 1))
			if err != nil {
				return err
			}
			engine, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer engine.Close()
			return engine.Logs(ctx, container, docker.LogOptions{Follow: follow, Tail: tail}, a.stdout)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep streaming")
	cmd.Flags().StringVar(&tail, "tail", "100", "how many lines to start with, or all")
	cmd.Flags().StringVar(&revision, "revision", "", "a revision's output, from the journal once its containers are gone")
	cmd.Flags().StringVar(&job, "job", "", "a job run's output, by the ID helios jobs shows")
	return cmd
}

func optional(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// resolveContainer finds the active container for an app's workload.
func (a *app) resolveContainer(ctx context.Context, appName, workload string) (string, error) {
	store, err := a.openState()
	if err != nil {
		return "", err
	}
	defer store.Close()
	rev, err := store.RevisionWithStatus(ctx, appName, state.RevisionActive)
	if err != nil {
		return "", err
	}
	if rev == nil {
		return "", fmt.Errorf("%s isn't deployed", appName)
	}
	if workload == "" {
		if len(rev.Containers) != 1 {
			names := make([]string, 0, len(rev.Containers))
			for n := range rev.Containers {
				names = append(names, n)
			}
			return "", fmt.Errorf("%s has several workloads; name one of %v", appName, names)
		}
		for _, c := range rev.Containers {
			return c, nil
		}
	}
	container, ok := rev.Containers[workload]
	if !ok {
		return "", fmt.Errorf("%s has no workload named %s", appName, workload)
	}
	return container, nil
}

func newRemove(a *app) *cobra.Command {
	var (
		planOnly      bool
		data          bool
		forgetSecrets bool
	)
	cmd := &cobra.Command{
		Use:   "remove <app>",
		Short: "Take an app off this machine. Its volumes, database and secrets stay unless asked.",
		Long: `Take an app off this machine. Its volumes, database and sealed secrets
stay unless asked, so it can be restored or deployed again with what it had.

--data removes them too, the secrets included. For an app that is no longer
on this machine, --data removes whatever it left behind: its sealed secrets,
volumes, database and networks. Its backups in the storage bucket stay, and
are the only way back.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.RemoveKind, apps.RemoveInput{App: args[0], Data: data, Secrets: forgetSecrets}, planOnly)
		},
	}
	cmd.Flags().BoolVar(&data, "data", false, "also remove the app's volumes, database and sealed secrets, or what a removed app left; only a backup brings them back")
	cmd.Flags().BoolVar(&forgetSecrets, "secrets", false, "also forget the app's sealed secrets, keeping its volumes and database")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}
