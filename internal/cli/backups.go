package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func newBackup(a *app) *cobra.Command {
	var planOnly bool
	cmd := &cobra.Command{
		Use:   "backup <app>",
		Short: "Back the app's data up to its bucket now. \"helios\" backs up the machine's own state.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.BackupKind, apps.BackupInput{App: backupAppName(args[0])}, planOnly)
		},
	}
	a.mutatingFlags(cmd, &planOnly)
	cmd.AddCommand(newBackupExtract(a))
	return cmd
}

func newDrill(a *app) *cobra.Command {
	var (
		planOnly bool
		snapshot string
		skipNext bool
		reason   string
	)
	cmd := &cobra.Command{
		Use:   "drill <app>",
		Short: "Prove a backup: restore it beside the app, start the app on it, check, clean up. Or skip the next scheduled one.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if skipNext {
				if snapshot != "" {
					return errors.New("--skip-next skips the next scheduled drill, which takes no --snapshot")
				}
				return a.operate(cmd.Context(), apps.DrillSkipKind, apps.DrillSkipInput{App: args[0], Reason: reason, By: requester()}, planOnly)
			}
			if reason != "" {
				return errors.New("--reason goes with --skip-next")
			}
			return a.operate(cmd.Context(), apps.DrillKind, apps.DrillInput{App: args[0], Snapshot: snapshot}, planOnly)
		},
	}
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "a snapshot id instead of the latest")
	cmd.Flags().BoolVar(&skipNext, "skip-next", false, "skip the next scheduled drill instead of running one; again before it, the one after")
	cmd.Flags().StringVar(&reason, "reason", "", "why the drill is skipped; required with --skip-next")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

// requester is who asks for a skip or a hold, for its plan and receipt: the
// person behind sudo, or else the account running the command.
func requester() string {
	if name := os.Getenv("SUDO_USER"); name != "" {
		return name
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func newRestore(a *app) *cobra.Command {
	var (
		planOnly bool
		snapshot string
	)
	cmd := &cobra.Command{
		Use:   "restore <app>",
		Short: "Bring an app's data back from its bucket onto this machine, before deploying it here.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.RestoreKind, apps.RestoreInput{App: args[0], Snapshot: snapshot}, planOnly)
		},
	}
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "a snapshot id instead of the latest")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

func newBackups(a *app) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "backups [app]",
		Short: "List backups, drills and restores, newest first.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			runs, err := store.BackupRuns(cmd.Context(), backupAppName(optional(args, 0)), "", limit)
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(runs)
			}
			if len(runs) == 0 {
				fmt.Fprintln(a.stdout, "no backups yet")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "APP\tKIND\tSTARTED\tTOOK\tRESULT\tSNAPSHOT\tDETAIL")
			for _, r := range runs {
				result, took, detail := "running", "", r.Detail
				switch {
				case r.Kind == state.BackupRunDrillSkip:
					result, detail = "skipped", "skipped by operator: "+r.Detail
				case r.Finished():
					took = r.FinishedAt.Sub(r.StartedAt).Round(time.Second).String()
					if r.OK {
						result = "ok"
					} else {
						result, detail = "FAILED", r.Error
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.App, r.Kind, r.StartedAt.Local().Format("2006-01-02 15:04:05"), took, result, orDash(r.Snapshot), detail)
			}
			return w.Flush()
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "how many to list")
	return cmd
}

// The machine backup keeps its existing sealed namespace and repository.
func backupAppName(name string) string {
	if name == "helios" {
		return manifest.ReservedApp
	}
	return name
}

// newBackupExtract deliberately uses the new binary's local kernel. An existing
// daemon can remain on v0.7.17; no upgrade or remote dispatch is involved.
func newBackupExtract(a *app) *cobra.Command {
	var planOnly bool
	var in apps.BackupExtractInput
	cmd := &cobra.Command{
		Use: "extract <app>", Short: "Extract exact backup files into new private staging, using --socket=.",
		Long: "Extract 1 to 16 exact regular files (at most 8 GiB total) without changing app data.\n\nRun directly on the host with an explicit empty --socket= and the existing\n--state-dir. The destination must not exist; its parent must be owner-only\nmode 0700. Every attempt leaves a private fence. Inspect incomplete outcomes\nprivately; never retry into the same directory. No Bao recovery is performed.",
		Args: cobra.ExactArgs(1), Annotations: map[string]string{"host-local-extract": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			in.App = args[0]
			return a.operate(cmd.Context(), apps.BackupExtractKind, in, planOnly)
		},
	}
	cmd.Flags().StringVar(&in.Snapshot, "snapshot", "", "required full lowercase 64-hex snapshot ID")
	cmd.Flags().StringArrayVar(&in.Paths, "path", nil, "exact regular-file path beneath /data; repeat for each file")
	cmd.Flags().StringVar(&in.Destination, "destination", "", "new absolute private staging directory")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}
