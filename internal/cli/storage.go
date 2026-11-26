package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/state"
)

func newStorage(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "What each backup bucket holds, how fast it grows, and which removed apps' buckets are about to expire.",
		Long: `One row for each bucket this machine owns: every app that is backed up, the
machine's own, and every removed app whose bucket has not expired yet.

The figures are the ones the nightly storage sweep recorded, so the report
reads no storage and shows the account as of the time it names. helios
storage sweep measures again now.

  SIZE       every version of every file in the bucket: what is billed
  SNAPSHOTS  how many snapshots the repository holds
  NEWEST     when the newest of them was taken
  7D GROWTH  SIZE now against SIZE seven days ago; in a bucket's first week
             of samples, against its first sample, and it says so
  DEAD       SIZE less what "restic stats --mode raw-data" counts: the
             stored size of every blob a snapshot still uses, read from the
             repository's index without downloading any data. What is left
             is data no snapshot uses, waiting for a prune, and it includes
             the repository's own indexes, a few megabytes.

A removed app's bucket is deleted, with every backup in it, 30 days after
helios remove. helios storage keep <app> cancels that and helios storage
purge <app> does it now. Only a bucket this machine removed the app of is
ever deleted, and only when every snapshot in it is one this machine made:
a bucket that holds another machine's backups stays, and says so.

The second list is buckets that carry this machine's prefix and belong to
another machine or to nobody. They are reported and never touched.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			now := time.Now().UTC()
			samples, err := store.StorageSamples(cmd.Context(), now.Add(-apps.StorageSampleWindow))
			if err != nil {
				return err
			}
			tombstones, err := store.StorageTombstones(cmd.Context())
			if err != nil {
				return err
			}
			report := apps.BuildStorageReport(samples, tombstones, now)
			if a.json {
				return json.NewEncoder(a.stdout).Encode(report)
			}
			return printStorageReport(a.stdout, report, now)
		},
	}

	var sweepPlan bool
	sweep := &cobra.Command{
		Use:   "sweep",
		Short: "Measure every bucket now and delete the buckets of apps removed more than 30 days ago.",
		Long: `Do now what runs every night: measure each bucket for the report and the
growth alert, then delete the bucket of every app removed more than 30 days
ago. The plan names each bucket it would delete.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.operate(cmd.Context(), apps.StorageSweepKind, apps.StorageSweepInput{}, sweepPlan)
		},
	}
	a.mutatingFlags(sweep, &sweepPlan)

	var keepPlan bool
	keep := &cobra.Command{
		Use:   "keep <app>",
		Short: "Keep a removed app's bucket: cancel its expiry.",
		Long: `Keep a removed app's bucket and the backups in it. Nothing deletes it
afterwards except helios storage purge. Removing the app again, after it
was deployed again, starts a new 30 days.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.StorageKeepKind, apps.StorageAppInput{App: args[0]}, keepPlan)
		},
	}
	a.mutatingFlags(keep, &keepPlan)

	var purgePlan bool
	purge := &cobra.Command{
		Use:   "purge <app>",
		Short: "Delete a removed app's bucket now, with every backup in it.",
		Long: `Delete a removed app's bucket now, without waiting for its 30 days: every
version of every file, then the bucket. Nothing brings the backups back.

Only an app helios remove took off this machine can be purged. A bucket is
refused when it holds a snapshot this machine has no record of making, when
it holds files but no snapshot, or when it was written to after the app was
removed: another machine backs up to it. Backups a machine recovery brought
with it count as the other machine's. A purge that stops part way is run
again to finish.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.StoragePurgeKind, apps.StorageAppInput{App: args[0]}, purgePlan)
		},
	}
	a.mutatingFlags(purge, &purgePlan)

	cmd.AddCommand(sweep, keep, purge)
	return cmd
}

func printStorageReport(out io.Writer, report apps.StorageReport, now time.Time) error {
	if len(report.Buckets) == 0 && len(report.Unowned) == 0 {
		fmt.Fprintln(out, "no bucket has been measured yet; the storage sweep runs every night, or now: helios storage sweep")
		return nil
	}
	if report.SampledAt.IsZero() {
		fmt.Fprintln(out, "No bucket has been measured yet; the storage sweep runs every night, or now: helios storage sweep")
	} else {
		fmt.Fprintf(out, "Measured %s, %s ago.\n", report.SampledAt.Local().Format("2006-01-02 15:04"), storageAge(now.Sub(report.SampledAt)))
	}
	fmt.Fprintln(out)
	var remarks []string
	if len(report.Buckets) > 0 {
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "BUCKET\tOF\tSIZE\tSNAPSHOTS\tNEWEST\t7D GROWTH\tDEAD\tSTATE")
		for _, row := range report.Buckets {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", row.Bucket, storageOwner(row), storageBytes(row.StoredBytes), storageCount(row.Snapshots),
				storageDate(row.NewestSnapshotAt), storageGrowth(row), storageBytes(row.DeadBytes), storageState(row))
			remarks = append(remarks, storageRemarks(row)...)
		}
		if err := w.Flush(); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(out, "This machine owns no bucket.")
	}
	if len(report.Unowned) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Under this machine's prefix, not owned by it (reported only, never deleted):")
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "BUCKET\tSIZE\tLAST WRITTEN\tSTATE")
		for _, row := range report.Unowned {
			what := ""
			if row.Moved {
				what = row.Owner + " moved to another machine"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.Bucket, storageBytes(row.StoredBytes), storageDate(row.LastWriteAt), orDash(what))
			remarks = append(remarks, storageRemarks(row)...)
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	if len(remarks) > 0 {
		fmt.Fprintln(out)
		for _, remark := range remarks {
			fmt.Fprintln(out, remark)
		}
	}
	return nil
}

func storageOwner(row apps.StorageRow) string {
	if row.Kind == state.StorageMachine {
		return "this machine"
	}
	return orDash(row.Owner)
}

func storageBytes(n int64) string {
	if n < 0 {
		return "?"
	}
	return apps.HumanBytes(n)
}

func storageCount(n int64) string {
	if n < 0 {
		return "?"
	}
	return fmt.Sprint(n)
}

func storageDate(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02")
}

// storageGrowth is how much a bucket grew in the week before its sample.
// A bucket with less than a week of samples says how many days it covers.
func storageGrowth(row apps.StorageRow) string {
	if row.GrowthSince.IsZero() || row.StoredBytes < 0 {
		return "-"
	}
	grew := "0 B"
	switch {
	case row.GrowthBytes > 0:
		grew = "+" + apps.HumanBytes(row.GrowthBytes)
	case row.GrowthBytes < 0:
		grew = "-" + apps.HumanBytes(-row.GrowthBytes)
	}
	covered := row.SampledAt.Sub(row.GrowthSince)
	if covered < apps.StorageGrowthWindow-12*time.Hour {
		return fmt.Sprintf("%s in %s", grew, storageAge(covered))
	}
	return grew
}

func storageState(row apps.StorageRow) string {
	if row.Kind != state.StorageRemoved {
		return "-"
	}
	removed := "removed " + storageDate(row.RemovedAt)
	switch {
	case row.Kept && row.Held != "":
		return removed + ", kept (see below)"
	case row.Kept:
		return removed + ", kept"
	case row.Held != "":
		return removed + ", not deleted (see below)"
	}
	return removed + ", deleted after " + storageDate(row.ExpiresAt)
}

// storageRemarks are the lines under the tables: what is unusual about a
// bucket, why one is not being deleted, and what could not be read.
func storageRemarks(row apps.StorageRow) []string {
	var out []string
	if len(row.Unusual) > 0 {
		out = append(out, fmt.Sprintf("%s: %s", row.Bucket, strings.Join(row.Unusual, "; ")))
	}
	switch {
	case row.Held == "" || row.Moved:
	case row.Kept:
		// The one thing recorded against a kept bucket is a deletion that
		// was begun and not finished, which says itself what to do.
		out = append(out, fmt.Sprintf("%s is kept, but %s", row.Bucket, row.Held))
	default:
		out = append(out, fmt.Sprintf("%s is not being deleted: %s. helios storage keep %s keeps it; helios storage purge %s tries again now", row.Bucket, row.Held, row.Owner, row.Owner))
	}
	if row.Note != "" {
		out = append(out, fmt.Sprintf("%s: %s", row.Bucket, row.Note))
	}
	return out
}

func storageAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
