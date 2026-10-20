package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/signals"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
	"github.com/kylebegeman/helios/internal/watch"
)

// appRow is one app as ls and status see it.
type appRow struct {
	Name        string    `json:"name"`
	Owner       string    `json:"owner,omitempty"`
	Description string    `json:"description,omitempty"`
	Repo        string    `json:"repo,omitempty"`
	Hosts       []string  `json:"hosts,omitempty"`
	Revision    string    `json:"revision"`
	Commit      string    `json:"commit,omitempty"`
	DeployedAt  time.Time `json:"deployed_at"`
	// BackedUp says the app has data and backups aren't off.
	BackedUp   bool             `json:"backed_up"`
	LastBackup *state.BackupRun `json:"last_backup,omitempty"`
	GoodBackup *state.BackupRun `json:"good_backup,omitempty"`
	LastDrill  *state.BackupRun `json:"last_drill,omitempty"`
	// DrillSkip is the scheduled drill an operator skipped, until a drill runs.
	DrillSkip *state.BackupRun `json:"drill_skip,omitempty"`
	// CronHolds are the cron workloads an operator holds now.
	CronHolds  []state.JobRun `json:"cron_holds,omitempty"`
	manifest   manifest.Manifest
	containers map[string]string
}

// appRows reads every deployed app.
func appRows(ctx context.Context, store *state.Store) ([]appRow, error) {
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return nil, err
	}
	var rows []appRow
	now := time.Now()
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return nil, err
		}
		row := appRow{Name: rev.App, Owner: m.Owner, Description: m.Description, Repo: m.Repo, Hosts: m.Hosts(), Revision: rev.ID, Commit: rev.Source, DeployedAt: rev.CreatedAt, BackedUp: m.BackedUp(), manifest: m, containers: rev.Containers}
		row.LastBackup, _ = store.LastBackupRun(ctx, rev.App, state.BackupRunBackup)
		row.GoodBackup, _ = store.LastGoodBackupRun(ctx, rev.App, state.BackupRunBackup)
		row.LastDrill, _ = store.LastBackupRun(ctx, rev.App, state.BackupRunDrill)
		if row.BackedUp {
			row.DrillSkip, _ = apps.ActiveDrillSkip(ctx, store, rev.App)
		}
		for _, name := range m.WorkloadNames() {
			if m.Workloads[name].Kind != manifest.Cron {
				continue
			}
			if hold, _ := apps.ActiveCronHold(ctx, store, rev.App, name, now); hold != nil {
				row.CronHolds = append(row.CronHolds, *hold)
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// backupWord sums up an app's backups in a few words.
func backupWord(r appRow, now time.Time) string {
	if !r.BackedUp {
		if r.manifest.HasData() {
			return "off"
		}
		return "no data"
	}
	if r.GoodBackup == nil {
		if r.LastBackup != nil && r.LastBackup.Finished() {
			return "FAILED: " + r.LastBackup.Error
		}
		return "never"
	}
	word := agoWord(r.GoodBackup.StartedAt, now)
	if r.LastBackup != nil && r.LastBackup.ID != r.GoodBackup.ID && r.LastBackup.Finished() && !r.LastBackup.OK {
		word += ", then FAILED"
	}
	return word
}

// drillWord sums up an app's last drill, and says when the next is skipped.
func drillWord(r appRow, now time.Time) string {
	word := lastDrillWord(r, now)
	if word != "" && r.DrillSkip != nil {
		word += ", next skipped"
	}
	return word
}

func lastDrillWord(r appRow, now time.Time) string {
	switch {
	case !r.BackedUp:
		return ""
	case r.LastDrill == nil:
		return "none yet"
	case !r.LastDrill.Finished():
		return "running"
	case r.LastDrill.OK:
		return "ok " + agoWord(r.LastDrill.StartedAt, now)
	default:
		return "FAILED " + agoWord(r.LastDrill.StartedAt, now)
	}
}

func agoWord(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.0f h ago", d.Hours())
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func newLs(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List the apps on this machine: owner, hosts, repository, last deploy, last backup.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			rows, err := appRows(ctx, store)
			if err != nil {
				return err
			}
			var unmanaged []string
			// Docker failure leaves useful app status, but cannot prove an empty inventory.
			unmanagedKnown := false
			if engine, err := docker.Connect(ctx); err == nil {
				if names, err := engine.Unowned(ctx); err == nil {
					unmanaged, unmanagedKnown = names, true
				}
				engine.Close()
			}
			if a.json {
				if rows == nil {
					rows = []appRow{}
				}
				return json.NewEncoder(a.stdout).Encode(struct {
					Apps           []appRow `json:"apps"`
					Unmanaged      []string `json:"unmanaged,omitempty"`
					UnmanagedKnown bool     `json:"unmanaged_known"`
				}{rows, unmanaged, unmanagedKnown})
			}
			now := time.Now().UTC()
			if len(rows) == 0 {
				fmt.Fprintln(a.stdout, "no apps deployed yet")
			} else {
				w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "APP\tOWNER\tHOSTS\tREPO\tDEPLOYED\tBACKUP")
				for _, r := range rows {
					deployed := agoWord(r.DeployedAt, now)
					if r.Commit != "" {
						deployed += " (" + short7(r.Commit) + ")"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, orDash(r.Owner), orDash(strings.Join(r.Hosts, ", ")), orDash(r.Repo), deployed, backupWord(r, now))
				}
				w.Flush()
				for _, r := range rows {
					if r.Description != "" {
						fmt.Fprintf(a.stdout, "  %s: %s\n", r.Name, r.Description)
					}
				}
			}
			if !unmanagedKnown {
				fmt.Fprintln(a.stdout, "unmanaged containers: unknown (Docker inventory unavailable)")
			} else if len(unmanaged) > 0 {
				sort.Strings(unmanaged)
				fmt.Fprintf(a.stdout, "not managed by helios: %s\n", strings.Join(unmanaged, ", "))
			}
			return nil
		},
	}
}

// short7 is a commit as git shows it: its first seven characters.
func short7(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// alerts are the open incidents that need attention. A notice is an
// operator's own hold or skip, so it is shown but never counted as an alert.
func alerts(open []state.Incident) []state.Incident {
	var out []state.Incident
	for _, inc := range open {
		if inc.Severity != state.SeverityNotice {
			out = append(out, inc)
		}
	}
	return out
}

// holdLines are an app's operator holds and skips, one per line.
func holdLines(r appRow) []string {
	var out []string
	if r.DrillSkip != nil {
		out = append(out, fmt.Sprintf("%s drill due %s: skipped by operator: %s", r.Name, apps.OperatorTime(r.DrillSkip.StartedAt), r.DrillSkip.Detail))
	}
	for _, hold := range r.CronHolds {
		out = append(out, fmt.Sprintf("%s/%s cron held until %s: %s", r.Name, hold.Workload, apps.OperatorTime(hold.FinishedAt), hold.Output))
	}
	return out
}

// machineLine says how the machine is doing, in one line.
func machineLine(ctx context.Context, hostname string, open []state.Incident) string {
	open = alerts(open)
	parts := []string{"helios " + version.Current().Version}
	if engine, err := docker.Connect(ctx); err != nil {
		parts = append(parts, "DOCKER NOT ANSWERING")
	} else {
		if info, err := engine.Inspect(ctx, edge.Container); err == nil && info.Running {
			parts = append(parts, "edge ok")
		} else {
			parts = append(parts, "EDGE NOT RUNNING")
		}
		engine.Close()
	}
	if free, total, ok := watch.DiskFree("/"); ok {
		parts = append(parts, fmt.Sprintf("%s free of %s", apps.HumanBytes(int64(free)), apps.HumanBytes(int64(total))))
	}
	if avail, total, ok := watch.Memory(); ok {
		parts = append(parts, fmt.Sprintf("%s of %s memory available", apps.HumanBytes(int64(avail)), apps.HumanBytes(int64(total))))
	}
	if load, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(load)); len(f) >= 3 {
			parts = append(parts, "load "+f[0]+" "+f[1]+" "+f[2])
		}
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		parts = append(parts, "REBOOT REQUIRED")
	}
	alerts := "no open alerts"
	if len(open) == 1 {
		alerts = "1 OPEN ALERT: " + open[0].Subject
	} else if len(open) > 1 {
		alerts = fmt.Sprintf("%d OPEN ALERTS", len(open))
	}
	parts = append(parts, alerts)
	return hostname + ": " + strings.Join(parts, ", ")
}

func newStatus(a *app) *cobra.Command {
	var since time.Duration
	cmd := &cobra.Command{
		Use:   "status [app]",
		Short: "How the machine and its apps are doing: health, traffic, resources, backups, alerts.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			now := time.Now().UTC()
			rows, err := appRows(ctx, store)
			if err != nil {
				return err
			}
			open, err := store.OpenIncidents(ctx)
			if err != nil {
				return err
			}
			openBy := map[string]state.Incident{}
			for _, inc := range open {
				openBy[inc.Key] = inc
			}
			sums, err := signals.AppSummaries(ctx, store, now.Add(-since))
			if err != nil {
				return err
			}
			hostname, _ := os.Hostname()
			if len(args) == 1 {
				for _, r := range rows {
					if r.Name == args[0] {
						return a.appStatus(ctx, store, r, sums, openBy, now, since)
					}
				}
				return fmt.Errorf("%s isn't deployed", args[0])
			}
			if a.json {
				type row struct {
					appRow
					Health   string          `json:"health"`
					Signals  signals.Summary `json:"signals"`
					Incident *state.Incident `json:"incident,omitempty"`
				}
				out := make([]row, 0, len(rows))
				for _, r := range rows {
					health, inc := healthWord(r, openBy)
					out = append(out, row{r, health, sums[r.Name], inc})
				}
				return json.NewEncoder(a.stdout).Encode(struct {
					Machine string           `json:"machine"`
					Apps    []row            `json:"apps"`
					Open    []state.Incident `json:"open_alerts"`
				}{machineLine(ctx, hostname, open), out, open})
			}
			fmt.Fprintln(a.stdout, machineLine(ctx, hostname, open))
			if len(rows) == 0 {
				fmt.Fprintln(a.stdout, "no apps deployed yet")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "APP\tHEALTH\tREQ/%s\tERRORS\tP95\tCPU\tMEMORY\tDISK\tBACKUP\tDRILL\n", strings.ToUpper(windowWord(since)))
			for _, r := range rows {
				health, _ := healthWord(r, openBy)
				s := sums[r.Name]
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, health, count(s.Requests), count(s.Errors), latency(s.P95MS, s.Requests), percent(s.CPUPercent, s.Hours), bytesWord(s.MemoryBytes), bytesWord(s.DiskBytes), backupWord(r, now), orDash(drillWord(r, now)))
			}
			w.Flush()
			for _, r := range rows {
				for _, line := range holdLines(r) {
					fmt.Fprintln(a.stdout, "HOLD "+line)
				}
			}
			for _, inc := range alerts(open) {
				fmt.Fprintf(a.stdout, "ALERT %s since %s: %s\n", inc.Subject, inc.OpenedAt.Local().Format("15:04"), inc.Message)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&since, "since", 24*time.Hour, "the window for traffic and resources")
	return cmd
}

// appStatus shows one app in detail.
func (a *app) appStatus(ctx context.Context, store *state.Store, r appRow, sums map[string]signals.Summary, openBy map[string]state.Incident, now time.Time, since time.Duration) error {
	health, inc := healthWord(r, openBy)
	rows, _ := store.Signals(ctx, r.Name, now.Add(-since))
	if a.json {
		return json.NewEncoder(a.stdout).Encode(struct {
			appRow
			Health   string          `json:"health"`
			Signals  signals.Summary `json:"signals"`
			Incident *state.Incident `json:"incident,omitempty"`
			Rollups  []state.Signal  `json:"rollups"`
		}{r, health, sums[r.Name], inc, rows})
	}
	fmt.Fprintf(a.stdout, "%s: %s\n", r.Name, health)
	if inc != nil {
		fmt.Fprintf(a.stdout, "  since %s: %s\n", inc.OpenedAt.Local().Format("2006-01-02 15:04"), inc.Message)
	}
	if r.Description != "" {
		fmt.Fprintf(a.stdout, "  %s\n", r.Description)
	}
	deployed := agoWord(r.DeployedAt, now)
	if r.Commit != "" {
		deployed += ", commit " + short7(r.Commit)
	}
	fmt.Fprintf(a.stdout, "  revision %s, deployed %s\n", r.Revision, deployed)
	if len(r.Hosts) > 0 {
		fmt.Fprintf(a.stdout, "  hosts: %s\n", strings.Join(r.Hosts, ", "))
	}
	s := sums[r.Name]
	fmt.Fprintf(a.stdout, "  last %s: %s requests, %s errors, p95 %s, %s sent; cpu %s, memory %s (peak %s), disk %s\n", windowWord(since), count(s.Requests), count(s.Errors), latency(s.P95MS, s.Requests), bytesWord(s.Bytes), percent(s.CPUPercent, s.Hours), bytesWord(s.MemoryBytes), bytesWord(s.MemoryMax), bytesWord(s.DiskBytes))
	byHost := map[string][]state.Signal{}
	byWorkload := map[string][]state.Signal{}
	for _, sig := range rows {
		switch sig.Metric {
		case state.SignalCPUPercent, state.SignalMemoryBytes, state.SignalMemoryMax:
			byWorkload[sig.Key] = append(byWorkload[sig.Key], sig)
		case state.SignalDiskBytes:
		default:
			byHost[sig.Key] = append(byHost[sig.Key], sig)
		}
	}
	for _, h := range sortedKeys(byHost) {
		hs := signals.Summarize(byHost[h])
		fmt.Fprintf(a.stdout, "    %s: %s requests, %s errors, p95 %s\n", h, count(hs.Requests), count(hs.Errors), latency(hs.P95MS, hs.Requests))
	}
	for _, wl := range sortedKeys(byWorkload) {
		ws := signals.Summarize(byWorkload[wl])
		fmt.Fprintf(a.stdout, "    %s: cpu %s, memory %s (peak %s)\n", wl, percent(ws.CPUPercent, ws.Hours), bytesWord(ws.MemoryBytes), bytesWord(ws.MemoryMax))
	}
	if r.BackedUp {
		fmt.Fprintf(a.stdout, "  backups: %s; drill %s\n", backupWord(r, now), orDash(drillWord(r, now)))
		if r.GoodBackup != nil {
			fmt.Fprintf(a.stdout, "    last good snapshot %s from %s: %s\n", r.GoodBackup.Snapshot, r.GoodBackup.SnapshotAt.Local().Format("2006-01-02 15:04"), r.GoodBackup.Detail)
		}
		if r.LastDrill != nil && r.LastDrill.Finished() {
			fmt.Fprintf(a.stdout, "    last drill: %s\n", orDash(firstNonEmpty(r.LastDrill.Detail, r.LastDrill.Error)))
		}
		if r.DrillSkip != nil {
			fmt.Fprintf(a.stdout, "    drill due %s: skipped by operator: %s\n", apps.OperatorTime(r.DrillSkip.StartedAt), r.DrillSkip.Detail)
		}
	} else if r.manifest.HasData() {
		fmt.Fprintln(a.stdout, "  backups: off in helios.yaml")
	}
	for _, hold := range r.CronHolds {
		fmt.Fprintf(a.stdout, "  cron %s: held until %s: %s\n", hold.Workload, apps.OperatorTime(hold.FinishedAt), hold.Output)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

// healthWord is an app's health as the watcher last saw it.
func healthWord(r appRow, openBy map[string]state.Incident) (string, *state.Incident) {
	if inc, ok := openBy["app:"+r.Name]; ok {
		word := "PROBLEM"
		if inc.Severity == state.SeverityCritical {
			word = "DOWN"
		}
		return word, &inc
	}
	n := len(r.containers)
	if n == 1 {
		return "ok, 1 container", nil
	}
	return fmt.Sprintf("ok, %d containers", n), nil
}

func windowWord(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		days := int(d.Hours() / 24)
		if days == 1 {
			return "24h"
		}
		return fmt.Sprintf("%dd", days)
	}
	return d.String()
}

func count(n int64) string {
	s := fmt.Sprint(n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func latency(ms float64, requests int64) string {
	if requests == 0 {
		return "-"
	}
	if ms >= 1000 {
		return fmt.Sprintf("%.1f s", ms/1000)
	}
	return fmt.Sprintf("%.0f ms", ms)
}

func percent(p float64, hours int) string {
	if hours == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", p)
}

func bytesWord(n int64) string {
	if n <= 0 {
		return "-"
	}
	return apps.HumanBytes(n)
}
