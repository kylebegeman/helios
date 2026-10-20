package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// The run lists and status show what an operator skipped or held, and why,
// and a hold's notice is never counted as an alert.
func TestStatusAndTheRunListsShowWhatAnOperatorSkippedOrHeld(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Minute)
	m := manifest.Manifest{App: "site",
		Workloads: map[string]manifest.Workload{"report": {Kind: manifest.Cron, Schedule: "45 4 * * *", Image: "site:r1"}},
		Data:      &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}}}
	raw, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: "site", ID: "r1", Status: state.RevisionActive, Manifest: raw, Containers: map[string]string{}, CreatedAt: now.Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	id, err := store.StartBackupRun(ctx, "site", state.BackupRunBackup, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: now.Add(-time.Hour), OK: true, Snapshot: "good-snapshot"}); err != nil {
		t.Fatal(err)
	}
	skipped := now.Add(72 * time.Hour)
	if _, err := store.SkipDrill(ctx, "site", skipped, "the disk is being resized"); err != nil {
		t.Fatal(err)
	}
	until := now.Add(48 * time.Hour)
	if _, err := store.HoldJob(ctx, "site", "report", "r1", now.Add(-time.Hour), until, "the volume is being moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenIncident(ctx, state.Incident{Key: "hold:site/report", Subject: "site/report cron", Severity: state.SeverityNotice, Message: "held until " + apps.OperatorTime(until) + ": the volume is being moved", OpenedAt: now}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		args []string
		want []string
		not  []string
	}{
		{[]string{"status"}, []string{
			"no open alerts",
			"none yet, next skipped",
			"HOLD site drill due " + apps.OperatorTime(skipped) + ": skipped by operator: the disk is being resized",
			"HOLD site/report cron held until " + apps.OperatorTime(until) + ": the volume is being moved",
		}, []string{"ALERT", "OPEN ALERT"}},
		{[]string{"status", "site"}, []string{
			"drill due " + apps.OperatorTime(skipped) + ": skipped by operator: the disk is being resized",
			"cron report: held until " + apps.OperatorTime(until) + ": the volume is being moved",
		}, nil},
		{[]string{"backups", "site"}, []string{"skipped", "skipped by operator: the disk is being resized"}, nil},
		{[]string{"jobs", "site"}, []string{"held until " + apps.OperatorTime(until) + ": the volume is being moved"}, nil},
	} {
		out, errOut, code := run(t, dir, tc.args...)
		if code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", tc.args, code, errOut)
		}
		for _, want := range tc.want {
			if !strings.Contains(out, want) {
				t.Errorf("%v doesn't say %q:\n%s", tc.args, want, out)
			}
		}
		for _, not := range tc.not {
			if strings.Contains(out, not) {
				t.Errorf("%v says %q:\n%s", tc.args, not, out)
			}
		}
	}
}

// The commands refuse what they can't send before asking the daemon.
func TestHoldAndSkipFlagsNameWhatIsWrong(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"cron", "hold", "site", "report", "--reason", "moving"}, "--until is required"},
		{[]string{"cron", "hold", "site", "report", "--until", "tuesday", "--reason", "moving"}, `--until "tuesday" is not an RFC 3339 time`},
		{[]string{"drill", "site", "--skip-next", "--snapshot", "aaaaaaaa", "--reason", "resizing"}, "--skip-next skips the next scheduled drill, which takes no --snapshot"},
		{[]string{"drill", "site", "--reason", "resizing"}, "--reason goes with --skip-next"},
	} {
		_, errOut, code := run(t, dir, tc.args...)
		if code == 0 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: exit %d, stderr %q, want %q", tc.args, code, errOut, tc.want)
		}
	}
}
