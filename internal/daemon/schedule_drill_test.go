package daemon

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func drillTestStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func recordBackupRun(t *testing.T, store *state.Store, kind string, at time.Time, r state.BackupRun) {
	t.Helper()
	ctx := context.Background()
	id, err := store.StartBackupRun(ctx, "hello", kind, at)
	if err != nil {
		t.Fatal(err)
	}
	r.FinishedAt = at.Add(time.Minute)
	if err := store.FinishBackupRun(ctx, id, r); err != nil {
		t.Fatal(err)
	}
}

// A drill that refuses for want of disk space is a failed drill like any
// other. The schedule counts from when it started, so it waits for its
// next Sunday instead of refusing again on every tick.
func TestARefusedDrillWaitsForItsNextScheduledRun(t *testing.T) {
	store := drillTestStore(t)
	ctx := context.Background()
	s := &Scheduler{Store: store, Log: func(string, ...any) {}}
	const weekly = "10 6 * * 0"

	// The store keeps times in UTC, and a schedule reads a time in its own
	// zone.
	backedUp := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	refused := time.Date(2026, 10, 25, 6, 10, 0, 0, time.UTC)
	recordBackupRun(t, store, state.BackupRunBackup, backedUp, state.BackupRun{OK: true})
	recordBackupRun(t, store, state.BackupRunDrill, refused, state.BackupRun{
		Error: "snapshot aaaaaaaa: restoring needs 90.0 GB plus a 5.0 GB reserve on /var/lib/helios/drills/hello, which has 8.0 GB free; free space, or skip it: helios drill hello --skip-next --reason <text>"})
	for _, now := range []time.Time{refused.Add(time.Minute), refused.Add(24 * time.Hour), time.Date(2026, 11, 1, 6, 9, 0, 0, time.UTC)} {
		if s.drillDue(ctx, "hello", weekly, now) {
			t.Fatalf("the refused drill was due again at %s", now)
		}
	}
	if next := time.Date(2026, 11, 1, 6, 10, 0, 0, time.UTC); !s.drillDue(ctx, "hello", weekly, next) {
		t.Fatalf("the drill wasn't due at its next Sunday, %s", next)
	}
}

// An operator who knows the next drill can't fit skips it ahead of time.
// The scheduler passes the skipped occurrence without running or failing a
// drill, and runs the one after it as usual.
func TestASkippedDrillWaitsForTheFollowingOccurrence(t *testing.T) {
	store := drillTestStore(t)
	ctx := context.Background()
	s := &Scheduler{Store: store, Log: func(string, ...any) {}}
	m := &manifest.Manifest{App: "hello",
		Workloads: map[string]manifest.Workload{"web": {Kind: manifest.Web, Image: "example.test/hello:1"}},
		Data:      &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}},
		Backup:    &manifest.Backup{Drill: "10 6 * * 0"}}
	encoded, _ := json.Marshal(m)
	deployed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := store.SaveRevision(ctx, state.Revision{App: "hello", ID: "r1", Status: state.RevisionActive, Manifest: encoded, CreatedAt: deployed, Images: map[string]string{"web": "sha256:abc"}, Containers: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	recordBackupRun(t, store, state.BackupRunDrill, time.Date(2026, 10, 18, 6, 10, 0, 0, time.UTC), state.BackupRun{OK: true, Detail: "restored and verified"})
	recordBackupRun(t, store, state.BackupRunBackup, time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC), state.BackupRun{OK: true})

	skip := app.DrillSkip{Store: store, Now: func() time.Time { return time.Date(2026, 10, 25, 5, 20, 0, 0, time.UTC) }}
	raw, _ := json.Marshal(app.DrillSkipInput{App: "hello", Reason: "the disk is being resized", By: "operator"})
	plan, err := skip.Plan(ctx, raw)
	if err != nil {
		t.Fatalf("plan the skip: %v", err)
	}
	if want := "skip the drill of hello due Sunday 25 October 06:10 UTC (the disk is being resized, asked by operator); the next drill is due Sunday 1 November 06:10 UTC"; plan.Steps[0].Change != want {
		t.Fatalf("plan says\n  %s\nwant\n  %s", plan.Steps[0].Change, want)
	}
	if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatalf("apply the skip: %v", err)
	}

	skipped := time.Date(2026, 10, 25, 6, 10, 0, 0, time.UTC)
	for _, now := range []time.Time{skipped, skipped.Add(time.Hour), skipped.Add(6 * 24 * time.Hour)} {
		if s.drillDue(ctx, "hello", m.DrillSchedule(), now) {
			t.Fatalf("the skipped drill was due at %s", now)
		}
	}
	if active, err := app.ActiveDrillSkip(ctx, store, "hello"); err != nil || active == nil || !strings.Contains(active.Detail, "resized") {
		t.Fatalf("the skip isn't active: %+v, %v", active, err)
	}

	// A second skip passes the one already skipped.
	plan, err = skip.Plan(ctx, raw)
	if err != nil {
		t.Fatalf("plan a second skip: %v", err)
	}
	if want := "the drill of hello due Sunday 25 October 06:10 UTC is already skipped, so skip the one after it, due Sunday 1 November 06:10 UTC"; !strings.HasPrefix(plan.Steps[0].Change, want) {
		t.Fatalf("plan says %q, want it to start %q", plan.Steps[0].Change, want)
	}

	recordBackupRun(t, store, state.BackupRunBackup, time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC), state.BackupRun{OK: true})
	if s.drillDue(ctx, "hello", m.DrillSchedule(), time.Date(2026, 11, 1, 6, 9, 0, 0, time.UTC)) {
		t.Fatal("the next drill was due before its time")
	}
	if !s.drillDue(ctx, "hello", m.DrillSchedule(), time.Date(2026, 11, 1, 6, 10, 0, 0, time.UTC)) {
		t.Fatal("the drill after the skipped one wasn't due")
	}
	last, err := store.LastBackupRun(ctx, "hello", state.BackupRunDrill)
	if err != nil || last == nil || !last.OK || !last.StartedAt.Equal(time.Date(2026, 10, 18, 6, 10, 0, 0, time.UTC)) {
		t.Fatalf("the skip recorded a drill: %+v, %v", last, err)
	}
}
