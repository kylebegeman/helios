package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// The storage sweep keeps no run log, so its schedule reads the last
// operation of its kind: once a night, and a failed sweep waits for the
// next night like any other.
func TestTheStorageSweepIsDueOnceANight(t *testing.T) {
	store := drillTestStore(t)
	ctx := context.Background()
	s := &Scheduler{Store: store, Log: func(string, ...any) {}}
	started := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	due := func(now time.Time) bool {
		return s.dueOp(ctx, app.StorageSweepKind, StorageSweepSchedule, started, now)
	}

	if due(started.Add(4*time.Hour + 59*time.Minute)) {
		t.Fatal("the sweep ran before its hour")
	}
	first := started.Add(5 * time.Hour)
	if !due(first) {
		t.Fatal("the first sweep after the daemon came up should be due at its hour")
	}
	if err := store.CreateOperation(ctx, state.NewOperation{ID: "sweep-1", Kind: app.StorageSweepKind, Input: []byte(`{}`), Plan: []byte(`{}`), CreatedAt: first}); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(ctx, "sweep-1", state.Failed, "sample: list buckets: storage answered HTTP 503", nil, first.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{first.Add(time.Minute), first.Add(12 * time.Hour), first.Add(24*time.Hour - time.Minute)} {
		if due(now) {
			t.Fatalf("the sweep was due again at %s, the same night", now)
		}
	}
	if !due(first.Add(24 * time.Hour)) {
		t.Fatal("the sweep should be due the next night")
	}
}

// A sample must show what the night's backups and garbage collection left
// behind, so the sweep's hour comes after both of theirs.
func TestTheStorageSweepRunsAfterTheNightsBackups(t *testing.T) {
	midnight := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	at := func(schedule string) time.Time {
		t.Helper()
		sched, err := manifest.ParseSchedule(schedule)
		if err != nil {
			t.Fatalf("%s: %v", schedule, err)
		}
		return sched.Next(midnight)
	}
	sweep := at(StorageSweepSchedule)
	for name, other := range map[string]string{"the machine backup": MachineBackupSchedule, "garbage collection": MachineGCSchedule, "the default app backup": manifest.DefaultBackupSchedule} {
		if !sweep.After(at(other)) {
			t.Errorf("the sweep at %s does not come after %s at %s", sweep.Format("15:04"), name, at(other).Format("15:04"))
		}
	}
}
