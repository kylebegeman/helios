package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/state"
)

// Garbage collection keeps no run log of its own, so the schedule reads the
// last operation of its kind. Without this a machine only ever collected
// when somebody typed the command, and build cache grew until the disk
// filled.
func TestGCIsDueFromTheLastOperation(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	s := &Scheduler{Store: store, Log: func(string, ...any) {}}

	started := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

	// Nothing has ever run: the first 04:00 after the daemon came up is due.
	if !s.dueOp(ctx, app.GCKind, MachineGCSchedule, started, started.Add(5*time.Hour)) {
		t.Fatal("gc should be due once the schedule has passed and nothing has run")
	}
	// Before that hour arrives it is not.
	if s.dueOp(ctx, app.GCKind, MachineGCSchedule, started, started.Add(time.Hour)) {
		t.Fatal("gc should not be due before its hour")
	}
	// A daemon with no start time has no anchor and must not run.
	if s.dueOp(ctx, app.GCKind, MachineGCSchedule, time.Time{}, started.Add(5*time.Hour)) {
		t.Fatal("gc should not be due without a starting point")
	}
	// An unreadable schedule is refused rather than treated as always due.
	if s.dueOp(ctx, app.GCKind, "not a schedule", started, started.Add(99*time.Hour)) {
		t.Fatal("an unparseable schedule should never be due")
	}
}

// The ceiling is what actually bounds the cache: a machine mid-iteration
// holds gigabytes of it, all younger than any age rule, so gc must still
// plan to trim it.
func TestBuildCacheCeilingDefaults(t *testing.T) {
	if app.DefaultBuildCacheMax <= 0 {
		t.Fatal("there must be a default ceiling, or age alone bounds the cache")
	}
	if app.DefaultBuildCacheMax > 32<<30 {
		t.Fatalf("default ceiling %d is too permissive to protect a small disk", app.DefaultBuildCacheMax)
	}
}

func TestFirstDeployKeepsTheEarliestRetainedTimestampAndErrorFallback(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, status := range []state.RevisionStatus{state.RevisionFailed, state.RevisionRetired, state.RevisionActive} {
		if err := store.SaveRevision(ctx, state.Revision{App: "fixture", ID: string(status), Status: status, CreatedAt: first.Add(time.Duration(i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	s := &Scheduler{Store: store}
	if got := s.firstDeploy(ctx, "fixture"); !got.Equal(first) {
		t.Fatalf("first deployment moved to %s, want %s", got, first)
	}
	if got := s.firstDeploy(ctx, "missing"); !got.IsZero() {
		t.Fatalf("missing app got a deployment timestamp: %s", got)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if got := s.firstDeploy(cancelled, "fixture"); !got.IsZero() {
		t.Fatalf("failed lookup got a deployment timestamp: %s", got)
	}
}
