package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// A drill that refuses for want of disk space is a failed drill like any
// other. The schedule counts from when it started, so it waits for its
// next Sunday instead of refusing again on every tick.
func TestARefusedDrillWaitsForItsNextScheduledRun(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	s := &Scheduler{Store: store, Log: func(string, ...any) {}}
	const app, weekly = "notes", "10 6 * * 0"

	// The store keeps times in UTC, and a schedule reads a time in its own
	// zone.
	backedUp := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	refused := time.Date(2026, 10, 25, 6, 10, 0, 0, time.UTC)
	id, err := store.StartBackupRun(ctx, app, state.BackupRunDrill, refused)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: refused.Add(time.Minute),
		Error: "snapshot 7bfd5f28: restoring needs 89.7 GB plus a 5.0 GB reserve on /var/lib/helios/drills/notes, which has 7.8 GB free; free space or skip this drill"}); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{refused.Add(time.Minute), refused.Add(24 * time.Hour), time.Date(2026, 11, 1, 6, 9, 0, 0, time.UTC)} {
		if s.due(ctx, app, state.BackupRunDrill, weekly, backedUp, now) {
			t.Fatalf("the refused drill was due again at %s", now)
		}
	}
	if next := time.Date(2026, 11, 1, 6, 10, 0, 0, time.UTC); !s.due(ctx, app, state.BackupRunDrill, weekly, backedUp, next) {
		t.Fatalf("the drill wasn't due at its next Sunday, %s", next)
	}
}
