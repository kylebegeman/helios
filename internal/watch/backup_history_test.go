package watch

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

func TestNeverBackedUpUsesTheEarliestRetainedDeployment(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, r := range []state.Revision{
		{App: "old", ID: "first", Status: state.RevisionRetired, CreatedAt: now.Add(-2 * BackupStale)},
		{App: "old", ID: "latest", Status: state.RevisionActive, CreatedAt: now.Add(-time.Minute)},
		{App: "new", ID: "first", Status: state.RevisionActive, CreatedAt: now.Add(-time.Minute)},
		{App: "undated", ID: "first", Status: state.RevisionActive},
	} {
		if err := store.SaveRevision(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	p := &Prober{Store: store}
	for _, name := range []string{"old", "undated"} {
		if got := p.backupProblem(ctx, name, now); !strings.HasPrefix(got, "never backed up, deployed ") {
			t.Fatalf("%s lost its stale backup warning: %q", name, got)
		}
	}
	for _, name := range []string{"new", "missing"} {
		if got := p.backupProblem(ctx, name, now); got != "" {
			t.Fatalf("%s got an unjustified stale backup warning: %q", name, got)
		}
	}
}
