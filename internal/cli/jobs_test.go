package cli

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// The text list leads every run and hold with the id the JSON carries, so
// an operator can name a run without reading JSON.
func TestJobsListsEveryRunUnderItsID(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	ok, err := store.StartJobRun(ctx, state.JobRun{App: "hello", Workload: "tick", Revision: "r1", Kind: "cron", StartedAt: t0})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishJobRun(ctx, ok, 0, "", "tick\n", t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	failed, err := store.StartJobRun(ctx, state.JobRun{App: "hello", Workload: "tick", Revision: "r1", Kind: "run", StartedAt: t0.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishJobRun(ctx, failed, 1, "exited 1", "", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	hold, err := store.HoldJob(ctx, "hello", "tick", "r1", t0.Add(3*time.Minute), t0.Add(48*time.Hour), "the volume is being moved")
	if err != nil {
		t.Fatal(err)
	}

	out, errOut, code := run(t, dir, "jobs", "hello")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if code != 0 || len(lines) != 4 {
		t.Fatalf("jobs: exit %d, stderr %q, output:\n%s", code, errOut, out)
	}
	if header := strings.Join(strings.Fields(lines[0]), " "); header != "ID WORKLOAD KIND STARTED TOOK RESULT" {
		t.Fatalf("header %q", header)
	}
	for i, want := range []struct {
		id     int64
		kind   string
		result string
	}{
		{hold, state.JobHold, ": the volume is being moved"},
		{failed, "run", "exited 1"},
		{ok, "cron", "ok"},
	} {
		row := lines[i+1]
		fields := strings.Fields(row)
		if len(fields) < 3 || fields[0] != strconv.FormatInt(want.id, 10) || fields[1] != "tick" || fields[2] != want.kind || !strings.HasSuffix(row, want.result) {
			t.Errorf("row %d = %q, want id %d, tick, %s, ending %q", i+1, row, want.id, want.kind, want.result)
		}
	}
}
