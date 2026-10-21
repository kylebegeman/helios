package state

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCronAdmissionUsesTheLatestHoldAtItsScheduledOccurrence(t *testing.T) {
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, scenario := range []string{"no-hold", "held", "expired", "released-before", "released-after", "latest-released", "same-time-latest-released", "other-workload", "other-app"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			s := open(t)
			wantHeld := scenario == "held" || scenario == "released-after"
			until := at.Add(time.Hour)
			if scenario != "no-hold" {
				app, workload := "site", "tick"
				if scenario == "other-workload" {
					workload = "another"
				}
				if scenario == "other-app" {
					app = "another"
				}
				if scenario == "expired" {
					until = at
				}
				id, err := s.HoldJob(ctx, app, workload, "older-revision", at.Add(-time.Hour), until, "maintenance")
				if err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "released-before", "released-after":
					until = at.Add(-time.Minute)
					if scenario == "released-after" {
						until = at.Add(time.Minute)
					}
					if err := s.EndJobHold(ctx, id, until); err != nil {
						t.Fatal(err)
					}
				case "latest-released", "same-time-latest-released":
					placed := at.Add(-30 * time.Minute)
					if scenario == "same-time-latest-released" {
						placed = at.Add(-time.Hour)
					}
					if _, err := s.HoldJob(ctx, app, workload, "new-revision", placed, at.Add(-time.Minute), "released"); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Admission happens after every hold has ended in wall-clock time;
			// the scheduled occurrence still decides whether it was skipped.
			run := JobRun{App: "site", Workload: "tick", Revision: "new-revision", Kind: "cron", StartedAt: at.Add(2 * time.Hour), Container: "cron-container"}
			id, heldUntil, err := s.StartCronRun(ctx, run, at)
			if err != nil {
				t.Fatal(err)
			}
			if wantHeld {
				if id != 0 || !heldUntil.Equal(until) {
					t.Fatalf("held occurrence admitted: id=%d, held until=%s, want %s", id, heldUntil, until)
				}
			} else {
				if id == 0 || !heldUntil.IsZero() {
					t.Fatalf("unheld occurrence refused: id=%d, held until=%s", id, heldUntil)
				}
				stored, err := s.JobRun(ctx, id)
				if err != nil || stored.Container != run.Container || !stored.StartedAt.Equal(run.StartedAt) || stored.Kind != "cron" {
					t.Fatalf("admission lost run identity: %+v, %v", stored, err)
				}
			}
			open, err := s.OpenJobRuns(ctx)
			if err != nil || len(open) != map[bool]int{false: 1, true: 0}[wantHeld] {
				t.Fatalf("wrong durable open runs: %+v, %v", open, err)
			}
			if _, err := s.StartJobRun(ctx, JobRun{App: "site", Workload: "tick", Revision: "new-revision", Kind: "run", StartedAt: at}); err != nil {
				t.Fatalf("one-off admission changed: %v", err)
			}
		})
	}
}

func TestCronAdmissionAndConcurrentHoldsHaveOneDurableOrder(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	other, err := Open(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	type admission struct {
		id    int64
		until time.Time
		err   error
	}
	type holdResult struct {
		id  int64
		err error
	}
	for i := range 64 {
		workload := fmt.Sprintf("tick-%d", i)
		start := make(chan struct{})
		admitted := make(chan admission, 1)
		held := make(chan holdResult, 1)
		go func() {
			<-start
			id, until, err := s.StartCronRun(ctx, JobRun{App: "site", Workload: workload, Revision: "r1", Kind: "cron", StartedAt: at}, at)
			admitted <- admission{id, until, err}
		}()
		go func() {
			<-start
			id, err := other.HoldJob(ctx, "site", workload, "r1", at, at.Add(time.Hour), "maintenance")
			held <- holdResult{id, err}
		}()
		close(start)
		a, h := <-admitted, <-held
		if a.err != nil || h.err != nil {
			t.Fatalf("concurrent admission=%v, hold=%v", a.err, h.err)
		}
		// IDs record SQLite's insertion order. A hold committed before a
		// cron row must refuse it; a run admitted first is allowed to finish.
		if a.id != 0 && a.id >= h.id {
			t.Fatalf("cron %d was inserted after hold %d had committed", a.id, h.id)
		}
		if a.id == 0 && !a.until.Equal(at.Add(time.Hour)) {
			t.Fatalf("refusal lost the hold deadline: %s", a.until)
		}
	}
}
