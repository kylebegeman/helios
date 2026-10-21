package kernel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

type regressionPlan struct {
	plan *Plan
}

func (regressionPlan) Kind() string                                           { return "test.journal-regression" }
func (d regressionPlan) Plan(context.Context, json.RawMessage) (*Plan, error) { return d.plan, nil }

func TestRecoveryRefusesShiftedJournalIndicesBeforeRunningSteps(t *testing.T) {
	for _, tc := range []struct {
		recovery Recovery
		offset   int
	}{{Resume, 10}, {Compensate, 10}, {Resume, -10}, {Compensate, -10}} {
		t.Run(fmt.Sprintf("%s/%d", tc.recovery, tc.offset), func(t *testing.T) {
			ctx := context.Background()
			store := newStore(t)
			applied, undone := 0, 0
			plan := &Plan{Target: "fixture", Recovery: tc.recovery, Steps: []Step{
				{Name: "first", Apply: func(context.Context, io.Writer) error { applied++; return nil }, Undo: func(context.Context, io.Writer) error { undone++; return nil }},
				{Name: "second", Apply: func(context.Context, io.Writer) error { applied++; return nil }},
			}}
			reg := Registry{}
			reg.Add(regressionPlan{plan: plan})
			at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			first := New(store, reg, "first", WithClock(func() time.Time { return at }))
			first.crashAfterStep = func(int) bool { return true }
			if _, err := first.Run(ctx, regressionPlan{}.Kind(), nil, func(Event) {}); !errors.Is(err, errCrashed) {
				t.Fatalf("simulate interruption: %v", err)
			}
			ops, err := store.List(ctx, 1)
			if err != nil || len(ops) != 1 {
				t.Fatalf("operations: %v %v", ops, err)
			}
			db, err := sql.Open("sqlite", store.Path())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			// Keep the same names and row count, but move them off the positions
			// the engine uses to record step starts and results.
			if _, err := db.ExecContext(ctx, "UPDATE steps SET idx = idx + ? WHERE operation_id = ?", tc.offset, ops[0].ID); err != nil {
				t.Fatal(err)
			}
			later := New(store, reg, "later", WithClock(func() time.Time { return at.Add(time.Minute) }))
			if n, err := later.Recover(ctx, func(Event) {}); err != nil || n != 1 {
				t.Fatalf("recover: %d %v", n, err)
			}
			receipt, err := later.ReceiptOf(ctx, ops[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if applied != 1 || undone != 0 {
				t.Fatalf("corrupt journal ran work: applied=%d undone=%d", applied, undone)
			}
			if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "index") {
				t.Fatalf("receipt: %+v", receipt)
			}
		})
	}
}

func TestCompensationReceivesTheJournaledOperationID(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		name := "failed"
		if interrupted {
			name = "interrupted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := newStore(t)
			var applyID, undoID string
			plan := &Plan{Target: "fixture", Recovery: Compensate, Steps: []Step{
				{Name: "reserve", Apply: func(ctx context.Context, _ io.Writer) error { applyID = OperationID(ctx); return nil }, Undo: func(ctx context.Context, _ io.Writer) error { undoID = OperationID(ctx); return nil }},
				{Name: "fail", Apply: func(context.Context, io.Writer) error { return errors.New("fixture failure") }},
			}}
			reg := Registry{}
			reg.Add(regressionPlan{plan: plan})
			at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			e := New(store, reg, "first", WithClock(func() time.Time { return at }))
			if interrupted {
				e.crashAfterStep = func(int) bool { return true }
			}
			receipt, err := e.Run(ctx, regressionPlan{}.Kind(), nil, func(Event) {})
			if interrupted {
				if !errors.Is(err, errCrashed) {
					t.Fatalf("simulate interruption: %v", err)
				}
				later := New(store, reg, "later", WithClock(func() time.Time { return at.Add(time.Minute) }))
				if n, err := later.Recover(ctx, func(Event) {}); err != nil || n != 1 {
					t.Fatalf("recover: %d %v", n, err)
				}
				receipt, err = later.ReceiptOf(ctx, applyID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Status != state.Compensated {
				t.Fatalf("receipt: %+v", receipt)
			}
			if applyID != receipt.ID || undoID != receipt.ID {
				t.Fatalf("operation identity: apply=%q undo=%q receipt=%q", applyID, undoID, receipt.ID)
			}
		})
	}
}
