package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

func newStore(t *testing.T) *state.Store {
	t.Helper()
	s, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func registry() Registry {
	r := Registry{}
	r.Add(Exercise{})
	return r
}

func exercise(t *testing.T, dir string, steps, failAt int, recovery Recovery) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(ExerciseInput{Dir: dir, Steps: steps, FailAt: failAt, Recovery: recovery})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type recorder struct{ events []Event }

func (r *recorder) emit(e Event) { r.events = append(r.events, e) }

func (r *recorder) types() []EventType {
	var out []EventType
	for _, e := range r.events {
		if e.Type != EventStepOutput {
			out = append(out, e.Type)
		}
	}
	return out
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestRunAppliesEveryStepAndLeavesAReceipt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e := New(newStore(t), registry(), "test-a")
	var rec recorder
	receipt, err := e.Run(ctx, ExerciseKind, exercise(t, dir, 3, 0, Resume), rec.emit)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Succeeded || len(receipt.Steps) != 3 || receipt.Interruptions != 0 {
		t.Fatalf("receipt: %+v", receipt)
	}
	for n := 1; n <= 3; n++ {
		if !exists(filepath.Join(dir, "step-"+string(rune('0'+n)))) {
			t.Fatalf("step-%d marker missing", n)
		}
	}
	want := []EventType{EventPlanned, EventStepStarted, EventStepFinished, EventStepStarted, EventStepFinished, EventStepStarted, EventStepFinished, EventFinished}
	if got := rec.types(); len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	if rec.events[0].Plan == nil || rec.events[0].Plan.Digest == "" || len(rec.events[0].Plan.Steps) != 3 {
		t.Fatalf("planned event: %+v", rec.events[0])
	}
	stored, err := e.ReceiptOf(ctx, receipt.ID)
	if err != nil || stored.Status != state.Succeeded || stored.PlanDigest != receipt.PlanDigest {
		t.Fatalf("stored receipt: %v %+v", err, stored)
	}
}

func TestPlanOnlyRecordsNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := newStore(t)
	e := New(store, registry(), "test-a")
	view, err := e.PlanOnly(ctx, ExerciseKind, exercise(t, dir, 2, 0, Resume))
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Steps) != 2 || view.Steps[1].Name != "step-2" || view.Recovery != Resume {
		t.Fatalf("plan: %+v", view)
	}
	if exists(filepath.Join(dir, "step-1")) {
		t.Fatal("planning must change nothing")
	}
	if ops, _ := store.List(ctx, 10); len(ops) != 0 {
		t.Fatalf("planning must record nothing, got %d operations", len(ops))
	}
}

func TestFailureWithoutUndoStopsAndFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e := New(newStore(t), registry(), "test-a")
	var rec recorder
	receipt, err := e.Run(ctx, ExerciseKind, exercise(t, dir, 3, 2, Resume), rec.emit)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Failed || receipt.Error != "step-2: asked to fail at step 2" {
		t.Fatalf("receipt: %+v", receipt)
	}
	if !exists(filepath.Join(dir, "step-1")) || exists(filepath.Join(dir, "step-3")) {
		t.Fatal("step 1 should stay, step 3 should never run")
	}
	if receipt.Steps[1].Status != state.StepFailed || receipt.Steps[2].Status != state.StepPending {
		t.Fatalf("steps: %+v", receipt.Steps)
	}
}

func TestFailureWithCompensationUndoesTheRest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e := New(newStore(t), registry(), "test-a")
	var rec recorder
	receipt, err := e.Run(ctx, ExerciseKind, exercise(t, dir, 3, 3, Compensate), rec.emit)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Compensated {
		t.Fatalf("receipt: %+v", receipt)
	}
	if exists(filepath.Join(dir, "step-1")) || exists(filepath.Join(dir, "step-2")) {
		t.Fatal("completed steps must be undone")
	}
	if receipt.Steps[0].Status != state.StepUndone || receipt.Steps[1].Status != state.StepUndone || receipt.Steps[2].Status != state.StepFailed {
		t.Fatalf("steps: %+v", receipt.Steps)
	}
	// Undo events run in reverse order and say so.
	var undone []string
	for _, ev := range rec.events {
		if ev.Type == EventStepFinished && ev.Step.Undoing {
			undone = append(undone, ev.Step.Name)
		}
	}
	if len(undone) != 2 || undone[0] != "step-2" || undone[1] != "step-1" {
		t.Fatalf("undo order: %v", undone)
	}
}

func TestACrashIsResumedByTheNextDaemon(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := newStore(t)
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	first := New(store, registry(), "daemon-a", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0 }))
	first.crashAfterStep = func(i int) bool { return i == 0 }
	var rec recorder
	if _, err := first.Run(ctx, ExerciseKind, exercise(t, dir, 3, 0, Resume), rec.emit); !errors.Is(err, errCrashed) {
		t.Fatalf("want the simulated crash, got %v", err)
	}
	ops, _ := store.List(ctx, 1)
	if len(ops) != 1 || ops[0].Status != state.Applying || ops[0].LeaseOwner != "daemon-a" {
		t.Fatalf("after crash: %+v", ops)
	}

	// While the lease is live, nothing is orphaned.
	early := New(store, registry(), "daemon-b", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0.Add(30 * time.Second) }))
	if n, err := early.Recover(ctx, rec.emit); err != nil || n != 0 {
		t.Fatalf("recover during a live lease: n=%d err=%v", n, err)
	}

	// After it expires, the next daemon resumes from step 2.
	later := New(store, registry(), "daemon-b", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0.Add(2 * time.Minute) }))
	rec = recorder{}
	n, err := later.Recover(ctx, rec.emit)
	if err != nil || n != 1 {
		t.Fatalf("recover: n=%d err=%v", n, err)
	}
	receipt, err := later.ReceiptOf(ctx, ops[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	// The receipt names the daemon that finished it.
	if receipt.Status != state.Succeeded || receipt.Interruptions != 1 || receipt.Owner != "daemon-b" {
		t.Fatalf("receipt: %+v", receipt)
	}
	if receipt.Steps[0].Attempts != 1 || receipt.Steps[1].Attempts != 1 || receipt.Steps[2].Attempts != 1 {
		t.Fatalf("step 1 must not rerun: %+v", receipt.Steps)
	}
	if got := rec.types(); got[0] != EventResumed || got[len(got)-1] != EventFinished {
		t.Fatalf("events: %v", got)
	}
	for n := 1; n <= 3; n++ {
		if !exists(filepath.Join(dir, "step-"+string(rune('0'+n)))) {
			t.Fatalf("step-%d marker missing after resume", n)
		}
	}
}

func TestACrashCanBeCompensatedInstead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := newStore(t)
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	first := New(store, registry(), "daemon-a", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0 }))
	first.crashAfterStep = func(i int) bool { return i == 1 }
	var rec recorder
	if _, err := first.Run(ctx, ExerciseKind, exercise(t, dir, 3, 0, Compensate), rec.emit); !errors.Is(err, errCrashed) {
		t.Fatalf("want the simulated crash, got %v", err)
	}
	later := New(store, registry(), "daemon-b", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0.Add(2 * time.Minute) }))
	if _, err := later.Recover(ctx, rec.emit); err != nil {
		t.Fatal(err)
	}
	ops, _ := store.List(ctx, 1)
	receipt, _ := later.ReceiptOf(ctx, ops[0].ID)
	if receipt.Status != state.Compensated || receipt.Interruptions != 1 {
		t.Fatalf("receipt: %+v", receipt)
	}
	if exists(filepath.Join(dir, "step-1")) || exists(filepath.Join(dir, "step-2")) {
		t.Fatal("steps 1 and 2 must be undone")
	}
	if receipt.Steps[2].Status != state.StepPending {
		t.Fatalf("step 3 never ran: %+v", receipt.Steps[2])
	}
}

// A caller holding only the store reads the receipt the engine would: the
// one a finished operation saved, the journal's view of one still going,
// and state.ErrNotFound for one never recorded.
func TestAStoreAloneReadsTheReceiptTheEngineDoes(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	e := New(store, registry(), "daemon-a")
	finished, err := e.Run(ctx, ExerciseKind, exercise(t, t.TempDir(), 2, 0, Resume), func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	crashed := New(store, registry(), "daemon-a")
	crashed.crashAfterStep = func(i int) bool { return i == 0 }
	var rec recorder
	if _, err := crashed.Run(ctx, ExerciseKind, exercise(t, t.TempDir(), 2, 0, Resume), rec.emit); !errors.Is(err, errCrashed) {
		t.Fatalf("want the simulated crash, got %v", err)
	}
	going := rec.events[0].Operation
	asJSON := func(r *Receipt) string {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	saved, err := ReceiptFromStore(ctx, store, finished.ID)
	if err != nil || asJSON(saved) != asJSON(finished) {
		t.Fatalf("finished operation: %v\n got %s\nwant %s", err, asJSON(saved), asJSON(finished))
	}
	partial, err := ReceiptFromStore(ctx, store, going)
	if err != nil || partial.Status != state.Applying || len(partial.Steps) != 2 ||
		partial.Steps[0].Status != state.StepSucceeded || partial.Steps[1].Status != state.StepPending {
		t.Fatalf("operation still going: %+v %v", partial, err)
	}
	for _, id := range []string{finished.ID, going} {
		fromStore, _ := ReceiptFromStore(ctx, store, id)
		fromEngine, err := e.ReceiptOf(ctx, id)
		if err != nil || asJSON(fromEngine) != asJSON(fromStore) {
			t.Fatalf("%s: the engine read %s (%v), the store %s", id, asJSON(fromEngine), err, asJSON(fromStore))
		}
	}
	if _, err := ReceiptFromStore(ctx, store, "op-never"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("unknown operation from the store: %v", err)
	}
	if _, err := e.ReceiptOf(ctx, "op-never"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("unknown operation from the engine: %v", err)
	}
}

type otherPlan struct{}

func (otherPlan) Kind() string { return ExerciseKind }
func (otherPlan) Plan(context.Context, json.RawMessage) (*Plan, error) {
	return &Plan{Target: "elsewhere", Steps: []Step{{Name: "different", Apply: func(context.Context, io.Writer) error { return nil }}}}, nil
}

func TestAChangedPlanIsNotResumed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := newStore(t)
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	first := New(store, registry(), "daemon-a", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0 }))
	first.crashAfterStep = func(i int) bool { return i == 0 }
	if _, err := first.Run(ctx, ExerciseKind, exercise(t, dir, 2, 0, Resume), func(Event) {}); !errors.Is(err, errCrashed) {
		t.Fatalf("want the simulated crash, got %v", err)
	}
	changed := Registry{}
	changed.Add(otherPlan{})
	later := New(store, changed, "daemon-b", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0.Add(2 * time.Minute) }))
	if _, err := later.Recover(ctx, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	ops, _ := store.List(ctx, 1)
	if ops[0].Status != state.Failed || ops[0].Error != "interrupted, and the plan changed since it started" {
		t.Fatalf("after recover: %+v", ops[0])
	}
}

func TestIDsSortByTimeAndDiffer(t *testing.T) {
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	a, b := NewID(t0), NewID(t0.Add(time.Second))
	if a >= b || len(a) != len("op-20260919-120000-abcde") || a[:19] != "op-20260919-120000-" {
		t.Fatalf("ids %q %q", a, b)
	}
	if NewID(t0) == NewID(t0) {
		t.Fatal("ids at the same instant must differ")
	}
}

type attemptRecorder struct{ attempts []int }

func (attemptRecorder) Kind() string { return "test.attempts" }
func (r *attemptRecorder) Plan(context.Context, json.RawMessage) (*Plan, error) {
	return &Plan{Target: "x", Steps: []Step{{Name: "only", Apply: func(ctx context.Context, _ io.Writer) error {
		r.attempts = append(r.attempts, Attempt(ctx))
		return nil
	}}}}, nil
}

func TestStepsKnowTheirAttempt(t *testing.T) {
	if Attempt(context.Background()) != 0 {
		t.Fatal("no attempt outside a step")
	}
	rec := &attemptRecorder{}
	reg := Registry{}
	reg.Add(rec)
	e := New(newStore(t), reg, "test")
	if _, err := e.Run(context.Background(), "test.attempts", json.RawMessage(`{}`), func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if len(rec.attempts) != 1 || rec.attempts[0] != 1 {
		t.Fatalf("attempts: %v", rec.attempts)
	}
}

func TestAJournalThatNoLongerFitsItsPlanEndsTheOperation(t *testing.T) {
	store := newStore(t)
	e := New(store, registry(), "test")
	ctx := context.Background()
	dir := t.TempDir()
	input := exercise(t, dir, 3, 0, Resume)
	plan, view, err := e.plan(ctx, ExerciseKind, input)
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	// A journal with one step where the plan has three.
	now := e.now()
	if err := store.CreateOperation(ctx, state.NewOperation{ID: "op-short", Kind: ExerciseKind, Target: plan.Target, Input: input, Plan: planJSON,
		PlanDigest: view.Digest, Recovery: string(plan.Recovery), StepNames: []string{"step-1"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	op, err := store.Claim(ctx, "op-short", "test", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := e.apply(ctx, op, plan, view, func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "holds 1 step(s) for a plan of 3") {
		t.Fatalf("receipt: %s %q", receipt.Status, receipt.Error)
	}
	if _, err := os.Stat(filepath.Join(dir, "step-1")); err == nil {
		t.Fatal("a step ran against a journal that doesn't fit")
	}
}

// Recovery must retain ownership while rebuilding and undoing a plan, even
// when either phase lasts longer than the lease originally claimed.
type leaseRecoveryPlan struct {
	planWait func(context.Context) error
	undoWait func(context.Context) error
}

func (leaseRecoveryPlan) Kind() string { return "test.lease-recovery" }
func (d leaseRecoveryPlan) Plan(ctx context.Context, _ json.RawMessage) (*Plan, error) {
	if d.planWait != nil {
		if err := d.planWait(ctx); err != nil {
			return nil, err
		}
	}
	return &Plan{Target: "here", Recovery: Compensate, Steps: []Step{{Name: "only", Apply: func(context.Context, io.Writer) error { return nil }, Undo: func(ctx context.Context, _ io.Writer) error {
		if d.undoWait != nil {
			return d.undoWait(ctx)
		}
		return nil
	}}}}, nil
}
func TestRecoveryRenewsLeaseWhilePlanningAndCompensating(t *testing.T) {
	for _, phase := range []string{"plan", "undo"} {
		t.Run(phase, func(t *testing.T) {
			store := newStore(t)
			reg := Registry{}
			reg.Add(leaseRecoveryPlan{})
			first := New(store, reg, "first", WithClock(func() time.Time { return time.Now().Add(-time.Hour) }))
			first.crashAfterStep = func(int) bool { return true }
			if _, err := first.Run(context.Background(), "test.lease-recovery", nil, func(Event) {}); !errors.Is(err, errCrashed) {
				t.Fatal(err)
			}
			ops, err := store.List(context.Background(), 1)
			if err != nil || len(ops) != 1 {
				t.Fatalf("operations: %v %v", ops, err)
			}
			id := ops[0].ID
			var claimErr error
			wait := func(ctx context.Context) error {
				timer := time.NewTimer(150 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
				}
				_, claimErr = store.Claim(ctx, id, "competitor", time.Now(), time.Now().Add(time.Hour))
				return nil
			}
			d := leaseRecoveryPlan{}
			if phase == "plan" {
				d.planWait = wait
			} else {
				d.undoWait = wait
			}
			reg.Add(d)
			later := New(store, reg, "later", WithLeaseTTL(60*time.Millisecond))
			if n, err := later.Recover(context.Background(), func(Event) {}); err != nil || n != 1 {
				t.Fatalf("recover: %d %v", n, err)
			}
			if !errors.Is(claimErr, state.ErrLeased) {
				t.Fatalf("recovery lost its lease during %s: %v", phase, claimErr)
			}
		})
	}
}

// abandoning plans two steps, or fails to plan when broken, or plans other
// steps when changed, and keeps what Recover tells it it abandons, with the
// operation's status at the time.
type abandoning struct {
	broken, changed bool
	store           *state.Store
	told            *[]string
}

func (abandoning) Kind() string { return "test.abandon" }
func (d abandoning) Plan(context.Context, json.RawMessage) (*Plan, error) {
	if d.broken {
		return nil, errors.New("its input is gone")
	}
	first := "first"
	if d.changed {
		first = "another"
	}
	apply := func(context.Context, io.Writer) error { return nil }
	return &Plan{Target: "here", Steps: []Step{{Name: first, Apply: apply}, {Name: "second", Apply: apply}}}, nil
}
func (d abandoning) Abandon(ctx context.Context, operation, reason string) {
	op, _, err := d.store.Get(ctx, operation)
	if err != nil {
		*d.told = append(*d.told, err.Error())
		return
	}
	*d.told = append(*d.told, fmt.Sprintf("%s %s: %s", operation, op.Status, reason))
}

// An operation Recover ends without applying it again may have left
// something open for its resumed attempt, so its definition is told, while
// the operation is still applying, and nothing is told when it resumes.
func TestRecoverTellsADefinitionWhenItEndsAnOperationWithoutResumingIt(t *testing.T) {
	for _, c := range []struct {
		name            string
		broken, changed bool
		reason          string
	}{
		{name: "resumed"},
		{name: "the plan changed", changed: true, reason: "interrupted, and the plan changed since it started"},
		{name: "the plan can't be rebuilt", broken: true, reason: "interrupted, and the plan can't be rebuilt: plan test.abandon: its input is gone"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			store := newStore(t)
			var told []string
			reg := Registry{}
			reg.Add(abandoning{store: store, told: &told})
			t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
			first := New(store, reg, "daemon-a", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0 }))
			first.crashAfterStep = func(i int) bool { return i == 0 }
			if _, err := first.Run(ctx, "test.abandon", nil, func(Event) {}); !errors.Is(err, errCrashed) {
				t.Fatalf("want the simulated crash, got %v", err)
			}
			ops, _ := store.List(ctx, 1)
			reg.Add(abandoning{broken: c.broken, changed: c.changed, store: store, told: &told})
			later := New(store, reg, "daemon-b", WithLeaseTTL(time.Minute), WithClock(func() time.Time { return t0.Add(2 * time.Minute) }))
			if n, err := later.Recover(ctx, func(Event) {}); err != nil || n != 1 {
				t.Fatalf("recover: n=%d err=%v", n, err)
			}
			receipt, err := later.ReceiptOf(ctx, ops[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if c.reason == "" {
				if receipt.Status != state.Succeeded || len(told) != 0 {
					t.Fatalf("a resumed operation must finish and tell nothing: %s, told %q", receipt.Status, told)
				}
				return
			}
			if receipt.Status != state.Failed || receipt.Error != c.reason {
				t.Fatalf("receipt: %s %q, want failed with %q", receipt.Status, receipt.Error, c.reason)
			}
			if want := []string{ops[0].ID + " " + string(state.Applying) + ": " + c.reason}; strings.Join(told, "\n") != strings.Join(want, "\n") {
				t.Fatalf("told %q, want %q", told, want)
			}
		})
	}
}
