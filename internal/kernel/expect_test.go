package kernel

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/kylebegeman/helios/internal/state"
)

// Reading a plan and applying it are two acts, and the point of naming the
// digest is that nothing may change in between.
func TestRunExpectingAppliesTheNamedPlan(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e := New(newStore(t), registry(), "test-expect")

	view, err := e.PlanOnly(ctx, ExerciseKind, exercise(t, dir, 2, 0, Resume))
	if err != nil {
		t.Fatal(err)
	}
	if view.Digest == "" {
		t.Fatal("a plan has to have a digest to name")
	}
	receipt, err := e.RunExpecting(ctx, ExerciseKind, exercise(t, dir, 2, 0, Resume), view.Digest, func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Succeeded || receipt.PlanDigest != view.Digest {
		t.Fatalf("receipt: %+v", receipt)
	}
}

// A plan that has moved on must not be applied under the old approval, and
// nothing may run before that is noticed.
func TestRunExpectingRefusesAPlanThatMoved(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := newStore(t)
	e := New(store, registry(), "test-expect")

	view, err := e.PlanOnly(ctx, ExerciseKind, exercise(t, dir, 2, 0, Resume))
	if err != nil {
		t.Fatal(err)
	}
	// Apply something that is not what was read: three steps, not two.
	_, err = e.RunExpecting(ctx, ExerciseKind, exercise(t, dir, 3, 0, Resume), view.Digest, func(Event) {
		t.Fatal("nothing may be emitted for a plan that is refused")
	})
	if !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("want ErrPlanChanged, got %v", err)
	}
	for n := 1; n <= 3; n++ {
		if exists(filepath.Join(dir, "step-"+string(rune('0'+n)))) {
			t.Fatalf("step-%d ran despite the refusal", n)
		}
	}
	ops, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("a refused plan recorded %d operation(s)", len(ops))
	}
}

// An empty digest is the ordinary path and must keep working.
func TestRunExpectingWithoutADigestAppliesAsBefore(t *testing.T) {
	dir := t.TempDir()
	e := New(newStore(t), registry(), "test-expect")
	receipt, err := e.RunExpecting(context.Background(), ExerciseKind, exercise(t, dir, 1, 0, Resume), "", func(Event) {})
	if err != nil || receipt.Status != state.Succeeded {
		t.Fatalf("%v %+v", err, receipt)
	}
	if _, err := os.Stat(filepath.Join(dir, "step-1")); err != nil {
		t.Fatal("the step should have run")
	}
}

// Step descriptions can contain command output or multiline input. Those
// bytes must not be mistaken for the separators between different steps.
func TestRunExpectingRefusesDescriptionsThatImpersonateAdditionalSteps(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	ran := false
	apply := func(context.Context, io.Writer) error { ran = true; return nil }
	plan := &Plan{Target: "fixture", Steps: []Step{{Name: "first", Change: "stage\n1\tsecond\tfinish", Apply: apply}}}
	reg := Registry{}
	reg.Add(regressionPlan{plan: plan})
	e := New(store, reg, "test")
	view, err := e.PlanOnly(ctx, regressionPlan{}.Kind(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps = []Step{{Name: "first", Change: "stage", Apply: apply}, {Name: "second", Change: "finish", Apply: apply}}
	_, err = e.RunExpecting(ctx, regressionPlan{}.Kind(), nil, view.Digest, func(Event) {})
	if !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("a different plan passed approval: %v", err)
	}
	if ran {
		t.Fatal("an unapproved step ran")
	}
	ops, err := store.List(ctx, 10)
	if err != nil || len(ops) != 0 {
		t.Fatalf("refused plan journaled: %v %v", ops, err)
	}
}

func TestPlanDigestSeparatesStepNamesAndChanges(t *testing.T) {
	first := &PlanView{Kind: "test", Target: "fixture", Recovery: Resume, Steps: []PlanStepView{{Name: "first\tpart", Change: "last"}}}
	second := &PlanView{Kind: "test", Target: "fixture", Recovery: Resume, Steps: []PlanStepView{{Name: "first", Change: "part\tlast"}}}
	if digestPlan(first) == digestPlan(second) {
		t.Fatal("different step names and changes share an approval")
	}
}

func TestPlanDigestsRetainExistingSimplePlansAndIgnoreNotes(t *testing.T) {
	view := &PlanView{Kind: "test", Target: "fixture", Recovery: Resume, Steps: []PlanStepView{{Index: 0, Name: "first", Change: "stage"}, {Index: 1, Name: "second", Change: "finish"}}}
	const want = "fe96948fcfd6052db63cc45b"
	if got := digestPlan(view); got != want {
		t.Fatalf("existing plan digest changed: got %s, want %s", got, want)
	}
	view.Steps[0].Note = "the world changed"
	if got := digestPlan(view); got != want {
		t.Fatalf("a note changed the approval: got %s, want %s", got, want)
	}
}

func TestPlanDigestDistinguishesLiteralEscapesFromControlCharacters(t *testing.T) {
	view := &PlanView{Kind: "test", Target: "fixture", Recovery: Resume, Steps: []PlanStepView{{Name: "first", Change: "stage\nfinish\t"}}}
	first := digestPlan(view)
	view.Steps[0].Change = `stage\nfinish\t`
	if first == digestPlan(view) {
		t.Fatal("escaped delimiters share an approval with literal text")
	}
}
