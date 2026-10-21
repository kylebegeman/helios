package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// This is the exact separator encoding used by b7f0e37 and older binaries.
// Keep it independent of the current encoder to exercise persisted journals.
func legacyPlanDigestForTest(view *PlanView) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", view.Kind, view.Target, view.Recovery)
	for _, st := range view.Steps {
		fmt.Fprintf(h, "%d\t%s\t%s\n", st.Index, st.Name, st.Change)
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func persistLegacyPlan(t *testing.T, store *state.Store, view *PlanView, at time.Time) string {
	t.Helper()
	ctx := context.Background()
	view.Digest = legacyPlanDigestForTest(view)
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(view.Steps))
	for i, st := range view.Steps {
		names[i] = st.Name
	}
	const id = "op-legacy-fixture"
	if err := store.CreateOperation(ctx, state.NewOperation{ID: id, Kind: view.Kind, Target: view.Target, Input: json.RawMessage(`null`), Plan: raw, PlanDigest: view.Digest, Recovery: string(view.Recovery), StepNames: names, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, id, "old-daemon", at, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRecoveryPreservesUnchangedLegacySpecialCharacterPlans(t *testing.T) {
	for _, recovery := range []Recovery{Resume, Compensate} {
		t.Run(string(recovery), func(t *testing.T) {
			ctx := context.Background()
			store := newStore(t)
			applied, undone := 0, 0
			plan := &Plan{Target: "fixture\\path", Recovery: recovery, Steps: []Step{
				{Name: "first", Change: "reserve\nfixture\tpath", Note: "new observation", Apply: func(context.Context, io.Writer) error { applied++; return nil }, Undo: func(context.Context, io.Writer) error { undone++; return nil }},
				{Name: "second", Change: "complete", Apply: func(context.Context, io.Writer) error { applied++; return nil }},
			}}
			reg := Registry{}
			reg.Add(regressionPlan{plan: plan})
			at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			saved := &PlanView{Kind: regressionPlan{}.Kind(), Target: plan.Target, Recovery: recovery, Steps: []PlanStepView{{Index: 0, Name: "first", Change: plan.Steps[0].Change, Note: "old observation"}, {Index: 1, Name: "second", Change: "complete"}}}
			id := persistLegacyPlan(t, store, saved, at)
			if err := store.StepStarted(ctx, id, 0, at); err != nil {
				t.Fatal(err)
			}
			if err := store.StepFinished(ctx, id, 0, state.StepSucceeded, "", "", at); err != nil {
				t.Fatal(err)
			}
			e := New(store, reg, "new-daemon", WithClock(func() time.Time { return at.Add(time.Minute) }))
			if n, err := e.Recover(ctx, func(Event) {}); err != nil || n != 1 {
				t.Fatalf("recover: %d %v", n, err)
			}
			receipt, err := e.ReceiptOf(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			want := state.Succeeded
			if recovery == Compensate {
				want = state.Compensated
			}
			if receipt.Status != want || receipt.PlanDigest != saved.Digest {
				t.Fatalf("unchanged legacy plan was not recovered with its original digest: %+v", receipt)
			}
			if recovery == Resume && (applied != 1 || undone != 0) || recovery == Compensate && (applied != 0 || undone != 1) {
				t.Fatalf("recovery repeated the wrong work: applied=%d undone=%d", applied, undone)
			}
			op, _, err := store.Get(ctx, id)
			if err != nil || op.PlanDigest != saved.Digest {
				t.Fatalf("persisted approval changed: %+v %v", op, err)
			}
		})
	}
}

func TestRecoveryRefusesLegacySeparatorCollisions(t *testing.T) {
	for _, ordinaryFresh := range []bool{true, false} {
		t.Run(fmt.Sprint(ordinaryFresh), func(t *testing.T) {
			ctx := context.Background()
			store := newStore(t)
			ran := false
			apply := func(context.Context, io.Writer) error { ran = true; return nil }
			saved := &PlanView{Kind: regressionPlan{}.Kind(), Target: "fixture", Recovery: Resume, Steps: []PlanStepView{{Index: 0, Name: "first", Change: "stage\n1\tsecond\tfinish"}}}
			plan := &Plan{Target: "fixture", Recovery: Resume, Steps: []Step{{Name: "first", Change: "stage", Apply: apply}, {Name: "second", Change: "finish", Apply: apply}}}
			if !ordinaryFresh {
				saved.Steps[0].Change = "stage\n1\tsecond\tmiddle"
				saved.Steps = append(saved.Steps, PlanStepView{Index: 1, Name: "second", Change: "finish"})
				plan.Steps[1].Change = "middle\n1\tsecond\tfinish"
			}
			reg := Registry{}
			reg.Add(regressionPlan{plan: plan})
			at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			id := persistLegacyPlan(t, store, saved, at)
			e := New(store, reg, "new-daemon", WithClock(func() time.Time { return at.Add(time.Minute) }))
			if n, err := e.Recover(ctx, func(Event) {}); err != nil || n != 1 {
				t.Fatalf("recover: %d %v", n, err)
			}
			receipt, err := e.ReceiptOf(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if ran || receipt.Status != state.Failed || !strings.Contains(receipt.Error, "plan changed") {
				t.Fatalf("changed legacy plan was accepted: ran=%v receipt=%+v", ran, receipt)
			}
		})
	}
}

func TestEscapedPlanDigestCannotReuseALegacyLiteralEscapeApproval(t *testing.T) {
	view := &PlanView{Kind: "test", Target: "fixture", Recovery: Resume, Steps: []PlanStepView{{Name: "first", Change: `foo\n`}}}
	legacy := legacyPlanDigestForTest(view)
	view.Steps[0].Change = "foo\n"
	if legacy == digestPlan(view) {
		t.Fatal("a legacy literal-escape approval accepts a new plan with a newline")
	}
}
