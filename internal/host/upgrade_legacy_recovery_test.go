package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

// Seed the journal that 0.7.18 leaves when systemctl restart ends its daemon.
// The exact historical description and digest encoder stay independent of the
// current planner, so this exercises an actual persisted version boundary.
func legacyUpgradeJournal(t *testing.T, store *state.Store, u Upgrade, mutate func(*kernel.PlanView), completed int, legacy bool) (string, string) {
	t.Helper()
	ctx := context.Background()
	input := upgradeInput(t, "/tmp/candidate")
	reg := kernel.Registry{}
	reg.Add(u)
	view, err := kernel.New(store, reg, "planner").PlanOnly(ctx, UpgradeKind, input)
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		view.Steps[1].Change = "put the new binary at " + BinaryPath
	}
	if mutate != nil {
		mutate(view)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", view.Kind, view.Target, view.Recovery)
	names := make([]string, len(view.Steps))
	for i, st := range view.Steps {
		fmt.Fprintf(h, "%d\t%s\t%s\n", st.Index, st.Name, st.Change)
		names[i] = st.Name
	}
	view.Digest = hex.EncodeToString(h.Sum(nil))[:24]
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Hour)
	const id = "op-legacy-upgrade"
	if err := store.CreateOperation(ctx, state.NewOperation{ID: id, Kind: UpgradeKind, Target: BinaryPath, Input: input, Plan: raw, PlanDigest: view.Digest, Recovery: string(kernel.Resume), StepNames: names, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, id, "old-daemon", at, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < completed; i++ {
		if err := store.StepStarted(ctx, id, i, at); err != nil {
			t.Fatal(err)
		}
		if err := store.StepFinished(ctx, id, i, state.StepSucceeded, "", "", at); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.StepStarted(ctx, id, completed, at); err != nil {
		t.Fatal(err)
	}
	return id, view.Digest
}

func TestUpgradeRecoversTheLegacyJournalAfterSwitch(t *testing.T) {
	m, store, u := upgradeCompatibilityFixture(t)
	target := version.Info{Version: "0.8.0-test", Commit: "bbbbbbbbbbbb", OS: "linux", Arch: "amd64"}
	u.Env.RunningVersion = func() version.Info { return target }
	id, digest := legacyUpgradeJournal(t, store, u, nil, 2, true)
	m.write(BinaryPath, "new binary")
	m.write(PreviousBinary, "old binary")
	m.write(StagedMarker, identity(target)+"\n")
	reg := kernel.Registry{}
	reg.Add(u)
	engine := kernel.New(store, reg, "new-daemon")
	if n, err := engine.Recover(context.Background(), func(kernel.Event) {}); err != nil || n != 1 {
		t.Fatalf("recover: %d %v", n, err)
	}
	receipt, err := engine.ReceiptOf(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Succeeded || receipt.PlanDigest != digest {
		t.Fatalf("legacy upgrade did not finish with its original approval: %+v", receipt)
	}
	if m.read(StagedMarker) != "" || m.read(PreviousBinary) != "old binary" || m.ranCommand("systemctl restart") {
		t.Fatal("recovery repeated completed work or retained rollback marker")
	}
	for _, st := range receipt.Steps {
		if st.Status != state.StepSucceeded {
			t.Fatalf("unfinished step: %+v", st)
		}
	}
}

func TestUpgradeLegacyRecoveryDoesNotApproveUnfinishedSwitchOrOtherPlanChanges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		completed int
		mutate    func(*kernel.PlanView)
	}{
		{name: "switch unfinished", completed: 1},
		{name: "stage changed", completed: 2, mutate: func(v *kernel.PlanView) { v.Steps[0].Change += " changed" }},
		{name: "restart changed", completed: 2, mutate: func(v *kernel.PlanView) { v.Steps[2].Change += " changed" }},
		{name: "target changed", completed: 2, mutate: func(v *kernel.PlanView) { v.Target += "-other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, store, u := upgradeCompatibilityFixture(t)
			id, _ := legacyUpgradeJournal(t, store, u, tc.mutate, tc.completed, true)
			reg := kernel.Registry{}
			reg.Add(u)
			engine := kernel.New(store, reg, "new-daemon")
			if _, err := engine.Recover(context.Background(), func(kernel.Event) {}); err != nil {
				t.Fatal(err)
			}
			receipt, err := engine.ReceiptOf(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "plan changed") {
				t.Fatalf("changed legacy plan accepted: %+v", receipt)
			}
			if m.read(BinaryPath) != "old binary" || m.read(PreviousBinary) != "" || m.ranCommand("systemctl restart") {
				t.Fatal("unapproved recovery changed host")
			}
		})
	}
}

func TestUpgradeRecoveryDoesNotDropTheChecksumFromANewApproval(t *testing.T) {
	m, store, u := upgradeCompatibilityFixture(t)
	id, _ := legacyUpgradeJournal(t, store, u, nil, 2, false)
	// The installed binary reports the same build, but its source bytes changed.
	m.write("/tmp/candidate", "different binary with the same version")
	reg := kernel.Registry{}
	reg.Add(u)
	engine := kernel.New(store, reg, "new-daemon")
	if _, err := engine.Recover(context.Background(), func(kernel.Event) {}); err != nil {
		t.Fatal(err)
	}
	receipt, err := engine.ReceiptOf(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "plan changed") {
		t.Fatalf("new approval lost its byte binding: %+v", receipt)
	}
	if m.ranCommand("systemctl restart") {
		t.Fatal("changed candidate was restarted")
	}
}
