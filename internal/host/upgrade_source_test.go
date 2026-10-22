package host

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/kernel"
)

func TestTheUpgradePlanBindsTheCandidatesBytes(t *testing.T) {
	m, store, u := upgradeCompatibilityFixture(t)
	reg := kernel.Registry{}
	reg.Add(u)
	engine := kernel.New(store, reg, "test")
	input := upgradeInput(t, "/tmp/candidate")
	before, err := engine.PlanOnly(context.Background(), UpgradeKind, input)
	if err != nil {
		t.Fatal(err)
	}
	// Version and capability answers still match, but the executable changed.
	m.write("/tmp/candidate", "different binary with the same version")
	after, err := engine.PlanOnly(context.Background(), UpgradeKind, input)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest == after.Digest {
		t.Fatal("replacing the candidate did not change the approved upgrade digest")
	}
}

func TestUpgradeRefusesChangedBytesBeforeStagingOrSwitching(t *testing.T) {
	for _, step := range []int{0, 1} {
		t.Run([]string{"stage", "switch"}[step], func(t *testing.T) {
			m, _, u := upgradeCompatibilityFixture(t)
			plan, err := u.Plan(context.Background(), upgradeInput(t, "/tmp/candidate"))
			if err != nil {
				t.Fatal(err)
			}
			m.write("/tmp/candidate", "changed after approval")
			err = plan.Steps[step].Apply(context.Background(), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("changed candidate was not refused: %v", err)
			}
			if m.read(BinaryPath) != "old binary" || m.read(PreviousBinary) != "" || m.read(StagedMarker) != "" {
				t.Fatal("changed candidate modified the installed binary or rollback state")
			}
		})
	}
}
