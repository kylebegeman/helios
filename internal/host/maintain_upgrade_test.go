package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
	"os"
	"path/filepath"
)

func maintainRegistry(m *fakeMachine) kernel.Registry {
	reg := kernel.Registry{}
	reg.Add(Maintain{Env: m.env()})
	reg.Add(Upgrade{Env: m.env()})
	return reg
}

func TestMaintainUpdatesRebootsWhenAskedAndVerifies(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.answers["dpkg-query *"] = ""
	m.answers["apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade"] = "Reading...\n3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
	m.answers["systemctl is-active docker"] = "active"
	m.write("/var/run/reboot-required", "")
	engine := kernel.New(openStore(t), maintainRegistry(m), "test")
	input, _ := json.Marshal(MaintainInput{Reboot: true})
	var lines []string
	receipt, err := engine.Run(context.Background(), MaintainKind, input, func(ev kernel.Event) {
		if ev.Type == kernel.EventStepOutput {
			lines = append(lines, ev.Line)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Succeeded {
		t.Fatalf("receipt: %+v", receipt)
	}
	if !m.ranCommand("apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade") || !m.ranCommand("reboot") || !m.ranCommand("apt-get -y autoremove") {
		t.Fatalf("commands: %v", m.commands())
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "3 upgraded") || !strings.Contains(joined, "rebooting") || !strings.Contains(joined, "doctor: ") {
		t.Fatalf("output:\n%s", joined)
	}
}

func TestMaintainWithoutRebootOnlyReports(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.answers["dpkg-query *"] = ""
	m.answers["systemctl is-active docker"] = "active"
	m.write("/var/run/reboot-required", "")
	engine := kernel.New(openStore(t), maintainRegistry(m), "test")
	var lines []string
	receipt, err := engine.Run(context.Background(), MaintainKind, json.RawMessage(`{}`), func(ev kernel.Event) {
		if ev.Type == kernel.EventStepOutput {
			lines = append(lines, ev.Line)
		}
	})
	if err != nil || receipt.Status != state.Succeeded {
		t.Fatalf("%v %+v", err, receipt)
	}
	if m.ranCommand("reboot") || !strings.Contains(strings.Join(lines, "\n"), "a reboot is pending; run maintain with --reboot") {
		t.Fatalf("commands %v\noutput %v", m.commands(), lines)
	}
}

func TestMaintainFailsWhenTheDoctorFindsSomethingBroken(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.answers["dpkg-query *"] = ""
	m.answers["systemctl is-active docker"] = "active"
	m.answers["ufw status"] = "Status: inactive"
	engine := kernel.New(openStore(t), maintainRegistry(m), "test")
	receipt, err := engine.Run(context.Background(), MaintainKind, json.RawMessage(`{}`), func(kernel.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "firewall: ufw inactive") {
		t.Fatalf("receipt: %+v", receipt)
	}
}

func upgradeInput(t *testing.T, path string) json.RawMessage {
	t.Helper()
	b, _ := json.Marshal(UpgradeInput{Path: path})
	return b
}

func TestUpgradeStagesSwitchesRestartsAndVerifies(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.write(BinaryPath, "old binary")
	m.write("/tmp/bedrock-new", "new binary")
	// The candidate reports the build this test process will "become".
	m.answers["/tmp/bedrock-new version --json"] = `{"version":"0.7.0-test","commit":"aaaaaaaaaaaa","go":"go1.26","os":"linux","arch":"amd64"}`
	m.answers["/tmp/bedrock-new capabilities --json"] = `{"api_version":1,"manifest_version":1,"state_version":1,"min_state_version":0,"max_state_version":1,"capabilities":["kernel.plan.v1","kernel.apply.v1","kernel.expect.v1","state.migrations.v1","upgrade.checkpoint.v1"]}`
	running := m.runningVersion()
	running.Commit = "000000000000"
	env := m.env()
	env.RunningVersion = func() version.Info { return running }
	reg := kernel.Registry{}
	store := openStore(t)
	reg.Add(Upgrade{Env: env, Store: store})
	engine := kernel.New(store, reg, "test")

	view, err := engine.PlanOnly(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/bedrock-new"))
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Steps) != 4 || !strings.Contains(view.Steps[0].Change, "stage 0.7.0-test (aaaaaaaaaaaa)") || view.Steps[0].Note != "replacing 0.7.0-test (000000000000)" {
		t.Fatalf("plan: %+v", view)
	}

	// Run with the old build: stage, switch, and the restart that ends the
	// process. The fake's restart returns, so the step reports it restarted.
	var seen []string
	receipt, err := engine.Run(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/bedrock-new"), func(ev kernel.Event) {
		if ev.Type == kernel.EventStepFinished {
			seen = append(seen, ev.Step.Name+":"+string(ev.Step.Status))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	// After the restart the old build is still "running" here, so verify fails
	// the way it would when the rollback unit had put the old binary back.
	if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "verify: running 0.7.0-test (000000000000), not 0.7.0-test (aaaaaaaaaaaa)") {
		t.Fatalf("receipt: %+v (%v)", receipt, seen)
	}
	if m.read(BinaryPath) != "new binary" || m.read(PreviousBinary) != "old binary" || strings.TrimSpace(m.read(StagedMarker)) != "0.7.0-test@aaaaaaaaaaaa" {
		t.Fatalf("files: bin=%q previous=%q staged=%q", m.read(BinaryPath), m.read(PreviousBinary), m.read(StagedMarker))
	}
	if !m.ranCommand("systemctl restart bedrock.service") {
		t.Fatalf("commands: %v", m.commands())
	}
}

// The plan, its digest and the receipt say what vouched for a downloaded
// build: the release key that signed it, or why it is unsigned.
func TestTheUpgradePlanNamesWhatVouchedForTheBuild(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.write(BinaryPath, "old binary")
	m.write("/tmp/bedrock-new", "new binary")
	m.answers["/tmp/bedrock-new version --json"] = `{"version":"0.7.15","commit":"aaaaaaaaaaaa","go":"go1.26","os":"linux","arch":"amd64"}`
	m.answers["/tmp/bedrock-new capabilities --json"] = `{"api_version":1,"manifest_version":1,"state_version":1,"min_state_version":0,"max_state_version":1,"capabilities":["kernel.plan.v1","kernel.apply.v1","kernel.expect.v1","state.migrations.v1","upgrade.checkpoint.v1"]}`
	reg := kernel.Registry{}
	store := openStore(t)
	reg.Add(Upgrade{Env: m.env(), Store: store})
	engine := kernel.New(store, reg, "test")
	for _, c := range []struct {
		in   UpgradeInput
		want string
	}{
		{UpgradeInput{Path: "/tmp/bedrock-new", Signer: "SHA256:L5pKCki3biS1Qo9z4OnvewnKmMNG9LOj0swiKu+oiG0"}, "stage 0.7.15 (aaaaaaaaaaaa), signed by Helios release key SHA256:L5pKCki3biS1Qo9z4OnvewnKmMNG9LOj0swiKu+oiG0"},
		{UpgradeInput{Path: "/tmp/bedrock-new", Unsigned: "v0.7.14 publishes no SHA256SUMS.sig"}, "stage 0.7.15 (aaaaaaaaaaaa), unsigned (v0.7.14 publishes no SHA256SUMS.sig) and vouched for by its pinned checksum"},
		{UpgradeInput{Path: "/tmp/bedrock-new"}, "stage 0.7.15 (aaaaaaaaaaaa)"},
	} {
		raw, _ := json.Marshal(c.in)
		view, err := engine.PlanOnly(context.Background(), UpgradeKind, raw)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(view.Steps[0].Change, c.want) {
			t.Fatalf("want the stage step to end %q, got %q", c.want, view.Steps[0].Change)
		}
	}
}

func TestUpgradeResumedOnTheNewBuildSucceeds(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.write(BinaryPath, "new binary")
	m.write(PreviousBinary, "old binary")
	m.write(StagedMarker, "0.7.0-test@aaaaaaaaaaaa\n")
	m.write("/tmp/bedrock-new", "new binary")
	m.answers["/tmp/bedrock-new version --json"] = `{"version":"0.7.0-test","commit":"aaaaaaaaaaaa","go":"go1.26","os":"linux","arch":"amd64"}`
	m.answers["/tmp/bedrock-new capabilities --json"] = `{"api_version":1,"manifest_version":1,"state_version":1,"min_state_version":0,"max_state_version":1,"capabilities":["kernel.plan.v1","kernel.apply.v1","kernel.expect.v1","state.migrations.v1","upgrade.checkpoint.v1"]}`
	// This process is the new build now. The plan says so in a note, its
	// digest is unchanged, and the restart step sees no restart to do.
	reg := kernel.Registry{}
	store := openStore(t)
	reg.Add(Upgrade{Env: m.env(), Store: store})
	engine := kernel.New(store, reg, "test")
	view, err := engine.PlanOnly(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/bedrock-new"))
	if err != nil || view.Steps[0].Note != "already the running build" {
		t.Fatalf("%v %+v", err, view)
	}
	receipt, err := engine.Run(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/bedrock-new"), func(kernel.Event) {})
	if err != nil || receipt.Status != state.Succeeded {
		t.Fatalf("%v %+v", err, receipt)
	}
	if m.ranCommand("systemctl restart") {
		t.Fatal("no restart when the new build is already running")
	}
	// Verified: the marker goes, so a crash later is restarted by systemd
	// and never rolled back to the previous build.
	if m.read(StagedMarker) != "" {
		t.Fatalf("the staged marker outlived a verified upgrade: %q", m.read(StagedMarker))
	}
}

func TestTheRollbackScriptOnlyActsOnAFreshUpgrade(t *testing.T) {
	for _, want := range []string{`-f "$lib/staged"`, `-mmin -10`, `rm -f "$lib/staged"`, "the binary stays and systemd restarts it"} {
		if !strings.Contains(RollbackScriptContent, want) {
			t.Errorf("the rollback script lacks %q", want)
		}
	}
}

func TestUpgradeRefusesWrongBinaries(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.write(BinaryPath, "old binary")
	reg := kernel.Registry{}
	store := openStore(t)
	reg.Add(Upgrade{Env: m.env(), Store: store})
	engine := kernel.New(store, reg, "test")
	if _, err := engine.PlanOnly(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/not-bedrock")); err == nil || !strings.Contains(err.Error(), "doesn't run as helios") {
		t.Fatalf("not helios: %v", err)
	}
	m.answers["/tmp/bedrock-mac version --json"] = `{"version":"0.7.1","commit":"bbbbbbbbbbbb","go":"go1.26","os":"darwin","arch":"arm64"}`
	if _, err := engine.PlanOnly(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/bedrock-mac")); err == nil || !strings.Contains(err.Error(), "built for darwin/arm64") {
		t.Fatalf("wrong platform: %v", err)
	}
	if _, err := engine.PlanOnly(context.Background(), UpgradeKind, upgradeInput(t, "relative/path")); err == nil {
		t.Fatal("relative paths must be refused")
	}
}

func TestVerifyAsksTheDaemonWhenThisProcessIsNotIt(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.write(BinaryPath, "old binary")
	m.write("/tmp/bedrock-new", "new binary")
	m.answers["/tmp/bedrock-new version --json"] = `{"version":"0.7.0-test","commit":"aaaaaaaaaaaa","go":"go1.26","os":"linux","arch":"amd64"}`
	m.answers["/tmp/bedrock-new capabilities --json"] = `{"api_version":1,"manifest_version":1,"state_version":1,"min_state_version":0,"max_state_version":1,"capabilities":["kernel.plan.v1","kernel.apply.v1","kernel.expect.v1","state.migrations.v1","upgrade.checkpoint.v1"]}`
	target := m.runningVersion()
	old := target
	old.Commit = "000000000000"
	env := m.env()
	// This process is the old command line; the daemon it restarts is new.
	env.RunningVersion = func() version.Info { return old }
	daemon := func(context.Context) (version.Info, bool) {
		if m.ranCommand("systemctl restart bedrock.service") {
			return target, true
		}
		return old, true
	}
	reg := kernel.Registry{}
	store := openStore(t)
	reg.Add(Upgrade{Env: env, Store: store, DaemonVersion: daemon})
	engine := kernel.New(store, reg, "test")
	receipt, err := engine.Run(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/bedrock-new"), func(kernel.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Succeeded {
		t.Fatalf("receipt: %+v", receipt)
	}
	if _, err := os.Stat(filepath.Join(m.root, StagedMarker)); err == nil {
		t.Fatal("the staged marker outlived a verified upgrade")
	}
}

func TestVerifyTrustsItselfWhenNoDaemonAnswers(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.write(BinaryPath, "old binary")
	m.write("/tmp/bedrock-new", "new binary")
	m.answers["/tmp/bedrock-new version --json"] = `{"version":"0.7.0-test","commit":"aaaaaaaaaaaa","go":"go1.26","os":"linux","arch":"amd64"}`
	m.answers["/tmp/bedrock-new capabilities --json"] = `{"api_version":1,"manifest_version":1,"state_version":1,"min_state_version":0,"max_state_version":1,"capabilities":["kernel.plan.v1","kernel.apply.v1","kernel.expect.v1","state.migrations.v1","upgrade.checkpoint.v1"]}`
	env := m.env() // this process already runs the target build
	reg := kernel.Registry{}
	reg.Add(Upgrade{Env: env, DaemonVersion: func(context.Context) (version.Info, bool) { return version.Info{}, false }})
	engine := kernel.New(openStore(t), reg, "test")
	view, err := engine.PlanOnly(context.Background(), UpgradeKind, upgradeInput(t, "/tmp/bedrock-new"))
	if err != nil {
		t.Fatal(err)
	}
	if view.Steps[0].Note != "already the running build" {
		t.Fatalf("with no daemon answering, this process's build is the running one: %+v", view.Steps[0])
	}
}
