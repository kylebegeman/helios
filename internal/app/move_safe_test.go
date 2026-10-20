package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func safeMoveFixture(t *testing.T) (*state.Store, *manifest.Manifest, Handoff, string) {
	t.Helper()
	store := goldenStore(t)
	m := &manifest.Manifest{App: "site", Workloads: map[string]manifest.Workload{
		"web":    {Kind: manifest.Web, Image: "site:old", Port: 80, Routes: []manifest.Route{{Host: "site.example.com"}}},
		"worker": {Kind: manifest.Worker, Image: "site:old"},
		"cron":   {Kind: manifest.Cron, Image: "site:old", Schedule: "0 0 * * *"},
	}}
	dir := t.TempDir()
	data, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	h := Handoff{App: m.App, From: "source", To: "target", Migration: "move-0123456789abcdef", Phase: "final", Revision: "source-r1", ManifestDigest: manifestDigest(m)}
	return store, m, h, dir
}

func addMoveWriter(fake *dockertest.Server, name, role string, running bool) {
	c := dockertest.Container{Name: name, Running: running, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: "site", docker.LabelWorkload: role}}
	c.HostConfig.RestartPolicy.Name = "unless-stopped"
	fake.Add(c)
}

func TestMoveFinalFenceIsDurableAcrossStartupAndNeverAutomaticallyResumes(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, _ := safeMoveFixture(t)
	for _, role := range []string{"web", "worker", "cron", objectsWorkload} {
		addMoveWriter(fake, "bedrock-site-"+role+"-r1", role, true)
	}
	addMoveWriter(fake, "bedrock-site-web-stopped", "web", false)
	addMoveWriter(fake, "bedrock-site-postgres", postgresWorkload, true)
	e, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := fenceMigration(ctx, e, store.Path(), m, h, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"web", "worker", "cron", objectsWorkload} {
		c, _ := fake.Container("bedrock-site-" + role + "-r1")
		if c.Running || c.HostConfig.RestartPolicy.Name != "no" {
			t.Fatalf("writer %s was not reboot-fenced: %+v", role, c)
		}
	}
	if c, _ := fake.Container("bedrock-site-postgres"); !c.Running {
		t.Fatal("dump database was stopped")
	}
	// No in-memory fence is needed: a fresh state reader still excludes jobs.
	if err := CheckMigrationAccess(store.Path(), m.App); err == nil {
		t.Fatal("fresh data command admitted behind persistent fence")
	}
	if unlock, err := AcquireDataAccess(ctx, store.Path(), m.App); err == nil {
		unlock()
		t.Fatal("operator/job entrypoint ignored migration fence")
	}
	// Simulate an external policy restart before daemon startup; enforcement
	// stops it again without restoring the original automatic policy.
	fake.Update("bedrock-site-web-r1", func(c *dockertest.Container) { c.Running = true; c.HostConfig.RestartPolicy.Name = "always" })
	if err := EnforceMigrationFences(ctx, store.Path()); err != nil {
		t.Fatal(err)
	}
	if err := RecoverBackupPauses(ctx, store.Path()); err != nil {
		t.Fatal(err)
	}
	if c, _ := fake.Container("bedrock-site-web-r1"); c.Running || c.HostConfig.RestartPolicy.Name != "no" {
		t.Fatal("startup resumed frozen source")
	}
	if err := fenceMigration(ctx, e, store.Path(), m, h, io.Discard); err != nil {
		t.Fatalf("replayed fence: %v", err)
	}
	record, err := readMigration(store.Path(), m.App)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumeMigration(ctx, e, store.Path(), record); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"web", "worker", "cron", objectsWorkload} {
		c, _ := fake.Container("bedrock-site-" + role + "-r1")
		if !c.Running || c.HostConfig.RestartPolicy.Name != "unless-stopped" {
			t.Fatalf("deliberate resume lost %s policy", role)
		}
	}
	if c, _ := fake.Container("bedrock-site-web-stopped"); c.Running {
		t.Fatal("resume started a writer that was previously stopped")
	}
	if err := CheckMigrationAccess(store.Path(), m.App); err != nil {
		t.Fatal(err)
	}
}

func TestMoveFenceFailureRetainsDurableExclusion(t *testing.T) {
	fake := dockertest.New(t)
	store, m, h, _ := safeMoveFixture(t)
	addMoveWriter(fake, "bedrock-site-web-r1", "web", true)
	addMoveWriter(fake, "bedrock-site-worker-r1", "worker", true)
	fake.Update("bedrock-site-web-r1", func(c *dockertest.Container) { c.ExitCode = 137 })
	e, err := docker.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := fenceMigration(context.Background(), e, store.Path(), m, h, io.Discard); err == nil {
		t.Fatal("unclean stop accepted for final snapshot")
	}
	if err := CheckMigrationAccess(store.Path(), m.App); err == nil {
		t.Fatal("failed final capture lost its fence")
	}
	if c, _ := fake.Container("bedrock-site-web-r1"); c.Running || c.HostConfig.RestartPolicy.Name != "no" {
		t.Fatal("failed fence resumed writer")
	}
	if c, _ := fake.Container("bedrock-site-worker-r1"); c.Running || c.HostConfig.RestartPolicy.Name != "no" {
		t.Fatal("one writer's failure left another writer accepting data")
	}
	// The daemon must start so an operator can explicitly resume or remove
	// the source, while another final capture still refuses the unclean stop.
	if err := EnforceMigrationFences(context.Background(), store.Path()); err != nil {
		t.Fatalf("safely stopped unclean writer prevented daemon startup: %v", err)
	}
	if err := CheckMigrationAccess(store.Path(), m.App); err == nil {
		t.Fatal("startup admitted writes after an unclean capture")
	}
	if err := fenceMigration(context.Background(), e, store.Path(), m, h, io.Discard); err == nil {
		t.Fatal("startup made an unclean final capture safe")
	}
	record, err := readMigration(store.Path(), m.App)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumeMigration(context.Background(), e, store.Path(), record); err != nil {
		t.Fatalf("deliberate recovery of an unclean writer: %v", err)
	}
	if c, _ := fake.Container("bedrock-site-web-r1"); !c.Running || c.HostConfig.RestartPolicy.Name != "unless-stopped" {
		t.Fatal("deliberate recovery lost the original writer state")
	}
}

func TestMoveStageDoesNotActivateRoutesDNSWorkersOrReleaseJobs(t *testing.T) {
	dockertest.New(t)
	store, m, h, dir := safeMoveFixture(t)
	stage := MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}, Hostname: func() string { return "target" }}
	in := MoveStageInput{Source: dir, Revision: MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(in)
	plan, err := stage.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Name == "switch" || step.Name == "dns" || step.Name == "certificates" || step.Name == "verify" || step.Name == "release" || step.Name == "retire" {
			t.Fatalf("staging admitted %s", step.Name)
		}
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if active, err := store.ActiveRevisions(context.Background()); err != nil || len(active) != 0 {
		t.Fatal("staging fence created active routes")
	}
	if err := CheckMigrationAccess(store.Path(), m.App); err == nil {
		t.Fatal("target admitted operator writes before staging")
	}
	// Replanned pending staging carries the same source/target/revision binding.
	reg := kernel.Registry{}
	reg.Add(stage)
	engine := kernel.New(store, reg, "test")
	first, err := engine.PlanOnly(context.Background(), MoveStageKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.PlanOnly(context.Background(), MoveStageKind, raw)
	if err != nil || first.Digest != second.Digest {
		t.Fatalf("stage digest changed: %v", err)
	}
	changed := in
	changed.Revision = "different-r1"
	other, _ := json.Marshal(changed)
	if _, err := stage.Plan(context.Background(), other); err == nil {
		t.Fatal("a different target revision reused reserved data")
	}
	changed = in
	changed.Handoff.Phase = "rehearsal"
	other, _ = json.Marshal(changed)
	if _, err := stage.Plan(context.Background(), other); err == nil {
		t.Fatal("rehearsal snapshot accepted as final source fence")
	}
}

func TestMoveStagePreservesUploadedCommitAndRefusesActualCheckoutMismatch(t *testing.T) {
	store, _, h, dir := safeMoveFixture(t)
	h.SourceCommit = strings.Repeat("a", 40)
	stage := MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return "target" }}
	input := MoveStageInput{Source: dir, Revision: MoveTargetRevision(h), Commit: h.SourceCommit, Handoff: h}
	raw, _ := json.Marshal(input)
	if _, err := stage.Plan(context.Background(), raw); err != nil {
		t.Fatalf("preserved uploaded commit: %v", err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	git("init", "-q")
	git("add", manifest.FileName)
	git("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "fixture")
	if _, err := stage.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "checkout") {
		t.Fatalf("checkout mismatch accepted: %v", err)
	}
	input.Commit = ""
	raw, _ = json.Marshal(input)
	if _, err := stage.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "captured source commit") {
		t.Fatalf("source mismatch accepted: %v", err)
	}
}

func TestMoveResumeRequiresExplicitTargetStopAndReplaysAfterFenceRemoval(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, _ := safeMoveFixture(t)
	addMoveWriter(fake, "bedrock-site-web-r1", "web", true)
	e, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := fenceMigration(ctx, e, store.Path(), m, h, io.Discard); err != nil {
		t.Fatal(err)
	}
	resume := MoveResume{Store: store}
	input := MoveResumeInput{App: m.App, Migration: h.Migration}
	raw, _ := json.Marshal(input)
	if _, err := resume.Plan(ctx, raw); err == nil {
		t.Fatal("source resume omitted target-stopped assertion")
	}
	input.TargetStopped = true
	raw, _ = json.Marshal(input)
	plan, err := resume.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	replayed, err := resume.Plan(ctx, raw)
	if err != nil {
		t.Fatalf("removed fence lost recovery plan: %v", err)
	}
	if err := replayed.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(migrationFile(store.Path(), m.App)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed resume retained active fence")
	}
}

func TestMoveCutoverRequiresAValidatedPinnedTarget(t *testing.T) {
	store, m, h, _ := safeMoveFixture(t)
	rev := MoveTargetRevision(h)
	rawManifest, _ := json.Marshal(m)
	if err := store.SaveRevision(context.Background(), state.Revision{App: m.App, ID: rev, Status: revisionStaged, Manifest: rawManifest, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: "restoring", TargetRevision: rev}); err != nil {
		t.Fatal(err)
	}
	cutover := MoveCutover{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}}
	input := MoveCutoverInput{App: m.App, Migration: h.Migration, Revision: rev}
	raw, _ := json.Marshal(input)
	if _, err := cutover.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatalf("unfinished stage admitted cutover: %v", err)
	}
	input.Snapshot = strings.Repeat("b", 64)
	raw, _ = json.Marshal(input)
	if _, err := cutover.Plan(context.Background(), raw); err == nil {
		t.Fatal("different final snapshot accepted")
	}
}

func TestMoveStageStartsOnlyServingContainersWithoutPublicActivation(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	fake.Add(dockertest.Container{Name: "image-holder", Image: "site:old"})
	store, m, h, dir := safeMoveFixture(t)
	stage := MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}, Hostname: func() string { return "target" }}
	input := MoveStageInput{Source: dir, Revision: MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(input)
	plan, err := stage.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if err := step.Apply(ctx, io.Discard); err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
		if step.Name == "stage-start" {
			break
		}
	}
	if c, ok := fake.Container(docker.ContainerName(m.App, "web", input.Revision)); !ok || !c.Running || c.HostConfig.RestartPolicy.Name == "unless-stopped" {
		t.Fatalf("staged web missing or reboot-enabled: %+v", c)
	}
	for _, role := range []string{"worker", "cron"} {
		if _, ok := fake.Container(docker.ContainerName(m.App, role, input.Revision)); ok {
			t.Fatalf("background %s started during staging", role)
		}
	}
	if active, err := store.ActiveRevisions(ctx); err != nil || len(active) != 0 {
		t.Fatal("staged serving container became active routing")
	}
	for _, call := range fake.Calls() {
		if strings.Contains(call, "bedrock-edge") && strings.Contains(call, "exec") {
			t.Fatal("staging reloaded public edge")
		}
	}
}

func TestStandaloneDNSPointCannotBypassMigrationFence(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			store, m, h, _ := safeMoveFixture(t)
			sec := newSecrets(t)
			if _, _, err := integration.Set(sec, integration.CloudflareName, map[string]string{"token": "token"}); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(m)
			if err := store.SaveRevision(context.Background(), state.Revision{App: m.App, ID: h.Revision, Status: revisionStaged, Manifest: data, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			phase := "staged"
			if role == "source" {
				phase = "fenced"
			}
			if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: role, Phase: phase, TargetRevision: h.Revision}); err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(PointInput{Host: "site.example.com"})
			for _, allow := range []string{"", "move-ffffffffffffffff"} {
				point := Point{Store: store, Secrets: sec, AllowMigration: allow}
				if _, err := point.Plan(context.Background(), input); err == nil || !strings.Contains(err.Error(), "fenced") {
					t.Fatalf("standalone/mismatch admitted DNS: %v", err)
				}
			}
			point := Point{Store: store, Secrets: sec, AllowMigration: h.Migration}
			_, err := point.Plan(context.Background(), input)
			if role == "source" && err == nil {
				t.Fatal("matching ID bypassed source fence")
			}
			if role == "target" && err != nil {
				t.Fatalf("validated internal cutover blocked: %v", err)
			}
		})
	}
}

func TestSafeMoveRequiresFullFinalSnapshotIdentity(t *testing.T) {
	_, _, h, _ := safeMoveFixture(t)
	h.HasData = true
	for _, snapshot := range []string{"latest", "abcd1234", strings.Repeat("f", 63), strings.Repeat("g", 64)} {
		h.Snapshot = snapshot
		if err := checkMigrationHandoff(h, "target", "final"); err == nil {
			t.Fatalf("nonexact recovery point %q accepted", snapshot)
		}
	}
	h.Snapshot = strings.Repeat("f", 64)
	if err := checkMigrationHandoff(h, "target", "final"); err != nil {
		t.Fatal(err)
	}
}

func TestMoveStageRefusesUntrackedDestinationWritersBeforeRestoring(t *testing.T) {
	fake := dockertest.New(t)
	store, _, h, dir := safeMoveFixture(t)
	addMoveWriter(fake, "bedrock-site-worker-orphan", "worker", true)
	stage := MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return "target" }}
	raw, _ := json.Marshal(MoveStageInput{Source: dir, Revision: MoveTargetRevision(h), Handoff: h})
	plan, err := stage.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err == nil {
		t.Fatal("orphan destination writer admitted during restore")
	}
	if record, err := readMigration(store.Path(), h.App); err != nil || record != nil {
		t.Fatal("target was reserved before unsafe orphan was refused")
	}
}

func TestMoveFinalCapturePinsStorageAndRefusesChangedBucket(t *testing.T) {
	ctx := context.Background()
	store, m, _, _ := safeMoveFixture(t)
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}}
	data, _ := json.Marshal(m)
	rev := state.Revision{App: m.App, ID: "source-r1", Status: state.RevisionActive, Manifest: data, CreatedAt: time.Now()}
	if err := store.SaveRevision(ctx, rev); err != nil {
		t.Fatal(err)
	}
	sec := newSecrets(t)
	setStorage := func(prefix string) {
		t.Helper()
		if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "https://storage.example.com", "key_id": "fixture", "key": "fixture", "bucket_prefix": prefix, "password": "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	setStorage("source")
	capture := MoveCapture{Backup: Backup{Store: store, Secrets: sec, StateDir: filepath.Dir(store.Path())}}
	input, err := MoveCaptureInputFor(ctx, store, m.App, "source", "target", true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(input)
	plan, err := capture.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, step := range plan.Steps {
		if step.Name == "snapshot" {
			found = strings.Contains(step.Change, "source-site")
		}
	}
	if !found {
		t.Fatal("reviewed final capture omits the storage bucket")
	}
	h := migrationHandoff(&rev, m, input)
	h.Bucket = "source-site"
	if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "source", Phase: "fenced"}); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Plan(ctx, raw); err != nil {
		t.Fatalf("unchanged bucket cannot resume: %v", err)
	}
	setStorage("changed")
	if _, err := capture.Plan(ctx, raw); err == nil {
		t.Fatal("frozen capture resumed against a different bucket")
	}
}

func TestStandaloneRestoreCannotEnterAStagedMigration(t *testing.T) {
	store, _, h, _ := safeMoveFixture(t)
	if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: "restoring", TargetRevision: MoveTargetRevision(h)}); err != nil {
		t.Fatal(err)
	}
	r := RestoreDef{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}
	if _, err := r.Plan(context.Background(), json.RawMessage(`{"app":"site"}`)); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("standalone restore entered reserved data: %v", err)
	}
}

func TestMoveCutoverKeepsManualDNSUnderOperatorControl(t *testing.T) {
	store, m, h, _ := safeMoveFixture(t)
	revision := MoveTargetRevision(h)
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(context.Background(), state.Revision{App: m.App, ID: revision, Status: revisionStaged, Manifest: data, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: "staged", TargetRevision: revision}); err != nil {
		t.Fatal(err)
	}
	c := MoveCutover{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}}
	raw, _ := json.Marshal(MoveCutoverInput{App: m.App, Migration: h.Migration, Revision: revision})
	plan, err := c.Plan(context.Background(), raw)
	if err != nil {
		t.Fatalf("manual DNS wrongly requires Cloudflare: %v", err)
	}
	for _, step := range plan.Steps {
		if strings.HasPrefix(step.Name, "dns-") {
			t.Fatal("cutover planned a change to a manual DNS record")
		}
	}
}

func TestMoveRehearsalFailureCompensatesScratchAndCandidateRevision(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, dir := safeMoveFixture(t)
	h.Phase = "rehearsal"
	fake.OnCreate = func(c dockertest.Container) {
		if strings.Contains(c.Name, ".workload.web") {
			fake.Update(c.Name, func(c *dockertest.Container) { c.ExitAfter = 1; c.ExitCode = 42 })
		}
	}
	// An ordinary drill name is unrelated to this test's reservation.
	fake.Add(dockertest.Container{Name: "bedrock-site.drill.web", Running: true})
	input := MoveStageInput{Source: dir, Revision: "test-" + MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(input)
	reg := kernel.Registry{}
	reg.Add(MoveTest{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}, Hostname: func() string { return "target" }})
	engine := kernel.New(store, reg, "test")
	receipt, err := engine.Run(ctx, MoveTestKind, raw, func(kernel.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Compensated || !strings.Contains(receipt.Error, "exit code 42") {
		t.Fatalf("scratch failure was not compensated: %+v", receipt)
	}
	if _, err := store.GetRevision(ctx, m.App, input.Revision); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("candidate revision survived failed proof: %v", err)
	}
	if c, exists := fake.Container("bedrock-site.drill.web"); !exists || !c.Running {
		t.Fatal("compensation changed an unrelated normal drill")
	}
	if got := fake.NetworkNames(); len(got) != 0 {
		t.Fatalf("scratch networks survived: %v", got)
	}
	if run, err := store.LastBackupRun(ctx, m.App, state.BackupRunDrill); err != nil || run == nil || !run.Finished() || run.OK {
		t.Fatalf("failed rehearsal has no honest result: %+v, %v", run, err)
	}
}

func TestMoveRehearsalCompensationSurvivesRemovedSourceAndLaterAppActivation(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, dir := safeMoveFixture(t)
	h.Phase = "rehearsal"
	test := MoveTest{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}, Hostname: func() string { return "target" }}
	input := MoveStageInput{Source: dir, Revision: "test-" + MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(input)
	plan, err := test.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Recovery != kernel.Compensate || plan.Steps[0].Undo == nil {
		t.Fatal("interrupted rehearsal has no durable compensation step")
	}
	for _, step := range plan.Steps[:2] {
		if err := step.Apply(ctx, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	workspace := filepath.Join(filepath.Dir(store.Path()), "moves", m.App, "tests", input.Revision)
	names := rehearsalNames(workspace, m, "move-test-"+input.Revision)
	fake.Add(dockertest.Container{Name: names.containers["web"], Running: true, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: m.App, docker.LabelWorkload: "web"}})
	fake.Add(dockertest.Container{Name: "bedrock-site-web-live", Running: true})
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: "live", Status: state.RevisionActive, Manifest: data, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	recovered, err := test.Plan(ctx, raw)
	if err != nil {
		t.Fatalf("source cleanup prevents compensation: %v", err)
	}
	if planText(recovered) != planText(plan) {
		t.Fatal("captured reservation changed recovery plan identity")
	}
	if err := recovered.Steps[0].Undo(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, exists := fake.Container(names.containers["web"]); exists {
		t.Fatal("scratch writer survived compensation")
	}
	if _, exists := fake.Container("bedrock-site-web-live"); !exists {
		t.Fatal("compensation removed live app writer")
	}
	if _, err := store.GetRevision(ctx, m.App, "live"); err != nil {
		t.Fatal("compensation forgot later active app history")
	}
	if _, err := os.Stat(workspace + ".json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful compensation retained its reservation")
	}
}

func TestMoveRehearsalCleanupRefusesForeignContainersAndReportsFailures(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, dir := safeMoveFixture(t)
	h.Phase = "rehearsal"
	test := MoveTest{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}, Hostname: func() string { return "target" }}
	input := MoveStageInput{Source: dir, Revision: "test-" + MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(input)
	plan, err := test.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(filepath.Dir(store.Path()), "moves", m.App, "tests", input.Revision)
	names := rehearsalNames(workspace, m, "move-test-"+input.Revision)
	fake.Add(dockertest.Container{Name: names.containers["web"], Running: true})
	if err := plan.Steps[0].Undo(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "another container") {
		t.Fatalf("foreign scratch name silently removed: %v", err)
	}
	if _, err := os.Stat(workspace + ".json"); err != nil {
		t.Fatal("failed cleanup lost its recovery reservation")
	}
	if c, exists := fake.Container(names.containers["web"]); !exists || !c.Running {
		t.Fatal("foreign container changed during refusal")
	}
}

func TestMoveRehearsalSuccessRemovesScratchAndRecordsPinnedSnapshot(t *testing.T) {
	fake := dockertest.New(t)
	store, m, h, dir := safeMoveFixture(t)
	web := m.Workloads["web"]
	web.Health = &manifest.Health{Command: []string{"true"}}
	m.Workloads["web"] = web
	data, _ := yaml.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	h.Phase, h.ManifestDigest = "rehearsal", manifestDigest(m)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	createdWeb := false
	fake.OnCreate = func(c dockertest.Container) {
		if strings.Contains(c.Name, ".workload.web") {
			createdWeb = true
		}
		if strings.Contains(c.Name, ".workload.worker") || strings.Contains(c.Name, ".workload.cron") {
			t.Error("rehearsal admitted a background workload")
		}
	}
	test := MoveTest{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}, Hostname: func() string { return "target" }}
	input := MoveStageInput{Source: dir, Revision: "test-" + MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(input)
	reg := kernel.Registry{}
	reg.Add(test)
	receipt, err := kernel.New(store, reg, "test").Run(context.Background(), MoveTestKind, raw, func(kernel.Event) {})
	if err != nil || receipt.Status != state.Succeeded || !createdWeb {
		t.Fatalf("private rehearsal failed: %+v, %v, created web %v", receipt, err, createdWeb)
	}
	if len(fake.NetworkNames()) != 0 || len(fake.VolumeNames()) != 0 {
		t.Fatal("successful rehearsal left scratch resources")
	}
	if _, err := store.GetRevision(context.Background(), m.App, input.Revision); !errors.Is(err, state.ErrNotFound) {
		t.Fatal("successful rehearsal retained candidate revision")
	}
	if run, err := store.LastBackupRun(context.Background(), m.App, state.BackupRunDrill); err != nil || run == nil || !run.OK || run.Snapshot != h.Snapshot {
		t.Fatalf("successful rehearsal lacks its exact result: %+v, %v", run, err)
	}
}

func TestMoveRehearsalPinsOriginalCredentialsBeforeScratchDatabase(t *testing.T) {
	fake := dockertest.New(t)
	store, m, h, dir := safeMoveFixture(t)
	m.Data = &manifest.Data{Postgres: &manifest.Postgres{Version: "16"}}
	data, _ := yaml.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	h.Phase, h.HasData, h.Bucket, h.Snapshot, h.ManifestDigest = "rehearsal", true, "fixture-site", strings.Repeat("a", 64), manifestDigest(m)
	sec := newSecrets(t)
	if _, err := sec.Set(m.App, postgresPasswordName, "original"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "https://storage.example.com", "key_id": "fixture", "key": "fixture", "bucket_prefix": "fixture", "password": "fixture"}); err != nil {
		t.Fatal(err)
	}
	test := MoveTest{Deploy: Deploy{Store: store, Secrets: sec, StateDir: filepath.Dir(store.Path())}, Hostname: func() string { return "target" }}
	input := MoveStageInput{Source: dir, Revision: "test-" + MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(input)
	plan, err := test.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	pinned := false
	var database kernel.Step
	for _, step := range plan.Steps {
		if step.Name == "database" {
			database = step
			break
		}
		if step.Name == "restore" {
			continue // Transfer is separate; exercise the scratch service boundary.
		}
		if err := step.Apply(context.Background(), io.Discard); err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
		if step.Name == "pin-test-images" {
			pinned = true
		}
	}
	if !pinned || database.Apply == nil {
		t.Fatal("scratch database has no pinned candidate")
	}
	if _, err := sec.Set(m.App, postgresPasswordName, "changed-after-pin"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	created := false
	fake.OnCreate = func(c dockertest.Container) {
		if strings.HasSuffix(c.Name, ".postgres") {
			created = true
			if !strings.Contains(strings.Join(c.Env, "\n"), "POSTGRES_PASSWORD=original") {
				t.Error("scratch database lost its original pinned credentials")
			}
			cancel() // Stop before readiness; no real database is needed here.
		}
	}
	if err := database.Apply(ctx, io.Discard); err == nil || !created {
		t.Fatalf("scratch database did not reach its pinned credential boundary: %v, created %v", err, created)
	}
	if err := plan.Steps[0].Undo(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestCompletedMoveTargetCanBecomeSourceOfReverseMove(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, prior, _ := safeMoveFixture(t)
	revision := MoveTargetRevision(prior)
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: revision, Status: state.RevisionActive, Manifest: data, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := saveMigration(store.Path(), &migrationRecord{Handoff: prior, Role: "target", Phase: "cutover", TargetRevision: revision}); err != nil {
		t.Fatal(err)
	}
	addMoveWriter(fake, "bedrock-site-web-live", "web", true)
	capture := MoveCapture{Backup: Backup{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path())}}
	for _, final := range []bool{false, true} {
		input, err := MoveCaptureInputFor(ctx, store, m.App, "target", "source", final)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(input)
		plan, err := capture.Plan(ctx, raw)
		if err != nil {
			t.Fatalf("completed destination cannot move again (final=%v): %v", final, err)
		}
		for _, step := range plan.Steps {
			if err := step.Apply(ctx, io.Discard); err != nil {
				t.Fatalf("%s: %v", step.Name, err)
			}
		}
	}
	record, err := readMigration(store.Path(), m.App)
	if err != nil || record == nil || record.Role != "source" || record.Phase != "captured" || record.Handoff.From != "target" || record.Handoff.To != "source" {
		t.Fatalf("reverse final capture did not retain the new source fence: %+v, %v", record, err)
	}
	if c, _ := fake.Container("bedrock-site-web-live"); c.Running || c.HostConfig.RestartPolicy.Name != "no" {
		t.Fatal("reverse capture left destination writes enabled")
	}
	archive := filepath.Join(filepath.Dir(store.Path()), "moves", m.App, "completed", prior.Migration+".json")
	if _, err := os.Stat(archive); err != nil {
		t.Fatal("reverse capture discarded prior cutover history")
	}
}

func TestMoveFinalCaptureFailureRecordsFailureAndKeepsSourceFenced(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, _, _ := safeMoveFixture(t)
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}}
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: "source-r1", Status: state.RevisionActive, Manifest: data, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	addMoveWriter(fake, "bedrock-site-web-live", "web", true)
	sec := newSecrets(t)
	setStorage := func(prefix string) {
		t.Helper()
		if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "https://storage.example.com", "key_id": "fixture", "key": "fixture", "bucket_prefix": prefix, "password": "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	setStorage("source")
	capture := MoveCapture{Backup: Backup{Store: store, Secrets: sec, StateDir: filepath.Dir(store.Path())}}
	input, err := MoveCaptureInputFor(ctx, store, m.App, "source", "target", true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(input)
	plan, err := capture.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Name == "snapshot" {
			setStorage("changed")
			if err := step.Apply(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "storage bucket changed") {
				t.Fatalf("capture used changed storage: %v", err)
			}
			break
		}
		if err := step.Apply(ctx, io.Discard); err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
	}
	if run, err := store.LastBackupRun(ctx, m.App, state.BackupRunBackup); err != nil || run == nil || !run.Finished() || run.OK {
		t.Fatalf("failed final snapshot is still reported as running: %+v, %v", run, err)
	}
	if err := CheckMigrationAccess(store.Path(), m.App); err == nil {
		t.Fatal("capture failure removed the source fence")
	}
	if c, _ := fake.Container("bedrock-site-web-live"); c.Running || c.HostConfig.RestartPolicy.Name != "no" {
		t.Fatal("capture failure resumed source writers")
	}
}

func TestMoveStageCannotRegressCutoverWriterAuthority(t *testing.T) {
	for _, phase := range []string{"cutting-over", "cutover"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			store, m, h, dir := safeMoveFixture(t)
			in := MoveStageInput{Source: dir, Revision: MoveTargetRevision(h), Handoff: h}
			stage := MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return "target" }}
			raw, _ := json.Marshal(in)
			plan, err := stage.Plan(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: phase, TargetRevision: in.Revision}); err != nil {
				t.Fatal(err)
			}
			if err := plan.Steps[0].Apply(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "cutover") {
				t.Fatalf("reviewed staging can regress %s writer authority: %v", phase, err)
			}
			if _, err := stage.Plan(ctx, raw); err == nil || !strings.Contains(err.Error(), "cutover") {
				t.Fatalf("staging can regress %s writer authority: %v", phase, err)
			}
			record, err := readMigration(store.Path(), m.App)
			if err != nil || record.Phase != phase {
				t.Fatalf("rejected staging changed authority: %+v, %v", record, err)
			}
		})
	}
}

// The edge holds a host to the strictest origin pull any app here asks of
// it, so a moved app asking less of a host that another app requires still
// lands behind a check the target's edge needs a CA for.
func TestAMoveOntoAHostAnotherAppRequiresWaitsForTheTargetToTrustItsCA(t *testing.T) {
	for name, mode := range map[string]manifest.OriginPullMode{"optional": manifest.OriginPullOptional, "off": manifest.OriginPullOff} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			host := "site.example.com"
			store, m, h, dir := safeMoveFixture(t)
			w := m.Workloads["web"]
			w.Routes = []manifest.Route{{Host: host, DNS: manifest.DNSProxied, OriginPull: mode}}
			m.Workloads["web"] = w
			writeManifestFile(t, dir, m)
			h.ManifestDigest = manifestDigest(m)
			api := &manifest.Manifest{App: "api", Workloads: map[string]manifest.Workload{"web": {Kind: manifest.Web, Image: "api:1", Port: 8080,
				Routes: []manifest.Route{{Host: host, Path: "/api", DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullRequired}}}}}
			if err := api.Validate(); err != nil {
				t.Fatal(err)
			}
			saveActive(t, store, api)
			sec := newSecrets(t)
			if _, _, err := integration.Set(sec, integration.CloudflareName, map[string]string{"token": "token"}); err != nil {
				t.Fatal(err)
			}
			revision := MoveTargetRevision(h)
			stage := MoveStage{Deploy: Deploy{Store: store, Secrets: sec}, Hostname: func() string { return "target" }}
			staging, _ := json.Marshal(MoveStageInput{Source: dir, Revision: revision, Handoff: h})
			_, err := stage.Plan(ctx, staging)
			for _, want := range []string{"api requires origin pull on site.example.com", "helios edge origin-pull trust <host>", "then stage again"} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("a move was staged onto a host api requires and the edge would refuse: %v", err)
				}
			}

			data, _ := json.Marshal(m)
			if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: revision, Status: revisionStaged, Manifest: data, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: "staged", TargetRevision: revision}); err != nil {
				t.Fatal(err)
			}
			c := MoveCutover{Deploy: Deploy{Store: store, Secrets: sec}}
			cutover, _ := json.Marshal(MoveCutoverInput{App: m.App, Migration: h.Migration, Revision: revision})
			_, err = c.Plan(ctx, cutover)
			for _, want := range []string{"api requires origin pull on site.example.com", "helios edge origin-pull trust <host>", "then cut over again"} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("a move was cut over onto a host api requires and the edge would refuse: %v", err)
				}
			}

			if _, err := TrustOriginPull(ctx, store, sec, host, mintCA(t, host, time.Now()).PEM, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := stage.Plan(ctx, staging); err != nil {
				t.Fatalf("a target trusting the CA was refused staging: %v", err)
			}
			if _, err := c.Plan(ctx, cutover); err != nil {
				t.Fatalf("a target trusting the CA was refused cutover: %v", err)
			}
		})
	}
}
