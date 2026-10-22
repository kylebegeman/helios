package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func TestMoveAuditFailedStageCanRetryItsReservedRevisionWithoutLosingPins(t *testing.T) {
	ctx := context.Background()
	dockertest.New(t)
	store, m, h, source := safeMoveFixture(t)
	stage := MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return h.To }}
	input := MoveStageInput{Source: source, Revision: MoveTargetRevision(h), Handoff: h}
	raw, _ := json.Marshal(input)
	first, err := stage.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	// An ordinary failure after record leaves a failed revision and its
	// target reservation. A fresh retry has step attempt 1, unlike recovery
	// of an interrupted operation, whose record step gets attempt 2.
	for _, step := range first.Steps[:2] {
		if err := step.Apply(ctx, io.Discard); err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
	}
	revision, err := store.GetRevision(ctx, m.App, input.Revision)
	if err != nil {
		t.Fatal(err)
	}
	revision.Images = map[string]string{"web": "sha256:captured"}
	revision.SecretsVersion = 7
	if err := store.SaveRevision(ctx, *revision); err != nil {
		t.Fatal(err)
	}
	retry, err := stage.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range retry.Steps[:2] {
		if err := step.Apply(ctx, io.Discard); err != nil {
			t.Fatalf("retry %s: %v", step.Name, err)
		}
	}
	got, err := store.GetRevision(ctx, m.App, input.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got.Images, revision.Images) || got.SecretsVersion != revision.SecretsVersion || !got.CreatedAt.Equal(revision.CreatedAt) {
		t.Fatalf("stage retry replaced its recorded pins: %+v", got)
	}
}

func TestMoveAuditStageCannotAdoptRevisionHistoryWithoutItsReservation(t *testing.T) {
	ctx := context.Background()
	store, m, h, source := safeMoveFixture(t)
	revision := MoveTargetRevision(h)
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: revision, Status: state.RevisionFailed, Manifest: data,
		Containers: map[string]string{"web": docker.ContainerName(m.App, "web", revision)}, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	stage := MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return h.To }}
	raw, _ := json.Marshal(MoveStageInput{Source: source, Revision: revision, Handoff: h})
	if _, err := stage.Plan(ctx, raw); err == nil {
		t.Fatal("staging adopted an existing revision without a matching migration reservation")
	}
}

func TestMoveAuditCutoverRechecksTheTargetsWebPolicy(t *testing.T) {
	ctx := context.Background()
	store, m, h, _ := safeMoveFixture(t)
	revision := MoveTargetRevision(h)
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: revision, Status: revisionStaged, Manifest: data, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: "staged", TargetRevision: revision}); err != nil {
		t.Fatal(err)
	}
	cutover := MoveCutover{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: filepath.Dir(store.Path()),
		CloudflareOnly: func() (bool, error) { return true, nil }}}
	raw, _ := json.Marshal(MoveCutoverInput{App: m.App, Migration: h.Migration, Revision: revision})
	if _, err := cutover.Plan(ctx, raw); err == nil || !strings.Contains(err.Error(), "only from Cloudflare") {
		t.Fatalf("cutover admitted routes unreachable under the current host policy: %v", err)
	}
}

func TestMoveAuditRehearsalNeverDeletesUnreservedScratchVolumes(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, source := safeMoveFixture(t)
	h.Phase = "rehearsal"
	input := MoveStageInput{Source: source, Revision: "test-" + MoveTargetRevision(h), Handoff: h}
	def := MoveTest{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return h.To }}
	raw, _ := json.Marshal(input)
	plan, err := def.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(filepath.Dir(store.Path()), "moves", m.App, "tests", input.Revision)
	names := rehearsalNames(workspace, m, "move-test-"+input.Revision)
	fake.AddVolume(names.postgresVolume, map[string]string{docker.LabelOwner: "another-system"})
	if err := plan.Steps[0].Apply(ctx, io.Discard); err == nil {
		t.Error("move test claimed and deleted a preexisting volume without a reservation")
	}
	if !slices.Contains(fake.VolumeNames(), names.postgresVolume) {
		t.Fatal("unreserved volume was deleted by move test cleanup")
	}
}

func TestMoveAuditRehearsalNeverDeletesAForeignVolumeAfterReservation(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, source := safeMoveFixture(t)
	h.Phase = "rehearsal"
	input := MoveStageInput{Source: source, Revision: "test-" + MoveTargetRevision(h), Handoff: h}
	def := MoveTest{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return h.To }}
	raw, _ := json.Marshal(input)
	plan, err := def.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(filepath.Dir(store.Path()), "moves", m.App, "tests", input.Revision)
	names := rehearsalNames(workspace, m, "move-test-"+input.Revision)
	fake.AddVolume(names.postgresVolume, map[string]string{docker.LabelOwner: "another-system"})
	if err := plan.Steps[0].Undo(ctx, io.Discard); err == nil {
		t.Error("move test reservation authorized deleting another system's volume")
	}
	if !slices.Contains(fake.VolumeNames(), names.postgresVolume) {
		t.Fatal("foreign volume was deleted by move test compensation")
	}
}

type moveAuditCancelFence struct {
	*docker.Engine
	cancel context.CancelFunc
}

func (e *moveAuditCancelFence) SetRestartPolicy(ctx context.Context, id string, policy docker.RestartPolicy) error {
	err := e.Engine.SetRestartPolicy(ctx, id, policy)
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	return err
}

func TestMoveAuditCanceledFinalCaptureStillStopsItsReservedWriters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := dockertest.New(t)
	store, m, h, _ := safeMoveFixture(t)
	for _, role := range []string{"web", "worker"} {
		addMoveWriter(fake, "bedrock-site-"+role+"-r1", role, true)
	}
	engine, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	e := &moveAuditCancelFence{Engine: engine, cancel: cancel}
	if err := fenceMigration(ctx, e, store.Path(), m, h, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled capture lost its cancellation: %v", err)
	}
	for _, role := range []string{"web", "worker"} {
		writer, _ := fake.Container("bedrock-site-" + role + "-r1")
		if writer.Running || writer.HostConfig.RestartPolicy.Name != "no" {
			t.Errorf("canceled final capture left %s accepting writes or able to restart: %+v", role, writer)
		}
	}
	if err := CheckMigrationAccess(store.Path(), m.App); err == nil {
		t.Fatal("canceled final capture discarded its durable fence")
	}
}

func TestMoveAuditFailedStageCompletesOnAFreshOperationRetry(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, h, source := safeMoveFixture(t)
	web := m.Workloads["web"]
	web.Health = &manifest.Health{Command: []string{"true"}}
	m.Workloads["web"] = web
	writeManifestFile(t, source, m)
	h.ManifestDigest = manifestDigest(m)
	input := MoveStageInput{Source: source, Revision: MoveTargetRevision(h), Handoff: h}
	webName := docker.ContainerName(m.App, "web", input.Revision)
	fake.OnCreate = func(c dockertest.Container) {
		if c.Name == webName {
			fake.Update(c.Name, func(c *dockertest.Container) { c.ExitAfter, c.ExitCode = 1, 42 })
		}
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	raw, _ := json.Marshal(input)
	reg := kernel.Registry{}
	reg.Add(MoveStage{Deploy: Deploy{Store: store, Secrets: newSecrets(t)}, Hostname: func() string { return h.To }})
	engine := kernel.New(store, reg, "move-audit")
	first, err := engine.Run(ctx, MoveStageKind, raw, func(kernel.Event) {})
	if err != nil || first.Status != state.Failed || !strings.Contains(first.Error, "exit code 42") {
		t.Fatalf("initial stage did not fail at readiness: %+v, %v", first, err)
	}
	fake.Update(webName, func(c *dockertest.Container) { c.ExitAfter, c.ExitCode = 0, 0 })
	retry, err := engine.Run(ctx, MoveStageKind, raw, func(kernel.Event) {})
	if err != nil || retry.Status != state.Succeeded {
		t.Fatalf("fresh retry could not finish its reserved stage: %+v, %v", retry, err)
	}
	revision, err := store.GetRevision(ctx, m.App, input.Revision)
	if err != nil || revision.Status != revisionStaged {
		t.Fatalf("retry did not record a staged target: %+v, %v", revision, err)
	}
	if err := CheckMigrationAccess(store.Path(), m.App); err == nil {
		t.Fatal("successful stage admitted normal target writes before cutover")
	}
}
