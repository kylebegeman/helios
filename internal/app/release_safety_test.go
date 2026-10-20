package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

func releaseTestStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func releaseTestManifest() *manifest.Manifest {
	return &manifest.Manifest{App: "site", Data: &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}}, Workloads: map[string]manifest.Workload{"web": {Kind: manifest.Worker, Image: "image"}, "migrate": {Kind: manifest.Release, Image: "image"}}}
}

func releaseTestRevision(t *testing.T, store *state.Store, m *manifest.Manifest, id string, status state.RevisionStatus, at time.Time) *state.Revision {
	t.Helper()
	encoded, _ := json.Marshal(m)
	rev := &state.Revision{App: m.App, ID: id, Status: status, Manifest: encoded, CreatedAt: at, Images: map[string]string{"web": "sha256:abc", "migrate": "sha256:abc"}, Containers: map[string]string{}}
	if err := store.SaveRevision(context.Background(), *rev); err != nil {
		t.Fatal(err)
	}
	return rev
}

func TestRollbackIncludesFailedDataMutationsAndRequiresMatchingExactCheckpoint(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	now := time.Now().UTC().Truncate(time.Millisecond)
	target := releaseTestRevision(t, store, m, "old-rev", state.RevisionPrevious, now)
	current := releaseTestRevision(t, store, m, "active-rev", state.RevisionActive, now.Add(time.Minute))
	releaseTestRevision(t, store, m, "failed-rev", state.RevisionFailed, now.Add(2*time.Minute))
	store.Activate(ctx, m.App, current.ID, now.Add(time.Minute))
	for _, id := range []string{current.ID, "failed-rev"} {
		b := state.ReleaseBoundary{App: m.App, Revision: id, PreviousRevision: target.ID, Compatibility: manifest.DataRestoreRequired, Snapshot: strings.Repeat("a", 64), StartedAt: now.Add(3 * time.Minute)}
		if err := store.BeginReleaseBoundary(ctx, b); err != nil {
			t.Fatal(err)
		}
		if err := store.FinishReleaseBoundary(ctx, m.App, id, state.ReleaseFailed, "partial mutation", now.Add(4*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	rollback := Rollback{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: t.TempDir()}}
	raw, _ := json.Marshal(RollbackInput{App: m.App, Revision: target.ID})
	_, err := rollback.Plan(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "failed-rev") || !strings.Contains(err.Error(), "--restore-data") {
		t.Fatalf("unsafe rollback admitted or missing guidance: %v", err)
	}
	for _, snapshot := range []string{"latest", "aaaaaaaa", strings.Repeat("b", 64)} {
		raw, _ := json.Marshal(RollbackInput{App: m.App, Revision: target.ID, RestoreData: snapshot})
		if _, err := rollback.Plan(ctx, raw); err == nil {
			t.Fatalf("invalid checkpoint admitted: %s", snapshot)
		}
	}
	raw, _ = json.Marshal(RollbackInput{App: m.App, RestoreData: strings.Repeat("a", 64)})
	plan, err := rollback.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Steps[0].Name != "restore-release-checkpoint" {
		t.Fatal("older code can start before data restoration")
	}
	for _, s := range plan.Steps {
		if s.Name == "release" {
			t.Fatal("rollback reruns old mutation jobs")
		}
	}
	// A retry pins the checkpoint's target even after it was made active.
	store.Activate(ctx, m.App, target.ID, now.Add(5*time.Minute))
	if _, err := rollback.Plan(ctx, raw); err != nil {
		t.Fatalf("checkpoint retry changed target: %v", err)
	}
}

func TestBackwardCompatibleBoundariesAllowCodeRollbackAndPreparedOnesAreNotMutations(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	now := time.Now().UTC()
	target := releaseTestRevision(t, store, m, "old-rev", state.RevisionPrevious, now)
	releaseTestRevision(t, store, m, "new-rev", state.RevisionActive, now.Add(time.Minute))
	releaseTestRevision(t, store, m, "prepared-rev", state.RevisionFailed, now.Add(2*time.Minute))
	if err := store.BeginReleaseBoundary(ctx, state.ReleaseBoundary{App: m.App, Revision: "new-rev", Compatibility: manifest.DataBackwardCompatible, StartedAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := store.PrepareReleaseBoundary(ctx, state.ReleaseBoundary{App: m.App, Revision: "prepared-rev", Compatibility: manifest.DataCompatibilityUnknown, StartedAt: now.Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	unsafe, err := unsafeReleaseBoundaries(ctx, store, target)
	if err != nil || len(unsafe) != 0 {
		t.Fatalf("%+v %v", unsafe, err)
	}
}

func TestReleaseReplayNeverRerunsCompletedOrUncertainJobs(t *testing.T) {
	for _, status := range []string{state.ReleaseCompleted, state.ReleaseFailed, state.ReleaseStarted} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			m := releaseTestManifest()
			sec := newSecrets(t)
			rev := releaseTestRevision(t, store, m, "candidate-rev", state.RevisionFailed, time.Now().UTC())
			if err := store.BeginReleaseBoundary(ctx, state.ReleaseBoundary{App: m.App, Revision: rev.ID, Compatibility: manifest.DataCompatibilityUnknown, Snapshot: strings.Repeat("a", 64), StartedAt: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
			if status != state.ReleaseStarted {
				if err := store.FinishReleaseBoundary(ctx, m.App, rev.ID, status, "", time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
			}
			r := &rollout{d: Deploy{Store: store, Secrets: sec}, store: store, m: m, revision: rev.ID, from: &buildFrom{}}
			// If a job is replayed this unreachable engine forces the test to fail.
			t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
			var out strings.Builder
			err := r.releaseStep(m.ReleaseWorkloads()).Apply(ctx, &out)
			if status == state.ReleaseCompleted {
				if err != nil || !strings.Contains(out.String(), "not replayed") {
					t.Fatalf("%v %s", err, out.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), "not replayed automatically") {
				t.Fatalf("uncertain mutation replayed: %v", err)
			}
		})
	}
}

func TestReleaseRestoreFenceBlocksDataCommandsAcrossConnections(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	b := state.ReleaseBoundary{App: "site", Revision: "new-rev", PreviousRevision: "old-rev", Compatibility: manifest.DataCompatibilityUnknown, Snapshot: strings.Repeat("a", 64), StartedAt: time.Now().UTC()}
	store.BeginReleaseBoundary(ctx, b)
	if err := store.BeginReleaseRestore(ctx, b.App, b.Revision, b.Snapshot); err != nil {
		t.Fatal(err)
	}
	if err := CheckReleaseDataAccess(ctx, store.Path(), b.App); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("%v", err)
	}
	if err := CheckReleaseDataAccess(ctx, store.Path(), "other"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteReleaseRestore(ctx, b, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := CheckReleaseDataAccess(ctx, store.Path(), b.App); err != nil {
		t.Fatal(err)
	}
}

func TestDirectChecksKeepRedirectsInsideTheContainerOrigin(t *testing.T) {
	externalCalls := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { externalCalls++; w.WriteHeader(200) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/external":
			http.Redirect(w, r, other.URL, 302)
		case "/local":
			http.Redirect(w, r, "/ok", 302)
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer server.Close()
	client := &http.Client{CheckRedirect: directCheckRedirect}
	response, err := client.Get(server.URL + "/local")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if _, err := client.Get(server.URL + "/external"); err == nil {
		t.Fatal("cross-origin redirect followed")
	}
	if externalCalls != 0 {
		t.Fatal("direct check touched external service")
	}
}

func TestUnsafeDataReleasePlansCheckpointBeforeMutationAndCompatiblePolicySkipsIt(t *testing.T) {
	m := releaseTestManifest()
	source := t.TempDir()
	names := func() []string {
		plan, err := (Deploy{}).rollout(context.Background(), m, "candidate-rev", &buildFrom{source: source})
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, s := range plan.Steps {
			names = append(names, s.Name)
		}
		return names
	}
	first := names()
	if slices.Index(first, "release-checkpoint") != slices.Index(first, "release")-1 {
		t.Fatalf("unsafe ordering: %v", first)
	}
	m.Release = &manifest.ReleasePolicy{DataCompatibility: manifest.DataBackwardCompatible}
	if slices.Contains(names(), "release-checkpoint") {
		t.Fatal("declared compatible release unnecessarily requires restore checkpoint")
	}
	if _, err := os.Stat(filepath.Join(source, "backups")); !os.IsNotExist(err) {
		t.Fatal("planning mutated filesystem")
	}
}

func TestRollbackRefusesACheckpointTakenAfterAnEarlierUnsafeFailedRelease(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	now := time.Now().UTC().Truncate(time.Millisecond)
	target := releaseTestRevision(t, store, m, "old-rev", state.RevisionActive, now)
	for i, id := range []string{"first-failed", "second-failed"} {
		releaseTestRevision(t, store, m, id, state.RevisionFailed, now.Add(time.Duration(i+1)*time.Minute))
		b := state.ReleaseBoundary{App: m.App, Revision: id, PreviousRevision: target.ID, Compatibility: manifest.DataCompatibilityUnknown, Snapshot: strings.Repeat(string(rune('a'+i)), 64), StartedAt: now.Add(time.Duration(i+1) * time.Minute)}
		store.BeginReleaseBoundary(ctx, b)
		store.FinishReleaseBoundary(ctx, m.App, id, state.ReleaseFailed, "data may have changed", now)
	}
	rollback := Rollback{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: t.TempDir()}}
	raw, _ := json.Marshal(RollbackInput{App: m.App, RestoreData: strings.Repeat("b", 64)})
	if _, err := rollback.Plan(ctx, raw); err == nil || !strings.Contains(err.Error(), "after unsafe data release first-failed") {
		t.Fatalf("late checkpoint admitted: %v", err)
	}
	raw, _ = json.Marshal(RollbackInput{App: m.App, RestoreData: strings.Repeat("a", 64)})
	if _, err := rollback.Plan(ctx, raw); err != nil {
		t.Fatalf("earliest compatible checkpoint refused: %v", err)
	}
}

func TestCheckpointRestoreRetainsAuthorityHistoryAndReplaysPartialDataUnderFence(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	now := time.Now().UTC().Truncate(time.Millisecond)
	sec := newSecrets(t)
	original, err := sec.Set(m.App, "TOKEN", "original-value")
	if err != nil {
		t.Fatal(err)
	}
	// Storage values are fixture credentials, never copied into logs/proof.
	for name, value := range map[string]string{"STORAGE_KIND": "s3", "STORAGE_ENDPOINT": "http://store:9000", "STORAGE_KEY_ID": "test-key", "STORAGE_KEY": "test-secret", "STORAGE_BUCKET_PREFIX": "lane", "STORAGE_PASSWORD": "backup-password"} {
		sec.Set(manifest.ReservedApp, name, value)
	}
	target := releaseTestRevision(t, store, m, "old-rev", state.RevisionPrevious, now)
	target.SecretsVersion = original
	store.SaveRevision(ctx, *target)
	current := releaseTestRevision(t, store, m, "new-rev", state.RevisionActive, now.Add(time.Minute))
	store.Activate(ctx, m.App, current.ID, now.Add(time.Minute))
	sec.Set(m.App, "TOKEN", "candidate-value")
	snapshot := strings.Repeat("a", 64)
	boundary := state.ReleaseBoundary{App: m.App, Revision: current.ID, PreviousRevision: target.ID, Compatibility: manifest.DataRestoreRequired, Snapshot: snapshot, StartedAt: now.Add(time.Minute)}
	store.BeginReleaseBoundary(ctx, boundary)
	store.FinishReleaseBoundary(ctx, m.App, current.ID, state.ReleaseFailed, "partial writes", now.Add(2*time.Minute))
	fake := dockertest.New(t)
	roomToRestore(t)
	fake.Add(dockertest.Container{Name: "old-live", Running: true, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: m.App, docker.LabelWorkload: "web"}})
	fake.Add(dockertest.Container{Name: "unrelated-live", Running: true, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: "other", docker.LabelWorkload: "web"}})
	fake.AddVolume(docker.VolumeName(m.App, "files"), map[string]string{docker.LabelOwner: docker.OwnerValue})
	// VolumeEmpty uses the documented Docker CLI helper. Its fixture reports
	// the newly replaced volume empty; all container/restic calls use the API fake.
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	failVolume := true
	var volumeAttempts int
	// The snapshot's summary sizes the restore, so the app isn't down
	// while restic walks the snapshot's tree.
	counted := false
	fake.OnCreate = func(c dockertest.Container) {
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "snapshots":
				c.Logs = `[{"id":"` + snapshot + `","short_id":"aaaaaaaa","time":"2026-10-10T00:00:00Z","summary":{"total_files_processed":1,"total_bytes_processed":12}}]`
			case "stats":
				counted = true
			case "restore":
				staging := ""
				for _, bind := range c.HostConfig.Binds {
					if strings.HasSuffix(bind, ":/data") {
						staging = strings.TrimSuffix(bind, ":/data")
					}
				}
				if staging != "" {
					os.WriteFile(filepath.Join(staging, "manifest.json"), target.Manifest, 0o600)
				} else {
					volumeAttempts++
					if err := CheckReleaseDataAccess(ctx, store.Path(), m.App); !errors.Is(err, ErrReleaseRestorePending) {
						t.Fatalf("volume restore admitted without durable fence: %v", err)
					}
					if failVolume {
						c.ExitCode = 9
					}
				}
				c.Logs = `{"message_type":"summary","total_files":1,"files_restored":1}`
			}
		})
	}
	d := Deploy{Store: store, Secrets: sec, StateDir: t.TempDir()}
	step := rollbackCheckpointStep(d, target, boundary)
	if err := step.Apply(ctx, io.Discard); err == nil {
		t.Fatal("partial restore reported successful")
	}
	if err := CheckReleaseDataAccess(ctx, store.Path(), m.App); !errors.Is(err, ErrReleaseRestorePending) {
		t.Fatalf("failed restore released writers: %v", err)
	}
	if _, exists := fake.Container("old-live"); exists {
		t.Fatal("old code survived destructive restoration")
	}
	if other, exists := fake.Container("unrelated-live"); !exists || !other.Running {
		t.Fatal("other app was stopped")
	}
	failVolume = false
	if err := step.Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	if volumeAttempts != 2 {
		t.Fatalf("partial restore was not replayed from the same checkpoint: %d", volumeAttempts)
	}
	if counted {
		t.Fatal("the rollback counted a snapshot whose summary already sizes it")
	}
	if err := CheckReleaseDataAccess(ctx, store.Path(), m.App); err != nil {
		t.Fatal(err)
	}
	b, _ := store.ReleaseBoundary(ctx, m.App, current.ID)
	if b.Status != state.ReleaseRestored {
		t.Fatalf("%+v", b)
	}
	values, _, _ := sec.LoadCurrent(m.App)
	if values["TOKEN"] != "original-value" {
		t.Fatal("checkpoint credentials not restored")
	}
	kept, _ := store.GetRevision(ctx, m.App, target.ID)
	if kept.SecretsVersion != original || kept.Images["web"] == "" {
		t.Fatal("revision metadata or image pin lost")
	}
	active, _ := store.RevisionWithStatus(ctx, m.App, state.RevisionActive)
	if active != nil {
		t.Fatal("older code activated before rollout checks")
	}
}

func TestReleaseRestoreFencePreventsAppAndMachineBackupPlansAndReplayedSteps(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	sec := newSecrets(t)
	m := releaseTestManifest()
	for name, value := range map[string]string{"STORAGE_KIND": "s3", "STORAGE_ENDPOINT": "http://store:9000", "STORAGE_KEY_ID": "test-key", "STORAGE_KEY": "test-secret", "STORAGE_BUCKET_PREFIX": "lane", "STORAGE_PASSWORD": "backup-password"} {
		sec.Set(manifest.ReservedApp, name, value)
	}
	releaseTestRevision(t, store, m, "active-rev", state.RevisionActive, time.Now().UTC())
	backup := Backup{Store: store, Secrets: sec, StateDir: t.TempDir(), Hostname: func() string { return "fixture" }}
	appRaw, _ := json.Marshal(BackupInput{App: m.App})
	machineRaw, _ := json.Marshal(BackupInput{App: manifest.ReservedApp})
	appPlan, err := backup.Plan(ctx, appRaw)
	if err != nil {
		t.Fatal(err)
	}
	machinePlan, err := backup.Plan(ctx, machineRaw)
	if err != nil {
		t.Fatal(err)
	}
	b := state.ReleaseBoundary{App: m.App, Revision: "failed-rev", PreviousRevision: "active-rev", Compatibility: manifest.DataRestoreRequired, Snapshot: strings.Repeat("a", 64), StartedAt: time.Now().UTC()}
	store.BeginReleaseBoundary(ctx, b)
	if err := store.BeginReleaseRestore(ctx, b.App, b.Revision, b.Snapshot); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []json.RawMessage{appRaw, machineRaw} {
		if _, err := backup.Plan(ctx, raw); !errors.Is(err, ErrReleaseRestorePending) {
			t.Fatalf("backup plan admitted during partial restore: %v", err)
		}
	}
	for _, step := range []kernel.Step{appPlan.Steps[1], machinePlan.Steps[0], machinePlan.Steps[1]} {
		if err := step.Apply(ctx, io.Discard); !errors.Is(err, ErrReleaseRestorePending) {
			t.Fatalf("replayed %s admitted during partial restore: %v", step.Name, err)
		}
	}
	if err := store.CompleteReleaseRestore(ctx, b, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Plan(ctx, machineRaw); err != nil {
		t.Fatalf("completed restore kept machine backups blocked: %v", err)
	}
}

func TestRestoredCheckpointCannotSkipLaterUnsafeDataTransition(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	at := time.Now().UTC().Truncate(time.Millisecond)
	target := releaseTestRevision(t, store, m, "original-code", state.RevisionActive, at)
	releaseTestRevision(t, store, m, "first-release", state.RevisionRetired, at.Add(time.Minute))
	first := state.ReleaseBoundary{App: m.App, Revision: "first-release", PreviousRevision: target.ID, Compatibility: manifest.DataRestoreRequired, Snapshot: strings.Repeat("a", 64), StartedAt: at.Add(time.Minute)}
	if err := store.BeginReleaseBoundary(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishReleaseBoundary(ctx, m.App, first.Revision, state.ReleaseRestored, "", at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	rollback := Rollback{Deploy: Deploy{Store: store, Secrets: newSecrets(t), StateDir: t.TempDir()}}
	raw, _ := json.Marshal(RollbackInput{App: m.App, RestoreData: first.Snapshot})
	plan, err := rollback.Plan(ctx, raw)
	if err != nil {
		t.Fatalf("completed restoration retry must remain idempotent: %v", err)
	}
	// No Docker access is needed to replay a completed restoration safely.
	if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}

	releaseTestRevision(t, store, m, "later-release", state.RevisionActive, at.Add(3*time.Minute))
	later := state.ReleaseBoundary{App: m.App, Revision: "later-release", PreviousRevision: target.ID, Compatibility: manifest.DataRestoreRequired, Snapshot: strings.Repeat("b", 64), StartedAt: at.Add(3 * time.Minute)}
	if err := store.BeginReleaseBoundary(ctx, later); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishReleaseBoundary(ctx, m.App, later.Revision, state.ReleaseCompleted, "", at.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := rollback.Plan(ctx, raw); err == nil || !strings.Contains(err.Error(), "already restored") || !strings.Contains(err.Error(), later.Snapshot) {
		t.Fatalf("old completed restoration admitted older code against later mutated data: %v", err)
	}
	// The newer pre-mutation checkpoint still restores the same code safely.
	raw, _ = json.Marshal(RollbackInput{App: m.App, RestoreData: later.Snapshot})
	if _, err := rollback.Plan(ctx, raw); err != nil {
		t.Fatalf("matching newer checkpoint refused: %v", err)
	}
}
