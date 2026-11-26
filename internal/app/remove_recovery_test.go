package app

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

func TestRemoveCleanupFailureCanRetryWithoutDeletingRetainedData(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store := goldenStore(t)
	seedApp(t, store, "site")
	sec := newSecrets(t)
	if _, err := sec.Set("site", "TOKEN", "retained"); err != nil {
		t.Fatal(err)
	}
	volume := docker.VolumeName("site", "files")
	fake.AddVolume(volume, map[string]string{docker.LabelOwner: docker.OwnerValue})
	stateDir := filepath.Dir(store.Path())
	blocked := filepath.Join(stateDir, "backups")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgetApp(ctx, store, sec, stateDir, "site", false, nil, io.Discard); err == nil {
		t.Fatal("filesystem cleanup failure was ignored")
	}
	if revisions, err := store.Revisions(ctx, "site"); err != nil || len(revisions) != 1 {
		t.Fatalf("failed cleanup lost retryable app records: %+v, %v", revisions, err)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	r := Remove{Store: store, Secrets: sec, StateDir: stateDir}
	plan, err := r.Plan(ctx, json.RawMessage(`{"app":"site"}`))
	if err != nil || plan.Steps[0].Name != "unroute" {
		t.Fatalf("retaining-data removal could not retry: %+v, %v", plan, err)
	}
	if err := forgetApp(ctx, store, sec, stateDir, "site", false, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if values, _, err := sec.LoadCurrent("site"); err != nil || values["TOKEN"] != "retained" {
		t.Fatalf("retry deleted retained credentials: %+v, %v", values, err)
	}
	if names := fake.VolumeNames(); len(names) != 1 || names[0] != volume {
		t.Fatalf("retry deleted retained data: %v", names)
	}
}

func TestRemoveReviewedHistoryCannotCaptureALaterRevision(t *testing.T) {
	ctx := context.Background()
	store := goldenStore(t)
	seedApp(t, store, "site")
	r := Remove{Store: store, StateDir: filepath.Dir(store.Path())}
	raw := json.RawMessage(`{"app":"site"}`)
	plan, err := r.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	reg := kernel.Registry{}
	reg.Add(r)
	engine := kernel.New(store, reg, "test")
	before, err := engine.PlanOnly(ctx, RemoveKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.GetRevision(ctx, "site", "r1")
	if err != nil {
		t.Fatal(err)
	}
	revision.ID, revision.CreatedAt = "r2", time.Now().UTC().Add(time.Second)
	if err := store.SaveRevision(ctx, *revision); err != nil {
		t.Fatal(err)
	}
	after, err := engine.PlanOnly(ctx, RemoveKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest == after.Digest {
		t.Fatal("reviewed removal approval also authorized a later revision")
	}
	for _, step := range plan.Steps {
		if err := step.Apply(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "revision history changed") {
			t.Fatalf("stale %s removal touched later app state: %v", step.Name, err)
		}
	}
	if active, err := store.GetRevision(ctx, "site", "r2"); err != nil || active.Status != state.RevisionActive {
		t.Fatalf("stale removal changed the later revision: %+v, %v", active, err)
	}
}
