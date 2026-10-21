package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// Supply actual image metadata around the existing container stand-in so the
// regression exercises collection, including images loaded from another host.
func gcImageFixture(t *testing.T, fake *dockertest.Server, images map[string]map[string]string) func(string) bool {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		switch {
		case path == "/images/json":
			mu.Lock()
			defer mu.Unlock()
			var listed []any
			for id, labels := range images {
				listed = append(listed, map[string]any{"Id": id, "Labels": labels, "RepoTags": []string{"test/" + strings.TrimPrefix(id, "sha256:") + ":latest"}})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(listed)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/images/"):
			mu.Lock()
			delete(images, strings.TrimPrefix(path, "/images/"))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]any{})
		default:
			fake.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(server.URL, "http"))
	return func(id string) bool {
		mu.Lock()
		defer mu.Unlock()
		_, ok := images[id]
		return ok
	}
}

func runCollection(t *testing.T, store *state.Store) {
	t.Helper()
	ctx := context.Background()
	plan, err := (GC{Store: store}).Plan(ctx, json.RawMessage(`{"keep_build_cache":true}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if err := step.Apply(ctx, io.Discard); err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
	}
}

func TestGCPreservesUnfinishedMigrationTargetsAndTheirImages(t *testing.T) {
	for _, phase := range []string{"restoring", "staged", "cutting-over"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			store, m, handoff, _ := safeMoveFixture(t)
			revision := "target-r1"
			releaseTestRevision(t, store, m, revision, revisionStaged, time.Now())
			record := &migrationRecord{Handoff: handoff, Role: "target", Phase: phase, TargetRevision: revision}
			if err := saveMigration(store.Path(), record); err != nil {
				t.Fatal(err)
			}
			fake := dockertest.New(t)
			wanted := docker.ContainerName(m.App, "web", revision)
			fake.Add(dockertest.Container{Name: wanted, Running: true, Labels: imageLabels(m.App, "web", revision)})
			fake.Add(dockertest.Container{Name: "unused-container", Labels: imageLabels(m.App, "web", "unused-r1")})
			imageExists := gcImageFixture(t, fake, map[string]map[string]string{
				"sha256:target-image": imageLabels(m.App, "web", revision),
				"sha256:unused-image": imageLabels(m.App, "web", "unused-r1"),
			})
			runCollection(t, store)
			if _, ok := fake.Container(wanted); !ok || !imageExists("sha256:target-image") {
				t.Fatal("GC destroyed resources needed for reviewed migration cutover")
			}
			if _, ok := fake.Container("unused-container"); ok || imageExists("sha256:unused-image") {
				t.Fatal("GC stopped collecting unrelated stale resources")
			}
			// A completed migration cannot keep a superseded revision forever.
			record.Phase = "cutover"
			if err := saveMigration(store.Path(), record); err != nil {
				t.Fatal(err)
			}
			if err := store.SetRevisionStatus(ctx, m.App, revision, state.RevisionRetired); err != nil {
				t.Fatal(err)
			}
			runCollection(t, store)
			if _, ok := fake.Container(wanted); ok || imageExists("sha256:target-image") {
				t.Fatal("completed migration prevented ordinary collection")
			}
		})
	}
}

func TestGCPreservesCheckpointTargetsBeyondOrdinaryHistoryLimit(t *testing.T) {
	for _, status := range []string{state.ReleasePrepared, state.ReleaseStarted, state.ReleaseCompleted, state.ReleaseFailed, state.ReleaseRestoring} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			m := releaseTestManifest()
			at := time.Now().UTC()
			target := releaseTestRevision(t, store, m, "checkpoint-target", state.RevisionRetired, at)
			releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, at.Add(20*time.Minute))
			if err := store.Activate(ctx, m.App, "active-revision", at.Add(20*time.Minute)); err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= retiredKept+1; i++ {
				releaseTestRevision(t, store, m, fmt.Sprintf("ordinary-old-%d", i), state.RevisionRetired, at.Add(time.Duration(i)*time.Minute))
			}
			boundary := state.ReleaseBoundary{App: m.App, Revision: "data-release", PreviousRevision: target.ID, Compatibility: manifest.DataRestoreRequired, Snapshot: strings.Repeat("a", 64), StartedAt: at.Add(10 * time.Minute)}
			if status == state.ReleasePrepared {
				if err := store.PrepareReleaseBoundary(ctx, boundary); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := store.BeginReleaseBoundary(ctx, boundary); err != nil {
					t.Fatal(err)
				}
				if status == state.ReleaseRestoring {
					if err := store.BeginReleaseRestore(ctx, m.App, boundary.Revision, boundary.Snapshot); err != nil {
						t.Fatal(err)
					}
				} else if status != state.ReleaseStarted {
					if err := store.FinishReleaseBoundary(ctx, m.App, boundary.Revision, status, "", at.Add(11*time.Minute)); err != nil {
						t.Fatal(err)
					}
				}
			}
			fake := dockertest.New(t)
			imageExists := gcImageFixture(t, fake, map[string]map[string]string{
				"sha256:checkpoint-image": imageLabels(m.App, "web", target.ID),
				"sha256:obsolete-image":   imageLabels(m.App, "web", "ordinary-old-1"),
			})
			runCollection(t, store)
			if _, err := store.GetRevision(ctx, m.App, target.ID); err != nil || !imageExists("sha256:checkpoint-image") {
				t.Fatal("retained data checkpoint lost its required revision or image", err)
			}
			if _, err := store.GetRevision(ctx, m.App, "ordinary-old-1"); err == nil || imageExists("sha256:obsolete-image") {
				t.Fatal("unreferenced history stopped being collected")
			}
			if err := store.FinishReleaseBoundary(ctx, m.App, boundary.Revision, state.ReleaseRestored, "", at.Add(21*time.Minute)); err != nil {
				t.Fatal(err)
			}
			// The checkpoint no longer protects a target once restoration has
			// completed and that revision is no longer active or previous.
			runCollection(t, store)
			if _, err := store.GetRevision(ctx, m.App, target.ID); err == nil || imageExists("sha256:checkpoint-image") {
				t.Fatal("completed checkpoint restore prevented ordinary collection")
			}
		})
	}
}

func TestGCPreservesRecoveredImageIDsWithOriginalSourceLabels(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	rev := releaseTestRevision(t, store, m, "recovered-target", state.RevisionActive, time.Now())
	rev.Images = map[string]string{"web": "sha256:source-image"}
	if err := store.SaveRevision(ctx, *rev); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(ctx, m.App, rev.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	fake := dockertest.New(t)
	imageExists := gcImageFixture(t, fake, map[string]map[string]string{
		"sha256:source-image": imageLabels(m.App, "web", "original-source-revision"),
		"sha256:unused-image": imageLabels(m.App, "web", "unused-source-revision"),
	})
	runCollection(t, store)
	if !imageExists("sha256:source-image") || imageExists("sha256:unused-image") {
		t.Fatal("collection ignored the recovered revision's pinned image identity")
	}
}

func TestGCPreservesRetainedRepositoryDigestsWithOriginalSourceLabels(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	rev := releaseTestRevision(t, store, m, "recovered-target", state.RevisionActive, time.Now())
	digest := "registry.example/app@sha256:" + strings.Repeat("a", 64)
	rev.Images = map[string]string{"web": digest}
	if err := store.SaveRevision(ctx, *rev); err != nil {
		t.Fatal(err)
	}
	fake := dockertest.New(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		if path == "/images/json" {
			json.NewEncoder(w).Encode([]any{map[string]any{"Id": "sha256:source-image", "Labels": imageLabels(m.App, "web", "source-revision"), "RepoTags": []string{"registry.example/app:old"}, "RepoDigests": []string{digest}}})
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	e, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	keep, err := gcResourcesToKeep(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := staleImages(ctx, e, keep)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 0 {
		t.Fatalf("GC would discard the retained digest %s: %+v", digest, stale)
	}
}

func TestGCProtectsTheRevisionOfAnOpenJob(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	rev := releaseTestRevision(t, store, m, "running-job-revision", state.RevisionRetired, time.Now())
	if _, err := store.StartJobRun(ctx, state.JobRun{App: m.App, Revision: rev.ID, Workload: "web", Kind: JobCron, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	keep, err := gcResourcesToKeep(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if !keep.revisions[rev.App+"/"+rev.ID] || !keep.images[rev.Images["web"]] {
		t.Fatal("GC discarded the image and manifest needed by an unfinished job")
	}
}

func TestGCTrimsFailedDeploymentsBeforeAnAppEverBecomesActive(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	at := time.Now().UTC()
	for i := range retiredKept + 2 {
		releaseTestRevision(t, store, m, fmt.Sprintf("failed-revision-%d", i), state.RevisionFailed, at.Add(time.Duration(i)*time.Minute))
	}
	if err := (GC{Store: store}).forgetStep().Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	revisions, err := store.Revisions(ctx, m.App)
	if err != nil || len(revisions) != retiredKept {
		t.Fatalf("failed first deployments escaped history retention: %d revisions, %v", len(revisions), err)
	}
	if _, err := store.GetRevision(ctx, m.App, "failed-revision-0"); err == nil {
		t.Fatal("GC kept the oldest failed deployment")
	}
}
