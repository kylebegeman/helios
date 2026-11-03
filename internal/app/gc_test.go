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
// Image sha256:<name> has one name, test/<name>:latest, and answers to its ID
// and test/<name>@sha256:<name> too; removing it by any of them removes it.
func gcImageFixture(t *testing.T, fake *dockertest.Server, images map[string]map[string]string) func(string) bool {
	t.Helper()
	var mu sync.Mutex
	repository := func(id string) string { return "test/" + strings.TrimPrefix(id, "sha256:") }
	resolve := func(ref string) (string, bool) {
		for id := range images {
			if ref == id || ref == repository(id)+":latest" || ref == repository(id)+"@"+id {
				return id, true
			}
		}
		return "", false
	}
	describe := func(id string) map[string]any {
		return map[string]any{"Id": id, "Labels": images[id], "Config": map[string]any{"Labels": images[id]}, "RepoTags": []string{repository(id) + ":latest"}, "RepoDigests": []string{repository(id) + "@" + id}}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		ref, image := strings.CutPrefix(path, "/images/")
		inspect := r.Method == http.MethodGet && strings.HasSuffix(ref, "/json")
		if !image || !(ref == "json" || inspect || r.Method == http.MethodDelete) {
			fake.ServeHTTP(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if ref == "json" {
			listed := []any{}
			for id := range images {
				listed = append(listed, describe(id))
			}
			_ = json.NewEncoder(w).Encode(listed)
			return
		}
		id, ok := resolve(strings.TrimSuffix(ref, "/json"))
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "No such image: " + ref})
		case inspect:
			_ = json.NewEncoder(w).Encode(describe(id))
		default:
			delete(images, id)
			_ = json.NewEncoder(w).Encode([]any{})
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
	plan, err := (GC{Store: store, Registry: newRegistryStandIn(t).addr()}).Plan(ctx, json.RawMessage(`{"keep_build_cache":true}`))
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
			// Pulled images carry no helios label; only the revisions record them.
			target.Images = map[string]string{"web": "test/checkpoint-pull@sha256:checkpoint-pull"}
			if err := store.SaveRevision(ctx, *target); err != nil {
				t.Fatal(err)
			}
			releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, at.Add(20*time.Minute))
			if err := store.Activate(ctx, m.App, "active-revision", at.Add(20*time.Minute)); err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= retiredKept+1; i++ {
				rev := releaseTestRevision(t, store, m, fmt.Sprintf("ordinary-old-%d", i), state.RevisionRetired, at.Add(time.Duration(i)*time.Minute))
				if i == 1 {
					rev.Images = map[string]string{"web": "test/obsolete-pull@sha256:obsolete-pull"}
					if err := store.SaveRevision(ctx, *rev); err != nil {
						t.Fatal(err)
					}
				}
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
				"sha256:checkpoint-pull":  nil,
				"sha256:obsolete-pull":    nil,
			})
			runCollection(t, store)
			if _, err := store.GetRevision(ctx, m.App, target.ID); err != nil || !imageExists("sha256:checkpoint-image") || !imageExists("sha256:checkpoint-pull") {
				t.Fatal("retained data checkpoint lost its required revision or image", err)
			}
			if _, err := store.GetRevision(ctx, m.App, "ordinary-old-1"); err == nil || imageExists("sha256:obsolete-image") {
				t.Fatal("unreferenced history stopped being collected")
			}
			if imageExists("sha256:obsolete-pull") {
				t.Fatal("forgetting the only revision that recorded a pulled image left the image behind")
			}
			if err := store.FinishReleaseBoundary(ctx, m.App, boundary.Revision, state.ReleaseRestored, "", at.Add(21*time.Minute)); err != nil {
				t.Fatal(err)
			}
			// The checkpoint no longer protects a target once restoration has
			// completed and that revision is no longer active or previous.
			runCollection(t, store)
			if _, err := store.GetRevision(ctx, m.App, target.ID); err == nil || imageExists("sha256:checkpoint-image") || imageExists("sha256:checkpoint-pull") {
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
	// The two oldest are forgotten. One image stays recorded by a kept
	// revision under its ID, and one stays in use by a stopped container.
	pulled := map[int]map[string]string{
		0:               {"web": "test/kept-pull@sha256:kept-pull", "migrate": "test/failed-pull@sha256:failed-pull"},
		1:               {"web": "test/stopped-pull:latest"},
		retiredKept + 1: {"web": "sha256:kept-pull"},
	}
	for i := range retiredKept + 2 {
		rev := releaseTestRevision(t, store, m, fmt.Sprintf("failed-revision-%d", i), state.RevisionFailed, at.Add(time.Duration(i)*time.Minute))
		if images, ok := pulled[i]; ok {
			rev.Images = images
			if err := store.SaveRevision(ctx, *rev); err != nil {
				t.Fatal(err)
			}
		}
	}
	fake := dockertest.New(t)
	fake.Add(dockertest.Container{Name: "stopped-example", Image: "test/stopped-pull:latest", ImageID: "sha256:stopped-pull"})
	imageExists := gcImageFixture(t, fake, map[string]map[string]string{"sha256:kept-pull": nil, "sha256:failed-pull": nil, "sha256:stopped-pull": nil})
	if err := (GC{Store: store}).forgetStep().Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	if imageExists("sha256:failed-pull") {
		t.Fatal("GC kept an image only forgotten deployments recorded")
	}
	if !imageExists("sha256:kept-pull") || !imageExists("sha256:stopped-pull") {
		t.Fatal("GC removed an image a remaining revision records or a stopped container uses")
	}
	revisions, err := store.Revisions(ctx, m.App)
	if err != nil || len(revisions) != retiredKept {
		t.Fatalf("failed first deployments escaped history retention: %d revisions, %v", len(revisions), err)
	}
	if _, err := store.GetRevision(ctx, m.App, "failed-revision-0"); err == nil {
		t.Fatal("GC kept the oldest failed deployment")
	}
}
