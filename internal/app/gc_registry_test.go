package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/state"
)

const (
	ociIndex    = "application/vnd.oci.image.index.v1+json"
	ociManifest = "application/vnd.oci.image.manifest.v1+json"
)

// registryStandIn answers the local registry's HTTP API from memory. Every
// image is pushed as a build pushes it: an index of the image's manifest
// and its attestation's.
type registryStandIn struct {
	mu        sync.Mutex
	server    *httptest.Server
	pageSize  int
	tags      map[string]map[string]string   // repository, tag, index digest
	manifests map[string]map[string][]string // repository, digest, what an index lists
	deletes   []string
}

func newRegistryStandIn(t *testing.T) *registryStandIn {
	t.Helper()
	r := &registryStandIn{pageSize: 100, tags: map[string]map[string]string{}, manifests: map[string]map[string][]string{}}
	r.server = httptest.NewServer(r)
	t.Cleanup(r.server.Close)
	return r
}

func (r *registryStandIn) addr() string { return strings.TrimPrefix(r.server.URL, "http://") }

func fakeDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// push tags image in repo and returns its index's digest. Pushing one image
// twice stores the same content.
func (r *registryStandIn) push(repo, tag, image string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := fakeDigest(image + " index")
	listed := []string{fakeDigest(image + " image"), fakeDigest(image + " attestation")}
	if r.manifests[repo] == nil {
		r.manifests[repo], r.tags[repo] = map[string][]string{}, map[string]string{}
	}
	r.manifests[repo][index] = listed
	for _, d := range listed {
		r.manifests[repo][d] = nil
	}
	r.tags[repo][tag] = index
	return index
}

// pullable reports whether repo:tag and every manifest its index lists are
// still there.
func (r *registryStandIn) pullable(repo, tag string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	listed, ok := r.manifests[repo][r.tags[repo][tag]]
	if !ok {
		return false
	}
	for _, d := range listed {
		if _, ok := r.manifests[repo][d]; !ok {
			return false
		}
	}
	return true
}

// stored reports whether any manifest of image is still in repo.
func (r *registryStandIn) stored(repo, image string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, part := range []string{" index", " image", " attestation"} {
		if _, ok := r.manifests[repo][fakeDigest(image+part)]; ok {
			return true
		}
	}
	return false
}

func (r *registryStandIn) deleted() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.deletes)
}

func (r *registryStandIn) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := strings.TrimPrefix(req.URL.Path, "/v2/")
	switch {
	case path == "":
		w.WriteHeader(http.StatusOK)
	case path == "_catalog":
		r.page(w, req, map[string]any{}, "repositories", slices.Sorted(maps.Keys(r.manifests)))
	case strings.HasSuffix(path, "/tags/list"):
		repo := strings.TrimSuffix(path, "/tags/list")
		if len(r.tags[repo]) == 0 {
			registryError(w, "NAME_UNKNOWN")
			return
		}
		r.page(w, req, map[string]any{"name": repo}, "tags", slices.Sorted(maps.Keys(r.tags[repo])))
	case strings.Contains(path, "/manifests/"):
		at := strings.LastIndex(path, "/manifests/")
		repo, ref := path[:at], path[at+len("/manifests/"):]
		digest := ref
		if !strings.HasPrefix(ref, "sha256:") {
			digest = r.tags[repo][ref]
		}
		listed, ok := r.manifests[repo][digest]
		if !ok {
			registryError(w, "MANIFEST_UNKNOWN")
			return
		}
		if req.Method == http.MethodDelete {
			r.deletes = append(r.deletes, repo+" "+ref)
			if ref == digest {
				delete(r.manifests[repo], digest)
				maps.DeleteFunc(r.tags[repo], func(_, d string) bool { return d == digest })
			} else {
				delete(r.tags[repo], ref)
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		mediaType, body := ociManifest, map[string]any{"schemaVersion": 2, "mediaType": ociManifest, "layers": []any{}}
		if listed != nil {
			var manifests []map[string]string
			for _, d := range listed {
				manifests = append(manifests, map[string]string{"mediaType": ociManifest, "digest": d})
			}
			mediaType, body = ociIndex, map[string]any{"schemaVersion": 2, "mediaType": ociIndex, "manifests": manifests}
		}
		// Like distribution, it offers an index only to a client that accepts one.
		if !strings.Contains(req.Header.Get("Accept"), mediaType) {
			registryError(w, "MANIFEST_UNKNOWN")
			return
		}
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Docker-Content-Digest", digest)
		_ = json.NewEncoder(w).Encode(body)
	default:
		registryError(w, "NAME_UNKNOWN")
	}
}

// page answers one page of a listing and links the next, as distribution does.
func (r *registryStandIn) page(w http.ResponseWriter, req *http.Request, body map[string]any, key string, items []string) {
	start := 0
	if last := req.URL.Query().Get("last"); last != "" {
		start = sort.SearchStrings(items, last)
		if start < len(items) && items[start] == last {
			start++
		}
	}
	end := min(start+r.pageSize, len(items))
	body[key] = items[start:end]
	if end < len(items) {
		next := url.Values{"last": {items[end-1]}, "n": {fmt.Sprint(r.pageSize)}}
		w.Header().Set("Link", "<"+req.URL.Path+"?"+next.Encode()+`>; rel="next"`)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func registryError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{"errors":[{"code":%q}]}`, code)
}

// registryCLI stands in for the docker commands run inside the registry's
// container and returns those run so far. Its storage shrinks from 3 MiB
// to 1 MiB once garbage-collect has run.
func registryCLI(t *testing.T) func() []string {
	t.Helper()
	calls := filepath.Join(t.TempDir(), "calls")
	dockerCLI(t, `echo "$*" >> "`+calls+`"
case "$*" in *" du "*)
	if grep -q garbage-collect "`+calls+`"; then echo "1024	/var/lib/registry"; else echo "3072	/var/lib/registry"; fi ;;
esac`)
	return func() []string {
		data, _ := os.ReadFile(calls)
		return strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' })
	}
}

// registryRevision records a revision of the fixture app whose web image a
// build pushed to reg.
func registryRevision(t *testing.T, store *state.Store, reg *registryStandIn, id string, status state.RevisionStatus, at time.Time) {
	t.Helper()
	rev := releaseTestRevision(t, store, releaseTestManifest(), id, status, at)
	rev.Images = map[string]string{"web": docker.Registry + "/site/web@" + reg.push("site/web", id, id)}
	if err := store.SaveRevision(context.Background(), *rev); err != nil {
		t.Fatal(err)
	}
}

// collectAgainst runs a whole collection, keeping the build cache, with the
// local registry at addr, and returns what it said.
func collectAgainst(t *testing.T, store *state.Store, addr string) (string, error) {
	t.Helper()
	ctx := context.Background()
	dockertest.New(t)
	plan, err := (GC{Store: store, Registry: addr}).Plan(ctx, json.RawMessage(`{"keep_build_cache":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, step := range plan.Steps {
		if err := step.Apply(ctx, &out); err != nil {
			return out.String(), fmt.Errorf("%s: %w", step.Name, err)
		}
	}
	return out.String(), nil
}

var registryDay = time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)

func TestGCDeletesRegistryImagesOfRevisionsItNoLongerHasOnRecord(t *testing.T) {
	store := releaseTestStore(t)
	reg := newRegistryStandIn(t)
	active := NewRevision(registryDay.Add(time.Hour))
	registryRevision(t, store, reg, active, state.RevisionActive, registryDay.Add(time.Hour))
	var retired []string
	for i := range retiredKept + 1 {
		at := registryDay.Add(time.Duration(i) * time.Minute)
		registryRevision(t, store, reg, NewRevision(at), state.RevisionRetired, at)
		retired = append(retired, NewRevision(at))
	}
	// Forgotten by a collection that left the registry alone.
	earlier := NewRevision(registryDay.Add(-24 * time.Hour))
	reg.push("site/web", earlier, earlier)
	calls := registryCLI(t)

	out, err := collectAgainst(t, store, reg.addr())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{earlier, retired[0]} {
		if reg.stored("site/web", id) {
			t.Errorf("site/web:%s stayed in the registry with no revision on record", id)
		}
		if !strings.Contains(out, "deleted site/web:"+id+"\n") {
			t.Errorf("the collection did not say it deleted site/web:%s:\n%s", id, out)
		}
	}
	for _, id := range append([]string{active}, retired[1:]...) {
		if !reg.pullable("site/web", id) {
			t.Errorf("site/web:%s, which a revision on record uses, can no longer be pulled", id)
		}
	}
	collected, restarted := false, false
	for _, call := range calls() {
		args := strings.Fields(call)
		switch {
		case slices.Contains(args, "garbage-collect"):
			// Untagged manifests stay: an image pushed by hand can be
			// deployed by digest after its tag moved on.
			if slices.Contains(args, "--delete-untagged") || slices.Contains(args, "-m") {
				t.Errorf("garbage-collect also deletes untagged images: %s", call)
			}
			collected = true
		case call == "restart "+docker.RegistryContainer:
			restarted = collected
		}
	}
	if !collected || !restarted {
		t.Errorf("the registry's storage was not reclaimed, then the registry restarted: %q", calls())
	}
	if !strings.Contains(out, "reclaimed 2 MB of registry storage\n") {
		t.Errorf("the collection did not say what it reclaimed:\n%s", out)
	}
}

func TestGCKeepsRegistryImagesThatRevisionsOnRecordUse(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	reg := newRegistryStandIn(t)
	active, retired := NewRevision(registryDay.Add(time.Hour)), NewRevision(registryDay)
	registryRevision(t, store, reg, active, state.RevisionActive, registryDay.Add(time.Hour))
	registryRevision(t, store, reg, retired, state.RevisionRetired, registryDay)
	// The active revision's image, under a tag of a forgotten revision.
	sameImage := NewRevision(registryDay.Add(-3 * time.Hour))
	reg.push("site/web", sameImage, active)
	// A restored revision records the image's ID, which is its index's digest.
	restored := releaseTestRevision(t, store, releaseTestManifest(), "restored-revision", state.RevisionRetired, registryDay.Add(-time.Hour))
	byID := NewRevision(registryDay.Add(-2 * time.Hour))
	restored.Images = map[string]string{"web": reg.push("site/web", byID, "restored image")}
	if err := store.SaveRevision(ctx, *restored); err != nil {
		t.Fatal(err)
	}
	// An unfinished job keeps its revision's image though the revision is gone.
	running := NewRevision(registryDay.Add(-4 * time.Hour))
	reg.push("site/web", running, running)
	if _, err := store.StartJobRun(ctx, state.JobRun{App: "site", Revision: running, Workload: "web", Kind: JobCron, StartedAt: registryDay}); err != nil {
		t.Fatal(err)
	}
	calls := registryCLI(t)

	if _, err := collectAgainst(t, store, reg.addr()); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{active, retired, sameImage, byID, running} {
		if !reg.pullable("site/web", tag) {
			t.Errorf("site/web:%s is in use but can no longer be pulled", tag)
		}
	}
	if deleted := reg.deleted(); len(deleted) != 0 {
		t.Errorf("the collection deleted %q", deleted)
	}
	if ran := calls(); len(ran) != 0 {
		t.Errorf("with nothing deleted the registry was still collected: %q", ran)
	}
}

func TestGCLeavesRegistryImagesHeliosDidNotPushAlone(t *testing.T) {
	store := releaseTestStore(t)
	reg := newRegistryStandIn(t)
	active := NewRevision(registryDay)
	registryRevision(t, store, reg, active, state.RevisionActive, registryDay)
	forgotten := NewRevision(registryDay.Add(-time.Hour))
	reg.push("site/web", forgotten, forgotten)
	// Pushed by hand: a tag that is no revision, on a forgotten revision's
	// image, and repositories helios does not name.
	reg.push("site/web", "latest", forgotten)
	for _, repo := range []string{"site-tools", "other/web", "site/web/cache"} {
		reg.push(repo, forgotten, repo)
	}
	registryCLI(t)

	if _, err := collectAgainst(t, store, reg.addr()); err != nil {
		t.Fatal(err)
	}
	if deleted := reg.deleted(); !slices.Equal(deleted, []string{"site/web " + forgotten}) {
		t.Errorf("the collection deleted %q, want only the forgotten revision's tag", deleted)
	}
	if !reg.pullable("site/web", "latest") || reg.pullable("site/web", forgotten) {
		t.Error("the forgotten revision's tag should go and the hand-pushed tag on its image stay")
	}
	for _, repo := range []string{"site-tools", "other/web", "site/web/cache"} {
		if !reg.pullable(repo, forgotten) {
			t.Errorf("the collection changed %s, which helios never pushed", repo)
		}
	}
}

func TestGCFindsRegistryImagesOnEveryPage(t *testing.T) {
	store := releaseTestStore(t)
	reg := newRegistryStandIn(t)
	reg.pageSize = 1
	for i := range 2 {
		at := registryDay.Add(time.Duration(i) * time.Hour)
		registryRevision(t, store, reg, NewRevision(at), state.RevisionRetired, at)
	}
	reg.push("other/web", "latest", "other")
	reg.push("aaa", "latest", "aaa")
	last := NewRevision(registryDay.Add(5 * time.Hour))
	reg.push("site/web", last, last)
	registryCLI(t)

	if _, err := collectAgainst(t, store, reg.addr()); err != nil {
		t.Fatal(err)
	}
	if reg.stored("site/web", last) {
		t.Error("the forgotten revision on the last page of the last repository stayed")
	}
}

func TestGCSaysHowToStartAMissingRegistry(t *testing.T) {
	store := releaseTestStore(t)
	releaseTestRevision(t, store, releaseTestManifest(), NewRevision(registryDay), state.RevisionActive, registryDay)
	gone := newRegistryStandIn(t)
	gone.server.Close()

	_, err := collectAgainst(t, store, gone.addr())
	if err == nil || !strings.HasPrefix(err.Error(), "registry: ") || !strings.Contains(err.Error(), "docker start "+docker.RegistryContainer) {
		t.Fatalf("got %v, want the registry step to say how to start the registry", err)
	}
}
