package app

import (
	"context"
	"encoding/json"
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

const rehearsalYAML = `app: site
data:
  volumes: {files: {}}
release:
  data_compatibility: restore-required
workloads:
  second:
    kind: release
    order: 2
    image: alpine:3.21
    user: "0"
    command: ["true"]
  first:
    kind: release
    order: 1
    image: alpine:3.21
    user: "0"
    command: ["true"]
`

func rehearsalFixture(t *testing.T) (Rehearse, RehearseInput, *manifest.Manifest) {
	t.Helper()
	ctx := context.Background()
	source := t.TempDir()
	os.WriteFile(filepath.Join(source, manifest.FileName), []byte(rehearsalYAML), 0o600)
	m, err := manifest.Load(source)
	if err != nil {
		t.Fatal(err)
	}
	store := releaseTestStore(t)
	sec := newSecrets(t)
	sec.Set(m.App, "ORIGINAL", "pinned-original-secret")
	version, _ := sec.Current(m.App)
	encoded, _ := json.Marshal(m)
	rev := state.Revision{App: m.App, ID: "active-rev", Status: state.RevisionActive, Manifest: encoded, SecretsVersion: version, CreatedAt: time.Now().UTC()}
	store.SaveRevision(ctx, rev)
	store.Activate(ctx, m.App, rev.ID, time.Now().UTC())
	sec.Set(manifest.ReservedApp, "STORAGE_KIND", "s3")
	sec.Set(manifest.ReservedApp, "STORAGE_ENDPOINT", "http://store:9000")
	sec.Set(manifest.ReservedApp, "STORAGE_KEY_ID", "test-key")
	sec.Set(manifest.ReservedApp, "STORAGE_KEY", "storage-secret")
	sec.Set(manifest.ReservedApp, "STORAGE_PASSWORD", "backup-password")
	sec.Set(manifest.ReservedApp, "STORAGE_BUCKET_PREFIX", "lane")
	return Rehearse{Store: store, Secrets: sec, StateDir: t.TempDir()}, RehearseInput{Source: source, Revision: "candidate-rev"}, m
}

func TestRehearsalSourceCapturePinsBytesAndModesAndRejectsLinks(t *testing.T) {
	from, to := t.TempDir(), filepath.Join(t.TempDir(), "capture")
	dir := filepath.Join(from, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "program")
	os.WriteFile(path, []byte("before"), 0o700)
	os.Chmod(path, 0o751)
	os.Chmod(dir, 0o777)
	before, err := rehearsalSourceHash(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyRehearsalSource(from, to); err != nil {
		t.Fatal(err)
	}
	copied, err := rehearsalSourceHash(to)
	if err != nil || before != copied {
		t.Fatalf("capture does not preserve identity: %s %s %v", before, copied, err)
	}
	os.WriteFile(path, []byte("after"), 0o700)
	after, _ := rehearsalSourceHash(from)
	if after == before {
		t.Fatal("source byte change did not alter identity")
	}
	os.Symlink(path, filepath.Join(from, "link"))
	if _, err := rehearsalSourceHash(from); err == nil {
		t.Fatal("source symlink admitted")
	}
}

func TestRehearsalPlanDigestPinsCandidateBytes(t *testing.T) {
	def, in, _ := rehearsalFixture(t)
	registry := kernel.Registry{}
	registry.Add(def)
	engine := kernel.New(def.Store, registry, "test")
	raw, _ := json.Marshal(in)
	first, err := engine.PlanOnly(context.Background(), RehearseKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(in.Source, "candidate.txt"), []byte("changed"), 0o600)
	second, err := engine.PlanOnly(context.Background(), RehearseKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Fatal("changed candidate retained approved digest")
	}
	if first.Recovery != kernel.Compensate {
		t.Fatal("interrupted rehearsal can be resumed with stale scratch state")
	}
	operations, _ := def.Store.List(context.Background(), 10)
	if len(operations) != 0 {
		t.Fatal("planning journaled an operation")
	}
}

func TestRehearsalReleaseSpecCannotMountLiveDataOrPublishPorts(t *testing.T) {
	m := releaseTestManifest()
	w := m.Workloads["migrate"]
	w.Mounts = []manifest.Mount{{Volume: "files", Path: "/files"}}
	w.Ports = []manifest.PublishedPort{{Port: 9000}}
	m.Workloads["migrate"] = w
	names := rehearsalNames(t.TempDir(), m, "candidate-rev")
	image := "sha256:immutable-image"
	spec, err := rehearsalReleaseSpec(m, "candidate-rev", "migrate", image, map[string]string{}, names)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Image != image || spec.Restart || len(spec.Publish) != 0 || !slices.Equal(spec.Networks, []string{names.network}) || !slices.Equal(spec.Mounts, []string{names.volumes["files"] + ":/files"}) {
		t.Fatalf("unsafe scratch spec: %+v", spec)
	}
	if names.volumes["files"] == docker.VolumeName(m.App, "files") || names.network == docker.AppNetwork(m.App) {
		t.Fatal("scratch names collide with live resources")
	}
}

func TestPinnedScratchSecretsUseOriginalVersionAndNeverRotateLiveValues(t *testing.T) {
	original := newSecrets(t)
	version, err := original.Set("site", "TOKEN", "old-value")
	if err != nil {
		t.Fatal(err)
	}
	current, err := original.Set("site", "TOKEN", "new-value")
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := copyPinnedRehearsalSecrets(original, &state.Revision{App: "site", SecretsVersion: version}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	values, _, _ := scratch.LoadCurrent("site")
	if values["TOKEN"] != "old-value" {
		t.Fatal("scratch followed current instead of pinned original")
	}
	scratch.Set("site", "TOKEN", "scratch-only")
	values, v, _ := original.LoadCurrent("site")
	if v != current || values["TOKEN"] != "new-value" {
		t.Fatal("scratch mutated live secrets")
	}
}

func TestRehearsalRunsReleasesInOrderRecordsExactEvidenceAndCleansFailure(t *testing.T) {
	for _, failRelease := range []bool{false, true} {
		t.Run(map[bool]string{false: "pass", true: "release-failure"}[failRelease], func(t *testing.T) {
			def, in, m := rehearsalFixture(t)
			fake := dockertest.New(t)
			roomToRestore(t)
			// Internal network inspection is part of the scratch safety contract.
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
				if path != "/images/json" && strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json") {
					json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:" + strings.Repeat("b", 64), "RepoDigests": []string{"alpine@sha256:" + strings.Repeat("b", 64)}, "Config": map[string]any{"User": "0"}})
					return
				}
				fake.ServeHTTP(w, r)
			}))
			defer proxy.Close()
			t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
			snapshot := strings.Repeat("a", 64)
			var releases []string
			var snapshots []string
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.ExitAfter = 1
					if c.Cmd[0] == "snapshots" {
						c.Logs = `[{"id":"` + snapshot + `","short_id":"aaaaaaaa","time":"2026-10-10T00:00:00Z","summary":{"total_bytes_processed":12}}]`
					}
					if c.Cmd[0] == "restore" {
						snapshots = append(snapshots, c.Cmd[1])
						c.Logs = `{"message_type":"summary","total_files":1,"files_restored":1}`
					}
					if strings.Contains(c.Name, ".workload.") {
						name := strings.TrimPrefix(c.Name, "bedrock.site.rehearse.candidate-rev.workload.")
						releases = append(releases, name)
						if failRelease && name == "second" {
							c.ExitCode = 7
						}
					}
				})
			}
			raw, _ := json.Marshal(in)
			plan, err := def.Plan(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range plan.Steps {
				err = step.Apply(context.Background(), io.Discard)
				if err != nil {
					break
				}
			}
			if failRelease {
				if err == nil || !strings.Contains(err.Error(), "scratch release second failed") {
					t.Fatalf("%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(releases, []string{"first", "second"}) {
				t.Fatalf("release order: %v", releases)
			}
			if !slices.Equal(snapshots, []string{snapshot}) {
				t.Fatalf("restore not pinned: %v", snapshots)
			}
			data, err := os.ReadFile(RehearsalProofPath(def.StateDir, m.App, in.Revision))
			if err != nil {
				t.Fatal(err)
			}
			var proof RehearsalProof
			if err := json.Unmarshal(data, &proof); err != nil {
				t.Fatal(err)
			}
			expected := "passed"
			if failRelease {
				expected = "failed"
			}
			if proof.Status != expected || proof.Snapshot != snapshot || proof.SourceSHA256 == "" || proof.Images["first"] == "" || proof.Images["first"] != proof.Images["second"] {
				t.Fatalf("incomplete evidence: %+v", proof)
			}
			for _, name := range []string{"first", "second"} {
				if _, exists := fake.Container("bedrock.site.rehearse.candidate-rev.workload." + name); exists {
					t.Fatal("release scratch container left after finish")
				}
			}
			current, _ := def.Store.RevisionWithStatus(context.Background(), m.App, state.RevisionActive)
			if current == nil || current.ID != "active-rev" {
				t.Fatal("rehearsal changed live authority")
			}
			if strings.Contains(string(data), "pinned-original-secret") || strings.Contains(string(data), "storage-secret") {
				t.Fatal("proof contains credentials")
			}
		})
	}
}

func TestRehearsalSourceChangedAfterPlanIsReportedFailedAndCleanupErrorsAreVisible(t *testing.T) {
	def, in, m := rehearsalFixture(t)
	fake := dockertest.New(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/volumes/") && r.Method == http.MethodDelete {
			w.WriteHeader(500)
			io.WriteString(w, `{"message":"cleanup failed"}`)
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	raw, _ := json.Marshal(in)
	plan, err := def.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(in.Source, "new-code"), []byte("new"), 0o600)
	plan.Steps[0].Apply(context.Background(), io.Discard)
	err = plan.Steps[1].Apply(context.Background(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "source changed") || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("%v", err)
	}
	data, err := os.ReadFile(RehearsalProofPath(def.StateDir, m.App, in.Revision))
	if err != nil {
		t.Fatal(err)
	}
	var proof RehearsalProof
	json.Unmarshal(data, &proof)
	if proof.Status != "failed" {
		t.Fatalf("false passed proof: %+v", proof)
	}
}

func TestInterruptedRehearsalCanCompensateAfterRemoteSourceDisappears(t *testing.T) {
	def, in, m := rehearsalFixture(t)
	fake := dockertest.New(t)
	raw, _ := json.Marshal(in)
	registry := kernel.Registry{}
	registry.Add(def)
	engine := kernel.New(def.Store, registry, "test")
	before, err := engine.PlanOnly(context.Background(), RehearseKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := def.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(in.Source); err != nil {
		t.Fatal(err)
	}
	def.Store.SetRevisionStatus(context.Background(), m.App, "active-rev", state.RevisionRetired)
	rebuilt, err := def.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	after, err := engine.PlanOnly(context.Background(), RehearseKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest != after.Digest {
		t.Fatal("cleanup plan changed when source or live authority disappeared")
	}
	name := "bedrock.site.rehearse.candidate-rev.workload.first"
	fake.Add(dockertest.Container{Name: name, Running: true, Labels: imageLabels(m.App, "first", in.Revision)})
	if err := rebuilt.Steps[0].Undo(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, exists := fake.Container(name); exists {
		t.Fatal("interrupted release container survived compensation")
	}
	data, err := os.ReadFile(RehearsalProofPath(def.StateDir, m.App, in.Revision))
	if err != nil {
		t.Fatal(err)
	}
	var proof RehearsalProof
	json.Unmarshal(data, &proof)
	if proof.Status != "failed" || !strings.Contains(proof.Error, "interrupted") {
		t.Fatalf("interruption has no failed proof: %+v", proof)
	}
	if _, err := os.Stat(rehearsalReservationPath(def.StateDir, in)); !os.IsNotExist(err) {
		t.Fatal("completed compensation left reservation")
	}
}
