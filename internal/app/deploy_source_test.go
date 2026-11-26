package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func deploySourceFixture(t *testing.T) (Deploy, DeployInput) {
	t.Helper()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, manifest.FileName), []byte("app: site\nworkloads:\n  web: {kind: worker, image: alpine}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "app.txt"), []byte("approved source"), 0644); err != nil {
		t.Fatal(err)
	}
	return Deploy{Store: releaseTestStore(t), Secrets: newSecrets(t), StateDir: t.TempDir()}, DeployInput{Source: source, Revision: "candidate-revision"}
}

func TestDeployPlanDigestPinsSourceBytesAndPermissionModes(t *testing.T) {
	d, in := deploySourceFixture(t)
	registry := kernel.Registry{}
	registry.Add(d)
	engine := kernel.New(d.Store, registry, "test")
	raw, _ := json.Marshal(in)
	before, err := engine.PlanOnly(context.Background(), DeployKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.Source, "app.txt"), []byte("changed source"), 0644); err != nil {
		t.Fatal(err)
	}
	after, err := engine.PlanOnly(context.Background(), DeployKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest == after.Digest {
		t.Fatal("source changed without changing its deploy approval digest")
	}
	if err := os.Chmod(filepath.Join(in.Source, "app.txt"), 0755); err != nil {
		t.Fatal(err)
	}
	mode, err := engine.PlanOnly(context.Background(), DeployKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	if after.Digest == mode.Digest {
		t.Fatal("executable mode changed without changing its deploy approval digest")
	}
}

func TestDeployRefusesSourceChangesBetweenPlanningAndCapture(t *testing.T) {
	d, in := deploySourceFixture(t)
	raw, _ := json.Marshal(in)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.Source, "app.txt"), []byte("unapproved source"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "source changed") {
		t.Fatalf("unapproved source was captured: %v", err)
	}
	if revs, err := d.Store.Revisions(context.Background(), "site"); err != nil || len(revs) != 0 {
		t.Fatalf("stale source mutated revision state: %+v %v", revs, err)
	}
}

func TestDeployRecoveryUsesCapturedBytesAfterOriginalSourceDisappears(t *testing.T) {
	d, in := deploySourceFixture(t)
	if err := os.Mkdir(filepath.Join(in.Source, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.Source, ".git", "HEAD"), []byte("version metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("app.txt", filepath.Join(in.Source, "relative-link")); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	registry := kernel.Registry{}
	registry.Add(d)
	engine := kernel.New(d.Store, registry, "test")
	before, err := engine.PlanOnly(context.Background(), DeployKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	captured := filepath.Join(deploySourceDir(d.StateDir, "site", in.Revision), "source")
	if got, err := os.ReadFile(filepath.Join(captured, "app.txt")); err != nil || string(got) != "approved source" {
		t.Fatalf("wrong source capture: %q %v", got, err)
	}
	if link, err := os.Readlink(filepath.Join(captured, "relative-link")); err != nil || link != "app.txt" {
		t.Fatalf("safe link changed: %q %v", link, err)
	}
	if got, err := os.ReadFile(filepath.Join(captured, ".git", "HEAD")); err != nil || string(got) != "version metadata" {
		t.Fatalf("git version metadata lost: %q %v", got, err)
	}
	if err := os.RemoveAll(in.Source); err != nil {
		t.Fatal(err)
	}
	after, err := engine.PlanOnly(context.Background(), DeployKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest != after.Digest {
		t.Fatal("captured deployment cannot recover its approved digest")
	}
	recovered, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Steps[len(recovered.Steps)-1].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(captured); !os.IsNotExist(err) {
		t.Fatalf("completed deployment retained source: %v", err)
	}
	finished, err := engine.PlanOnly(context.Background(), DeployKind, raw)
	if err != nil || finished.Digest != before.Digest {
		t.Fatalf("cleanup lost final receipt recovery: %+v %v", finished, err)
	}
}

type captureOnlyDeploy struct{ Deploy }

func (d captureOnlyDeploy) Kind() string { return "test.deploy.capture" }
func (d captureOnlyDeploy) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	plan, err := d.Deploy.Plan(ctx, raw)
	if err != nil {
		return nil, err
	}
	plan.Steps = plan.Steps[:1]
	return plan, nil
}

func TestCapturedDeploySourceCannotBeAdoptedByAnotherOperation(t *testing.T) {
	d, in := deploySourceFixture(t)
	registry := kernel.Registry{}
	registry.Add(captureOnlyDeploy{d})
	engine := kernel.New(d.Store, registry, "test")
	raw, _ := json.Marshal(in)
	first, err := engine.Run(context.Background(), "test.deploy.capture", raw, func(kernel.Event) {})
	if err != nil || first.Status != state.Succeeded {
		t.Fatalf("capture failed: %+v %v", first, err)
	}
	second, err := engine.Run(context.Background(), "test.deploy.capture", raw, func(kernel.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != state.Failed || !strings.Contains(second.Error, "another operation") {
		t.Fatalf("new operation adopted another capture: %+v", second)
	}
}

func TestDeploySourceCaptureRefusesEscapingLinksAndItsOwnStateTree(t *testing.T) {
	for _, link := range []string{"../outside", "/etc/passwd"} {
		t.Run(link, func(t *testing.T) {
			d, in := deploySourceFixture(t)
			if err := os.Symlink(link, filepath.Join(in.Source, "unsafe-link")); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(in)
			if _, err := d.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "outside") {
				t.Fatalf("escaping link accepted: %v", err)
			}
		})
	}
	d, in := deploySourceFixture(t)
	d.StateDir = filepath.Join(in.Source, "state")
	raw, _ := json.Marshal(in)
	if _, err := d.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "build captures") {
		t.Fatalf("recursive source capture accepted: %v", err)
	}
}

func TestDeploySourceCaptureRefusesASymlinkedStateDirectoryInsideSource(t *testing.T) {
	d, in := deploySourceFixture(t)
	outside := t.TempDir()
	if err := os.Symlink(in.Source, filepath.Join(outside, "state")); err != nil {
		t.Fatal(err)
	}
	d.StateDir = filepath.Join(outside, "state")
	raw, _ := json.Marshal(in)
	if _, err := d.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "build captures") {
		t.Fatalf("symlinked recursive capture accepted: %v", err)
	}
}

func TestRemovingAnAppClearsItsDeployReservationsAndKeepsOtherApps(t *testing.T) {
	d, in := deploySourceFixture(t)
	raw, _ := json.Marshal(in)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	other := deploySourceReservation{Manifest: manifest.Manifest{App: "other"}}
	otherPath := filepath.Join(d.StateDir, "builds", ".pending", "other.json")
	if err := writeRehearsalJSON(otherPath, other); err != nil {
		t.Fatal(err)
	}
	if err := forgetApp(context.Background(), d.Store, d.Secrets, d.StateDir, "site", false, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(deploySourceReservationPath(d.StateDir, in)); !os.IsNotExist(err) {
		t.Fatalf("removed app retained a deploy reservation: %v", err)
	}
	if _, err := os.Stat(otherPath); err != nil {
		t.Fatalf("other app's reservation removed: %v", err)
	}
}

func TestDeploySourceRefusesComposedEscapingLinks(t *testing.T) {
	d, in := deploySourceFixture(t)
	if err := os.Mkdir(filepath.Join(in.Source, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(in.Source, "sub", "up")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/up/../external-file", filepath.Join(in.Source, "escape")); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	if _, err := d.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("composed external link was approved: %v", err)
	}
}

func TestDeploySourceKeepsSafeDanglingLinks(t *testing.T) {
	d, in := deploySourceFixture(t)
	if err := os.Symlink("generated/future.txt", filepath.Join(in.Source, "future")); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	captured := filepath.Join(deploySourceDir(d.StateDir, "site", in.Revision), "source", "future")
	if got, err := os.Readlink(captured); err != nil || got != "generated/future.txt" {
		t.Fatalf("safe dangling link lost: %q %v", got, err)
	}
}

func TestDeploySourceReadRefusesARegularFileReplacedByAFIFO(t *testing.T) {
	d, in := deploySourceFixture(t)
	_ = d
	path := filepath.Join(in.Source, "app.txt")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(in.Source)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openDeploySourceFile(root, "app.txt", info)
	if file != nil {
		file.Close()
	}
	if err == nil {
		t.Fatal("read accepted a swapped FIFO")
	}
}

func TestDeployRecordRefusesAnExistingLiveRevision(t *testing.T) {
	d, in := deploySourceFixture(t)
	m, err := manifest.Load(in.Source)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(m)
	live := state.Revision{App: "site", ID: in.Revision, Status: state.RevisionActive, Manifest: data, Images: map[string]string{"web": "sha256:live"}, SecretsVersion: 3, CreatedAt: time.Now()}
	if err := d.Store.SaveRevision(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[1].Apply(context.Background(), io.Discard); err == nil {
		t.Fatal("a new deploy replaced an existing revision record")
	}
	got, err := d.Store.GetRevision(context.Background(), "site", in.Revision)
	if err != nil || got.Status != live.Status || got.Images["web"] != live.Images["web"] || got.SecretsVersion != live.SecretsVersion {
		t.Fatalf("existing revision changed: %+v %v", got, err)
	}
}

type recordOnlyDeploy struct{ Deploy }

func (d recordOnlyDeploy) Kind() string { return "test.deploy.record" }
func (d recordOnlyDeploy) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in DeployInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	m, err := manifest.Load(in.Source)
	if err != nil {
		return nil, err
	}
	plan, err := d.rollout(ctx, m, in.Revision, &buildFrom{source: in.Source, commit: in.Commit})
	if err != nil {
		return nil, err
	}
	plan.Steps = plan.Steps[:1]
	return plan, nil
}

func TestDeployRecordReplayPreservesPinnedImagesAndSecrets(t *testing.T) {
	d, in := deploySourceFixture(t)
	in.Commit = "approved-commit"
	ctx := context.Background()
	registry := kernel.Registry{}
	definition := recordOnlyDeploy{d}
	registry.Add(definition)
	engine := kernel.New(d.Store, registry, "test")
	raw, _ := json.Marshal(in)
	view, err := engine.PlanOnly(ctx, definition.Kind(), raw)
	if err != nil {
		t.Fatal(err)
	}
	viewJSON, _ := json.Marshal(view)
	t0 := time.Now().Add(-time.Hour)
	if err := d.Store.CreateOperation(ctx, state.NewOperation{ID: "interrupted-record", Kind: definition.Kind(), Target: "site", Input: raw, Plan: viewJSON, PlanDigest: view.Digest, Recovery: string(kernel.Resume), StepNames: []string{"record"}, CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Claim(ctx, "interrupted-record", "old-daemon", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.StepStarted(ctx, "interrupted-record", 0, t0); err != nil {
		t.Fatal(err)
	}
	m, _ := manifest.Load(in.Source)
	data, _ := json.Marshal(m)
	live := state.Revision{App: "site", ID: in.Revision, Status: state.RevisionFailed, Manifest: data, Images: map[string]string{"web": "sha256:pinned"}, Containers: map[string]string{"web": "bedrock-site-web-" + in.Revision}, Source: in.Commit, SecretsVersion: 3, CreatedAt: t0}
	if err := d.Store.SaveRevision(ctx, live); err != nil {
		t.Fatal(err)
	}
	if n, err := engine.Recover(ctx, func(kernel.Event) {}); err != nil || n != 1 {
		t.Fatalf("record replay failed: %d %v", n, err)
	}
	got, err := d.Store.GetRevision(ctx, "site", in.Revision)
	if err != nil || got.Status != live.Status || got.Images["web"] != live.Images["web"] || got.SecretsVersion != live.SecretsVersion || !got.CreatedAt.Equal(live.CreatedAt.Truncate(time.Millisecond)) {
		t.Fatalf("record replay erased pinned state: %+v %v", got, err)
	}
}

func TestDeployCaptureBudgetPreservesWorkloadDiskSpace(t *testing.T) {
	if err := deployCaptureBudget(1024, deployCaptureFreeMin+1024); err != nil {
		t.Fatal(err)
	}
	for _, free := range []uint64{deployCaptureFreeMin - 1, deployCaptureFreeMin, deployCaptureFreeMin + 1023} {
		if err := deployCaptureBudget(1024, free); err == nil {
			t.Fatalf("capture could consume reserved disk space with %d bytes free", free)
		}
	}
}

func TestDeploySourceStorageIncludesSparseBytesAndPerEntrySpace(t *testing.T) {
	source := t.TempDir()
	file, err := os.Create(filepath.Join(source, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	bytes, err := deploySourceStorage(context.Background(), source, 4096)
	if err != nil || bytes < 1<<30+8192 {
		t.Fatalf("sparse logical copy or metadata omitted: %d %v", bytes, err)
	}
}

func TestDeploySourceCollectionOnlyDiscardsTerminalOwnedCaptures(t *testing.T) {
	d, in := deploySourceFixture(t)
	ctx := context.Background()
	raw, _ := json.Marshal(in)
	plan, err := d.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	reservation, err := readDeploySourceReservation(d.StateDir, in)
	if err != nil {
		t.Fatal(err)
	}
	reservation.Operation = "finished-deploy"
	if err := writeRehearsalJSON(deploySourceReservationPath(d.StateDir, in), reservation); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.CreateOperation(ctx, state.NewOperation{ID: reservation.Operation, Kind: DeployKind, Target: "site", Input: raw, Plan: json.RawMessage(`{}`), Recovery: string(kernel.Resume), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.Finish(ctx, reservation.Operation, state.Failed, "failed build", json.RawMessage(`{}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	// A second unfinished operation sharing the revision protects the common
	// tree even if the finished operation never managed to capture it.
	other := *reservation
	other.Input.Source = t.TempDir()
	other.Operation = "unfinished-deploy"
	otherRaw, _ := json.Marshal(other.Input)
	if err := writeRehearsalJSON(deploySourceReservationPath(d.StateDir, other.Input), &other); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.CreateOperation(ctx, state.NewOperation{ID: other.Operation, Kind: DeployKind, Target: "site", Input: otherRaw, Plan: json.RawMessage(`{}`), Recovery: string(kernel.Resume), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if removed, err := collectDeploySources(ctx, d.Store, d.StateDir); err != nil || removed != 1 {
		t.Fatalf("terminal marker not collected: %d %v", removed, err)
	}
	captured := deploySourceDir(d.StateDir, "site", in.Revision)
	if _, err := os.Stat(captured); err != nil {
		t.Fatalf("unfinished capture was removed: %v", err)
	}
	if _, err := os.Stat(deploySourceReservationPath(d.StateDir, other.Input)); err != nil {
		t.Fatalf("unfinished reservation was removed: %v", err)
	}
	if err := d.Store.Finish(ctx, other.Operation, state.Compensated, "failed deploy", json.RawMessage(`{}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	if removed, err := collectDeploySources(ctx, d.Store, d.StateDir); err != nil || removed != 1 {
		t.Fatalf("finished capture not collected: %d %v", removed, err)
	}
	if _, err := os.Stat(captured); !os.IsNotExist(err) {
		t.Fatalf("terminal capture remains: %v", err)
	}
}

func TestDeployBuildUsesCapturedSourceAfterOriginalChanges(t *testing.T) {
	d, in := deploySourceFixture(t)
	if err := os.WriteFile(filepath.Join(in.Source, manifest.FileName), []byte("app: site\nworkloads:\n  web: {kind: worker, build: {context: .}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.Source, "Dockerfile"), []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[1].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.Source, "app.txt"), []byte("post-approval edits"), 0644); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	output := filepath.Join(t.TempDir(), "built-source")
	t.Setenv("BEDROCK_TEST_CAPTURE_OUTPUT", output)
	if err := os.WriteFile(filepath.Join(bin, "nice"), []byte("#!/bin/sh\nfor arg do context=$arg; done\ncat \"$context/app.txt\" > \"$BEDROCK_TEST_CAPTURE_OUTPUT\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	fake := dockertest.New(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		if strings.HasPrefix(path, "/images/") {
			json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:" + strings.Repeat("a", 64), "RepoDigests": []string{"127.0.0.1:5000/site/web@sha256:" + strings.Repeat("a", 64)}})
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	built := false
	for _, step := range plan.Steps {
		if step.Name == "build-web" {
			if err := step.Apply(context.Background(), io.Discard); err != nil {
				t.Fatal(err)
			}
			built = true
		}
	}
	if got, err := os.ReadFile(output); !built || err != nil || string(got) != "approved source" {
		t.Fatalf("build read changing original source: %q %v built=%v", got, err, built)
	}
}

func TestDeploySourceCollectionProtectsUnknownOperations(t *testing.T) {
	d, in := deploySourceFixture(t)
	raw, _ := json.Marshal(in)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	stored, err := readDeploySourceReservation(d.StateDir, in)
	if err != nil {
		t.Fatal(err)
	}
	stored.Operation = "missing-operation"
	if err := writeRehearsalJSON(deploySourceReservationPath(d.StateDir, in), stored); err != nil {
		t.Fatal(err)
	}
	if removed, err := collectDeploySources(context.Background(), d.Store, d.StateDir); removed != 0 || err != nil {
		t.Fatalf("unknown owner prevented collection or was removed: %d %v", removed, err)
	}
	if _, err := os.Stat(deploySourceDir(d.StateDir, "site", in.Revision)); err != nil {
		t.Fatalf("unknown owner's capture removed: %v", err)
	}
}
