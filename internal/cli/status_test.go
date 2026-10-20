package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

type lsInventoryJSON struct {
	Apps           []appRow `json:"apps"`
	Unmanaged      []string `json:"unmanaged"`
	UnmanagedKnown *bool    `json:"unmanaged_known"`
}

func lsInventoryApp(t *testing.T) (string, appRow) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	deployed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	m := manifest.Manifest{
		App: "site", Owner: "personal", Description: "Fixture website", Repo: "https://example.invalid/site.git",
		Workloads: map[string]manifest.Workload{"web": {
			Kind: manifest.Web, Image: "site:r1", Port: 80, Routes: []manifest.Route{{Host: "site.example.invalid"}},
		}},
		Data: &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRevision(ctx, state.Revision{
		App: "site", ID: "r1", Status: state.RevisionActive, Manifest: raw,
		Containers: map[string]string{"web": "bedrock-site-web-r1"}, Source: "abc1234567", CreatedAt: deployed,
	}); err != nil {
		t.Fatal(err)
	}
	good := state.BackupRun{
		App: "site", Kind: state.BackupRunBackup, StartedAt: deployed.Add(time.Minute),
		FinishedAt: deployed.Add(2 * time.Minute), OK: true, Snapshot: "good-snapshot",
		SnapshotAt: deployed.Add(time.Minute), Files: 3, Bytes: 1024, Detail: "saved fixture files",
	}
	last := state.BackupRun{
		App: "site", Kind: state.BackupRunBackup, StartedAt: deployed.Add(3 * time.Minute),
		FinishedAt: deployed.Add(4 * time.Minute), Error: "fixture storage unavailable",
	}
	drill := state.BackupRun{
		App: "site", Kind: state.BackupRunDrill, StartedAt: deployed.Add(5 * time.Minute),
		FinishedAt: deployed.Add(6 * time.Minute), OK: true, Snapshot: "good-snapshot",
		SnapshotAt: deployed.Add(time.Minute), Files: 3, Bytes: 1024, Detail: "verified fixture files",
	}
	for _, backup := range []*state.BackupRun{&good, &last, &drill} {
		backup.ID, err = store.StartBackupRun(ctx, backup.App, backup.Kind, backup.StartedAt)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.FinishBackupRun(ctx, backup.ID, *backup); err != nil {
			t.Fatal(err)
		}
	}
	return dir, appRow{
		Name: "site", Owner: "personal", Description: "Fixture website", Repo: "https://example.invalid/site.git",
		Hosts: []string{"site.example.invalid"}, Revision: "r1", Commit: "abc1234567", DeployedAt: deployed,
		BackedUp: true, LastBackup: &last, GoodBackup: &good, LastDrill: &drill,
	}
}

func lsJSONInventory(t *testing.T, dir string) lsInventoryJSON {
	t.Helper()
	out, errOut, code := run(t, dir, "ls", "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("ls must keep its app listing available: exit %d, stderr %q", code, errOut)
	}
	var result lsInventoryJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("ls returned invalid JSON: %v", err)
	}
	return result
}

func assertLsInventoryKnown(t *testing.T, result lsInventoryJSON, want bool) {
	t.Helper()
	if result.UnmanagedKnown == nil {
		t.Fatal("ls JSON omitted unmanaged_known; unknown inventory cannot be distinguished from an empty completed inventory")
	}
	if *result.UnmanagedKnown != want {
		t.Fatalf("unmanaged_known = %t, want %t", *result.UnmanagedKnown, want)
	}
}

func TestLsJSONReportsCompletedUnmanagedInventoryAndPreservesApps(t *testing.T) {
	dir, app := lsInventoryApp(t)
	fake := dockertest.New(t)
	fake.Add(dockertest.Container{Name: "bedrock-site-web-r1", Running: true, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue}})
	fake.Add(dockertest.Container{Name: "bedrock-site-web-old", Running: false, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue}})
	fake.Add(dockertest.Container{Name: "foreign-running", Running: true, Labels: map[string]string{docker.LabelOwner: "another-tool"}})
	fake.Add(dockertest.Container{Name: "bedrock-foreign-stopped", Running: false})
	var listed atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion) == "/containers/json" {
			listed.Store(true)
			if r.URL.Query().Get("all") != "1" {
				t.Error("Docker inventory must include stopped containers")
			}
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))

	result := lsJSONInventory(t, dir)
	if !listed.Load() {
		t.Fatal("ls never read the Docker container inventory")
	}
	if !reflect.DeepEqual(result.Apps, []appRow{app}) {
		t.Errorf("app metadata or backup history changed: got %+v, want %+v", result.Apps, app)
	}
	slices.Sort(result.Unmanaged)
	if want := []string{"bedrock-foreign-stopped", "foreign-running"}; !slices.Equal(result.Unmanaged, want) {
		t.Errorf("unmanaged = %v, want %v", result.Unmanaged, want)
	}
	assertLsInventoryKnown(t, result, true)
}

func TestLsJSONMarksCompletedEmptyInventoryKnown(t *testing.T) {
	dockertest.New(t)
	result := lsJSONInventory(t, t.TempDir())
	if len(result.Apps) != 0 || len(result.Unmanaged) != 0 {
		t.Fatalf("fresh fixture unexpectedly has apps or unmanaged containers: %+v", result)
	}
	assertLsInventoryKnown(t, result, true)
}

func TestLsJSONKeepsAppsWhenDockerInventoryFailsWithoutDisclosingDetails(t *testing.T) {
	for _, failingPath := range []string{"ping", "list"} {
		t.Run(failingPath, func(t *testing.T) {
			dir, app := lsInventoryApp(t)
			fake := dockertest.New(t)
			const privateEndpoint = "http://fixture-user:fixture-password@private.example.invalid:2375"
			const endpointPath = "/fixture-endpoint-password"
			var refused atomic.Bool
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, endpointPath)
				path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
				if failingPath == "ping" && path == "/_ping" || failingPath == "list" && path == "/containers/json" {
					refused.Store(true)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{"message": "private engine detail: " + privateEndpoint})
					return
				}
				fake.ServeHTTP(w, r)
			}))
			defer proxy.Close()
			t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http")+endpointPath)

			out, errOut, code := run(t, dir, "ls", "--json")
			if code != 0 || errOut != "" {
				t.Errorf("Docker inventory failure must preserve app listing: exit %d, stderr %q", code, errOut)
			}
			for _, private := range []string{"fixture-user", "fixture-password", "fixture-endpoint-password", "private.example.invalid", "private engine detail"} {
				if strings.Contains(out+errOut, private) {
					t.Errorf("ls disclosed private Docker failure detail %q", private)
				}
			}
			if !refused.Load() {
				t.Fatal("fixture did not exercise the intended Docker failure")
			}
			var result lsInventoryJSON
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatalf("ls returned invalid JSON: %v", err)
			}
			if !reflect.DeepEqual(result.Apps, []appRow{app}) {
				t.Errorf("Docker failure lost app metadata or backup history: got %+v, want %+v", result.Apps, app)
			}
			if len(result.Unmanaged) != 0 {
				t.Errorf("failed inventory unexpectedly reports unmanaged containers: %v", result.Unmanaged)
			}
			assertLsInventoryKnown(t, result, false)
		})
	}
}

func TestLsJSONFreshStateWithoutDockerReportsUnknownInventory(t *testing.T) {
	dir := t.TempDir()
	// An owned, nonexistent socket ensures this cannot query real Docker.
	t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(dir, "missing-docker.sock"))
	t.Setenv("DOCKER_API_VERSION", dockertest.APIVersion)
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	result := lsJSONInventory(t, dir)
	if len(result.Apps) != 0 || len(result.Unmanaged) != 0 {
		t.Fatalf("fresh state unexpectedly has apps or unmanaged containers: %+v", result)
	}
	assertLsInventoryKnown(t, result, false)
	// A script reads apps as a list; a machine with none is an empty one.
	out, _, _ := run(t, dir, "ls", "--json")
	if !strings.Contains(out, `"apps":[]`) {
		t.Fatalf("ls JSON must give a machine with no apps an empty list, not null: %s", out)
	}
}

func TestLsPlainReportsUnknownUnmanagedInventoryWithoutDisclosingDetails(t *testing.T) {
	dir, _ := lsInventoryApp(t)
	fake := dockertest.New(t)
	const privateDetail = "private engine detail: fixture-user:fixture-password@private.example.invalid"
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion) == "/containers/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": privateDetail})
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))

	out, errOut, code := run(t, dir, "ls")
	if code != 0 || errOut != "" {
		t.Errorf("plain ls must preserve app listing: exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "site") || !strings.Contains(out, "Fixture website") {
		t.Error("plain ls lost the registered app or its description")
	}
	if human := strings.ToLower(out); !strings.Contains(human, "unknown") || !strings.Contains(human, "container") {
		t.Error("plain ls must explain that the container inventory is unknown")
	}
	for _, private := range []string{"private engine detail", "fixture-user", "fixture-password", "private.example.invalid"} {
		if strings.Contains(out+errOut, private) {
			t.Errorf("plain ls disclosed private Docker failure detail %q", private)
		}
	}
}
