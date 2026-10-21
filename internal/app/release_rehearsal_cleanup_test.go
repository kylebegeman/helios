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

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
)

func TestRehearsalCleanupRetainsForeignScratchResources(t *testing.T) {
	for _, resource := range []string{"container", "volume", "network"} {
		t.Run(resource, func(t *testing.T) {
			def, in, m := rehearsalFixture(t)
			fake := dockertest.New(t)
			raw, _ := json.Marshal(in)
			plan, err := def.Plan(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
				t.Fatal(err)
			}
			names := rehearsalNames(filepath.Join(def.StateDir, "rehearsals", m.App, "scratch-"+in.Revision), m, in.Revision)
			switch resource {
			case "container":
				fake.Add(dockertest.Container{Name: names.containers["first"], Running: true, Labels: map[string]string{docker.LabelOwner: "someone-else"}})
			case "volume":
				fake.AddVolume(names.volumes["files"], map[string]string{docker.LabelOwner: "someone-else"})
			case "network":
				fake.AddNetwork(names.network, map[string]string{docker.LabelOwner: "someone-else"})
			}
			if err := plan.Steps[0].Undo(context.Background(), io.Discard); err == nil {
				t.Fatal("cleanup accepted a foreign scratch resource")
			}
			for _, call := range fake.Calls() {
				if strings.HasPrefix(call, "DELETE ") || strings.HasSuffix(call, "/stop") {
					t.Fatalf("cleanup mutated scratch resources before establishing ownership: %s", call)
				}
			}
			if _, err := os.Stat(rehearsalReservationPath(def.StateDir, in)); err != nil {
				t.Fatalf("failed cleanup lost its reservation: %v", err)
			}
		})
	}
}

func TestRehearsalCleanupKeepsDataUntilEveryWriterIsRemoved(t *testing.T) {
	def, in, m := rehearsalFixture(t)
	fake := dockertest.New(t)
	raw, _ := json.Marshal(in)
	plan, err := def.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(def.StateDir, "rehearsals", m.App, "scratch-"+in.Revision)
	names := rehearsalNames(workspace, m, in.Revision)
	spec, err := rehearsalReleaseSpec(m, in.Revision, "first", "alpine:3.21", nil, names)
	if err != nil {
		t.Fatal(err)
	}
	spec.Labels[docker.LabelOwner] = docker.OwnerValue
	fake.Add(dockertest.Container{Name: spec.Name, Running: true, Labels: spec.Labels})
	fake.AddVolume(names.volumes["files"], map[string]string{docker.LabelOwner: docker.OwnerValue})
	artifact := filepath.Join(workspace, "staged-data")
	if err := os.WriteFile(artifact, []byte("restored"), 0o600); err != nil {
		t.Fatal(err)
	}
	drillCleanupFailure(t, fake, func(r *http.Request) bool {
		return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/stop")
	})
	if err := plan.Steps[0].Undo(context.Background(), io.Discard); err == nil || !strings.Contains(err.Error(), "scratch cleanup unavailable") {
		t.Fatalf("writer cleanup failure was not returned: %v", err)
	}
	if !slices.Contains(fake.VolumeNames(), names.volumes["files"]) {
		t.Fatal("cleanup deleted data while its writer could still run")
	}
	if _, err := os.Stat(artifact); err != nil {
		t.Fatalf("cleanup deleted staging while its writer could still run: %v", err)
	}
	if _, err := os.Stat(rehearsalReservationPath(def.StateDir, in)); err != nil {
		t.Fatalf("failed cleanup lost its reservation: %v", err)
	}
}

func TestRehearsalCleanupRemovesOnlyItsOwnBuildTags(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign", true: "owned"}[owned], func(t *testing.T) {
			def, in, m := rehearsalFixture(t)
			first := m.Workloads["first"]
			first.Build, first.Image = &manifest.Build{}, ""
			m.Workloads["first"] = first
			fake := dockertest.New(t)
			ref := docker.ImageRef(m.App, "first", "rehearse-"+in.Revision)
			labels := imageLabels(m.App, "first", in.Revision)
			if !owned {
				labels[docker.LabelOwner] = "another-system"
			}
			deleted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
				if path == "/images/json" {
					json.NewEncoder(w).Encode([]any{map[string]any{"Id": "sha256:fixture", "RepoTags": []string{ref}, "Labels": labels}})
					return
				}
				if r.Method == http.MethodDelete && strings.HasPrefix(path, "/images/") {
					deleted = true
					json.NewEncoder(w).Encode([]any{})
					return
				}
				fake.ServeHTTP(w, r)
			}))
			defer server.Close()
			t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(server.URL, "http"))
			workspace := t.TempDir()
			x := &releaseRehearsal{def: def, input: in, candidate: m, workspace: workspace, reservation: filepath.Join(t.TempDir(), "reservation"), names: rehearsalNames(workspace, m, in.Revision)}
			if err := x.cleanup(context.Background(), io.Discard); err != nil {
				t.Fatal(err)
			}
			if deleted != owned {
				t.Fatalf("build tag removal=%v, ownership=%v", deleted, owned)
			}
		})
	}
}
