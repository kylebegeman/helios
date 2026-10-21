package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

func drillCleanupFailure(t *testing.T, fake *dockertest.Server, fails func(*http.Request) bool) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fails(r) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"message":"scratch cleanup unavailable"}`)
			return
		}
		fake.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(server.URL, "http"))
}

func TestDrillRefusesToRestoreWhenPreviousScratchDataCannotBeRemoved(t *testing.T) {
	d, fake := drillFixture(t, "uploads")
	fake.AddVolume(d.names.volumes["uploads"], nil)
	drillCleanupFailure(t, fake, func(r *http.Request) bool {
		return r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/volumes/")
	})
	restored := false
	fake.OnCreate = func(c dockertest.Container) {
		if len(c.Cmd) > 0 && c.Cmd[0] == "restore" {
			restored = true
		}
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			if len(c.Cmd) > 0 && c.Cmd[0] == "snapshots" {
				c.Logs = snapshotList(d.snapshot, `{"total_bytes_processed":12}`)
			} else if len(c.Cmd) > 0 && c.Cmd[0] == "restore" {
				c.Logs = `{"message_type":"summary","files_restored":1,"total_files":1,"bytes_restored":12,"total_bytes":12}`
			}
		})
	}
	roomToRestore(t)
	err := d.restoreStep().Apply(context.Background(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "scratch cleanup unavailable") || restored {
		t.Fatalf("restored over stale scratch data: restored=%v, error=%v", restored, err)
	}
}

func TestDrillCleanupFailureCannotProduceASuccessfulProof(t *testing.T) {
	for _, failure := range []string{"writer", "volume", "network"} {
		t.Run(failure, func(t *testing.T) {
			d, fake := drillFixture(t, "uploads")
			if err := d.run.begin(context.Background()); err != nil {
				t.Fatal(err)
			}
			d.found = &restic.Snapshot{ID: d.snapshot, ShortID: d.snapshot[:8], Time: time.Now().UTC()}
			d.started = time.Now().UTC()
			fake.Add(dockertest.Container{Name: d.names.containers["web"], Running: true, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: d.app, docker.LabelWorkload: "web"}})
			fake.AddVolume(d.names.volumes["uploads"], nil)
			fake.AddNetwork(d.names.network, map[string]string{docker.LabelOwner: docker.OwnerValue})
			if err := os.MkdirAll(d.names.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			artifact := filepath.Join(d.names.dir, "postgres.dump")
			if err := os.WriteFile(artifact, []byte("dump"), 0o600); err != nil {
				t.Fatal(err)
			}
			drillCleanupFailure(t, fake, func(r *http.Request) bool {
				switch failure {
				case "writer":
					return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/stop")
				case "volume":
					return r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/volumes/")
				default:
					return r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/networks/")
				}
			})
			err := d.cleanupStep().Apply(context.Background(), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "scratch cleanup unavailable") {
				t.Fatalf("cleanup failure was accepted: %v", err)
			}
			run, err := d.dr.Store.LastBackupRun(context.Background(), d.app, state.BackupRunDrill)
			if err != nil || run == nil || run.OK || !run.Finished() {
				t.Fatalf("cleanup failure produced a successful or unfinished proof: %+v, %v", run, err)
			}
			if failure == "writer" {
				if _, err := os.Stat(artifact); errors.Is(err, os.ErrNotExist) {
					t.Fatal("cleanup discarded staged data while a writer could still run")
				}
				for _, call := range fake.Calls() {
					if strings.HasPrefix(call, "DELETE /volumes/") || strings.HasPrefix(call, "DELETE /networks/") {
						t.Fatalf("cleanup removed data or networks before its writers: %s", call)
					}
				}
			}
		})
	}
}

func TestDrillCleanupRefusesForeignScratchResourcesBeforeRemovingAnything(t *testing.T) {
	for _, foreign := range []string{"container owner", "container app", "container workload", "network", "volume", "database volume"} {
		t.Run(foreign, func(t *testing.T) {
			d, fake := drillFixture(t, "uploads")
			n := d.names
			labels := map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: d.app, docker.LabelWorkload: "web"}
			switch foreign {
			case "container owner":
				labels[docker.LabelOwner] = "another-system"
			case "container app":
				labels[docker.LabelApp] = "another-app"
			case "container workload":
				labels[docker.LabelWorkload] = "another-workload"
			}
			fake.Add(dockertest.Container{Name: n.containers["web"], Running: true, Labels: labels})
			owner := map[string]string{docker.LabelOwner: docker.OwnerValue}
			fake.AddNetwork(n.network, owner)
			fake.AddVolume(n.volumes["uploads"], owner)
			fake.AddVolume(n.postgresVolume, owner)
			switch foreign {
			case "network":
				fake.AddNetwork(n.network, map[string]string{docker.LabelOwner: "another-system"})
			case "volume":
				fake.AddVolume(n.volumes["uploads"], map[string]string{docker.LabelOwner: "another-system"})
			case "database volume":
				fake.AddVolume(n.postgresVolume, map[string]string{docker.LabelOwner: "another-system"})
			}
			if err := os.MkdirAll(n.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			artifact := filepath.Join(n.dir, "postgres.dump")
			if err := os.WriteFile(artifact, []byte("retained"), 0o600); err != nil {
				t.Fatal(err)
			}
			e, err := docker.Connect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if err := n.cleanup(e); err == nil || !strings.Contains(err.Error(), "owner") {
				t.Errorf("cleanup accepted foreign scratch %s: %v", foreign, err)
			}
			if c, ok := fake.Container(n.containers["web"]); !ok || !c.Running {
				t.Fatal("ownership rejection stopped or removed a scratch container")
			}
			if len(fake.VolumeNames()) != 3 || len(fake.NetworkNames()) != 1 {
				t.Fatal("ownership rejection deleted scratch or live data")
			}
			if data, err := os.ReadFile(artifact); err != nil || string(data) != "retained" {
				t.Fatalf("ownership rejection removed staged data: %q, %v", data, err)
			}
			for _, call := range fake.Calls() {
				if strings.HasPrefix(call, "DELETE ") || strings.HasSuffix(call, "/stop") {
					t.Fatalf("cleanup mutated resources before checking every owner: %s", call)
				}
			}
		})
	}
}
