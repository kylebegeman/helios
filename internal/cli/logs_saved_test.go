package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/state"
)

func TestSavedJobOutputWithoutAContainerDoesNotNeedDocker(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	id, err := store.StartJobRun(context.Background(), state.JobRun{App: "site", Workload: "worker", Kind: "run", Revision: "r1", StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	const saved = "saved fixture output\n"
	if err := store.FinishJobRun(context.Background(), id, 0, "", saved, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	unavailableDocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fixture engine unavailable", http.StatusServiceUnavailable)
	}))
	defer unavailableDocker.Close()
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(unavailableDocker.URL, "http://"))
	t.Setenv("DOCKER_API_VERSION", dockertest.APIVersion)
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	out, stderr, code := run(t, dir, "logs", "site", "--job", strconv.FormatInt(id, 10))
	if code != 0 || out != saved || !strings.Contains(stderr, "kept with the run") {
		t.Fatalf("saved output unavailable: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}
