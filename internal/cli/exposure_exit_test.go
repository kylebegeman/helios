package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
)

func TestExposureJSONPreservesIsolationFailureStatus(t *testing.T) {
	fake := dockertest.New(t)
	for _, app := range []string{"one", "two"} {
		fake.Add(dockertest.Container{Name: app, Running: true, Labels: map[string]string{
			docker.LabelOwner: docker.OwnerValue, docker.LabelApp: app, docker.LabelWorkload: "web",
		}})
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		if strings.HasPrefix(path, "/containers/") && path != "/containers/json" && strings.HasSuffix(path, "/json") {
			recorded := httptest.NewRecorder()
			fake.ServeHTTP(recorded, r)
			var body map[string]any
			if err := json.Unmarshal(recorded.Body.Bytes(), &body); err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			body["NetworkSettings"] = map[string]any{"Networks": map[string]any{"shared-fixture": map[string]any{}}}
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	out, stderr, code := run(t, t.TempDir(), "exposure", "--json")
	var report exposureReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.Shared) != 1 {
		t.Fatalf("isolation fixture: %q, %v", out, err)
	}
	if code != 1 {
		t.Fatalf("JSON isolation failure exited %d: %s", code, stderr)
	}
}
