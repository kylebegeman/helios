package docker

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// imageServer stands in for a daemon speaking one API version, answering
// image inspects with the given answer. It reports whether any inspect
// asked for manifests.
func imageServer(t *testing.T, version string, answer func(id string, manifests bool) (int, any)) (*Engine, *bool) {
	t.Helper()
	asked := new(bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", version)
		if r.URL.Path == "/_ping" {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/v"+version+"/images/")
		id, isInspect := strings.CutSuffix(rest, "/json")
		if !ok || !isInspect {
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		manifests := r.URL.Query().Get("manifests") == "1"
		*asked = *asked || manifests
		status, body := answer(id, manifests)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(server.URL, "http"))
	t.Setenv("DOCKER_API_VERSION", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	e, err := Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, asked
}

func manifest(kind string, content int64, available bool) map[string]any {
	return map[string]any{"Kind": kind, "ID": "sha256:" + strings.Repeat("d", 64), "Available": available, "Size": map[string]any{"Content": content}}
}

// The containerd image store streams the compressed content its manifests
// count, far less than the size it can report with the unpacked snapshots;
// a graph driver store, or a daemon too old to list manifests, saves near
// the reported size after copying it all once into its own data root.
func TestAnImageArchiveIsSizedByWhatSaveCopies(t *testing.T) {
	ids := []string{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64)}
	for _, tc := range []struct {
		name, version string
		answer        map[string]any
		want          int64
		manifests     bool
		err           string
	}{
		{
			name: "containerd store", version: "1.48", manifests: true,
			// An image, its attestation and a platform only partly here.
			answer: map[string]any{"Size": 4000, "Manifests": []any{manifest("image", 900, true), manifest("attestation", 80, true), manifest("image", 20, false)}},
			want:   1000,
		},
		{
			name: "graph driver store", version: "1.56", manifests: true,
			answer: map[string]any{"Size": 4000},
			want:   8000,
		},
		{
			name: "a daemon before manifests", version: "1.47",
			answer: map[string]any{"Size": 4000, "Manifests": []any{manifest("image", 900, true)}},
			want:   8000,
		},
		{
			name: "content past the largest size", version: "1.48", manifests: true,
			answer: map[string]any{"Size": 4000, "Manifests": []any{manifest("image", math.MaxInt64, true), manifest("attestation", math.MaxInt64, true)}},
			want:   math.MaxInt64,
		},
		{
			name: "negative content", version: "1.48", manifests: true,
			answer: map[string]any{"Size": 4000, "Manifests": []any{manifest("image", -1, true)}},
			err:    "docker reported -1 bytes of content for " + ids[0],
		},
		{
			name: "a reported size past the largest", version: "1.56", manifests: true,
			answer: map[string]any{"Size": math.MaxInt64},
			want:   math.MaxInt64,
		},
		{
			name: "negative size", version: "1.47",
			answer: map[string]any{"Size": -1},
			err:    "docker reported -1 bytes for " + ids[0],
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, asked := imageServer(t, tc.version, func(id string, manifests bool) (int, any) {
				answer := map[string]any{"Id": id}
				for k, v := range tc.answer {
					if k != "Manifests" || manifests {
						answer[k] = v
					}
				}
				return http.StatusOK, answer
			})
			sizes, err := e.ArchiveSizes(context.Background(), ids)
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("got %v, %v, want %q", sizes, err, tc.err)
				}
				return
			}
			if err != nil || len(sizes) != 2 || sizes[0] != tc.want || sizes[1] != tc.want {
				t.Fatalf("got %v, %v, want %d for each", sizes, err, tc.want)
			}
			if *asked != tc.manifests {
				t.Fatalf("asked for manifests %v, want %v", *asked, tc.manifests)
			}
		})
	}
	t.Run("a missing image", func(t *testing.T) {
		e, _ := imageServer(t, "1.48", func(string, bool) (int, any) {
			return http.StatusNotFound, map[string]any{"message": "No such image"}
		})
		if sizes, err := e.ArchiveSizes(context.Background(), ids); err == nil || !strings.Contains(err.Error(), "No such image") {
			t.Fatalf("got %v, %v, want the daemon's refusal", sizes, err)
		}
	})
}
