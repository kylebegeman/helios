package watch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func TestHealthProbeCannotSucceedByRedirectingOutsideItsContainer(t *testing.T) {
	var outsideRequests atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideRequests.Add(1)
	}))
	defer outside.Close()
	container := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outside.URL, http.StatusFound)
	}))
	defer container.Close()
	u, err := url.Parse(container.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	info := &docker.Info{IPs: map[string]string{docker.EdgeNetwork: u.Hostname()}}
	workload := manifest.Workload{Kind: manifest.Web, Port: port, Health: &manifest.Health{Path: "/health"}}
	problem := healthProblem(context.Background(), info, workload)
	if problem == "" {
		t.Error("a response from outside the container certified its health")
	}
	if got := outsideRequests.Load(); got != 0 {
		t.Errorf("the direct health probe made %d requests outside the container", got)
	}
}

func TestHealthProbeFollowsRedirectsWithinItsContainer(t *testing.T) {
	container := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			http.Redirect(w, r, "/ready", http.StatusFound)
		case "/ready":
			w.WriteHeader(http.StatusNoContent)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer container.Close()
	u, err := url.Parse(container.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	info := &docker.Info{IPs: map[string]string{docker.EdgeNetwork: u.Hostname()}}
	workload := manifest.Workload{Kind: manifest.Web, Port: port, Health: &manifest.Health{Path: "/health"}}
	if problem := healthProblem(context.Background(), info, workload); problem != "" {
		t.Fatalf("a healthy redirect within the container failed: %s", problem)
	}
	workload.Health.Path = "/loop"
	if problem := healthProblem(context.Background(), info, workload); !strings.Contains(problem, "10 redirects") {
		t.Fatalf("a redirect loop did not report its bound: %s", problem)
	}
	workload.Health.Path = "/missing"
	if problem := healthProblem(context.Background(), info, workload); problem != "answers 404 Not Found" {
		t.Fatalf("an unsuccessful health response was accepted: %s", problem)
	}
}

func TestPublicWatchesRequire200AndMayFollowPublicRedirects(t *testing.T) {
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer outside.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
		case "/down":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/redirect":
			http.Redirect(w, r, outside.URL, http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	w, now := newWatcher(t, nil)
	for _, path := range []string{"/ok", "/empty", "/down", "/redirect"} {
		if err := w.Store.AddWatch(ctx, server.URL+path, *now); err != nil {
			t.Fatal(err)
		}
	}
	p := NewProber(w.Store)
	conditions := p.watches(ctx)
	if len(conditions) != 2 {
		t.Fatalf("want only the 204 and 503 watches to fail, got %+v", conditions)
	}
	byKey := map[string]Condition{}
	for _, c := range conditions {
		byKey[c.Key] = c
	}
	for _, path := range []string{"/empty", "/down"} {
		c := byKey["watch:"+server.URL+path]
		if c.Key == "" || c.Unknown || c.Severity != state.SeverityCritical || !strings.Contains(c.Message, "want 200") {
			t.Errorf("watch %s did not report its failed status assertion: %+v", path, c)
		}
	}
}
