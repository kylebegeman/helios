package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func routeFixture(t *testing.T, app, path string, mode manifest.DNSMode) *manifest.Manifest {
	t.Helper()
	m := &manifest.Manifest{App: app, Workloads: map[string]manifest.Workload{"web": {
		Kind: manifest.Web, Image: "example/app:1", Port: 8080,
		Routes: []manifest.Route{{Host: "shared.example.com", Path: path, DNS: mode}},
	}}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDeployPlanRefusesAnotherAppsExactRouteBeforeApplyingAnything(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	existing := routeFixture(t, "site", "/api", "")
	saveActive(t, store, existing)
	candidate := routeFixture(t, "other", "/api/", "")
	d := Deploy{Store: store, StateDir: t.TempDir()}
	_, err = d.rollout(ctx, candidate, "check", &buildFrom{source: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "shared.example.com/api/ for web is already routed to site's web") {
		t.Fatalf("a colliding route reached a deploy plan: %v", err)
	}
	ops, err := store.List(ctx, 20)
	if err != nil || len(ops) != 0 {
		t.Fatalf("planning changed the operation journal: %v %v", ops, err)
	}
}

func TestRoutePreflightAllowsOwnRoutesAndDistinctPrefixes(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	saveActive(t, store, routeFixture(t, "site", "", ""))
	if err := CheckRouteConflicts(ctx, store, routeFixture(t, "site", "/", "")); err != nil {
		t.Fatalf("the app cannot redeploy its own route: %v", err)
	}
	if err := CheckRouteConflicts(ctx, store, routeFixture(t, "api", "/api", "")); err != nil {
		t.Fatalf("distinct prefixes cannot share a host: %v", err)
	}
	if err := CheckRouteConflicts(ctx, store, routeFixture(t, "api", "/api", manifest.DNSProxied)); err == nil || !strings.Contains(err.Error(), "routes sharing a host must use one DNS mode") {
		t.Fatalf("conflicting DNS ownership wasn't refused: %v", err)
	}
}

func TestRoutePlanFixtureWithoutAStoreHasNoExistingRoutes(t *testing.T) {
	if err := CheckRouteConflicts(context.Background(), nil, routeFixture(t, "site", "/", "")); err != nil {
		t.Fatal(err)
	}
}

func TestRoutePreflightKeepsEveryConflictInStableOrder(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	existing := &manifest.Manifest{App: "existing", Workloads: map[string]manifest.Workload{
		"zeta": {Routes: []manifest.Route{{Host: "shared.example.com", Path: "/a/", DNS: manifest.DNSDirect}}},
		"alpha": {Routes: []manifest.Route{
			{Host: "unrelated.example.com", Path: "/", DNS: manifest.DNSProxied},
			{Host: "shared.example.com", Path: "/a", DNS: manifest.DNSDirect},
			{Host: "shared.example.com", Path: "/z", DNS: manifest.DNSProxied},
		}},
	}}
	saveActive(t, store, existing)
	candidate := &manifest.Manifest{App: "candidate", Workloads: map[string]manifest.Workload{
		"zeta":  {Routes: []manifest.Route{{Host: "shared.example.com", Path: "/b", DNS: manifest.DNSDirect}}},
		"alpha": {Routes: []manifest.Route{{Host: "shared.example.com", Path: "/a/", DNS: manifest.DNSDirect}}},
	}}
	want := "candidate can't route what conflicts with another app on this machine: " +
		"shared.example.com/a/ for alpha is already routed to existing's alpha; " +
		"shared.example.com uses dns \"direct\" here and \"proxied\" in existing; routes sharing a host must use one DNS mode; " +
		"shared.example.com/a/ for alpha is already routed to existing's zeta; " +
		"shared.example.com uses dns \"direct\" here and \"proxied\" in existing; routes sharing a host must use one DNS mode"
	for range 10 {
		if err := CheckRouteConflicts(context.Background(), store, candidate); err == nil || err.Error() != want {
			t.Fatalf("conflict diagnostics changed: %v", err)
		}
	}
}

func TestRoutePreflightStillRejectsUnreadableUnrelatedManifests(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SaveRevision(context.Background(), state.Revision{App: "broken", ID: "r1", Status: state.RevisionActive, Manifest: []byte("{")}); err != nil {
		t.Fatal(err)
	}
	if err := CheckRouteConflicts(context.Background(), store, routeFixture(t, "candidate", "/", "")); err == nil || !strings.Contains(err.Error(), "revision broken/r1 manifest:") {
		t.Fatalf("unreadable active manifest was ignored: %v", err)
	}
}
