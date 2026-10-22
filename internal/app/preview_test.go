package app

import (
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/manifest"

	"gopkg.in/yaml.v3"
)

const parentYAML = `
app: kylebegeman
description: kylebegeman.com, the front door
repo: github.com/kylebegeman/kylebegeman.com
workloads:
  web:
    kind: web
    image: local/site:1
    port: 8000
    routes:
      - host: kylebegeman.com
        dns: proxied
      - host: www.kylebegeman.com
        dns: proxied
  bakery:
    kind: web
    image: local/bakery:1
    port: 8001
    routes:
      - host: bakery.kylebegeman.com
data:
  postgres:
    version: "17"
backup:
  schedule: "0 3 * * *"
  verify: {sql: "select count(*) from pages", at_least: 1}
checks:
  - url: https://kylebegeman.com/
    contains: Kyle
`

func parent(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(parentYAML))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The guard is the only thing that makes seeding a preview from production
// data defensible, so it is not optional and cannot be absent.
func TestEveryPreviewRouteIsBehindASignIn(t *testing.T) {
	p, err := PreviewOf(parent(t), "feature/new-nav", "preview.begam.in")
	if err != nil {
		t.Fatal(err)
	}
	routes := 0
	for name, w := range p.Workloads {
		for _, r := range w.Routes {
			routes++
			if r.Auth != manifest.AuthLoom {
				t.Fatalf("%s routes %s without a sign-in", name, r.Host)
			}
		}
	}
	if routes == 0 {
		t.Fatal("the preview has no routes at all")
	}
	if len(p.GuardedRoutes()) != routes {
		t.Fatalf("%d routes but %d guarded", routes, len(p.GuardedRoutes()))
	}
}

// A content assertion must survive the route's new sign-in requirement.
func TestAPreviewRewritesCompatibleChecksAndReportsUnsupportedOnes(t *testing.T) {
	m := parent(t)
	m.Checks = append(m.Checks,
		manifest.Check{URL: "https://external.example.com/", Context: manifest.CheckEdge},
		manifest.Check{URL: "https://kylebegeman.com:8443/"},
		manifest.Check{URL: "https://bakery.kylebegeman.com/orders?q=new", Context: manifest.CheckEdge, HeadersFromSecrets: map[string]string{"Cookie": "CHECK_COOKIE"}},
	)
	p, skipped, err := PreviewOfWithReport(m, "feature/new-nav", "preview.begam.in")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Checks) != 2 || len(skipped) != 2 {
		t.Fatalf("checks %+v, skipped %+v", p.Checks, skipped)
	}
	if p.Checks[0].URL != "https://feature-new-nav.kylebegeman.preview.begam.in/" || p.Checks[0].Contains != "Kyle" {
		t.Fatal(p.Checks[0])
	}
	if p.Checks[1].URL != "https://feature-new-nav.bakery.preview.begam.in/orders?q=new" || p.Checks[1].HeadersFromSecrets["Cookie"] != "CHECK_COOKIE" {
		t.Fatal(p.Checks[1])
	}
	p.Checks[1].HeadersFromSecrets["Cookie"] = "OTHER"
	if m.Checks[3].HeadersFromSecrets["Cookie"] != "CHECK_COOKIE" || len(m.Checks) != 4 {
		t.Fatal("preview mutated the parent")
	}
	if skipped[0].URL != "https://external.example.com/" || !strings.Contains(skipped[1].Reason, "port") {
		t.Fatal(skipped)
	}
}

func TestAPreviewIsNotBackedUp(t *testing.T) {
	p, err := PreviewOf(parent(t), "main", "preview.begam.in")
	if err != nil {
		t.Fatal(err)
	}
	if p.BackedUp() {
		t.Fatal("a preview's data is a copy; backing it up doubles the storage for nothing")
	}
	if p.Backup.Schedule != "" || p.Backup.Verify != nil {
		t.Fatalf("a preview kept the parent's backup settings: %+v", p.Backup)
	}
}

// An app and its www alias collapse onto one preview hostname, and two
// genuinely different hostnames must not.
func TestHostnamesCollapseOnlyWhenTheyAreTheSameThing(t *testing.T) {
	p, err := PreviewOf(parent(t), "nav", "preview.begam.in")
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, name := range p.WorkloadNames() {
		for _, r := range p.Workloads[name].Routes {
			hosts = append(hosts, r.Host)
		}
	}
	// kylebegeman.com and www.kylebegeman.com are one site; bakery is not.
	want := map[string]bool{
		"nav.kylebegeman.preview.begam.in": true,
		"nav.www.preview.begam.in":         true,
		"nav.bakery.preview.begam.in":      true,
	}
	if len(hosts) != 3 {
		t.Fatalf("got %v", hosts)
	}
	for _, h := range hosts {
		if !want[h] {
			t.Fatalf("unexpected host %q in %v", h, hosts)
		}
	}
}

// The same branch must always give the same app, or pushing twice makes a
// second preview instead of updating the first.
func TestAPreviewsNameIsStableAndFitsAManifest(t *testing.T) {
	for _, branch := range []string{
		"main", "feature/new-nav", "Feature/New_Nav", "renovate/some-extremely-long-dependency-bump-branch-name-that-goes-on",
	} {
		first := previewName("kylebegeman", branch)
		if first != previewName("kylebegeman", branch) {
			t.Fatalf("%s: the name is not stable", branch)
		}
		if len(first) > maxAppName {
			t.Fatalf("%s: %q is %d characters", branch, first, len(first))
		}
		if err := (manifest.Scaffold{App: first, Kind: manifest.Worker}).Check(); err != nil {
			t.Fatalf("%s: %q is not a usable app name: %v", branch, first, err)
		}
	}
	// Two long branches of one app must not land on the same preview.
	a := previewName("kylebegeman", "renovate/bump-the-first-extremely-long-dependency-name-here")
	b := previewName("kylebegeman", "renovate/bump-the-second-extremely-long-dependency-name-here")
	if a == b {
		t.Fatalf("two branches collided on %q", a)
	}
}

func TestBranchNamesBecomeHostnameLabels(t *testing.T) {
	for branch, want := range map[string]string{
		"main":            "main",
		"feature/new-nav": "feature-new-nav",
		"Feature_Nav":     "feature-nav",
		"--weird--":       "weird",
		"a//b":            "a-b",
	} {
		if got := DNSLabel(branch); got != want {
			t.Fatalf("%q: got %q, want %q", branch, got, want)
		}
	}
}

func TestPreviewRefusesWhatCannotBeAHostname(t *testing.T) {
	if _, err := PreviewOf(parent(t), "///", "preview.begam.in"); err == nil {
		t.Fatal("a branch with nothing usable in it must be refused")
	}
	for _, domain := range []string{"", "not a domain", "preview", "https://preview.begam.in"} {
		if _, err := PreviewOf(parent(t), "main", domain); err == nil {
			t.Fatalf("%q must be refused as a preview domain", domain)
		}
	}
}

// The data and the workloads are the point of a preview: they have to come
// across intact.
func TestAPreviewKeepsWhatMakesItTheSameApp(t *testing.T) {
	src := parent(t)
	p, err := PreviewOf(src, "nav", "preview.begam.in")
	if err != nil {
		t.Fatal(err)
	}
	if p.PostgresVersion() != src.PostgresVersion() {
		t.Fatal("the preview lost the database")
	}
	if len(p.Workloads) != len(src.Workloads) {
		t.Fatalf("%d workloads, want %d", len(p.Workloads), len(src.Workloads))
	}
	if p.Workloads["web"].Port != 8000 || p.Workloads["bakery"].Port != 8001 {
		t.Fatal("the preview changed a port")
	}
	if p.Repo != src.Repo {
		t.Fatal("the preview lost the repository")
	}
	if !strings.Contains(p.Description, "kylebegeman") || !strings.Contains(p.Description, "nav") {
		t.Fatalf("the description says nothing useful: %q", p.Description)
	}
	// The parent's own routes must be exactly as they were.
	if src.Workloads["web"].Routes[0].Host != "kylebegeman.com" || src.Workloads["web"].Routes[0].Auth != manifest.AuthNone {
		t.Fatal("deriving a preview changed the parent")
	}
}

func TestAPreviewSharesNothingWithItsParent(t *testing.T) {
	src, err := manifest.Parse([]byte("app: shop\nworkloads:\n  web:\n    kind: web\n    image: x\n    port: 80\n    routes: [{host: shop.example.com, dns: direct}]\ndata:\n  postgres: {version: \"16\", env: {TZ: UTC}}\n  volumes:\n    files: {}\nsecrets:\n  generate: {TOKEN: hex:16}\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := PreviewOf(src, "nav", "preview.example.com")
	if err != nil {
		t.Fatal(err)
	}
	p.Data.Postgres.Version = "18"
	p.Data.Postgres.Env["TZ"] = "Mars"
	p.Data.Volumes["more"] = manifest.Volume{}
	p.Secrets.Generate["OTHER"] = "hex:8"
	SetRouteDNS(p, manifest.DNSManual)
	if src.Data.Postgres.Version != "16" || src.Data.Postgres.Env["TZ"] != "UTC" || len(src.Data.Volumes) != 1 || len(src.Secrets.Generate) != 1 {
		t.Fatalf("the parent changed underneath: %+v %+v", src.Data, src.Secrets)
	}
	if src.Workloads["web"].Routes[0].DNS != manifest.DNSDirect || p.Workloads["web"].Routes[0].DNS != manifest.DNSManual {
		t.Fatalf("routes: parent %v, preview %v", src.Workloads["web"].Routes, p.Workloads["web"].Routes)
	}
}

func TestAPreviewSaysWhatItPreviewsWhateverItIsCalled(t *testing.T) {
	p, err := PreviewOf(parent(t), "feature/new-nav", "preview.begam.in")
	if err != nil {
		t.Fatal(err)
	}
	if p.Preview == nil || p.Preview.Of != "kylebegeman" || p.Preview.Branch != "feature/new-nav" {
		t.Fatalf("preview block: %+v", p.Preview)
	}
	// The mark survives the round trip a deploy makes of it.
	body, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := manifest.Parse(body)
	if err != nil || back.Preview == nil || back.Preview.Of != "kylebegeman" {
		t.Fatalf("%v %+v", err, back)
	}
	// An app whose name merely looks like a preview's is not one.
	plain, err := manifest.Parse([]byte("app: api-pr-tools\nworkloads:\n  w:\n    kind: worker\n    image: x\n"))
	if err != nil || plain.Preview != nil {
		t.Fatalf("%v %+v", err, plain)
	}
}

func TestPreviewRefusesCollidingRoutesOfDifferentWorkloads(t *testing.T) {
	m, err := manifest.Parse([]byte(`app: site
workloads:
  first:
    kind: web
    image: image
    port: 80
    routes: [{host: api.first.example.com}]
  second:
    kind: web
    image: image
    port: 80
    routes: [{host: api.second.example.com}, {host: other.second.example.com}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewOf(m, "feature", "preview.example.com"); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("preview silently dropped a workload's route: %v", err)
	}
}

func TestPreviewRefusesCollidingRoutesThatReachDifferentPorts(t *testing.T) {
	m, err := manifest.Parse([]byte(`app: site
workloads:
  api:
    kind: web
    image: image
    port: 80
    routes:
      - {host: api.first.example.com}
      - {host: api.second.example.com, port: 8080}
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewOf(m, "feature", "preview.example.com"); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("preview silently changed a route's upstream port: %v", err)
	}
}
