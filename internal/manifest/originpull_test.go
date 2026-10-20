package manifest

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const pulled = `app: shop
workloads:
  web:
    kind: web
    image: example/shop:1
    port: 8080
    routes:
      - {host: shop.example.com, dns: proxied, origin_pull: required}
      - {host: shop.example.com, path: /api, dns: proxied, origin_pull: required}
      - {host: www.example.com, dns: proxied, origin_pull: optional}
      - {host: open.example.com, dns: direct}
  admin:
    kind: web
    image: example/admin:1
    port: 8081
    routes:
      - {host: shop.example.com, path: /admin, dns: proxied, origin_pull: required}
`

func TestOriginPullParsesPerHost(t *testing.T) {
	m, err := Parse([]byte(pulled))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]OriginPullMode{"shop.example.com": OriginPullRequired, "www.example.com": OriginPullOptional}
	got := m.OriginPullHosts()
	if len(got) != len(want) {
		t.Fatalf("origin-pull hosts: %v", got)
	}
	for host, mode := range want {
		if got[host] != mode {
			t.Fatalf("origin-pull hosts: %v, want %v", got, want)
		}
	}
}

func TestOriginPullIsValidated(t *testing.T) {
	for _, c := range []struct{ name, from, to, want string }{
		{"an unknown mode", "www.example.com, dns: proxied, origin_pull: optional", "www.example.com, dns: proxied, origin_pull: strict",
			`workloads.web.routes[2].origin_pull: "strict" isn't optional or required`},
		{"a mode in another case", "www.example.com, dns: proxied, origin_pull: optional", "www.example.com, dns: proxied, origin_pull: Required",
			`workloads.web.routes[2].origin_pull: "Required" isn't optional or required`},
		{"a direct record", "open.example.com, dns: direct}", "open.example.com, dns: direct, origin_pull: optional}",
			"workloads.web.routes[3].origin_pull: needs dns: proxied"},
		{"a record kept by hand", "www.example.com, dns: proxied, origin_pull: optional", "www.example.com, origin_pull: required",
			"workloads.web.routes[2].origin_pull: needs dns: proxied"},
		{"a route on the host that leaves it out", "path: /api, dns: proxied, origin_pull: required", "path: /api, dns: proxied",
			`routes: shop.example.com has origin_pull "required" on one route and "" on another; give every route to shop.example.com the same origin_pull`},
		{"another workload asking less", "path: /admin, dns: proxied, origin_pull: required", "path: /admin, dns: proxied, origin_pull: optional",
			`routes: shop.example.com has origin_pull "optional" on one route and "required" on another`},
	} {
		t.Run(c.name, func(t *testing.T) {
			changed := strings.Replace(pulled, c.from, c.to, 1)
			if changed == pulled {
				t.Fatalf("%q isn't in the manifest", c.from)
			}
			_, err := Parse([]byte(changed))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

// A host with three routes that disagree is one problem, said once.
func TestOriginPullDisagreementIsSaidOncePerHost(t *testing.T) {
	changed := strings.Replace(pulled, "path: /api, dns: proxied, origin_pull: required", "path: /api, dns: proxied", 1)
	changed = strings.Replace(changed, "path: /admin, dns: proxied, origin_pull: required", "path: /admin, dns: proxied, origin_pull: optional", 1)
	_, err := Parse([]byte(changed))
	if err == nil || strings.Count(err.Error(), "routes: shop.example.com has origin_pull") != 1 {
		t.Fatalf("want one line for shop.example.com, got %v", err)
	}
}

// Stored revisions are decoded without validation, so the per-host mode
// must not depend on route order, and a mode from a newer helios must not
// leave a host open.
func TestOriginPullHostsTakesTheStrictestAndFailsClosed(t *testing.T) {
	m := &Manifest{Workloads: map[string]Workload{
		"a": {Routes: []Route{
			{Host: "mixed.example.com", OriginPull: OriginPullOptional},
			{Host: "unknown.example.com", OriginPull: "strict"},
			{Host: "open.example.com"},
		}},
		"b": {Routes: []Route{
			{Host: "mixed.example.com", OriginPull: OriginPullRequired},
			{Host: "mixed.example.com", Path: "/later"},
			{Host: "soft.example.com", OriginPull: OriginPullOptional},
			{Host: "soft.example.com", Path: "/x"},
		}},
	}}
	got := m.OriginPullHosts()
	want := map[string]OriginPullMode{
		"mixed.example.com":   OriginPullRequired,
		"unknown.example.com": OriginPullRequired,
		"soft.example.com":    OriginPullOptional,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for host, mode := range want {
		if got[host] != mode {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestStricterOrdersOriginPullModes(t *testing.T) {
	order := []OriginPullMode{OriginPullOff, OriginPullOptional, OriginPullRequired}
	for i, a := range order {
		for j, b := range order {
			if got := a.Stricter(b); got != (i > j) {
				t.Errorf("%q.Stricter(%q) = %v", a, b, got)
			}
		}
	}
	unknown := OriginPullMode("strict")
	if !unknown.Stricter(OriginPullOptional) || unknown.Stricter(OriginPullRequired) || OriginPullRequired.Stricter(unknown) {
		t.Fatal("a mode helios doesn't know must rank with required")
	}
}

// Revisions, move digests and previews marshal the manifest, so a route
// without origin_pull must marshal exactly as it did before the field.
func TestARouteWithoutOriginPullMarshalsAsBefore(t *testing.T) {
	r := Route{Host: "app.example.com", Path: "/api", DNS: DNSProxied, Auth: AuthLoom}
	js, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"host":"app.example.com","path":"/api","dns":"proxied","auth":"loom"}`; string(js) != want {
		t.Fatalf("json: %s, want %s", js, want)
	}
	ys, err := yaml.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := "host: app.example.com\npath: /api\ndns: proxied\nauth: loom\n"; string(ys) != want {
		t.Fatalf("yaml: %q, want %q", ys, want)
	}
	r.OriginPull = OriginPullRequired
	if js, _ := json.Marshal(r); !strings.HasSuffix(string(js), `"origin_pull":"required"}`) {
		t.Fatalf("json with origin pull: %s", js)
	}
}
