package edge

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files from what the code does now")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to write it)", err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s changed:\n%s", name, got)
	}
}

var goldenRoutes = []Route{
	{Host: "site.example.com", Path: "/", Dial: "bedrock-site-web-abc:8080"},
	{Host: "site.example.com", Path: "/api/", Dial: "bedrock-site-api-abc:9000"},
	{Host: "site.example.com", Path: HookPath + "/", Dial: HooksDial},
	{Host: "admin.example.com", Path: "/", Dial: "bedrock-admin-web-abc:8080", Guard: &Guard{
		Dial: "core.example.com:443", Path: "/api/cloud/auth/verify", TLS: true, ServerName: "core.example.com",
		HeaderName: "X-Loom-Verified", HeaderValue: "yes",
	}},
}

func TestTheEdgeConfigStaysWhatItWas(t *testing.T) {
	cfg, err := Config(goldenRoutes)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "config", cfg)
}

func TestTheEdgeBehindCloudflareStaysWhatItWas(t *testing.T) {
	cfg, err := ConfigBehind(goldenRoutes[:1], []string{"173.245.48.0/20", "2400:cb00::/32"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "config-behind", cfg)
}

// The golden routes again, with every kind of origin pull: a host that
// requires it with two CAs, one where it is optional, one that requires it
// before any CA exists, and one where it is optional with no CA yet. A
// guarded host without origin pull sits among them unchanged.
func TestTheEdgeWithOriginPullStaysWhatItWas(t *testing.T) {
	a, b := fixedCA(t, "a"), fixedCA(t, "b")
	routes := []Route{
		{Host: "site.example.com", Path: "/", Dial: "bedrock-site-web-abc:8080", OriginPull: OriginPullRequired, ClientCAs: []string{b, a}},
		{Host: "site.example.com", Path: "/api/", Dial: "bedrock-site-api-abc:9000", OriginPull: OriginPullRequired, ClientCAs: []string{b, a}},
		{Host: "site.example.com", Path: HookPath + "/", Dial: HooksDial},
		{Host: "shop.example.com", Path: "/", Dial: "bedrock-shop-web-abc:8080", OriginPull: OriginPullOptional, ClientCAs: []string{a}},
		{Host: "vault.example.com", Path: "/", Dial: "bedrock-vault-web-abc:8080", OriginPull: OriginPullRequired},
		{Host: "beta.example.com", Path: "/", Dial: "bedrock-beta-web-abc:8080", OriginPull: OriginPullOptional},
		{Host: "admin.example.com", Path: "/", Dial: "bedrock-admin-web-abc:8080", Guard: &Guard{
			Dial: "core.example.com:443", Path: "/verify", TLS: true, ServerName: "core.example.com",
			HeaderName: "X-Verified", HeaderValue: "yes",
		}},
	}
	cfg, err := ConfigBehind(routes, []string{"192.0.2.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "config-originpull", cfg)
}
