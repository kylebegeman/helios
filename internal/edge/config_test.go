package edge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestConfigGroupsByHostAndOrdersPrefixes(t *testing.T) {
	cfg, err := Config([]Route{
		{Host: "kylebegeman.com", Path: "/", Dial: "bedrock-kylebegeman-site-abc:8080"},
		{Host: "kylebegeman.com", Path: "/thebatteredbaker/", Dial: "bedrock-kylebegeman-bakery-abc:8383"},
		{Host: "www.kylebegeman.com", Path: "/", Dial: "bedrock-kylebegeman-site-abc:8080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Admin struct {
			Listen string `json:"listen"`
		} `json:"admin"`
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen []string `json:"listen"`
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
						} `json:"match"`
						Handle []struct {
							Handler string `json:"handler"`
							Routes  []struct {
								Match []struct {
									Path []string `json:"path"`
								} `json:"match"`
								Handle []struct {
									Handler   string `json:"handler"`
									Upstreams []struct {
										Dial string `json:"dial"`
									} `json:"upstreams"`
								} `json:"handle"`
							} `json:"routes"`
						} `json:"handle"`
						Terminal bool `json:"terminal"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	// Never a network address: an app on an edge network must not reach it.
	if parsed.Admin.Listen != "unix//run/bedrock/caddy.sock" {
		t.Fatalf("admin: %+v", parsed.Admin)
	}
	server := parsed.Apps.HTTP.Servers["bedrock"]
	if strings.Join(server.Listen, ",") != ":80,:443" || len(server.Routes) != 2 {
		t.Fatalf("server: %+v", server)
	}
	first := server.Routes[0]
	if first.Match[0].Host[0] != "kylebegeman.com" || !first.Terminal || first.Handle[0].Handler != "subroute" {
		t.Fatalf("first route: %+v", first)
	}
	sub := first.Handle[0].Routes
	if len(sub) != 2 || strings.Join(sub[0].Match[0].Path, ",") != "/thebatteredbaker,/thebatteredbaker/*" || sub[0].Handle[0].Upstreams[0].Dial != "bedrock-kylebegeman-bakery-abc:8383" {
		t.Fatalf("prefix route first: %+v", sub[0])
	}
	if len(sub[1].Match) != 0 || sub[1].Handle[0].Upstreams[0].Dial != "bedrock-kylebegeman-site-abc:8080" {
		t.Fatalf("catch-all last: %+v", sub[1])
	}
	if server.Routes[1].Match[0].Host[0] != "www.kylebegeman.com" {
		t.Fatalf("second host: %+v", server.Routes[1])
	}
}

func TestInitialServesNothingButAnswersAdmin(t *testing.T) {
	var parsed map[string]any
	if err := json.Unmarshal(Initial(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(Initial()), `"routes": []`) {
		t.Fatalf("initial config:\n%s", Initial())
	}
}

// Every handler that reaches an app keeps its upgraded connections for a
// while after a reload, guarded or not; the guard's own probe is never
// upgraded and has no reason to.
func TestUpgradedConnectionsOutliveAReload(t *testing.T) {
	cfg, err := Config([]Route{
		{Host: "site.example.com", Path: "/", Dial: "bedrock-site-abc:8080"},
		{Host: "site.example.com", Path: "/ws/", Dial: "bedrock-site-abc:8081"},
		{Host: "admin.example.com", Path: "/", Dial: "bedrock-admin-abc:8000",
			Guard: &Guard{Dial: "loom.example.com:443", Path: "/verify", TLS: true, HeaderName: "X-Loom-Verified", HeaderValue: "1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := json.Unmarshal(cfg, &tree); err != nil {
		t.Fatal(err)
	}
	delays := map[string]any{}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if v["handler"] == "reverse_proxy" {
				dial := v["upstreams"].([]any)[0].(map[string]any)["dial"].(string)
				delays[dial] = v["stream_close_delay"]
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(tree)
	for _, dial := range []string{"bedrock-site-abc:8080", "bedrock-site-abc:8081", "bedrock-admin-abc:8000"} {
		if delays[dial] != StreamCloseDelay {
			t.Errorf("%s: stream_close_delay %v, want %s", dial, delays[dial], StreamCloseDelay)
		}
	}
	if delay, found := delays["loom.example.com:443"]; !found || delay != nil {
		t.Errorf("the guard's probe: stream_close_delay %v (found %v), want none", delay, found)
	}
	if _, err := time.ParseDuration(StreamCloseDelay); err != nil {
		t.Fatalf("Caddy reads the delay as a Go duration: %v", err)
	}
}

// pullServer is what a configuration says about origin pulls: each host's
// route, as written, and the server's TLS settings.
type pullServer struct {
	Routes        []json.RawMessage `json:"routes"`
	StrictSNIHost *bool             `json:"strict_sni_host"`
	Policies      []json.RawMessage `json:"tls_connection_policies"`
}

func pullConfig(t *testing.T, routes []Route) pullServer {
	t.Helper()
	cfg, err := ConfigBehind(routes, nil)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Apps struct {
			HTTP struct {
				Servers struct {
					Bedrock pullServer `json:"bedrock"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.Apps.HTTP.Servers.Bedrock
}

// hostMatch is the host and protocol a host's route matches on.
func (s pullServer) hostMatch(t *testing.T, host string) string {
	t.Helper()
	for _, raw := range s.Routes {
		var route struct {
			Match []struct {
				Host     []string `json:"host"`
				Protocol string   `json:"protocol"`
			} `json:"match"`
		}
		if err := json.Unmarshal(raw, &route); err != nil {
			t.Fatal(err)
		}
		if len(route.Match) == 1 && slices.Equal(route.Match[0].Host, []string{host}) {
			return host + " " + route.Match[0].Protocol
		}
	}
	t.Fatalf("no route for %s", host)
	return ""
}

func (s pullServer) policies(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, raw := range s.Policies {
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			t.Fatal(err)
		}
		out = append(out, compact.String())
	}
	return out
}

// checking is the policy that checks host's clients against cas.
func checking(host, mode string, cas ...string) string {
	quoted, _ := json.Marshal(cas)
	return `{"client_authentication":{"ca":{"provider":"inline","trusted_ca_certs":` + string(quoted) + `},"mode":"` + mode + `"},"match":{"sni":["` + host + `"]}}`
}

// refusing is the policy that refuses every handshake for host.
func refusing(host string) string { return `{"drop":true,"match":{"sni":["` + host + `"]}}` }

func TestEachOriginPullHostGetsItsOwnTLSPolicy(t *testing.T) {
	a, b := fixedCA(t, "a"), fixedCA(t, "b")
	minted, err := MintOriginPull("pull.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pem.Decode(minted.LeafPEM)
	damaged := []string{"not base64!", base64.StdEncoding.EncodeToString(leaf.Bytes), base64.StdEncoding.EncodeToString([]byte("not DER")), ""}
	pull := func(mode string, cas ...string) []Route {
		return []Route{{Host: "pull.example.com", Path: "/", Dial: "app:8080", OriginPull: mode, ClientCAs: cas}}
	}
	cases := []struct {
		name     string
		routes   []Route
		policies []string
	}{
		{"required with a CA", pull(OriginPullRequired, a), []string{checking("pull.example.com", "require_and_verify", a), "{}"}},
		{"optional with a CA", pull(OriginPullOptional, a), []string{checking("pull.example.com", "verify_if_given", a), "{}"}},
		// Nothing to check a certificate against: the host takes every
		// connection, as it would without origin pull, until a CA is
		// trusted for it.
		{"optional without a CA", pull(OriginPullOptional), nil},
		// Nothing to check a certificate against, and a certificate
		// required: no connection can be let in, and no other host is
		// any the worse for it.
		{"required without a CA", pull(OriginPullRequired), []string{refusing("pull.example.com"), "{}"}},
		{"a mode this edge doesn't know, with a CA", pull("always", a), []string{checking("pull.example.com", "require_and_verify", a), "{}"}},
		{"a mode this edge doesn't know, without a CA", pull("Optional"), []string{refusing("pull.example.com"), "{}"}},
		{"damaged CAs are left out", pull(OriginPullRequired, append(slices.Clone(damaged), b)...), []string{checking("pull.example.com", "require_and_verify", b), "{}"}},
		{"only damaged CAs, required", pull(OriginPullRequired, damaged...), []string{refusing("pull.example.com"), "{}"}},
		{"only damaged CAs, optional", pull(OriginPullOptional, damaged...), nil},
		// A host trusts its old CA and its new one while Cloudflare moves
		// from the old leaf to the new one; each is written once.
		{"two CAs", pull(OriginPullRequired, b, a, b), []string{checking("pull.example.com", "require_and_verify", slices.Sorted(slices.Values([]string{a, b}))...), "{}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := pullConfig(t, tc.routes)
			if got := server.hostMatch(t, "pull.example.com"); got != "pull.example.com https" {
				t.Fatalf("host match: %q; port 80 must redirect rather than serve", got)
			}
			if got := server.policies(t); !slices.Equal(got, tc.policies) {
				t.Fatalf("policies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.policies, "\n"))
			}
			// Strict SNI is on whenever a policy is written, and otherwise
			// not written at all.
			if wantStrict := tc.policies != nil; (server.StrictSNIHost != nil) != wantStrict || (wantStrict && !*server.StrictSNIHost) {
				t.Fatalf("strict_sni_host: %v with %d policies", server.StrictSNIHost, len(tc.policies))
			}
		})
	}
}

// The git hook's route on an app's first host carries no mode of its own;
// whatever order the routes come in, it never weakens the host's.
func TestTheStrictestRouteDecidesAHostsOriginPull(t *testing.T) {
	a, b := fixedCA(t, "a"), fixedCA(t, "b")
	routes := []Route{
		{Host: "site.example.com", Path: HookPath + "/", Dial: HooksDial},
		{Host: "site.example.com", Path: "/", Dial: "web:8080", OriginPull: OriginPullRequired, ClientCAs: []string{b}},
		{Host: "site.example.com", Path: "/api/", Dial: "api:9000", OriginPull: OriginPullOptional, ClientCAs: []string{a}},
	}
	want := []string{checking("site.example.com", "require_and_verify", slices.Sorted(slices.Values([]string{a, b}))...), "{}"}
	var first []byte
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		ordered := make([]Route, len(order))
		for i, at := range order {
			ordered[i] = routes[at]
		}
		if got := pullConfig(t, ordered).policies(t); !slices.Equal(got, want) {
			t.Fatalf("order %v: policies %s", order, got)
		}
		cfg, err := Config(ordered)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = cfg
		} else if !bytes.Equal(cfg, first) {
			t.Fatalf("order %v built a different configuration", order)
		}
	}
	if got := pullConfig(t, routes[:1]).Policies; got != nil {
		t.Fatalf("the hook route alone asks for origin pull: %s", got)
	}
}

// A host that doesn't take origin pulls, such as a dns: direct one, is
// written exactly as it was before any host did, and a configuration with
// no origin-pull host at all is the one helios always wrote.
func TestAHostWithoutOriginPullKeepsItsBytes(t *testing.T) {
	a := fixedCA(t, "a")
	direct := []Route{
		{Host: "direct.example.com", Path: "/", Dial: "web:8080"},
		{Host: "direct.example.com", Path: "/api/", Dial: "api:9000", Guard: &Guard{Dial: "auth:443", Path: "/verify", TLS: true, HeaderName: "X-Verified", HeaderValue: "yes"}},
		{Host: "direct.example.com", Path: HookPath + "/", Dial: HooksDial},
	}
	before, err := Config(direct)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"strict_sni_host", "tls_connection_policies"} {
		if bytes.Contains(before, []byte(`"`+field+`"`)) {
			t.Fatalf("a configuration without origin pull writes %s", field)
		}
	}
	alone := pullConfig(t, direct)
	if got := alone.hostMatch(t, "direct.example.com"); got != "direct.example.com " {
		t.Fatalf("a configuration without origin pull matches the host by %q", got)
	}
	beside := pullConfig(t, append(slices.Clone(direct),
		Route{Host: "a-pull.example.com", Path: "/", Dial: "pull:8080", OriginPull: OriginPullRequired, ClientCAs: []string{a}},
		Route{Host: "z-pull.example.com", Path: "/", Dial: "pull:8080", OriginPull: OriginPullOptional}))
	if len(beside.Routes) != 3 || !bytes.Equal(beside.Routes[1], alone.Routes[0]) {
		t.Fatalf("the direct host changed beside origin-pull hosts:\n%s\nwas:\n%s", beside.Routes[1], alone.Routes[0])
	}
	if got := beside.hostMatch(t, "direct.example.com"); got != "direct.example.com " {
		t.Fatalf("the direct host's match: %q", got)
	}
}

func TestOriginPullPoliciesFollowHostOrderThenTheCatchAll(t *testing.T) {
	a, b := fixedCA(t, "a"), fixedCA(t, "b")
	routes := []Route{
		{Host: "c.example.com", Path: "/", Dial: "c:80", OriginPull: OriginPullRequired},
		{Host: "plain.example.com", Path: "/", Dial: "p:80"},
		{Host: "a.example.com", Path: "/", Dial: "a:80", OriginPull: OriginPullOptional, ClientCAs: []string{b, a}},
		{Host: "b.example.com", Path: "/", Dial: "b:80", OriginPull: OriginPullRequired, ClientCAs: []string{a}},
		{Host: "d.example.com", Path: "/", Dial: "d:80", OriginPull: OriginPullOptional},
	}
	original := slices.Clone(routes)
	for i := range original {
		original[i].ClientCAs = slices.Clone(original[i].ClientCAs)
	}
	server := pullConfig(t, routes)
	want := []string{
		checking("a.example.com", "verify_if_given", slices.Sorted(slices.Values([]string{a, b}))...),
		checking("b.example.com", "require_and_verify", a),
		refusing("c.example.com"),
		"{}",
	}
	if got := server.policies(t); !slices.Equal(got, want) {
		t.Fatalf("policies:\n%s", strings.Join(got, "\n"))
	}
	if server.StrictSNIHost == nil || !*server.StrictSNIHost {
		t.Fatalf("strict_sni_host: %v", server.StrictSNIHost)
	}
	for host, protocol := range map[string]string{"a": "https", "b": "https", "c": "https", "d": "https", "plain": ""} {
		if got := server.hostMatch(t, host+".example.com"); got != host+".example.com "+protocol {
			t.Errorf("host match: %q", got)
		}
	}
	if !reflect.DeepEqual(routes, original) {
		t.Fatal("building the configuration changed the routes it was given")
	}
}
