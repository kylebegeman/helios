package edge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Keep the pre-optimization encoder as a test oracle. The boot file and Caddy
// reload payload must retain their complete bytes, including map key ordering,
// JSON escaping, empty objects/arrays and authentication response nesting.
func TestConfigBehindMatchesMapEncoding(t *testing.T) {
	guarded := &Guard{Dial: "auth.example.com:443", Path: "/verify", TLS: true, HeaderName: "X-Verified", HeaderValue: "yes"}
	special := "quote\"\\\n\t<>&\u2028\u2029雪" + string([]byte{0xff})
	routes, proxies := configBenchmarkFixture(10)
	cases := []struct {
		name    string
		routes  []Route
		proxies []string
	}{
		{name: "nil"},
		{name: "empty", routes: []Route{}, proxies: []string{}},
		{name: "proxies without routes", proxies: proxies},
		{name: "mixed", routes: routes, proxies: proxies},
		{name: "equal length prefixes", routes: []Route{{Host: "h", Path: "/aa/", Dial: "a"}, {Host: "h", Path: "/bb/", Dial: "b"}, {Host: "h", Path: "/", Dial: "root"}}},
		{name: "empty fields", routes: []Route{{}}},
		{name: "escaping", routes: []Route{{Host: special, Path: "/" + special + "/", Dial: special, Guard: &Guard{Dial: special, Path: special, TLS: true, ServerName: special, HeaderName: special, HeaderValue: special}}}, proxies: []string{special}},
		{name: "TLS without server name", routes: []Route{{Host: "h", Path: "/", Dial: "d", Guard: guarded}}},
		{name: "invalid guard", routes: []Route{{Host: "h", Path: "/", Guard: &Guard{Dial: "auth"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkConfigEncodingEquivalent(t, tc.routes, tc.proxies) })
	}
	// Exercise repeated hosts, equal prefix lengths, guards shared by routes,
	// both transports and optional TLS names across deterministic input orders.
	rng := rand.New(rand.NewPCG(7, 11))
	for n := range 32 {
		t.Run(fmt.Sprintf("mixed order %d", n), func(t *testing.T) {
			shuffled := slices.Clone(routes)
			rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			for i := range shuffled {
				if shuffled[i].Guard != nil {
					guard := *shuffled[i].Guard
					guard.TLS = rng.IntN(2) == 0
					if rng.IntN(2) == 0 {
						guard.ServerName = ""
					}
					if rng.IntN(2) == 0 {
						guard.HeaderValue = ""
					}
					shuffled[i].Guard = &guard
				}
			}
			checkConfigEncodingEquivalent(t, shuffled, proxies)
		})
	}
}

func checkConfigEncodingEquivalent(t *testing.T, routes []Route, proxies []string) {
	t.Helper()
	originalRoutes := slices.Clone(routes)
	for i := range originalRoutes {
		if originalRoutes[i].Guard != nil {
			guard := *originalRoutes[i].Guard
			originalRoutes[i].Guard = &guard
		}
	}
	originalProxies := slices.Clone(proxies)
	want, wantErr := legacyConfigBehind(routes, proxies)
	got, gotErr := ConfigBehind(routes, proxies)
	if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatalf("error: got %v, want %v", gotErr, wantErr)
	}
	if !bytes.Equal(got, want) {
		at := 0
		for at < len(got) && at < len(want) && got[at] == want[at] {
			at++
		}
		t.Fatalf("config differs at byte %d (length %d, want %d): got %q, want %q", at, len(got), len(want), got[at:min(at+80, len(got))], want[at:min(at+80, len(want))])
	}
	if !reflect.DeepEqual(routes, originalRoutes) || !reflect.DeepEqual(proxies, originalProxies) {
		t.Fatal("configuration generation mutated the input")
	}
}

// legacyClientHeaders tell an upstream who the visitor is, and only that: one
// address each, whatever the request carried. Caddy's own X-Forwarded-For
// would keep what a client wrote in front of the proxy's entry, where an
// app reading the first address would take it at its word.
var legacyClientHeaders = map[string][]string{
	"X-Forwarded-For": {clientIP},
	"X-Real-IP":       {clientIP},
}

// legacyProxyTo is a reverse_proxy to one upstream that says who the visitor is.
func legacyProxyTo(dial string) map[string]any {
	return map[string]any{
		"handler":            "reverse_proxy",
		"upstreams":          []map[string]any{{"dial": dial}},
		"headers":            map[string]any{"request": map[string]any{"set": legacyClientHeaders}},
		"stream_close_delay": StreamCloseDelay,
	}
}

func legacyConfigBehind(routes []Route, proxies []string) ([]byte, error) {
	byHost := map[string][]Route{}
	for _, r := range routes {
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var serverRoutes []map[string]any
	for _, host := range hosts {
		rs := byHost[host]
		// Longest prefix first; the catch-all last, without a path matcher.
		sort.Slice(rs, func(i, j int) bool { return len(rs[i].Path) > len(rs[j].Path) })
		var sub []map[string]any
		for _, r := range rs {
			handle := []map[string]any{legacyProxyTo(r.Dial)}
			if r.Guard != nil {
				// A guard that decides on the status alone can be talked
				// into a yes by any server that answers 200 for a path it
				// does not know, which is what a single-page app does. There
				// is no configuration in which that is wanted, so it is not
				// one that can be built.
				if r.Guard.HeaderName == "" {
					return nil, fmt.Errorf("the guard on %s%s names no header to require; a status alone can be answered by anything", r.Host, r.Path)
				}
				handle = []map[string]any{legacyGuardHandler(r.Guard, handle)}
			}
			if r.Path == "/" {
				sub = append(sub, map[string]any{"handle": handle})
				continue
			}
			prefix := strings.TrimSuffix(r.Path, "/")
			sub = append(sub, map[string]any{
				"match":  []map[string]any{{"path": []string{prefix, prefix + "/*"}}},
				"handle": handle,
			})
		}
		serverRoutes = append(serverRoutes, map[string]any{
			"match":    []map[string]any{{"host": []string{host}}},
			"handle":   []map[string]any{{"handler": "subroute", "routes": sub}},
			"terminal": true,
		})
	}
	if serverRoutes == nil {
		serverRoutes = []map[string]any{}
	}
	server := map[string]any{
		"listen": []string{":80", ":443"},
		"routes": serverRoutes,
		"logs":   map[string]any{},
	}
	if len(proxies) > 0 {
		server["trusted_proxies"] = map[string]any{"source": "static", "ranges": proxies}
		// Cloudflare sets CF-Connecting-IP to the visitor and nothing
		// else. X-Forwarded-For is read right to left, past the proxies,
		// so what a client wrote at its start is never taken.
		server["client_ip_headers"] = []string{"CF-Connecting-IP", "X-Forwarded-For"}
		server["trusted_proxies_strict"] = 1
	}
	cfg := map[string]any{
		// The admin API is a socket in a directory only this machine and
		// the edge share. helios keeps the configuration itself (BootFile),
		// so Caddy's own copy is off.
		"admin": map[string]any{"listen": adminListen, "config": map[string]any{"persist": false}},
		"logging": map[string]any{"logs": map[string]any{
			"default": map[string]any{"writer": map[string]any{"output": "stdout"}, "encoder": map[string]any{"format": "json"}},
		}},
		"apps": map[string]any{
			"http": map[string]any{
				// Per-host counters and latency histograms on the admin
				// API's /metrics: the traffic signals helios keeps per app.
				"metrics": map[string]any{"per_host": true},
				"servers": map[string]any{"bedrock": server},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// legacyGuardHandler asks the guard about the request and, only on a 2xx, runs
// the handlers that reach the app.
//
// This is Caddy's forward_auth written out: a reverse_proxy to the guard
// whose response is handled here rather than returned, with the app's own
// handlers nested under a 2xx match. Anything the guard answers that is not
// a 2xx is copied back to the browser untouched, which is how a 302 to a
// sign-in page reaches the person rather than the app.
func legacyGuardHandler(g *Guard, allowed []map[string]any) map[string]any {
	upstream := map[string]any{"dial": g.Dial}
	allow := map[string]any{"status_code": []int{2}}
	if g.HeaderName != "" {
		allow["headers"] = map[string]any{g.HeaderName: []string{g.HeaderValue}}
	}
	proxy := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]any{upstream},
		// The probe carries no body and asks about, rather than performs,
		// the request; the original method and target travel as headers so
		// the guard can decide on them.
		"rewrite": map[string]any{"method": "GET", "uri": g.Path},
		"headers": map[string]any{"request": map[string]any{"set": map[string]any{
			"X-Forwarded-Method": []string{"{http.request.method}"},
			"X-Forwarded-Uri":    []string{"{http.request.uri}"},
			"X-Forwarded-Host":   []string{"{http.request.host}"},
			"X-Forwarded-For":    legacyClientHeaders["X-Forwarded-For"],
			"X-Real-IP":          legacyClientHeaders["X-Real-IP"],
		}}},
		"handle_response": []map[string]any{{
			"match":  allow,
			"routes": []map[string]any{{"handle": allowed}},
		}},
	}
	if g.TLS {
		tls := map[string]any{}
		if g.ServerName != "" {
			tls["server_name"] = g.ServerName
		}
		proxy["transport"] = map[string]any{"protocol": "http", "tls": tls}
	}
	return proxy
}
