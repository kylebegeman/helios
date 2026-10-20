package edge

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"math/rand/v2"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// Keep the pre-optimization encoder as a test oracle. The boot file and Caddy
// reload payload must retain their complete bytes, including map key ordering,
// JSON escaping, empty objects/arrays and authentication response nesting.
func TestConfigBehindMatchesMapEncoding(t *testing.T) {
	guarded := &Guard{Dial: "auth.example.com:443", Path: "/verify", TLS: true, HeaderName: "X-Verified", HeaderValue: "yes"}
	special := "quote\"\\\n\t<>&\u2028\u2029雪" + string([]byte{0xff})
	routes, proxies := configBenchmarkFixture(t, 10)
	// Origin pull CAs as the edge is handed them: two good ones, one of
	// them with the line breaks base64 allows, a client certificate that
	// isn't a CA, a CA that may not sign certificates, and text that isn't
	// a certificate at all.
	a, b := fixedCA(t, "a"), fixedCA(t, "b")
	minted, err := MintOriginPull("pull.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	unsigning, _ := selfSigned(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	})
	var der []string
	for _, text := range []string{string(minted.LeafPEM), unsigning} {
		block, _ := pem.Decode([]byte(text))
		der = append(der, base64.StdEncoding.EncodeToString(block.Bytes))
	}
	cas := []string{a, b, a[:40] + "\r\n" + a[40:], der[0], der[1], "not base64", ""}
	leaf := der[0]
	pulled := []Route{
		{Host: "required.example.com", Path: "/", Dial: "r", OriginPull: OriginPullRequired, ClientCAs: []string{b, a}},
		{Host: "required.example.com", Path: HookPath + "/", Dial: HooksDial},
		{Host: "optional.example.com", Path: "/", Dial: "o", OriginPull: OriginPullOptional, ClientCAs: []string{cas[2]}},
		{Host: "refused.example.com", Path: "/", Dial: "x", OriginPull: OriginPullRequired, ClientCAs: []string{leaf, der[1], "not base64"}},
		{Host: "open.example.com", Path: "/", Dial: "p", OriginPull: OriginPullOptional},
		{Host: "unknown.example.com", Path: "/", Dial: "u", OriginPull: "always", ClientCAs: []string{a}},
		{Host: "mixed.example.com", Path: "/", Dial: "m", OriginPull: OriginPullOptional, ClientCAs: []string{a}},
		{Host: "mixed.example.com", Path: "/api/", Dial: "m", OriginPull: OriginPullRequired, ClientCAs: []string{b, a}, Guard: guarded},
		{Host: "direct.example.com", Path: "/", Dial: "d"},
	}
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
		{name: "origin pull", routes: pulled, proxies: proxies},
		{name: "origin pull without proxies", routes: pulled},
		{name: "origin pull escaping", routes: []Route{
			{Host: special, Path: "/", Dial: "d", OriginPull: OriginPullRequired, ClientCAs: []string{a}},
			{Host: special + "-", Path: "/", Dial: "d", OriginPull: OriginPullRequired},
		}},
		{name: "empty CA list", routes: []Route{{Host: "h", Path: "/", Dial: "d", OriginPull: OriginPullRequired, ClientCAs: []string{}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkConfigEncodingEquivalent(t, tc.routes, tc.proxies) })
	}
	// Exercise repeated hosts, equal prefix lengths, guards shared by routes,
	// both transports and optional TLS names across deterministic input orders.
	// Every other order also gives the routes origin pull modes and CAs, so a
	// host's routes disagree about them.
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
				if n%2 == 1 {
					shuffled[i].OriginPull = []string{"", "", OriginPullOptional, OriginPullRequired, "always"}[rng.IntN(5)]
					var named []string
					for range rng.IntN(3) {
						named = append(named, cas[rng.IntN(len(cas))])
					}
					shuffled[i].ClientCAs = named
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
		originalRoutes[i].ClientCAs = slices.Clone(originalRoutes[i].ClientCAs)
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
	var policies []map[string]any
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
		match := map[string]any{"host": []string{host}}
		if mode := legacyOriginPullMode(rs); mode != "" {
			match["protocol"] = "https"
			if policy := legacyOriginPullPolicy(host, mode, rs); policy != nil {
				policies = append(policies, policy)
			}
		}
		serverRoutes = append(serverRoutes, map[string]any{
			"match":    []map[string]any{match},
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
	if len(policies) > 0 {
		server["tls_connection_policies"] = append(policies, map[string]any{})
		server["strict_sni_host"] = true
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

// legacyOriginPullMode is the strictest origin pull any of a host's routes
// asks for. A mode the edge doesn't know is taken as required.
func legacyOriginPullMode(rs []Route) string {
	strictest := 0
	for _, r := range rs {
		rank, known := map[string]int{"": 0, OriginPullOptional: 1}[r.OriginPull]
		if !known {
			rank = 2
		}
		strictest = max(strictest, rank)
	}
	return []string{"", OriginPullOptional, OriginPullRequired}[strictest]
}

// legacyOriginPullPolicy is the TLS connection policy for a host that takes
// origin pulls, or nil when it needs none: every CA certificate its routes
// name, once each and sorted, or a refusal when a required host has none.
func legacyOriginPullPolicy(host, mode string, rs []Route) map[string]any {
	found := map[string]bool{}
	for _, r := range rs {
		for _, text := range r.ClientCAs {
			der, err := base64.StdEncoding.DecodeString(text)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err == nil && cert.BasicConstraintsValid && cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign != 0 {
				found[base64.StdEncoding.EncodeToString(der)] = true
			}
		}
	}
	match := map[string]any{"sni": []string{host}}
	if len(found) == 0 {
		if mode == OriginPullRequired {
			return map[string]any{"drop": true, "match": match}
		}
		return nil
	}
	check := "verify_if_given"
	if mode == OriginPullRequired {
		check = "require_and_verify"
	}
	return map[string]any{
		"client_authentication": map[string]any{
			"ca":   map[string]any{"provider": "inline", "trusted_ca_certs": slices.Sorted(maps.Keys(found))},
			"mode": check,
		},
		"match": match,
	}
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
