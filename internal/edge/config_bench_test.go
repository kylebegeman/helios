package edge

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ConfigBehind rebuilds the complete edge configuration on deployment and
// daemon startup. Each app contributes a catch-all, an API, a guarded admin
// route and a route on a shared host. This measures grouping and prefix sorting
// as well as encoding open and guarded handlers, without Docker or Caddy I/O.
func BenchmarkConfigBehind(b *testing.B) {
	for _, apps := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("apps=%d", apps), func(b *testing.B) {
			routes, proxies := configBenchmarkFixture(apps)
			config, err := ConfigBehind(routes, proxies)
			if err != nil {
				b.Fatal(err)
			}
			checkConfigBenchmarkFixture(b, config, routes, proxies)
			b.ReportAllocs()
			b.SetBytes(int64(len(config)))
			b.ReportMetric(float64(len(routes)), "routes/op")
			b.ReportMetric(float64(apps+1), "hosts/op")
			for b.Loop() {
				if _, err := ConfigBehind(routes, proxies); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func configBenchmarkFixture(apps int) ([]Route, []string) {
	guards := []*Guard{
		{Dial: "auth.example.com:443", Path: "/api/cloud/auth/verify", TLS: true, ServerName: "auth.example.com", HeaderName: "X-Loom-Verified", HeaderValue: "yes"},
		{Dial: "bedrock-auth-api-ab12cd:4773", Path: "/verify", HeaderName: "X-Loom-Verified", HeaderValue: "yes"},
	}
	routes := make([]Route, 0, apps*4)
	// Reverse app order and interleave hosts so the benchmark cannot rely on
	// inputs already being grouped or sorted. Guard pointers are shared, as in
	// app.edgeConfig, rather than allocating an artificial guard per route.
	for app := apps - 1; app >= 0; app-- {
		host := fmt.Sprintf("app-%04d.example.com", app)
		dial := fmt.Sprintf("bedrock-app-%04d-web-ab12cd:8080", app)
		guard := guards[app%len(guards)]
		var sharedGuard *Guard
		if app%2 == 0 {
			sharedGuard = guard
		}
		routes = append(routes,
			Route{Host: host, Path: "/", Dial: dial},
			Route{Host: "shared.example.com", Path: fmt.Sprintf("/apps/app-%04d/", app), Dial: dial, Guard: sharedGuard},
			Route{Host: host, Path: "/api/", Dial: fmt.Sprintf("bedrock-app-%04d-api-ab12cd:9000", app)},
			Route{Host: host, Path: "/admin/", Dial: dial, Guard: guard},
		)
	}
	// Representative IPv4 and IPv6 Cloudflare ranges. The benchmark is local
	// and deterministic; it never fetches the current list from the network.
	proxies := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
		"2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32",
	}
	return routes, proxies
}

type benchmarkConfigRoute struct {
	Match []struct {
		Host []string `json:"host"`
		Path []string `json:"path"`
	} `json:"match"`
	Handle   []benchmarkConfigHandler `json:"handle"`
	Terminal bool                     `json:"terminal"`
}

type benchmarkConfigHandler struct {
	Handler   string                 `json:"handler"`
	Routes    []benchmarkConfigRoute `json:"routes"`
	Upstreams []struct {
		Dial string `json:"dial"`
	} `json:"upstreams"`
	Rewrite struct {
		Method string `json:"method"`
		URI    string `json:"uri"`
	} `json:"rewrite"`
	HandleResponse []struct {
		Match struct {
			StatusCode []int               `json:"status_code"`
			Headers    map[string][]string `json:"headers"`
		} `json:"match"`
		Routes []benchmarkConfigRoute `json:"routes"`
	} `json:"handle_response"`
}

// Check correctness outside the timed loop so dropping hosts, upstreams,
// authentication or trusted proxy configuration cannot improve the result.
func checkConfigBenchmarkFixture(tb testing.TB, raw []byte, routes []Route, proxies []string) {
	tb.Helper()
	var config struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes         []benchmarkConfigRoute `json:"routes"`
					TrustedProxies struct {
						Source string   `json:"source"`
						Ranges []string `json:"ranges"`
					} `json:"trusted_proxies"`
					ClientIPHeaders      []string `json:"client_ip_headers"`
					TrustedProxiesStrict int      `json:"trusted_proxies_strict"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		tb.Fatal(err)
	}
	server, ok := config.Apps.HTTP.Servers["bedrock"]
	if !ok || server.TrustedProxies.Source != "static" || !slices.Equal(server.TrustedProxies.Ranges, proxies) || server.TrustedProxiesStrict != 1 || !slices.Equal(server.ClientIPHeaders, []string{"CF-Connecting-IP", "X-Forwarded-For"}) {
		tb.Fatal("benchmark config lost the trusted proxy configuration")
	}
	want := make(map[string]map[string]Route)
	for _, route := range routes {
		if want[route.Host] == nil {
			want[route.Host] = make(map[string]Route)
		}
		want[route.Host][route.Path] = route
	}
	if len(server.Routes) != len(want) {
		tb.Fatalf("config hosts: got %d, want %d", len(server.Routes), len(want))
	}
	lastHost := ""
	for _, hostRoute := range server.Routes {
		if len(hostRoute.Match) != 1 || len(hostRoute.Match[0].Host) != 1 || len(hostRoute.Handle) != 1 || !hostRoute.Terminal || hostRoute.Handle[0].Handler != "subroute" {
			tb.Fatal("benchmark config has a malformed host route")
		}
		host := hostRoute.Match[0].Host[0]
		expected := want[host]
		if host <= lastHost || expected == nil || len(hostRoute.Handle[0].Routes) != len(expected) {
			tb.Fatalf("missing, duplicate or unsorted host %q", host)
		}
		lastHost = host
		lastPrefixLength := int(^uint(0) >> 1)
		for _, sub := range hostRoute.Handle[0].Routes {
			path := "/"
			if len(sub.Match) > 0 {
				if len(sub.Match) != 1 || len(sub.Match[0].Path) != 2 {
					tb.Fatal("benchmark config has a malformed path matcher")
				}
				prefix := sub.Match[0].Path[0]
				if sub.Match[0].Path[1] != prefix+"/*" {
					tb.Fatalf("malformed path matcher on %s%s", host, prefix)
				}
				path = strings.TrimSuffix(prefix, "/") + "/"
			}
			route, exists := expected[path]
			if !exists || len(path) > lastPrefixLength || len(sub.Handle) != 1 {
				tb.Fatalf("missing, duplicate or unsorted route %s%s", host, path)
			}
			delete(expected, path)
			lastPrefixLength = len(path)
			handler := sub.Handle[0]
			if route.Guard != nil {
				g := route.Guard
				if len(handler.Upstreams) != 1 || handler.Upstreams[0].Dial != g.Dial || handler.Rewrite.Method != "GET" || handler.Rewrite.URI != g.Path || len(handler.HandleResponse) != 1 {
					tb.Fatalf("missing guard on %s%s", host, path)
				}
				response := handler.HandleResponse[0]
				if !slices.Equal(response.Match.StatusCode, []int{2}) || !slices.Equal(response.Match.Headers[g.HeaderName], []string{g.HeaderValue}) || len(response.Routes) != 1 || len(response.Routes[0].Handle) != 1 {
					tb.Fatalf("missing guarded allow branch on %s%s", host, path)
				}
				handler = response.Routes[0].Handle[0]
			} else if len(handler.HandleResponse) != 0 {
				tb.Fatalf("open route unexpectedly guarded: %s%s", host, path)
			}
			if handler.Handler != "reverse_proxy" || len(handler.Upstreams) != 1 || handler.Upstreams[0].Dial != route.Dial {
				tb.Fatalf("missing app upstream on %s%s", host, path)
			}
		}
	}
}
