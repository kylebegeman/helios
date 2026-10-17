// Package edge is the web front door: one Caddy on ports 80 and 443 whose
// whole configuration helios owns and rebuilds from the apps it runs.
package edge

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Route sends one host and path prefix to a container.
type Route struct {
	Host string
	// Path is a normalized prefix ending in "/"; "/" is the catch-all.
	Path string
	// Dial is the upstream as Caddy reaches it on the edge network, such as
	// bedrock-kylebegeman-site-3f2a9c:8080, or a Unix socket (unix//path)
	// for helios's own endpoints.
	Dial string
	// Guard, when set, is asked about every request before the upstream
	// sees it. A route with no Guard is open.
	Guard *Guard
}

// Guard is an endpoint the edge asks whether a request may proceed.
//
// A 2xx carrying the named header lets the request through to the app;
// anything else the endpoint answers is returned to the browser as it
// stands. That is what makes a redirect to a sign-in page work without the
// edge knowing anything about signing in.
//
// Nothing of the original request's body is sent, and the probe is a GET,
// so asking is cheap and cannot have side effects of its own.
type Guard struct {
	// Dial is host:port as Caddy reaches the endpoint.
	Dial string
	// Path is the endpoint's path, such as /api/cloud/auth/verify.
	Path string
	// TLS says the endpoint is reached over HTTPS.
	TLS bool
	// ServerName is the name to present and verify when TLS is on, for an
	// endpoint dialled by address rather than by name.
	ServerName string
	// HeaderName and HeaderValue are a header the answer must carry before
	// a 2xx counts as a yes.
	//
	// A status code on its own is not enough. An application that serves a
	// single-page app answers 200 with its index for any path it does not
	// recognise, so a guard pointed at a host that has no verify endpoint
	// at all, or one that has been rolled back to before it existed, would
	// read that 200 as permission and let everybody through. The header is
	// something only the endpoint itself sets, so a fallback cannot say
	// yes by accident.
	HeaderName  string
	HeaderValue string
}

// StreamCloseDelay is how long a connection upgraded through the edge, such
// as a WebSocket or Tailscale's control protocol, outlives the configuration
// it was opened under.
//
// Every deploy and every daemon start loads a whole new configuration, and
// Caddy's default is to close every upgraded connection the moment the old
// one is unloaded, so a deploy of any one app would cut every client of
// every app at the same instant and have them all reconnect together. With
// a delay, a stream that ends on its own within five minutes never notices
// the reload, and the ones still open are closed then rather than in the
// middle of the deploy that caused it. A deploy reloads more than once, so
// the delay is minutes rather than seconds, and it is bounded because the
// streams are closed in the end all the same: clients such as Tailscale's
// reconnect on their own. The guard's probe is never upgraded and has none.
const StreamCloseDelay = "5m"

// Config is Caddy's JSON, built from routes, trusting no proxy. Every
// host gets automatic HTTPS because it appears in a host matcher.
func Config(routes []Route) ([]byte, error) { return ConfigBehind(routes, nil) }

// clientIP is the visitor's address as Caddy works it out: the connecting
// address, or, when that is a trusted proxy's, the address the proxy says
// it connected for.
const clientIP = "{http.vars.client_ip}"

// clientHeaders tell an upstream who the visitor is, and only that: one
// address each, whatever the request carried. Caddy's own X-Forwarded-For
// would keep what a client wrote in front of the proxy's entry, where an
// app reading the first address would take it at its word.
var clientHeaders = func() caddyHeaders {
	var headers caddyHeaders
	headers.Request.Set.XForwardedFor = [1]string{clientIP}
	headers.Request.Set.XRealIP = [1]string{clientIP}
	return headers
}()

var guardHeaders = func() caddyHeaders {
	headers := clientHeaders
	headers.Request.Set.XForwardedHost = []string{"{http.request.host}"}
	headers.Request.Set.XForwardedMethod = []string{"{http.request.method}"}
	headers.Request.Set.XForwardedURI = []string{"{http.request.uri}"}
	return headers
}()

// proxyTo is a reverse_proxy to one upstream that says who the visitor is.
func proxyTo(dial string) caddyHandler {
	proxy := caddyHandler{
		Handler:          "reverse_proxy",
		Headers:          &clientHeaders,
		StreamCloseDelay: StreamCloseDelay,
		Upstreams:        []caddyUpstream{{Dial: dial}},
	}
	return proxy
}

// ConfigBehind is Config for an edge that some requests reach through a
// proxy, such as Cloudflare's: a request that arrives from one of proxies
// is taken to be from the address the proxy names, and every other
// request's claims about where it came from are ignored.
func ConfigBehind(routes []Route, proxies []string) ([]byte, error) {
	byHost := map[string][]Route{}
	for _, r := range routes {
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	serverRoutes := make([]caddyRoute, len(hosts))
	for hostIndex, host := range hosts {
		rs := byHost[host]
		// Longest prefix first; the catch-all last, without a path matcher.
		sort.Slice(rs, func(i, j int) bool { return len(rs[i].Path) > len(rs[j].Path) })
		sub := make([]caddyRoute, len(rs))
		for routeIndex, r := range rs {
			handle := proxyTo(r.Dial)
			if r.Guard != nil {
				// A guard that decides on the status alone can be talked
				// into a yes by any server that answers 200 for a path it
				// does not know, which is what a single-page app does. There
				// is no configuration in which that is wanted, so it is not
				// one that can be built.
				if r.Guard.HeaderName == "" {
					return nil, fmt.Errorf("the guard on %s%s names no header to require; a status alone can be answered by anything", r.Host, r.Path)
				}
				handle = guardHandler(r.Guard, handle)
			}
			sub[routeIndex].Handle[0] = handle
			if r.Path != "/" {
				prefix := strings.TrimSuffix(r.Path, "/")
				sub[routeIndex].Match = []caddyMatcher{{Path: []string{prefix, prefix + "/*"}}}
			}
		}
		serverRoutes[hostIndex] = caddyRoute{
			Handle:   [1]caddyHandler{{Handler: "subroute", Routes: sub}},
			Match:    []caddyMatcher{{Host: []string{host}}},
			Terminal: true,
		}
	}
	server := caddyServer{Listen: [2]string{":80", ":443"}, Routes: serverRoutes}
	if len(proxies) > 0 {
		server.TrustedProxies = &caddyTrustedProxies{Ranges: proxies, Source: "static"}
		// Cloudflare sets CF-Connecting-IP to the visitor and nothing
		// else. X-Forwarded-For is read right to left, past the proxies,
		// so what a client wrote at its start is never taken.
		server.ClientIPHeaders = []string{"CF-Connecting-IP", "X-Forwarded-For"}
		server.TrustedProxiesStrict = 1
	}
	var cfg caddyConfig
	// The admin API is a socket in a directory only this machine and
	// the edge share. helios keeps the configuration itself (BootFile),
	// so Caddy's own copy is off.
	cfg.Admin.Listen = adminListen
	// Per-host counters and latency histograms on the admin API's /metrics:
	// the traffic signals helios keeps per app.
	cfg.Apps.HTTP.Metrics.PerHost = true
	cfg.Apps.HTTP.Servers.Bedrock = server
	cfg.Logging.Logs.Default.Encoder.Format = "json"
	cfg.Logging.Logs.Default.Writer.Output = "stdout"
	return json.MarshalIndent(cfg, "", "  ")
}

// Initial is the configuration the edge starts with before any app is
// deployed: an admin API helios can reach, and nothing to serve.
func Initial() []byte {
	b, _ := Config(nil)
	return b
}

// guardHandler asks the guard about the request and, only on a 2xx, runs
// the handlers that reach the app.
//
// This is Caddy's forward_auth written out: a reverse_proxy to the guard
// whose response is handled here rather than returned, with the app's own
// handlers nested under a 2xx match. Anything the guard answers that is not
// a 2xx is copied back to the browser untouched, which is how a 302 to a
// sign-in page reaches the person rather than the app.
func guardHandler(g *Guard, allowed caddyHandler) caddyHandler {
	var response caddyResponse
	response.Match.Headers = map[string][]string{g.HeaderName: {g.HeaderValue}}
	response.Match.StatusCode = [1]int{2}
	response.Routes[0].Handle[0] = allowed
	proxy := caddyHandler{
		HandleResponse: []caddyResponse{response},
		Handler:        "reverse_proxy",
		Headers:        &guardHeaders,
		Upstreams:      []caddyUpstream{{Dial: g.Dial}},
	}
	// The probe carries no body and asks about, rather than performs,
	// the request; the original method and target travel as headers so
	// the guard can decide on them.
	proxy.Rewrite = &caddyRewrite{Method: "GET", URI: g.Path}
	if g.TLS {
		proxy.Transport = &caddyTransport{Protocol: "http"}
		proxy.Transport.TLS.ServerName = g.ServerName
	}
	return proxy
}
