package edge

// Fields follow JSON key order so typed encoding preserves the boot file bytes
// produced by encoding/json's sorted map keys. The concrete shape avoids
// rebuilding and reflecting over a tree of generic maps on every reload.
type caddyConfig struct {
	Admin struct {
		Config struct {
			Persist bool `json:"persist"`
		} `json:"config"`
		Listen string `json:"listen"`
	} `json:"admin"`
	Apps struct {
		HTTP struct {
			Metrics struct {
				PerHost bool `json:"per_host"`
			} `json:"metrics"`
			Servers struct {
				Bedrock caddyServer `json:"bedrock"`
			} `json:"servers"`
		} `json:"http"`
	} `json:"apps"`
	Logging struct {
		Logs struct {
			Default struct {
				Encoder struct {
					Format string `json:"format"`
				} `json:"encoder"`
				Writer struct {
					Output string `json:"output"`
				} `json:"writer"`
			} `json:"default"`
		} `json:"logs"`
	} `json:"logging"`
}

type caddyServer struct {
	ClientIPHeaders      []string             `json:"client_ip_headers,omitempty"`
	Listen               [2]string            `json:"listen"`
	Logs                 struct{}             `json:"logs"`
	Routes               []caddyRoute         `json:"routes"`
	TrustedProxies       *caddyTrustedProxies `json:"trusted_proxies,omitempty"`
	TrustedProxiesStrict int                  `json:"trusted_proxies_strict,omitempty"`
}

type caddyRoute struct {
	Handle   [1]caddyHandler `json:"handle"`
	Match    []caddyMatcher  `json:"match,omitempty"`
	Terminal bool            `json:"terminal,omitempty"`
}

type caddyMatcher struct {
	Host []string `json:"host,omitempty"`
	Path []string `json:"path,omitempty"`
}

type caddyHandler struct {
	HandleResponse   []caddyResponse `json:"handle_response,omitempty"`
	Handler          string          `json:"handler"`
	Headers          *caddyHeaders   `json:"headers,omitempty"`
	Rewrite          *caddyRewrite   `json:"rewrite,omitempty"`
	Routes           []caddyRoute    `json:"routes,omitempty"`
	StreamCloseDelay string          `json:"stream_close_delay,omitempty"`
	Transport        *caddyTransport `json:"transport,omitempty"`
	Upstreams        []caddyUpstream `json:"upstreams,omitempty"`
}

type caddyTrustedProxies struct {
	Ranges []string `json:"ranges"`
	Source string   `json:"source"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

type caddyRewrite struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
}

type caddyTransport struct {
	Protocol string `json:"protocol"`
	TLS      struct {
		ServerName string `json:"server_name,omitempty"`
	} `json:"tls"`
}

type caddyResponse struct {
	Match struct {
		Headers    map[string][]string `json:"headers"`
		StatusCode [1]int              `json:"status_code"`
	} `json:"match"`
	Routes [1]caddyRoute `json:"routes"`
}

type caddyHeaders struct {
	Request struct {
		Set struct {
			XForwardedFor    [1]string `json:"X-Forwarded-For"`
			XForwardedHost   []string  `json:"X-Forwarded-Host,omitempty"`
			XForwardedMethod []string  `json:"X-Forwarded-Method,omitempty"`
			XForwardedURI    []string  `json:"X-Forwarded-Uri,omitempty"`
			XRealIP          [1]string `json:"X-Real-IP"`
		} `json:"set"`
	} `json:"request"`
}
