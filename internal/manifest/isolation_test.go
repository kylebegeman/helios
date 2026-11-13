package manifest

import (
	"slices"
	"strings"
	"testing"
)

const isolated = `app: loom
workloads:
  web:
    kind: web
    image: local/loom:1
    port: 3773
    user: "1000:1000"
    dns_servers: [192.0.2.53, "2001:db8::53"]
    tmpfs: [/app/.cache]
    routes:
      - host: core.example.com
        dns: direct
      - host: core.example.com
        path: /hooks
        dns: direct
  runner:
    kind: worker
    image: local/runner:1
    privileged: true
  mail:
    kind: worker
    image: local/mail:1
    capabilities: [NET_BIND_SERVICE, cap_chown]
    writable_root: true
`

func TestIsolationAndDNSFieldsParse(t *testing.T) {
	m, err := Parse([]byte(isolated))
	if err != nil {
		t.Fatal(err)
	}
	if w := m.Workloads["web"]; w.User != "1000:1000" || w.WritableRoot || len(w.Tmpfs) != 1 || w.Privileged {
		t.Fatalf("web: %+v", w)
	}
	if !m.Workloads["runner"].Privileged {
		t.Fatal("runner should be privileged")
	}
	if got := m.Workloads["web"].DNSServers; !slices.Equal(got, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Fatalf("DNS servers: %v", got)
	}
	if len(m.Workloads["runner"].DNSServers) != 0 {
		t.Fatal("a workload without DNS servers must keep Docker's defaults")
	}
	if caps := m.Workloads["mail"].CapabilityNames(); strings.Join(caps, ",") != "NET_BIND_SERVICE,CHOWN" {
		t.Fatalf("capabilities: %v", caps)
	}
	if hosts := m.ManagedHosts(); len(hosts) != 1 || hosts["core.example.com"] != DNSDirect {
		t.Fatalf("managed hosts: %v", hosts)
	}
}

func TestIsolationAndDNSAreValidated(t *testing.T) {
	cases := []struct{ yaml, want string }{
		{strings.Replace(isolated, "        dns: direct\n      - host: core.example.com\n        path: /hooks\n        dns: direct", "        dns: direct\n      - host: core.example.com\n        path: /hooks\n        dns: proxied", 1), "use one"},
		{strings.Replace(isolated, "dns: direct\n      - host", "dns: cloudy\n      - host", 1), "isn't direct or proxied"},
		{strings.Replace(isolated, `user: "1000:1000"`, `user: "bad user"`, 1), "must be a user"},
		{strings.Replace(isolated, "cap_chown", "chown everything", 1), "isn't a capability name"},
		{strings.Replace(isolated, "privileged: true", "privileged: true\n    capabilities: [SYS_ADMIN]", 1), "keeps every capability already"},
		{strings.Replace(isolated, "tmpfs: [/app/.cache]", "tmpfs: [app/.cache]", 1), "absolute path"},
		{strings.Replace(isolated, "app: loom", "app: edge", 1), "a name helios uses for itself"},
		{strings.Replace(isolated, "app: loom", "app: registry", 1), "a name helios uses for itself"},
		{isolated + "data:\n  volumes:\n    postgres: {}\n", "helios's own volume for the database"},
	}
	for _, server := range []string{"", "resolver.example.com", "192.0.2.53:53", "192.0.2.0/24", "[2001:db8::53]", "fe80::1%eth0", "999.0.0.1"} {
		cases = append(cases, struct{ yaml, want string }{
			strings.Replace(isolated, `dns_servers: [192.0.2.53, "2001:db8::53"]`, `dns_servers: ["`+server+`"]`, 1),
			"workloads.web.dns_servers: use literal IPv4 or IPv6 addresses without a zone",
		})
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.yaml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
	}
}
