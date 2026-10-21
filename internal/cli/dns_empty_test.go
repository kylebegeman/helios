package cli

import (
	"encoding/json"
	"testing"

	"github.com/kylebegeman/helios/internal/dns"
)

func TestDNSJSONWithNoRoutesReturnsAnEmptyList(t *testing.T) {
	out, stderr, code := run(t, t.TempDir(), "dns", "--json")
	var statuses []dns.Status
	if code != 0 || json.Unmarshal([]byte(out), &statuses) != nil || statuses == nil || len(statuses) != 0 {
		t.Fatalf("empty DNS JSON: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}
