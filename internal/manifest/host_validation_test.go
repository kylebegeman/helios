package manifest

import (
	"fmt"
	"strings"
	"testing"
)

func TestHostnamesFitDNSLabelAndNameLimits(t *testing.T) {
	for _, tc := range []struct {
		host  string
		valid bool
	}{
		{"site.example.com", true},
		{strings.Repeat("a", 63) + ".example.com", true},
		{"site." + strings.Repeat("a", 63), true},
		{"site." + strings.Repeat("a", 64), false},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), true},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), false},
	} {
		t.Run(fmt.Sprintf("%d/%s", len(tc.host), tc.host), func(t *testing.T) {
			if got := ValidHost(tc.host); got != tc.valid {
				t.Errorf("ValidHost = %v, want %v", got, tc.valid)
			}
			_, err := Parse([]byte(fmt.Sprintf("app: site\nworkloads:\n  web:\n    kind: web\n    image: image\n    port: 8000\n    routes: [{host: %s}]\n", tc.host)))
			if (err == nil) != tc.valid {
				t.Errorf("Parse: %v; want valid %v", err, tc.valid)
			}
			if err := (Scaffold{App: "site", Kind: Web, Host: tc.host}).Check(); (err == nil) != tc.valid {
				t.Errorf("Scaffold.Check: %v; want valid %v", err, tc.valid)
			}
		})
	}
}
