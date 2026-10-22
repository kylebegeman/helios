package manifest

import (
	"strings"
	"testing"
)

const checkedApp = "app: site\nworkloads:\n  web:\n    kind: web\n    image: image\n    port: 80\n    routes: [{host: site.example.com, auth: loom}]\n"

func TestCheckContextsAndCredentialNamesAreValidated(t *testing.T) {
	for _, tc := range []struct{ check, want string }{
		{"{url: https://site.example.com/, context: edge, headers_from_secrets: {Cookie: CHECK_COOKIE, Authorization: CHECK_AUTHORIZATION}}", ""},
		{"{url: https://site.example.com/, context: application}", ""},
		{"{url: https://site.example.com/}", ""},
		{"{url: https://site.example.com/, context: both}", "context"},
		{"{url: https://site.example.com/, headers_from_secrets: {Cookie: CHECK_COOKIE}}", "context: edge"},
		{"{url: http://site.example.com/, context: edge, headers_from_secrets: {Cookie: CHECK_COOKIE}}", "https"},
		{"{url: https://site.example.com/, context: edge, headers_from_secrets: {Host: CHECK_HOST}}", "allowed request header"},
		{"{url: https://site.example.com/, context: edge, headers_from_secrets: {X-Forwarded-Host: CHECK_HOST}}", "allowed request header"},
		{"{url: https://site.example.com/, context: edge, headers_from_secrets: {'Bad Header': CHECK_TOKEN}}", "allowed request header"},
		{"{url: https://site.example.com/, context: edge, headers_from_secrets: {Cookie: 'plain value'}}", "UPPER_CASE"},
		{"{url: https://site.example.com/, context: edge, headers_from_secrets: {Cookie: ONE, cookie: TWO}}", "different case"},
		{"{url: 'https://user:password@site.example.com/'}", "credentials belong"},
		{"{url: 'https:///path'}", "name a host"},
	} {
		t.Run(tc.check, func(t *testing.T) {
			_, err := Parse([]byte(checkedApp + "checks:\n  - " + tc.check + "\n"))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %s", err, tc.want)
			}
		})
	}
}

func TestChecksRequireAnHTTPStatusOrTheDefault(t *testing.T) {
	for _, status := range []string{"0", "100", "200", "599", "1", "99", "600"} {
		_, err := Parse([]byte(checkedApp + "checks:\n  - {url: https://site.example.com/, status: " + status + "}\n"))
		valid := status == "0" || status == "100" || status == "200" || status == "599"
		if valid && err != nil {
			t.Errorf("status %s: %v", status, err)
		}
		if !valid && (err == nil || !strings.Contains(err.Error(), "status must be an HTTP status")) {
			t.Errorf("accepted status %s: %v", status, err)
		}
	}
}
