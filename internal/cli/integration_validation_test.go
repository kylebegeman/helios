package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/secrets"
)

func TestCloudflareIntegrationRejectsInvalidInputBeforeVerification(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"success":true,"result":[]}`)
	}))
	defer server.Close()
	for _, tc := range []struct {
		name, fields, wantError string
	}{
		{"malformed credentials", "token=fixture-token\napi=http://fixture-user:fixture-url-password@127.0.0.1:bad\n", "cloudflare.api"},
		{"query", "token=fixture-token\napi=" + server.URL + "?key=fixture-query-secret\n", "cloudflare.api"},
		{"missing token", "api=" + server.URL + "\n", "needs token"},
		{"unknown field", "token=fixture-token\napi=" + server.URL + "\nextra=fixture-value\n", "no field named"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			before := requests.Load()
			out, stderr, code := withStdin(t, tc.fields, dir, "integration", "set", "cloudflare")
			if code != 1 || !strings.Contains(stderr, tc.wantError) {
				t.Errorf("invalid integration: exit %d, stdout %q, stderr %q", code, out, stderr)
			}
			for _, secret := range []string{"fixture-token", "fixture-user", "fixture-url-password", "fixture-query-secret"} {
				if strings.Contains(out+stderr, secret) {
					t.Errorf("invalid integration disclosed %s", secret)
				}
			}
			if requests.Load() != before {
				t.Error("verification sent a request before validating the integration")
			}
			if _, err := integration.Get(secrets.DefaultStore(dir), integration.CloudflareName); !errors.Is(err, integration.ErrNotSet) {
				t.Errorf("invalid integration was saved: %v", err)
			}
		})
	}
}

func TestCloudflareVerificationErrorsDoNotEchoCredentials(t *testing.T) {
	const token = "fixture-token-kept-private"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"errors":[{"code":1000,"message":"rejected Authorization: Bearer %s"}]}`, token)
	}))
	defer server.Close()
	dir := t.TempDir()
	out, stderr, code := withStdin(t, "token="+token+"\napi="+server.URL+"\n", dir, "integration", "set", "cloudflare")
	if code != 1 || !strings.Contains(stderr, "cloudflare token") {
		t.Fatalf("verification failure: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if strings.Contains(out+stderr, token) {
		t.Fatal("verification error disclosed the token")
	}
	if _, err := integration.Get(secrets.DefaultStore(dir), integration.CloudflareName); !errors.Is(err, integration.ErrNotSet) {
		t.Errorf("unverified integration was saved: %v", err)
	}
}

func TestCloudflareVerificationUsesPatchedValuesAndRejectsAnExplicitEmptyToken(t *testing.T) {
	var requests atomic.Int32
	var authorization atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		authorization.Store(r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"success":true,"result":[]}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	store := secrets.DefaultStore(dir)
	if _, _, _, err := store.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := integration.Set(store, integration.CloudflareName, map[string]string{"token": "fixture-original-token", "api": server.URL}); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := withStdin(t, "token=  fixture-replacement-token  \n", dir, "integration", "set", "cloudflare"); code != 0 {
		t.Fatalf("partial update failed: exit %d, stderr %q", code, stderr)
	}
	if requests.Load() != 1 || authorization.Load() != "Bearer fixture-replacement-token" {
		t.Fatalf("verification did not use the effective update: requests %d, authorization %v", requests.Load(), authorization.Load())
	}
	if _, stderr, code := withStdin(t, "token=\n", dir, "integration", "set", "cloudflare"); code != 1 || !strings.Contains(stderr, "needs token") {
		t.Fatalf("empty token: exit %d, stderr %q", code, stderr)
	}
	if requests.Load() != 1 {
		t.Fatal("explicit empty token triggered verification with a different token")
	}
	kept, err := integration.Get(store, integration.CloudflareName)
	if err != nil || kept["token"] != "fixture-replacement-token" || kept["api"] != server.URL {
		t.Fatalf("rejected update changed current fields: %v", err)
	}
}
