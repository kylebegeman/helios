package watch

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kylebegeman/helios/internal/integration"
)

func TestLoomResponseCodesCannotEchoWebhookCredentials(t *testing.T) {
	const token = "example_hook_token"
	const secret = "example_signing_secret"
	var code atomic.Value
	code.Store("")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": code.Load().(string)})
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	before := loomRoots
	loomRoots = roots
	t.Cleanup(func() { loomRoots = before })
	notifier := &LoomNotifier{LoomWebhook: integration.LoomWebhook{
		URL: server.URL + "/v1/hooks/0123456789abcdef/example/" + token, Secret: secret,
	}}
	for _, echoed := range []string{token, secret, "invalid_" + token, "invalid_" + secret} {
		code.Store(echoed)
		answer := notifier.post(context.Background(), []byte(`{}`), secret)
		if answer.code != "" {
			t.Errorf("a response code containing a credential was retained")
		}
		for _, credential := range []string{token, secret} {
			if strings.Contains(answer.answered(), credential) {
				t.Errorf("a credential escaped through the response description")
			}
		}
	}
	code.Store("invalid_signature")
	if got := notifier.post(context.Background(), []byte(`{}`), secret); got.code != "invalid_signature" {
		t.Fatalf("a public error code was lost: %s", got.code)
	}
}
