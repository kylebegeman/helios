package cli

import (
	"encoding/json"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/secrets"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withStdin runs helios with stdin replaced by text, for commands that
// read values without echo.
func withStdin(t *testing.T, text string, stateDir string, args ...string) (string, string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	go func() {
		_, _ = w.WriteString(text)
		w.Close()
	}()
	return run(t, stateDir, args...)
}

func TestIntegrationsAreSetFromStdinAndListedWithoutValues(t *testing.T) {
	stateDir := t.TempDir()
	out, errOut, code := withStdin(t, "smtp_host=127.0.0.1\nsmtp_port=1025\nfrom=bedrock@lane\nto=kyle@lane\n", stateDir, "integration", "set", "email")
	if code != 0 || !strings.Contains(out, "email set") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	if !strings.Contains(errOut, "recovery identity is shown once") {
		t.Fatalf("the first secret should make the machine's key: %q", errOut)
	}
	out, errOut, code = withStdin(t, "kind=s3\nendpoint=http://127.0.0.1:9000\nkey_id=lane\nkey=hush\nbucket_prefix=lane\n", stateDir, "integration", "set", "storage")
	if code != 0 || !strings.Contains(out, "storage set") || !strings.Contains(errOut, "helios made a password for storage") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	out, _, code = run(t, stateDir, "integration", "list")
	if code != 0 {
		t.Fatalf("list: %q", out)
	}
	for _, want := range []string{"storage", "kind=s3", "key=(set)", "password=(set)", "smtp_host=127.0.0.1", "cloudflare", "  no  "} {
		if !strings.Contains(out, want) {
			t.Fatalf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hush") {
		t.Fatal("a secret value was listed")
	}
	// Setting it again changes only what is named: the s3 endpoint stays,
	// which b2 then refuses.
	_, errOut, code = withStdin(t, "kind=b2\n", stateDir, "integration", "set", "storage")
	if code != 1 || !strings.Contains(errOut, "endpoint is for s3 only") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	out, _, code = run(t, stateDir, "integration", "remove", "email")
	if code != 0 || !strings.Contains(out, "email removed") {
		t.Fatalf("remove: %q", out)
	}
	_, errOut, code = run(t, stateDir, "alerts", "test")
	if code != 1 || !strings.Contains(errOut, "no way to send alerts is set up") {
		t.Fatalf("a test alert without email: code %d, err %q", code, errOut)
	}
}

func TestWatchesAreKept(t *testing.T) {
	stateDir := t.TempDir()
	_, errOut, code := run(t, stateDir, "watch", "add", "core.begam.in")
	if code != 1 || !strings.Contains(errOut, "must start with https://") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	out, _, code := run(t, stateDir, "watch", "add", "https://core.begam.in/healthz")
	if code != 0 || !strings.Contains(out, "watching https://core.begam.in/healthz") {
		t.Fatalf("code %d, out %q", code, out)
	}
	out, _, _ = run(t, stateDir, "watch")
	if !strings.Contains(out, "https://core.begam.in/healthz (since ") {
		t.Fatalf("list: %q", out)
	}
	out, _, code = run(t, stateDir, "watch", "remove", "https://core.begam.in/healthz")
	if code != 0 || !strings.Contains(out, "no longer watching") {
		t.Fatalf("code %d, out %q", code, out)
	}
	_, errOut, code = run(t, stateDir, "watch", "remove", "https://core.begam.in/healthz")
	if code != 1 || !strings.Contains(errOut, "wasn't being watched") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
}

func TestEmptyMachineReadsAsEmpty(t *testing.T) {
	stateDir := t.TempDir()
	out, _, code := run(t, stateDir, "backups")
	if code != 0 || !strings.Contains(out, "no backups yet") {
		t.Fatalf("backups: %d %q", code, out)
	}
	out, _, code = run(t, stateDir, "alerts")
	if code != 0 || !strings.Contains(out, "nothing wrong right now") {
		t.Fatalf("alerts: %d %q", code, out)
	}
	out, _, code = run(t, stateDir, "--json", "alerts")
	if code != 0 || strings.TrimSpace(out) != "null" {
		t.Fatalf("alerts json: %d %q", code, out)
	}
	_, errOut, code := run(t, stateDir, "backup", "hello", "--yes")
	if code != 1 || !strings.Contains(errOut, "storage integration") {
		t.Fatalf("backup without storage: %d %q", code, errOut)
	}
	_, errOut, code = run(t, stateDir, "drill", "hello", "--yes")
	if code != 1 || !strings.Contains(errOut, "isn't deployed") {
		t.Fatalf("drill of an unknown app: %d %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.db")); err != nil {
		t.Fatal("the state store wasn't made")
	}
	var rows []json.RawMessage
	out, _, _ = run(t, stateDir, "--json", "backups")
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 0 {
		t.Fatalf("backups json: %v %q", err, out)
	}
}

func TestIntegrationSetAgainKeepsTheStoragePassword(t *testing.T) {
	stateDir := t.TempDir()
	if _, errOut, code := withStdin(t, "kind=s3\nendpoint=http://127.0.0.1:9000\nkey_id=lane\nkey=hush\nbucket_prefix=lane\n", stateDir, "integration", "set", "storage"); code != 0 {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	first, err := integration.LoadStorage(secrets.DefaultStore(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	_, errOut, code := withStdin(t, "key=hush2\n", stateDir, "integration", "set", "storage")
	if code != 0 || strings.Contains(errOut, "helios made a password") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	again, err := integration.LoadStorage(secrets.DefaultStore(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if again.Key != "hush2" || again.Password != first.Password || again.Endpoint != first.Endpoint {
		t.Fatalf("after setting the key again: %+v, was %+v", again, first)
	}
}
