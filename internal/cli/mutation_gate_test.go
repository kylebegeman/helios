package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

func TestDirectSecretAndIntegrationWritesRespectRecoveryReservation(t *testing.T) {
	dir := t.TempDir()
	locks := filepath.Join(dir, "locks")
	if err := os.MkdirAll(locks, 0o700); err != nil {
		t.Fatal(err)
	}
	gate, _ := json.Marshal(map[string]string{"id": "recover-fixture", "source": "old-host", "snapshot": strings.Repeat("a", 64)})
	if err := os.WriteFile(filepath.Join(locks, "machine-recovery.json"), gate, 0o600); err != nil {
		t.Fatal(err)
	}
	mutations := [][]string{
		{"secret", "set", "demo", "TOKEN"}, {"secret", "remove", "demo", "TOKEN"},
		{"secret", "import", "demo", "TOKEN"}, {"secret", "copy", "demo", "TOKEN", "other"},
		{"integration", "set", "email"}, {"integration", "remove", "email"},
		{"integration", "import", "email"}, {"move", "secrets", "demo", "--accept"},
		{"git", "webhook", "demo", "--off"},
		{"peer", "init", "--name", "web1"}, {"peer", "key", "--rotate"},
		{"peer", "add", "web2", "--key", peerKey("a")}, {"peer", "rm", "web2"},
	}
	for _, args := range mutations {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, stderr bytes.Buffer
			full := append([]string{"--state-dir", dir, "--socket", filepath.Join(dir, "absent.sock")}, args...)
			if code := Main(full, &out, &stderr); code == 0 || !strings.Contains(stderr.String(), "reserved by recovery") {
				t.Fatalf("mutation bypassed reservation: code %d", code)
			}
		})
	}
	store := secrets.DefaultStore(dir)
	if _, err := os.Stat(store.KeyPath); !os.IsNotExist(err) {
		t.Fatal("refused mutation created an encryption key")
	}
	if _, err := os.Stat(store.Dir); !os.IsNotExist(err) {
		t.Fatal("refused mutation created secret history")
	}
	var out, stderr bytes.Buffer
	if code := Main([]string{"--state-dir", dir, "secret", "list", "demo", "--json"}, &out, &stderr); code != 0 {
		t.Fatal("reservation must retain read-only secret inspection")
	}
}

func TestIntegrationWritesRespectAnyPendingReleaseRestore(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	snapshot := strings.Repeat("a", 64)
	if err := store.BeginReleaseBoundary(ctx, state.ReleaseBoundary{App: "demo", Revision: "candidate", Compatibility: "restore-required", Snapshot: snapshot, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginReleaseRestore(ctx, "demo", "candidate", snapshot); err != nil {
		t.Fatal(err)
	}
	store.Close()
	for _, args := range [][]string{{"integration", "set", "email"}, {"integration", "remove", "email"}, {"integration", "import", "email"}, {"secret", "remove", "demo", "TOKEN"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, stderr bytes.Buffer
			full := append([]string{"--state-dir", dir}, args...)
			if code := Main(full, &out, &stderr); code == 0 || !strings.Contains(stderr.String(), "fenced while checkpoint") {
				t.Fatalf("mutation bypassed release fence: code %d", code)
			}
		})
	}
	var out, stderr bytes.Buffer
	if code := Main([]string{"--state-dir", dir, "integration", "list", "--json"}, &out, &stderr); code != 0 {
		t.Fatalf("read-only integrations refused: code %d", code)
	}
	if _, err := os.Stat(secrets.DefaultStore(dir).KeyPath); !os.IsNotExist(err) {
		t.Fatal("refused integration write created a key")
	}
}
