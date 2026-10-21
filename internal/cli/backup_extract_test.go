package cli

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackupExtractRequiresDirectHostAndExplicitEmptySocket(t *testing.T) {
	for _, flags := range [][]string{nil, {"--socket", "/unused.sock"}, {"--socket=", "--target", "unconfigured"}} {
		var out, errOut bytes.Buffer
		args := append(append([]string(nil), flags...), "backup", "extract", "loom-vault-backup", "--plan")
		if Main(args, &out, &errOut) == 0 {
			t.Fatal("unsafe dispatch accepted")
		}
		if !strings.Contains(errOut.String(), "backup extract") || strings.Contains(errOut.String(), "unconfigured target") {
			t.Fatalf("dispatch was not rejected locally: %s", errOut.String())
		}
	}
}

func TestBackupExtractEmptySocketUsesLocalRegistryWithoutDaemonContact(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("", "hx-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "d")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var contacted atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			contacted.Store(true)
			c.Close()
		}
	}()
	t.Setenv("BEDROCK_SOCKET", socket)
	t.Setenv("HELIOS_SOCKET", socket)
	var out, errOut bytes.Buffer
	destination := filepath.Join(parent, "retrieved")
	args := []string{"--socket=", "--state-dir", filepath.Join(parent, "state"), "backup", "extract", "loom-vault-backup",
		"--snapshot", strings.Repeat("a", 64), "--path", "/data/volumes/snapshots/generations/g-" + strings.Repeat("c", 32) + "/snapshot.snap",
		"--destination", destination, "--plan"}
	if Main(args, &out, &errOut) != 0 {
		t.Fatalf("operator local plan failed: %s", errOut.String())
	}
	if !strings.Contains(out.String(), "app.backup.extract") || !strings.Contains(out.String(), "plan digest") {
		t.Fatalf("local registry missing: %s", out.String())
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("plan created destination")
	}
	listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("test listener failed to stop")
	}
	if contacted.Load() {
		t.Fatal("new operator contacted old daemon")
	}
}
