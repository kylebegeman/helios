package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSystemd collects notify datagrams the way systemd would.
type fakeSystemd struct {
	conn *net.UnixConn
	mu   sync.Mutex
	got  []string
}

func newFakeSystemd(t *testing.T) *fakeSystemd {
	t.Helper()
	// Unix socket paths are limited to about 100 bytes, and t.TempDir() is
	// longer than that on macOS.
	dir, err := os.MkdirTemp("/tmp", "bedrock-notify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSystemd{conn: conn}
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			f.mu.Lock()
			f.got = append(f.got, string(buf[:n]))
			f.mu.Unlock()
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return f
}

func (f *fakeSystemd) path() string { return f.conn.LocalAddr().String() }

func (f *fakeSystemd) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

func TestNotifierFeedsTheWatchdogWhileHealthy(t *testing.T) {
	sd := newFakeSystemd(t)
	n := newNotifier(sd.path(), "100000") // 100 ms watchdog: ping every 50 ms
	n.ready()
	ctx, cancel := context.WithCancel(context.Background())
	healthy := true
	var mu sync.Mutex
	done := n.watchdog(ctx, func() bool { mu.Lock(); defer mu.Unlock(); return healthy })
	time.Sleep(230 * time.Millisecond)
	mu.Lock()
	healthy = false
	mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	n.stopping()
	time.Sleep(20 * time.Millisecond)
	msgs := sd.messages()
	if len(msgs) < 3 || msgs[0] != "READY=1" || msgs[len(msgs)-1] != "STOPPING=1" {
		t.Fatalf("messages: %v", msgs)
	}
	pings := 0
	for _, m := range msgs {
		if m == "WATCHDOG=1" {
			pings++
		}
	}
	if pings < 3 || pings > 5 {
		t.Fatalf("want 3 to 5 watchdog pings (4 while healthy), got %d: %v", pings, msgs)
	}
}

func TestNotifierIsSilentWithoutSystemd(t *testing.T) {
	n := newNotifier("", "")
	n.ready()
	done := n.watchdog(context.Background(), func() bool { return true })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("no watchdog loop should run without a socket")
	}
	if n.interval != 0 {
		t.Fatal("no interval without WATCHDOG_USEC")
	}
}

func TestAbstractSocketNamesAreTranslated(t *testing.T) {
	n := newNotifier("@systemd/notify", "")
	// Sending must not panic or block; there is no listener.
	n.send("READY=1")
	if !strings.HasPrefix(n.socket, "@") {
		t.Fatal("socket name kept as given")
	}
}

func TestStartupExtensionsRequireHealthAndStopWithRecovery(t *testing.T) {
	sd := newFakeSystemd(t)
	// Startup extensions must work without a runtime watchdog configured.
	n := newNotifier(sd.path(), "")
	checks := make(chan chan bool)
	stop := n.startup(t.Context(), 5*time.Millisecond, func(ctx context.Context) bool {
		result := make(chan bool)
		select {
		case checks <- result:
		case <-ctx.Done():
			return false
		}
		select {
		case healthy := <-result:
			return healthy
		case <-ctx.Done():
			return false
		}
	})
	defer stop()
	nextCheck := func() chan bool {
		t.Helper()
		select {
		case result := <-checks:
			return result
		case <-time.After(time.Second):
			t.Fatal("startup health was not checked")
			return nil
		}
	}
	nextCheck() <- true
	messages := awaitNotification(t, sd, 0, "EXTEND_TIMEOUT_USEC=", time.Second)
	if len(messages) != 1 || messages[0] != "EXTEND_TIMEOUT_USEC=30000000" {
		t.Fatalf("startup extension: %v", messages)
	}
	nextCheck() <- false
	_ = nextCheck() // the unhealthy check completed, with the next blocked
	if messages := sd.messages(); len(messages) != 1 {
		t.Fatalf("unhealthy recovery extended its deadline: %v", messages)
	}
	// Stopping cancels and joins an in-progress health query. A later READY
	// or STOPPING cannot race a startup extension from this loop.
	stop()
	n.ready()
	n.stopping()
	messages = awaitNotification(t, sd, 1, "STOPPING=1", time.Second)
	if len(messages) != 3 || messages[1] != "READY=1" || messages[2] != "STOPPING=1" {
		t.Fatalf("notifications after recovery stopped: %v", messages)
	}
}

func TestCanceledStartupHealthCannotExtendTheDeadline(t *testing.T) {
	sd := newFakeSystemd(t)
	checking := make(chan struct{})
	stop := newNotifier(sd.path(), "").startup(t.Context(), time.Millisecond, func(ctx context.Context) bool {
		close(checking)
		<-ctx.Done()
		return true // even a stale successful health check cannot renew now
	})
	defer stop()
	select {
	case <-checking:
	case <-time.After(time.Second):
		t.Fatal("startup health was not checked")
	}
	stop()
	n := newNotifier(sd.path(), "")
	n.stopping()
	messages := awaitNotification(t, sd, 0, "STOPPING=1", time.Second)
	if len(messages) != 1 {
		t.Fatalf("canceled recovery extended its deadline: %v", messages)
	}
}

func TestStartupWithoutSystemdDoesNotCheckHealth(t *testing.T) {
	stop := newNotifier("", "").startup(t.Context(), time.Millisecond, func(context.Context) bool {
		t.Error("no startup notification loop should run without systemd")
		return true
	})
	stop()
}

func TestStartupExtendsBeforeTheFirstRenewalInterval(t *testing.T) {
	sd := newFakeSystemd(t)
	stop := newNotifier(sd.path(), "").startup(t.Context(), time.Hour, func(context.Context) bool { return true })
	defer stop()
	awaitNotification(t, sd, 0, "EXTEND_TIMEOUT_USEC=", time.Second)
}
