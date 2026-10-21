package daemon_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/cli"
	"github.com/kylebegeman/helios/internal/daemon"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/peer"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// loopback is where everything in this test listens.
var loopback = netip.MustParsePrefix("127.0.0.0/8").Addr().Next()

// The sentinel is where web2 answers on the mesh: a name no resolver in
// this test resolves, on a port nothing here uses, so a trace of either
// in what the daemon says is a leak.
const (
	sentinelHost = "web2-sentinel.mesh.example.test"
	sentinelPort = 47913
)

// The daemon runs as web1, set up through the CLI to listen on loopback
// and to watch web2 at a sentinel mesh name, with a Mac registered to
// read it. No name resolves, so every path to web2 fails without a
// packet leaving, and web1's own public URL fails too; the Mac's view
// keeps web1 from counting itself cut off. web2 never answers over many
// rounds, so web1 opens an incident about it and pages it through ntfy.
// Neither the sentinel nor where web1 listens, nor either key, is in
// anything the daemon says or keeps in the open: its log, its incidents,
// the page, helios alerts --json, its summary or its sidecar.
func TestNoMeshAddressLeaves(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "")
	t.Setenv("WATCHDOG_PID", "")
	noDNS(t)
	ntfy := &fakeNtfy{}
	ntfyServer := httptest.NewServer(ntfy)
	defer ntfyServer.Close()
	listen := unusedPort(t)

	dir := t.TempDir()
	helios(t, dir, "peer", "init", "--name", "web1", "--listen", listen.String(), "--public", "https://web1.example.test")
	helios(t, dir, "peer", "add", "web2", "--mesh", net.JoinHostPort(sentinelHost, strconv.Itoa(sentinelPort)), "--public", "https://web2.example.test")
	macKey, err := peer.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	helios(t, dir, "peer", "add", "mac", "--key", peer.Fingerprint(macKey))
	sec := secrets.DefaultStore(dir)
	if _, _, err := integration.Set(sec, integration.NtfyName, map[string]string{"topic_url": ntfyServer.URL + "/peer-leak"}); err != nil {
		t.Fatal(err)
	}
	set, err := peer.Load(sec)
	if err != nil {
		t.Fatal(err)
	}

	socketDir, err := os.MkdirTemp("/tmp", "bedrock-peer-leak-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	var log lockedLog
	stop := runDaemon(t, daemon.Config{StateDir: dir, Socket: filepath.Join(socketDir, "api.sock"), Owner: "peer-leak", WatchInterval: 100 * time.Millisecond}, &log)
	defer stop()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	view := `{"self_check":true,"sends":false,"views":[{"subject":"web2","summary":"refused","tls":"refused","public":"refused"}]}`
	waitFor(t, &log, "the listener to take the Mac's view", func() (bool, string) {
		code, answer, err := ask(client, http.MethodPost, listen, peer.ViewPath, macKey, view)
		return err == nil && code == http.StatusNoContent, string(answer)
	})
	waitFor(t, &log, "web1 to page web2 after five rounds", func() (bool, string) {
		alerts := helios(t, dir, "--json", "alerts")
		var incidents []state.Incident
		if json.Unmarshal([]byte(alerts), &incidents) != nil {
			return false, alerts
		}
		for _, inc := range incidents {
			if inc.Key == "peer:web2" && inc.Open() && inc.Observations >= 5 && !inc.NotifiedAt.IsZero() {
				return ntfy.pages() != "", alerts
			}
		}
		return false, alerts
	})
	code, summary, err := ask(client, http.MethodGet, listen, peer.SummaryPath, macKey, "")
	if err != nil || code != http.StatusOK {
		t.Fatalf("the summary: %d %v", code, err)
	}
	stop()

	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	incidents, err := store.IncidentHistory(context.Background(), 1000)
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := json.Marshal(incidents)
	sidecar, err := os.ReadFile(filepath.Join(dir, peer.SidecarFile))
	if err != nil {
		t.Fatalf("no sidecar: %v", err)
	}
	said := map[string][]byte{
		"the daemon's log":     []byte(log.String()),
		"the incidents":        rows,
		"the page":             []byte(ntfy.pages()),
		"helios alerts --json": []byte(helios(t, dir, "--json", "alerts")),
		"web1's summary":       summary,
		peer.SidecarFile:       sidecar,
	}
	never := map[string]*regexp.Regexp{
		"the sentinel":       regexp.MustCompile(`sentinel`),
		"its port":           portIn(sentinelPort),
		"where web1 listens": regexp.MustCompile(regexp.QuoteMeta(listen.String())),
		"web1's port":        portIn(int(listen.Port())),
		"web1's key":         regexp.MustCompile(regexp.QuoteMeta(set.Token)),
		"the Mac's key":      regexp.MustCompile(regexp.QuoteMeta(macKey)),
		"a key":              regexp.MustCompile(`hp1_`),
	}
	for where, text := range said {
		for what, pattern := range never {
			if pattern.Match(text) {
				t.Errorf("found %s in %s: %s", what, where, text)
			}
		}
	}
}

// portIn matches port as a number on its own.
func portIn(port int) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^0-9])` + strconv.Itoa(port) + `([^0-9]|$)`)
}

// helios runs the CLI against the state in dir and returns what it
// printed, failing the test when it fails.
func helios(t *testing.T, dir string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := cli.Main(append([]string{"--state-dir", dir, "--socket", filepath.Join(dir, "no.sock")}, args...), &out, &errOut); code != 0 {
		t.Fatalf("helios %s: code %d, err %q", strings.Join(args, " "), code, errOut.String())
	}
	return out.String()
}

// noDNS has every name fail to resolve until the test ends, through
// the system's resolver and the public one the daemon's checks use, so
// nothing the daemon looks up leaves this machine.
func noDNS(t *testing.T) {
	fail := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no DNS in this test")
	}}
	system, public := net.DefaultResolver, edge.PublicResolver
	net.DefaultResolver, edge.PublicResolver = fail, fail
	t.Cleanup(func() { net.DefaultResolver, edge.PublicResolver = system, public })
}

// unusedPort is an address on loopback nothing listens at.
func unusedPort(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.Listen("tcp", netip.AddrPortFrom(loopback, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return netip.MustParseAddrPort(l.Addr().String())
}

// ask sends a request with key to the peer listener at addr and returns
// the answer's status and body.
func ask(client *http.Client, method string, addr netip.AddrPort, path, key, body string) (int, []byte, error) {
	req, err := http.NewRequest(method, "http://"+addr.String()+path, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	return resp.StatusCode, answer, err
}

// waitFor waits up to 20 seconds for done, and fails the test with
// what done last saw and the daemon's log if it never is.
func waitFor(t *testing.T, log *lockedLog, what string, done func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		ok, saw := done()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited too long for %s; saw %s\nlog:\n%s", what, saw, log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// runDaemon runs the daemon with cfg, logging to log, until the stop it
// returns, which waits for the daemon to finish and is safe to call
// again.
func runDaemon(t *testing.T, cfg daemon.Config, log io.Writer) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg, log) }()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("daemon: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("daemon didn't stop")
			}
		})
	}
}

// fakeNtfy is an ntfy server that keeps every page it is sent.
type fakeNtfy struct {
	mu   sync.Mutex
	sent []string
}

func (f *fakeNtfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.sent = append(f.sent, string(body))
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{}")
}

// pages is every page sent so far, one to a line.
func (f *fakeNtfy) pages() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.sent, "\n")
}

// lockedLog is the daemon's log, which the test reads while the daemon
// writes it.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
