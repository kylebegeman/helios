package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/peer"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// loopback is where the tests' peer listeners listen.
var loopback = netip.MustParsePrefix("127.0.0.0/8").Addr().Next()

// web1 is a daemon set up as web1, built directly on temp stores: its
// fan-out delivers every notice to a fake, and its peer watch runs on a
// clock the test moves. A Mac holds the key in macKey. lookAtPeers,
// when set, takes the place of peer watch's look at the peers.
type web1 struct {
	*daemon
	fanout      *fanout
	macKey      string
	clock       time.Time
	lookAtPeers func(context.Context) []watch.Condition

	mu   sync.Mutex
	logs []string
}

func web1Daemon(t *testing.T) *web1 {
	t.Helper()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sec := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "secrets.key")}
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	macKey, err := peer.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	w := &web1{fanout: &fanout{}, macKey: macKey, clock: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
	w.daemon = &daemon{store: store, sec: sec, machine: "web1", alerts: w.fanout, logf: w.log,
		peers: &peer.Source{Secrets: sec, Store: store, Log: w.log, Now: w.now}}
	return w
}

func (w *web1) now() time.Time { return w.clock }

func (w *web1) log(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs = append(w.logs, fmt.Sprintf(format, args...))
}

// logged is every line web1 logged, and how many of them begin with
// prefix.
func (w *web1) logged(prefix string) (string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, line := range w.logs {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return strings.Join(w.logs, "\n"), n
}

// setUp sets up web1's peer watch, the Mac allowed to read it, with
// change made to its configuration.
func (w *web1) setUp(t *testing.T, change func(c *peer.Config)) {
	t.Helper()
	if _, _, err := peer.Update(w.sec, true, func(c *peer.Config) (err error) {
		if c.Token == "" {
			c.Token, err = peer.NewToken()
		}
		c.Self.Name = "web1"
		c.Observers = map[string]string{"mac": peer.Fingerprint(w.macKey)}
		change(c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// listenAt sets web1 up to listen for its peers at addr.
func (w *web1) listenAt(t *testing.T, addr netip.AddrPort) {
	t.Helper()
	w.setUp(t, func(c *peer.Config) {
		c.Self.Listen, c.Self.Public = addr.String(), []string{"https://web1.example.test"}
	})
}

// sidecar is what web1's peer watch saved, nil when it saved nothing.
func (w *web1) sidecar(t *testing.T) *peer.Sidecar {
	t.Helper()
	if _, err := os.Stat(filepath.Join(filepath.Dir(w.store.Path()), peer.SidecarFile)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	sc, err := peer.ReadSidecar(w.store)
	if err != nil {
		t.Fatal(err)
	}
	return &sc
}

// fanout is a machine's alert fan-out that delivers every notice.
type fanout struct {
	mu   sync.Mutex
	sent []watch.Notice
}

func (f *fanout) Notify(_ context.Context, n watch.Notice) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, n)
	return nil
}

// told is each notice delivered about key, as transition@host.
func (f *fanout) told(key string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var told []string
	for _, n := range f.sent {
		if n.Key == key {
			told = append(told, n.Transition+"@"+n.Host)
		}
	}
	return told
}

// freePort is a loopback address nothing listens on.
func freePort(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.Listen("tcp", netip.AddrPortFrom(loopback, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return netip.MustParseAddrPort(l.Addr().String())
}

// offMesh is an address on the mesh that isn't on this machine, as
// before the mesh comes up; ok is false when every one tried is here.
func offMesh() (addr netip.Addr, ok bool) {
	addr = netip.MustParsePrefix("100.64.0.0/10").Addr()
	for range 16 {
		addr = addr.Next()
		probe, err := net.Listen("tcp", netip.AddrPortFrom(addr, 0).String())
		if err == nil {
			probe.Close()
			continue
		}
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// listening is where l's server listens, invalid when it doesn't.
func listening(l *peerListener) netip.AddrPort {
	if addr := l.Server.Addr(); addr != nil {
		return netip.MustParseAddrPort(addr.String())
	}
	return netip.AddrPort{}
}

// refuses reports whether nothing answers at addr.
func refuses(addr netip.AddrPort) bool {
	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err == nil {
		conn.Close()
	}
	return err != nil
}

// ask sends a request with key to the peer listener at addr and returns
// the answer's status and Helios-Peer header, the body decoded into into
// when it is set.
func ask(t *testing.T, client *http.Client, method string, addr netip.AddrPort, path, key, body string, into any) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr.String()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if into != nil {
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, resp.Header.Get(peer.Header)
}

// The daemon's peer listener follows peer watch's configuration from one
// tick to the next: none until an address is set, then listening there
// with this machine's summary for a registered key and its peer watch
// taking what the Mac pushes; moved when the address changes; kept as it
// is while the configuration can't be read; waiting, said once, while
// the mesh address isn't up; closed when the address or the whole
// configuration is removed; and closed when the daemon stops, however a
// peer left its connection, before the daemon's loops are done. Nothing
// it logs names the address or the port.
func TestListenerFollowsConfig(t *testing.T) {
	w := web1Daemon(t)
	ctx := context.Background()
	l := w.newPeerListener()
	defer l.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	ports := []netip.AddrPort{}
	port := func() netip.AddrPort {
		ap := freePort(t)
		ports = append(ports, ap)
		return ap
	}

	l.Tick(ctx)
	if got := listening(l); got.IsValid() {
		t.Fatal("listening before peer watch was set up")
	}

	first := port()
	w.listenAt(t, first)
	l.Tick(ctx)
	if got := listening(l); got != first {
		t.Fatalf("listening at %v, set up at %v", got, first)
	}
	var summary peer.Summary
	if code, header := ask(t, client, http.MethodGet, first, peer.SummaryPath, w.macKey, "", &summary); code != http.StatusOK || header != "1" || summary.Name != "web1" {
		t.Fatalf("summary: %d, %s header %q, %+v", code, peer.Header, header, summary)
	}
	if code, _ := ask(t, client, http.MethodPost, first, peer.ViewPath, w.macKey, `{"self_check":true,"views":[]}`, nil); code != http.StatusNoContent {
		t.Fatalf("the Mac's push: %d", code)
	}
	if err := w.peers.Save(); err != nil {
		t.Fatal(err)
	}
	if sc := w.sidecar(t); sc == nil || sc.LastView["mac"].IsZero() {
		t.Fatalf("the Mac's push never reached peer watch: %+v", sc)
	}

	// A configuration that can't be read leaves the listener as it is.
	sealed, _, err := w.sec.LoadCurrent(manifest.ReservedApp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.sec.Set(manifest.ReservedApp, peer.ListKey, "{not json"); err != nil {
		t.Fatal(err)
	}
	l.Tick(ctx)
	l.Tick(ctx)
	if got := listening(l); got != first || refuses(first) {
		t.Fatalf("an unreadable configuration moved the listener to %v", got)
	}
	if _, n := w.logged("peer listener: peer watch can't be read"); n != 1 {
		t.Fatalf("said %d times that peer watch can't be read", n)
	}
	if _, err := w.sec.Set(manifest.ReservedApp, peer.ListKey, sealed[peer.ListKey]); err != nil {
		t.Fatal(err)
	}

	second := port()
	w.listenAt(t, second)
	l.Tick(ctx)
	if got := listening(l); got != second || !refuses(first) {
		t.Fatalf("moved to %v; the old address refuses: %v", got, refuses(first))
	}
	if code, _ := ask(t, client, http.MethodGet, second, peer.SummaryPath, w.macKey, "", nil); code != http.StatusOK {
		t.Fatalf("summary at the new address: %d", code)
	}

	// An address on the mesh that isn't up yet is waited for.
	if addr, ok := offMesh(); !ok {
		t.Log("this machine has every mesh address tried, so waiting for one isn't tried")
	} else {
		mesh := netip.AddrPortFrom(addr, 7700)
		ports = append(ports, mesh)
		w.listenAt(t, mesh)
		l.Tick(ctx)
		l.Tick(ctx)
		if got := listening(l); got.IsValid() || !refuses(second) {
			t.Fatalf("listening at %v while waiting for the mesh address", got)
		}
		if _, n := w.logged("peer listener: waiting for the mesh address"); n != 1 {
			t.Fatalf("said %d times that it waits for the mesh address", n)
		}
	}

	w.listenAt(t, second)
	l.Tick(ctx)
	if got := listening(l); got != second {
		t.Fatalf("listening at %v once the address came back", got)
	}
	w.setUp(t, func(c *peer.Config) { c.Self.Listen = "" })
	l.Tick(ctx)
	if got := listening(l); got.IsValid() || !refuses(second) {
		t.Fatalf("listening at %v once the address was removed", got)
	}
	w.listenAt(t, second)
	l.Tick(ctx)
	if _, err := w.sec.Remove(manifest.ReservedApp, peer.ListKey); err != nil {
		t.Fatal(err)
	}
	l.Tick(ctx)
	if got := listening(l); got.IsValid() || !refuses(second) {
		t.Fatalf("listening at %v once peer watch was removed", got)
	}

	// The daemon's loop listens from its first tick and closes the
	// listener when the daemon stops. A peer that never finishes its
	// request holds the close only a while, and the daemon's loops are
	// done once its connection is closed.
	third := port()
	w.listenAt(t, third)
	loopCtx, stop := context.WithCancel(ctx)
	defer stop()
	w.servePeers(loopCtx, l)
	for deadline := time.Now().Add(5 * time.Second); listening(l) != third; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the daemon's loop never listened")
		}
	}
	if code, _ := ask(t, client, http.MethodGet, third, peer.SummaryPath, w.macKey, "", nil); code != http.StatusOK {
		t.Fatalf("summary from the daemon's loop: %d", code)
	}
	stuck, err := net.Dial("tcp", third.String())
	if err != nil {
		t.Fatal(err)
	}
	defer stuck.Close()
	if _, err := io.WriteString(stuck, "GET "+peer.SummaryPath+" HTTP/1.1\r\nHost: web1.example.test\r\n"); err != nil {
		t.Fatal(err)
	}
	stop()
	stopped := make(chan struct{})
	go func() { w.loops.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(7 * time.Second):
		t.Fatal("the peer listener held up the daemon's stop")
	}
	stuck.SetReadDeadline(time.Now().Add(time.Second))
	var timeout net.Error
	if _, err := io.Copy(io.Discard, stuck); errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("the daemon's loops were done with a peer's connection still open")
	}
	if !refuses(third) {
		t.Fatal("the peer listener still answers after the daemon stopped")
	}

	logs, _ := w.logged("")
	for _, ap := range ports {
		if strings.Contains(logs, ap.Addr().String()) || strings.Contains(logs, strconv.Itoa(int(ap.Port()))) {
			t.Fatalf("a log line names the listen address:\n%s", logs)
		}
	}
}

// shopDown is the condition web1's own look finds while its shop app is
// down.
var shopDown = watch.Condition{Key: "app:shop", Subject: "shop", Severity: state.SeverityCritical, Message: "https://shop.example.test answered 502"}

// rounds runs n rounds of web1's watch, a minute apart, its own look
// finding the shop down while down is set.
func (w *web1) rounds(t *testing.T, watcher *watch.Watcher, n int, down bool) {
	t.Helper()
	lookAtPeers := w.peers.Observe
	if w.lookAtPeers != nil {
		lookAtPeers = w.lookAtPeers
	}
	for range n {
		w.clock = w.clock.Add(time.Minute)
		w.watchRound(context.Background(), watcher, func(context.Context) []watch.Condition {
			if down {
				return []watch.Condition{shopDown}
			}
			return nil
		}, lookAtPeers)
	}
}

// open is web1's open incident about key, nil when there is none.
func (w *web1) open(t *testing.T, key string) *state.Incident {
	t.Helper()
	inc, err := w.store.OpenIncidentByKey(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return inc
}

// macSilent sets web1's peer watch up with the Mac reading it, has the
// Mac push once, and lets it fall silent.
func (w *web1) macSilent(t *testing.T) {
	t.Helper()
	w.setUp(t, func(*peer.Config) {})
	w.peers.Receive("mac", peer.Push{SelfCheck: true}, w.clock)
	w.clock = w.clock.Add(peer.ObserverSilent)
}

// What peer watch finds goes into the watcher's one round beside what
// this machine finds about itself, so neither resolves the other's
// incidents: the shop's incident recovers while the Mac stays silent and
// opens again, and the Mac's recovers while the shop stays down. Every
// notice passes the peer gate, so the Mac's carry its name as their host
// and the shop's carry this machine's. A machine that never set up peer
// watch gets no sidecar; once it has, each round is recorded for its
// summary and saved.
func TestPeerConditionsJoinTheOneRound(t *testing.T) {
	w := web1Daemon(t)
	watcher := w.newWatcher()
	watcher.Now = w.now

	w.rounds(t, watcher, 1, false)
	if sc := w.sidecar(t); sc != nil {
		t.Fatalf("a round before peer watch was set up saved %+v", sc)
	}

	w.macSilent(t)
	w.rounds(t, watcher, watch.DefaultOpenAfter, true)
	shop, mac := w.open(t, "app:shop"), w.open(t, "peer:mac")
	if shop == nil || mac == nil {
		t.Fatalf("open: shop %v, mac %v", shop, mac)
	}
	w.rounds(t, watcher, watch.DefaultResolveAfter, false)
	if inc := w.open(t, "app:shop"); inc != nil {
		t.Fatalf("the shop came back and its incident is still open: %+v", inc)
	}
	if inc := w.open(t, "peer:mac"); inc == nil || inc.ID != mac.ID {
		t.Fatalf("the shop's recovery resolved the Mac's incident: %+v", inc)
	}
	w.rounds(t, watcher, watch.DefaultOpenAfter, true)
	shop = w.open(t, "app:shop")
	if inc := w.open(t, "peer:mac"); shop == nil || inc == nil || inc.ID != mac.ID {
		t.Fatalf("open: shop %v, mac %v", shop, inc)
	}

	w.peers.Receive("mac", peer.Push{SelfCheck: true}, w.clock)
	w.rounds(t, watcher, watch.DefaultResolveAfter, true)
	if inc := w.open(t, "peer:mac"); inc != nil {
		t.Fatalf("the Mac came back and its incident is still open: %+v", inc)
	}
	if inc := w.open(t, "app:shop"); inc == nil || inc.ID != shop.ID {
		t.Fatalf("the Mac's recovery resolved the shop's incident: %+v", inc)
	}

	open, resolved := watch.TransitionOpen, watch.TransitionResolved
	if got, want := w.fanout.told("app:shop"), []string{open + "@web1", resolved + "@web1", open + "@web1"}; !slices.Equal(got, want) {
		t.Fatalf("told about the shop %v, want %v", got, want)
	}
	if got, want := w.fanout.told("peer:mac"), []string{open + "@mac", resolved + "@mac"}; !slices.Equal(got, want) {
		t.Fatalf("told about the Mac %v, want %v", got, want)
	}
	sc := w.sidecar(t)
	if sc == nil || sc.Self != "web1" || !slices.ContainsFunc(sc.Told, func(told peer.Told) bool { return told.Key == "peer:mac" && told.By == "web1" }) {
		t.Fatalf("saved %+v", sc)
	}
	if got := w.peers.Last().Round; !got.Equal(w.clock) {
		t.Fatalf("the last round is recorded at %v, want %v", got, w.clock)
	}
}

// A look at the peers that panics holds their open incidents as they
// are, so no peer recovers on a look never taken, and the round goes on
// for what this machine finds about itself.
func TestAPeerWatchThatPanicsHoldsItsIncidents(t *testing.T) {
	w := web1Daemon(t)
	watcher := w.newWatcher()
	watcher.Now = w.now
	w.macSilent(t)
	w.rounds(t, watcher, watch.DefaultOpenAfter, false)
	mac := w.open(t, "peer:mac")
	if mac == nil {
		t.Fatal("the silent Mac's incident never opened")
	}

	w.lookAtPeers = func(context.Context) []watch.Condition { panic("a defect in peer watch") }
	w.rounds(t, watcher, watch.DefaultOpenAfter, true)
	if inc := w.open(t, "peer:mac"); inc == nil || inc.ID != mac.ID {
		t.Fatalf("a panicking peer watch resolved the Mac's incident: %+v", inc)
	}
	if got := w.fanout.told("peer:mac"); !slices.Equal(got, []string{watch.TransitionOpen + "@mac"}) {
		t.Fatalf("told about the Mac %v", got)
	}
	if w.open(t, "app:shop") == nil {
		t.Fatal("the round stopped with peer watch: the shop's incident never opened")
	}
	if _, n := w.logged("peer watch: panic"); n == 0 {
		t.Fatal("the panic was never logged")
	}
}
