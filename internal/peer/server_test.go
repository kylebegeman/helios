package peer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// web1 is a server set up as web1: it watches web2, and web2 and a Mac
// may read it, each with its own key.
type web1 struct {
	secrets *secrets.Store
	store   *state.Store
	// keys holds each reader's token, by name.
	keys  map[string]string
	clock time.Time
}

func setUpWeb1(t *testing.T) *web1 {
	t.Helper()
	w := &web1{secrets: keyedStore(t), store: stateStore(t), keys: map[string]string{}, clock: now}
	for _, name := range []string{"web2", "mac"} {
		token, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		w.keys[name] = token
	}
	if _, _, err := Update(w.secrets, true, func(c *Config) (err error) {
		c.Self = Self{Name: "web1", Public: []string{"https://web1.example.test"}}
		c.Peers = []Peer{{Name: "web2", Mesh: at(in("100.64.0.0/10"), 7700), Public: []string{"https://web2.example.test"}}}
		c.Observers = map[string]string{"web2": Fingerprint(w.keys["web2"]), "mac": Fingerprint(w.keys["mac"])}
		c.Token, err = NewToken()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

func stateStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// server is web1's peer server, on web1's clock.
func (w *web1) server(t *testing.T) *Server {
	return &Server{Deps: Deps{Store: w.store, Secrets: w.secrets, Root: t.TempDir(), Now: func() time.Time { return w.clock }}}
}

// listening starts s on loopback and returns where it answers.
func listening(t *testing.T, s *Server) string {
	t.Helper()
	if err := s.Start(context.Background(), netip.AddrPortFrom(in("127.0.0.0/8"), 0)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return "http://" + s.Addr().String()
}

// call asks a listening server, presenting key when there is one.
func call(t *testing.T, base, method, path, key, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	read, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(read)
}

// asked answers one request through the handler alone, as if from addr.
func asked(s *Server, from, method, path, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = from
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func markedAsPeer(resp *http.Response) bool { return resp.Header.Get(Header) == "1" }

// The listener answers its two routes and nothing else, even to a key
// it accepts: the daemon's API is not there.
func TestPeerListenerServesNoDaemonAPI(t *testing.T) {
	w := setUpWeb1(t)
	base := listening(t, w.server(t))
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/v1/apps", http.StatusNotFound},
		{http.MethodGet, "/v1/status", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodGet, SummaryPath + "/", http.StatusNotFound},
		{http.MethodPost, SummaryPath, http.StatusMethodNotAllowed},
		{http.MethodGet, ViewPath, http.StatusMethodNotAllowed},
		{http.MethodGet, SummaryPath, http.StatusOK},
	} {
		resp, _ := call(t, base, tc.method, tc.path, w.keys["web2"], "")
		if resp.StatusCode != tc.code || !markedAsPeer(resp) {
			t.Fatalf("%s %s answered %d with %q, want %d from Helios", tc.method, tc.path, resp.StatusCode, resp.Header.Get(Header), tc.code)
		}
	}
}

// Only a key registered here reads the summary. A missing key, an
// unknown one and one rotated away are each refused in a way that says
// Helios refused it, and a key registered in its place counts at once.
func TestSummaryNeedsARegisteredKey(t *testing.T) {
	w := setUpWeb1(t)
	base := listening(t, w.server(t))
	unknown, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	refused := func(why, key string) {
		t.Helper()
		resp, _ := call(t, base, http.MethodGet, SummaryPath, key, "")
		if resp.StatusCode != http.StatusUnauthorized || !markedAsPeer(resp) {
			t.Fatalf("%s answered %d with %q, want 401 from Helios", why, resp.StatusCode, resp.Header.Get(Header))
		}
	}
	refused("no key", "")
	refused("an unknown key", unknown)
	refused("a fingerprint presented as the key", Fingerprint(w.keys["web2"]))

	resp, body := call(t, base, http.MethodGet, SummaryPath, w.keys["web2"], "")
	var summary Summary
	if resp.StatusCode != http.StatusOK || !markedAsPeer(resp) || json.Unmarshal([]byte(body), &summary) != nil || summary.Name != "web1" {
		t.Fatalf("the registered key got %d: %s", resp.StatusCode, body)
	}

	rotated, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Update(w.secrets, false, func(c *Config) error {
		c.Observers["web2"] = Fingerprint(rotated)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	refused("a key rotated away", w.keys["web2"])
	if resp, body := call(t, base, http.MethodGet, SummaryPath, rotated, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("the key registered in its place got %d: %s", resp.StatusCode, body)
	}
}

// A push belongs to the machine whose key sent it, whatever the body
// claims, and arrives at this machine's time. Views of a machine web1
// doesn't watch, or of web1 itself, are dropped and the rest kept.
func TestViewIsAttributedToTheKeyOwner(t *testing.T) {
	w := setUpWeb1(t)
	s := w.server(t)
	type got struct {
		observer string
		push     Push
		at       time.Time
	}
	var mu sync.Mutex
	var received []got
	s.Receive = func(observer string, p Push, at time.Time) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, got{observer, p, at})
	}
	base := listening(t, s)
	pushed := func(key, body string) []got {
		t.Helper()
		resp, answer := call(t, base, http.MethodPost, ViewPath, key, body)
		if resp.StatusCode != http.StatusNoContent || !markedAsPeer(resp) {
			t.Fatalf("the push got %d: %s", resp.StatusCode, answer)
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]got(nil), received...)
	}

	w.clock = now.Add(time.Minute)
	arrived := pushed(w.keys["mac"], `{"observer":"web2","self_check":true,"sends":false,"views":[
		{"subject":"web2","summary":"ok","tls":"ok","public":"timeout","age_s":9000},
		{"subject":"web1","summary":"refused","tls":"refused","public":"refused"},
		{"subject":"web9","summary":"ok","tls":"ok","public":"ok"}]}`)
	want := Push{SelfCheck: true, Views: []PushView{{Subject: "web2", Paths: Paths{WordOK, WordOK, "timeout"}}}}
	if len(arrived) != 1 || arrived[0].observer != "mac" || !arrived[0].at.Equal(w.clock) || !samePush(arrived[0].push, want) {
		t.Fatalf("received %+v, want mac's %+v at %s", arrived, want, w.clock)
	}

	arrived = pushed(w.keys["web2"], `{"self_check":false,"views":[{"subject":"web1","summary":"ok"}]}`)
	if len(arrived) != 2 || arrived[1].observer != "web2" || len(arrived[1].push.Views) != 0 {
		t.Fatalf("a push with nothing to keep: %+v", arrived)
	}
}

func samePush(a, b Push) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// Every read is bounded: headers that never finish are cut off, headers
// too large are refused, a ninth request at once is turned away, and a
// push too large or more than one JSON object is refused.
func TestPeerServerIsBounded(t *testing.T) {
	t.Run("slow headers are cut off", func(t *testing.T) {
		w := setUpWeb1(t)
		s := w.server(t)
		if built := s.httpServer(context.Background()); built.ReadHeaderTimeout != 5*time.Second || built.MaxHeaderBytes != MaxHeaderBytes {
			t.Fatalf("the listener waits %s for headers of %d bytes", built.ReadHeaderTimeout, built.MaxHeaderBytes)
		}
		s.HeaderWait = 200 * time.Millisecond
		base := listening(t, s)
		conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "GET "+SummaryPath+" HTTP/1.1\r\nHost: web1.example.test\r\n"); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatalf("a request whose headers never finished was still open: %v", err)
		}
	})

	t.Run("headers over 8 KiB are refused", func(t *testing.T) {
		w := setUpWeb1(t)
		base := listening(t, w.server(t))
		req, err := http.NewRequest(http.MethodGet, base+SummaryPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+w.keys["web2"])
		req.Header.Set("X-Padding", strings.Repeat("a", 2*MaxHeaderBytes))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("16 KiB of headers got %d", resp.StatusCode)
		}
	})

	t.Run("a ninth request at once is turned away", func(t *testing.T) {
		w := setUpWeb1(t)
		s := w.server(t)
		arrived, release := make(chan struct{}), make(chan struct{})
		s.Receive = func(string, Push, time.Time) {
			arrived <- struct{}{}
			<-release
		}
		base := listening(t, s)
		var held sync.WaitGroup
		codes := make(chan int, MaxInFlight)
		for range MaxInFlight {
			held.Add(1)
			go func() {
				defer held.Done()
				req, _ := http.NewRequest(http.MethodPost, base+ViewPath, strings.NewReader(`{"views":[]}`))
				req.Header.Set("Authorization", "Bearer "+w.keys["mac"])
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					codes <- 0
					return
				}
				resp.Body.Close()
				codes <- resp.StatusCode
			}()
		}
		for range MaxInFlight {
			<-arrived
		}
		resp, _ := call(t, base, http.MethodGet, SummaryPath, w.keys["web2"], "")
		close(release)
		held.Wait()
		close(codes)
		if resp.StatusCode != http.StatusServiceUnavailable || !markedAsPeer(resp) {
			t.Fatalf("the ninth request got %d with %q, want 503 from Helios", resp.StatusCode, resp.Header.Get(Header))
		}
		for code := range codes {
			if code != http.StatusNoContent {
				t.Fatalf("a held push got %d", code)
			}
		}
		if resp, _ := call(t, base, http.MethodGet, SummaryPath, w.keys["web2"], ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("once the eight finished, a request got %d", resp.StatusCode)
		}
	})

	t.Run("a push must be one JSON object of at most 64 KiB", func(t *testing.T) {
		w := setUpWeb1(t)
		s := w.server(t)
		var pushes atomic.Int32
		s.Receive = func(string, Push, time.Time) { pushes.Add(1) }
		base := listening(t, s)
		for _, tc := range []struct {
			why, body string
			code      int
		}{
			{"over 64 KiB", `{"views":[],"padding":"` + strings.Repeat("a", MaxViewBytes) + `"}`, http.StatusRequestEntityTooLarge},
			{"one object, then more than 64 KiB", `{"views":[]}` + strings.Repeat(" ", MaxViewBytes), http.StatusRequestEntityTooLarge},
			{"two objects", `{"views":[]}{"views":[]}`, http.StatusBadRequest},
			{"an array", `[{"views":[]}]`, http.StatusBadRequest},
			{"null", `null`, http.StatusBadRequest},
			{"nothing", ``, http.StatusBadRequest},
			{"not JSON", `views`, http.StatusBadRequest},
		} {
			if resp, body := call(t, base, http.MethodPost, ViewPath, w.keys["mac"], tc.body); resp.StatusCode != tc.code || !markedAsPeer(resp) {
				t.Fatalf("a push of %s got %d: %s", tc.why, resp.StatusCode, body)
			}
		}
		if n := pushes.Load(); n != 0 {
			t.Fatalf("%d refused pushes were taken", n)
		}
		if resp, body := call(t, base, http.MethodPost, ViewPath, w.keys["mac"], "\n"+`{"views":[]}`+"\n"); resp.StatusCode != http.StatusNoContent || pushes.Load() != 1 {
			t.Fatalf("one object between blank lines got %d: %s", resp.StatusCode, body)
		}
	})
}

// Only the mesh and loopback may ask, even with a registered key: a
// listener bound to the wrong interface still answers nobody else.
func TestPeerServerRefusesOutsideMeshRanges(t *testing.T) {
	w := setUpWeb1(t)
	s := w.server(t)
	outside := in("192.0.2.0/24")
	for _, from := range []string{at(outside, 7700), at(netip.AddrFrom16(outside.As16()), 7700), at(in("2001:db8::/32"), 7700), "web2.example.test:7700"} {
		rec := asked(s, from, http.MethodGet, SummaryPath, w.keys["web2"], "")
		if rec.Code != http.StatusForbidden || !markedAsPeer(rec.Result()) {
			t.Fatalf("a request from %s got %d", from, rec.Code)
		}
		if host, _, err := net.SplitHostPort(from); err != nil || strings.Contains(rec.Body.String(), host) {
			t.Fatalf("the refusal repeats where it came from: %s", rec.Body)
		}
	}
	mesh := in("100.64.0.0/10")
	for _, from := range []string{at(mesh, 7700), at(netip.AddrFrom16(mesh.As16()), 7700), at(in("fc00::/7"), 7700), at(in("127.0.0.0/8"), 7700)} {
		if rec := asked(s, from, http.MethodGet, SummaryPath, w.keys["web2"], ""); rec.Code != http.StatusOK {
			t.Fatalf("a request from the mesh at %s got %d: %s", from, rec.Code, rec.Body)
		}
	}
}

// However often peers ask, the summary is built at most once every
// SummaryCache, and rebuilt once that has passed.
func TestSummaryIsBuiltAtMostEveryTenSeconds(t *testing.T) {
	ctx := context.Background()
	w := setUpWeb1(t)
	s := w.server(t)
	from := at(in("100.64.0.0/10"), 7700)
	incidents := func() int {
		t.Helper()
		rec := asked(s, from, http.MethodGet, SummaryPath, w.keys["web2"], "")
		var summary Summary
		if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
			t.Fatalf("%d: %v", rec.Code, err)
		}
		return len(summary.Incidents)
	}
	if n := incidents(); n != 0 {
		t.Fatalf("%d incidents before any opened", n)
	}
	if _, err := w.store.OpenIncident(ctx, state.Incident{Key: "app:shop", Subject: "shop", Severity: state.SeverityWarning, OpenedAt: w.clock}); err != nil {
		t.Fatal(err)
	}
	w.clock = w.clock.Add(SummaryCache - time.Second)
	if n := incidents(); n != 0 {
		t.Fatalf("the summary was rebuilt %s after the last", SummaryCache-time.Second)
	}
	w.clock = w.clock.Add(time.Second)
	if n := incidents(); n != 1 {
		t.Fatalf("the summary was not rebuilt after %s: %d incidents", SummaryCache, n)
	}
}

// Starting where the address isn't on this machine says so, without
// the address.
func TestListeningWhereTheAddressIsNotUpSaysSo(t *testing.T) {
	w := setUpWeb1(t)
	s := w.server(t)
	addr := netip.AddrPortFrom(notHere(t, "100.64.0.0/10"), 7700)
	err := s.Start(context.Background(), addr)
	if err == nil {
		s.Stop()
	}
	if !errors.Is(err, ErrAddressNotUp) || strings.Contains(err.Error(), addr.Addr().String()) {
		t.Fatalf("got %v", err)
	}
}

// notHere is an address in prefix that none of this machine's
// interfaces has.
func notHere(t *testing.T, prefix string) netip.Addr {
	t.Helper()
	local, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	here := map[netip.Addr]bool{}
	for _, a := range local {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			here[p.Addr()] = true
		}
	}
	for addr := in(prefix); netip.MustParsePrefix(prefix).Contains(addr); addr = addr.Next() {
		if !here[addr] {
			return addr
		}
	}
	t.Skipf("this machine has every address in %s", prefix)
	return netip.Addr{}
}
