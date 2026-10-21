package peer

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// The paths a fake fails, by name.
const (
	pathSummary = "summary"
	pathTLS     = "tls"
	pathPublic  = "public"
)

// watcher is a machine, web1 unless the test names another, watching its
// peers through fake paths, on a clock the test moves. Every path passes
// unless failing holds how it fails, by machine and path, and a peer's
// summary is a fresh one unless summaries holds what it says. The
// machine's own public URL is its own public path.
type watcher struct {
	self    string
	src     *Source
	secrets *secrets.Store
	store   *state.Store
	token   string
	clock   time.Time

	mu sync.Mutex
	// names holds each peer's name, by its mesh address.
	names     map[string]string
	failing   map[string]error
	summaries map[string]Summary
	// checked counts the public URLs fetched, and taken every path.
	checked map[string]int
	taken   int
}

// peerNamed is a peer at a public URL of its own name; watching gives it
// a mesh address when it has none.
func peerNamed(name string) Peer {
	return Peer{Name: name, Public: []string{"https://" + name + ".example.test"}}
}

func watching(t *testing.T, peers ...Peer) *watcher {
	t.Helper()
	return watchingAs(t, "web1", peers...)
}

// watchingAs is the machine named self watching peers.
func watchingAs(t *testing.T, self string, peers ...Peer) *watcher {
	t.Helper()
	w := &watcher{self: self, secrets: keyedStore(t), store: stateStore(t), clock: now, names: map[string]string{},
		failing: map[string]error{}, summaries: map[string]Summary{}, checked: map[string]int{}}
	for i := range peers {
		if peers[i].Mesh == "" {
			peers[i].Mesh = at(in("100.64.0.0/10"), uint16(7701+i))
		}
		w.names[peers[i].Mesh] = peers[i].Name
	}
	c, _, err := Update(w.secrets, true, func(c *Config) (err error) {
		c.Self = Self{Name: self, Public: []string{"https://" + self + ".example.test"}}
		c.Peers = peers
		c.Token, err = NewToken()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	w.token = c.Token
	w.src = &Source{Secrets: w.secrets, Store: w.store, Now: func() time.Time { return w.clock },
		fetch: w.fetch, handshake: w.handshake, check: w.check}
	return w
}

// register lets the machine named read web1.
func (w *watcher) register(t *testing.T, name string) {
	t.Helper()
	key, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Update(w.secrets, false, func(c *Config) error {
		if c.Observers == nil {
			c.Observers = map[string]string{}
		}
		c.Observers[name] = Fingerprint(key)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// fail makes one path of the machine named fail with err.
func (w *watcher) fail(name, path string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failing[name+" "+path] = err
}

// down makes every path of each machine named refuse.
func (w *watcher) down(names ...string) {
	for _, name := range names {
		for _, path := range []string{pathSummary, pathTLS, pathPublic} {
			w.fail(name, path, syscall.ECONNREFUSED)
		}
	}
}

// up makes every path of each machine named pass again.
func (w *watcher) up(names ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, name := range names {
		for _, path := range []string{pathSummary, pathTLS, pathPublic} {
			delete(w.failing, name+" "+path)
		}
	}
}

func (w *watcher) says(name string, s Summary) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.summaries[name] = s
}

func (w *watcher) failed(name, path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.taken++
	return w.failing[name+" "+path]
}

func (w *watcher) fetch(_ context.Context, mesh, token string) (Summary, error) {
	name := w.names[mesh]
	if err := w.failed(name, pathSummary); err != nil {
		return Summary{}, err
	}
	if token != w.token {
		return Summary{}, errUntrusted
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.summaries[name]; ok {
		return s, nil
	}
	return Summary{Name: name, LastRoundAgeS: 30}, nil
}

func (w *watcher) handshake(_ context.Context, host, _ string) error {
	return w.failed(firstLabel(host), pathTLS)
}

func (w *watcher) check(_ context.Context, u string) error {
	w.mu.Lock()
	w.checked[u]++
	w.mu.Unlock()
	return w.failed(firstLabel(hostname(u)), pathPublic)
}

func firstLabel(host string) string {
	label, _, _ := strings.Cut(host, ".")
	return label
}

// observe moves the clock on a minute and looks at the peers, returning
// what holds by key; a key given twice would count twice.
func (w *watcher) observe(t *testing.T) map[string]watch.Condition {
	t.Helper()
	w.clock = w.clock.Add(time.Minute)
	conditions := map[string]watch.Condition{}
	for _, c := range w.src.Observe(context.Background()) {
		if _, twice := conditions[c.Key]; twice {
			t.Fatalf("%s given twice", c.Key)
		}
		conditions[c.Key] = c
	}
	return conditions
}

// round is one round of the machine's watch over what its peers show.
func (w *watcher) round(t *testing.T, wt *watch.Watcher) {
	t.Helper()
	w.clock = w.clock.Add(time.Minute)
	if err := wt.Round(context.Background(), w.src.Observe(context.Background())); err != nil {
		t.Fatal(err)
	}
	w.src.RoundDone(w.clock)
}

// incidents watches the machine's store on its clock.
func (w *watcher) incidents(n watch.Notifier) *watch.Watcher {
	return &watch.Watcher{Store: w.store, Notifier: n, Hostname: w.self, Now: func() time.Time { return w.clock }}
}

func openIncidentKeys(t *testing.T, store *state.Store) []string {
	t.Helper()
	open, err := store.OpenIncidents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, i := range open {
		keys = append(keys, i.Key)
	}
	sort.Strings(keys)
	return keys
}

// summaryOf answers with s.
func summaryOf(s Summary) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(rw).Encode(s) }
}

// serving answers on loopback until the test ends.
func serving(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// Each round looks at a peer three ways at once: its Helios's summary
// over the mesh with this machine's key, a handshake with its edge on the
// mesh as the host of its first public URL, and every public URL, which
// passes when any answers and fails as the first did otherwise. This
// machine's own public URL is checked alongside.
func TestProbeUsesThreePaths(t *testing.T) {
	asked := make(chan string, 1)
	srv := serving(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		select {
		case asked <- r.Method + " " + r.URL.Path + " " + r.Header.Get("Authorization"):
		default:
		}
		summaryOf(Summary{Name: "web2", LastRoundAgeS: 30})(rw, r)
	}))
	web2 := Peer{Name: "web2", Mesh: srv.Listener.Addr().String(), Public: []string{"https://shop.example.test", "https://web2.example.test/up"}}
	w := watching(t, web2)
	w.src.fetch = nil
	var shook []string
	w.src.handshake = func(_ context.Context, host, addr string) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		shook = append(shook, host+" "+addr)
		return nil
	}
	w.fail("shop", pathPublic, syscall.ECONNREFUSED)

	if got := w.observe(t); len(got) != 0 {
		t.Fatalf("a healthy peer: %+v", got)
	}
	select {
	case got := <-asked:
		if want := "GET " + SummaryPath + " Bearer " + w.token; got != want {
			t.Fatalf("the summary was asked as %q, want %q", got, want)
		}
	default:
		t.Fatal("the summary was never asked for")
	}
	host, _, _ := net.SplitHostPort(web2.Mesh)
	if want := []string{"shop.example.test " + net.JoinHostPort(host, "443")}; !slices.Equal(shook, want) {
		t.Fatalf("shook hands as %q, want %q", shook, want)
	}
	if w.checked["https://shop.example.test"] != 1 || w.checked["https://web2.example.test/up"] != 1 || w.checked["https://web1.example.test"] != 1 {
		t.Fatalf("public URLs fetched: %v", w.checked)
	}
	if last := w.src.Last(); last.Paths["web2"] != allOK || !last.SelfCheck || !last.Looked.Equal(w.clock) {
		t.Fatalf("%+v", last)
	}

	w.fail("web2", pathPublic, context.DeadlineExceeded)
	got := w.observe(t)
	if last := w.src.Last(); last.Paths["web2"] != (Paths{Summary: WordOK, TLS: WordOK, Public: WordRefused}) {
		t.Fatalf("with every public URL failing: %+v", last)
	}
	if c := got["peer:web2"]; len(got) != 1 || c.Severity != state.SeverityWarning || !strings.Contains(c.Message, "(public: refused)") {
		t.Fatalf("%+v", got)
	}
	w.fail("web1", pathPublic, context.DeadlineExceeded)
	w.observe(t)
	if w.src.Last().SelfCheck {
		t.Fatal("this machine's own public URL failed, yet it passed its self-check")
	}
}

// summaryWord is the word web1's summary path to web2 ends in, where web2
// answers at mesh.
func summaryWord(t *testing.T, mesh string) string {
	t.Helper()
	w := watching(t, Peer{Name: "web2", Mesh: mesh, Public: []string{"https://web2.example.test"}})
	w.src.fetch = nil
	w.observe(t)
	return w.src.Last().Paths["web2"].Summary
}

// The summary path says what Helios on the peer answered: ok, a watch
// stopped longer than StaleRound, another machine, or this machine's key
// refused. A refusal from anything but Helios, a redirect, or an answer
// too long or not a summary is a failure, and a redirect is never
// followed.
func TestTheSummaryPathReadsWhatHeliosAnswers(t *testing.T) {
	var followed atomic.Bool
	elsewhere := serving(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		followed.Store(true)
		summaryOf(Summary{Name: "web2", LastRoundAgeS: 30})(rw, r)
	}))
	padded := func(n int) http.HandlerFunc {
		return func(rw http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(rw, `{"name":"web2","last_round_age_s":30,"version":%q}`, strings.Repeat("x", n))
		}
	}
	stale := int64(StaleRound / time.Second)
	for _, tc := range []struct {
		name   string
		answer http.HandlerFunc
		want   string
	}{
		{"its watch ran StaleRound ago", summaryOf(Summary{Name: "web2", LastRoundAgeS: stale}), WordOK},
		{"its watch ran longer ago", summaryOf(Summary{Name: "web2", LastRoundAgeS: stale + 1}), WordStale},
		{"another machine answers", summaryOf(Summary{Name: "web3", LastRoundAgeS: 30}), WordMismatch},
		{"Helios refuses the key", func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set(Header, "1")
			http.Error(rw, "this key is not registered here", http.StatusUnauthorized)
		}, WordUntrusted},
		{"something else refuses it", func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "no", http.StatusUnauthorized)
		}, "status 401"},
		{"it redirects", func(rw http.ResponseWriter, r *http.Request) {
			http.Redirect(rw, r, elsewhere.URL+SummaryPath, http.StatusFound)
		}, "status 302"},
		{"it is busy", func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "busy; ask again", http.StatusServiceUnavailable)
		}, "status 503"},
		{"it answers a page", func(rw http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(rw, "<html>") }, WordFailed},
		{"its summary is just short enough", padded(MaxSummaryBytes - 100), WordOK},
		{"its summary is too long", padded(MaxSummaryBytes), WordFailed},
		{"one summary, then more than the limit", func(rw http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(rw, `{"name":"web2","last_round_age_s":30}`+strings.Repeat(" ", MaxSummaryBytes))
		}, WordFailed},
		{"two summaries", func(rw http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(rw, `{"name":"web2","last_round_age_s":30}{"name":"web3"}`)
		}, WordFailed},
		{"a summary followed by garbage", func(rw http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(rw, `{"name":"web2","last_round_age_s":30}broken`)
		}, WordFailed},
		{"null is not a summary", func(rw http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(rw, `null`)
		}, WordFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serving(t, tc.answer)
			if got := summaryWord(t, srv.Listener.Addr().String()); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if followed.Load() {
		t.Fatal("the redirect was followed")
	}
}

// A path that hangs, and one that never returns at all, end at the
// round's deadline as a timeout; the paths that answered still count.
func TestProbesEndAtTheRoundDeadline(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })
	w := watching(t, Peer{Name: "web2", Mesh: hung.Listener.Addr().String(), Public: []string{"https://web2.example.test"}})
	w.src.fetch = nil
	w.src.handshake = func(context.Context, string, string) error {
		<-release
		return nil
	}
	w.src.deadline = 300 * time.Millisecond

	done := make(chan Paths, 1)
	go func() {
		w.src.Observe(context.Background())
		done <- w.src.Last().Paths["web2"]
	}()
	select {
	case got := <-done:
		if want := (Paths{Summary: WordTimeout, TLS: WordTimeout, Public: WordOK}); got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the round outlived its deadline")
	}
}

// A path that panics, on any goroutine a round looks on, panics again on
// the goroutine that asked for the round, with the stack it was raised
// on, where the daemon's guard holds the round's incidents. On any other
// goroutine nothing could recover it, and the daemon would stop. The
// watch is left as it was, and its next round looks as usual.
func TestAPathThatPanicsPanicsWhereTheRoundWasAsked(t *testing.T) {
	panicking := func(path string) { panic("a defect in the " + path + " path") }
	for _, path := range []struct {
		name   string
		breaks func(w *watcher)
	}{
		{"summary", func(w *watcher) {
			w.src.fetch = func(context.Context, string, string) (Summary, error) { panicking("summary"); return Summary{}, nil }
		}},
		{"edge", func(w *watcher) {
			w.src.handshake = func(context.Context, string, string) error { panicking("edge"); return nil }
		}},
		{"public", func(w *watcher) {
			w.src.check = func(_ context.Context, u string) error {
				if u == "https://web2.example.test" {
					panicking("public")
				}
				return nil
			}
		}},
		{"self-check", func(w *watcher) {
			w.src.check = func(_ context.Context, u string) error {
				if u == "https://web1.example.test" {
					panicking("self-check")
				}
				return nil
			}
		}},
	} {
		t.Run(path.name, func(t *testing.T) {
			w := watching(t, peerNamed("web2"))
			fetch, handshake, check := w.src.fetch, w.src.handshake, w.src.check
			path.breaks(w)
			raised := func() (p any) {
				defer func() { p = recover() }()
				w.src.Observe(context.Background())
				return nil
			}()
			if got := fmt.Sprint(raised); !strings.Contains(got, "a defect in the "+path.name+" path") || !strings.Contains(got, "prober_test.go") {
				t.Fatalf("raised %q, want the panic and the stack it was raised on", got)
			}

			w.src.fetch, w.src.handshake, w.src.check = fetch, handshake, check
			done := make(chan Paths, 1)
			go func() {
				w.src.Observe(context.Background())
				done <- w.src.Last().Paths["web2"]
			}()
			select {
			case got := <-done:
				if want := (Paths{Summary: WordOK, TLS: WordOK, Public: WordOK}); got != want {
					t.Fatalf("the next round found %+v, want %+v", got, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the next round never finished")
			}
		})
	}
}

// A path that panics once its time is up has nobody waiting for it: the
// path is a timeout, and the panic is logged with the stack it was
// raised on.
func TestAPathThatPanicsOnceItTimedOutIsLogged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	late := make(chan struct{})
	logged := make(chan string, 1)
	log := func(format string, args ...any) { logged <- fmt.Sprintf(format, args...) }
	err := attempt(ctx, log, func(context.Context) error {
		<-late
		panic("a defect in a late path")
	})
	if word(err) != WordTimeout {
		t.Fatalf("the path ended in %v", err)
	}
	close(late)
	select {
	case line := <-logged:
		if !strings.HasPrefix(line, "peer watch: panic once its path had timed out: a defect in a late path") || !strings.Contains(line, "prober_test.go") {
			t.Fatalf("logged %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the late panic was never logged")
	}
}

// A path that panics just as its time runs out is raised or logged, and
// never lost between the two: a panic that reaches within after the
// deadline woke it, but before it stopped waiting, is raised. Many paths
// race deadlines a few microseconds long, half panicking at once and
// half the moment their time is up, so some panics land on the deadline.
func TestAPathThatPanicsAsItsTimeRunsOutIsRaisedOrLogged(t *testing.T) {
	const paths = 10000
	const defect = "a defect in a path racing its deadline"
	logged := make(chan string, paths)
	log := func(format string, args ...any) { logged <- fmt.Sprintf(format, args...) }
	var raised atomic.Int64
	var wg sync.WaitGroup
	for n := range paths {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(n/2%30)*time.Microsecond)
			defer cancel()
			defer func() {
				if p := recover(); p != nil {
					if !strings.Contains(fmt.Sprint(p), defect) {
						t.Errorf("raised %v", p)
					}
					raised.Add(1)
				}
			}()
			_ = attempt(ctx, log, func(ctx context.Context) error {
				if n%2 == 1 {
					<-ctx.Done()
				}
				panic(defect)
			})
		})
	}
	wg.Wait()
	late := paths - int(raised.Load())
	timeout := time.After(5 * time.Second)
	for got := range late {
		select {
		case line := <-logged:
			if !strings.HasPrefix(line, "peer watch: panic once its path had timed out: "+defect) {
				t.Fatalf("logged %q", line)
			}
		case <-timeout:
			t.Fatalf("of %d panics, %d were raised, %d logged, and %d lost", paths, paths-late, got, late-got)
		}
	}
}

// failureWord is any word a path can end in: one of a fixed few, or a
// status code, never anything an error held.
var failureWord = regexp.MustCompile(`^(ok|stale|untrusted|mismatch|timeout|refused|reset|dns|tls|unreachable|failed|status [1-5][0-9]{2})$`)

// What a real failure comes to is a word that names no address, though
// the error it came from may, and a peer's condition says only words.
func TestErrorWordsCarryNoAddress(t *testing.T) {
	ctx := context.Background()
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	src := &Source{}

	closed, err := net.Listen("tcp", at(in("127.0.0.0/8"), 0))
	if err != nil {
		t.Fatal(err)
	}
	closedAt := closed.Addr().String()
	closed.Close()
	hangsUp := closing(t, func(conn net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		conn.Close()
	})
	resets := closing(t, func(conn net.Conn) {
		_ = conn.(*net.TCPConn).SetLinger(0)
		conn.Close()
	})
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })
	plain := serving(t, http.NotFoundHandler())
	busy := serving(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "busy", http.StatusServiceUnavailable)
	}))
	refusing := serving(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set(Header, "1")
		http.Error(rw, "this key is not registered here", http.StatusUnauthorized)
	}))
	offMesh := at(in("192.0.2.0/24"), 7700)
	fetch := func(ctx context.Context, src *Source, mesh string) func() error {
		return func() error {
			_, err := src.fetchSummary(ctx, mesh, token)
			return err
		}
	}
	shortly, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	for _, tc := range []struct {
		name string
		err  func() error
		// names is what the error names that its word must not.
		names, want string
	}{
		{"nothing listens", fetch(ctx, src, closedAt), closedAt, WordRefused},
		{"it hangs up", fetch(ctx, src, hangsUp), hangsUp, WordReset},
		{"it resets the connection", fetch(ctx, src, resets), resets, WordReset},
		{"it never answers", fetch(shortly, src, hung.Listener.Addr().String()), hung.Listener.Addr().String(), WordTimeout},
		{"the name is unknown", fetch(ctx, &Source{resolver: resolving(t, netip.Addr{})}, "web2.example.test:7700"), "web2.example.test", WordDNS},
		{"the address is off the mesh", fetch(ctx, src, offMesh), offMesh, WordUnreachable},
		{"Helios refuses the key", fetch(ctx, src, refusing.Listener.Addr().String()), "", WordUntrusted},
		{"the edge doesn't speak TLS", func() error {
			return src.shake(ctx, "shop.example.test", plain.Listener.Addr().String())
		}, "", WordTLS},
		{"the public URL is busy", func() error {
			return app.RunCheck(ctx, manifest.Check{URL: busy.URL})
		}, busy.Listener.Addr().String(), "status 503"},
	} {
		err := tc.err()
		got := word(err)
		if got != tc.want || !failureWord.MatchString(got) {
			t.Fatalf("%s: %v came to %q, want %q", tc.name, err, got, tc.want)
		}
		if tc.names != "" && !strings.Contains(err.Error(), tc.names) {
			t.Fatalf("%s: the error doesn't name what the test looks for: %v", tc.name, err)
		}
	}

	// A peer seen once and then failing every way is told in words.
	web2 := serving(t, summaryOf(Summary{Name: "web2", LastRoundAgeS: 30}))
	w := watching(t, Peer{Name: "web2", Mesh: web2.Listener.Addr().String(), Public: []string{"https://web2.example.test"}})
	w.src.fetch = nil
	w.observe(t)
	web2.Close()
	shake := src.shake(ctx, "web2.example.test", plain.Listener.Addr().String())
	check := app.RunCheck(ctx, manifest.Check{URL: busy.URL})
	w.src.handshake = func(context.Context, string, string) error { return shake }
	w.src.check = func(_ context.Context, u string) error {
		if u == "https://web1.example.test" {
			return nil
		}
		return check
	}
	c := w.observe(t)["peer:web2"]
	if !strings.Contains(c.Message, "(summary: refused, edge: tls, public: status 503)") {
		t.Fatalf("%+v", c)
	}
	host, port, _ := net.SplitHostPort(web2.Listener.Addr().String())
	for _, said := range []string{c.Subject, c.Message} {
		if strings.Contains(said, host) || strings.Contains(said, port) {
			t.Fatalf("the condition names an address: %+v", c)
		}
	}
}

// closing is where a loopback listener answers that ends each connection
// it takes with end.
func closing(t *testing.T, end func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", at(in("127.0.0.0/8"), 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			end(conn)
		}
	}()
	return listener.Addr().String()
}

// resolving is a resolver whose every lookup finds addr, or no such host
// when addr is the zero address, answered by the test's own DNS server
// on loopback.
func resolving(t *testing.T, addr netip.Addr) *net.Resolver {
	t.Helper()
	conn, err := net.ListenPacket("udp", at(in("127.0.0.0/8"), 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		query := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(query)
			if err != nil {
				return
			}
			if answer := dnsAnswer(query[:n], addr); answer != nil {
				_, _ = conn.WriteTo(answer, from)
			}
		}
	}()
	server := conn.LocalAddr().String()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", server)
	}}
}

// dnsAnswer answers one DNS query: addr to a query for an IPv4 address,
// no address to any other, and no such name to every query when addr is
// the zero address.
func dnsAnswer(query []byte, addr netip.Addr) []byte {
	if len(query) < 12 {
		return nil
	}
	end := 12
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	// The root label, then the type and the class.
	end += 5
	if end > len(query) {
		return nil
	}
	answer := append([]byte{query[0], query[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, query[12:end]...)
	switch {
	case !addr.IsValid():
		answer[3] = 0x83
	case binary.BigEndian.Uint16(query[end-4:end-2]) == 1 && addr.Is4():
		answer[7] = 1
		a := addr.As4()
		// A pointer to the question's name, IN A, a minute, four bytes.
		answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		answer = append(answer, a[:]...)
	}
	return answer
}

// A mesh name is only ever reached on the mesh or loopback, whatever it
// resolves to: one that resolves anywhere else is refused before any
// connection is made, so this machine's key never goes there, for the
// summary or the edge's handshake.
func TestAMeshNameResolvingOffTheMeshNeverGetsTheKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	keys := make(chan string, 1)
	srv := serving(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		keys <- r.Header.Get("Authorization")
		summaryOf(Summary{Name: "web2", LastRoundAgeS: 30})(rw, r)
	}))
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	mesh := net.JoinHostPort("web2.example.test", port)

	src := &Source{resolver: resolving(t, in("127.0.0.0/8"))}
	if _, err := src.fetchSummary(ctx, mesh, token); err != nil {
		t.Fatalf("the name resolving onto loopback: %v", err)
	}
	if got := <-keys; got != "Bearer "+token {
		t.Fatalf("got %q", got)
	}

	src = &Source{resolver: resolving(t, in("192.0.2.0/24"))}
	if _, err := src.fetchSummary(ctx, mesh, token); !errors.Is(err, errOffMesh) || word(err) != WordUnreachable {
		t.Fatalf("the summary from a name resolving off the mesh: %v", err)
	}
	if err := src.shake(ctx, "shop.example.test", net.JoinHostPort("web2.example.test", "443")); !errors.Is(err, errOffMesh) {
		t.Fatalf("the handshake with a name resolving off the mesh: %v", err)
	}
}

// The edge on the mesh passes on any certificate at all, trusted or not
// and for any name, since an edge behind Cloudflare may serve its origin
// certificate; an edge that doesn't speak TLS fails.
func TestTheEdgeOnTheMeshIsJudgedOnAnyCertificate(t *testing.T) {
	ctx := context.Background()
	src := &Source{}
	edgeOnMesh := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(edgeOnMesh.Close)
	if err := src.shake(ctx, "shop.example.test", edgeOnMesh.Listener.Addr().String()); err != nil {
		t.Fatalf("an edge serving a certificate nothing trusts: %v", err)
	}
	plain := serving(t, http.NotFoundHandler())
	if err := src.shake(ctx, "shop.example.test", plain.Listener.Addr().String()); word(err) != WordTLS {
		t.Fatalf("an edge without TLS: %v", err)
	}
}

// An observer that reaches neither its own public URL nor any peer says
// so, and holds what it had open about its peers: the incident open
// before stays open, the same one, and nothing new opens or recovers
// however long it lasts.
func TestIsolatedObserverHoldsPeerIncidents(t *testing.T) {
	ctx := context.Background()
	w := watching(t, peerNamed("web2"), peerNamed("web3"))
	n := &fakeNotifier{}
	wt := w.incidents(n)
	w.round(t, wt)
	w.down("web2")
	for range watch.DefaultOpenAfter {
		w.round(t, wt)
	}
	before, err := w.store.OpenIncidentByKey(ctx, "peer:web2")
	if err != nil || before == nil || before.Severity != state.SeverityCritical {
		t.Fatalf("web2 down: %+v, %v", before, err)
	}

	w.fail("web1", pathPublic, context.DeadlineExceeded)
	w.down("web3")
	for range watch.DefaultOpenAfter + watch.DefaultResolveAfter {
		w.round(t, wt)
	}
	if got := openIncidentKeys(t, w.store); !slices.Equal(got, []string{"peer:self", "peer:web2"}) {
		t.Fatalf("open: %v", got)
	}
	after, err := w.store.OpenIncidentByKey(ctx, "peer:web2")
	if err != nil || after == nil || after.ID != before.ID || after.Severity != state.SeverityCritical {
		t.Fatalf("held: %+v, %v", after, err)
	}
	var told []string
	for _, sent := range n.sent {
		told = append(told, sent.Key+" "+sent.Transition)
	}
	if want := []string{"peer:web2 open", "peer:self open"}; !slices.Equal(told, want) {
		t.Fatalf("told %v, want %v", told, want)
	}
}

// When this machine's peer configuration can't be read, every open peer
// incident is held as it is and nothing else is said: no path is taken,
// and no peer incident opens or recovers. Where peer watch was never set
// up there is nothing to hold.
func TestUnreadablePeerConfigHoldsPeerIncidents(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, store *secrets.Store)
	}{
		{"its key is gone", func(t *testing.T, store *secrets.Store) {
			if err := os.Remove(store.KeyPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"its list is not JSON", func(t *testing.T, store *secrets.Store) {
			list := "{"
			if _, err := store.SetAll(manifest.ReservedApp, map[string]*string{ListKey: &list}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := watching(t, peerNamed("web2"))
			for _, key := range []string{"peer:web2", "peer:edge-provider", "app:shop"} {
				opened(t, w.store, state.Incident{Key: key, Subject: key, Severity: state.SeverityWarning, OpenedAt: now})
			}
			tc.spoil(t, w.secrets)
			if _, err := Load(w.secrets); err == nil || errors.Is(err, ErrNotSet) {
				t.Fatalf("the configuration still reads: %v", err)
			}
			got := w.src.Observe(ctx)
			sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })
			want := []watch.Condition{{Key: "peer:edge-provider", Unknown: true}, {Key: "peer:web2", Unknown: true}}
			if !slices.Equal(got, want) || w.taken != 0 {
				t.Fatalf("got %+v after %d paths, want %+v", got, w.taken, want)
			}
			wt := w.incidents(&fakeNotifier{})
			for range watch.DefaultOpenAfter + watch.DefaultResolveAfter {
				w.round(t, wt)
			}
			for _, key := range []string{"peer:edge-provider", "peer:web2"} {
				if inc, err := w.store.OpenIncidentByKey(ctx, key); err != nil || inc == nil {
					t.Fatalf("%s was not held: %v", key, err)
				}
			}
		})
	}

	store := stateStore(t)
	opened(t, store, state.Incident{Key: "peer:web2", Subject: "web2", Severity: state.SeverityWarning, OpenedAt: now})
	if got := (&Source{Secrets: keyedStore(t), Store: store}).Observe(ctx); got != nil {
		t.Fatalf("without peer watch: %+v", got)
	}
}

// Every peer's public URL failing while the mesh reaches each is one
// warning about the edge provider, not one per peer; one peer whose
// public URL alone fails, while this machine's own answers, is that
// peer's edge.
func TestPublicURLsFailingOverAWorkingMeshAreOneWarning(t *testing.T) {
	w := watching(t, peerNamed("web2"), peerNamed("web3"))
	w.fail("web2", pathPublic, context.DeadlineExceeded)
	w.fail("web3", pathPublic, context.DeadlineExceeded)
	if got := w.observe(t); len(got) != 1 || got["peer:edge-provider"].Severity != state.SeverityWarning {
		t.Fatalf("%+v", got)
	}

	w = watching(t, peerNamed("web2"))
	w.fail("web2", pathPublic, context.DeadlineExceeded)
	if got := w.observe(t); len(got) != 1 || !strings.Contains(got["peer:web2"].Message, "(public: timeout)") {
		t.Fatalf("%+v", got)
	}
}

// A Mac's push counts while it is fresh: it keeps an observer that
// reaches nothing from calling itself cut off, and its view votes on a
// page. Once the Mac has sent a view, its silence is a warning. A push
// from a machine not registered counts for nothing.
func TestAMacsPushCountsWhileFresh(t *testing.T) {
	w := watching(t, peerNamed("web2"), peerNamed("web3"))
	w.register(t, "mac")
	w.observe(t)
	w.fail("web1", pathPublic, context.DeadlineExceeded)
	w.down("web2", "web3")
	sawDown := func(subject string) Push {
		return Push{SelfCheck: true, Views: []PushView{{Subject: subject, Paths: allDown}}}
	}

	w.src.Receive("old", sawDown("web2"), w.clock)
	if got := w.observe(t); len(got) != 1 || got["peer:self"].Severity != state.SeverityWarning {
		t.Fatalf("with a push from a machine not registered: %+v", got)
	}
	w.src.Receive("mac", sawDown("web3"), w.clock)
	pushed := w.clock
	if got := w.observe(t); len(got) != 2 || got["peer:web3"].Severity != state.SeverityCritical || got["peer:web2"].Severity != state.SeverityWarning {
		t.Fatalf("with the Mac's fresh view of web3: %+v", got)
	}
	w.clock = pushed.Add(ViewFresh)
	if got := w.observe(t); len(got) != 1 || got["peer:self"].Severity != state.SeverityWarning {
		t.Fatalf("once the Mac's view is past ViewFresh: %+v", got)
	}
	w.up("web2")
	if got := w.observe(t); len(got) != 1 || got["peer:web3"].Severity != state.SeverityWarning {
		t.Fatalf("with web2 answering and the Mac's view of web3 past ViewFresh: %+v", got)
	}

	w.up("web1", "web2", "web3")
	w.clock = pushed.Add(ObserverSilent - time.Minute)
	if got := w.observe(t); len(got) != 0 {
		t.Fatalf("the Mac quiet for ObserverSilent: %+v", got)
	}
	if got := w.observe(t)["peer:mac"]; got.Severity != state.SeverityWarning || got.Message != "mac has sent no views for 11 min" {
		t.Fatalf("the Mac quiet for longer: %+v", got)
	}
}

// What a peer's summary says counts toward its condition: a summary from
// a stopped watch still shows what is quietly wrong there, and the fresh
// views in another peer's summary vote on whether it is down.
func TestAPeersSummaryCountsTowardItsCondition(t *testing.T) {
	w := watching(t, peerNamed("web2"), peerNamed("web3"))
	w.observe(t)
	stale := int64(StaleRound/time.Second) + 60
	w.says("web2", Summary{Name: "web2", LastRoundAgeS: stale,
		Backups: []SummaryBackup{{App: "shop", LastGoodBackupAgeS: seconds(int64(50 * time.Hour / time.Second))}},
		Legs:    []SummaryLeg{{Name: "email"}}})
	message := w.observe(t)["peer:web2"].Message
	for _, want := range []string{"its watch has stopped (summary: stale)", "its last good backup of shop is 2 days old", "its email alerts have never worked"} {
		if !strings.Contains(message, want) {
			t.Fatalf("%q lacks %q", message, want)
		}
	}

	w.down("web2")
	w.fail("web1", pathPublic, context.DeadlineExceeded)
	sawDown := func(age time.Duration) Summary {
		return Summary{Name: "web3", LastRoundAgeS: 30, SelfCheck: true, Views: []SummaryView{{Subject: "web2", AgeS: int64(age / time.Second), Paths: allDown}}}
	}
	w.says("web3", sawDown(30*time.Second))
	if got := w.observe(t)["peer:web2"]; got.Severity != state.SeverityCritical {
		t.Fatalf("with web3's fresh view: %+v", got)
	}
	w.says("web3", sawDown(ViewFresh+time.Second))
	if got := w.observe(t)["peer:web2"]; got.Severity != state.SeverityWarning {
		t.Fatalf("with web3's view past ViewFresh: %+v", got)
	}
}

// This machine's summary says when its watch last finished a round, or
// started before its first, and what its last look at its peers found,
// leaving out what it only held.
func TestLastIsWhatTheWatchLastFound(t *testing.T) {
	w := watching(t, peerNamed("web2"))
	started := w.clock
	if last := w.src.Last(); !last.Round.Equal(started) || !last.Looked.IsZero() {
		t.Fatalf("before any round: %+v", last)
	}
	w.down("web2")
	w.observe(t)
	w.src.RoundDone(w.clock)
	last := w.src.Last()
	refused := Paths{Summary: WordRefused, TLS: WordRefused, Public: WordRefused}
	if !last.Round.Equal(w.clock) || !last.Looked.Equal(w.clock) || !last.SelfCheck || last.Paths["web2"] != refused ||
		!slices.Equal(last.Findings, []Finding{{Key: "peer:web2", Severity: state.SeverityWarning}}) {
		t.Fatalf("%+v", last)
	}

	opened(t, w.store, state.Incident{Key: "peer:web2", Subject: "web2", Severity: state.SeverityWarning, OpenedAt: now})
	w.fail("web1", pathPublic, context.DeadlineExceeded)
	w.observe(t)
	if last := w.src.Last(); last.SelfCheck || !slices.Equal(last.Findings, []Finding{{Key: "peer:self", Severity: state.SeverityWarning}}) {
		t.Fatalf("isolated: %+v", last)
	}
}

// A peer removed and added again is watched afresh: until it answers, it
// is only never seen, whatever it was before.
func TestAPeerAddedAgainIsSeenAfresh(t *testing.T) {
	w := watching(t, peerNamed("web2"))
	w.observe(t)
	var web2 Peer
	change := func(change func(*Config)) {
		t.Helper()
		if _, _, err := Update(w.secrets, false, func(c *Config) error {
			change(c)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	change(func(c *Config) { web2, c.Peers = c.Peers[0], nil })
	if got := w.observe(t); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	change(func(c *Config) { c.Peers = []Peer{web2} })
	w.down("web2")
	if got := w.observe(t)["peer:web2"]; got.Severity != state.SeverityWarning || !strings.Contains(got.Message, "it has never answered") {
		t.Fatalf("%+v", got)
	}
}
