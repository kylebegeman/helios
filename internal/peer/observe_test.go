package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// macReader is a server's peer listener on loopback that lets a Mac read
// it with the Mac's key. It keeps each push it was sent, as sent and as
// the listener took it.
type macReader struct {
	name   string
	srv    *httptest.Server
	config func(change func(*Config))

	mu sync.Mutex
	// sent holds each push's body and the Authorization it came with;
	// took each push the listener took, and from whom.
	sent []sentPush
	took []tookPush
}

type sentPush struct{ body, authorization string }

type tookPush struct {
	observer string
	push     Push
}

// readByMac is the server named name, watching the others named, and
// letting the Mac whose key is macKey read it.
func readByMac(t *testing.T, name, macKey string, others ...string) *macReader {
	t.Helper()
	sec := keyedStore(t)
	if _, _, err := Update(sec, true, func(c *Config) (err error) {
		c.Self = Self{Name: name, Public: []string{"https://" + name + ".example.test"}}
		for i, other := range others {
			c.Peers = append(c.Peers, Peer{Name: other, Mesh: at(in("100.64.0.0/10"), uint16(7701+i)), Public: []string{"https://" + other + ".example.test"}})
		}
		c.Observers = map[string]string{"mac": Fingerprint(macKey)}
		c.Token, err = NewToken()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r := &macReader{name: name}
	r.config = func(change func(*Config)) {
		t.Helper()
		if _, _, err := Update(sec, false, func(c *Config) error {
			change(c)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Deps: Deps{Store: stateStore(t), Secrets: sec, Root: t.TempDir(), Last: func() Last { return Last{Round: time.Now()} }},
		Receive: func(observer string, p Push, _ time.Time) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.took = append(r.took, tookPush{observer, p})
		}}
	handler := s.Handler()
	r.srv = serving(t, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == ViewPath {
			body, _ := io.ReadAll(req.Body)
			r.mu.Lock()
			r.sent = append(r.sent, sentPush{string(body), req.Header.Get("Authorization")})
			r.mu.Unlock()
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		handler.ServeHTTP(rw, req)
	}))
	return r
}

// pushes are the pushes sent to the listener, and those it took.
func (r *macReader) pushes() ([]sentPush, []tookPush) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sent), slices.Clone(r.took)
}

// macWatching is a Mac, named mac, that watches nothing yet.
func macWatching(t *testing.T) *watcher {
	t.Helper()
	mac := watchingAs(t, "mac")
	mac.src.fetch = nil
	return mac
}

// watchServers has the Mac watch the servers at their listeners: their
// summaries are the real ones, and their edges and public URLs the Mac's
// fakes.
func (w *watcher) watchServers(t *testing.T, servers ...*macReader) {
	t.Helper()
	if _, _, err := Update(w.secrets, false, func(c *Config) error {
		c.Self = Self{Name: w.self}
		for _, s := range servers {
			mesh := s.srv.Listener.Addr().String()
			c.Peers = append(c.Peers, Peer{Name: s.name, Mesh: mesh, Public: []string{"https://" + s.name + ".example.test"}})
			w.names[mesh] = s.name
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// lines is a run of the Mac, one line per server.
func lines(t *testing.T, mac *watcher) []string {
	t.Helper()
	observed, err := mac.src.ObserveOnly(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range observed {
		got = append(got, o.String())
	}
	return got
}

// A Mac's run looks at every server and pushes what it saw to each with
// its own key, saying whether it reached anything and that it sends no
// pages. Each server keeps the views of the machines it watches. A
// server that can't be reached, or doesn't know the Mac's key, keeps the
// others from nothing, and the run says what each path and push came to
// in words alone.
func TestObservePushesViewsToEveryServer(t *testing.T) {
	mac := macWatching(t)
	web1, web2 := readByMac(t, "web1", mac.token, "web2"), readByMac(t, "web2", mac.token, "web1")
	mac.watchServers(t, web1, web2)
	mac.fail("web2", pathPublic, syscall.ECONNREFUSED)

	want := []string{"web1: summary ok, edge ok, public ok; view sent", "web2: summary ok, edge ok, public refused; view sent"}
	if got := lines(t, mac); !slices.Equal(got, want) {
		t.Fatalf("the run printed %q, want %q", got, want)
	}
	kept := map[*macReader]Push{
		web1: {SelfCheck: true, Views: []PushView{{Subject: "web2", Paths: Paths{WordOK, WordOK, WordRefused}}}},
		web2: {SelfCheck: true, Views: []PushView{{Subject: "web1", Paths: allOK}}},
	}
	for s, want := range kept {
		sent, took := s.pushes()
		if len(sent) != 1 || sent[0].authorization != "Bearer "+mac.token || len(took) != 1 || took[0].observer != "mac" {
			t.Fatalf("%s was sent %+v and took %+v", s.name, sent, took)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal([]byte(sent[0].body), &body); err != nil {
			t.Fatal(err)
		}
		if string(body["sends"]) != "false" || string(body["self_check"]) != "true" {
			t.Fatalf("%s was sent %s", s.name, sent[0].body)
		}
		if !samePush(took[0].push, want) {
			t.Fatalf("%s kept %+v, want %+v", s.name, took[0].push, want)
		}
	}

	// A Mac that reached nothing still says what it saw, and that it is
	// cut off, so its views never vote.
	mac.src.fetch = mac.fetch
	mac.down("web1", "web2")
	if got := lines(t, mac); got[0] != "web1: summary refused, edge refused, public refused; view sent" {
		t.Fatalf("cut off: %q", got)
	}
	if _, took := web1.pushes(); len(took) != 2 || took[1].push.SelfCheck {
		t.Fatalf("cut off, web1 took %+v", took)
	}

	mac.src.fetch = nil
	mac.up("web1", "web2")
	web2.srv.Close()
	web1.config(func(c *Config) { delete(c.Observers, "mac") })
	want = []string{"web1: summary untrusted, edge ok, public ok; view not sent (untrusted)", "web2: summary refused, edge ok, public ok; view not sent (refused)"}
	if got := lines(t, mac); !slices.Equal(got, want) {
		t.Fatalf("with web2 down and web1 not knowing the Mac: %q, want %q", got, want)
	}
	web1.config(func(c *Config) { c.Observers = map[string]string{"mac": Fingerprint(mac.token)} })
	if got := lines(t, mac)[0]; got != "web1: summary ok, edge ok, public ok; view sent" {
		t.Fatalf("with web2 down: %q", got)
	}
	web2Down := Push{SelfCheck: true, Views: []PushView{{Subject: "web2", Paths: Paths{WordRefused, WordOK, WordOK}}}}
	if _, took := web1.pushes(); len(took) != 3 || !samePush(took[2].push, web2Down) {
		t.Fatalf("with web2 down, web1 took %+v", took)
	}

	observed, err := mac.src.ObserveOnly(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(observed[0]); string(got) != `{"name":"web1","summary":"ok","tls":"ok","public":"ok","view":"ok"}` {
		t.Fatalf("as JSON: %s", got)
	}
}

// paired is one of two servers watching each other, reading the other's
// summary as its listener would build it, paging through a gate to its
// own fan-out, and letting a Mac read it.
type paired struct {
	*watcher
	fanout *fakeNotifier
	wt     *watch.Watcher
}

func watchingEachOther(t *testing.T) (web1, web2 *paired) {
	t.Helper()
	web1 = &paired{watcher: watchingAs(t, "web1", peerNamed("web2")), fanout: &fakeNotifier{}}
	web2 = &paired{watcher: watchingAs(t, "web2", peerNamed("web1")), fanout: &fakeNotifier{}}
	for _, p := range []*paired{web1, web2} {
		p.register(t, "mac")
		p.wt = p.incidents(&Gate{Next: p.fanout, Source: p.src})
	}
	web1.src.fetch, web2.src.fetch = web2.summary(t), web1.summary(t)
	return web1, web2
}

// summary is the machine's summary as its listener would answer it now.
func (p *paired) summary(t *testing.T) func(context.Context, string, string) (Summary, error) {
	root := t.TempDir()
	return func(ctx context.Context, _, _ string) (Summary, error) {
		return Build(ctx, Deps{Store: p.store, Secrets: p.secrets, Root: root, Now: func() time.Time { return p.clock }, Last: p.src.Last}, p.self)
	}
}

// A Mac that has never sent a view is never missed. Once it has, its
// silence past ObserverSilent opens a warning on each server it reads,
// and the page goes out once, from the server elected to send it.
func TestSilentMacOpensItsIncident(t *testing.T) {
	web1, web2 := watchingEachOther(t)
	minutes := func(n int) {
		t.Helper()
		for range n {
			web1.round(t, web1.wt)
			web2.round(t, web2.wt)
		}
	}
	silent := int(ObserverSilent / time.Minute)

	minutes(silent + watch.DefaultOpenAfter + 2)
	for _, p := range []*paired{web1, web2} {
		if open := openIncidentKeys(t, p.store); open != nil || p.fanout.sent != nil {
			t.Fatalf("a Mac never seen: %s has %v open and sent %+v", p.self, open, p.fanout.sent)
		}
	}

	macSaw := func(p *paired, subject string) {
		p.src.Receive("mac", Push{SelfCheck: true, Views: []PushView{{Subject: subject, Paths: allOK}}}, p.clock)
	}
	macSaw(web1, "web2")
	macSaw(web2, "web1")
	minutes(silent + watch.DefaultOpenAfter - 1)
	for _, p := range []*paired{web1, web2} {
		if open := openIncidentKeys(t, p.store); open != nil {
			t.Fatalf("before the Mac's silence counts: %s has %v open", p.self, open)
		}
	}
	minutes(1)
	for _, p := range []*paired{web1, web2} {
		inc, err := p.store.OpenIncidentByKey(context.Background(), "peer:mac")
		if err != nil || inc == nil || inc.Severity != state.SeverityWarning || inc.Message != "mac has sent no views for 13 min" {
			t.Fatalf("%s: %+v (%v)", p.self, inc, err)
		}
	}
	minutes(2 * handoff)
	if len(web1.fanout.sent) != 1 || web1.fanout.sent[0].Key != "peer:mac" || web1.fanout.sent[0].Host != "mac" || web2.fanout.sent != nil {
		t.Fatalf("web1 sent %+v and web2 %+v", web1.fanout.sent, web2.fanout.sent)
	}
	if inc, _ := web2.store.OpenIncidentByKey(context.Background(), "peer:mac"); inc.NotifiedAt.IsZero() || inc.NotifyError != "" {
		t.Fatalf("web2 doesn't read it as told: %+v", inc)
	}
}
