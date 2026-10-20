package peer

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// cluster is servers that watch each other, each reading the others'
// summaries from their real peer listeners on loopback, with its own
// stores, watch and gate, all on one clock the test moves. Their edges
// and public URLs are fakes. A machine that is down stops listening and
// fails every fake path to it; a link that is cut fails every path from
// one machine to another, the summary too. Each machine pages through
// its own fake fan-out.
type cluster struct {
	// machines are in name order.
	machines []*machine
	byName   map[string]*machine
	// named holds each machine's name, by its mesh address.
	named map[string]string

	mu    sync.Mutex
	clock time.Time
	// down holds each machine that is down, and cut each link that is,
	// as "from to".
	down map[string]bool
	cut  map[string]bool
}

// machine is one server of a cluster.
type machine struct {
	name   string
	store  *state.Store
	src    *Source
	server *Server
	at     netip.AddrPort
	wt     *watch.Watcher
	fanout *fakeNotifier
}

// formCluster is the servers named, in name order, each watching every
// other and readable by every other with its own key, after none has
// looked yet.
func formCluster(t *testing.T, names ...string) *cluster {
	t.Helper()
	c := &cluster{byName: map[string]*machine{}, named: map[string]string{}, clock: now, down: map[string]bool{}, cut: map[string]bool{}}
	tokens := map[string]string{}
	for _, name := range names {
		token, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		tokens[name] = token
		m := &machine{name: name, store: stateStore(t), fanout: &fakeNotifier{}}
		m.src = &Source{Secrets: keyedStore(t), Store: m.store, Now: c.now,
			fetch: func(ctx context.Context, mesh, token string) (Summary, error) {
				if c.isCut(name, c.named[mesh]) {
					return Summary{}, syscall.ECONNREFUSED
				}
				return m.src.fetchSummary(ctx, mesh, token)
			},
			handshake: func(_ context.Context, host, _ string) error { return c.reach(name, firstLabel(host)) },
			check:     func(_ context.Context, u string) error { return c.reach(name, firstLabel(hostname(u))) }}
		m.server = &Server{Deps: Deps{Store: m.store, Secrets: m.src.Secrets, Root: t.TempDir(), Now: c.now, Last: m.src.Last}, Receive: m.src.Receive}
		if err := m.server.Start(context.Background(), netip.AddrPortFrom(in("127.0.0.0/8"), 0)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.server.Stop)
		m.at = netip.MustParseAddrPort(m.server.Addr().String())
		m.wt = &watch.Watcher{Store: m.store, Notifier: &Gate{Next: m.fanout, Source: m.src}, Hostname: name, Now: c.now}
		c.machines = append(c.machines, m)
		c.byName[name] = m
		c.named[m.at.String()] = name
	}
	for _, m := range c.machines {
		if _, _, err := Update(m.src.Secrets, true, func(cfg *Config) error {
			cfg.Self = Self{Name: m.name, Public: []string{"https://" + m.name + ".example.test"}}
			cfg.Observers = map[string]string{}
			for _, other := range c.machines {
				if other != m {
					cfg.Peers = append(cfg.Peers, Peer{Name: other.name, Mesh: other.at.String(), Public: []string{"https://" + other.name + ".example.test"}})
					cfg.Observers[other.name] = Fingerprint(tokens[other.name])
				}
			}
			cfg.Token = tokens[m.name]
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func (c *cluster) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clock
}

// reach is how a fake path from one machine to another ends: refused
// when the other is down or the link is cut. A machine's own public URL
// always answers it.
func (c *cluster) reach(from, to string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down[to] || c.cut[from+" "+to] {
		return syscall.ECONNREFUSED
	}
	return nil
}

func (c *cluster) isCut(from, to string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cut[from+" "+to]
}

func (c *cluster) isDown(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.down[name]
}

// rounds runs n rounds a minute apart. In each, every machine that is up
// looks at its peers and runs its watch in turn, the highest name first,
// so an observer that isn't to page opens its incident before the one
// that is. A summary is cached for SummaryCache, so within a round most
// machines read each other as of the round before.
func (c *cluster) rounds(t *testing.T, n int) {
	t.Helper()
	for range n {
		c.mu.Lock()
		c.clock = c.clock.Add(time.Minute)
		c.mu.Unlock()
		for _, m := range slices.Backward(c.machines) {
			if !c.isDown(m.name) {
				m.round(t)
			}
		}
	}
}

// round is one round of the machine's watch, as the daemon runs it.
func (m *machine) round(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := m.wt.Round(ctx, m.src.Observe(ctx)); err != nil {
		t.Fatal(err)
	}
	m.src.RoundDone(m.wt.Now())
	if err := m.src.Save(); err != nil {
		t.Fatal(err)
	}
}

// takeDown stops the machine named: its listener closes, and its edge
// and public URLs refuse.
func (c *cluster) takeDown(name string) {
	c.mu.Lock()
	c.down[name] = true
	c.mu.Unlock()
	c.byName[name].server.Stop()
}

// bringBack starts the machine named again where it listened, and its
// watch runs a round at once, as the daemon's does when it starts.
func (c *cluster) bringBack(t *testing.T, name string) {
	t.Helper()
	m := c.byName[name]
	if err := m.server.Start(context.Background(), m.at); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	delete(c.down, name)
	c.mu.Unlock()
	m.round(t)
}

// cutOff fails every path from one machine to another, and none back.
func (c *cluster) cutOff(from, to string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cut[from+" "+to] = true
}

// leg is a machine's fan-out made one leg with a ledger, as the daemon's
// is, that fails every notice while failing is set. What it delivers is
// what the machine told.
type leg struct {
	failing bool
	to      *fakeNotifier
}

func (l *leg) Notify(ctx context.Context, n watch.Notice) error {
	if l.failing {
		return errors.New("refused")
	}
	return l.to.Notify(ctx, n)
}

// oneLeg makes the machine's fan-out one leg, and returns it.
func (m *machine) oneLeg() *leg {
	l := &leg{to: m.fanout}
	m.wt.Notifier.(*Gate).Next = &watch.Fanout{Legs: []watch.Leg{{Name: "pushover", Notifier: l}}, Ledger: &watch.Ledger{}, Now: m.src.Now}
	return l
}

// told is what the machine's fan-out sent about key, as each notice's
// transition and severity.
func (m *machine) told(key string) []string {
	var told []string
	for _, n := range m.fanout.sent {
		if n.Key == key {
			told = append(told, n.Transition+" "+n.Severity)
		}
	}
	return told
}

// open is the machine's open incident about key.
func (m *machine) open(t *testing.T, key string) state.Incident {
	t.Helper()
	inc, err := m.store.OpenIncidentByKey(context.Background(), key)
	if err != nil || inc == nil {
		t.Fatalf("%s has no open %s: %v", m.name, key, err)
	}
	return *inc
}

// Two servers that watch a third both see it go down, and both open an
// incident, but it is paged once and its recovery told once, by web1,
// whom Sender elects. web2 looks first, so it opens before web1 has told
// anyone and holds the page for web1; it stands down once web1's summary
// shows web1 told it, and an outage longer than HandoffWait never has it
// page as well. Its recovery waits for web1's, and then goes nowhere.
func TestTwoObserversPageOnce(t *testing.T) {
	c := formCluster(t, "web1", "web2", "web3")
	web1, web2, web3 := c.byName["web1"], c.byName["web2"], c.byName["web3"]
	c.rounds(t, 1)
	c.takeDown("web3")
	c.rounds(t, watch.DefaultOpenAfter+handoff+1)
	for _, m := range []*machine{web1, web2} {
		if inc := m.open(t, "peer:web3"); inc.Severity != state.SeverityCritical || inc.NotifyError != "" || inc.NotifiedAt.IsZero() {
			t.Fatalf("%s's incident about web3: %+v", m.name, inc)
		}
	}
	c.bringBack(t, "web3")
	c.rounds(t, watch.DefaultResolveAfter+1)

	if got, want := web1.told("peer:web3"), []string{"open critical", "resolved critical"}; !slices.Equal(got, want) {
		t.Fatalf("web1 told %q, want %q", got, want)
	}
	for _, n := range web1.fanout.sent {
		if n.Host != "web3" {
			t.Fatalf("a page about web3 came from host %q", n.Host)
		}
	}
	for _, m := range []*machine{web2, web3} {
		if len(m.fanout.sent) != 0 {
			t.Fatalf("%s paged too: %+v", m.name, m.fanout.sent)
		}
	}
	for _, m := range c.machines {
		if open := openIncidentKeys(t, m.store); len(open) != 0 {
			t.Fatalf("%s still has open: %v", m.name, open)
		}
		pending, err := m.store.PendingResolvedIncidentNotices(context.Background())
		if err != nil || len(pending) != 0 {
			t.Fatalf("%s still owes a recovery: %+v %v", m.name, pending, err)
		}
	}
}

// A server is down, and critical, only when most of the observers with a
// fresh view of it agree. web1 cut off from web3 sees every path fail,
// but web2 reaches it, so one of two is no majority and web1's incident
// stays a warning. Cut off from web4 along with web2, while web3 reaches
// it, web1 has two of three: it is critical, and paged once.
func TestThreeObserversNeedAMajority(t *testing.T) {
	c := formCluster(t, "web1", "web2", "web3")
	c.rounds(t, 1)
	c.cutOff("web1", "web3")
	c.rounds(t, watch.DefaultOpenAfter+2)
	web1 := c.byName["web1"]
	if inc := web1.open(t, "peer:web3"); inc.Severity != state.SeverityWarning {
		t.Fatalf("one observer of two made web3 %s: %s", inc.Severity, inc.Message)
	}
	if got, want := web1.told("peer:web3"), []string{"open warning"}; !slices.Equal(got, want) {
		t.Fatalf("web1 told %q, want %q", got, want)
	}
	for _, m := range c.machines[1:] {
		if open := openIncidentKeys(t, m.store); len(open) != 0 || len(m.fanout.sent) != 0 {
			t.Fatalf("%s, which reaches web3, has open %v and told %+v", m.name, open, m.fanout.sent)
		}
	}

	c = formCluster(t, "web1", "web2", "web3", "web4")
	c.rounds(t, 1)
	c.cutOff("web1", "web4")
	c.cutOff("web2", "web4")
	c.rounds(t, watch.DefaultOpenAfter+2)
	for _, name := range []string{"web1", "web2"} {
		if inc := c.byName[name].open(t, "peer:web4"); inc.Severity != state.SeverityCritical {
			t.Fatalf("two observers of three left web4 %s on %s: %s", inc.Severity, name, inc.Message)
		}
	}
	if got, want := c.byName["web1"].told("peer:web4"), []string{"open critical"}; !slices.Equal(got, want) {
		t.Fatalf("web1 told %q, want %q", got, want)
	}
	for _, m := range c.machines[1:] {
		if len(m.fanout.sent) != 0 {
			t.Fatalf("%s paged too: %+v", m.name, m.fanout.sent)
		}
	}
}

// A warning one observer told is no page of the outage that follows it.
// web1, cut off from web3, tells web3's warning; web3 then goes down for
// everyone while every leg of web1's fan-out fails. web1's summary lists
// web3 as critical but shows only the warning told, so web2 doesn't stand
// down on it and covers web1's failed page with its own. Once web1's legs
// work again it stands down on web2's page, so each step is paged once.
func TestAWarningToldIsNoPageOfTheOutage(t *testing.T) {
	c := formCluster(t, "web1", "web2", "web3")
	web1, web2 := c.byName["web1"], c.byName["web2"]
	leg := web1.oneLeg()
	c.rounds(t, 1)
	c.cutOff("web1", "web3")
	c.rounds(t, watch.DefaultOpenAfter+2)
	if got, want := web1.told("peer:web3"), []string{"open warning"}; !slices.Equal(got, want) {
		t.Fatalf("web1 told %q, want %q", got, want)
	}

	leg.failing = true
	c.takeDown("web3")
	c.rounds(t, watch.DefaultOpenAfter+2*handoff)
	if got, want := web2.told("peer:web3"), []string{"open critical"}; !slices.Equal(got, want) {
		t.Fatalf("web2 told %q, want %q", got, want)
	}
	leg.failing = false
	c.rounds(t, 2*handoff)
	if got, want := web1.told("peer:web3"), []string{"open warning"}; !slices.Equal(got, want) {
		t.Fatalf("web1 told %q once its legs worked, want %q", got, want)
	}
	if got := web2.told("peer:web3"); len(got) != 1 {
		t.Fatalf("web2 told %q", got)
	}
	if inc := web1.open(t, "peer:web3"); inc.NotifyError != "" || inc.NotifiedAt.IsZero() {
		t.Fatalf("web1 never stood down on web2's page: %+v", inc)
	}
}
