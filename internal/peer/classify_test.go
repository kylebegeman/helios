package peer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

var (
	now     = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	allOK   = Paths{Summary: WordOK, TLS: WordOK, Public: WordOK}
	allDown = Paths{Summary: "timeout", TLS: "timeout", Public: "timeout"}
)

// round is web1's round, an hour after it started, with its own public
// URL answering.
func round(peers ...Sight) Round {
	return Round{Self: "web1", Now: now, Started: now.Add(-time.Hour), SelfCheck: true, Peers: peers}
}

// seen is a peer whose summary last came back ok a minute ago.
func seen(name string, p Paths) Sight {
	return Sight{Name: name, Paths: p, LastGood: now.Add(-time.Minute)}
}

// judged runs Judge and returns its conditions by key; a key given twice
// would count twice toward an incident.
func judged(t *testing.T, r Round) map[string]watch.Condition {
	t.Helper()
	conditions := map[string]watch.Condition{}
	for _, c := range Judge(r) {
		if _, twice := conditions[c.Key]; twice {
			t.Fatalf("%s given twice: %+v", c.Key, Judge(r))
		}
		conditions[c.Key] = c
	}
	return conditions
}

// Each row of the classification table, in its order: what the three
// paths show decides the class, and the class its severity, here for a
// pair of servers whose observer passed its self-check.
func TestClassify(t *testing.T) {
	for _, row := range []struct {
		paths    Paths
		seen     bool
		class    Class
		severity string
	}{
		{Paths{WordUntrusted, WordOK, WordOK}, true, NotTrusted, state.SeverityWarning},
		{Paths{WordMismatch, "timeout", "timeout"}, true, NotTrusted, state.SeverityWarning},
		{Paths{"refused", WordOK, WordOK}, false, NeverSeen, state.SeverityWarning},
		{allDown, false, NeverSeen, state.SeverityWarning},
		{allOK, true, Healthy, ""},
		{Paths{WordOK, "timeout", WordOK}, true, EdgeDegraded, state.SeverityWarning},
		{Paths{WordOK, WordOK, "status 502"}, true, EdgeDegraded, state.SeverityWarning},
		{Paths{WordStale, WordOK, WordOK}, true, WatcherDown, state.SeverityWarning},
		// A stale summary is an answer from the peer, so one never ok is
		// stuck rather than never seen, here for the hour web1 has run.
		{Paths{WordStale, "timeout", "timeout"}, false, WatcherDown, state.SeverityCritical},
		{Paths{"refused", WordOK, WordOK}, true, WatcherDown, state.SeverityWarning},
		{Paths{"refused", WordOK, "timeout"}, true, WatcherDown, state.SeverityWarning},
		{Paths{"timeout", "timeout", WordOK}, true, MeshDegraded, state.SeverityWarning},
		{allDown, true, HostDown, state.SeverityCritical},
		{Paths{"", "", ""}, true, HostDown, state.SeverityCritical},
	} {
		if got := Classify(row.paths, row.seen); got != row.class {
			t.Fatalf("%+v, seen %v: classed %q, want %q", row.paths, row.seen, got, row.class)
		}
		s := Sight{Name: "web2", Paths: row.paths}
		if row.seen {
			s.LastGood = now.Add(-time.Minute)
		}
		c, found := judged(t, round(s))["peer:web2"]
		if c.Severity != row.severity || found != (row.severity != "") {
			t.Fatalf("%+v: judged %+v, want severity %q", row.paths, c, row.severity)
		}
		if found && (c.Subject != "web2" || c.Message == "") {
			t.Fatalf("%+v: judged %+v", row.paths, c)
		}
	}
}

// A peer whose machine answers on the mesh while its Helios doesn't, or
// answers stale, can't send its own alerts: a warning, and critical once
// that has lasted 15 minutes. The clock never runs from before this
// process started.
func TestWatcherDownTurnsCriticalAfter15Minutes(t *testing.T) {
	refused := Paths{Summary: "refused", TLS: WordOK, Public: WordOK}
	for _, tc := range []struct {
		paths    Paths
		lastGood time.Duration
		started  time.Duration
		severity string
		message  string
	}{
		{refused, 15*time.Minute - time.Second, time.Hour, state.SeverityWarning, "its edge answers on the mesh but Helios does not (summary: refused) for 14 min; it cannot send its own alerts"},
		{refused, WatcherDownCritical, time.Hour, state.SeverityCritical, "for 15 min"},
		{Paths{WordStale, WordOK, WordOK}, 20 * time.Minute, time.Hour, state.SeverityCritical, "Helios answers on the mesh but its watch has stopped (summary: stale) for 20 min"},
		{refused, 20 * time.Minute, 5 * time.Minute, state.SeverityWarning, "for 5 min"},
		{refused, 20 * time.Minute, WatcherDownCritical, state.SeverityCritical, "for 15 min"},
	} {
		r := round(Sight{Name: "web2", Paths: tc.paths, LastGood: now.Add(-tc.lastGood)})
		r.Started = now.Add(-tc.started)
		c := judged(t, r)["peer:web2"]
		if c.Severity != tc.severity || !strings.Contains(c.Message, tc.message) {
			t.Fatalf("last good %s ago, started %s ago: %+v, want %s with %q", tc.lastGood, tc.started, c, tc.severity, tc.message)
		}
	}
}

// A peer that has never answered stays a warning however long it fails
// and however many observers agree: a mistyped address never pages.
func TestNeverSeenPeerStaysWarning(t *testing.T) {
	for _, p := range []Paths{allDown, {Summary: "refused", TLS: WordOK, Public: "timeout"}} {
		r := round(Sight{Name: "web2", Paths: p}, seen("web3", allOK))
		r.Started = now.Add(-48 * time.Hour)
		r.Views = []View{
			{Observer: "web3", Subject: "web2", Age: time.Minute, SelfCheck: true, Paths: allDown},
			{Observer: "mac", Subject: "web2", Age: time.Minute, SelfCheck: true, Paths: allDown},
		}
		c := judged(t, r)["peer:web2"]
		if c.Severity != state.SeverityWarning || !strings.Contains(c.Message, "it has never answered over the mesh") {
			t.Fatalf("%+v: %+v", p, c)
		}
	}
}

// With two servers and no Mac, the observer pages a host down alone only
// when its mesh, edge and public paths fail together and its own public
// URL answers. When its own fails too, it is cut off, and says so instead.
func TestTwoServersNeedEveryPathAndSelfCheck(t *testing.T) {
	if c := judged(t, round(seen("web2", allDown)))["peer:web2"]; c.Severity != state.SeverityCritical {
		t.Fatalf("every path failing with the self-check passing: %+v", c)
	}
	for _, p := range []Paths{
		{Summary: WordOK, TLS: "timeout", Public: "timeout"},
		{Summary: "timeout", TLS: WordOK, Public: "timeout"},
		{Summary: "timeout", TLS: "timeout", Public: WordOK},
	} {
		if c := judged(t, round(seen("web2", p)))["peer:web2"]; c.Severity != state.SeverityWarning {
			t.Fatalf("%+v pages with a path passing: %+v", p, c)
		}
	}
	r := round(seen("web2", allDown))
	r.SelfCheck = false
	conditions := judged(t, r)
	if _, judgedPeer := conditions["peer:web2"]; judgedPeer || conditions["peer:self"].Severity != state.SeverityWarning {
		t.Fatalf("an observer whose own public URL fails judged its only peer: %+v", conditions)
	}
}

// When every peer's public URL fails while the mesh reaches each, the
// edge provider or this machine's internet is at fault: one warning, not
// one per peer, though what each peer's own summary shows still stands.
// One peer's public URL failing while this machine's answers is that
// peer's edge.
func TestEdgeProviderDegradedRaisesOneWarning(t *testing.T) {
	publicDown := Paths{Summary: WordOK, TLS: WordOK, Public: "timeout"}
	web3 := seen("web3", publicDown)
	web3.Report = &Report{Backups: []Backup{{App: "shop", BackedUp: true, BackupAge: 3 * 24 * time.Hour}}}
	web4 := seen("web4", Paths{Summary: "refused", TLS: WordOK, Public: "timeout"})
	conditions := judged(t, round(seen("web2", publicDown), web3, web4))
	if c := conditions["peer:edge-provider"]; c.Severity != state.SeverityWarning || c.Subject != "public edge" {
		t.Fatalf("edge provider: %+v", conditions)
	}
	if _, ok := conditions["peer:web2"]; ok {
		t.Fatalf("a peer's edge is blamed for the edge provider's trouble: %+v", conditions)
	}
	if c := conditions["peer:web3"]; c.Message != "its last good backup of shop is 3 days old" {
		t.Fatalf("what the peer's own summary shows was dropped with its edge: %+v", c)
	}
	if c := conditions["peer:web4"]; !strings.Contains(c.Message, "Helios does not") {
		t.Fatalf("a peer whose Helios is down is hidden behind the edge provider: %+v", c)
	}

	conditions = judged(t, round(seen("web2", publicDown)))
	if _, ok := conditions["peer:edge-provider"]; ok || !strings.Contains(conditions["peer:web2"].Message, "its public URLs do not (public: timeout)") {
		t.Fatalf("one peer's edge, this machine's own answering: %+v", conditions)
	}
	alone := round(seen("web2", publicDown))
	alone.SelfCheck = false
	conditions = judged(t, alone)
	if _, ok := conditions["peer:web2"]; ok || conditions["peer:edge-provider"].Severity != state.SeverityWarning {
		t.Fatalf("one peer's edge, this machine's own failing too: %+v", conditions)
	}
	conditions = judged(t, round(seen("web2", publicDown), seen("web3", allOK)))
	if _, ok := conditions["peer:edge-provider"]; ok || conditions["peer:web2"].Severity != state.SeverityWarning {
		t.Fatalf("one of two peers' edge: %+v", conditions)
	}
}

// A mesh that can't reach a peer whose public URLs answer, as in a
// tailnet outage, is a warning however long it lasts and however many
// observers see every path fail.
func TestMeshFailuresAloneAreNeverCritical(t *testing.T) {
	for _, summary := range []string{"timeout", "refused", "reset", "dns", "unreachable", "failed", "status 502"} {
		for _, tls := range []string{"timeout", "refused", "reset", "tls", "unreachable"} {
			for _, agreeing := range []int{0, 1, 3} {
				r := round(Sight{Name: "web2", Paths: Paths{Summary: summary, TLS: tls, Public: WordOK}, LastGood: now.Add(-2 * time.Hour)})
				r.Started = now.Add(-3 * time.Hour)
				for i := range agreeing {
					r.Views = append(r.Views, View{Observer: "observer" + string(rune('a'+i)), Subject: "web2", Age: time.Minute, SelfCheck: true, Paths: allDown})
				}
				if c := judged(t, r)["peer:web2"]; c.Severity != state.SeverityWarning {
					t.Fatalf("summary %s, edge %s, %d agreeing: %+v", summary, tls, agreeing, c)
				}
			}
		}
	}
}

// An observer whose own public URL fails and which no peer's Helios
// answers is cut off itself: it says so, holds every open peer incident
// as it is, and judges no peer. A machine with no peers is never cut off
// from them.
func TestAnIsolatedObserverJudgesNoPeer(t *testing.T) {
	r := round(seen("web2", allDown), seen("web3", Paths{Summary: "refused", TLS: WordOK, Public: "timeout"}))
	r.SelfCheck = false
	r.Open = []string{"peer:web2", "peer:self", "peer:edge-provider", "app:shop"}
	conditions := judged(t, r)
	if len(conditions) != 3 {
		t.Fatalf("an isolated round: %+v", conditions)
	}
	if c := conditions["peer:self"]; c.Unknown || c.Severity != state.SeverityWarning || c.Subject != "peer watch" ||
		c.Message != "this machine cannot reach its own public URL or any peer; peer findings are on hold" {
		t.Fatalf("peer:self: %+v", c)
	}
	for _, key := range []string{"peer:web2", "peer:edge-provider"} {
		if c := conditions[key]; !c.Unknown {
			t.Fatalf("%s is not held: %+v", key, conditions)
		}
	}
	if conditions := judged(t, Round{Self: "web1", Now: now, Started: now.Add(-time.Hour)}); len(conditions) != 0 {
		t.Fatalf("no peers: %+v", conditions)
	}
}

// A Mac's view arriving proves this machine is reachable, so an observer
// that hears from its Mac while fresh is not cut off.
func TestAMacViewMeansNotIsolated(t *testing.T) {
	r := round(seen("web2", allDown))
	r.SelfCheck = false
	r.Observers = []Observer{{Name: "mac", LastView: now.Add(-ViewFresh)}}
	conditions := judged(t, r)
	if _, isolated := conditions["peer:self"]; isolated || conditions["peer:web2"].Severity == "" {
		t.Fatalf("a Mac's view %s ago: %+v", ViewFresh, conditions)
	}
	r.Observers[0].LastView = now.Add(-ViewFresh - time.Second)
	conditions = judged(t, r)
	if _, judgedPeer := conditions["peer:web2"]; judgedPeer || conditions["peer:self"].Severity == "" {
		t.Fatalf("a Mac's view past fresh: %+v", conditions)
	}
}

// A Mac that has sent a view and then goes quiet is a warning after 10
// minutes, counted from when this process started at the earliest. One
// that never sent a view is not watched yet.
func TestASilentMacIsAWarningOnceItHasSentAView(t *testing.T) {
	for _, tc := range []struct {
		lastView, started time.Duration
		message           string
	}{
		{0, time.Hour, ""},
		{ObserverSilent, time.Hour, ""},
		{25 * time.Minute, time.Hour, "mac has sent no views for 25 min"},
		{25 * time.Minute, 5 * time.Minute, ""},
	} {
		r := round(seen("web2", allOK))
		r.Started = now.Add(-tc.started)
		r.Observers = []Observer{{Name: "mac"}}
		if tc.lastView > 0 {
			r.Observers[0].LastView = now.Add(-tc.lastView)
		}
		c, found := judged(t, r)["peer:mac"]
		if found != (tc.message != "") || found && (c.Message != tc.message || c.Severity != state.SeverityWarning || c.Subject != "mac") {
			t.Fatalf("last view %s ago, started %s ago: %+v", tc.lastView, tc.started, c)
		}
	}
}

// reported judges a healthy peer whose summary says rep.
func reported(t *testing.T, rep Report) (watch.Condition, bool) {
	t.Helper()
	s := seen("web2", allOK)
	s.Report = &rep
	c, found := judged(t, round(s))["peer:web2"]
	return c, found
}

// A peer's backup older than BackupStale is a warning, the reserved app
// helios keeps for itself included, as is an app never backed up since
// it was deployed that long ago. It folds into whatever else is wrong,
// the graver severity standing.
func TestDeadManWarnsOnStaleBackup(t *testing.T) {
	c, _ := reported(t, Report{Backups: []Backup{
		{App: "shop", BackedUp: true, BackupAge: 3 * 24 * time.Hour},
		{App: "bedrock", BackedUp: true, BackupAge: 40 * time.Hour},
		{App: "blog", DeployedAge: 2 * 24 * time.Hour},
		{App: "notes", BackedUp: true, BackupAge: time.Hour},
		{App: "wiki", DeployedAge: time.Hour},
	}})
	if c.Severity != state.SeverityWarning || c.Message != "its last good backup of shop is 3 days old; its last good backup of bedrock is 40.0 h old; it has never backed up blog, deployed 2 days ago" {
		t.Fatalf("%+v", c)
	}

	stuck := Sight{Name: "web2", Paths: Paths{Summary: WordStale, TLS: WordOK, Public: WordOK}, LastGood: now.Add(-20 * time.Minute),
		Report: &Report{Backups: []Backup{{App: "shop", BackedUp: true, BackupAge: 3 * 24 * time.Hour}}}}
	c = judged(t, round(stuck))["peer:web2"]
	if c.Severity != state.SeverityCritical || !strings.HasSuffix(c.Message, "it cannot send its own alerts; its last good backup of shop is 3 days old") {
		t.Fatalf("folded into a stuck watcher: %+v", c)
	}
}

// A restore drill more than DrillGrace past due is a warning.
func TestDeadManWarnsOnOverdueDrill(t *testing.T) {
	c, _ := reported(t, Report{Backups: []Backup{
		{App: "shop", BackedUp: true, BackupAge: time.Hour, DrillOverdue: 2 * 24 * time.Hour},
		{App: "blog", BackedUp: true, BackupAge: time.Hour, DrillOverdue: 23 * time.Hour},
	}})
	if c.Severity != state.SeverityWarning || c.Message != "its restore drill for shop is 2 days overdue" {
		t.Fatalf("%+v", c)
	}
}

// An alert leg that hasn't worked within LegsFresh, or ever, is a
// warning, and names what the peer has open, since nobody may have heard.
func TestDeadManWarnsOnSilentLegs(t *testing.T) {
	c, _ := reported(t, Report{
		Legs: []Leg{{Name: "email", Worked: true, LastOK: time.Hour}, {Name: "pushover", Worked: true, LastOK: 9 * 24 * time.Hour}, {Name: "ntfy"}},
		Open: []OpenIncident{{Subject: "disk forecast", Severity: state.SeverityCritical}, {Subject: "shop", Severity: state.SeverityWarning}},
	})
	if c.Severity != state.SeverityWarning || c.Message != "its pushover alerts have not worked in 9 days; its ntfy alerts have never worked; open there: disk forecast (critical), shop (warning)" {
		t.Fatalf("%+v", c)
	}
}

// A peer whose backups, drills and legs are all within their limits, to
// the limit, says nothing, whatever it has open.
func TestDeadManQuietWhenFresh(t *testing.T) {
	c, found := reported(t, Report{
		Backups: []Backup{
			{App: "shop", BackedUp: true, BackupAge: watch.BackupStale, DrillOverdue: DrillGrace},
			{App: "blog", DeployedAge: watch.BackupStale},
		},
		Legs: []Leg{{Name: "email", Worked: true, LastOK: LegsFresh}},
		Open: []OpenIncident{{Subject: "shop", Severity: state.SeverityWarning}},
	})
	if found {
		t.Fatalf("%+v", c)
	}
}

type fakeNotifier struct{ sent []watch.Notice }

func (f *fakeNotifier) Notify(_ context.Context, n watch.Notice) error {
	f.sent = append(f.sent, n)
	return nil
}

// Peer findings are ordinary conditions: a host down opens and pages
// once it has held for OpenAfter rounds and recovers after ResolveAfter
// clean ones.
func TestPeerIncidentsFollowWatcherPatience(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	n := &fakeNotifier{}
	clock := now
	w := &watch.Watcher{Store: store, Notifier: n, Hostname: "web1", Now: func() time.Time { return clock }}
	watched := func(p Paths) *state.Incident {
		t.Helper()
		clock = clock.Add(time.Minute)
		r := round(Sight{Name: "web2", Paths: p, LastGood: now})
		r.Now = clock
		if err := w.Round(ctx, Judge(r)); err != nil {
			t.Fatal(err)
		}
		inc, err := store.OpenIncidentByKey(ctx, "peer:web2")
		if err != nil {
			t.Fatal(err)
		}
		return inc
	}
	for range watch.DefaultOpenAfter - 1 {
		if inc := watched(allDown); inc != nil {
			t.Fatalf("opened before it held: %+v", inc)
		}
	}
	if inc := watched(allDown); inc == nil || inc.Severity != state.SeverityCritical || len(n.sent) != 1 || n.sent[0].Subject != "web1: web2 is down" {
		t.Fatalf("host down after %d rounds: %+v, %+v", watch.DefaultOpenAfter, inc, n.sent)
	}
	for range watch.DefaultResolveAfter - 1 {
		if inc := watched(allOK); inc == nil {
			t.Fatal("resolved after one clean round")
		}
	}
	if inc := watched(allOK); inc != nil || len(n.sent) != 2 || n.sent[1].Subject != "web1: web2 recovered" {
		t.Fatalf("recovery after %d clean rounds: %+v, %+v", watch.DefaultResolveAfter, inc, n.sent)
	}
}
