package peer

import (
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

var publicUp = Paths{Summary: "timeout", TLS: "timeout", Public: WordOK}

// view is a fresh view of web2 from an observer that passed its
// self-check.
func view(observer string, p Paths) View {
	return View{Observer: observer, Subject: "web2", Age: time.Minute, SelfCheck: true, Paths: p}
}

// A host down or a stuck watcher is critical only when a majority of the
// observers with a fresh view agree: this machine when its own public
// URL answers, or for a watcher always, and each other observer that
// passed its own self-check, once, by its latest view of that peer. A
// summary that is stale or refuses the key still answered, so the host
// is up, and a stale one agrees its watcher is stuck.
func TestCriticalNeedsAgreement(t *testing.T) {
	notChecked := view("mac", publicUp)
	notChecked.SelfCheck = false
	old := view("mac", publicUp)
	old.Age = 4 * time.Minute
	earlier := view("mac", allDown)
	earlier.Age = 2 * time.Minute
	ofWeb3 := func(p Paths) View {
		v := view("mac", p)
		v.Subject = "web3"
		return v
	}
	watcherDown := Paths{Summary: "refused", TLS: WordOK, Public: WordOK}
	for _, tc := range []struct {
		name      string
		web2      Paths
		selfCheck bool
		views     []View
		severity  string
	}{
		{"alone", allDown, true, nil, state.SeverityCritical},
		{"the Mac agrees", allDown, true, []View{view("mac", allDown)}, state.SeverityCritical},
		{"the Mac sees its public URLs", allDown, true, []View{view("mac", publicUp)}, state.SeverityWarning},
		{"the Mac's self-check failed", allDown, true, []View{notChecked}, state.SeverityCritical},
		{"the Mac's view is old", allDown, true, []View{old}, state.SeverityCritical},
		{"the Mac agrees, and sees web3's public URLs", allDown, true, []View{ofWeb3(publicUp), view("mac", allDown)}, state.SeverityCritical},
		{"the Mac sees its public URLs, and web3 down", allDown, true, []View{ofWeb3(allDown), view("mac", publicUp)}, state.SeverityWarning},
		{"the Mac's latest view sees its public URLs", allDown, true, []View{earlier, view("mac", publicUp)}, state.SeverityWarning},
		{"the Mac's latest view, sent first, sees its public URLs", allDown, true, []View{view("mac", publicUp), earlier}, state.SeverityWarning},
		{"the Mac's key is refused", allDown, true, []View{view("mac", Paths{WordUntrusted, "timeout", "timeout"})}, state.SeverityWarning},
		{"the Mac reads its summary stale", allDown, true, []View{view("mac", Paths{WordStale, "timeout", "timeout"})}, state.SeverityWarning},
		{"two of three", allDown, true, []View{view("web3", allDown), view("mac", publicUp)}, state.SeverityCritical},
		{"two of three, the Mac's view sent twice", allDown, true, []View{view("web3", allDown), view("mac", publicUp), view("mac", publicUp)}, state.SeverityCritical},
		{"one of three", allDown, true, []View{view("web3", publicUp), view("mac", publicUp)}, state.SeverityWarning},
		{"own self-check failed, nobody else", allDown, false, nil, state.SeverityWarning},
		{"own self-check failed, web3 agrees", allDown, false, []View{view("web3", allDown)}, state.SeverityCritical},
		{"watcher, the Mac reads its summary", watcherDown, true, []View{view("mac", allOK)}, state.SeverityWarning},
		{"watcher, the Mac's key is refused", watcherDown, true, []View{view("mac", Paths{WordUntrusted, WordOK, WordOK})}, state.SeverityWarning},
		{"watcher, the Mac reads it stale", watcherDown, true, []View{view("mac", Paths{WordStale, WordOK, WordOK})}, state.SeverityCritical},
		{"watcher, the Mac can't either", watcherDown, true, []View{view("mac", allDown)}, state.SeverityCritical},
		{"watcher, own self-check failed", watcherDown, false, nil, state.SeverityCritical},
	} {
		r := round(Sight{Name: "web2", Paths: tc.web2, LastGood: now.Add(-20 * time.Minute)}, seen("web3", allOK))
		r.SelfCheck, r.Views = tc.selfCheck, tc.views
		if c := judged(t, r)["peer:web2"]; c.Severity != tc.severity {
			t.Fatalf("%s: %+v, want %s", tc.name, c, tc.severity)
		}
	}
}

// A Mac's view of a peer counts toward agreeing for three minutes after
// it arrived and not after.
func TestMacViewsCountWhileFresh(t *testing.T) {
	for _, tc := range []struct {
		age      time.Duration
		severity string
	}{
		{ViewFresh - time.Second, state.SeverityWarning},
		{ViewFresh + time.Second, state.SeverityCritical},
	} {
		mac := view("mac", publicUp)
		mac.Age = tc.age
		r := round(seen("web2", allDown))
		r.Views = []View{mac}
		if c := judged(t, r)["peer:web2"]; c.Severity != tc.severity {
			t.Fatalf("a disagreeing view %s old: %+v, want %s", tc.age, c, tc.severity)
		}
	}
}

// A peer never votes on itself: its own word that it is fine doesn't
// outvote the observers that can't reach it.
func TestMajorityExcludesTheSubject(t *testing.T) {
	r := round(seen("web2", allDown))
	r.Views = []View{view("web2", allOK)}
	if c := judged(t, r)["peer:web2"]; c.Severity != state.SeverityCritical {
		t.Fatalf("%+v", c)
	}
}

// eligible is a candidate that may send a page about web1 at critical.
func eligible(name string) Candidate {
	return Candidate{Name: name, SelfCheck: true,
		Legs:     []Leg{{Name: "email", Worked: true, LastOK: time.Hour}, {Name: "pushover", Worked: true, LastOK: 2 * 24 * time.Hour}},
		Findings: []Finding{{Key: "peer:web1", Severity: state.SeverityCritical}}}
}

// The sender of a page is the lowest-named observer that isn't its
// subject, passed its self-check, has every alert leg working and sees
// the page at least as grave.
func TestSenderIsLowestNamedEligibleObserver(t *testing.T) {
	failedCheck := eligible("web2")
	failedCheck.SelfCheck = false
	quietLeg := eligible("web2")
	quietLeg.Legs[1].LastOK = LegsFresh + time.Hour
	neverWorked := eligible("web2")
	neverWorked.Legs = []Leg{{Name: "pushover"}}
	warningOnly := eligible("web2")
	warningOnly.Findings[0].Severity = state.SeverityWarning
	anotherPeer := eligible("web2")
	anotherPeer.Findings[0].Key = "peer:web3"
	for _, tc := range []struct {
		name       string
		severity   string
		candidates []Candidate
		sender     string
	}{
		{"all eligible", state.SeverityCritical, []Candidate{eligible("web4"), eligible("web1"), eligible("web3"), eligible("web2")}, "web2"},
		{"its self-check failed", state.SeverityCritical, []Candidate{eligible("web4"), failedCheck, eligible("web3")}, "web3"},
		{"a leg is quiet", state.SeverityCritical, []Candidate{eligible("web4"), quietLeg, eligible("web3")}, "web3"},
		{"a leg never worked", state.SeverityCritical, []Candidate{eligible("web4"), neverWorked, eligible("web3")}, "web3"},
		{"it sees only a warning", state.SeverityCritical, []Candidate{eligible("web4"), warningOnly, eligible("web3")}, "web3"},
		{"it found another peer critical", state.SeverityCritical, []Candidate{eligible("web4"), anotherPeer, eligible("web3")}, "web3"},
		{"it sees it graver", state.SeverityWarning, []Candidate{eligible("web4"), eligible("web2"), eligible("web3")}, "web2"},
	} {
		if got := Sender("web4", "peer:web1", tc.severity, tc.candidates); got != tc.sender {
			t.Fatalf("%s: %s sends, want %s", tc.name, got, tc.sender)
		}
	}
}

// When no observer has every leg working the legs aren't asked, and when
// none passed its self-check this machine sends rather than nobody.
func TestFallbackWhenNoCandidateQualifies(t *testing.T) {
	quiet := func(name string) Candidate {
		c := eligible(name)
		c.Legs[0].LastOK = LegsFresh + time.Hour
		return c
	}
	noLegs := eligible("web2")
	noLegs.Legs = nil
	failed := func(name string) Candidate {
		c := eligible(name)
		c.SelfCheck = false
		return c
	}
	for _, tc := range []struct {
		name       string
		candidates []Candidate
		sender     string
	}{
		{"every leg quiet", []Candidate{quiet("web4"), quiet("web3"), quiet("web2")}, "web2"},
		{"no legs set up", []Candidate{eligible("web4"), noLegs, eligible("web3")}, "web3"},
		{"every self-check failed", []Candidate{failed("web4"), failed("web2"), failed("web3")}, "web4"},
		{"nobody else", nil, "web4"},
	} {
		if got := Sender("web4", "peer:web1", state.SeverityCritical, tc.candidates); got != tc.sender {
			t.Fatalf("%s: %s sends, want %s", tc.name, got, tc.sender)
		}
	}
}

// A Mac only watches: it is never the sender, even with the lowest name
// and every leg working.
func TestMacIsNeverElectedSender(t *testing.T) {
	mac := eligible("mac")
	mac.ObserverOnly = true
	if got := Sender("web4", "peer:web1", state.SeverityCritical, []Candidate{mac, eligible("web3"), eligible("web4")}); got != "web3" {
		t.Fatalf("%s sends", got)
	}
	web3 := eligible("web3")
	web3.Legs = nil
	if got := Sender("web4", "peer:web1", state.SeverityCritical, []Candidate{mac, web3}); got != "web3" {
		t.Fatalf("with no server's legs working, %s sends", got)
	}
}
