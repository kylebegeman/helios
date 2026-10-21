package peer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// handoff is HandoffWait in rounds of a minute.
const handoff = int(HandoffWait / time.Minute)

// pager is web2 watching web1 and web3 through fake paths, its watch
// paging through a gate to its own fan-out, after a first round in which
// both answered. web1 sorts first, so it is to send each page about web3
// whenever its summary makes it a candidate.
type pager struct {
	*watcher
	gate   *Gate
	fanout *fakeNotifier
	wt     *watch.Watcher
}

func paging(t *testing.T) *pager {
	t.Helper()
	p := &pager{watcher: watchingAs(t, "web2", peerNamed("web1"), peerNamed("web3")), fanout: &fakeNotifier{}}
	p.gate = &Gate{Next: p.fanout, Source: p.src}
	p.wt = p.incidents(p.gate)
	p.rounds(t, 1)
	return p
}

// web1 makes web1 a machine that may send web3's pages, its summary
// showing what it has open and the keys it is sending.
func (p *pager) web1(open []SummaryIncident, sending ...string) {
	p.says("web1", Summary{Name: "web1", LastRoundAgeS: 30, SelfCheck: true,
		Findings: []Finding{{Key: "peer:web3", Severity: state.SeverityCritical}}, Incidents: open, Sending: sending})
}

// web3Open is web3's incident as web1's summary lists it: told that many
// seconds ago when told is set, and owed when owed is.
func web3Open(told *int64, owed bool) []SummaryIncident {
	return []SummaryIncident{{Key: "peer:web3", Subject: "web3", Severity: state.SeverityCritical, OpenedAgeS: 600, ToldAgeS: told, Owed: owed}}
}

// rounds runs n rounds of web2's watch, a minute apart.
func (p *pager) rounds(t *testing.T, n int) {
	t.Helper()
	for range n {
		p.round(t, p.wt)
	}
}

// told is what web2's own fan-out sent about key, by transition.
func (p *pager) told(key string) []string {
	var told []string
	for _, n := range p.fanout.sent {
		if n.Key == key {
			told = append(told, n.Transition)
		}
	}
	return told
}

// open is web2's open incident about key.
func (p *pager) open(t *testing.T, key string) state.Incident {
	t.Helper()
	inc, err := p.store.OpenIncidentByKey(context.Background(), key)
	if err != nil || inc == nil {
		t.Fatalf("%s isn't open: %v", key, err)
	}
	return *inc
}

// pending are the keys of web2's recoveries still to be told.
func (p *pager) pending(t *testing.T) []string {
	t.Helper()
	incidents, err := p.store.PendingResolvedIncidentNotices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, i := range incidents {
		keys = append(keys, i.Key)
	}
	return keys
}

// shown is how web2's summary shows its incident about key to the
// machines that read it.
func (p *pager) shown(t *testing.T, key string) SummaryIncident {
	t.Helper()
	s, err := Build(context.Background(), Deps{Store: p.store, Secrets: p.secrets, Root: t.TempDir(),
		Now: func() time.Time { return p.clock }, Last: p.src.Last}, "web2")
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range s.Incidents {
		if i.Key == key {
			return i
		}
	}
	t.Fatalf("web2's summary doesn't list %s: %+v", key, s.Incidents)
	return SummaryIncident{}
}

// restart is web2's daemon starting again: a new watch over the same
// store and secrets, which knows only what the sidecar kept.
func (p *pager) restart(t *testing.T) {
	t.Helper()
	if err := p.src.Save(); err != nil {
		t.Fatal(err)
	}
	p.crash()
}

// crash is web2's daemon stopped before it saves the sidecar, and
// started again.
func (p *pager) crash() {
	p.src = &Source{Secrets: p.secrets, Store: p.store, Now: p.src.Now, fetch: p.fetch, handshake: p.handshake, check: p.check}
	p.gate = &Gate{Next: p.gate.Next, Source: p.src}
	p.wt = p.incidents(p.gate)
}

// logging keeps every line web2's watch and its peer watch log, and
// returns them.
func (p *pager) logging() *[]string {
	lines := &[]string{}
	p.wt.Log = func(format string, args ...any) { *lines = append(*lines, fmt.Sprintf(format, args...)) }
	p.src.Log = p.wt.Log
	return lines
}

// fakeLeg is one leg of an observer's own fan-out, failing while failing
// is set.
type fakeLeg struct {
	failing bool
	got     []watch.Notice
}

func (l *fakeLeg) Notify(_ context.Context, n watch.Notice) error {
	if l.failing {
		return errors.New("refused")
	}
	l.got = append(l.got, n)
	return nil
}

// legs makes web2's fan-out two fake legs with a ledger, so a retry goes
// only to a leg that missed the notice.
func (p *pager) legs() (pushover, email *fakeLeg) {
	pushover, email = &fakeLeg{}, &fakeLeg{}
	p.gate.Next = &watch.Fanout{Legs: []watch.Leg{{Name: "pushover", Notifier: pushover}, {Name: "email", Notifier: email}},
		Ledger: &watch.Ledger{}, Now: func() time.Time { return p.clock }}
	return pushover, email
}

func transitions(notices []watch.Notice) []string {
	var got []string
	for _, n := range notices {
		got = append(got, n.Transition)
	}
	return got
}

// An observer that isn't to send a page holds it and says who is, never
// as a notice it owes. Once the sender's summary shows the page told, it
// stands down: its incident reads as told, sent by the sender, its own
// fan-out never sends it, and its summary doesn't show it told, so no
// third observer reads that as a page.
func TestDeferredObserverStandsDownWhenSenderTold(t *testing.T) {
	p := paging(t)
	p.web1(web3Open(nil, false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	if held := p.open(t, "peer:web3"); held.NotifyError != "web1 is to send this" || !held.NotifiedAt.IsZero() {
		t.Fatalf("held for web1: %+v", held)
	}
	if shown := p.shown(t, "peer:web3"); shown.Owed || shown.ToldAgeS != nil {
		t.Fatalf("a page held reads as owed or told: %+v", shown)
	}

	p.web1(web3Open(seconds(20), false))
	p.rounds(t, 1)
	told := p.open(t, "peer:web3")
	if told.NotifyError != "" || told.NotifiedAt.IsZero() {
		t.Fatalf("web1 told it: %+v", told)
	}
	p.rounds(t, 2*handoff)
	if got := p.told("peer:web3"); got != nil {
		t.Fatalf("web2 sent %v as well", got)
	}
	if shown := p.shown(t, "peer:web3"); shown.Owed || shown.ToldAgeS != nil {
		t.Fatalf("web2's summary shows web1's page as its own: %+v", shown)
	}
	if err := p.src.Save(); err != nil {
		t.Fatal(err)
	}
	sidecar, err := ReadSidecar(p.store)
	if by, _, ok := sidecar.SentBy(told); err != nil || !ok || by != "web1" {
		t.Fatalf("sent by %q, %v (%v)", by, ok, err)
	}
}

// When the sender's summary never shows the page told, the observer
// holding it sends it through its own fan-out once HandoffWait has passed
// since it first held it, once. The page carries the subject's name as
// its host, as it does from any observer.
func TestDeferredObserverSendsAfterHandoffWait(t *testing.T) {
	p := paging(t)
	p.web1(web3Open(nil, false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter+handoff-1)
	if got := p.told("peer:web3"); got != nil {
		t.Fatalf("sent %v before HandoffWait", got)
	}
	p.rounds(t, 1)
	if got := p.told("peer:web3"); !slices.Equal(got, []string{watch.TransitionOpen}) || p.fanout.sent[0].Host != "web3" {
		t.Fatalf("after HandoffWait: %v, %+v", got, p.fanout.sent)
	}
	if shown := p.shown(t, "peer:web3"); shown.ToldAgeS == nil || shown.Owed {
		t.Fatalf("web2 told it itself: %+v", shown)
	}
	p.rounds(t, 2*handoff)
	if got := p.told("peer:web3"); len(got) != 1 {
		t.Fatalf("sent again: %v", got)
	}
}

// noting is a fan-out that notes, while it has a notice, the keys this
// machine's summary says it is sending.
type noting struct {
	fakeNotifier
	src     *Source
	sending [][]string
}

func (n *noting) Notify(ctx context.Context, notice watch.Notice) error {
	n.sending = append(n.sending, n.src.Last().Sending)
	return n.fakeNotifier.Notify(ctx, notice)
}

// A sender still passing a page to its fan-out is given one more
// HandoffWait, even when its summary shows its last try failed: the
// observer holding the page doesn't send it while the sender may yet,
// and stands down once it has. A sender stuck sending past that is
// covered, and the observer's own summary shows the page sending while
// its fan-out has it.
func TestInFlightSenderIsNotDoubled(t *testing.T) {
	p := paging(t)
	p.web1(web3Open(nil, true), "peer:web3")
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter+2*handoff-1)
	if got := p.told("peer:web3"); got != nil {
		t.Fatalf("sent %v while web1 was sending", got)
	}
	p.web1(web3Open(seconds(20), false))
	p.rounds(t, 2*handoff)
	if got := p.told("peer:web3"); got != nil {
		t.Fatalf("sent %v after web1 told it", got)
	}

	p = paging(t)
	fanout := &noting{src: p.src}
	p.gate.Next = fanout
	p.web1(web3Open(nil, true), "peer:web3")
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter+2*handoff-1)
	if len(fanout.sent) != 0 {
		t.Fatalf("sent %+v before two HandoffWaits", fanout.sent)
	}
	p.rounds(t, 1)
	if len(fanout.sent) != 1 || !slices.Equal(fanout.sending[0], []string{"peer:web3"}) || len(p.src.Last().Sending) != 0 {
		t.Fatalf("web1 stuck sending: sent %+v, sending %v then %v", fanout.sent, fanout.sending, p.src.Last().Sending)
	}
}

type panickingFanout struct {
	src     *Source
	sending []string
}

func (f *panickingFanout) Notify(context.Context, watch.Notice) error {
	f.sending = f.src.Last().Sending
	panic("a defect in alert delivery")
}

// The watch catches a notifier panic as a failed notice. The peer gate
// must also end its in-flight marker, so another observer can cover it
// without waiting for a send that has already stopped.
func TestAPanickingSenderNoLongerReadsAsSending(t *testing.T) {
	p := paging(t)
	fanout := &panickingFanout{src: p.src}
	p.gate.Next = fanout
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	if !slices.Equal(fanout.sending, []string{"peer:web3"}) {
		t.Fatalf("the page was not shown sending while delivery had it: %v", fanout.sending)
	}
	if inc := p.open(t, "peer:web3"); inc.NotifyError == "" || !inc.NotifiedAt.IsZero() {
		t.Fatal("the panicking notifier was not recorded as a failed notice")
	}
	if got := p.src.Last().Sending; len(got) != 0 {
		t.Fatalf("a send that panicked is still shown in flight: %v", got)
	}
	p.gate.Next = p.fanout
	p.rounds(t, 1)
	if inc := p.open(t, "peer:web3"); inc.NotifyError != "" || inc.NotifiedAt.IsZero() || len(p.fanout.sent) != 1 {
		t.Fatal("the failed page was not retried successfully")
	}
}

// A sender whose summary shows a page owed, every leg of its fan-out
// having failed, is covered at once: the observer holding the page sends
// it through its own fan-out without waiting out HandoffWait, and the
// sender telling it later doesn't make the observer send it again.
func TestSenderWithFailedLegsIsCoveredByAnother(t *testing.T) {
	p := paging(t)
	p.web1(web3Open(nil, true))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	if got := p.told("peer:web3"); !slices.Equal(got, []string{watch.TransitionOpen}) {
		t.Fatalf("with web1 owing it: %v", got)
	}
	p.web1(web3Open(seconds(20), false))
	p.rounds(t, 2*handoff)
	if got := p.told("peer:web3"); len(got) != 1 {
		t.Fatalf("sent again: %v", got)
	}
}

// A page this machine told on some legs while another missed it is
// finished here, on the legs that missed it, even once another observer
// becomes the one to send it.
func TestAPageToldOnSomeLegsIsFinishedHere(t *testing.T) {
	p := paging(t)
	pushover, email := p.legs()
	email.failing = true
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	if len(pushover.got) != 1 || p.open(t, "peer:web3").NotifyError == "" {
		t.Fatalf("told on pushover alone: %+v", p.open(t, "peer:web3"))
	}

	p.web1(web3Open(nil, false))
	email.failing = false
	p.rounds(t, 1)
	if len(pushover.got) != 1 || len(email.got) != 1 || p.open(t, "peer:web3").NotifyError != "" {
		t.Fatalf("finished: pushover %d, email %d, %+v", len(pushover.got), len(email.got), p.open(t, "peer:web3"))
	}
}

// A page this machine held for another observer and then sends goes out
// on every leg of its fan-out, even when an earlier notice of the same
// kind reached some legs here and not others.
func TestAHeldPageGoesOutOnEveryLeg(t *testing.T) {
	p := paging(t)
	p.wt.Renotify = 10 * time.Minute
	pushover, email := p.legs()
	// web3's mesh fails while its public URL answers: a warning.
	p.fail("web3", pathSummary, syscall.ECONNREFUSED)
	p.fail("web3", pathTLS, syscall.ECONNREFUSED)
	p.rounds(t, watch.DefaultOpenAfter)
	email.failing = true
	p.rounds(t, 10)
	if got := transitions(pushover.got); !slices.Equal(got, []string{watch.TransitionOpen, watch.TransitionRepeat}) {
		t.Fatalf("the open and a repeat on pushover: %v", got)
	}

	// web3 goes down altogether once web1 is to send its pages, and web1
	// never sends the page saying so.
	p.web1(web3Open(nil, false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	if held := p.open(t, "peer:web3"); held.Severity != state.SeverityCritical || held.NotifyError != "web1 is to send this" {
		t.Fatalf("the page that web3 is down is held for web1: %+v", held)
	}
	email.failing = false
	p.rounds(t, handoff)
	want := []string{watch.TransitionOpen, watch.TransitionRepeat, watch.TransitionRepeat}
	if got := transitions(pushover.got); !slices.Equal(got, want) || pushover.got[2].Severity != state.SeverityCritical {
		t.Fatalf("pushover had %v, want %v", got, want)
	}
}

// A recovery goes from whoever told the incident opened. This machine
// sends its own; another observer's is that observer's to send, once it
// no longer lists the incident; and an observer out of sight for
// HandoffWait has its recovery sent here.
func TestRecoveryIsSentByWhoeverToldTheOpen(t *testing.T) {
	p := paging(t)
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	p.up("web3")
	p.rounds(t, watch.DefaultResolveAfter)
	if got := p.told("peer:web3"); !slices.Equal(got, []string{watch.TransitionOpen, watch.TransitionResolved}) || p.fanout.sent[1].Host != "web3" {
		t.Fatalf("web2 told the open: %v", got)
	}

	p = paging(t)
	p.web1(web3Open(seconds(20), false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	p.up("web3")
	p.rounds(t, watch.DefaultResolveAfter+handoff)
	if got := p.pending(t); !slices.Equal(got, []string{"peer:web3"}) {
		t.Fatalf("the recovery isn't held while web1 lists web3: %v", got)
	}
	p.web1(nil)
	p.rounds(t, 1)
	if got, pending := p.told("peer:web3"), p.pending(t); got != nil || pending != nil {
		t.Fatalf("web1 told the open: sent %v, pending %v", got, pending)
	}

	p = paging(t)
	p.web1(web3Open(seconds(20), false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	p.up("web3")
	p.down("web1")
	p.rounds(t, watch.DefaultResolveAfter+handoff-1)
	if got := p.told("peer:web3"); got != nil {
		t.Fatalf("sent %v before web1 was out of sight for HandoffWait", got)
	}
	p.rounds(t, 1)
	if got, pending := p.told("peer:web3"), p.pending(t); !slices.Equal(got, []string{watch.TransitionResolved}) || pending != nil {
		t.Fatalf("web1 out of sight: sent %v, pending %v", got, pending)
	}
}

// A repeat this machine sent while the observer that paged the outage
// was out of its sight leaves the recovery with that observer, which told
// the outage first: it would send its own, and two would go.
func TestARepeatSentHereLeavesTheRecoveryWithTheSender(t *testing.T) {
	p := paging(t)
	p.wt.Renotify = 10 * time.Minute
	p.web1(web3Open(seconds(20), false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	p.fail("web1", pathSummary, syscall.ECONNREFUSED)
	p.rounds(t, 10)
	if got := p.told("peer:web3"); !slices.Equal(got, []string{watch.TransitionRepeat}) {
		t.Fatalf("web1 out of sight at the repeat: %v", got)
	}
	p.up("web1", "web3")
	p.rounds(t, watch.DefaultResolveAfter+1)
	p.web1(nil)
	p.rounds(t, 1)
	if got, pending := p.told("peer:web3"), p.pending(t); !slices.Equal(got, []string{watch.TransitionRepeat}) || pending != nil {
		t.Fatalf("web1 paged the outage: sent %v, pending %v", got, pending)
	}
}

// A recovery held for the observer that told the incident stays held for
// as long as that observer lists the incident, past HandoffWait: it has
// its own incident open, and sends the recovery when it closes it. Once
// that observer has been out of sight for HandoffWait, the recovery goes
// from here, once. A hold, of a page or a recovery, is a wait: it is
// logged once, and never as an alert that wasn't delivered.
func TestAHeldRecoveryWaitsWhileTheSenderListsIt(t *testing.T) {
	p := paging(t)
	logged := p.logging()
	p.web1(web3Open(nil, false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter+1)
	p.web1(web3Open(seconds(20), false))
	p.rounds(t, 1)
	p.up("web3")
	p.rounds(t, watch.DefaultResolveAfter+2*handoff)
	if got, pending := p.told("peer:web3"), p.pending(t); got != nil || !slices.Equal(pending, []string{"peer:web3"}) {
		t.Fatalf("held past HandoffWait while web1 lists web3: sent %v, pending %v", got, pending)
	}
	p.down("web1")
	p.rounds(t, handoff-1)
	if got := p.told("peer:web3"); got != nil {
		t.Fatalf("sent %v before web1 was out of sight for HandoffWait", got)
	}
	p.rounds(t, 1)
	if got, pending := p.told("peer:web3"), p.pending(t); !slices.Equal(got, []string{watch.TransitionResolved}) || pending != nil {
		t.Fatalf("web1 out of sight for HandoffWait: sent %v, pending %v", got, pending)
	}

	var held []string
	for _, line := range *logged {
		if strings.HasPrefix(line, "alert not delivered") {
			t.Fatalf("a hold was logged as an alert not delivered:\n%s", strings.Join(*logged, "\n"))
		}
		if strings.HasPrefix(line, "alert held") {
			held = append(held, line)
		}
	}
	if want := []string{"alert held: web3: web1 is to send this", "alert held: web3: web1 is to send this"}; !slices.Equal(held, want) {
		t.Fatalf("logged %q, want the page's hold and the recovery's", held)
	}
}

// An observer that sees a peer's problem as a warning stands down on the
// warning another observer told, though that observer's incident has
// since grown critical and its critical went out on no leg: its summary
// lists the incident critical and owed, with the warning told.
func TestAWarningToldElsewhereIsNotRepeated(t *testing.T) {
	web1 := watchingAs(t, "web1", peerNamed("web2"), peerNamed("web3"))
	toldAt := web1.clock
	id := opened(t, web1.store, state.Incident{Key: "peer:web3", Subject: "web3", Severity: state.SeverityCritical,
		OpenedAt: toldAt.Add(-10 * time.Minute), NotifiedAt: toldAt, NotifyError: "pushover: refused"})
	last := Last{Sent: []Told{{IncidentID: id, Key: "peer:web3", Transition: watch.TransitionOpen, Severity: state.SeverityWarning, By: "web1", At: toldAt}}}
	p := paging(t)
	p.fail("web3", pathSummary, syscall.ECONNREFUSED)
	p.fail("web3", pathTLS, syscall.ECONNREFUSED)
	for range watch.DefaultOpenAfter + handoff + 2 {
		s, err := Build(context.Background(), Deps{Store: web1.store, Secrets: web1.secrets, Root: t.TempDir(),
			Now: func() time.Time { return p.clock }, Last: func() Last { return last }}, "web1")
		if err != nil {
			t.Fatal(err)
		}
		s.LastRoundAgeS, s.SelfCheck = 30, true
		s.Findings = []Finding{{Key: "peer:web3", Severity: state.SeverityCritical}}
		p.says("web1", s)
		p.rounds(t, 1)
	}
	if inc := p.open(t, "peer:web3"); inc.Severity != state.SeverityWarning || inc.NotifiedAt.IsZero() || inc.NotifyError != "" {
		t.Fatalf("web2's incident isn't a warning told elsewhere: %+v", inc)
	}
	if got := p.told("peer:web3"); got != nil {
		t.Fatalf("web2 repeated the warning web1 told: sent %v", got)
	}
}

// Nobody heard an incident opened that was held for its sender and never
// told, so nobody hears it recovered.
func TestNoRecoveryWhenNobodyToldTheOpen(t *testing.T) {
	p := paging(t)
	p.web1(web3Open(nil, false))
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	p.up("web3")
	p.rounds(t, watch.DefaultResolveAfter)
	if open := openIncidentKeys(t, p.store); open != nil {
		t.Fatalf("still open: %v", open)
	}
	p.rounds(t, 2*handoff)
	if got, pending := p.told("peer:web3"), p.pending(t); got != nil || pending != nil {
		t.Fatalf("sent %v, pending %v", got, pending)
	}
}

// A peer removed while its incident is open recovers quietly: it is no
// longer watched, so nobody hears it came back.
func TestRecoveryForARemovedPeerIsSwallowed(t *testing.T) {
	p := paging(t)
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	if _, _, err := Update(p.secrets, false, func(c *Config) error {
		c.Peers = slices.DeleteFunc(c.Peers, func(peer Peer) bool { return peer.Name == "web3" })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p.rounds(t, watch.DefaultResolveAfter)
	if open := openIncidentKeys(t, p.store); open != nil {
		t.Fatalf("still open: %v", open)
	}
	if got, pending := p.told("peer:web3"), p.pending(t); !slices.Equal(got, []string{watch.TransitionOpen}) || pending != nil {
		t.Fatalf("sent %v, pending %v", got, pending)
	}
}

// Notices about anything but another machine pass the gate as they are,
// this machine's own isolation among them, even while another observer
// is to send the pages about a peer. A notice about a peer goes out under
// the peer's name as its host and one about the edge provider under
// peers, so every observer's notice about one thing has one Pushover tag.
func TestOnlyNoticesAboutOtherMachinesAreGated(t *testing.T) {
	ctx := context.Background()
	p := paging(t)
	p.web1(nil)
	p.observe(t)
	err := p.gate.Notify(ctx, watch.Notice{IncidentID: 1, Key: "peer:web3", Transition: watch.TransitionOpen, Severity: state.SeverityCritical, Host: "web2"})
	if held := (*Deferred)(nil); !errors.As(err, &held) || held.To != "web1" {
		t.Fatalf("web3's page isn't held for web1: %v", err)
	}
	for _, n := range []watch.Notice{
		{IncidentID: 2, Key: "app:shop", Transition: watch.TransitionOpen, Severity: state.SeverityCritical, Host: "web2"},
		{IncidentID: 3, Key: "peer:self", Transition: watch.TransitionOpen, Severity: state.SeverityWarning, Host: "web2"},
		{IncidentID: 4, Key: "peer:edge-provider", Transition: watch.TransitionOpen, Severity: state.SeverityWarning, Host: "web2"},
	} {
		if err := p.gate.Notify(ctx, n); err != nil {
			t.Fatalf("%s: %v", n.Key, err)
		}
	}
	var hosts []string
	for _, n := range p.fanout.sent {
		hosts = append(hosts, n.Key+" "+n.Host)
	}
	if want := []string{"app:shop web2", "peer:self web2", "peer:edge-provider peers"}; !slices.Equal(hosts, want) {
		t.Fatalf("sent %v, want %v", hosts, want)
	}
}
