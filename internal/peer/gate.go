package peer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/watch"
)

// HandoffWait is how long an observer that isn't to send a peer page
// waits for the one that is before it sends the page itself.
const HandoffWait = 5 * time.Minute

// sameTell is how near this machine's last record another observer's
// told time may fall and still be the tell already recorded. A told time
// is worked out from an age in a summary that can be a SummaryCache old,
// as of a round that can take a RoundDeadline to look, so the same tell
// reads a little later from one round to the next.
const sameTell = time.Minute

// Deferred is a peer notice held back because another observer, To, is
// to send it. The watcher keeps it as the incident's notify error and
// asks again next round.
type Deferred struct {
	To string
}

func (d *Deferred) Error() string { return d.To + " is to send this" }

// Held implements watch.Held: a notice held for another observer is a
// wait, never a delivery that failed.
func (d *Deferred) Held() bool { return true }

// deferredTo reads an incident's notify error as a deferral, and the
// observer the notice is held for. Whichever observer it is, a notice
// held is waiting, not owed.
func deferredTo(notifyError string) (string, bool) {
	to, ok := strings.CutSuffix(notifyError, (&Deferred{}).Error())
	return to, ok && ValidName(to)
}

// Gate sends each notice about a peer from one machine. Every observer
// that sees a peer go down opens its own incident; the gate lets the one
// elected by Sender page through its own fan-out, stands the rest down
// once a summary shows it told, and has another page after HandoffWait
// when it doesn't. A recovery goes from whoever told the incident at its
// gravest.
// Notices about anything else, and peer watch's own isolation, pass
// straight through.
type Gate struct {
	Next   watch.Notifier
	Source *Source
}

// Notify implements watch.Notifier. Every notice about one peer carries
// the same host, so it carries the same Pushover tag from any observer,
// and a recovery from any of them ends an emergency any of them raised.
// A notice about a machine no longer watched goes nowhere.
func (g *Gate) Notify(ctx context.Context, n watch.Notice) error {
	if !gated(n.Key) {
		return g.Next.Notify(ctx, n)
	}
	n.Host = sharedHost(n.Key)
	c, err := Load(g.Source.Secrets)
	switch {
	case errors.Is(err, ErrNotSet):
		return nil
	case err != nil:
		return fmt.Errorf("peer watch can't tell who sends this: %w", err)
	case !c.watches(n.Key):
		return nil
	case n.Transition == watch.TransitionResolved:
		return g.recovered(ctx, c.Self.Name, n)
	}
	return g.page(ctx, c.Self.Name, n)
}

// page decides an open or repeat notice. It stands down when another
// observer's summary shows it told the notice since this machine last
// recorded one, finishes a notice this machine told on the legs that
// missed it, and sends a notice this machine is elected to. Otherwise it
// holds the notice for the sender until HandoffWait has passed, or the
// sender shows it owes the notice, and then sends it itself. A sender
// still passing the notice to its fan-out gets one more HandoffWait.
func (g *Gate) page(ctx context.Context, self string, n watch.Notice) error {
	s := g.Source
	mine := Candidate{Name: self}
	// Legs that can't be read only make this machine a less likely sender.
	if ls, err := legs(ctx, s.Store, s.Secrets, s.now()); err == nil {
		for _, l := range ls {
			mine.Legs = append(mine.Legs, l.leg())
		}
	}
	now := s.now()
	s.mu.Lock()
	finishing := s.decide(self, n)
	if by, at, ok := s.toldElsewhere(n); ok {
		s.record(n, by, at)
		s.mu.Unlock()
		return nil
	}
	if finishing {
		s.mu.Unlock()
		return g.send(ctx, n, true)
	}
	mine.SelfCheck, mine.Findings = s.last.SelfCheck, s.last.Findings
	candidates := []Candidate{mine}
	for _, summary := range s.seen {
		candidates = append(candidates, summary.candidate())
	}
	sender := Sender(self, n.Key, n.Severity, candidates)
	if sender == self {
		s.forget(n.IncidentID)
		s.mu.Unlock()
		return g.send(ctx, n, false)
	}
	held := s.hold(n, sender, now)
	waited := now.Sub(later(held.Since, s.started))
	theirs := s.seen[sender]
	due := waited >= HandoffWait || theirs.owes(n.Key)
	if due && theirs.sends(n.Key) {
		due = waited >= 2*HandoffWait
	}
	s.mu.Unlock()
	if due {
		return g.send(ctx, n, false)
	}
	return &Deferred{To: sender}
}

// recovered decides a recovery. It goes from the teller, and to nobody
// when nobody told the incident. Another observer's recovery is its own
// once its summary no longer lists the incident, and this machine holds
// it while that observer still does, for HandoffWait at most: by then the
// observer, in sight with its incident still open, sends the recovery
// when it closes it. An observer out of sight for HandoffWait has its
// recovery sent from here.
func (g *Gate) recovered(ctx context.Context, self string, n watch.Notice) error {
	s := g.Source
	now := s.now()
	s.mu.Lock()
	finishing := s.decide(self, n)
	teller, told := s.teller(n.IncidentID)
	switch {
	case finishing, told && teller.By == self:
		s.forget(n.IncidentID)
		s.mu.Unlock()
		return g.send(ctx, n, finishing)
	case !told:
		s.forget(n.IncidentID)
		s.mu.Unlock()
		return nil
	}
	theirs, seen := s.seen[teller.By]
	since := later(s.hold(n, teller.By, now).Since, s.started)
	if seen && (!theirs.lists(n.Key) || now.Sub(since) >= HandoffWait) {
		s.forget(n.IncidentID)
		s.mu.Unlock()
		return nil
	}
	due := !seen && now.Sub(later(s.lastGood[teller.By], since)) >= HandoffWait
	s.mu.Unlock()
	if due {
		return g.send(ctx, n, false)
	}
	return &Deferred{To: teller.By}
}

// decide starts deciding a notice for this machine, named self, and
// reports whether the notice finishes one this machine told while some
// leg missed it. The watcher asks again only while a notice hasn't
// arrived everywhere, so any other notice ends what this machine's last
// try missed. The caller holds mu.
func (s *Source) decide(self string, n watch.Notice) bool {
	s.begin()
	s.self = self
	m, tried := s.missed[n.IncidentID]
	if !tried || !n.Retry || m.transition != n.Transition {
		delete(s.missed, n.IncidentID)
		return false
	}
	return m.told
}

// send passes the notice to this machine's own fan-out, showing it in
// this machine's summary while it goes. A notice any leg delivered is
// recorded as told by this machine, unless it finishes one already told.
// Next's error comes back unchanged, so the watcher retries the legs that
// missed it.
func (g *Gate) send(ctx context.Context, n watch.Notice, finishing bool) error {
	s := g.Source
	s.mu.Lock()
	// The fan-out sends a retry only to the legs that missed its last try
	// and have waited out their backoff. A notice held until now was never
	// tried here, so it goes to every leg.
	_, tried := s.missed[n.IncidentID]
	n.Retry = n.Retry && tried
	s.sending[n.Key]++
	s.mu.Unlock()
	err := g.Next.Notify(ctx, n)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sending[n.Key]--; s.sending[n.Key] <= 0 {
		delete(s.sending, n.Key)
	}
	var missed *watch.DeliveryError
	told := err == nil || errors.As(err, &missed) && missed.Partial()
	if err == nil {
		delete(s.missed, n.IncidentID)
	} else {
		s.missed[n.IncidentID] = miss{transition: n.Transition, told: told || finishing}
	}
	if told && !finishing {
		s.record(n, s.self, s.now())
	}
	return err
}

// miss is a notice this machine passed to its fan-out that some leg
// missed: its transition, and whether another leg had it.
type miss struct {
	transition string
	told       bool
}

// toldElsewhere finds the observer whose summary this round shows it
// told the notice's incident at the notice's severity or graver: since
// this machine's last record of it, or at any time when there is none.
// It is the earliest to tell, and the lowest named of those that told at
// once. The caller holds mu.
func (s *Source) toldElsewhere(n watch.Notice) (by string, at time.Time, ok bool) {
	last, recorded := s.latest(n.IncidentID)
	for name, summary := range s.seen {
		for _, i := range summary.Incidents {
			if i.Key != n.Key || i.ToldAgeS == nil || rank(i.Severity) < rank(n.Severity) {
				continue
			}
			told := s.last.Looked.Add(-elapsed(*i.ToldAgeS))
			if recorded && !told.After(last.At.Add(sameTell)) {
				continue
			}
			if !ok || told.Before(at) || told.Equal(at) && name < by {
				by, at, ok = name, told, true
			}
		}
	}
	return by, at, ok
}

// latest is the incident's latest told record. The caller holds mu.
func (s *Source) latest(incident int64) (Told, bool) {
	var found Told
	ok := false
	for _, t := range s.told {
		if t.IncidentID == incident && (!ok || !t.At.Before(found.At)) {
			found, ok = t, true
		}
	}
	return found, ok
}

// teller is the incident's told record its recovery goes by: the first
// at its gravest severity. Every observer that stood down on that notice
// recorded it, and none that told a lesser notice earlier, or repeated
// the notice later, reads another teller from its own records. The caller
// holds mu.
func (s *Source) teller(incident int64) (Told, bool) {
	var found Told
	ok := false
	for _, t := range s.told {
		if t.IncidentID != incident {
			continue
		}
		graver, same := rank(t.Severity) > rank(found.Severity), rank(t.Severity) == rank(found.Severity)
		if !ok || graver || same && t.At.Before(found.At) {
			found, ok = t, true
		}
	}
	return found, ok
}

// record keeps that by told the notice at at, which ends any hold on it.
// The caller holds mu.
func (s *Source) record(n watch.Notice, by string, at time.Time) {
	s.told = append(s.told, Told{IncidentID: n.IncidentID, Key: n.Key, Transition: n.Transition, Severity: n.Severity, By: by, At: at})
	s.forget(n.IncidentID)
}

// hold holds the notice for to, from when this machine first held the
// notice's transition, and returns the hold. The caller holds mu.
func (s *Source) hold(n watch.Notice, to string, now time.Time) Deferral {
	held := Deferral{IncidentID: n.IncidentID, Key: n.Key, Transition: n.Transition, Since: now}
	for _, d := range s.deferring {
		if d.IncidentID == n.IncidentID && d.Transition == n.Transition {
			held.Since = d.Since
		}
	}
	held.To = to
	s.forget(n.IncidentID)
	s.deferring = append(s.deferring, held)
	return held
}

// forget lets go of any hold on the incident's notice. The caller holds
// mu.
func (s *Source) forget(incident int64) {
	kept := s.deferring[:0]
	for _, d := range s.deferring {
		if d.IncidentID != incident {
			kept = append(kept, d)
		}
	}
	s.deferring = kept
}

// candidate is the machine a summary is from, as a possible sender.
func (s Summary) candidate() Candidate {
	c := Candidate{Name: s.Name, SelfCheck: s.SelfCheck, Findings: s.Findings}
	for _, l := range s.Legs {
		c.Legs = append(c.Legs, l.leg())
	}
	return c
}

// lists reports whether the summary shows key open, owes whether it shows
// its notice failed to go out, and sends whether its gate is passing that
// notice to its fan-out right now.
func (s Summary) lists(key string) bool {
	for _, i := range s.Incidents {
		if i.Key == key {
			return true
		}
	}
	return false
}

func (s Summary) owes(key string) bool {
	for _, i := range s.Incidents {
		if i.Key == key && i.Owed {
			return true
		}
	}
	return false
}

func (s Summary) sends(key string) bool {
	for _, k := range s.Sending {
		if k == key {
			return true
		}
	}
	return false
}

// gated reports whether a notice about key is one every observer may
// send: about a peer, a Mac or the edge provider, never about this
// machine's own isolation.
func gated(key string) bool {
	return strings.HasPrefix(key, keyPrefix) && key != keyPrefix+selfName
}

// sharedHost is the host every observer gives a notice about key: the
// machine's name, or peers for the edge provider.
func sharedHost(key string) string {
	subject := strings.TrimPrefix(key, keyPrefix)
	if subject == edgeProviderName {
		return "peers"
	}
	return subject
}

// watches reports whether key is about something this machine still
// watches: one of its peers, a Mac that reads it, or the edge provider
// while it has a peer.
func (c Config) watches(key string) bool {
	subject := strings.TrimPrefix(key, keyPrefix)
	if subject == edgeProviderName {
		return len(c.Peers) > 0
	}
	if _, ok := c.Observers[subject]; ok {
		return true
	}
	for _, p := range c.Peers {
		if p.Name == subject {
			return true
		}
	}
	return false
}
