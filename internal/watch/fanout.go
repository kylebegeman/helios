package watch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// What a notice announces about its incident.
const (
	TransitionOpen     = "open"
	TransitionRepeat   = "repeat"
	TransitionResolved = "resolved"
)

// How the fan-out delivers.
const (
	// LegTimeout bounds one leg's delivery when the leg sets no timeout.
	LegTimeout = 2 * time.Minute
	// LegRetryFirst is how long a leg that missed a notice waits before
	// it is tried again. Each further miss doubles the wait, up to
	// LegRetryMax.
	LegRetryFirst = time.Minute
	LegRetryMax   = 15 * time.Minute
)

// Leg is one way of telling a person.
type Leg struct {
	Name     string
	Notifier Notifier
	// MinSeverity is the least severe notice the leg carries; empty
	// carries every notice.
	MinSeverity string
	// Timeout bounds one delivery; zero means LegTimeout.
	Timeout time.Duration
}

// Fanout sends each notice to every leg that carries its severity, all
// at once, so a slow or broken leg never holds back another.
type Fanout struct {
	Legs []Leg
	// Ledger remembers which legs have had an incident's notice, so a
	// retry goes only to the ones that missed it. Nil remembers nothing.
	Ledger *Ledger
	Now    func() time.Time
}

// LegError is one leg's failure to deliver.
type LegError struct {
	Leg string
	Err error
}

// DeliveryError says which legs a notice didn't reach, and which it did.
// A notice some leg delivered has told the person; the rest are owed.
type DeliveryError struct {
	Failed    []LegError
	Delivered []string
}

func (e *DeliveryError) Error() string {
	parts := make([]string, 0, len(e.Failed))
	for _, f := range e.Failed {
		parts = append(parts, f.Leg+": "+f.Err.Error())
	}
	msg := strings.Join(parts, "; ")
	if len(e.Delivered) > 0 {
		msg += "; delivered by " + strings.Join(e.Delivered, ", ")
	}
	return msg
}

// Partial reports whether some leg delivered the notice.
func (e *DeliveryError) Partial() bool { return len(e.Delivered) > 0 }

// Notify implements Notifier. It returns nil once every leg that carries
// the notice has it, and a *DeliveryError otherwise.
func (f *Fanout) Notify(ctx context.Context, n Notice) error {
	var legs []Leg
	for _, l := range f.Legs {
		if carries(l.MinSeverity, n.Severity) {
			legs = append(legs, l)
		}
	}
	if len(legs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	if f.Now != nil {
		now = f.Now()
	}
	ledger := f.Ledger
	if ledger == nil || n.IncidentID == 0 {
		ledger = &Ledger{}
	}
	entry, due := ledger.start(n, legs, now)

	results := make([]error, len(due))
	var wg sync.WaitGroup
	for i, l := range due {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = deliver(ctx, l, n)
		}()
	}
	wg.Wait()
	return ledger.finish(n.IncidentID, entry, legs, due, results, now)
}

// deliver sends through one leg within its timeout. A leg that panics
// has failed; it never takes the others down.
func deliver(ctx context.Context, l Leg, n Notice) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed unexpectedly: %v", r)
		}
	}()
	timeout := l.Timeout
	if timeout <= 0 {
		timeout = LegTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return l.Notifier.Notify(ctx, n)
}

// carries reports whether a leg that takes least and up takes severity.
// A notice without a severity counts as a warning.
func carries(least, severity string) bool {
	return least == "" || severityRank(severity) >= severityRank(least)
}

func severityRank(severity string) int {
	switch severity {
	case state.SeverityNotice:
		return 0
	case state.SeverityCritical:
		return 2
	default:
		return 1
	}
}

// Ledger remembers, for each incident, which legs have its latest
// notice. It lives in memory: after a restart a retry goes to every leg,
// which can repeat a notice but never loses one.
type Ledger struct {
	mu      sync.Mutex
	sending map[int64]*sending
}

// sending is one notice on its way to its legs.
type sending struct {
	transition string
	legs       map[string]*legState
}

type legState struct {
	delivered bool
	misses    int
	next      time.Time
	err       error
}

// start returns the notice's entry and the legs to send it through now:
// every leg for a new notice; for a retry, the legs that missed it and
// have waited out their backoff.
func (l *Ledger) start(n Notice, legs []Leg, now time.Time) (*sending, []Leg) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sending == nil {
		l.sending = map[int64]*sending{}
	}
	entry := l.sending[n.IncidentID]
	if !n.Retry || entry == nil || entry.transition != n.Transition {
		entry = &sending{transition: n.Transition, legs: map[string]*legState{}}
		l.sending[n.IncidentID] = entry
	}
	var due []Leg
	for _, leg := range legs {
		s := entry.legs[leg.Name]
		if s == nil {
			s = &legState{}
			entry.legs[leg.Name] = s
		}
		if !s.delivered && !now.Before(s.next) {
			due = append(due, leg)
		}
	}
	return entry, due
}

// finish records what the legs did and says where the notice stands.
func (l *Ledger) finish(id int64, entry *sending, legs, due []Leg, results []error, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, leg := range due {
		s := entry.legs[leg.Name]
		if results[i] == nil {
			s.delivered, s.err = true, nil
			continue
		}
		s.misses++
		s.err = results[i]
		s.next = now.Add(retryAfter(s.misses))
	}
	failed := &DeliveryError{}
	for _, leg := range legs {
		switch s := entry.legs[leg.Name]; {
		case s.delivered:
			failed.Delivered = append(failed.Delivered, leg.Name)
		case s.err != nil:
			failed.Failed = append(failed.Failed, LegError{Leg: leg.Name, Err: s.err})
		default:
			failed.Failed = append(failed.Failed, LegError{Leg: leg.Name, Err: errors.New("not tried yet")})
		}
	}
	if len(failed.Failed) > 0 {
		return failed
	}
	if l.sending[id] == entry {
		delete(l.sending, id)
	}
	return nil
}

// retryAfter is how long a leg waits after its nth miss in a row.
func retryAfter(misses int) time.Duration {
	wait := LegRetryFirst
	for i := 1; i < misses && wait < LegRetryMax; i++ {
		wait *= 2
	}
	return min(wait, LegRetryMax)
}
