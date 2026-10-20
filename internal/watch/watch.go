// Package watch keeps an eye on the machine and its apps and tells a
// person when something is wrong, once, and again when it is fixed. A
// condition has to hold for several rounds before it becomes an incident,
// so a blip never sends a mail, and an incident is one per subject, so an
// outage sends one notice however many checks it fails.
package watch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// Condition is one thing found wrong in a round.
type Condition struct {
	// Key names the subject: app:dragon-writer, host:disk, watch:<url>,
	// edge:origin-pull:<host>.
	Key      string
	Subject  string
	Severity string
	Message  string
	// Unknown holds an existing incident when its subject could not be
	// observed, without recording a failure or a clean recovery round.
	Unknown bool
}

// Notice is what a person gets told.
type Notice struct {
	Subject string
	Body    string
	// IncidentID is the incident the notice is about; zero for one that
	// isn't about an incident, such as a test or a deploy's outcome.
	IncidentID int64
	Key        string
	// Transition is what the notice announces: TransitionOpen,
	// TransitionRepeat or TransitionResolved.
	Transition string
	Severity   string
	Host       string
	// Retry asks for the notice again only where it hasn't arrived.
	Retry bool
}

// Notifier delivers notices.
type Notifier interface {
	Notify(ctx context.Context, n Notice) error
}

// Held is the error of a notice a notifier holds back on purpose, for
// someone else to send: a wait, not a failure. The incident keeps it as
// its notify error and the notice is asked for again each round, as a
// failed one is, but the watcher logs only when the hold begins or moves.
type Held interface {
	error
	Held() bool
}

// NoAlertsSetUp is the notify error of an incident nobody can be told
// about.
const NoAlertsSetUp = "no way to send alerts is set up; run helios integration set email"

// Defaults for the watcher's patience.
const (
	DefaultOpenAfter    = 3
	DefaultResolveAfter = 2
	DefaultRenotify     = 24 * time.Hour
)

// Watcher turns rounds of conditions into incidents and notices.
type Watcher struct {
	Store *state.Store
	// Notifier tells a person; nil records incidents and tells no one.
	Notifier Notifier
	Hostname string
	Now      func() time.Time
	// OpenAfter is how many rounds in a row a condition must hold before
	// an incident opens; ResolveAfter how many clean rounds close it.
	OpenAfter    int
	ResolveAfter int
	// Renotify is how often an open incident is repeated.
	Renotify time.Duration
	Log      func(format string, args ...any)

	failing map[string]int
	passing map[string]int
	// graver counts the rounds in a row an open incident's condition has
	// been graver than the incident, and milder the rounds it has been
	// milder.
	graver map[string]int
	milder map[string]int
	// owed holds each incident whose latest notice some leg missed.
	owed map[int64]owedNotice
}

// owedNotice is a notice that hasn't reached every leg yet.
type owedNotice struct {
	transition string
	// told is whether any leg delivered it.
	told bool
}

func (w *Watcher) init() {
	if w.failing == nil {
		w.failing = map[string]int{}
		w.passing = map[string]int{}
		w.graver = map[string]int{}
		w.milder = map[string]int{}
		w.owed = map[int64]owedNotice{}
	}
	if w.Now == nil {
		w.Now = func() time.Time { return time.Now().UTC() }
	}
	if w.OpenAfter <= 0 {
		w.OpenAfter = DefaultOpenAfter
	}
	if w.ResolveAfter <= 0 {
		w.ResolveAfter = DefaultResolveAfter
	}
	if w.Renotify <= 0 {
		w.Renotify = DefaultRenotify
	}
	if w.Log == nil {
		w.Log = func(string, ...any) {}
	}
}

// Round takes this round's conditions and updates incidents: opens the
// ones that held long enough, resolves the ones that cleared, and
// notifies about both.
func (w *Watcher) Round(ctx context.Context, conditions []Condition) error {
	w.init()
	now := w.Now()
	pending, err := w.Store.PendingResolvedIncidentNotices(ctx)
	if err != nil {
		return err
	}
	for _, incident := range pending {
		n := w.resolvedNotice(incident)
		n.Retry = true
		w.notify(ctx, &incident, n, now)
		if err := w.Store.UpdateIncident(ctx, incident); err != nil {
			return err
		}
	}
	current := map[string]Condition{}
	for _, c := range conditions {
		current[c.Key] = c
	}
	open, err := w.Store.OpenIncidents(ctx)
	if err != nil {
		return err
	}
	openByKey := map[string]state.Incident{}
	for _, inc := range open {
		openByKey[inc.Key] = inc
	}

	for key, c := range current {
		if c.Unknown {
			delete(w.failing, key)
			delete(w.passing, key)
			delete(w.graver, key)
			delete(w.milder, key)
			continue
		}
		w.failing[key]++
		w.passing[key] = 0
		inc, isOpen := openByKey[key]
		if !isOpen {
			if w.failing[key] < w.OpenAfter {
				continue
			}
			inc = state.Incident{Key: key, Subject: c.Subject, Severity: c.Severity, Message: c.Message, OpenedAt: now, Observations: w.failing[key]}
			id, err := w.Store.OpenIncident(ctx, inc)
			if err != nil {
				return err
			}
			inc.ID = id
			w.Log("alert: %s: %s", c.Subject, c.Message)
			w.notify(ctx, &inc, w.openNotice(inc), now)
			if err := w.Store.UpdateIncident(ctx, inc); err != nil {
				return err
			}
			continue
		}
		inc.Observations++
		// A notice is told once; it is repeated only once it needs
		// attention. An incident that grows graver, a notice that needs
		// attention or a warning that became an outage, is told at once
		// rather than at the next daily repeat. Like a new incident, the
		// graver severity has to hold for OpenAfter rounds first, so a
		// blip to critical never pages; until then the incident stays as
		// it was. A notice grows graver on the clock, not on a probe, so
		// it can't blip. Easing back, an outage back to a warning, has to
		// hold for ResolveAfter rounds, as a recovery does, so an outage
		// that flaps is one outage and told once.
		rank, was := severityRank(c.Severity), severityRank(inc.Severity)
		escalated := rank > was
		switch {
		case escalated && inc.Severity != state.SeverityNotice && w.graver[key]+1 < w.OpenAfter:
			w.graver[key]++
			delete(w.milder, key)
			c.Severity, c.Message, escalated = inc.Severity, inc.Message, false
		case rank < was && w.milder[key]+1 < w.ResolveAfter:
			w.milder[key]++
			delete(w.graver, key)
			c.Severity, c.Message = inc.Severity, inc.Message
		default:
			delete(w.graver, key)
			delete(w.milder, key)
		}
		inc.Message, inc.Severity = c.Message, c.Severity
		repeat := escalated || inc.Severity != state.SeverityNotice && !inc.NotifiedAt.IsZero() && now.Sub(inc.NotifiedAt) >= w.Renotify
		owed, isOwed := w.owed[inc.ID]
		switch {
		case isOwed && !repeat:
			// Only the legs that missed it hear it again.
			n := w.openNotice(inc)
			n.Transition, n.Retry = owed.transition, true
			w.notify(ctx, &inc, n, now)
		case repeat || inc.NotifiedAt.IsZero() || inc.NotifyError != "":
			w.notify(ctx, &inc, w.openNotice(inc), now)
		}
		if err := w.Store.UpdateIncident(ctx, inc); err != nil {
			return err
		}
	}

	for key, inc := range openByKey {
		if _, still := current[key]; still {
			continue
		}
		w.passing[key]++
		w.failing[key] = 0
		delete(w.graver, key)
		delete(w.milder, key)
		if w.passing[key] < w.ResolveAfter {
			continue
		}
		inc.ResolvedAt = now
		w.Log("recovered: %s", inc.Subject)
		w.notify(ctx, &inc, w.resolvedNotice(inc), now)
		if err := w.Store.UpdateIncident(ctx, inc); err != nil {
			return err
		}
		delete(w.passing, key)
	}

	for key := range w.failing {
		if _, ok := current[key]; !ok {
			if _, ok := openByKey[key]; !ok {
				delete(w.failing, key)
				delete(w.passing, key)
				delete(w.graver, key)
				delete(w.milder, key)
			}
		}
	}
	return nil
}

// notify sends a notice and records the outcome on the incident. A
// notice any leg delivered has told the person; a leg that missed it is
// kept as the incident's notify error and tried again next round.
func (w *Watcher) notify(ctx context.Context, inc *state.Incident, n Notice, now time.Time) {
	if w.Notifier == nil {
		inc.NotifyError = NoAlertsSetUp
		return
	}
	err := w.Notifier.Notify(ctx, n)
	var missed *DeliveryError
	told := err == nil || errors.As(err, &missed) && missed.Partial()
	before, retried := w.owed[inc.ID]
	retried = retried && n.Retry && before.transition == n.Transition
	// A retry that completes a told notice doesn't restart the clock
	// for the next repeat.
	if told && !(retried && before.told) {
		inc.NotifiedAt = now
	}
	if err == nil {
		inc.NotifyError = ""
		delete(w.owed, inc.ID)
		return
	}
	was := inc.NotifyError
	inc.NotifyError = err.Error()
	w.owed[inc.ID] = owedNotice{transition: n.Transition, told: told || retried && before.told}
	var held Held
	if errors.As(err, &held) && held.Held() {
		if inc.NotifyError != was {
			w.Log("alert held: %s: %v", inc.Subject, err)
		}
		return
	}
	w.Log("alert not delivered: %v", err)
}

func (w *Watcher) openNotice(inc state.Incident) Notice {
	word, again := "has a problem", fmt.Sprintf("You'll hear again when it recovers, or in %s if it doesn't.", w.Renotify)
	switch inc.Severity {
	case state.SeverityCritical:
		word = "is down"
	case state.SeverityNotice:
		word, again = "is held by an operator", "You'll hear again if it needs attention, and when it ends."
	}
	subject := fmt.Sprintf("%s: %s %s", w.Hostname, inc.Subject, word)
	transition := TransitionRepeat
	if inc.NotifiedAt.IsZero() {
		transition = TransitionOpen
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", inc.Message)
	fmt.Fprintf(&b, "Since %s (%s), seen in %d rounds.\n", inc.OpenedAt.Format("2006-01-02 15:04 UTC"), ago(inc.OpenedAt, w.Now()), inc.Observations)
	fmt.Fprintf(&b, "Machine: %s\n\nhelios status and helios alerts on the machine show more. %s\n", w.Hostname, again)
	return Notice{Subject: subject, Body: b.String(), IncidentID: inc.ID, Key: inc.Key, Transition: transition, Severity: inc.Severity, Host: w.Hostname}
}

func (w *Watcher) resolvedNotice(inc state.Incident) Notice {
	word, verb := "recovered", "Recovered"
	if operatorKey(inc.Key) {
		word, verb = "is no longer held", "Ended"
	}
	subject := fmt.Sprintf("%s: %s %s", w.Hostname, inc.Subject, word)
	body := fmt.Sprintf("%s after %s.\n\nIt was: %s\n\nMachine: %s\n", verb, ago(inc.OpenedAt, inc.ResolvedAt), inc.Message, w.Hostname)
	return Notice{Subject: subject, Body: body, IncidentID: inc.ID, Key: inc.Key, Transition: TransitionResolved, Severity: inc.Severity, Host: w.Hostname}
}

// ago says how long before now a time was, roughly.
func ago(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f h", d.Hours())
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
