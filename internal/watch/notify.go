package watch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/mail"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// Names of the legs alerts go out through.
const (
	EmailLeg = integration.EmailName
	// The phone legs carry warnings and worse; email carries everything.
	PushoverLeg = integration.PushoverName
	NtfyLeg     = integration.NtfyName
	// The Loom leg opens a thread for a critical incident. It tells an
	// agent, not a person, so it never goes alone.
	LoomWebhookLeg = integration.LoomWebhookName
)

// NoPersonLeg is the notify error of a fan-out that would tell Loom and
// no one else.
const NoPersonLeg = "loom_webhook needs a person leg too; set email, pushover or ntfy"

// RelayTimeout bounds one mail server's attempt, so a hung server leaves
// time to fail over to the next.
const RelayTimeout = time.Minute

// EmailNotifier sends a notice through the first mail server that takes
// it, in order. It never sends one notice through two servers.
type EmailNotifier struct {
	Relays []integration.Email
	Store  *state.Store
	// send delivers one mail; nil means mail.Send.
	send func(context.Context, mail.Server, mail.Message) error
}

// Notify implements Notifier.
func (e EmailNotifier) Notify(ctx context.Context, n Notice) error {
	if len(e.Relays) == 0 {
		return errors.New("no mail server is set up; run helios integration set email")
	}
	send := e.send
	if send == nil {
		send = mail.Send
	}
	var failures []string
	for _, r := range e.Relays {
		rctx, cancel := context.WithTimeout(ctx, RelayTimeout)
		err := send(rctx, mail.Server{Host: r.Host, Port: r.Port, User: r.User, Password: r.Password},
			mail.Message{From: r.From, FromName: r.FromName, To: r.To, Subject: "[helios] " + n.Subject, Body: n.Body})
		cancel()
		if err == nil {
			if e.Store != nil {
				_ = e.Store.RecordIntegrationUse(ctx, r.Name, "alert: "+n.Subject, time.Now().UTC())
			}
			return nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", r.Name, err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(failures) == 1 && len(e.Relays) == 1 {
		return errors.New(strings.TrimPrefix(failures[0], e.Relays[0].Name+": "))
	}
	return errors.New("every mail server failed: " + strings.Join(failures, "; "))
}

// testNotice is what a test of the alerts says.
func testNotice(hostname string) Notice {
	return Notice{
		Subject:    hostname + ": test alert",
		Body:       fmt.Sprintf("This is helios on %s checking that alerts reach you. Nothing is wrong.\n", hostname),
		Transition: TransitionOpen,
		Severity:   state.SeverityWarning,
		Host:       hostname,
	}
}

// legSpec is one leg as set up, before it is put to use: a mail server is
// one leg in a test and part of the email leg in an alert.
type legSpec struct {
	name     string
	to       string
	least    string
	notifier Notifier
	// timeout bounds one delivery; zero means LegTimeout.
	timeout time.Duration
	// once is set for a leg that hears of an incident once.
	once bool
}

// loadLegs reads the integrations set up now, mail servers first in the
// order they are tried. One that can't be read becomes a leg that fails
// with the reason, so the others still deliver.
func loadLegs(sec *secrets.Store, store *state.Store) []legSpec {
	var legs []legSpec
	relays, err := integration.LoadEmailRelays(sec)
	if err != nil {
		legs = append(legs, legSpec{name: EmailLeg, least: state.SeverityNotice, notifier: broken{err}})
	}
	for _, r := range relays {
		legs = append(legs, legSpec{name: r.Name, to: strings.Join(r.To, ", "), least: state.SeverityNotice,
			notifier: EmailNotifier{Relays: []integration.Email{r}, Store: store}})
	}
	if p, err := integration.LoadPushover(sec); err == nil {
		legs = append(legs, legSpec{name: PushoverLeg, to: "Pushover", least: state.SeverityWarning, notifier: &PushoverNotifier{Pushover: *p, Store: store}})
	} else if !errors.Is(err, integration.ErrNotSet) {
		legs = append(legs, legSpec{name: PushoverLeg, least: state.SeverityWarning, notifier: broken{err}})
	}
	if t, err := integration.LoadNtfy(sec); err == nil {
		legs = append(legs, legSpec{name: NtfyLeg, to: "the ntfy topic", least: state.SeverityWarning, notifier: &NtfyNotifier{Ntfy: *t, Store: store}})
	} else if !errors.Is(err, integration.ErrNotSet) {
		legs = append(legs, legSpec{name: NtfyLeg, least: state.SeverityWarning, notifier: broken{err}})
	}
	if w, err := integration.LoadLoomWebhook(sec); err == nil {
		legs = append(legs, legSpec{name: LoomWebhookLeg, to: "the Loom task", least: state.SeverityCritical, timeout: LoomTimeout, once: true,
			notifier: &LoomNotifier{LoomWebhook: *w, Store: store, Secrets: sec}})
	} else if !errors.Is(err, integration.ErrNotSet) {
		legs = append(legs, legSpec{name: LoomWebhookLeg, least: state.SeverityCritical, timeout: LoomTimeout, once: true, notifier: broken{err}})
	}
	return legs
}

// LegNames names each alert leg set up now by the name its deliveries are
// recorded under: each mail server by its own name, then pushover and
// ntfy. One whose integration can't be read is named too.
func LegNames(sec *secrets.Store) []string {
	var names []string
	for _, l := range loadLegs(sec, nil) {
		names = append(names, l.name)
	}
	return names
}

// LoadFanout builds the fan-out from the integrations set up now: one
// email leg that fails over through the mail servers in order, a phone
// leg for each of Pushover and ntfy, and the Loom leg.
func LoadFanout(sec *secrets.Store, store *state.Store) (*Fanout, error) {
	return fanoutOf(loadLegs(sec, store), store)
}

// fanoutOf folds the mail servers among legs into the one email leg and
// keeps the rest as they are. A fan-out whose only leg is Loom is refused:
// a warning would count as told with no leg to carry it, and an outage
// would reach an agent and no person.
func fanoutOf(legs []legSpec, store *state.Store) (*Fanout, error) {
	f := &Fanout{}
	var relays []integration.Email
	person := false
	for _, l := range legs {
		if e, ok := l.notifier.(EmailNotifier); ok {
			relays = append(relays, e.Relays...)
			continue
		}
		person = person || l.name != LoomWebhookLeg
		f.Legs = append(f.Legs, Leg{Name: l.name, Notifier: l.notifier, MinSeverity: l.least, Timeout: l.timeout, Once: l.once})
	}
	if len(relays) > 0 {
		email := Leg{Name: EmailLeg, Notifier: EmailNotifier{Relays: relays, Store: store}, MinSeverity: state.SeverityNotice,
			Timeout: time.Duration(len(relays)) * RelayTimeout}
		f.Legs = append([]Leg{email}, f.Legs...)
		person = true
	}
	if len(f.Legs) == 0 {
		return nil, errors.New(NoAlertsSetUp)
	}
	if !person {
		return nil, errors.New(NoPersonLeg)
	}
	return f, nil
}

// broken is a leg whose integration can't be read.
type broken struct{ err error }

func (b broken) Notify(context.Context, Notice) error { return b.err }

// Alerts is how the daemon tells a person. It reads the integrations
// fresh for each notice, so a change takes effect without a restart, and
// keeps one ledger across notices.
type Alerts struct {
	Secrets *secrets.Store
	Store   *state.Store
	// Now is the ledger's clock; nil is the system's.
	Now    func() time.Time
	ledger Ledger
}

// Notify implements Notifier.
func (a *Alerts) Notify(ctx context.Context, n Notice) error {
	f, err := LoadFanout(a.Secrets, a.Store)
	if err != nil {
		return err
	}
	f.Ledger, f.Now = &a.ledger, a.Now
	return f.Notify(ctx, n)
}
