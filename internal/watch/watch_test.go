package watch

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

type fakeNotifier struct {
	sent []Notice
	fail bool
}

func (f *fakeNotifier) Notify(_ context.Context, n Notice) error {
	if f.fail {
		return errors.New("mail server down")
	}
	f.sent = append(f.sent, n)
	return nil
}

func newWatcher(t *testing.T, n Notifier) (*Watcher, *time.Time) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	w := &Watcher{Store: store, Notifier: n, Hostname: "box", Now: func() time.Time { return now }}
	return w, &now
}

func down(app string) Condition {
	return Condition{Key: "app:" + app, Subject: app, Severity: state.SeverityCritical, Message: "web isn't running"}
}

func stale(app string) Condition {
	return Condition{Key: "app:" + app, Subject: app, Severity: state.SeverityWarning, Message: "the last backup is 2 days old"}
}

// shopRound runs a round a minute after the last and returns shop's open
// incident after it, if any.
func shopRound(t *testing.T, w *Watcher, now *time.Time) func(...Condition) *state.Incident {
	return func(conditions ...Condition) *state.Incident {
		t.Helper()
		*now = now.Add(time.Minute)
		if err := w.Round(context.Background(), conditions); err != nil {
			t.Fatal(err)
		}
		inc, err := w.Store.OpenIncidentByKey(context.Background(), "app:shop")
		if err != nil {
			t.Fatal(err)
		}
		return inc
	}
}

func TestAnIncidentOpensAfterThreeRoundsAndResolvesAfterTwo(t *testing.T) {
	ctx := context.Background()
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	for i := 0; i < 2; i++ {
		if err := w.Round(ctx, []Condition{down("hello")}); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(time.Minute)
	}
	if open, _ := w.Store.OpenIncidents(ctx); len(open) != 0 || len(n.sent) != 0 {
		t.Fatalf("too eager: %d open, %d sent", len(open), len(n.sent))
	}
	if err := w.Round(ctx, []Condition{down("hello")}); err != nil {
		t.Fatal(err)
	}
	open, _ := w.Store.OpenIncidents(ctx)
	if len(open) != 1 || len(n.sent) != 1 {
		t.Fatalf("expected one incident and one notice: %d open, %d sent", len(open), len(n.sent))
	}
	if !strings.Contains(n.sent[0].Subject, "hello is down") || !strings.Contains(n.sent[0].Body, "web isn't running") {
		t.Fatalf("notice: %+v", n.sent[0])
	}
	// Still down: no second notice within a day.
	for i := 0; i < 5; i++ {
		*now = now.Add(time.Minute)
		_ = w.Round(ctx, []Condition{down("hello")})
	}
	if len(n.sent) != 1 {
		t.Fatalf("repeated too soon: %d notices", len(n.sent))
	}
	// One clean round isn't recovery yet.
	*now = now.Add(time.Minute)
	_ = w.Round(ctx, nil)
	if open, _ := w.Store.OpenIncidents(ctx); len(open) != 1 {
		t.Fatal("resolved after one clean round")
	}
	*now = now.Add(time.Minute)
	_ = w.Round(ctx, nil)
	if open, _ := w.Store.OpenIncidents(ctx); len(open) != 0 {
		t.Fatal("not resolved after two clean rounds")
	}
	if len(n.sent) != 2 || !strings.Contains(n.sent[1].Subject, "hello recovered") {
		t.Fatalf("recovery notice: %+v", n.sent)
	}
	all, _ := w.Store.Incidents(ctx, 10)
	if len(all) != 1 || all[0].Open() || all[0].Observations != 8 {
		t.Fatalf("history: %+v", all)
	}
}

func TestABlipNeverBecomesAnIncident(t *testing.T) {
	ctx := context.Background()
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	for i := 0; i < 6; i++ {
		var conds []Condition
		if i%2 == 0 {
			conds = []Condition{down("hello")}
		}
		_ = w.Round(ctx, conds)
		*now = now.Add(time.Minute)
	}
	if open, _ := w.Store.OpenIncidents(ctx); len(open) != 0 || len(n.sent) != 0 {
		t.Fatal("a flapping condition opened an incident")
	}
}

func TestAFailedNoticeIsTriedAgainNextRound(t *testing.T) {
	ctx := context.Background()
	n := &fakeNotifier{fail: true}
	w, now := newWatcher(t, n)
	for i := 0; i < 3; i++ {
		_ = w.Round(ctx, []Condition{down("hello")})
		*now = now.Add(time.Minute)
	}
	open, _ := w.Store.OpenIncidents(ctx)
	if len(open) != 1 || open[0].NotifyError == "" || !open[0].NotifiedAt.IsZero() {
		t.Fatalf("expected an open incident with a delivery error: %+v", open)
	}
	n.fail = false
	_ = w.Round(ctx, []Condition{down("hello")})
	open, _ = w.Store.OpenIncidents(ctx)
	if len(n.sent) != 1 || open[0].NotifyError != "" || open[0].NotifiedAt.IsZero() {
		t.Fatalf("not retried: sent %d, %+v", len(n.sent), open[0])
	}
}

func TestAnOpenIncidentIsRepeatedAfterADay(t *testing.T) {
	ctx := context.Background()
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	for i := 0; i < 3; i++ {
		_ = w.Round(ctx, []Condition{down("hello")})
		*now = now.Add(time.Minute)
	}
	*now = now.Add(25 * time.Hour)
	c := down("hello")
	c.Message = "web isn't running; https://hello.example/ answers connection refused"
	_ = w.Round(ctx, []Condition{c})
	if len(n.sent) != 2 || !strings.Contains(n.sent[1].Body, "connection refused") {
		t.Fatalf("expected a repeat with the latest message: %+v", n.sent)
	}
}

// A critical alert rings a phone every minute for an hour, so an app with
// a warning open whose health check fails for a round or two is not paged
// and stays a warning. The outage counts only once it has held as long as
// a new incident must, and any round that breaks it starts the count again.
func TestAWarningThatBlipsToCriticalNeitherPagesNorBecomesCritical(t *testing.T) {
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	round := shopRound(t, w, now)
	for range DefaultOpenAfter {
		round(stale("shop"))
	}
	if len(n.sent) != 1 || n.sent[0].Subject != "box: shop has a problem" {
		t.Fatalf("the warning is told once: %+v", n.sent)
	}

	inc := round(down("shop"))
	if len(n.sent) != 1 || inc.Severity != state.SeverityWarning || inc.Message != stale("shop").Message {
		t.Fatalf("one critical round paged or changed the warning: %+v, %+v", n.sent, inc)
	}
	// A round back at the warning, a clean round and a round shop couldn't
	// be looked at each start the count again.
	for _, between := range [][]Condition{{stale("shop")}, nil, {{Key: "app:shop", Unknown: true}}} {
		round(between...)
		for range DefaultOpenAfter - 1 {
			inc = round(down("shop"))
		}
	}
	if len(n.sent) != 1 || inc.Severity != state.SeverityWarning || inc.Message != stale("shop").Message {
		t.Fatalf("a flapping health check paged or changed the warning: %+v, %+v", n.sent, inc)
	}
}

// A warning that stays an outage as long as a new incident must hold is
// told then, once, rather than at the warning's next daily repeat. Easing
// back to a warning for a round and failing again is the same outage, so
// it doesn't page again however often it flaps.
func TestAWarningThatStaysAnOutageIsToldOnceInTheRoundItHolds(t *testing.T) {
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	round := shopRound(t, w, now)
	for range DefaultOpenAfter {
		round(stale("shop"))
	}
	for range DefaultOpenAfter - 1 {
		round(down("shop"))
	}
	if len(n.sent) != 1 {
		t.Fatalf("the outage is told before it has held: %+v", n.sent)
	}
	inc := round(down("shop"))
	if len(n.sent) != 2 || n.sent[1].Subject != "box: shop is down" || n.sent[1].Severity != state.SeverityCritical ||
		n.sent[1].Transition != TransitionRepeat || !strings.Contains(n.sent[1].Body, "web isn't running") {
		t.Fatalf("the outage is told in the round it has held: %+v", n.sent)
	}
	if inc.Severity != state.SeverityCritical || inc.Message != "web isn't running" {
		t.Fatalf("the incident didn't become the outage: %+v", inc)
	}
	for range 5 {
		round(down("shop"))
	}
	for range 3 {
		if inc := round(stale("shop")); inc.Severity != state.SeverityCritical || inc.Message != "web isn't running" {
			t.Fatalf("an outage that eased for a round is no longer the outage: %+v", inc)
		}
		for range DefaultOpenAfter {
			round(down("shop"))
		}
	}
	if len(n.sent) != 2 {
		t.Fatalf("the outage is told once: %+v", n.sent)
	}
}

// An outage that eases back to a warning for as long as a recovery must
// hold is a warning again, and an outage after that is a new one, told
// again once it holds.
func TestAnOutageThatEasesForAsLongAsARecoveryIsAWarningAgain(t *testing.T) {
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	round := shopRound(t, w, now)
	for range DefaultOpenAfter {
		round(stale("shop"))
	}
	for range DefaultOpenAfter {
		round(down("shop"))
	}
	for range DefaultResolveAfter - 1 {
		round(stale("shop"))
	}
	inc := round(stale("shop"))
	if inc.Severity != state.SeverityWarning || inc.Message != stale("shop").Message || len(n.sent) != 2 {
		t.Fatalf("an outage that eased as long as a recovery is still the outage: %+v, %+v", inc, n.sent)
	}
	for range DefaultOpenAfter - 1 {
		round(down("shop"))
	}
	if len(n.sent) != 2 {
		t.Fatalf("the new outage is told before it has held: %+v", n.sent)
	}
	round(down("shop"))
	if len(n.sent) != 3 || n.sent[2].Subject != "box: shop is down" {
		t.Fatalf("the new outage is told once it holds: %+v", n.sent)
	}
}

// A notice carries its incident's message and opening time, so a leg never
// has to read them from the store, where an escalation is saved only after
// it is told. The outage's notice carries the outage's message, and every
// notice the time the warning opened.
func TestANoticeCarriesItsIncidentsMessageAndOpeningTime(t *testing.T) {
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	round := shopRound(t, w, now)
	for range DefaultOpenAfter {
		round(stale("shop"))
	}
	opened := *now
	for range DefaultOpenAfter {
		round(down("shop"))
	}
	for range DefaultResolveAfter {
		round()
	}
	want := []struct{ transition, message string }{
		{TransitionOpen, stale("shop").Message},
		{TransitionRepeat, down("shop").Message},
		{TransitionResolved, down("shop").Message},
	}
	if len(n.sent) != len(want) {
		t.Fatalf("sent %+v", n.sent)
	}
	for i, sent := range n.sent {
		if sent.Transition != want[i].transition || sent.Message != want[i].message || !sent.OpenedAt.Equal(opened) || sent.Test != "" {
			t.Errorf("notice %d: %+v, want %s %q opened at %s", i, sent, want[i].transition, want[i].message, opened)
		}
	}
}

func TestWithoutANotifierIncidentsAreStillRecorded(t *testing.T) {
	ctx := context.Background()
	w, now := newWatcher(t, nil)
	for i := 0; i < 3; i++ {
		_ = w.Round(ctx, []Condition{{Key: "host:disk", Subject: "disk", Severity: state.SeverityCritical, Message: "2 GB free"}})
		*now = now.Add(time.Minute)
	}
	open, _ := w.Store.OpenIncidents(ctx)
	if len(open) != 1 || !strings.Contains(open[0].NotifyError, "integration set email") {
		t.Fatalf("%+v", open)
	}
}

func TestADeployUnderWayIsFoundByTheAppsName(t *testing.T) {
	w, now := newWatcher(t, nil)
	ctx := context.Background()
	start := func(id, target string) {
		t.Helper()
		op := state.NewOperation{ID: id, Kind: app.DeployKind, Target: target, Input: json.RawMessage(`{}`), Plan: json.RawMessage(`{}`),
			PlanDigest: "d", Recovery: string(kernel.Resume), StepNames: []string{"one"}, CreatedAt: *now}
		if err := w.Store.CreateOperation(ctx, op); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Store.Claim(ctx, id, "daemon", *now, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	start("op-1", "hello")
	// A journal from before 0.7.8 named the revision in the target.
	start("op-2", "world 20260922-120000")
	p := &Prober{Store: w.Store}
	if !p.deploying(ctx, "hello") {
		t.Fatal("hello's deploy was not found")
	}
	if !p.deploying(ctx, "world") {
		t.Fatal("world's older deploy was not found")
	}
	if p.deploying(ctx, "hello-pr-nav") {
		t.Fatal("another app's deploy was taken for hello-pr-nav's")
	}
	if err := w.Store.Finish(ctx, "op-1", state.Succeeded, "", json.RawMessage(`{}`), *now); err != nil {
		t.Fatal(err)
	}
	if p.deploying(ctx, "hello") {
		t.Fatal("a finished deploy still counts as under way")
	}
}

func TestAFailedRecoveryNoticeIsRetriedAfterResolution(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	w.OpenAfter, w.ResolveAfter = 1, 1
	if err := w.Round(ctx, []Condition{down("hello")}); err != nil {
		t.Fatal(err)
	}
	notifier.fail = true
	*now = now.Add(time.Minute)
	if err := w.Round(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if open, err := w.Store.OpenIncidents(ctx); err != nil || len(open) != 0 {
		t.Fatalf("failed mail should not keep resolved incident open: %+v, %v", open, err)
	}
	notifier.fail = false
	*now = now.Add(time.Minute)
	if err := w.Round(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(notifier.sent) != 2 || !strings.Contains(notifier.sent[1].Subject, "recovered") {
		t.Fatalf("failed recovery mail was lost: %+v", notifier.sent)
	}
	if err := w.Round(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(notifier.sent) != 2 {
		t.Fatal("successful recovery notice repeated")
	}
}
