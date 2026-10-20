package watch

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/mail"
	"github.com/kylebegeman/helios/internal/state"
)

const (
	testAppToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testUserKey  = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"
)

// mailbox stands in for the mail servers: it refuses mail for the hosts
// it is told to and keeps the rest.
type mailbox struct {
	mu        sync.Mutex
	refuse    map[string]bool
	tried     []string
	delivered []mail.Message
	through   []string
}

func (m *mailbox) send(_ context.Context, s mail.Server, msg mail.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tried = append(m.tried, s.Host)
	if m.refuse[s.Host] {
		return errors.New("535 authentication failed")
	}
	m.delivered = append(m.delivered, msg)
	m.through = append(m.through, s.Host)
	return nil
}

func (m *mailbox) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.delivered)
}

func relays(names ...string) []integration.Email {
	var out []integration.Email
	for i, name := range names {
		host := "smtp" + string(rune('1'+i)) + ".example.test"
		out = append(out, integration.Email{Name: name, Host: host, Port: 587, From: "helios@example.test", To: []string{"ops@example.test"}})
	}
	return out
}

// pushoverAPI stands in for Pushover and records every request.
type pushoverAPI struct {
	mu       sync.Mutex
	fail     bool
	requests []pushoverRequest
	server   *httptest.Server
}

type pushoverRequest struct {
	path     string
	form     url.Values
	accepted bool
}

func newPushoverAPI(t *testing.T) *pushoverAPI {
	api := &pushoverAPI{}
	api.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests = append(api.requests, pushoverRequest{path: r.URL.Path, form: form, accepted: !api.fail})
		if api.fail {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"status":0,"errors":["application token is invalid, see https://pushover.net/api"],"token":"invalid"}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":1,"request":"r1"}`)
	}))
	t.Cleanup(api.server.Close)
	return api
}

func (api *pushoverAPI) notifier() *PushoverNotifier {
	return &PushoverNotifier{Pushover: integration.Pushover{AppToken: testAppToken, UserKey: testUserKey}, API: api.server.URL + "/1/", Client: api.server.Client()}
}

func (api *pushoverAPI) setFail(fail bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.fail = fail
}

// messages are the messages Pushover accepted.
func (api *pushoverAPI) messages() []url.Values {
	api.mu.Lock()
	defer api.mu.Unlock()
	var out []url.Values
	for _, r := range api.requests {
		if r.path == "/1/messages.json" && r.accepted {
			out = append(out, r.form)
		}
	}
	return out
}

func (api *pushoverAPI) paths() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	var out []string
	for _, r := range api.requests {
		out = append(out, r.path)
	}
	return out
}

func emailAndPushover(mails *mailbox, api *pushoverAPI) *Fanout {
	return &Fanout{Ledger: &Ledger{}, Legs: []Leg{
		{Name: EmailLeg, Notifier: EmailNotifier{Relays: relays("email", "email2"), send: mails.send}, MinSeverity: state.SeverityNotice},
		{Name: PushoverLeg, Notifier: api.notifier(), MinSeverity: state.SeverityWarning},
	}}
}

func rounds(t *testing.T, w *Watcher, now *time.Time, n int, conditions ...Condition) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := w.Round(context.Background(), conditions); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(time.Minute)
	}
}

func openIncident(t *testing.T, w *Watcher) state.Incident {
	t.Helper()
	open, err := w.Store.OpenIncidents(context.Background())
	if err != nil || len(open) != 1 {
		t.Fatalf("expected one open incident: %v, %v", open, err)
	}
	return open[0]
}

// A critical incident is told once by email and once by a Pushover
// emergency that rings until acknowledged, and neither repeats it.
func TestACriticalNoticeReachesEmailAndPushoverOnceEach(t *testing.T) {
	mails, api := &mailbox{}, newPushoverAPI(t)
	f := emailAndPushover(mails, api)
	w, now := newWatcher(t, f)
	f.Now = func() time.Time { return *now }
	rounds(t, w, now, 10, down("hello"))

	if mails.count() != 1 || mails.through[0] != "smtp1.example.test" || !strings.Contains(mails.delivered[0].Subject, "box: hello is down") {
		t.Fatalf("email should carry it once, through the first server: %v %+v", mails.through, mails.delivered)
	}
	got := api.messages()
	if len(got) != 1 {
		t.Fatalf("Pushover should carry it once: %v", api.paths())
	}
	m := got[0]
	tag := pushoverTag(Notice{Host: "box", Key: "app:hello"})
	if m.Get("priority") != "2" || m.Get("retry") != "60" || m.Get("expire") != "3600" || m.Get("tags") != tag ||
		m.Get("token") != testAppToken || m.Get("user") != testUserKey || !strings.Contains(m.Get("title"), "hello is down") {
		t.Fatalf("not an emergency that rings until acknowledged: %v", m)
	}
	if strings.Contains(tag, "app:hello") || !strings.HasPrefix(tag, "helios-") {
		t.Fatalf("the tag should be safe in a path: %q", tag)
	}
	if inc := openIncident(t, w); inc.NotifyError != "" || inc.NotifiedAt.IsZero() {
		t.Fatalf("the incident should be told: %+v", inc)
	}
}

// The first mail server failing hands the notice to the second, and a
// notice never goes through both.
func TestAFailedMailServerFailsOverToTheNext(t *testing.T) {
	ctx := context.Background()
	mails := &mailbox{refuse: map[string]bool{"smtp1.example.test": true}}
	e := EmailNotifier{Relays: relays("email", "email2"), send: mails.send}
	if err := e.Notify(ctx, Notice{Subject: "box: hello is down"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(mails.tried, ",") != "smtp1.example.test,smtp2.example.test" || strings.Join(mails.through, ",") != "smtp2.example.test" {
		t.Fatalf("tried %v, delivered through %v", mails.tried, mails.through)
	}

	mails = &mailbox{}
	e.send = mails.send
	if err := e.Notify(ctx, Notice{Subject: "box: hello is down"}); err != nil || strings.Join(mails.tried, ",") != "smtp1.example.test" {
		t.Fatalf("a working first server is the only one used: %v, %v", mails.tried, err)
	}

	mails = &mailbox{refuse: map[string]bool{"smtp1.example.test": true, "smtp2.example.test": true}}
	e.send = mails.send
	err := e.Notify(ctx, Notice{Subject: "box: hello is down"})
	if err == nil || !strings.Contains(err.Error(), "email: 535") || !strings.Contains(err.Error(), "email2: 535") {
		t.Fatalf("both failing should name both: %v", err)
	}
}

// A leg that missed a notice is tried again on its own, after a backoff,
// and the legs that had it don't hear it twice.
func TestAFailedLegIsRetriedAlone(t *testing.T) {
	mails, api := &mailbox{}, newPushoverAPI(t)
	api.setFail(true)
	f := emailAndPushover(mails, api)
	w, now := newWatcher(t, f)
	f.Now = func() time.Time { return *now }
	rounds(t, w, now, 3, down("hello"))

	inc := openIncident(t, w)
	told := inc.NotifiedAt
	if mails.count() != 1 || told.IsZero() {
		t.Fatalf("email delivered, so the person was told: %d mails, %+v", mails.count(), inc)
	}
	if !strings.Contains(inc.NotifyError, "pushover: the Pushover API refused it: application token is invalid") || !strings.Contains(inc.NotifyError, "delivered by email") {
		t.Fatalf("the missed leg isn't recorded: %q", inc.NotifyError)
	}
	if strings.Contains(inc.NotifyError, testAppToken) {
		t.Fatal("the token leaked into the incident")
	}

	// A minute on, Pushover is tried again and misses again; then it
	// waits two minutes.
	rounds(t, w, now, 2, down("hello"))
	if attempts := len(api.paths()); attempts != 2 {
		t.Fatalf("Pushover should be tried after one minute, then wait two: %d attempts", attempts)
	}
	api.setFail(false)
	rounds(t, w, now, 1, down("hello"))
	if mails.count() != 1 || len(api.messages()) != 1 {
		t.Fatalf("only Pushover should be retried: %d mails, %v", mails.count(), api.paths())
	}
	inc = openIncident(t, w)
	if inc.NotifyError != "" || !inc.NotifiedAt.Equal(told) {
		t.Fatalf("delivered everywhere, and the repeat clock still counts from the first notice: %+v", inc)
	}
	rounds(t, w, now, 5, down("hello"))
	if mails.count() != 1 || len(api.messages()) != 1 {
		t.Fatalf("nothing more to send: %d mails, %v", mails.count(), api.paths())
	}
}

// A leg that hears every notice is owed only the latest, so the recovery
// of an outage it missed reaches it in the round the outage recovers,
// without waiting out the backoff of the outage's notice.
func TestARecoveryReachesALegThatMissedTheOutageAtOnce(t *testing.T) {
	ctx := context.Background()
	mails, api := &mailbox{}, newPushoverAPI(t)
	api.setFail(true)
	f := emailAndPushover(mails, api)
	w, now := newWatcher(t, f)
	f.Now = func() time.Time { return *now }
	// Pushover misses the outage as it opens, a minute on and two minutes
	// after that, and then waits four.
	rounds(t, w, now, 7, down("hello"))
	if attempts := len(api.paths()); attempts != 3 {
		t.Fatalf("Pushover should miss the outage three times: %v", api.paths())
	}
	api.setFail(false)
	rounds(t, w, now, 2)
	all, err := w.Store.Incidents(ctx, 10)
	if err != nil || len(all) != 1 || all[0].Open() {
		t.Fatalf("hello should have recovered: %+v, %v", all, err)
	}
	if got := api.messages(); len(got) != 1 || !strings.Contains(got[0].Get("title"), "hello recovered") || all[0].NotifyError != "" {
		t.Fatalf("Pushover should have the recovery at once: %v, %q", api.paths(), all[0].NotifyError)
	}
}

// The recovery of a critical incident stops its Pushover emergency, then
// says so quietly.
func TestAResolvedIncidentCancelsItsPushoverTag(t *testing.T) {
	mails, api := &mailbox{}, newPushoverAPI(t)
	f := emailAndPushover(mails, api)
	w, now := newWatcher(t, f)
	f.Now = func() time.Time { return *now }
	rounds(t, w, now, 3, down("hello"))
	rounds(t, w, now, 2)

	tag := pushoverTag(Notice{Host: "box", Key: "app:hello"})
	if got := strings.Join(api.paths(), ","); got != "/1/messages.json,/1/receipts/cancel_by_tag/"+tag+".json,/1/messages.json" {
		t.Fatalf("requests: %s", got)
	}
	cancel := api.requests[1].form
	if cancel.Get("token") != testAppToken || cancel.Get("user") != "" {
		t.Fatalf("the cancel should carry only the app token: %v", cancel)
	}
	quiet := api.requests[2].form
	if quiet.Get("priority") != "-1" || quiet.Get("tags") != "" || !strings.Contains(quiet.Get("title"), "hello recovered") {
		t.Fatalf("the recovery should be quiet: %v", quiet)
	}
	if mails.count() != 2 || !strings.Contains(mails.delivered[1].Subject, "hello recovered") {
		t.Fatalf("email should carry the recovery: %+v", mails.delivered)
	}
}

// A notice goes by email; only warnings and worse reach the phone. A leg
// that hangs is cut off at its timeout without holding up the rest.
func TestTheFanoutRoutesBySeverityAndCutsOffAHungLeg(t *testing.T) {
	ctx := context.Background()
	mails, api := &mailbox{}, newPushoverAPI(t)
	f := emailAndPushover(mails, api)
	if err := f.Notify(ctx, Notice{IncidentID: 1, Transition: TransitionOpen, Severity: state.SeverityNotice, Subject: "box: drills is held by an operator"}); err != nil {
		t.Fatal(err)
	}
	if mails.count() != 1 || len(api.paths()) != 0 {
		t.Fatalf("a notice is for email only: %d mails, %v", mails.count(), api.paths())
	}

	hung := Leg{Name: "hung", Timeout: 50 * time.Millisecond, Notifier: notifierFunc(func(ctx context.Context, _ Notice) error {
		<-ctx.Done()
		return ctx.Err()
	})}
	f.Legs = append(f.Legs, hung)
	err := f.Notify(ctx, Notice{IncidentID: 2, Transition: TransitionOpen, Severity: state.SeverityWarning, Subject: "box: hello has a problem"})
	var missed *DeliveryError
	if !errors.As(err, &missed) || !missed.Partial() || len(missed.Failed) != 1 || missed.Failed[0].Leg != "hung" {
		t.Fatalf("only the hung leg should miss it: %v", err)
	}
	if mails.count() != 2 || len(api.messages()) != 1 {
		t.Fatalf("the others deliver regardless: %d mails, %v", mails.count(), api.paths())
	}
}

type notifierFunc func(context.Context, Notice) error

func (f notifierFunc) Notify(ctx context.Context, n Notice) error { return f(ctx, n) }

// Loom tells an agent, not a person, so a fan-out whose only leg is Loom
// is refused rather than counting an incident as told. Beside email or a
// phone, the Loom leg keeps its own severity and timeout.
func TestTheLoomLegNeverGoesAlone(t *testing.T) {
	quiet := notifierFunc(func(context.Context, Notice) error { return nil })
	loom := legSpec{name: LoomWebhookLeg, least: state.SeverityCritical, timeout: 45 * time.Second, notifier: quiet}
	if f, err := fanoutOf([]legSpec{loom}, nil); err == nil || err.Error() != NoPersonLeg {
		t.Fatalf("Loom alone: %+v, %v", f, err)
	}
	if _, err := fanoutOf(nil, nil); err == nil || err.Error() != NoAlertsSetUp {
		t.Fatalf("nothing set up: %v", err)
	}
	for _, person := range []legSpec{
		{name: "email", least: state.SeverityNotice, notifier: EmailNotifier{Relays: relays("email")}},
		{name: PushoverLeg, least: state.SeverityWarning, notifier: quiet},
	} {
		f, err := fanoutOf([]legSpec{person, loom}, nil)
		if err != nil || len(f.Legs) != 2 {
			t.Fatalf("Loom beside %s: %+v, %v", person.name, f, err)
		}
		if l := f.Legs[1]; l.Name != LoomWebhookLeg || l.MinSeverity != state.SeverityCritical || l.Timeout != 45*time.Second {
			t.Fatalf("the Loom leg lost its own severity or timeout: %+v", f.Legs)
		}
	}
}

// A notice no leg delivered is tried again by every leg, even when it
// was a repeat, and the person counts as told only once one delivers.
func TestANoticeNoLegDeliveredIsTriedAgain(t *testing.T) {
	mails := &mailbox{refuse: map[string]bool{"smtp1.example.test": true, "smtp2.example.test": true}}
	api := newPushoverAPI(t)
	api.setFail(true)
	f := emailAndPushover(mails, api)
	w, now := newWatcher(t, f)
	f.Now = func() time.Time { return *now }
	held := Condition{Key: "host:drills", Subject: "drills", Severity: state.SeverityNotice, Message: "held"}
	rounds(t, w, now, 3, held)
	if inc := openIncident(t, w); !inc.NotifiedAt.IsZero() || inc.NotifyError == "" {
		t.Fatalf("nobody was told: %+v", inc)
	}
	delete(mails.refuse, "smtp1.example.test")
	rounds(t, w, now, 1, held)
	told := openIncident(t, w).NotifiedAt
	if mails.count() != 1 || told.IsZero() {
		t.Fatalf("the retry should tell: %d mails", mails.count())
	}
	// It escalates while both servers refuse: the escalation is retried
	// until it is delivered.
	mails.refuse["smtp1.example.test"] = true
	worse := held
	worse.Severity = state.SeverityWarning
	rounds(t, w, now, 1, worse)
	if inc := openIncident(t, w); !inc.NotifiedAt.Equal(told) || inc.NotifyError == "" {
		t.Fatalf("the escalation reached no one: %+v", inc)
	}
	delete(mails.refuse, "smtp1.example.test")
	api.setFail(false)
	rounds(t, w, now, 2, worse)
	inc := openIncident(t, w)
	if mails.count() != 2 || len(api.messages()) != 1 || inc.NotifyError != "" || !inc.NotifiedAt.After(told) {
		t.Fatalf("the escalation should be delivered by both: %d mails, %v, %+v", mails.count(), api.paths(), inc)
	}
}

// ntfy gets the notice as JSON on the server, with the token, and the
// topic never shows up in an error.
func TestNtfyPublishesWithoutShowingTheTopic(t *testing.T) {
	var got struct {
		Topic    string   `json:"topic"`
		Title    string   `json:"title"`
		Message  string   `json:"message"`
		Priority int      `json:"priority"`
		Tags     []string `json:"tags"`
	}
	var (
		mu         sync.Mutex
		auth, path string
		refuse     bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		if refuse {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"code":40301,"http":403,"error":"forbidden for topic alerts-k3y"}`)
		}
	}))
	defer srv.Close()
	topic, err := integration.ParseNtfyTopic(srv.URL + "/alerts-k3y")
	if err != nil {
		t.Fatal(err)
	}
	n := &NtfyNotifier{Ntfy: integration.Ntfy{NtfyTopic: topic, Token: "tk_example"}, Client: srv.Client()}
	if err := n.Notify(context.Background(), Notice{Subject: "box: hello is down", Body: strings.Repeat("é", 3000), Severity: state.SeverityCritical, Transition: TransitionOpen}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if path != "/" || got.Topic != "alerts-k3y" || got.Priority != 5 || got.Title != "box: hello is down" || auth != "Bearer tk_example" || len(got.Message) > ntfyMessageMax {
		t.Fatalf("published %+v to %q with %q", got, path, auth)
	}
	mu.Unlock()
	_ = n.Notify(context.Background(), Notice{Subject: "box: hello recovered", Severity: state.SeverityCritical, Transition: TransitionResolved})
	mu.Lock()
	if got.Priority != 3 {
		t.Fatalf("a recovery should be quieter: %+v", got)
	}
	refuse = true
	mu.Unlock()
	err = n.Notify(context.Background(), Notice{Subject: "box: hello has a problem", Severity: state.SeverityWarning, Transition: TransitionOpen})
	if err == nil || strings.Contains(err.Error(), "alerts-k3y") || !strings.Contains(err.Error(), "forbidden for topic") {
		t.Fatalf("the refusal should be shown without the topic: %v", err)
	}
	mu.Lock()
	if got.Priority != 4 {
		t.Fatalf("a warning is high priority: %+v", got)
	}
}
