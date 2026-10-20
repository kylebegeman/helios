package watch

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/incident"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// The task's webhook on the relay, with an obviously fake token, and the
// secret its signature check is set to.
const (
	loomToken  = "examplehooktoken0000"
	loomSecret = "example-signing-secret-0000"
	loomPath   = "/v1/hooks/0123456789abcdef/incidents/" + loomToken
)

// loomHang is an answer that never comes: the fake reads the body, then
// holds the request until the client gives up.
const loomHang = -1

// loomHeld is the relay's answer while Loom is offline and it holds what
// it is sent: 202 {"queued":true}, whatever the signature, since only
// Loom checks it.
const loomHeld = -2

// loomCodes are the codes the relay and Loom answer each status with.
var loomCodes = map[int]string{
	http.StatusBadRequest: "invalid_body", http.StatusUnauthorized: "invalid_signature", http.StatusNotFound: "hook_not_found",
	http.StatusMethodNotAllowed: "method_not_allowed", http.StatusConflict: "hook_disabled", http.StatusGone: "delivery_too_old",
	http.StatusRequestEntityTooLarge: "body_too_large", http.StatusTooManyRequests: "rate_limited",
	http.StatusInternalServerError: "internal_error", http.StatusServiceUnavailable: "environment_unavailable",
	http.StatusGatewayTimeout: "environment_timeout",
}

// fakeLoom stands in for the relay and the Loom task behind it. It checks
// each body's signature as Loom's webhookVerification.ts does, and answers
// with the statuses it is given, in order, then as Loom would: 202 for a
// signed body and 401 for any other.
type fakeLoom struct {
	mu       sync.Mutex
	answers  []int
	requests []loomRequest
	server   *httptest.Server
}

type loomRequest struct {
	header http.Header
	body   []byte
	signed bool
	status int
}

func newFakeLoom(t *testing.T) *fakeLoom {
	t.Helper()
	f := &fakeLoom{}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		signed := verifyLoomSignature(loomSecret, r.Header, body)
		f.mu.Lock()
		status := http.StatusAccepted
		switch {
		case r.Method != http.MethodPost || r.URL.EscapedPath() != loomPath:
			status = http.StatusNotFound
		case len(f.answers) > 0:
			status, f.answers = f.answers[0], f.answers[1:]
		case !signed:
			status = http.StatusUnauthorized
		}
		f.requests = append(f.requests, loomRequest{header: r.Header.Clone(), body: body, signed: signed, status: status})
		n := len(f.requests)
		f.mu.Unlock()
		switch status {
		case loomHang:
			<-r.Context().Done()
		case loomHeld:
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprint(w, `{"queued":true}`)
		case http.StatusAccepted:
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"deliveryId":"delivery-%d"}`, n)
		default:
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"error":%q}`, loomCodes[status])
		}
	}))
	t.Cleanup(f.server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	was := loomRoots
	loomRoots = roots
	t.Cleanup(func() { loomRoots = was })
	return f
}

func (f *fakeLoom) url() string { return f.server.URL + loomPath }

// answer queues the statuses the next requests get.
func (f *fakeLoom) answer(statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers = append(f.answers, statuses...)
}

func (f *fakeLoom) got() []loomRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// last is the newest request, as Loom read it.
func (f *fakeLoom) last(t *testing.T) (loomRequest, loomSent) {
	t.Helper()
	got := f.got()
	if len(got) == 0 {
		t.Fatal("Loom got nothing")
	}
	return got[len(got)-1], got[len(got)-1].read(t)
}

// loomSent is a body as Loom reads it.
type loomSent struct {
	EventID    string          `json:"event_id"`
	IncidentID int64           `json:"incident_id"`
	Transition string          `json:"transition"`
	Host       string          `json:"host"`
	Key        string          `json:"key"`
	Severity   string          `json:"severity"`
	Message    string          `json:"message"`
	OpenedAt   time.Time       `json:"opened_at"`
	Evidence   json.RawMessage `json:"evidence"`
}

func (q loomRequest) read(t *testing.T) loomSent {
	t.Helper()
	var b loomSent
	if err := json.Unmarshal(q.body, &b); err != nil {
		t.Fatalf("the body isn't JSON: %v", err)
	}
	return b
}

// verifyLoomSignature is Loom's verifyWebhookSignature with the task's
// check set to header x-helios-signature, hex, prefix sha256=.
func verifyLoomSignature(secret string, headers http.Header, body []byte) bool {
	const prefix = "sha256="
	received := headers.Values(LoomSignatureHeader)
	if len(received) == 0 {
		return false
	}
	value := strings.TrimSpace(strings.Join(received, ", "))
	if !strings.HasPrefix(strings.ToLower(value), prefix) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return constantTimeEquals(strings.ToLower(value[len(prefix):]), hex.EncodeToString(mac.Sum(nil)))
}

// constantTimeEquals is Loom's: it compares digests, so the length of
// either string makes no difference to the time it takes.
func constantTimeEquals(a, b string) bool {
	da, db := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}

// fakeNtfy is the person's leg: an ntfy server that counts what it is
// sent, and fails while told to.
type fakeNtfy struct {
	mu   sync.Mutex
	fail bool
	sent int
	// at is when each push it took arrived.
	at     []time.Time
	server *httptest.Server
}

func newFakeNtfy(t *testing.T) *fakeNtfy {
	f := &fakeNtfy{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		f.sent++
		f.at = append(f.at, time.Now())
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeNtfy) setFail(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

func (f *fakeNtfy) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent
}

// since is how long after start each push since then arrived.
func (f *fakeNtfy) since(start time.Time) []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	var after []time.Duration
	for _, at := range f.at {
		if !at.Before(start) {
			after = append(after, at.Sub(start))
		}
	}
	return after
}

// noisyJournal has one container that wrote far more in the window than
// a body carries, its newest line naming the webhook's secret.
type noisyJournal struct{}

func (noisyJournal) Read(_ context.Context, q docker.JournalQuery) ([]docker.JournalContainer, error) {
	c := docker.JournalContainer{ID: "c0ffee", Name: "bedrock-hello-web-r1", App: q.App, Workload: "web", Revision: "r1"}
	for i := range 400 {
		c.Lines = append(c.Lines, docker.JournalLine{At: q.Until.Add(time.Duration(i-400) * time.Second), Stream: "stderr",
			Text: fmt.Sprintf("request %d: the upstream timed out %s", i, strings.Repeat("waiting ", 120))})
	}
	c.Lines = append(c.Lines, docker.JournalLine{At: q.Until, Stream: "stderr", Text: "signing alerts with " + loomSecret})
	return []docker.JournalContainer{c}, nil
}

func (noisyJournal) Suppressed(context.Context, time.Time, time.Time) ([]docker.JournalSuppressed, error) {
	return nil, nil
}

// loomRig is a watcher on web.example.test whose alerts go out through
// ntfy, the person's leg, and the Loom leg to a fake Loom, with a noisy
// app's logs as the evidence.
type loomRig struct {
	t        *testing.T
	w        *Watcher
	now      *time.Time
	sec      *secrets.Store
	loom     *fakeLoom
	ntfy     *fakeNtfy
	stateDir string
}

func newLoomRig(t *testing.T) *loomRig {
	t.Helper()
	r := &loomRig{t: t, loom: newFakeLoom(t), ntfy: newFakeNtfy(t), sec: newSecrets(t)}
	r.set(integration.NtfyName, map[string]string{"topic_url": r.ntfy.server.URL + "/alerts-example"})
	r.setLoomURL(r.loom.url())
	r.w, r.now = newWatcher(t, nil)
	// The clock has nanoseconds, which the state doesn't keep.
	*r.now = r.now.Add(123456789 * time.Nanosecond)
	r.w.Hostname = "web.example.test"
	r.w.Notifier = &Alerts{Secrets: r.sec, Store: r.w.Store, Now: r.w.Now}
	r.stateDir = filepath.Dir(r.w.Store.Path())
	was := evidenceSources
	evidenceSources = func(src *incident.Sources) func() {
		src.Journal = noisyJournal{}
		return func() {}
	}
	t.Cleanup(func() { evidenceSources = was })
	return r
}

func (r *loomRig) set(name string, values map[string]string) {
	r.t.Helper()
	if _, _, err := integration.Set(r.sec, name, values); err != nil {
		r.t.Fatal(err)
	}
}

func (r *loomRig) setLoomURL(url string) {
	r.t.Helper()
	r.set(integration.LoomWebhookName, map[string]string{"url": url, "secret": loomSecret})
}

func (r *loomRig) rounds(n int, conditions ...Condition) {
	r.t.Helper()
	rounds(r.t, r.w, r.now, n, conditions...)
}

// restart is the daemon starting again on the same state, with nothing
// it kept in memory.
func (r *loomRig) restart() {
	r.w = &Watcher{Store: r.w.Store, Hostname: r.w.Hostname, Now: r.w.Now,
		Notifier: &Alerts{Secrets: r.sec, Store: r.w.Store, Now: r.w.Now}}
}

func (r *loomRig) marker(id int64) *incident.LoomMarker {
	r.t.Helper()
	m, err := incident.LoadLoomMarker(r.stateDir, id)
	if err != nil {
		r.t.Fatalf("incident %d has no marker: %v", id, err)
	}
	return m
}

func (r *loomRig) hasMarker(id int64) bool {
	_, err := os.Stat(filepath.Join(incident.Dir(r.stateDir, id), incident.LoomFile))
	return err == nil
}

// hidesTheToken fails if the hook's token or the secret is in any of
// texts, any body Loom got, or any file kept beside the state.
func (r *loomRig) hidesTheToken(texts ...string) {
	r.t.Helper()
	for _, q := range r.loom.got() {
		texts = append(texts, "a body: "+string(q.body))
	}
	err := filepath.WalkDir(r.stateDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), "state.db") {
			return err
		}
		data, err := os.ReadFile(path)
		texts = append(texts, path+": "+string(data))
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
	for _, s := range texts {
		if strings.Contains(s, loomToken) || strings.Contains(s, loomSecret) {
			r.t.Fatalf("the token or the secret shows in %s", s)
		}
	}
}

func legResult(t *testing.T, results []LegResult, name string) LegResult {
	t.Helper()
	for _, r := range results {
		if r.Leg == name {
			return r
		}
	}
	t.Fatalf("no result for %s: %+v", name, results)
	return LegResult{}
}

// A critical incident reaches Loom once, signed, with its evidence fit
// to what a body carries. Retrying the person's leg, repeating the
// incident a day on and resolving it add nothing, and the delivery clears
// a refusal an earlier incident left.
func TestLoomGetsOneSignedBodyPerIncident(t *testing.T) {
	ctx := context.Background()
	r := newLoomRig(t)
	if err := updateAlertTest(r.w.Store, func(record *AlertTest) {
		record.Legs[LoomWebhookLeg] = LegTest{At: r.w.Now(), Error: "the Loom webhook refused incident 1"}
	}); err != nil {
		t.Fatal(err)
	}
	r.ntfy.setFail(true)
	r.rounds(3, down("hello"))
	inc := openIncident(t, r.w)
	q, body := r.loom.last(t)
	if n := len(r.loom.got()); n != 1 || !q.signed || q.status != http.StatusAccepted {
		t.Fatalf("Loom should take one signed body: %d, %+v", n, q)
	}
	if q.header.Get("Content-Type") != "application/json" || q.header.Get("Idempotency-Key") != "" {
		t.Fatalf("headers: %v", q.header)
	}
	want := loomSent{EventID: fmt.Sprintf("web.example.test:%d:open", inc.ID), IncidentID: inc.ID, Transition: TransitionOpen,
		Host: "web.example.test", Key: "app:hello", Severity: state.SeverityCritical, Message: "web isn't running", OpenedAt: inc.OpenedAt}
	got := body
	if !got.OpenedAt.Equal(want.OpenedAt) {
		t.Fatalf("opened_at %s, the incident's %s", got.OpenedAt, want.OpenedAt)
	}
	got.OpenedAt, got.Evidence = want.OpenedAt, nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("body:\n got %+v\nwant %+v", got, want)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, body.Evidence, "", "  "); err != nil {
		t.Fatal(err)
	}
	var evidence incident.Evidence
	if err := json.Unmarshal(body.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	saved, err := os.Stat(filepath.Join(incident.Dir(r.stateDir, inc.ID), incident.EvidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	if indented.Len() > incident.LoomEvidenceMax || len(evidence.Logs) != 1 || len(evidence.Truncated) == 0 || saved.Size() <= incident.LoomEvidenceMax {
		t.Fatalf("the body's evidence is %d bytes with %d logs, truncated %v; the saved is %d", indented.Len(), len(evidence.Logs), evidence.Truncated, saved.Size())
	}
	if m := r.marker(inc.ID); m.State != incident.LoomDelivered || m.Status != http.StatusAccepted || m.DeliveryID != "delivery-1" ||
		m.EventID != want.EventID || !m.OpenedAt.Equal(inc.OpenedAt) || m.Error != "" {
		t.Fatalf("marker: %+v", m)
	}
	if record, err := ReadAlertTest(r.w.Store); err != nil || record.Legs[LoomWebhookLeg].Error != "" {
		t.Fatalf("a delivery should clear the earlier refusal: %+v, %v", record, err)
	}
	if uses, err := r.w.Store.IntegrationUses(ctx); err != nil || uses[LoomWebhookLeg].Purpose != "alert: web.example.test: hello is down" {
		t.Fatalf("uses: %+v, %v", uses, err)
	}

	r.rounds(2, down("hello"))
	r.ntfy.setFail(false)
	r.rounds(3, down("hello"))
	if inc := openIncident(t, r.w); inc.NotifyError != "" || r.ntfy.count() != 1 {
		t.Fatalf("ntfy should have it by now: %d sent, %+v", r.ntfy.count(), inc)
	}
	*r.now = r.now.Add(25 * time.Hour)
	r.rounds(1, down("hello"))
	r.rounds(2)
	if n := len(r.loom.got()); n != 1 || r.ntfy.count() != 3 {
		t.Fatalf("Loom should hear of the incident once: %d bodies, ntfy %d", n, r.ntfy.count())
	}
	r.hidesTheToken()
}

// A warning that becomes an outage reaches Loom when it does, once, as a
// repeat with the outage's message.
func TestAWarningThatBecomesAnOutageReachesLoomOnce(t *testing.T) {
	r := newLoomRig(t)
	r.rounds(3, stale("hello"))
	if n := len(r.loom.got()); n != 0 || r.ntfy.count() != 1 {
		t.Fatalf("a warning is no business of Loom's: %d bodies, ntfy %d", n, r.ntfy.count())
	}
	r.rounds(3, down("hello"))
	inc := openIncident(t, r.w)
	_, body := r.loom.last(t)
	if n := len(r.loom.got()); n != 1 || body.EventID != fmt.Sprintf("web.example.test:%d:repeat", inc.ID) || body.Transition != TransitionRepeat ||
		body.Severity != state.SeverityCritical || body.Message != "web isn't running" || !body.OpenedAt.Equal(inc.OpenedAt) {
		t.Fatalf("%d bodies, the last %+v", n, body)
	}
	r.rounds(3, down("hello"))
	if n := len(r.loom.got()); n != 1 {
		t.Fatalf("the outage went to Loom %d times", n)
	}
}

// The body's key and message are the evidence's: redacted as it is, and
// cut to the same length.
func TestTheBodysKeyAndMessageAreRedactedAndCutAsTheEvidenceIs(t *testing.T) {
	r := newLoomRig(t)
	const token = "fake_watch_token_0000"
	tail := strings.Repeat("x", 5000)
	r.rounds(3, Condition{Key: "watch:https://status.example.test/health?token=" + token, Subject: "status.example.test", Severity: state.SeverityCritical,
		Message: "the probe signed with " + loomSecret + " from 10.0.0.1 got 502 " + tail})
	q, body := r.loom.last(t)
	var evidence incident.Evidence
	if err := json.Unmarshal(body.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	redacted := "the probe signed with [redacted LOOM_WEBHOOK_SECRET] from [private] got 502 " + tail
	message := redacted[:4<<10] + "[+" + strconv.Itoa(len(redacted)-4<<10) + " bytes]"
	key := "watch:https://status.example.test/health?token=[redacted]"
	if body.Key != key || evidence.Incident.Key != key || body.Message != message || evidence.Incident.Message != message {
		t.Fatalf("key %q, message %.120q of %d bytes; the evidence's %q, %.120q", body.Key, body.Message, len(body.Message), evidence.Incident.Key, evidence.Incident.Message)
	}
	for _, s := range []string{token, "10.0.0.1"} {
		if bytes.Contains(q.body, []byte(s)) {
			t.Fatalf("the body holds %q", s)
		}
	}
	r.hidesTheToken()
}

// A body Loom may have, because no clear answer came after it was
// written, is never sent again: not when the fan-out retries the leg, and
// not when the daemon starts again and sends the notice to every leg.
// Either way the error is told once and then clears.
func TestAnUnclearAnswerIsNeverSentAgain(t *testing.T) {
	was := loomRequestTimeout
	loomRequestTimeout = 300 * time.Millisecond
	t.Cleanup(func() { loomRequestTimeout = was })
	for _, status := range []int{loomHang, http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		for _, restart := range []bool{false, true} {
			name := strconv.Itoa(status)
			if status == loomHang {
				name = "hang"
			}
			if restart {
				name += " then a restart"
			}
			t.Run(name, func(t *testing.T) {
				r := newLoomRig(t)
				r.loom.answer(status)
				r.rounds(3, down("hello"))
				inc := openIncident(t, r.w)
				if !strings.Contains(inc.NotifyError, "loom_webhook: the Loom webhook may have incident") || !strings.Contains(inc.NotifyError, "it isn't sent again") {
					t.Fatalf("notify error: %q", inc.NotifyError)
				}
				m := r.marker(inc.ID)
				if wantStatus := max(status, 0); m.State != incident.LoomAmbiguous || m.Status != wantStatus {
					t.Fatalf("marker: %+v", m)
				}
				if restart {
					r.restart()
				}
				r.rounds(1, down("hello"))
				if inc := openIncident(t, r.w); inc.NotifyError != "" {
					t.Fatalf("the error should be told once: %q", inc.NotifyError)
				}
				*r.now = r.now.Add(25 * time.Hour)
				r.rounds(1, down("hello"))
				r.rounds(2)
				if got := r.loom.got(); len(got) != 1 {
					t.Fatalf("Loom got %d bodies", len(got))
				}
				r.hidesTheToken(inc.NotifyError, m.Error)
			})
		}
	}
}

// A body that never arrived, because nothing answered or the hook was
// rate limited before it was read, is tried again until Loom takes it,
// once.
func TestLoomIsTriedAgainOnlyWhileTheBodyHasntArrived(t *testing.T) {
	r := newLoomRig(t)
	r.setLoomURL("https://127.0.0.1:" + closedPort(t) + loomPath)
	r.rounds(3, down("hello"))
	inc := openIncident(t, r.w)
	if !strings.Contains(inc.NotifyError, "the Loom webhook wasn't reached") || !strings.Contains(inc.NotifyError, "it is tried again") || r.hasMarker(inc.ID) {
		t.Fatalf("an unreachable hook: %q, marker %v", inc.NotifyError, r.hasMarker(inc.ID))
	}
	refused := inc.NotifyError
	r.setLoomURL(r.loom.url())
	r.loom.answer(http.StatusTooManyRequests)
	r.rounds(1, down("hello"))
	inc = openIncident(t, r.w)
	if !strings.Contains(inc.NotifyError, "rate limited (HTTP 429 rate_limited); it is tried again") || r.hasMarker(inc.ID) {
		t.Fatalf("a rate limited hook: %q, marker %v", inc.NotifyError, r.hasMarker(inc.ID))
	}
	limited := inc.NotifyError
	r.rounds(3, down("hello"))
	inc = openIncident(t, r.w)
	var statuses []int
	for _, q := range r.loom.got() {
		statuses = append(statuses, q.status)
	}
	if !slices.Equal(statuses, []int{http.StatusTooManyRequests, http.StatusAccepted}) || inc.NotifyError != "" || r.marker(inc.ID).State != incident.LoomDelivered {
		t.Fatalf("Loom should take it once: %v, %q", statuses, inc.NotifyError)
	}
	r.rounds(3, down("hello"))
	if n := len(r.loom.got()); n != 2 {
		t.Fatalf("Loom got %d requests", n)
	}
	r.hidesTheToken(refused, limited)
}

// A body Loom turned away is never sent again, and the refusal stays a
// warning about the alerts until a signed test gets through: a passing
// probe shows the hook is there, not that the secret is right.
func TestARefusalIsNeverSentAgainAndRaisesAWarning(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusGone, http.StatusRequestEntityTooLarge} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			r := newLoomRig(t)
			r.loom.answer(status)
			r.rounds(3, down("hello"))
			inc := openIncident(t, r.w)
			want := fmt.Sprintf("the Loom webhook refused incident %d (HTTP %d %s): %s; it isn't sent again", inc.ID, status, loomCodes[status], loomRefusals[status])
			if inc.NotifyError != "loom_webhook: "+want+"; delivered by ntfy" {
				t.Fatalf("notify error: %q", inc.NotifyError)
			}
			if m := r.marker(inc.ID); m.State != incident.LoomRefused || m.Status != status {
				t.Fatalf("marker: %+v", m)
			}
			r.rounds(3, down("hello"))
			if inc := openIncident(t, r.w); len(r.loom.got()) != 1 || inc.NotifyError != "" {
				t.Fatalf("a refusal is told once and never sent again: %d bodies, %q", len(r.loom.got()), inc.NotifyError)
			}

			p := NewProber(r.w.Store)
			raised := func(what string) {
				t.Helper()
				got := p.alertTest()
				if len(got) != 1 || got[0].Key != "host:alerts" || !strings.Contains(got[0].Message, "loom_webhook failed its test on ") ||
					!strings.Contains(got[0].Message, want) || !strings.HasSuffix(got[0].Message, "fix it, then run helios alerts test --leg loom_webhook") {
					t.Fatalf("%s: %+v", what, got)
				}
			}
			raised("the refusal")
			results, err := SendTestAlerts(ctx, r.sec, r.w.Store, r.w.Hostname, "", r.w.Now())
			if l := legResult(t, results, LoomWebhookLeg); err != nil || l.Error != "" || !l.Probe {
				t.Fatalf("the probe should pass: %+v, %v", results, err)
			}
			raised("after a probe")
			results, err = SendTestAlerts(ctx, r.sec, r.w.Store, r.w.Hostname, LoomWebhookLeg, r.w.Now())
			if l := legResult(t, results, LoomWebhookLeg); err != nil || l.Error != "" || l.Probe {
				t.Fatalf("the signed test should pass: %+v, %v", results, err)
			}
			if got := p.alertTest(); got != nil {
				t.Fatalf("a signed test that arrives clears it: %+v", got)
			}
			if n := len(r.loom.got()); n != 3 {
				t.Fatalf("Loom got %d requests", n)
			}
			r.hidesTheToken(inc.NotifyError)
		})
	}
}

// A marker an earlier incident with the same id left, from before the
// state was replaced, is cleared away with its evidence and the incident
// is sent. A marker this incident left, still sending because the daemon
// stopped mid-send or torn by a crash, holds the send for good.
func TestAStaleMarkerIsReplacedAndALeftoverOneHoldsTheSend(t *testing.T) {
	ctx := context.Background()
	r := newLoomRig(t)
	l := &LoomNotifier{LoomWebhook: integration.LoomWebhook{URL: r.loom.url(), Secret: loomSecret}, Store: r.w.Store, Secrets: r.sec}
	opened := r.w.Now().Truncate(time.Millisecond)
	notice := func() Notice {
		inc := state.Incident{Key: "app:hello", Subject: "hello", Severity: state.SeverityCritical, Message: "web isn't running", OpenedAt: opened}
		id, err := r.w.Store.OpenIncident(ctx, inc)
		if err != nil {
			t.Fatal(err)
		}
		return Notice{IncidentID: id, Key: inc.Key, Transition: TransitionOpen, Severity: inc.Severity, Host: r.w.Hostname, Message: inc.Message, OpenedAt: opened}
	}
	write := func(id int64, data []byte) {
		t.Helper()
		dir := incident.Dir(r.stateDir, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := incident.WriteFile(filepath.Join(dir, incident.LoomFile), data); err != nil {
			t.Fatal(err)
		}
	}
	marker := func(id int64, at time.Time, state string) []byte {
		data, _ := json.Marshal(incident.LoomMarker{Schema: incident.LoomMarkerSchema, EventID: fmt.Sprintf("web.example.test:%d:open", id), OpenedAt: at, State: state})
		return data
	}

	n := notice()
	earlier := opened.Add(-48 * time.Hour)
	if err := incident.Save(r.stateDir, &incident.Evidence{Schema: incident.Schema, Incident: incident.Incident{ID: n.IncidentID, OpenedAt: earlier}}); err != nil {
		t.Fatal(err)
	}
	write(n.IncidentID, marker(n.IncidentID, earlier, incident.LoomDelivered))
	if err := l.Notify(ctx, n); err != nil {
		t.Fatal(err)
	}
	inc, err := r.w.Store.Incident(ctx, n.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if m := r.marker(n.IncidentID); len(r.loom.got()) != 1 || m.State != incident.LoomDelivered || !m.OpenedAt.Equal(opened) {
		t.Fatalf("the incident should be sent: %d bodies, %+v", len(r.loom.got()), m)
	}
	if _, err := incident.Load(r.stateDir, *inc); err != nil {
		t.Fatalf("the evidence should be this incident's: %v", err)
	}

	for name, data := range map[string][]byte{"sending": nil, "torn": []byte(`{"schema": 1, "state": "sen`)} {
		n := notice()
		if data == nil {
			data = marker(n.IncidentID, opened, incident.LoomSending)
		}
		write(n.IncidentID, data)
		if err := l.Notify(ctx, n); err != nil || len(r.loom.got()) != 1 {
			t.Fatalf("a %s marker should hold the send: %d bodies, %v", name, len(r.loom.got()), err)
		}
	}
}

// A marker that fails partway through being written was the claim on a
// send that never went out, so it is taken back and the send tried
// again: Loom gets the incident once the fault clears, and only once.
func TestAMarkerThatCantBeWrittenIsTakenBack(t *testing.T) {
	ctx := context.Background()
	r := newLoomRig(t)
	l := &LoomNotifier{LoomWebhook: integration.LoomWebhook{URL: r.loom.url(), Secret: loomSecret}, Store: r.w.Store, Secrets: r.sec}
	inc := state.Incident{Key: "app:hello", Subject: "hello", Severity: state.SeverityCritical, Message: "web isn't running", OpenedAt: r.w.Now().Truncate(time.Millisecond)}
	id, err := r.w.Store.OpenIncident(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	n := Notice{IncidentID: id, Key: inc.Key, Transition: TransitionOpen, Severity: inc.Severity, Host: r.w.Hostname, Message: inc.Message, OpenedAt: inc.OpenedAt}
	// A directory that can't be read takes the marker but fails the sync
	// that puts it on disk, as a full disk or an I/O error would.
	dir := incident.Dir(r.stateDir, id)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	err = l.Notify(ctx, n)
	if err == nil || !strings.Contains(err.Error(), "it is tried again") || r.hasMarker(id) || len(r.loom.got()) != 0 {
		t.Fatalf("a marker that can't be written: %v, marker %v, %d bodies", err, r.hasMarker(id), len(r.loom.got()))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := l.Notify(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if m := r.marker(id); len(r.loom.got()) != 1 || m.State != incident.LoomDelivered {
		t.Fatalf("Loom should get it once: %d bodies, %+v", len(r.loom.got()), m)
	}
}

// A body the connection was reset under while it was written never
// arrived whole, and a body cut short can't pass the signature check,
// so it is tried again.
func TestABodyCutOffWhileItIsWrittenIsTriedAgain(t *testing.T) {
	loom := newFakeLoom(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(raw, &tls.Config{Certificates: loom.server.TLS.Certificates})
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// The relay reads the start of the request and drops the
			// connection with a reset.
			_, _ = io.ReadFull(c, make([]byte, 4<<10))
			c.(*tls.Conn).NetConn().(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}()
	l := &LoomNotifier{LoomWebhook: integration.LoomWebhook{URL: "https://" + ln.Addr().String() + loomPath, Secret: loomSecret}}
	// Far more than the connection holds in flight, so the write is
	// still going when the reset comes.
	body := []byte(`{"message":"` + strings.Repeat("waiting ", 1<<20) + `"}`)
	a := l.post(context.Background(), body, loomSecret)
	if a.outcome() != "" || a.status != 0 || !strings.Contains(a.notSent().Error(), "the Loom webhook wasn't reached") {
		t.Fatalf("a body cut off while it is written: wrote %v, outcome %q, %v", a.wrote, a.outcome(), a.err)
	}
}

// The signature is the HMAC-SHA256 of the exact body, as openssl gives
// it, and Loom's check takes it, in any case and with space around it,
// only for that body and that secret.
func TestTheSignatureIsWhatLoomChecks(t *testing.T) {
	body := []byte(`{"event_id":"web.example.test:42:open","incident_id":42}`)
	// printf '%s' "$body" | openssl dgst -sha256 -hmac example-signing-secret-0000
	const want = "sha256=e3eb34f8e1d4bbf53a1a0311a37292fe6c2923f5684cc7412a245908c26e2f13"
	if got := signLoomBody(loomSecret, body); got != want {
		t.Fatalf("signature %s, want %s", got, want)
	}
	header := http.Header{}
	header.Set(LoomSignatureHeader, " SHA256="+strings.ToUpper(strings.TrimPrefix(want, "sha256="))+" ")
	if !verifyLoomSignature(loomSecret, header, body) {
		t.Fatal("Loom should take the signature")
	}
	if verifyLoomSignature(loomSecret, header, bytes.Replace(body, []byte("42"), []byte("43"), 1)) {
		t.Fatal("Loom should refuse a changed body")
	}
	if verifyLoomSignature("example-other-secret-0000", header, body) {
		t.Fatal("Loom should refuse another secret")
	}
}

// Loom tells an agent, so a host with only the Loom leg set up has no one
// to tell; beside ntfy, the Loom leg carries only outages and has its own
// timeout.
func TestTheLoomLegNeedsAPersonLegAndCarriesOnlyOutages(t *testing.T) {
	r := newLoomRig(t)
	if _, err := integration.Remove(r.sec, integration.NtfyName); err != nil {
		t.Fatal(err)
	}
	if f, err := LoadFanout(r.sec, r.w.Store); err == nil || err.Error() != NoPersonLeg {
		t.Fatalf("Loom alone: %+v, %v", f, err)
	}
	r.set(integration.NtfyName, map[string]string{"topic_url": r.ntfy.server.URL + "/alerts-example"})
	f, err := LoadFanout(r.sec, r.w.Store)
	if err != nil || len(f.Legs) != 2 {
		t.Fatalf("Loom beside ntfy: %+v, %v", f, err)
	}
	l := f.Legs[1]
	if _, ok := l.Notifier.(*LoomNotifier); !ok || l.Name != LoomWebhookLeg || l.MinSeverity != state.SeverityCritical || l.Timeout != LoomTimeout {
		t.Fatalf("the Loom leg: %+v", l)
	}
}

// A probe is signed with a key Loom can't know, so it passes only when
// Loom turns it away at the signature check. A test of the Loom leg alone
// is signed and opens a thread. Neither leaves a marker.
func TestAProbePassesOnlyWhenLoomTurnsItAway(t *testing.T) {
	ctx := context.Background()
	r := newLoomRig(t)
	probe := func(what string) LegResult {
		t.Helper()
		results, err := SendTestAlerts(ctx, r.sec, r.w.Store, r.w.Hostname, "", r.w.Now())
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if ntfy := legResult(t, results, NtfyLeg); ntfy.Error != "" || ntfy.Probe {
			t.Fatalf("%s: ntfy is sent a test: %+v", what, ntfy)
		}
		return legResult(t, results, LoomWebhookLeg)
	}
	if l := probe("turned away"); l.Error != "" || !l.Probe || l.To != "the Loom task" {
		t.Fatalf("a probe Loom turns away passes: %+v", l)
	}
	q, body := r.loom.last(t)
	if q.signed || q.status != http.StatusUnauthorized || body.Transition != "test" || !strings.HasPrefix(body.EventID, "web.example.test:probe:") ||
		body.IncidentID != 0 || string(body.Evidence) != "null" {
		t.Fatalf("probe %+v answered %d", body, q.status)
	}
	r.loom.answer(http.StatusAccepted)
	if l := probe("taken"); !strings.Contains(l.Error, "the Loom task took a body with a wrong signature") || !strings.Contains(l.Error, "header x-helios-signature, hex, prefix sha256=") {
		t.Fatalf("a probe Loom takes fails: %+v", l)
	}
	r.loom.answer(http.StatusNotFound)
	if l := probe("no such hook"); l.Error != "the Loom webhook answered HTTP 404 hook_not_found: "+loomRefusals[http.StatusNotFound] {
		t.Fatalf("a probe the relay can't route fails: %+v", l)
	}
	if got := NewProber(r.w.Store).alertTest(); len(got) != 1 || !strings.HasSuffix(got[0].Message, "fix it, then run helios alerts test") {
		t.Fatalf("a failed probe is fixed by another: %+v", got)
	}

	results, err := SendTestAlerts(ctx, r.sec, r.w.Store, r.w.Hostname, LoomWebhookLeg, r.w.Now())
	if l := legResult(t, results, LoomWebhookLeg); err != nil || l.Error != "" || l.Probe {
		t.Fatalf("a signed test Loom takes passes: %+v, %v", results, err)
	}
	q, body = r.loom.last(t)
	if !q.signed || q.status != http.StatusAccepted || body.Transition != "test" || !strings.HasPrefix(body.EventID, "web.example.test:test:") {
		t.Fatalf("test %+v answered %d", body, q.status)
	}
	if _, err := os.Stat(filepath.Join(r.stateDir, "incidents")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a probe or a test leaves no marker: %v", err)
	}
	r.hidesTheToken()
}

// While Loom is offline the relay holds what it is sent and answers 202
// before Loom has checked it. A held probe or test shows neither that the
// leg works nor that it doesn't, so the last result stands, and a held
// incident counts as sent but clears no refusal: only Loom's answer does.
func TestWhatTheRelayHoldsProvesNothing(t *testing.T) {
	ctx := context.Background()
	r := newLoomRig(t)
	p := NewProber(r.w.Store)
	test := func(only string) LegResult {
		t.Helper()
		results, err := SendTestAlerts(ctx, r.sec, r.w.Store, r.w.Hostname, only, r.w.Now())
		if err != nil {
			t.Fatal(err)
		}
		return legResult(t, results, LoomWebhookLeg)
	}
	r.loom.answer(loomHeld)
	if l := test(""); l.Error != "" || !l.Held || !l.Probe {
		t.Fatalf("a held probe: %+v", l)
	}
	if got := p.alertTest(); got != nil {
		t.Fatalf("a held probe raises nothing: %+v", got)
	}

	r.set(integration.LoomWebhookName, map[string]string{"url": r.loom.url(), "secret": "example-wrong-secret-0000"})
	r.rounds(3, down("hello"))
	raised := func(what string) {
		t.Helper()
		if got := p.alertTest(); len(got) != 1 || !strings.Contains(got[0].Message, loomRefusals[http.StatusUnauthorized]) {
			t.Fatalf("%s: %+v", what, got)
		}
	}
	raised("the refusal")
	r.loom.answer(loomHeld)
	if l := test(LoomWebhookLeg); l.Error != "" || !l.Held || l.Probe {
		t.Fatalf("a held test: %+v", l)
	}
	raised("after a held test")
	r.loom.answer(loomHeld)
	r.rounds(3, down("hello"), down("shop"))
	shop, err := r.w.Store.OpenIncidentByKey(ctx, "app:shop")
	if err != nil || shop == nil {
		t.Fatalf("shop: %+v, %v", shop, err)
	}
	if m := r.marker(shop.ID); m.State != incident.LoomDelivered || m.Status != http.StatusAccepted || shop.NotifyError != "" {
		t.Fatalf("a held incident is sent: %+v, %q", m, shop.NotifyError)
	}
	raised("after a held incident")
	if n := len(r.loom.got()); n != 4 {
		t.Fatalf("Loom got %d requests", n)
	}
}

// A page never waits on a Loom leg, whether it is another outage's that
// opens in the same round or a retry that is due as an incident
// recovers: every notice of a round goes out at once.
func TestAPageNeverWaitsOnALoomLeg(t *testing.T) {
	was := loomRequestTimeout
	loomRequestTimeout = 2 * time.Second
	t.Cleanup(func() { loomRequestTimeout = was })
	// timed runs one round and says how long after it started each page
	// arrived, failing if the round didn't wait out a hanging Loom leg.
	timed := func(r *loomRig, conditions ...Condition) []time.Duration {
		t.Helper()
		start := time.Now()
		r.rounds(1, conditions...)
		if took := time.Since(start); took < loomRequestTimeout {
			t.Fatalf("the round took %s, so no Loom leg hung in it", took)
		}
		return r.ntfy.since(start)
	}
	// prompt is well before a Loom leg that hangs gives up.
	prompt := loomRequestTimeout / 2

	t.Run("two outages in a round", func(t *testing.T) {
		r := newLoomRig(t)
		r.loom.answer(loomHang, loomHang)
		r.rounds(2, down("hello"), down("shop"))
		pages := timed(r, down("hello"), down("shop"))
		if len(pages) != 2 || pages[0] >= prompt || pages[1] >= prompt {
			t.Fatalf("both outages should be paged at once: %v", pages)
		}
		if n := len(r.loom.got()); n != 2 {
			t.Fatalf("Loom got %d requests", n)
		}
	})

	t.Run("a Loom retry as another incident recovers", func(t *testing.T) {
		r := newLoomRig(t)
		r.rounds(1, down("shop"))
		r.rounds(2, down("shop"), down("hello"))
		r.setLoomURL("https://127.0.0.1:" + closedPort(t) + loomPath)
		r.rounds(1, down("hello"))
		r.setLoomURL(r.loom.url())
		r.loom.answer(loomHang)
		pages := timed(r, down("hello"))
		if len(pages) != 1 || pages[0] >= prompt {
			t.Fatalf("shop's recovery should be paged at once: %v", pages)
		}
		if inc := openIncident(t, r.w); inc.Key != "app:hello" {
			t.Fatalf("shop should have recovered: %+v", inc)
		}
		var statuses []int
		for _, q := range r.loom.got() {
			statuses = append(statuses, q.status)
		}
		if !slices.Equal(statuses, []int{http.StatusAccepted, loomHang}) {
			t.Fatalf("Loom should take shop, then hang on hello's retry: %v", statuses)
		}
	})
}

// An outage whose body never left reaches Loom once it can, though the
// outage has recovered or eased to a warning by then: a later notice
// doesn't take the place of the one Loom missed.
func TestAnOutageThatEndsBeforeLoomIsReachedStillReachesItOnce(t *testing.T) {
	ctx := context.Background()
	// unreached opens hello's outage while the hook can't be reached.
	unreached := func(t *testing.T) (*loomRig, int64) {
		t.Helper()
		r := newLoomRig(t)
		r.setLoomURL("https://127.0.0.1:" + closedPort(t) + loomPath)
		r.rounds(3, down("hello"))
		inc := openIncident(t, r.w)
		if !strings.Contains(inc.NotifyError, "it is tried again") || r.hasMarker(inc.ID) {
			t.Fatalf("an unreachable hook: %q, marker %v", inc.NotifyError, r.hasMarker(inc.ID))
		}
		return r, inc.ID
	}
	// reachedOnce checks that Loom took the outage once, as the open
	// notice it missed, and that nothing is owed any more.
	reachedOnce := func(t *testing.T, r *loomRig, id int64) *state.Incident {
		t.Helper()
		r.rounds(20)
		got := r.loom.got()
		if len(got) != 1 || got[0].status != http.StatusAccepted {
			t.Fatalf("Loom should take the outage once: %d requests", len(got))
		}
		body := got[0].read(t)
		var evidence incident.Evidence
		if err := json.Unmarshal(body.Evidence, &evidence); err != nil {
			t.Fatal(err)
		}
		if body.Transition != TransitionOpen || body.Severity != state.SeverityCritical || !evidence.Late || r.marker(id).State != incident.LoomDelivered {
			t.Fatalf("the body should be the outage, collected late: %+v, late %v", body, evidence.Late)
		}
		inc, err := r.w.Store.Incident(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if inc.NotifyError != "" {
			t.Fatalf("nothing should be owed: %q", inc.NotifyError)
		}
		return inc
	}

	t.Run("recovered", func(t *testing.T) {
		r, id := unreached(t)
		r.setLoomURL(r.loom.url())
		r.rounds(2)
		if inc := reachedOnce(t, r, id); inc.ResolvedAt.IsZero() {
			t.Fatalf("hello should have recovered: %+v", inc)
		}
	})

	t.Run("recovered while Loom is still away", func(t *testing.T) {
		r, id := unreached(t)
		r.rounds(1, down("hello"))
		r.rounds(2)
		inc, err := r.w.Store.Incident(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if inc.ResolvedAt.IsZero() || !strings.Contains(inc.NotifyError, "loom_webhook: ") || len(r.loom.got()) != 0 {
			t.Fatalf("a recovery should keep Loom owed: %+v", inc)
		}
		r.setLoomURL(r.loom.url())
		reachedOnce(t, r, id)
		if n := r.ntfy.count(); n != 2 {
			t.Fatalf("ntfy should have the outage and its recovery once each: %d", n)
		}
	})

	t.Run("eased while Loom is still away", func(t *testing.T) {
		r, id := unreached(t)
		r.rounds(1, down("hello"))
		r.rounds(2, stale("hello"))
		if inc := openIncident(t, r.w); inc.Severity != state.SeverityWarning || !strings.Contains(inc.NotifyError, "loom_webhook: ") {
			t.Fatalf("easing should keep Loom owed: %+v", inc)
		}
		r.setLoomURL(r.loom.url())
		r.rounds(5, stale("hello"))
		if inc := reachedOnce(t, r, id); inc.ResolvedAt.IsZero() {
			t.Fatalf("hello should have recovered: %+v", inc)
		}
	})
}
