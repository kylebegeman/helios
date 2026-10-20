package watch

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kylebegeman/helios/internal/incident"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// LoomTimeout bounds the Loom leg's delivery: collecting the evidence
// takes up to incident.CollectBudget and the request up to 20 seconds,
// which leaves time to record what came of it.
const LoomTimeout = 45 * time.Second

// LoomSignatureHeader carries a body's signature: sha256= and the
// HMAC-SHA256 of the body under the integration's secret, in lowercase
// hex, as the Loom task's signature check is set to read it.
const LoomSignatureHeader = "x-helios-signature"

// loomTestTransition is the transition of a probe or a test send, which
// the task's prompt stops on.
const loomTestTransition = "test"

// loomAnswerMax is the most of an answer read.
const loomAnswerMax = 64 << 10

var (
	// loomRoots are what the relay's certificate is checked against; nil
	// is the system's. Tests replace it.
	loomRoots *x509.CertPool
	// loomRequestTimeout bounds one request, above the relay's 8 seconds
	// to reach Loom. Tests replace it.
	loomRequestTimeout = 20 * time.Second
	// evidenceSources points src at this machine's Docker, journal and
	// upstream status pages, and returns what releases them. Tests
	// replace it.
	evidenceSources = incident.Local
)

// Statuses that turn a body away for good: sending it again gets the
// same answer. Any 3xx does too, since the relay never redirects a hook.
var loomRefusals = map[int]string{
	http.StatusBadRequest:            "the relay couldn't read the body",
	http.StatusUnauthorized:          "loom_webhook.secret isn't the secret the task checks; set it again with helios integration set loom_webhook",
	http.StatusNotFound:              "the relay knows no such hook; check that loom_webhook.url is the task's webhook URL",
	http.StatusMethodNotAllowed:      "the relay takes no POST at that URL",
	http.StatusConflict:              "the task's webhook is turned off in Loom",
	http.StatusGone:                  "the relay held it past the hook's max delivery age",
	http.StatusRequestEntityTooLarge: "the body is over what Loom takes",
}

// loomCode is the shape of the error codes the relay and Loom answer
// with; anything else they say is left out.
var loomCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

// LoomNotifier opens a Loom thread for a critical incident, with the
// incident's evidence, through the task's webhook on the T3 Connect
// relay. It sends each incident at most once: a marker is on disk before
// the request goes, and a request that might have arrived is never sent
// again. Only one that never left is tried again.
type LoomNotifier struct {
	integration.LoomWebhook
	Store *state.Store
	// Secrets are what the evidence is redacted with; nil leaves the logs
	// out of it.
	Secrets *secrets.Store
}

// loomBody is what Loom gets. Evidence is null for a probe, a test, or an
// incident whose evidence couldn't be shown to be free of secrets.
type loomBody struct {
	EventID    string             `json:"event_id"`
	IncidentID int64              `json:"incident_id"`
	Transition string             `json:"transition"`
	Host       string             `json:"host"`
	Key        string             `json:"key"`
	Severity   string             `json:"severity"`
	Message    string             `json:"message"`
	OpenedAt   time.Time          `json:"opened_at"`
	Evidence   *incident.Evidence `json:"evidence"`
}

// Notify implements Notifier. Loom hears of an incident once, at its
// first critical notice: a resolve, a repeat of a notice already sent
// and anything less than critical return nil without sending.
func (l *LoomNotifier) Notify(ctx context.Context, n Notice) error {
	switch {
	case n.Test != "":
		return l.test(ctx, n)
	case n.IncidentID == 0 || n.Transition == TransitionResolved || n.Severity != state.SeverityCritical:
		// The fan-out keeps warnings from this leg; this keeps one from
		// taking the incident's one send if it ever got here.
		return nil
	case l.Store == nil:
		return errors.New("no state store to keep the send's marker in")
	}
	stateDir := filepath.Dir(l.Store.Path())
	dir := incident.Dir(stateDir, n.IncidentID)
	markerPath, evidencePath := filepath.Join(dir, incident.LoomFile), filepath.Join(dir, incident.EvidenceFile)
	// The state keeps times to the millisecond, so the incident read back
	// after a restart has to match the notice that was sent.
	openedAt := n.OpenedAt.UTC().Truncate(time.Millisecond)

	marker, err := incident.LoadLoomMarker(stateDir, n.IncidentID)
	switch {
	case err == nil && marker.OpenedAt.Equal(openedAt):
		return nil
	case err == nil:
		// The id was given out again after the state was replaced: the
		// marker and evidence are an earlier incident's.
		if err := incident.Remove(evidencePath, markerPath); err != nil {
			return fmt.Errorf("remove an earlier incident's Loom marker: %w", err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		// Anything there, even a marker torn by a crash, holds the send.
		return nil
	}

	m := incident.LoomMarker{Schema: incident.LoomMarkerSchema, EventID: fmt.Sprintf("%s:%d:%s", n.Host, n.IncidentID, n.Transition),
		OpenedAt: openedAt, State: incident.LoomSending, At: time.Now().UTC()}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := incident.CreateExclusive(markerPath, data); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		// Nothing went out, so what the failed write left is taken back
		// and the send tried again. A crash before the take-back reaches
		// the disk leaves the marker holding the send, as a crash mid-send
		// does.
		err = fmt.Errorf("mark incident %d as sending to Loom: %w", n.IncidentID, err)
		if rmErr := os.Remove(markerPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return fmt.Errorf("%w, and the marker can't be removed, so it won't be sent: %v", err, rmErr)
		}
		return fmt.Errorf("%w; it is tried again", err)
	}

	body, notes, err := l.body(ctx, n, m.EventID, openedAt, stateDir)
	if err != nil {
		if rmErr := incident.Remove(markerPath); rmErr != nil {
			return fmt.Errorf("%w, and its marker can't be removed, so it won't be sent: %v", err, rmErr)
		}
		return err
	}
	a := l.post(ctx, body, l.Secret)
	m.State, m.Status, m.DeliveryID, m.At = a.outcome(), a.status, a.deliveryID, time.Now().UTC()
	var sendErr error
	switch m.State {
	case "":
		sendErr = a.notSent()
	case incident.LoomRefused:
		sendErr = fmt.Errorf("the Loom webhook refused incident %d (%s): %s; it isn't sent again", n.IncidentID, a.answered(), a.hint())
	case incident.LoomAmbiguous:
		sendErr = fmt.Errorf("the Loom webhook may have incident %d: %s; it isn't sent again, so look for its thread in Loom", n.IncidentID, a.unclear())
	}
	if sendErr != nil {
		notes = append([]string{sendErr.Error()}, notes...)
	}
	m.Error = strings.Join(notes, "; ")

	if m.State == "" {
		if err := incident.Remove(markerPath); err != nil {
			return fmt.Errorf("%w, but its marker can't be removed, so it won't be: %v", sendErr, err)
		}
		return sendErr
	}
	var problems []string
	if data, err := json.MarshalIndent(m, "", "  "); err != nil {
		problems = append(problems, "its marker can't be encoded: "+err.Error())
	} else if err := incident.WriteFile(markerPath, data); err != nil {
		problems = append(problems, "its marker can't be updated: "+err.Error())
	}
	switch m.State {
	case incident.LoomDelivered:
		_ = l.Store.RecordIntegrationUse(ctx, LoomWebhookLeg, "alert: "+n.Subject, time.Now().UTC())
		if err := clearLoomFailure(l.Store); err != nil {
			problems = append(problems, "an earlier failure can't be cleared from "+AlertTestFile+": "+err.Error())
		}
	case incident.LoomRefused:
		// Recorded as the leg's failed test, so the prober raises it as a
		// warning through the legs that work.
		err := updateAlertTest(l.Store, func(record *AlertTest) {
			record.Legs[LoomWebhookLeg] = LegTest{At: m.At, Error: sendErr.Error()}
		})
		if err != nil {
			problems = append(problems, "it can't be recorded in "+AlertTestFile+": "+err.Error())
		}
	}
	switch {
	case len(problems) == 0:
		return sendErr
	case sendErr == nil:
		return fmt.Errorf("delivered incident %d to Loom, but %s", n.IncidentID, strings.Join(problems, "; "))
	}
	return fmt.Errorf("%w; and %s", sendErr, strings.Join(problems, "; "))
}

// body collects the incident's evidence, saves it, and returns the body
// that carries it fit to incident.LoomEvidenceMax, with notes on what
// went wrong. The key and message are the evidence's, redacted; evidence
// that can't be shown to be free of secrets leaves all three out.
func (l *LoomNotifier) body(ctx context.Context, n Notice, eventID string, openedAt time.Time, stateDir string) ([]byte, []string, error) {
	inc := state.Incident{ID: n.IncidentID, Key: n.Key, Severity: n.Severity, Message: n.Message, OpenedAt: openedAt}
	if stored, err := l.Store.Incident(ctx, n.IncidentID); err == nil {
		inc.Subject = stored.Subject
	}
	src := incident.Sources{Store: l.Store, Host: n.Host, CollectedBy: "daemon", Late: n.Retry || n.Transition != TransitionOpen}
	if l.Secrets != nil {
		src.Secrets = l.Secrets
	}
	release := evidenceSources(&src)
	e, err := incident.Collect(ctx, inc, src)
	release()

	b := loomBody{EventID: eventID, IncidentID: n.IncidentID, Transition: n.Transition, Host: n.Host, Severity: n.Severity, OpenedAt: openedAt}
	var notes []string
	if err != nil {
		notes = append(notes, "sent without evidence: "+err.Error())
	} else {
		if err := incident.Save(stateDir, e); err != nil {
			notes = append(notes, "the evidence can't be saved: "+err.Error())
		}
		b.Key, b.Message = e.Incident.Key, e.Incident.Message
		b.Evidence = e.Clone()
		incident.Fit(b.Evidence, incident.LoomEvidenceMax)
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, nil, fmt.Errorf("the body for incident %d can't be encoded: %w; it is tried again", n.IncidentID, err)
	}
	return data, notes, nil
}

// test sends a probe or a test send. A probe is signed with a key the
// task can't know, so it is turned away at the signature check and opens
// no thread: a 401 shows the relay, the hook, its token and the task's
// signature check all work. A test send is signed as an incident is and
// opens a thread. Neither leaves a marker.
func (l *LoomNotifier) test(ctx context.Context, n Notice) error {
	now := time.Now().UTC()
	probe := n.Test == TestProbe
	kind, key := "test", l.Secret
	if probe {
		kind, key = "probe", rand.Text()
	}
	body, err := json.Marshal(loomBody{EventID: fmt.Sprintf("%s:%s:%d", n.Host, kind, now.Unix()), Transition: loomTestTransition,
		Host: n.Host, Severity: n.Severity, Message: strings.TrimSpace(n.Body), OpenedAt: now})
	if err != nil {
		return err
	}
	a := l.post(ctx, body, key)
	switch {
	case probe && a.status == http.StatusUnauthorized:
		return nil
	case probe && a.status/100 == 2:
		return fmt.Errorf("the Loom task took a body with a wrong signature, so anyone with its URL can open threads; set the task's signature check to header %s, hex, prefix sha256=", LoomSignatureHeader)
	case a.status/100 == 2:
		if l.Store != nil {
			_ = l.Store.RecordIntegrationUse(ctx, LoomWebhookLeg, "alert: "+n.Subject, now)
		}
		return nil
	case a.status != 0:
		return fmt.Errorf("the Loom webhook answered %s: %s", a.answered(), a.hint())
	case !a.wrote:
		return fmt.Errorf("the Loom webhook wasn't reached: %s", a.why())
	}
	return fmt.Errorf("the Loom webhook didn't answer: %s", a.why())
}

// loomAnswer is what came of one request.
type loomAnswer struct {
	// wrote is whether the request went out, so it might have arrived.
	wrote bool
	// status is the answer's HTTP status, or zero for no answer.
	status int
	// code is the error the relay or Loom named.
	code       string
	deliveryID string
	// err is why there was no answer, with the URL and token hidden.
	err error
}

// post sends body signed with key. It reads no more of the answer than
// loomAnswerMax, and its errors never carry the URL, the token or the
// secret.
func (l *LoomNotifier) post(ctx context.Context, body []byte, key string) loomAnswer {
	var wrote atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		// A write that failed left part of the body unsent, and a body
		// cut short can't pass the signature check.
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				wrote.Store(true)
			}
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.URL, bytes.NewReader(body))
	if err != nil {
		return loomAnswer{err: errors.New("the webhook URL can't be used")}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(LoomSignatureHeader, signLoomBody(key, body))
	resp, err := loomClient().Do(req)
	if err != nil {
		return loomAnswer{wrote: wrote.Load(), err: l.scrub(err)}
	}
	defer resp.Body.Close()
	// The status decides; an answer cut off after it changes nothing.
	a := loomAnswer{wrote: true, status: resp.StatusCode}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, loomAnswerMax))
	var answer struct {
		DeliveryID string `json:"deliveryId"`
		Error      string `json:"error"`
	}
	if json.Unmarshal(data, &answer) == nil {
		if loomCode.MatchString(answer.Error) {
			a.code = answer.Error
		}
		a.deliveryID = truncateBytes(l.hide(answer.DeliveryID), 200)
	}
	return a
}

// outcome is the marker's state for the answer, or empty when the body
// never arrived: it was never written, or a 429 turned it away before it
// was read.
func (a loomAnswer) outcome() string {
	switch {
	case a.status == 0 && !a.wrote, a.status == http.StatusTooManyRequests:
		return ""
	case a.status/100 == 2:
		return incident.LoomDelivered
	case a.status/100 == 3:
		return incident.LoomRefused
	}
	if _, ok := loomRefusals[a.status]; ok {
		return incident.LoomRefused
	}
	return incident.LoomAmbiguous
}

// notSent says why a body that never arrived didn't, and that it is
// tried again.
func (a loomAnswer) notSent() error {
	if a.status != 0 {
		return fmt.Errorf("the Loom webhook is rate limited (%s); it is tried again", a.answered())
	}
	return fmt.Errorf("the Loom webhook wasn't reached: %s; it is tried again", a.why())
}

// answered is the status and code, such as HTTP 404 hook_not_found.
func (a loomAnswer) answered() string {
	s := fmt.Sprintf("HTTP %d", a.status)
	if a.code != "" {
		s += " " + a.code
	}
	return s
}

// hint says what a refusal means.
func (a loomAnswer) hint() string {
	if hint, ok := loomRefusals[a.status]; ok {
		return hint
	}
	switch {
	case a.status/100 == 3:
		return "the URL redirects, so it isn't the task's relay webhook URL"
	case a.status == http.StatusTooManyRequests:
		return "the hook is rate limited; try again in a minute"
	}
	return "Loom or the relay failed"
}

// unclear says why it isn't known whether Loom has the body.
func (a loomAnswer) unclear() string {
	if a.status != 0 {
		return "it answered " + a.answered()
	}
	return "no answer came: " + a.why()
}

func (a loomAnswer) why() string {
	if a.err == nil {
		return "no reason given"
	}
	return a.err.Error()
}

// scrub turns a request's error into one without the URL, which holds
// the hook's token, or the secret.
func (l *LoomNotifier) scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return errors.New("it timed out")
		}
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("it timed out")
	}
	return errors.New(l.hide(err.Error()))
}

// hide replaces the URL, the token and the secret in s.
func (l *LoomNotifier) hide(s string) string {
	token := l.URL[strings.LastIndex(l.URL, "/")+1:]
	for _, secret := range []string{l.URL, token, l.Secret} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "(hidden)")
		}
	}
	return s
}

// signLoomBody is the signature header's value for body under key.
func signLoomBody(key string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// loomClient sends each request once: over HTTP/1.1 on a connection of
// its own, which the transport never sends a request again on, and
// without following a redirect.
func loomClient() *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Client{
		Timeout: loomRequestTimeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
			Protocols:         protocols,
			TLSClientConfig:   &tls.Config{RootCAs: loomRoots, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// clearLoomFailure clears the Loom leg's failed test once Loom has taken
// an incident, which shows more than any test.
func clearLoomFailure(store *state.Store) error {
	// A record that can't be read is the prober's to raise.
	if record, err := ReadAlertTest(store); err != nil || record == nil || record.Legs[LoomWebhookLeg].Error == "" {
		return nil
	}
	return updateAlertTest(store, func(record *AlertTest) {
		if record.Legs[LoomWebhookLeg].Error != "" {
			record.Legs[LoomWebhookLeg] = LegTest{At: time.Now().UTC()}
		}
	})
}
