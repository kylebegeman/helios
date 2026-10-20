package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/state"
)

// PushoverAPI is where Pushover takes messages.
const PushoverAPI = "https://api.pushover.net/1/"

// A critical notice is a Pushover emergency: it repeats every
// PushoverRetry seconds until someone acknowledges it, for at most
// PushoverExpire seconds. Pushover allows a retry of 30 or more and an
// expiry of up to 10800.
const (
	PushoverRetry  = 60
	PushoverExpire = 3600
)

// Pushover's limits, in characters.
const (
	pushoverTitleMax   = 250
	pushoverMessageMax = 1024
)

// PushoverNotifier sends notices to a phone through Pushover.
type PushoverNotifier struct {
	integration.Pushover
	Store *state.Store
	// API is PushoverAPI unless a test sets it; Client is a plain client
	// unless a test sets it.
	API    string
	Client *http.Client
}

// Notify implements Notifier. A critical notice rings until it is
// acknowledged, and its incident's resolution stops the ringing first.
func (p *PushoverNotifier) Notify(ctx context.Context, n Notice) error {
	tag := pushoverTag(n)
	if n.Transition == TransitionResolved {
		if err := p.post(ctx, "receipts/cancel_by_tag/"+tag+".json", url.Values{"token": {p.AppToken}}); err != nil {
			return fmt.Errorf("stopping the alert that rings: %w", err)
		}
	}
	v := url.Values{
		"token":   {p.AppToken},
		"user":    {p.UserKey},
		"title":   {truncate(n.Subject, pushoverTitleMax)},
		"message": {truncate(n.Body, pushoverMessageMax)},
	}
	switch {
	case n.Transition == TransitionResolved:
		v.Set("priority", "-1")
	case n.Severity == state.SeverityCritical:
		v.Set("priority", "2")
		v.Set("retry", strconv.Itoa(PushoverRetry))
		v.Set("expire", strconv.Itoa(PushoverExpire))
		v.Set("tags", tag)
	default:
		v.Set("priority", "0")
	}
	if err := p.post(ctx, "messages.json", v); err != nil {
		return err
	}
	if p.Store != nil {
		_ = p.Store.RecordIntegrationUse(ctx, integration.PushoverName, "alert: "+n.Subject, time.Now().UTC())
	}
	return nil
}

// pushoverTag names an incident's emergency so its resolution can stop
// it. It is made from the machine and the incident's key, which can hold
// a URL, so it is always safe in a path.
func pushoverTag(n Notice) string {
	sum := sha256.Sum256([]byte(n.Host + "\n" + n.Key))
	return "helios-" + hex.EncodeToString(sum[:])[:20]
}

func (p *PushoverNotifier) post(ctx context.Context, path string, form url.Values) error {
	api := p.API
	if api == "" {
		api = PushoverAPI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client(p.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var answer struct {
		Status int      `json:"status"`
		Errors []string `json:"errors"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if json.Unmarshal(body, &answer) != nil {
		return fmt.Errorf("the Pushover API answered HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode/100 == 2 && answer.Status == 1 {
		return nil
	}
	if len(answer.Errors) == 0 {
		return fmt.Errorf("the Pushover API refused it (HTTP %d)", resp.StatusCode)
	}
	return errors.New("the Pushover API refused it: " + p.scrub(strings.Join(answer.Errors, "; ")))
}

// scrub keeps the credentials out of what Pushover says back.
func (p *PushoverNotifier) scrub(s string) string {
	for _, secret := range []string{p.AppToken, p.UserKey} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "(hidden)")
		}
	}
	return s
}

// truncate shortens s to at most limit characters.
func truncate(s string, limit int) string {
	if r := []rune(s); len(r) > limit {
		return string(r[:limit-1]) + "…"
	}
	return s
}

// phoneTimeout bounds one request to a phone service, so a leg's
// retries fit in its timeout.
const phoneTimeout = 30 * time.Second

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: phoneTimeout}
}
