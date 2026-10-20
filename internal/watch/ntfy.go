package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/state"
)

// ntfyMessageMax is the largest message ntfy shows as text, in bytes.
const ntfyMessageMax = 4096

// NtfyNotifier publishes notices to an ntfy topic. ntfy can't ring until
// acknowledged: a critical notice is its most urgent priority, once.
type NtfyNotifier struct {
	integration.Ntfy
	Store *state.Store
	// Client is a plain client unless a test sets it.
	Client *http.Client
}

// Notify implements Notifier.
func (t *NtfyNotifier) Notify(ctx context.Context, n Notice) error {
	priority, tag := 4, "warning"
	switch {
	case n.Transition == TransitionResolved:
		priority, tag = 3, "white_check_mark"
	case n.Severity == state.SeverityCritical:
		priority, tag = 5, "rotating_light"
	}
	body, err := json.Marshal(map[string]any{
		"topic":    t.Topic,
		"title":    n.Subject,
		"message":  truncateBytes(n.Body, ntfyMessageMax),
		"priority": priority,
		"tags":     []string{tag},
	})
	if err != nil {
		return err
	}
	// Publishing to the server, not the topic's URL, keeps the topic out
	// of any error the request returns.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Server, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	resp, err := client(t.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(answer, &refusal) == nil && refusal.Error != "" {
			return errors.New("ntfy refused it: " + t.scrub(refusal.Error))
		}
		return fmt.Errorf("ntfy answered HTTP %d", resp.StatusCode)
	}
	if t.Store != nil {
		_ = t.Store.RecordIntegrationUse(ctx, integration.NtfyName, "alert: "+n.Subject, time.Now().UTC())
	}
	return nil
}

// scrub keeps the topic and the token out of what ntfy says back.
func (t *NtfyNotifier) scrub(s string) string {
	for _, secret := range []string{t.Topic, t.Token} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "(hidden)")
		}
	}
	return s
}

// truncateBytes shortens s to at most limit bytes without splitting a
// character.
func truncateBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
