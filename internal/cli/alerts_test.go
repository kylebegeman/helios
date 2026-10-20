package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/peer"
	"github.com/kylebegeman/helios/internal/state"
)

func TestAlertsAlwaysIncludeOpenIncidentsBeyondHistoryLimit(t *testing.T) {
	stateDir := t.TempDir()
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		_, err := store.OpenIncident(ctx, state.Incident{Key: fmt.Sprintf("app:down-%d", i), Subject: fmt.Sprintf("down-%d", i), Message: "web stopped", Severity: state.SeverityCritical, OpenedAt: start.Add(time.Duration(i) * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		inc := state.Incident{Key: fmt.Sprintf("app:recovered-%d", i), Subject: fmt.Sprintf("recovered-%d", i), Message: "recovered", OpenedAt: start.Add(time.Duration(i+10) * time.Minute)}
		inc.ID, err = store.OpenIncident(ctx, inc)
		if err != nil {
			t.Fatal(err)
		}
		inc.ResolvedAt = inc.OpenedAt.Add(time.Minute)
		if err := store.UpdateIncident(ctx, inc); err != nil {
			t.Fatal(err)
		}
	}
	out, errOut, code := run(t, stateDir, "alerts", "--limit", "2")
	if code != 0 || strings.Contains(out, "nothing wrong right now") || strings.Count(out, "OPEN  ") != 3 || strings.Count(out, "past  ") != 2 {
		t.Fatalf("open alerts must survive history limits: code %d, stderr %q, output %q", code, errOut, out)
	}
	out, errOut, code = run(t, stateDir, "--json", "alerts", "--limit", "2")
	var incidents []state.Incident
	if code != 0 || json.Unmarshal([]byte(out), &incidents) != nil || len(incidents) != 5 {
		t.Fatalf("JSON must retain the incident array and all open incidents: code %d, stderr %q, output %q", code, errOut, out)
	}
	out, _, code = run(t, stateDir, "alerts", "--limit", "0")
	if code != 0 || strings.Count(out, "OPEN  ") != 3 || strings.Contains(out, "past  ") {
		t.Fatalf("zero history still shows all open alerts: code %d, output %q", code, out)
	}
}

// A peer incident says who sent its latest notice where another observer
// did, and which observer is to send it where this machine holds it,
// never as a notice that failed. Everything else reads as before.
func TestAlertsShowWhoSent(t *testing.T) {
	stateDir := t.TempDir()
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	start := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	open := func(key, subject string, notified time.Time, notifyError string) int64 {
		t.Helper()
		inc := state.Incident{Key: key, Subject: subject, Message: "no answer", Severity: state.SeverityCritical, OpenedAt: start}
		if inc.ID, err = store.OpenIncident(ctx, inc); err != nil {
			t.Fatal(err)
		}
		inc.NotifiedAt, inc.NotifyError = notified, notifyError
		if err := store.UpdateIncident(ctx, inc); err != nil {
			t.Fatal(err)
		}
		return inc.ID
	}
	sentByWeb1 := open("peer:web3", "web3", start.Add(4*time.Minute), "")
	heldForWeb1 := open("peer:web4", "web4", time.Time{}, "web1 is to send this")
	sentHere := open("peer:web5", "web5", start.Add(6*time.Minute), "")
	open("app:shop", "shop", time.Time{}, "pushover: refused")
	sidecar, err := json.Marshal(peer.Sidecar{Self: "web2",
		Told: []peer.Told{
			{IncidentID: sentByWeb1, Key: "peer:web3", By: "web1", At: start.Add(3 * time.Minute)},
			{IncidentID: sentHere, Key: "peer:web5", By: "web2", At: start.Add(6 * time.Minute)},
		},
		Deferring: []peer.Deferral{{IncidentID: heldForWeb1, Key: "peer:web4", To: "web1", Since: start.Add(5 * time.Minute)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, peer.SidecarFile), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, stateDir, "alerts")
	clock := func(d time.Duration) string { return start.Add(d).Local().Format("15:04") }
	for _, want := range []string{
		"      sent by web1 at " + clock(3*time.Minute) + "\n",
		"      web1 is to send this (waiting since " + clock(5*time.Minute) + ")\n",
		"      told you at " + clock(6*time.Minute) + "\n",
		"      NOT DELIVERED: pushover: refused\n",
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("want %q: code %d, stderr %q, output:\n%s", want, code, errOut, out)
		}
	}
	if strings.Count(out, "NOT DELIVERED") != 1 || strings.Count(out, "told you at") != 1 {
		t.Fatalf("a peer notice another observer sent or is to send reads as this machine's own:\n%s", out)
	}
}
