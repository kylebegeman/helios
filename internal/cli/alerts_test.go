package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/incident"
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

// A review's timeline puts what happened around an incident in order:
// the change before it, the operations near it, its alerts and its send
// to Loom, and the key's latest earlier incidents. An operation is listed
// once, as it finished rather than as the evidence caught it.
func TestAlertsReviewTimeline(t *testing.T) {
	stateDir := t.TempDir()
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	opened := time.Date(2026, 10, 20, 14, 2, 5, 0, time.UTC)
	deploy := apps.DeployInput{Revision: "r2", Commit: "0123456789abcdef0123456789abcdef01234567", Signer: "ops@example.test"}
	recordOperation(t, store, "op-deploy", apps.DeployKind, "api", deploy, opened.Add(-time.Minute), opened.Add(time.Minute), state.Succeeded)
	recordOperation(t, store, "op-backup", apps.BackupKind, "api", struct{}{}, opened.Add(-3*time.Minute), opened.Add(-2*time.Minute), state.Failed)
	recordOperation(t, store, "op-rollback", apps.RollbackKind, "api", apps.RollbackInput{Revision: "r1"}, opened.Add(5*time.Minute), opened.Add(6*time.Minute), state.Succeeded)
	// Neither in the window before it nor while it was open.
	recordOperation(t, store, "op-earlier", apps.GCKind, "api", struct{}{}, opened.Add(-30*time.Minute), opened.Add(-29*time.Minute), state.Succeeded)
	recordOperation(t, store, "op-later", apps.GCKind, "api", struct{}{}, opened.Add(40*time.Minute), opened.Add(41*time.Minute), state.Succeeded)

	// The key's earlier incidents, newest first, as the evidence keeps
	// them; the review lists three.
	var prior []incident.PriorIncident
	for i, message := range []string{"web timed out", "web answered 500 | twice", "web answered 502", "web refused connections"} {
		earlier := state.Incident{Key: "app:api", Subject: "api", Severity: state.SeverityCritical, Message: message, OpenedAt: opened.Add(-time.Duration(i+1) * 24 * time.Hour), Observations: 3}
		if earlier.ID, err = store.OpenIncident(ctx, earlier); err != nil {
			t.Fatal(err)
		}
		resolved := earlier.OpenedAt.Add(5 * time.Minute)
		prior = append(prior, incident.PriorIncident{ID: earlier.ID, Severity: earlier.Severity, OpenedAt: earlier.OpenedAt, ResolvedAt: &resolved, Observations: 3, Message: message})
	}
	inc := state.Incident{Key: "app:api", Subject: "api", Severity: state.SeverityCritical, Message: "web answered 502", OpenedAt: opened, Observations: 9}
	if inc.ID, err = store.OpenIncident(ctx, inc); err != nil {
		t.Fatal(err)
	}
	inc.ResolvedAt, inc.NotifiedAt = opened.Add(12*time.Minute), opened.Add(12*time.Minute)
	if err := store.UpdateIncident(ctx, inc); err != nil {
		t.Fatal(err)
	}
	// The evidence caught the deploy still applying.
	caught := incident.Change{Operation: "op-deploy", Kind: apps.DeployKind, App: "api", Revision: deploy.Revision, Commit: deploy.Commit, Signer: deploy.Signer,
		StartedAt: opened.Add(-time.Minute), Outcome: string(state.Applying)}
	e := &incident.Evidence{
		Schema: incident.Schema, Host: "web.example.test",
		Incident:    incident.Incident{ID: inc.ID, Key: inc.Key, Subject: inc.Subject, Severity: inc.Severity, Message: "web answered 502 | with\n[redacted API_TOKEN] in its body", OpenedAt: opened},
		Window:      incident.Window{Since: opened.Add(-10 * time.Minute), Until: opened},
		CollectedAt: opened.Add(2 * time.Second), CollectedBy: "daemon",
		Redaction:  incident.Redaction{Status: incident.RedactionApplied},
		LastChange: &caught,
		// Another app's deploy, from before the window the store is read in.
		RecentDeploys: []incident.Change{caught, {Operation: "op-site", Kind: apps.DeployKind, App: "site", Revision: "r7",
			StartedAt: opened.Add(-40 * time.Minute), FinishedAt: opened.Add(-39 * time.Minute), Outcome: string(state.Succeeded)}},
		History:   &incident.History{Incidents: prior},
		Truncated: []string{}, Errors: []incident.SourceError{},
	}
	if err := incident.Save(stateDir, e); err != nil {
		t.Fatal(err)
	}
	saveLoomMarker(t, stateDir, inc.ID, incident.LoomMarker{Schema: incident.LoomMarkerSchema, OpenedAt: opened, State: incident.LoomDelivered, Status: 202, At: opened.Add(4 * time.Second)})

	out, errOut, code := run(t, stateDir, "alerts", "review", strconv.FormatInt(inc.ID, 10))
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	path := filepath.Join("testdata", "alerts-review.golden")
	if *update {
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to write it)", err)
	}
	if out != string(want) {
		t.Fatalf("the review changed; diff %s against:\n%s", path, out)
	}
}

// show says how an incident's alerts and its send to Loom went, and its
// JSON carries the marker, or null for one that is another incident's.
func TestAlertsShowSaysHowTheIncidentWentToLoom(t *testing.T) {
	stateDir := t.TempDir()
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	opened := time.Date(2026, 10, 20, 14, 2, 5, 0, time.UTC)
	var ids []string
	for _, key := range []string{"app:api", "app:site", "host:disk"} {
		id, err := store.OpenIncident(ctx, state.Incident{Key: key, Subject: key, Severity: state.SeverityCritical, Message: "it stopped", OpenedAt: opened})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	id := func(i int) int64 { n, _ := strconv.ParseInt(ids[i], 10, 64); return n }
	saveLoomMarker(t, stateDir, id(0), incident.LoomMarker{Schema: incident.LoomMarkerSchema, OpenedAt: opened, State: incident.LoomAmbiguous, Status: 504, At: opened.Add(time.Second)})
	// An earlier incident's, from before the state was replaced.
	saveLoomMarker(t, stateDir, id(1), incident.LoomMarker{Schema: incident.LoomMarkerSchema, OpenedAt: opened.Add(-time.Hour), State: incident.LoomDelivered, Status: 202})

	for i, want := range []string{"ambiguous 504, not resent", "not configured", "not configured"} {
		out, errOut, code := run(t, stateDir, "alerts", "show", ids[i])
		if code != 0 || !strings.Contains(out, "Loom           "+want+"\n") || !strings.Contains(out, "key            "+[]string{"app:api", "app:site", "host:disk"}[i]+"\n") {
			t.Fatalf("incident %s: exit %d, stderr %q, output:\n%s", ids[i], code, errOut, out)
		}
	}

	var got struct {
		Incident state.Incident       `json:"incident"`
		Loom     *incident.LoomMarker `json:"loom"`
		Evidence json.RawMessage      `json:"evidence"`
	}
	out, errOut, code := run(t, stateDir, "--json", "alerts", "show", ids[0])
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || got.Incident.ID != id(0) || got.Loom == nil || got.Loom.State != incident.LoomAmbiguous || string(got.Evidence) != "null" {
		t.Fatalf("exit %d, stderr %q, output %s", code, errOut, out)
	}
	got.Loom = nil
	out, _, code = run(t, stateDir, "--json", "alerts", "show", ids[1])
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || got.Loom != nil {
		t.Fatalf("an earlier incident's marker was taken for this one's: exit %d, output %s", code, out)
	}

	for _, tc := range []struct{ arg, want string }{
		{"99", "no incident 99; helios alerts lists them"},
		{"api", "incidents are numbered; helios alerts lists them"},
	} {
		for _, command := range []string{"show", "review"} {
			if _, errOut, code := run(t, stateDir, "alerts", command, tc.arg); code == 0 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("alerts %s %s: exit %d, stderr %q", command, tc.arg, code, errOut)
			}
		}
	}
}

// Evidence an incident never got, as one that didn't go to Loom, is
// collected when asked for, marked late and by the CLI, and kept, so the
// next look reads it rather than collecting again.
func TestAlertsShowCollectsMissingEvidenceLateAndKeepsIt(t *testing.T) {
	stateDir := t.TempDir()
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	opened := time.Date(2026, 10, 20, 14, 2, 5, 0, time.UTC)
	inc := state.Incident{Key: "app:api", Subject: "api", Severity: state.SeverityCritical, Message: "web answered 502", OpenedAt: opened}
	if inc.ID, err = store.OpenIncident(context.Background(), inc); err != nil {
		t.Fatal(err)
	}
	journal := &emptyJournal{}
	was := evidenceSources
	evidenceSources = func(src *incident.Sources) func() {
		src.Journal = journal
		return func() {}
	}
	t.Cleanup(func() { evidenceSources = was })

	id := strconv.FormatInt(inc.ID, 10)
	out, errOut, code := run(t, stateDir, "--json", "alerts", "show", id, "--evidence")
	var got struct {
		Evidence *incident.Evidence `json:"evidence"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || got.Evidence == nil {
		t.Fatalf("exit %d, stderr %q, output %s", code, errOut, out)
	}
	if e := got.Evidence; e.CollectedBy != "cli" || !e.Late || e.Incident.ID != inc.ID || !e.Window.Until.Equal(opened) {
		t.Fatalf("collected by %q, late %v, incident %d, window %+v", e.CollectedBy, e.Late, e.Incident.ID, e.Window)
	}
	if journal.reads != 1 || !strings.Contains(errOut, "collected now; logs older than the journal's retention are gone") {
		t.Fatalf("%d journal reads, stderr %q", journal.reads, errOut)
	}
	saved, err := incident.Load(stateDir, inc)
	if err != nil || saved.CollectedBy != "cli" || !saved.Late {
		t.Fatalf("not kept: %v %+v", err, saved)
	}

	out, errOut, code = run(t, stateDir, "alerts", "show", id, "--evidence")
	if code != 0 || journal.reads != 1 || strings.Contains(errOut, "collected now") || !strings.Contains(out, "by cli, late; redaction applied") {
		t.Fatalf("the kept evidence wasn't read: exit %d, %d journal reads, stderr %q, output:\n%s", code, journal.reads, errOut, out)
	}
}

// emptyJournal has no lines, as for a window older than the journal
// keeps, and counts its reads.
type emptyJournal struct{ reads int }

func (j *emptyJournal) Read(context.Context, docker.JournalQuery) ([]docker.JournalContainer, error) {
	j.reads++
	return nil, nil
}

func (j *emptyJournal) Suppressed(context.Context, time.Time, time.Time) ([]docker.JournalSuppressed, error) {
	return nil, nil
}

// recordOperation keeps an operation that started and finished when
// given.
func recordOperation(t *testing.T, store *state.Store, id, kind, target string, input any, started, finished time.Time, status state.OperationStatus) {
	t.Helper()
	ctx := context.Background()
	in, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateOperation(ctx, state.NewOperation{ID: id, Kind: kind, Target: target, Input: in, Plan: json.RawMessage(`{}`), CreatedAt: started}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, id, "test", started, started.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(ctx, id, status, "", nil, finished); err != nil {
		t.Fatal(err)
	}
}

func saveLoomMarker(t *testing.T, stateDir string, id int64, m incident.LoomMarker) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(incident.Dir(stateDir, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incident.Dir(stateDir, id), incident.LoomFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
