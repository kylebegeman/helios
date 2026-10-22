package peer

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
	"github.com/kylebegeman/helios/internal/watch"
)

func seconds(n int64) *int64 { return &n }

// deployed makes app's active revision, first made at.
func deployed(t *testing.T, store *state.Store, m manifest.Manifest, at time.Time) {
	t.Helper()
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRevision(context.Background(), state.Revision{App: m.App, ID: "r1", Status: state.RevisionActive, Manifest: encoded,
		Images: map[string]string{}, Containers: map[string]string{}, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
}

// ran records a backup or drill that started at and worked.
func ran(t *testing.T, store *state.Store, appName, kind string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	id, err := store.StartBackupRun(ctx, appName, kind, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: at.Add(time.Minute), OK: true}); err != nil {
		t.Fatal(err)
	}
}

// opened records an open incident as it is given, told or owing a
// notice, and returns its ID.
func opened(t *testing.T, store *state.Store, i state.Incident) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := store.OpenIncident(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	i.ID = id
	if err := store.UpdateIncident(ctx, i); err != nil {
		t.Fatal(err)
	}
	return id
}

// The summary tells a peer what this machine may be unable to alert
// about: its open incidents, whether each was told, its backups and
// drills, when each alert leg last worked, its disk, and its own last
// look at its peers. A peer incident reads as told only when this
// machine sent it itself, and as owed never while another observer is to
// send it; the peer notices it is sending right now are listed, and the
// last recovery of each peer it sent itself. It never says why a notice
// failed or what a leg delivered, and no address it knows.
func TestSummaryReports(t *testing.T) {
	w := setUpWeb1(t)
	store, ctx := w.store, context.Background()
	files := &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}}
	deployed(t, store, manifest.Manifest{App: "shop", Data: files, Backup: &manifest.Backup{Drill: "10 6 * * 0"}}, now.Add(-10*24*time.Hour))
	deployed(t, store, manifest.Manifest{App: "static"}, now.Add(-10*24*time.Hour))
	// shop's last good backup was Sunday 03:00, so its drill was due
	// Sunday 06:10 and none has run since the one a week before.
	sunday := time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC)
	ran(t, store, "shop", state.BackupRunBackup, sunday)
	ran(t, store, "shop", state.BackupRunDrill, sunday.Add(-7*24*time.Hour+190*time.Minute))
	ran(t, store, manifest.ReservedApp, state.BackupRunBackup, now.Add(-time.Hour))

	const failure = "dial tcp smtp.example.test:587: connection refused"
	opened(t, store, state.Incident{Key: "app:shop", Subject: "shop", Severity: state.SeverityWarning, OpenedAt: now.Add(-90 * time.Minute),
		NotifiedAt: now.Add(-88 * time.Minute)})
	opened(t, store, state.Incident{Key: "host:disk", Subject: "disk", Severity: state.SeverityCritical, OpenedAt: now.Add(-30 * time.Minute),
		NotifyError: failure})
	// web3 told the edge provider's warning and this machine stood down;
	// it sent web2's warning and then its page itself, and holds web4's
	// for web3.
	opened(t, store, state.Incident{Key: "peer:edge-provider", Subject: "public edge", Severity: state.SeverityWarning,
		OpenedAt: now.Add(-25 * time.Minute), NotifiedAt: now.Add(-24 * time.Minute)})
	web2 := opened(t, store, state.Incident{Key: "peer:web2", Subject: "web2", Severity: state.SeverityCritical,
		OpenedAt: now.Add(-20 * time.Minute), NotifiedAt: now.Add(-19 * time.Minute), NotifyError: failure})
	opened(t, store, state.Incident{Key: "peer:web4", Subject: "web4", Severity: state.SeverityWarning,
		OpenedAt: now.Add(-10 * time.Minute), NotifyError: (&Deferred{To: "web3"}).Error()})
	// It sent the recovery of two earlier outages of web3, and of one of
	// the edge provider.
	var recoveries []Told
	for _, r := range []struct {
		key string
		ago time.Duration
	}{{"peer:web3", 30 * time.Minute}, {"peer:edge-provider", 45 * time.Minute}, {"peer:web3", 50 * time.Minute}} {
		id := opened(t, store, state.Incident{Key: r.key, Subject: strings.TrimPrefix(r.key, keyPrefix), Severity: state.SeverityCritical,
			OpenedAt: now.Add(-r.ago - 5*time.Minute), ResolvedAt: now.Add(-r.ago), NotifiedAt: now.Add(-r.ago)})
		recoveries = append(recoveries, Told{IncidentID: id, Key: r.key, Transition: watch.TransitionResolved, Severity: state.SeverityCritical,
			By: "web1", At: now.Add(-r.ago)})
	}

	if _, _, err := integration.Set(w.secrets, integration.EmailName, map[string]string{"smtp_host": "smtp.example.test", "smtp_port": "587",
		"from": "helios@example.test", "to": "ops@example.test"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := integration.Set(w.secrets, integration.PushoverName, map[string]string{"app_token": strings.Repeat("a", 30), "user_key": strings.Repeat("u", 30)}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordIntegrationUse(ctx, integration.EmailName, "alert: web1: shop has a problem", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	s := w.server(t)
	s.Deps.Last = func() Last {
		return Last{Round: now.Add(-41 * time.Second), Looked: now.Add(-41 * time.Second), SelfCheck: true,
			Findings: []Finding{{Key: "peer:web2", Severity: state.SeverityWarning}},
			Paths:    map[string]Paths{"web2": {WordOK, WordOK, "timeout"}},
			Sending:  []string{"peer:web2"},
			Sent: append([]Told{{IncidentID: web2, Key: "peer:web2", Severity: state.SeverityCritical, By: "web1", At: now.Add(-19 * time.Minute)},
				{IncidentID: web2, Key: "peer:web2", Severity: state.SeverityWarning, By: "web1", At: now.Add(-20 * time.Minute)}}, recoveries...)}
	}
	rec := asked(s, at(in("100.64.0.0/10"), 7700), http.MethodGet, SummaryPath, w.keys["web2"], "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("got %d: %s", rec.Code, rec.Body)
	}
	raw := rec.Body.String()
	var got Summary
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.Disk == nil || got.Disk.TotalBytes == 0 || got.Disk.FreeBytes > got.Disk.TotalBytes {
		t.Fatalf("the disk reads %+v", got.Disk)
	}
	got.Disk = nil
	want := Summary{Name: "web1", Version: version.Current().Version, LastRoundAgeS: 41, SelfCheck: true,
		Incidents: []SummaryIncident{
			{Key: "app:shop", Subject: "shop", Severity: state.SeverityWarning, OpenedAgeS: 5400, ToldAgeS: seconds(5280)},
			{Key: "host:disk", Subject: "disk", Severity: state.SeverityCritical, OpenedAgeS: 1800, Owed: true},
			{Key: "peer:edge-provider", Subject: "public edge", Severity: state.SeverityWarning, OpenedAgeS: 1500},
			{Key: "peer:web2", Subject: "web2", Severity: state.SeverityCritical, OpenedAgeS: 1200, ToldAgeS: seconds(1140),
				Tells: []SummaryTell{{Severity: state.SeverityWarning, AgeS: 1200}, {Severity: state.SeverityCritical, AgeS: 1140}}, Owed: true},
			{Key: "peer:web4", Subject: "web4", Severity: state.SeverityWarning, OpenedAgeS: 600}},
		Sending: []string{"peer:web2"},
		Backups: []SummaryBackup{
			{App: "shop", LastGoodBackupAgeS: seconds(54 * 3600), DeployedAgeS: seconds(10 * 86400),
				LastGoodDrillAgeS: seconds(9*86400 + 170*60), DrillOverdueS: seconds(2*86400 + 170*60)},
			{App: manifest.ReservedApp, LastGoodBackupAgeS: seconds(3600)}},
		Legs:      []SummaryLeg{{Name: integration.EmailName, LastOKAgeS: seconds(3600)}, {Name: integration.PushoverName}},
		Findings:  []Finding{{Key: "peer:web2", Severity: state.SeverityWarning}},
		Views:     []SummaryView{{Subject: "web2", AgeS: 41, Paths: Paths{WordOK, WordOK, "timeout"}}},
		Recovered: []SummaryRecovery{{Key: "peer:edge-provider", AgeS: 2700}, {Key: "peer:web3", AgeS: 1800}},
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Fatalf("the summary reads\n%s\nwant\n%s", gotJSON, wantJSON)
	}
	if strings.Contains(raw, `"told_age_s":null`) || strings.Count(raw, `"told_age_s"`) != 2 || strings.Count(raw, `"last_ok_age_s"`) != 1 {
		t.Fatalf("an age with nothing to measure from is not left out: %s", raw)
	}
	mesh, _, _ := strings.Cut(at(in("100.64.0.0/10"), 7700), ":")
	for _, kept := range []string{failure, "smtp.example.test", "has a problem", "ops@example.test", mesh, w.keys["web2"]} {
		if strings.Contains(raw, kept) {
			t.Fatalf("the summary carries %q: %s", kept, raw)
		}
	}
}

// A URL watch's incident key and subject both hold the watched URL.
// The summary identifies that incident without sharing its address or any
// credentials or query values in the URL with other machines.
func TestSummaryKeepsWatchedURLsPrivate(t *testing.T) {
	w := setUpWeb1(t)
	const watched = "https://reader:sample-password@private.mesh.example.test/health?token=sample-token"
	opened(t, w.store, state.Incident{Key: "watch:" + watched, Subject: watched, Severity: state.SeverityCritical, OpenedAt: now})
	s := w.server(t)
	rec := asked(s, at(in("100.64.0.0/10"), 7700), http.MethodGet, SummaryPath, w.keys["web2"], "")
	if rec.Code != http.StatusOK {
		t.Fatalf("summary answered %d", rec.Code)
	}
	for _, private := range []string{"private.mesh.example.test", "sample-password", "sample-token"} {
		if strings.Contains(rec.Body.String(), private) {
			t.Fatal("the summary exposed part of a watched URL")
		}
	}
	var summary Summary
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Incidents) != 1 || summary.Incidents[0].Key != "watch:1" || summary.Incidents[0].Subject != "watched URL (incident 1)" || summary.Incidents[0].Severity != state.SeverityCritical {
		t.Fatal("the summary did not identify the watched URL's incident and severity")
	}
	rep := summary.report()
	rep.Legs = []Leg{{Name: "email"}}
	message := strings.Join(deadMan(*rep), "; ")
	if !strings.Contains(message, "watched URL (incident 1) (critical)") || strings.Contains(message, watched) {
		t.Fatal("a peer's silent-alert finding did not safely identify the watched URL's incident")
	}
}

// A peer incident's tells count each at its own severity, so a warning
// told still reads as told to an observer that sees a warning, and never
// to one that sees the outage. A summary from a version before tells
// reads as it did: its told age is a tell at the incident's severity or
// graver.
func TestATellCountsAtItsOwnSeverity(t *testing.T) {
	for _, c := range []struct {
		incident                string
		warning, critical       int64
		toldWarning, toldOutage bool
	}{
		{`{"severity":"critical","told_age_s":60}`, 60, 60, true, true},
		{`{"severity":"critical"}`, 0, 0, false, false},
		{`{"severity":"warning","told_age_s":60}`, 60, 0, true, false},
		{`{"severity":"critical","tells":[{"severity":"warning","age_s":300}]}`, 300, 0, true, false},
		{`{"severity":"critical","told_age_s":60,"tells":[{"severity":"warning","age_s":300},{"severity":"critical","age_s":60}]}`, 60, 60, true, true},
	} {
		var i SummaryIncident
		if err := json.Unmarshal([]byte(c.incident), &i); err != nil {
			t.Fatal(err)
		}
		warning, toldWarning := i.toldAge(state.SeverityWarning)
		critical, toldOutage := i.toldAge(state.SeverityCritical)
		if warning != c.warning || toldWarning != c.toldWarning || critical != c.critical || toldOutage != c.toldOutage {
			t.Errorf("%s reads as told %ds ago %v as a warning and %ds ago %v as critical", c.incident, warning, toldWarning, critical, toldOutage)
		}
	}
}

// A disk that can't be read leaves the disk out, rather than reporting
// it empty or full.
func TestSummaryOmitsDiskWhenUnreadable(t *testing.T) {
	w := setUpWeb1(t)
	summary, err := Build(context.Background(), Deps{Store: w.store, Secrets: w.secrets, Root: filepath.Join(t.TempDir(), "missing"),
		Now: func() time.Time { return now }}, "web1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Disk != nil || strings.Contains(string(raw), `"disk"`) {
		t.Fatalf("an unreadable disk is reported: %s", raw)
	}
}

// A machine that has not finished a watch round yet, or has never
// looked at its peers, reads as stale and shows no views, rather than
// fresh and empty.
func TestSummaryOfAMachineThatNeverWatchedReadsAsStale(t *testing.T) {
	w := setUpWeb1(t)
	summary, err := Build(context.Background(), Deps{Store: w.store, Secrets: w.secrets, Root: t.TempDir(),
		Now: func() time.Time { return now }}, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(summary.LastRoundAgeS)*time.Second <= StaleRound || summary.SelfCheck || len(summary.Views) != 0 {
		t.Fatalf("got %+v", summary)
	}
}
