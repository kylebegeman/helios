package watch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func saveHoldsRevision(t *testing.T, store *state.Store, m *manifest.Manifest, at time.Time) {
	t.Helper()
	encoded, _ := json.Marshal(m)
	images := map[string]string{}
	for name := range m.Workloads {
		images[name] = "sha256:abc"
	}
	if err := store.SaveRevision(context.Background(), state.Revision{App: m.App, ID: "r1", Status: state.RevisionActive, Manifest: encoded, CreatedAt: at, Images: images, Containers: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
}

// finishedRun records a backup or drill that started at and took a minute.
func finishedRun(t *testing.T, store *state.Store, appName, kind string, at time.Time, ok bool) {
	t.Helper()
	ctx := context.Background()
	id, err := store.StartBackupRun(ctx, appName, kind, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: at.Add(time.Minute), OK: ok}); err != nil {
		t.Fatal(err)
	}
}

func conditionsWithKey(p *Prober, key string) []Condition {
	var out []Condition
	for _, c := range p.Observe(context.Background()) {
		if c.Key == key {
			out = append(out, c)
		}
	}
	return out
}

// A held cron workload is a notice that names the reason and the end, so
// the hold can't be forgotten. It is told once, again as a warning on its
// last day, and once more when it ends.
func TestAHeldCronIsANoticeThatWarnsOnItsLastDay(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	saveHoldsRevision(t, w.Store, &manifest.Manifest{App: "hello", Workloads: map[string]manifest.Workload{
		"report": {Kind: manifest.Cron, Schedule: "45 4 * * *", Image: "example.test/hello:1"}}}, now.Add(-time.Hour))
	until := now.Add(3 * 24 * time.Hour)
	if _, err := w.Store.HoldJob(ctx, "hello", "report", "r1", *now, until, "the volume is being moved"); err != nil {
		t.Fatal(err)
	}
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	round := func() []Condition {
		t.Helper()
		*now = now.Add(time.Minute)
		found := conditionsWithKey(p, "hold:hello/report")
		if err := w.Round(ctx, found); err != nil {
			t.Fatal(err)
		}
		return found
	}

	found := round()
	if len(found) != 1 || found[0].Severity != state.SeverityNotice || found[0].Subject != "hello/report cron" || found[0].Message != "held until Tuesday 22 September 12:00 UTC: the volume is being moved" {
		t.Fatalf("the hold reads %+v", found)
	}
	for range DefaultOpenAfter {
		round()
	}
	if len(notifier.sent) != 1 || notifier.sent[0].Subject != "box: hello/report cron is held by an operator" {
		t.Fatalf("the hold was told as %+v", notifier.sent)
	}
	*now = now.Add(25 * time.Hour)
	round()
	if len(notifier.sent) != 1 {
		t.Fatalf("a notice was repeated after a day: %+v", notifier.sent)
	}

	*now = until.Add(-23 * time.Hour)
	found = round()
	if len(found) != 1 || found[0].Severity != state.SeverityWarning || !strings.Contains(found[0].Message, "the hold ends in 23.0 h and the workload runs again on its schedule") {
		t.Fatalf("a hold ending within a day reads %+v", found)
	}
	if len(notifier.sent) != 2 || !strings.Contains(notifier.sent[1].Subject, "hello/report cron has a problem") {
		t.Fatalf("the hold's last day wasn't told: %+v", notifier.sent)
	}

	*now = until
	for range DefaultResolveAfter {
		if found := round(); len(found) != 0 {
			t.Fatalf("an ended hold is still reported: %+v", found)
		}
	}
	if open, err := w.Store.OpenIncidentByKey(ctx, "hold:hello/report"); err != nil || open != nil {
		t.Fatalf("the ended hold is still open: %+v, %v", open, err)
	}
	if last := notifier.sent[len(notifier.sent)-1]; last.Subject != "box: hello/report cron is no longer held" {
		t.Fatalf("the end of the hold was told as %+v", last)
	}
}

// A skipped drill is a notice, never a failed drill. It warns when the
// drill after it would leave the last good drill more than 14 days old, or
// when no drill has passed at all.
func TestASkippedDrillIsANoticeAndNeverAFailedDrill(t *testing.T) {
	ctx := context.Background()
	dockertest.New(t)
	w, now := newWatcher(t, &fakeNotifier{})
	*now = time.Date(2026, 10, 25, 5, 20, 0, 0, time.UTC)
	for _, name := range []string{"hello", "fresh"} {
		saveHoldsRevision(t, w.Store, &manifest.Manifest{App: name,
			Workloads: map[string]manifest.Workload{"report": {Kind: manifest.Cron, Schedule: "45 4 * * *", Image: "example.test/hello:1"}},
			Data:      &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}},
			Backup:    &manifest.Backup{Drill: "10 6 * * 0"}}, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
		finishedRun(t, w.Store, name, state.BackupRunBackup, time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC), true)
	}
	finishedRun(t, w.Store, "hello", state.BackupRunDrill, time.Date(2026, 10, 18, 6, 10, 0, 0, time.UTC), true)
	for _, name := range []string{"hello", "fresh"} {
		if _, err := w.Store.SkipDrill(ctx, name, time.Date(2026, 10, 25, 6, 10, 0, 0, time.UTC), "the disk is being resized"); err != nil {
			t.Fatal(err)
		}
	}
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }

	all := p.Observe(ctx)
	var skips []Condition
	for _, c := range all {
		if strings.Contains(c.Message, "restore drill failed") {
			t.Fatalf("a skip reads as a failed drill: %+v", c)
		}
		if strings.HasPrefix(c.Key, "skip:") {
			skips = append(skips, c)
		}
	}
	if len(skips) != 2 {
		t.Fatalf("want a condition for each skip: %+v", skips)
	}
	want := "the drill due Sunday 25 October 06:10 UTC is skipped by operator: the disk is being resized; the next drill is due Sunday 1 November 06:10 UTC"
	for _, c := range skips {
		switch c.Key {
		case "skip:hello":
			if c.Severity != state.SeverityNotice || c.Subject != "hello restore drill" || c.Message != want {
				t.Fatalf("hello's skip reads %+v", c)
			}
		case "skip:fresh":
			if c.Severity != state.SeverityWarning || c.Message != want+"; no drill has passed yet, so no restore of its backups is proven" {
				t.Fatalf("a skip with no good drill reads %+v", c)
			}
		}
	}

	// Skipping the next one too would leave the last good drill three weeks
	// old by the drill after it.
	if _, err := w.Store.SkipDrill(ctx, "hello", time.Date(2026, 11, 1, 6, 10, 0, 0, time.UTC), "the disk is still being resized"); err != nil {
		t.Fatal(err)
	}
	found := conditionsWithKey(p, "skip:hello")
	if len(found) != 1 || found[0].Severity != state.SeverityWarning || !strings.HasSuffix(found[0].Message, "; by then the last good drill will be 21 days old") {
		t.Fatalf("a second skip reads %+v", found)
	}
}
