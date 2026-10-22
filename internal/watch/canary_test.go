package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

func newSecrets(t *testing.T) *secrets.Store {
	t.Helper()
	dir := t.TempDir()
	s := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "key")}
	if _, _, _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	return s
}

// closedPort is a local port nothing listens on, so mail to it is
// refused at once.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return strconv.Itoa(port)
}

// A leg that fails the test is recorded, and the prober raises a warning
// naming it, which the legs that work then deliver. Testing one leg
// updates only its line; a test with nothing set up clears the record.
func TestAFailedAlertTestRaisesAWarning(t *testing.T) {
	ctx := context.Background()
	w, _ := newWatcher(t, nil)
	sec := newSecrets(t)
	email := map[string]string{"smtp_host": "127.0.0.1", "smtp_port": closedPort(t), "from": "helios@example.test", "to": "ops@example.test"}
	if _, _, err := integration.Set(sec, integration.EmailName, email); err != nil {
		t.Fatal(err)
	}
	p := NewProber(w.Store)
	if got := p.alertTest(); got != nil {
		t.Fatalf("no test yet, so nothing to say: %+v", got)
	}
	at := time.Date(2026, 10, 19, 9, 15, 0, 0, time.UTC)
	results, err := SendTestAlerts(ctx, sec, w.Store, "box", "", at)
	if err != nil || len(results) != 1 || results[0].Leg != "email" || results[0].To != "ops@example.test" || results[0].Error == "" {
		t.Fatalf("the email leg should fail its test: %+v, %v", results, err)
	}
	got := p.alertTest()
	if len(got) != 1 || got[0].Key != "host:alerts" || got[0].Severity != state.SeverityWarning ||
		!strings.Contains(got[0].Message, "email failed its test on 2026-10-19") || !strings.HasSuffix(got[0].Message, "fix it, then run helios alerts test") {
		t.Fatalf("condition: %+v", got)
	}

	if _, err := SendTestAlerts(ctx, sec, w.Store, "box", "pushover", at); err == nil || err.Error() != "no alert leg named pushover; set up: email" {
		t.Fatalf("an unknown leg should list the ones set up: %v", err)
	}
	if _, _, err := integration.Set(sec, integration.Email2Name, email); err != nil {
		t.Fatal(err)
	}
	later := at.Add(time.Hour)
	if results, err := SendTestAlerts(ctx, sec, w.Store, "box", "email2", later); err != nil || len(results) != 1 || results[0].Leg != "email2" {
		t.Fatalf("one leg: %+v, %v", results, err)
	}
	record, err := ReadAlertTest(w.Store)
	if err != nil || !record.At.Equal(at) || !record.Legs["email"].At.Equal(at) || !record.Legs["email2"].At.Equal(later) {
		t.Fatalf("testing one leg should keep the full test's time and the other leg: %+v, %v", record, err)
	}

	for _, name := range []string{integration.EmailName, integration.Email2Name} {
		if _, err := integration.Remove(sec, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SendTestAlerts(ctx, sec, w.Store, "box", "", later); err == nil || err.Error() != NoAlertsSetUp {
		t.Fatalf("nothing to test: %v", err)
	}
	if got := p.alertTest(); got != nil {
		t.Fatalf("a full test replaces the record: %+v", got)
	}
}

// Tests of different legs, and a leg recording a refusal, change the record
// at the same time; none of them loses another's line, and a probe's
// result stays marked as one.
func TestChangesToTheAlertTestRecordNeverLoseEachOther(t *testing.T) {
	w, _ := newWatcher(t, nil)
	at := time.Date(2026, 10, 19, 9, 15, 0, 0, time.UTC)
	const legs = 40
	var wg sync.WaitGroup
	for i := range legs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := updateAlertTest(w.Store, func(record *AlertTest) {
				record.Legs[fmt.Sprintf("leg%02d", i)] = LegTest{At: at, Error: "refused", Probe: i%2 == 0}
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	record, err := ReadAlertTest(w.Store)
	if err != nil || record == nil || len(record.Legs) != legs {
		t.Fatalf("lines were lost: %+v, %v", record, err)
	}
	for i := range legs {
		if got := record.Legs[fmt.Sprintf("leg%02d", i)]; got.Error != "refused" || got.Probe != (i%2 == 0) {
			t.Fatalf("leg%02d: %+v", i, got)
		}
	}
}

// The weekly test is due once its hour has passed since the last full
// test, or since the daemon started when there was none.
func TestTheAlertTestIsDueWeekly(t *testing.T) {
	w, _ := newWatcher(t, nil)
	sched, err := manifest.ParseSchedule("15 9 * * 1")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC) // a Monday
	if AlertTestDue(w.Store, sched.Next, started, started.Add(74*time.Minute)) {
		t.Fatal("not due before 09:15")
	}
	if !AlertTestDue(w.Store, sched.Next, started, started.Add(75*time.Minute)) {
		t.Fatal("due at 09:15")
	}
	if AlertTestDue(w.Store, sched.Next, time.Time{}, started.Add(75*time.Minute)) {
		t.Fatal("never due without a starting point")
	}
	ran := started.Add(75 * time.Minute)
	if err := writeAlertTest(w.Store, &AlertTest{At: ran}); err != nil {
		t.Fatal(err)
	}
	if AlertTestDue(w.Store, sched.Next, started, ran.Add(6*24*time.Hour)) {
		t.Fatal("not due again within the week")
	}
	if !AlertTestDue(w.Store, sched.Next, started, ran.Add(7*24*time.Hour)) {
		t.Fatal("due the next Monday")
	}
}

// A backup stops an app's writers for at most app.BackupPauseLimit. A
// short pause opens nothing; one that runs long is a critical incident.
func TestABackupPauseIsExcusedUntilItRunsLong(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	n := &fakeNotifier{}
	w, now := newWatcher(t, n)
	manifest := `{"app":"hello","workloads":{"work":{"kind":"worker","image":"x"}}}`
	rev := state.Revision{App: "hello", ID: "r1", Status: state.RevisionActive, Manifest: json.RawMessage(manifest),
		Containers: map[string]string{"work": "bedrock-hello-work-r1"}, CreatedAt: time.Now().UTC()}
	if err := w.Store.SaveRevision(ctx, rev); err != nil {
		t.Fatal(err)
	}
	fake.Add(dockertest.Container{Name: "bedrock-edge", Running: true})
	fake.Add(dockertest.Container{Name: "bedrock-hello-work-r1", Running: false})
	locks := filepath.Join(filepath.Dir(w.Store.Path()), "locks")
	if err := os.MkdirAll(locks, 0o700); err != nil {
		t.Fatal(err)
	}
	pause := filepath.Join(locks, "hello.quiesce.json")
	if err := os.WriteFile(pause, []byte(`[{"id":"elsewhere","name":"bedrock-hello-work-r1","grace":60000000000}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	pausedAt := func(ago time.Duration) {
		at := time.Now().Add(-ago)
		if err := os.Chtimes(pause, at, at); err != nil {
			t.Fatal(err)
		}
	}
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	// Only the app's notices count: the host the test runs on may have
	// troubles of its own, such as a full disk.
	told := func() int {
		count := 0
		for _, sent := range n.sent {
			if sent.Key == "app:hello" {
				count++
			}
		}
		return count
	}
	watch := func(rounds int) {
		for i := 0; i < rounds; i++ {
			if err := w.Round(ctx, p.Observe(ctx)); err != nil {
				t.Fatal(err)
			}
			*now = now.Add(time.Minute)
		}
	}

	pausedAt(4 * time.Minute)
	if got := appCondition(t, p); got != "" {
		t.Fatalf("a 4 minute pause is a backup at work: %q", got)
	}
	watch(5)
	if inc, _ := w.Store.OpenIncidentByKey(ctx, "app:hello"); inc != nil || told() != 0 {
		t.Fatalf("a 4 minute pause opened %+v and sent %d", inc, told())
	}

	pausedAt(40 * time.Minute)
	watch(3)
	inc, _ := w.Store.OpenIncidentByKey(ctx, "app:hello")
	if inc == nil || inc.Severity != state.SeverityCritical || !strings.Contains(inc.Message, "paused for a backup for 40 minutes") || told() != 1 {
		t.Fatalf("a 40 minute pause should be a critical incident: %+v, %d sent", inc, told())
	}

	// Without the pause, a stopped writer is down as ever.
	if err := os.Remove(pause); err != nil {
		t.Fatal(err)
	}
	if got := appCondition(t, p); !strings.Contains(got, "work isn't running") {
		t.Fatalf("without a pause: %q", got)
	}
}

func TestARestartDoesNotPostponeAnOverdueAlertTest(t *testing.T) {
	sched, err := manifest.ParseSchedule("15 9 * * 1")
	if err != nil {
		t.Fatal(err)
	}
	monday := time.Date(2026, 10, 19, 9, 15, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		last time.Time
		now  time.Time
		due  bool
	}{
		{"overdue after restart", monday.Add(-7 * 24 * time.Hour), monday.Add(time.Minute), true},
		{"not yet due after restart", monday.Add(-7 * 24 * time.Hour), monday.Add(-time.Minute), false},
		{"already tested this week", monday, monday.Add(time.Minute), false},
		{"only a single leg was tested", time.Time{}, monday.Add(time.Minute), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newWatcher(t, nil)
			record := &AlertTest{At: tc.last, Legs: map[string]LegTest{
				EmailLeg: {At: tc.now},
			}}
			if err := writeAlertTest(w.Store, record); err != nil {
				t.Fatal(err)
			}
			// The daemon starts at now, after any earlier full test. A
			// recent test of one leg does not move the full test's clock.
			if got := AlertTestDue(w.Store, sched.Next, tc.now, tc.now); got != tc.due {
				t.Fatalf("due = %v, want %v after restarting with a full test at %s", got, tc.due, tc.last)
			}
		})
	}
}
