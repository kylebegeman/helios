package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// The weekly alert test records itself even when nothing is set up, so
// it runs once a week and not on every tick after its hour.
func TestTheWeeklyAlertTestRunsOnce(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sec := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "key")}
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	var logged []string
	started := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC) // a Monday
	s := &Scheduler{Store: store, Secrets: sec, Hostname: "box", Started: started,
		Log: func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }}
	sched, err := manifest.ParseSchedule(AlertCanarySchedule)
	if err != nil {
		t.Fatal(err)
	}
	now := started.Add(75 * time.Minute)
	if !watch.AlertTestDue(store, sched.Next, s.Started, now) {
		t.Fatal("the test should be due at 09:15 on a Monday")
	}
	s.testAlerts(context.Background(), now)
	if len(logged) != 1 || !strings.Contains(logged[0], watch.NoAlertsSetUp) {
		t.Fatalf("logged %q", logged)
	}
	if watch.AlertTestDue(store, sched.Next, s.Started, now.Add(30*time.Second)) {
		t.Fatal("the test ran and recorded itself, so it isn't due again this week")
	}
}
