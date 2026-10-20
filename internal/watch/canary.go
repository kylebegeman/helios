package watch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// AlertTestFile records the last test of each way alerts go out, beside
// the state store.
const AlertTestFile = "alerts-test.json"

// AlertTest is the record of the last tests of the alerts.
type AlertTest struct {
	// At is when every leg was last tested together.
	At   time.Time          `json:"at"`
	Legs map[string]LegTest `json:"legs"`
}

// LegTest is one leg's last test.
type LegTest struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
	// Probe marks a result from a probe, which proves less than a test
	// that arrives: a passing probe clears only a failed probe.
	Probe bool `json:"probe,omitempty"`
}

// LegResult is how one leg did in a test.
type LegResult struct {
	Leg   string `json:"leg"`
	To    string `json:"to,omitempty"`
	Error string `json:"error,omitempty"`
	// Probe is set when the leg was probed rather than sent a test.
	Probe bool `json:"probe,omitempty"`
}

func alertTestPath(store *state.Store) string {
	return filepath.Join(filepath.Dir(store.Path()), AlertTestFile)
}

// SendTestAlerts sends a test notice through each leg on its own, each
// mail server as a leg of its own, and records how each did. only names
// the one leg to test; empty tests them all and replaces the record.
// Testing them all probes the Loom leg, which opens no thread; naming it
// sends it a test, which opens one.
func SendTestAlerts(ctx context.Context, sec *secrets.Store, store *state.Store, hostname, only string, now time.Time) ([]LegResult, error) {
	legs := loadLegs(sec, store)
	notice := testNotice(hostname)
	notice.Test = TestProbe
	if only != "" {
		i := slices.IndexFunc(legs, func(l legSpec) bool { return l.name == only })
		if i < 0 {
			return nil, unknownLeg(only, legs)
		}
		legs = legs[i : i+1]
		notice.Test = TestSend
	}
	results := make([]LegResult, len(legs))
	var wg sync.WaitGroup
	for i, l := range legs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = LegResult{Leg: l.name, To: l.to, Probe: notice.Test == TestProbe && l.name == LoomWebhookLeg}
			if err := deliver(ctx, Leg{Name: l.name, Notifier: l.notifier}, notice); err != nil {
				results[i].Error = err.Error()
			}
		}()
	}
	wg.Wait()

	err := updateAlertTest(store, func(record *AlertTest) {
		before := record.Legs
		if only == "" {
			*record = AlertTest{At: now, Legs: map[string]LegTest{}}
		}
		for _, r := range results {
			// A probe proves less than a test that arrives, so it never
			// takes the place of the failure of one.
			if was := before[r.Leg]; r.Probe && was.Error != "" && !was.Probe {
				record.Legs[r.Leg] = was
				continue
			}
			record.Legs[r.Leg] = LegTest{At: now, Error: r.Error, Probe: r.Probe}
		}
	})
	if err != nil {
		return results, fmt.Errorf("record the test: %w", err)
	}
	if len(legs) == 0 {
		return nil, errors.New(NoAlertsSetUp)
	}
	return results, nil
}

func unknownLeg(name string, legs []legSpec) error {
	if len(legs) == 0 {
		return fmt.Errorf("no alert leg named %s: %s", name, NoAlertsSetUp)
	}
	names := make([]string, len(legs))
	for i, l := range legs {
		names[i] = l.name
	}
	return fmt.Errorf("no alert leg named %s; set up: %s", name, strings.Join(names, ", "))
}

// ReadAlertTest returns the record of the last tests, or nil when there
// has been none.
func ReadAlertTest(store *state.Store) (*AlertTest, error) {
	data, err := os.ReadFile(alertTestPath(store))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record AlertTest
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("read %s: %w", AlertTestFile, err)
	}
	return &record, nil
}

// alertTestMu keeps changes to the record one at a time, so a test of one
// leg and a leg recording a refusal never write over each other.
var alertTestMu sync.Mutex

// updateAlertTest reads the record, changes it and writes it back. A
// record that can't be read starts again empty, as a full test would.
func updateAlertTest(store *state.Store, change func(*AlertTest)) error {
	alertTestMu.Lock()
	defer alertTestMu.Unlock()
	record, err := ReadAlertTest(store)
	if err != nil || record == nil {
		record = &AlertTest{}
	}
	if record.Legs == nil {
		record.Legs = map[string]LegTest{}
	}
	change(record)
	return writeAlertTest(store, record)
}

// writeAlertTest replaces the record whole, and only once the new one is
// on disk, so a crash leaves the old record or the new, never a torn one.
func writeAlertTest(store *state.Store, record *AlertTest) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	path := alertTestPath(store)
	f, err := os.CreateTemp(filepath.Dir(path), ".alerts-test-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// alertTest is the condition of the alerts themselves: a leg that failed
// its last test is a warning, which the legs that work deliver.
func (p *Prober) alertTest() []Condition {
	record, err := ReadAlertTest(p.Store)
	if err != nil {
		return []Condition{{Key: "host:alerts", Subject: "alerts", Severity: state.SeverityWarning, Message: "the record of the last alert test can't be read: " + err.Error()}}
	}
	if record == nil {
		return nil
	}
	var failed, again []string
	for _, name := range sortedLegs(record.Legs) {
		t := record.Legs[name]
		if t.Error == "" {
			continue
		}
		failed = append(failed, fmt.Sprintf("%s failed its test on %s (%s)", name, t.At.Format("2006-01-02"), t.Error))
		// Only a test that arrives clears what an incident or a test send
		// found wrong with the Loom leg; a full test only probes it.
		test := "helios alerts test"
		if name == LoomWebhookLeg && !t.Probe {
			test += " --leg " + LoomWebhookLeg
		}
		if !slices.Contains(again, test) {
			again = append(again, test)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return []Condition{{Key: "host:alerts", Subject: "alerts", Severity: state.SeverityWarning,
		Message: strings.Join(failed, "; ") + "; fix it, then run " + strings.Join(again, " and ")}}
}

func sortedLegs(legs map[string]LegTest) []string {
	names := make([]string, 0, len(legs))
	for name := range legs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// AlertTestDue says whether the weekly test has come round on a schedule
// since the last full test, or since a starting point when there was none.
func AlertTestDue(store *state.Store, next func(time.Time) time.Time, since, now time.Time) bool {
	if record, err := ReadAlertTest(store); err == nil && record != nil && record.At.After(since) {
		since = record.At
	}
	return !since.IsZero() && !next(since).After(now)
}
