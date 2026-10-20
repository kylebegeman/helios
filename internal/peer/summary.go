package peer

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
	"github.com/kylebegeman/helios/internal/watch"
)

// StaleRound is how long ago a machine's last watch round may have ended
// before its summary reads as stale: its Helios answers, but its watch
// has stopped.
const StaleRound = 5 * time.Minute

// Summary is what a machine tells the peers that watch it about itself:
// enough to judge whether its watch still runs, and what it may be unable
// to alert about. Every age is in seconds by its own clock, so the two
// machines' clocks never need to agree. It names apps, alert legs and
// peers, never an address.
type Summary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// LastRoundAgeS is how long ago its last watch round ended.
	LastRoundAgeS int64             `json:"last_round_age_s"`
	SelfCheck     bool              `json:"self_check"`
	Incidents     []SummaryIncident `json:"incidents"`
	// Sending are the keys of the peer notices it is passing to its own
	// fan-out right now.
	Sending []string        `json:"sending"`
	Backups []SummaryBackup `json:"backups"`
	Legs    []SummaryLeg    `json:"legs"`
	// Disk is left out when the disk can't be read.
	Disk     *SummaryDisk  `json:"disk,omitempty"`
	Findings []Finding     `json:"findings"`
	Views    []SummaryView `json:"views"`
}

// SummaryIncident is one of a machine's open incidents.
type SummaryIncident struct {
	Key        string `json:"key"`
	Subject    string `json:"subject"`
	Severity   string `json:"severity"`
	OpenedAgeS int64  `json:"opened_age_s"`
	// ToldAgeS is how long ago it was last told, absent when it never
	// was. A peer incident counts as told only when this machine sent
	// the notice itself, so one observer standing down for another never
	// reads as a page to a third, and only at its severity or graver, so
	// a warning told never reads as the page of an outage.
	ToldAgeS *int64 `json:"told_age_s,omitempty"`
	// Owed is a notice that failed to go out, and never one held while
	// another observer is to send it. Why is never said: a mail server's
	// error can name hosts.
	Owed bool `json:"owed"`
}

// SummaryBackup is how one app stands on backups and restore drills. An
// age is absent when there is nothing to measure it from.
type SummaryBackup struct {
	App                string `json:"app"`
	LastGoodBackupAgeS *int64 `json:"last_good_backup_age_s,omitempty"`
	DeployedAgeS       *int64 `json:"deployed_age_s,omitempty"`
	LastGoodDrillAgeS  *int64 `json:"last_good_drill_age_s,omitempty"`
	// DrillOverdueS is how far past due its next drill is, zero when it
	// isn't, and absent when no drill is scheduled.
	DrillOverdueS *int64 `json:"drill_overdue_s,omitempty"`
}

// SummaryLeg is one of a machine's alert legs, and how long ago it last
// delivered; absent when it never has. What it delivered is never said:
// that holds alert subjects.
type SummaryLeg struct {
	Name       string `json:"name"`
	LastOKAgeS *int64 `json:"last_ok_age_s,omitempty"`
}

// SummaryDisk is the room left on a machine's disk.
type SummaryDisk struct {
	FreeBytes  uint64 `json:"free_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
}

// SummaryView is a machine's own last look at one of its peers.
type SummaryView struct {
	Subject string `json:"subject"`
	AgeS    int64  `json:"age_s"`
	Paths
}

// Last is what a machine's own watching last found, for its summary.
type Last struct {
	// Round is when its last watch round ended, or when it started
	// watching before the first.
	Round time.Time
	// Looked is when it last looked at its peers: whether its own public
	// URL answered, the peer conditions it found, and each peer's paths
	// by name.
	Looked    time.Time
	SelfCheck bool
	Findings  []Finding
	Paths     map[string]Paths
	// Sending are the keys of the peer notices its gate is passing to its
	// own fan-out right now, and Sent the notices about its peer
	// incidents it sent itself.
	Sending []string
	Sent    []Told
}

// told is when this machine last sent a notice about the incident itself
// at the incident's severity or graver, zero when it never has.
func (l Last) told(i state.Incident) time.Time {
	var at time.Time
	for _, t := range l.Sent {
		if t.IncidentID == i.ID && rank(t.Severity) >= rank(i.Severity) {
			at = later(at, t.At)
		}
	}
	return at
}

// Deps is what a summary is built from.
type Deps struct {
	Store   *state.Store
	Secrets *secrets.Store
	// Root is the filesystem whose room is reported; / when empty.
	Root string
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Last is what this machine's watching last found. Without it the
	// machine has never watched, and its summary reads as stale.
	Last func() Last
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Build is the summary of the machine named name, as of now. A store
// that can't be read fails it; an app whose manifest can't be read is
// left out.
func Build(ctx context.Context, d Deps, name string) (Summary, error) {
	now := d.now()
	var last Last
	if d.Last != nil {
		last = d.Last()
	}
	s := Summary{Name: name, Version: version.Current().Version, LastRoundAgeS: age(now, last.Round), SelfCheck: last.SelfCheck,
		Incidents: []SummaryIncident{}, Sending: append([]string{}, last.Sending...), Backups: []SummaryBackup{}, Findings: []Finding{}, Views: []SummaryView{}}

	open, err := d.Store.OpenIncidents(ctx)
	if err != nil {
		return Summary{}, err
	}
	for _, i := range open {
		told, owed := i.NotifiedAt, i.NotifyError != ""
		if gated(i.Key) {
			_, held := deferredTo(i.NotifyError)
			told, owed = last.told(i), owed && !held
		}
		s.Incidents = append(s.Incidents, SummaryIncident{Key: i.Key, Subject: i.Subject, Severity: i.Severity,
			OpenedAgeS: age(now, i.OpenedAt), ToldAgeS: ageIf(now, told), Owed: owed})
	}
	if s.Backups, err = backups(ctx, d.Store, now); err != nil {
		return Summary{}, err
	}
	if s.Legs, err = legs(ctx, d.Store, d.Secrets, now); err != nil {
		return Summary{}, err
	}
	root := d.Root
	if root == "" {
		root = "/"
	}
	if free, total, ok := watch.DiskFree(root); ok {
		s.Disk = &SummaryDisk{FreeBytes: free, TotalBytes: total}
	}

	s.Findings = append(s.Findings, last.Findings...)
	sort.Slice(s.Findings, func(i, j int) bool { return s.Findings[i].Key < s.Findings[j].Key })
	if !last.Looked.IsZero() {
		for subject, p := range last.Paths {
			s.Views = append(s.Views, SummaryView{Subject: subject, AgeS: age(now, last.Looked), Paths: p})
		}
		sort.Slice(s.Views, func(i, j int) bool { return s.Views[i].Subject < s.Views[j].Subject })
	}
	return s, nil
}

// legs are each of a machine's alert legs, and how long ago it last
// delivered.
func legs(ctx context.Context, store *state.Store, sec *secrets.Store, now time.Time) ([]SummaryLeg, error) {
	uses, err := store.IntegrationUses(ctx)
	if err != nil {
		return nil, err
	}
	out := []SummaryLeg{}
	for _, leg := range watch.LegNames(sec) {
		out = append(out, SummaryLeg{Name: leg, LastOKAgeS: ageIf(now, uses[leg].UsedAt)})
	}
	return out, nil
}

// leg is a summary's leg as a judge reads it.
func (l SummaryLeg) leg() Leg {
	return Leg{Name: l.Name, Worked: l.LastOKAgeS != nil, LastOK: elapsedIf(l.LastOKAgeS)}
}

// backups are the apps the scheduler backs up, the way it finds them:
// each active app whose manifest asks for backups, then the machine's own.
func backups(ctx context.Context, store *state.Store, now time.Time) ([]SummaryBackup, error) {
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return nil, err
	}
	out := []SummaryBackup{}
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil || !m.BackedUp() {
			continue
		}
		b, err := backup(ctx, store, rev.App, now)
		if err != nil {
			return nil, err
		}
		if drill, err := store.LastGoodBackupRun(ctx, rev.App, state.BackupRunDrill); err != nil {
			return nil, err
		} else if drill != nil {
			b.LastGoodDrillAgeS = ageIf(now, drill.StartedAt)
		}
		// A drill waits for a good backup; until there is one, none is due.
		if next, err := app.NextDrill(ctx, store, rev.App, m.DrillSchedule()); err == nil && !next.IsZero() {
			overdue := age(now, next)
			b.DrillOverdueS = &overdue
		}
		out = append(out, b)
	}
	b, err := backup(ctx, store, manifest.ReservedApp, now)
	if err != nil {
		return nil, err
	}
	return append(out, b), nil
}

// backup is an app's last good backup and first deploy. The machine's
// own has no deploy, so its age is left out, as the machine's own watch
// leaves it out.
func backup(ctx context.Context, store *state.Store, appName string, now time.Time) (SummaryBackup, error) {
	b := SummaryBackup{App: appName}
	good, err := store.LastGoodBackupRun(ctx, appName, state.BackupRunBackup)
	if err != nil {
		return SummaryBackup{}, err
	}
	if good != nil {
		b.LastGoodBackupAgeS = ageIf(now, good.StartedAt)
	}
	first, err := store.FirstRevisionCreatedAt(ctx, appName)
	switch {
	case err == nil:
		b.DeployedAgeS = ageIf(now, first)
	case !errors.Is(err, state.ErrNotFound):
		return SummaryBackup{}, err
	}
	return b, nil
}

// age is how many whole seconds before now t was, and none when t is
// later.
func age(now, t time.Time) int64 {
	if t.After(now) {
		return 0
	}
	return int64(now.Sub(t) / time.Second)
}

// ageIf is age, and nothing when t is zero.
func ageIf(now, t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	a := age(now, t)
	return &a
}
