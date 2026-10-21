package daemon

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// MachineBackupSchedule is when the machine's own state is backed up.
const MachineBackupSchedule = "30 3 * * *"

// AlertCanarySchedule is when every way of sending alerts is tested, so
// a broken one is found before an incident needs it. A leg that fails
// opens a warning the others deliver.
const AlertCanarySchedule = "15 9 * * 1"

// MachineGCSchedule is when the machine reclaims what it no longer needs.
// It runs after the machine backup so a night's work is captured before
// anything is thrown away.
const MachineGCSchedule = "0 4 * * *"

// Scheduler starts backups and drills when they are due, one at a time,
// as operations with receipts like any other.
type Scheduler struct {
	Store   *state.Store
	Secrets *secrets.Store
	Server  *api.Server
	Log     func(format string, args ...any)
	// Hostname names the machine in the weekly test alert.
	Hostname string
	// Started is when this daemon came up; the machine backup counts
	// from there when it has never run.
	Started time.Time

	mu       sync.Mutex
	busy     bool
	warnedAt time.Time
}

// Tick runs whatever is due at now. A tick that finds the previous one
// still running does nothing.
func (s *Scheduler) Tick(ctx context.Context, now time.Time) {
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		return
	}
	s.busy = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
	}()

	active, err := s.Store.ActiveRevisions(ctx)
	if err != nil {
		s.Log("schedule: %v", err)
		return
	}
	// Reclaiming disk has nothing to do with backups, and the gate below
	// returns when storage is unset. Build cache in particular grows with
	// every deploy and is bounded by nothing else, so a machine that never
	// ran gc by hand would fill its disk.
	if s.dueOp(ctx, app.GCKind, MachineGCSchedule, s.Started, now) {
		s.run(ctx, app.GCKind, app.GCInput{}, "garbage collection")
	}
	if sched, err := manifest.ParseSchedule(AlertCanarySchedule); err == nil && watch.AlertTestDue(s.Store, sched.Next, s.Started, now) {
		s.testAlerts(ctx, now)
	}

	if _, err := integration.LoadStorage(s.Secrets); err != nil {
		// Nothing can be backed up until storage is set; say so once an
		// hour, only when there is something that wants backing up.
		if len(active) > 0 && now.Sub(s.warnedAt) >= time.Hour {
			s.warnedAt = now
			s.Log("schedule: no backups run until storage is set: helios integration set storage")
		}
		return
	}
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil || !m.BackedUp() {
			continue
		}
		if s.due(ctx, rev.App, state.BackupRunBackup, m.BackupSchedule(), s.firstDeploy(ctx, rev.App), now) {
			s.run(ctx, app.BackupKind, app.BackupInput{App: rev.App}, "backup "+rev.App)
		}
		if s.drillDue(ctx, rev.App, m.DrillSchedule(), now) {
			s.run(ctx, app.DrillKind, app.DrillInput{App: rev.App}, "drill "+rev.App)
		}
	}
	if s.due(ctx, manifest.ReservedApp, state.BackupRunBackup, MachineBackupSchedule, s.Started, now) {
		s.run(ctx, app.BackupKind, app.BackupInput{App: manifest.ReservedApp}, "backup of the machine")
	}
}

// testAlerts sends the weekly test through every leg. The prober turns a
// failed leg into a warning.
func (s *Scheduler) testAlerts(ctx context.Context, now time.Time) {
	results, err := watch.SendTestAlerts(ctx, s.Secrets, s.Store, s.Hostname, "", now)
	if err != nil {
		s.Log("schedule: alert test: %v", err)
	}
	for _, r := range results {
		switch {
		case r.Error != "":
			s.Log("schedule: alert test: %s failed: %s", r.Leg, r.Error)
		case r.Held:
			s.Log("schedule: alert test: the relay held %s's test for Loom, which is offline, so it shows nothing", r.Leg)
		}
	}
}

// dueOp is due for work that keeps no record of its own: the last
// operation of the kind stands in for a run log.
func (s *Scheduler) dueOp(ctx context.Context, kind, schedule string, since, now time.Time) bool {
	sched, err := manifest.ParseSchedule(schedule)
	if err != nil {
		return false
	}
	if last, err := s.Store.LastOfKind(ctx, kind); err == nil && last != nil && last.CreatedAt.After(since) {
		since = last.CreatedAt
	}
	if since.IsZero() {
		return false
	}
	return !sched.Next(since).After(now)
}

// due says whether a schedule has come round since the last run of a
// kind, or since a starting point when there was none.
func (s *Scheduler) due(ctx context.Context, appName, kind, schedule string, since, now time.Time) bool {
	sched, err := manifest.ParseSchedule(schedule)
	if err != nil {
		return false
	}
	if last, err := s.Store.LastBackupRun(ctx, appName, kind); err == nil && last != nil && last.StartedAt.After(since) {
		since = last.StartedAt
	}
	if since.IsZero() {
		return false
	}
	next := sched.Next(since)
	return !next.After(now)
}

// drillDue says whether an app's restore drill has come round. A drill
// waits for a good backup, and a skipped drill counts as one run at the
// occurrence it skipped.
func (s *Scheduler) drillDue(ctx context.Context, appName, schedule string, now time.Time) bool {
	next, err := app.NextDrill(ctx, s.Store, appName, schedule)
	return err == nil && !next.IsZero() && !next.After(now)
}

// firstDeploy is when an app first arrived, so a new app's first backup
// waits for the schedule rather than running the moment it is deployed.
func (s *Scheduler) firstDeploy(ctx context.Context, appName string) time.Time {
	first, err := s.Store.FirstRevisionCreatedAt(ctx, appName)
	if err != nil {
		return time.Time{}
	}
	return first
}

func (s *Scheduler) run(ctx context.Context, kind string, input any, what string) {
	raw, err := json.Marshal(input)
	if err != nil {
		return
	}
	s.Log("scheduled %s starting", what)
	receipt, err := s.Server.RunLocked(ctx, kind, raw, func(ev kernel.Event) {
		if ev.Type == kernel.EventStepFinished && ev.Step != nil && ev.Step.Error != "" {
			s.Log("scheduled %s: %s: %s", what, ev.Step.Name, ev.Step.Error)
		}
	})
	switch {
	case err != nil:
		s.Log("scheduled %s: %v", what, err)
	case receipt != nil:
		s.Log("scheduled %s: %s (%s)", what, receipt.Status, receipt.ID)
	}
}
