package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// An operator can skip one scheduled restore drill, or hold a cron workload
// for a while, and must say why. Status, the run lists and the watcher all
// show the reason. Backups are never held, and a hold always ends.
const (
	DrillSkipKind   = "app.drill.skip"
	CronHoldKind    = "app.cron.hold"
	CronReleaseKind = "app.cron.release"
)

// cronHoldMax is the furthest ahead a cron hold may end.
const cronHoldMax = 14 * 24 * time.Hour

// OperatorTime is how a skipped drill or a hold's end reads in a plan.
func OperatorTime(t time.Time) string { return t.UTC().Format("Monday 2 January 15:04 UTC") }

// NextDrill is when an app's next scheduled restore drill is due: the first
// occurrence of its drill schedule after the latest of its last good backup,
// its last drill and its last skipped drill. It is zero while the app has no
// good backup to drill.
func NextDrill(ctx context.Context, store *state.Store, appName, schedule string) (time.Time, error) {
	sched, err := manifest.ParseSchedule(schedule)
	if err != nil {
		return time.Time{}, err
	}
	good, err := store.LastGoodBackupRun(ctx, appName, state.BackupRunBackup)
	if err != nil || good == nil {
		return time.Time{}, err
	}
	since := good.StartedAt
	for _, kind := range []string{state.BackupRunDrill, state.BackupRunDrillSkip} {
		last, err := store.LastBackupRun(ctx, appName, kind)
		if err != nil {
			return time.Time{}, err
		}
		if last != nil && last.StartedAt.After(since) {
			since = last.StartedAt
		}
	}
	return sched.Next(since), nil
}

// ActiveDrillSkip is an app's skipped drill that no drill has run since, or
// nil.
func ActiveDrillSkip(ctx context.Context, store *state.Store, appName string) (*state.BackupRun, error) {
	skip, err := store.LastBackupRun(ctx, appName, state.BackupRunDrillSkip)
	if err != nil || skip == nil {
		return nil, err
	}
	drill, err := store.LastBackupRun(ctx, appName, state.BackupRunDrill)
	if err != nil {
		return nil, err
	}
	if drill != nil && !drill.StartedAt.Before(skip.StartedAt) {
		return nil, nil
	}
	return skip, nil
}

// ActiveCronHold is a cron workload's hold that hasn't ended at now, or nil.
func ActiveCronHold(ctx context.Context, store *state.Store, appName, workload string, now time.Time) (*state.JobRun, error) {
	hold, err := store.LastJobHold(ctx, appName, workload)
	if err != nil || hold == nil || !now.Before(hold.FinishedAt) {
		return nil, err
	}
	return hold, nil
}

// DrillSkip is the Definition for DrillSkipKind.
type DrillSkip struct {
	Store *state.Store
	// Now is the clock; nil is the real one.
	Now func() time.Time
}

// DrillSkipInput says whose next drill to skip and why.
type DrillSkipInput struct {
	App    string `json:"app"`
	Reason string `json:"reason"`
	// By is who asked, as the CLI found them.
	By string `json:"by,omitempty"`
}

// Kind implements kernel.Definition.
func (DrillSkip) Kind() string { return DrillSkipKind }

// drillSkip is the drill a skip would skip.
type drillSkip struct {
	// due is the occurrence skipped. An overdue drill is skipped where it
	// stands, so it is recorded at the time of the skip.
	due     time.Time
	overdue bool
	// skipped is a later drill already skipped, which this skip passes.
	skipped time.Time
	// next is the drill after this one.
	next time.Time
}

func (d DrillSkip) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d DrillSkip) find(ctx context.Context, appName string, now time.Time) (drillSkip, error) {
	m, _, err := activeManifest(ctx, d.Store, appName)
	if err != nil {
		return drillSkip{}, err
	}
	if !m.BackedUp() {
		return drillSkip{}, fmt.Errorf("%s isn't backed up, so it has no drill to skip", appName)
	}
	schedule := m.DrillSchedule()
	sched, err := manifest.ParseSchedule(schedule)
	if err != nil {
		return drillSkip{}, err
	}
	due, err := NextDrill(ctx, d.Store, appName, schedule)
	if err != nil {
		return drillSkip{}, err
	}
	if due.IsZero() {
		return drillSkip{}, fmt.Errorf("%s has no good backup yet, so no drill is scheduled to skip", appName)
	}
	s := drillSkip{due: due}
	last, err := d.Store.LastBackupRun(ctx, appName, state.BackupRunDrillSkip)
	if err != nil {
		return drillSkip{}, err
	}
	if last != nil && last.StartedAt.After(now) {
		s.skipped = last.StartedAt
	}
	at := due
	if !due.After(now) {
		s.overdue, at = true, now
	}
	s.next = sched.Next(at)
	return s, nil
}

func asked(reason, by string) string {
	if by == "" {
		return reason
	}
	return reason + ", asked by " + by
}

// Plan implements kernel.Definition.
func (d DrillSkip) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in DrillSkipInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("drill skip input: %w", err)
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.App == "" {
		return nil, errors.New("which app?")
	}
	if in.Reason == "" {
		return nil, errors.New("--reason is required: say why the drill is skipped")
	}
	planned, err := d.find(ctx, in.App, d.now())
	if err != nil {
		return nil, err
	}
	var change string
	switch {
	case planned.overdue:
		change = fmt.Sprintf("skip the overdue drill of %s, due since %s", in.App, OperatorTime(planned.due))
	case !planned.skipped.IsZero():
		change = fmt.Sprintf("the drill of %s due %s is already skipped, so skip the one after it, due %s", in.App, OperatorTime(planned.skipped), OperatorTime(planned.due))
	default:
		change = fmt.Sprintf("skip the drill of %s due %s", in.App, OperatorTime(planned.due))
	}
	change += fmt.Sprintf(" (%s); the next drill is due %s", asked(in.Reason, in.By), OperatorTime(planned.next))
	return &kernel.Plan{Target: in.App, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "skip drill", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			now := d.now()
			current, err := d.find(ctx, in.App, now)
			if err != nil {
				return err
			}
			if !current.due.Equal(planned.due) {
				return fmt.Errorf("the next drill of %s is now due %s, not %s; plan the skip again", in.App, OperatorTime(current.due), OperatorTime(planned.due))
			}
			at := current.due
			if current.overdue {
				at = now
			}
			if _, err := d.Store.SkipDrill(ctx, in.App, at, in.Reason); err != nil {
				return err
			}
			fmt.Fprintf(out, "skipped the drill of %s due %s; the next drill is due %s\n", in.App, OperatorTime(current.due), OperatorTime(current.next))
			return nil
		},
	}}}, nil
}

// CronHold is the Definition for CronHoldKind.
type CronHold struct {
	Store *state.Store
	// Now is the clock; nil is the real one.
	Now func() time.Time
}

// CronHoldInput says which cron workload to hold, until when, and why.
type CronHoldInput struct {
	App      string    `json:"app"`
	Workload string    `json:"workload"`
	Until    time.Time `json:"until"`
	Reason   string    `json:"reason"`
	// By is who asked, as the CLI found them.
	By string `json:"by,omitempty"`
}

// Kind implements kernel.Definition.
func (CronHold) Kind() string { return CronHoldKind }

func (h CronHold) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

// cronWorkload finds an active app's cron workload and its schedule.
func cronWorkload(ctx context.Context, store *state.Store, appName, workload string) (*state.Revision, cron.Schedule, error) {
	m, rev, err := activeManifest(ctx, store, appName)
	if err != nil {
		return nil, nil, err
	}
	w, ok := m.Workloads[workload]
	if !ok || w.Kind != manifest.Cron {
		return nil, nil, fmt.Errorf("%s has no cron workload named %s", appName, workload)
	}
	sched, err := manifest.ParseSchedule(w.Schedule)
	if err != nil {
		return nil, nil, fmt.Errorf("%s/%s schedule: %w", appName, workload, err)
	}
	return rev, sched, nil
}

func (in *CronHoldInput) check(now time.Time) error {
	in.Reason = strings.TrimSpace(in.Reason)
	switch {
	case in.App == "":
		return errors.New("which app?")
	case in.Workload == "":
		return errors.New("which cron workload?")
	case in.Reason == "":
		return fmt.Errorf("--reason is required: say why %s/%s is held", in.App, in.Workload)
	case in.Until.IsZero():
		return errors.New("--until is required: say when the hold ends, as an RFC 3339 time")
	case !in.Until.After(now):
		return fmt.Errorf("--until %s is not in the future", in.Until.UTC().Format(time.RFC3339))
	case in.Until.After(now.Add(cronHoldMax)):
		return fmt.Errorf("--until %s is more than %d days away; a hold may last at most %d days", in.Until.UTC().Format(time.RFC3339), int(cronHoldMax.Hours()/24), int(cronHoldMax.Hours()/24))
	}
	return nil
}

// Plan implements kernel.Definition.
func (h CronHold) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in CronHoldInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("cron hold input: %w", err)
	}
	if err := in.check(h.now()); err != nil {
		return nil, err
	}
	_, sched, err := cronWorkload(ctx, h.Store, in.App, in.Workload)
	if err != nil {
		return nil, err
	}
	change := fmt.Sprintf("hold cron %s/%s until %s (%s); it next runs at %s, and nothing runs to catch up",
		in.App, in.Workload, OperatorTime(in.Until), asked(in.Reason, in.By), OperatorTime(sched.Next(in.Until)))
	return &kernel.Plan{Target: in.App, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "hold cron", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			now := h.now()
			if err := in.check(now); err != nil {
				return err
			}
			rev, _, err := cronWorkload(ctx, h.Store, in.App, in.Workload)
			if err != nil {
				return err
			}
			hold, err := h.Store.LastJobHold(ctx, in.App, in.Workload)
			if err != nil {
				return err
			}
			// A resumed apply finds the hold it placed.
			if hold == nil || !hold.FinishedAt.Equal(in.Until) || hold.Output != in.Reason {
				if _, err := h.Store.HoldJob(ctx, in.App, in.Workload, rev.ID, now, in.Until, in.Reason); err != nil {
					return err
				}
			}
			fmt.Fprintf(out, "held cron %s/%s until %s\n", in.App, in.Workload, OperatorTime(in.Until))
			if last, err := h.Store.LastJobRun(ctx, in.App, in.Workload); err == nil && last != nil && last.FinishedAt.IsZero() {
				fmt.Fprintf(out, "the run that started %s is still going; a hold doesn't stop it\n", last.StartedAt.UTC().Format("15:04 UTC"))
			}
			return nil
		},
	}}}, nil
}

// CronRelease is the Definition for CronReleaseKind.
type CronRelease struct {
	Store *state.Store
	// Now is the clock; nil is the real one.
	Now func() time.Time
}

// CronReleaseInput says which cron workload's hold to end.
type CronReleaseInput struct {
	App      string `json:"app"`
	Workload string `json:"workload"`
	// By is who asked, as the CLI found them.
	By string `json:"by,omitempty"`
}

// Kind implements kernel.Definition.
func (CronRelease) Kind() string { return CronReleaseKind }

func (r CronRelease) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Plan implements kernel.Definition.
func (r CronRelease) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in CronReleaseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("cron release input: %w", err)
	}
	if in.App == "" {
		return nil, errors.New("which app?")
	}
	if in.Workload == "" {
		return nil, errors.New("which cron workload?")
	}
	_, sched, err := cronWorkload(ctx, r.Store, in.App, in.Workload)
	if err != nil {
		return nil, err
	}
	now := r.now()
	hold, err := ActiveCronHold(ctx, r.Store, in.App, in.Workload, now)
	if err != nil {
		return nil, err
	}
	if hold == nil {
		return nil, fmt.Errorf("%s/%s isn't held", in.App, in.Workload)
	}
	change := fmt.Sprintf("release cron %s/%s from its hold until %s; it next runs at %s", in.App, in.Workload, OperatorTime(hold.FinishedAt), OperatorTime(sched.Next(now)))
	if in.By != "" {
		change += ", asked by " + in.By
	}
	id := hold.ID
	return &kernel.Plan{Target: in.App, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "release cron", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			now := r.now()
			current, err := r.Store.LastJobHold(ctx, in.App, in.Workload)
			if err != nil {
				return err
			}
			if current == nil || current.ID != id {
				return fmt.Errorf("%s/%s was held again since this was planned; plan the release again", in.App, in.Workload)
			}
			if now.Before(current.FinishedAt) {
				if err := r.Store.EndJobHold(ctx, id, now); err != nil {
					return err
				}
			}
			fmt.Fprintf(out, "released cron %s/%s\n", in.App, in.Workload)
			return nil
		},
	}}}, nil
}

// activeManifest is an app's active revision and its manifest.
func activeManifest(ctx context.Context, store *state.Store, appName string) (*manifest.Manifest, *state.Revision, error) {
	if appName == "" {
		return nil, nil, errors.New("which app?")
	}
	rev, err := store.RevisionWithStatus(ctx, appName, state.RevisionActive)
	if err != nil {
		return nil, nil, err
	}
	if rev == nil {
		return nil, nil, fmt.Errorf("%s isn't deployed", appName)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return nil, nil, fmt.Errorf("%s's manifest cannot be read: %w", appName, err)
	}
	return &m, rev, nil
}
