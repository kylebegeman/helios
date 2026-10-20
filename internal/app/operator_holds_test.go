package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// cronHoldFixture is a site whose web workload runs at 04:45 UTC daily,
// deployed on a Sunday. The days are ahead of the real clock, which stamps
// each job run, so a run recorded during the test never moves the schedule.
type cronHoldFixture struct {
	store *state.Store
	jobs  *Jobs
	// sunday is the Sunday the site was deployed, at midnight UTC.
	sunday time.Time
}

func newCronHoldFixture(t *testing.T) *cronHoldFixture {
	t.Helper()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	w := m.Workloads["web"]
	w.Kind, w.Schedule = manifest.Cron, "45 4 * * *"
	m.Workloads["web"] = w
	sunday := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 7)
	for sunday.Weekday() != time.Sunday {
		sunday = sunday.AddDate(0, 0, 1)
	}
	releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, sunday.Add(12*time.Hour))
	fake := dockertest.New(t)
	fake.OnCreate = func(c dockertest.Container) { fake.Update(c.Name, func(c *dockertest.Container) { c.ExitAfter = 1 }) }
	return &cronHoldFixture{store: store, jobs: NewJobs(store, newSecrets(t)), sunday: sunday}
}

// at is a day after the deploy, at a time of day.
func (f *cronHoldFixture) at(days int, clock time.Duration) time.Time {
	return f.sunday.AddDate(0, 0, days).Add(clock)
}

// tick runs the cron scheduler once at now and says whether a run started.
func (f *cronHoldFixture) tick(t *testing.T, now time.Time) bool {
	t.Helper()
	before := f.cronRuns(t)
	f.jobs.Tick(context.Background(), now, func(string, ...any) {})
	f.jobs.Wait()
	return f.cronRuns(t) > before
}

func (f *cronHoldFixture) cronRuns(t *testing.T) int {
	t.Helper()
	runs, err := f.store.JobRuns(context.Background(), "site", "web", 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range runs {
		if r.Kind == JobCron {
			n++
		}
	}
	return n
}

func applyPlan(t *testing.T, d kernel.Definition, input any) string {
	t.Helper()
	raw, _ := json.Marshal(input)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		t.Fatalf("plan %s: %v", d.Kind(), err)
	}
	var out strings.Builder
	for _, step := range plan.Steps {
		if err := step.Apply(context.Background(), &out); err != nil {
			t.Fatalf("apply %s: %v", d.Kind(), err)
		}
	}
	return plan.Steps[0].Change
}

func clock(t time.Time) func() time.Time { return func() time.Time { return t } }

const (
	cronDue     = 4*time.Hour + 45*time.Minute
	holdEnds    = 5 * time.Hour
	monday      = 1
	tuesday     = 2
	wednesday   = 3
	mondayNoon  = 12 * time.Hour
	sundayAfter = 13 * time.Hour
)

// A hold skips every run until it ends, then the workload waits for its
// next scheduled time instead of catching up on the runs it missed.
func TestAHeldCronSkipsItsRunsUntilTheHoldEndsWithNoCatchUp(t *testing.T) {
	f := newCronHoldFixture(t)
	change := applyPlan(t, CronHold{Store: f.store, Now: clock(f.at(0, sundayAfter))},
		CronHoldInput{App: "site", Workload: "web", Until: f.at(tuesday, holdEnds), Reason: "the volume is being moved", By: "operator"})
	if !strings.Contains(change, "the volume is being moved, asked by operator") || !strings.Contains(change, "it next runs at "+OperatorTime(f.at(wednesday, cronDue))) {
		t.Fatalf("plan says %q", change)
	}
	for _, now := range []time.Time{f.at(monday, cronDue), f.at(tuesday, cronDue), f.at(tuesday, holdEnds), f.at(tuesday, holdEnds+time.Hour)} {
		if f.tick(t, now) {
			t.Fatalf("the held cron ran at %s", now)
		}
	}
	if !f.tick(t, f.at(wednesday, cronDue)) {
		t.Fatal("the cron didn't run on Wednesday, after its hold ended")
	}
	if hold, err := ActiveCronHold(context.Background(), f.store, "site", "web", f.at(wednesday, cronDue)); err != nil || hold != nil {
		t.Fatalf("the hold is still active: %+v, %v", hold, err)
	}
}

// Releasing a hold early lets the workload run at its next scheduled time.
func TestAReleasedCronRunsAtItsNextScheduledTime(t *testing.T) {
	f := newCronHoldFixture(t)
	applyPlan(t, CronHold{Store: f.store, Now: clock(f.at(0, sundayAfter))},
		CronHoldInput{App: "site", Workload: "web", Until: f.at(tuesday, holdEnds), Reason: "the volume is being moved"})
	if f.tick(t, f.at(monday, cronDue)) {
		t.Fatal("the held cron ran on Monday")
	}
	change := applyPlan(t, CronRelease{Store: f.store, Now: clock(f.at(monday, mondayNoon))}, CronReleaseInput{App: "site", Workload: "web"})
	if want := "release cron site/web from its hold until " + OperatorTime(f.at(tuesday, holdEnds)) + "; it next runs at " + OperatorTime(f.at(tuesday, cronDue)); change != want {
		t.Fatalf("plan says\n  %s\nwant\n  %s", change, want)
	}
	if f.tick(t, f.at(monday, mondayNoon)) {
		t.Fatal("the released cron caught up on Monday's run")
	}
	if !f.tick(t, f.at(tuesday, cronDue)) {
		t.Fatal("the released cron didn't run on Tuesday")
	}
}

// A skip or a hold says what is wrong with its input, by name.
func TestAHoldOrSkipNamesWhatItsInputIsMissing(t *testing.T) {
	f := newCronHoldFixture(t)
	now := f.at(0, sundayAfter)
	hold := CronHold{Store: f.store, Now: clock(now)}
	until := f.at(tuesday, holdEnds)
	for _, tc := range []struct {
		in   CronHoldInput
		want string
	}{
		{CronHoldInput{App: "site", Workload: "web", Until: until}, "--reason is required"},
		{CronHoldInput{App: "site", Workload: "web", Reason: "moving"}, "--until is required"},
		{CronHoldInput{App: "site", Workload: "web", Until: now.Add(-time.Minute), Reason: "moving"}, "is not in the future"},
		{CronHoldInput{App: "site", Workload: "web", Until: now.Add(15 * 24 * time.Hour), Reason: "moving"}, "a hold may last at most 14 days"},
		{CronHoldInput{App: "nope", Workload: "web", Until: until, Reason: "moving"}, "nope isn't deployed"},
		{CronHoldInput{App: "site", Workload: "nope", Until: until, Reason: "moving"}, "site has no cron workload named nope"},
		{CronHoldInput{App: "site", Workload: "migrate", Until: until, Reason: "moving"}, "site has no cron workload named migrate"},
	} {
		raw, _ := json.Marshal(tc.in)
		if _, err := hold.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("hold %+v: %v, want %q", tc.in, err, tc.want)
		}
	}
	raw, _ := json.Marshal(CronReleaseInput{App: "site", Workload: "web"})
	if _, err := (CronRelease{Store: f.store, Now: clock(now)}).Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "site/web isn't held") {
		t.Errorf("release with no hold: %v", err)
	}
	skip := DrillSkip{Store: f.store, Now: clock(now)}
	for _, tc := range []struct {
		in   DrillSkipInput
		want string
	}{
		{DrillSkipInput{App: "site"}, "--reason is required"},
		{DrillSkipInput{App: "nope", Reason: "resizing"}, "nope isn't deployed"},
		{DrillSkipInput{App: "site", Reason: "resizing"}, "site has no good backup yet"},
	} {
		raw, _ := json.Marshal(tc.in)
		if _, err := skip.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("skip %+v: %v, want %q", tc.in, err, tc.want)
		}
	}
}

// Correction 38: a cron container that outlives its timeout must not keep
// its run open because Docker refused the first removal. The run ends as
// timed out and the container goes, so backups and cron can proceed.
func TestATimedOutJobWhoseRemovalFailsAtFirstStillEndsItsRun(t *testing.T) {
	defer func(d time.Duration) { jobRemoveRetry = d }(jobRemoveRetry)
	jobRemoveRetry = 10 * time.Millisecond
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	w := m.Workloads["web"]
	w.Kind, w.Schedule, w.Timeout = manifest.Cron, "45 4 * * *", "100ms"
	m.Workloads["web"] = w
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, time.Now())
	fake := dockertest.New(t)
	created := make(chan string, 1)
	fake.OnCreate = func(c dockertest.Container) { created <- c.Name }
	var refused atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		if r.Method == http.MethodDelete && strings.Contains(path, "/containers/") && refused.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"removal of container is already in progress"}`))
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	_, err := NewJobs(store, newSecrets(t)).Run(ctx, rev, "web", nil, JobCron, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("the job didn't time out: %v", err)
	}
	name := <-created
	if refused.Load() < 3 {
		t.Fatalf("removal was tried %d times; the fixture refuses the first two", refused.Load())
	}
	if _, exists := fake.Container(name); exists {
		t.Fatal("the timed out container is still there")
	}
	if open := mustOpen(t, store); len(open) != 0 {
		t.Fatalf("the timed out run is still open: %+v", open)
	}
	runs, err := store.JobRuns(ctx, "site", "web", 10)
	if err != nil || len(runs) != 1 || runs[0].Error != "timed out" || runs[0].FinishedAt.IsZero() {
		t.Fatalf("the run didn't end as timed out: %+v, %v", runs, err)
	}
}
