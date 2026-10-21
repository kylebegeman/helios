package watch

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// appCondition is what the prober says about hello this round, or "".
func appCondition(t *testing.T, p *Prober) string {
	t.Helper()
	for _, c := range p.Observe(context.Background()) {
		if c.Key == "app:hello" {
			return c.Severity + ": " + c.Message
		}
	}
	return ""
}

func TestTheProberSeesAWorkloadStopRestartAndGo(t *testing.T) {
	fake := dockertest.New(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	manifest := `{"app":"hello","workloads":{"work":{"kind":"worker","image":"x"}}}`
	rev := state.Revision{App: "hello", ID: "r1", Status: state.RevisionActive, Manifest: json.RawMessage(manifest),
		Containers: map[string]string{"work": "bedrock-hello-work-r1"}, CreatedAt: time.Now().UTC()}
	if err := store.SaveRevision(context.Background(), rev); err != nil {
		t.Fatal(err)
	}
	fake.Add(dockertest.Container{Name: "bedrock-edge", Running: true})
	fake.Add(dockertest.Container{Name: "bedrock-hello-work-r1", Running: true})
	p := NewProber(store)
	p.Root = t.TempDir()

	if got := appCondition(t, p); got != "" {
		t.Fatalf("a healthy app has a condition: %q", got)
	}
	fake.Update("bedrock-hello-work-r1", func(c *dockertest.Container) { c.RestartCount = 2 })
	if got := appCondition(t, p); !strings.Contains(got, "work keeps restarting (2 restarts)") {
		t.Fatalf("restarts: %q", got)
	}
	fake.Update("bedrock-hello-work-r1", func(c *dockertest.Container) { c.Running, c.ExitCode = false, 3 })
	if got := appCondition(t, p); !strings.HasPrefix(got, state.SeverityCritical) || !strings.Contains(got, "work isn't running") || !strings.Contains(got, "exit code 3") {
		t.Fatalf("stopped: %q", got)
	}
	fake.Remove("bedrock-hello-work-r1")
	if got := appCondition(t, p); !strings.Contains(got, "work has no container") {
		t.Fatalf("gone: %q", got)
	}
}

func TestTheProberSeesAWorkloadThatCantWriteItsVolumeAndSeesItFixed(t *testing.T) {
	fake := dockertest.New(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	manifest := `{"app":"hello","workloads":{"work":{"kind":"worker","image":"x","mounts":[{"volume":"data","path":"/data"}]}}}`
	rev := state.Revision{App: "hello", ID: "r1", Status: state.RevisionActive, Manifest: json.RawMessage(manifest),
		Containers: map[string]string{"work": "bedrock-hello-work-r1"}, CreatedAt: time.Now().UTC()}
	if err := store.SaveRevision(context.Background(), rev); err != nil {
		t.Fatal(err)
	}
	// The volume holds a database the test's own user owns; the workload
	// runs as someone else, the way a hand copy made by root leaves it.
	volume := t.TempDir()
	db := filepath.Join(volume, "hello.sqlite")
	if err := os.WriteFile(db, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(volume, 0o777); err != nil {
		t.Fatal(err)
	}
	user := fmt.Sprintf("%d:%d", os.Getuid()+1, os.Getgid()+1)
	fake.Add(dockertest.Container{Name: "bedrock-edge", Running: true})
	fake.Add(dockertest.Container{Name: "bedrock-hello-work-r1", Running: true, User: user,
		Mounts: []dockertest.Mount{{Type: "volume", Name: "bedrock-hello-data", Source: volume, Destination: "/data", RW: true}}})
	now := time.Now().UTC()
	p := NewProber(store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return now }

	got := appCondition(t, p)
	want := "work runs as " + user + " and can't write 1 file or directory in volume data, such as hello.sqlite"
	if !strings.HasPrefix(got, state.SeverityCritical) || !strings.Contains(got, want) || !strings.Contains(got, "helios doctor says how") {
		t.Fatalf("unwritable data: %q", got)
	}

	// Fixed by hand: the next rounds reuse the walk until it is due again.
	if err := os.Chmod(db, 0o666); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if got := appCondition(t, p); !strings.Contains(got, want) {
		t.Fatalf("a round inside the hour walks nothing: %q", got)
	}
	now = now.Add(DataCheckEvery)
	if got := appCondition(t, p); got != "" {
		t.Fatalf("fixed and walked again: %q", got)
	}

	// Root, and a user helios didn't set, need no walk.
	for _, u := range []string{"0:0", ""} {
		fake.Update("bedrock-hello-work-r1", func(c *dockertest.Container) { c.User = u })
		if err := os.Chmod(db, 0o644); err != nil {
			t.Fatal(err)
		}
		now = now.Add(DataCheckEvery)
		if got := appCondition(t, p); got != "" {
			t.Fatalf("user %q: %q", u, got)
		}
	}
}

func TestHealthProbeReachesIPv6Containers(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/health" {
			http.NotFound(w, request)
		}
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	info := &docker.Info{IPs: map[string]string{docker.EdgeNetwork: "::1"}}
	workload := manifest.Workload{Kind: manifest.Web, Port: listener.Addr().(*net.TCPAddr).Port, Health: &manifest.Health{Path: "/health"}}
	if problem := healthProblem(context.Background(), info, workload); problem != "" {
		t.Fatalf("healthy IPv6 workload reported unavailable: %s", problem)
	}
}

func TestProberRetiresRestartHistoryForReplacedContainers(t *testing.T) {
	fake := dockertest.New(t)
	w, _ := newWatcher(t, nil)
	ctx := context.Background()
	body := json.RawMessage(`{"app":"hello","workloads":{"work":{"kind":"worker","image":"x"}}}`)
	fake.Add(dockertest.Container{Name: "bedrock-edge", Running: true})
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	for _, id := range []string{"r1", "r2"} {
		container := "bedrock-hello-work-" + id
		fake.Add(dockertest.Container{Name: container, Running: true})
		if err := w.Store.SaveRevision(ctx, state.Revision{App: "hello", ID: id, Status: state.RevisionFailed, Manifest: body, Containers: map[string]string{"work": container}, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := w.Store.Activate(ctx, "hello", id, time.Now()); err != nil {
			t.Fatal(err)
		}
		p.Observe(ctx)
		if len(p.restarts) != 1 {
			t.Fatalf("old container restart history survived deployment: %v", p.restarts)
		}
	}
	if err := w.Store.SetRevisionStatus(ctx, "hello", "r2", state.RevisionFailed); err != nil {
		t.Fatal(err)
	}
	p.Observe(ctx)
	if len(p.restarts) != 0 {
		t.Fatalf("removed app restart history remains: %v", p.restarts)
	}
}

func TestDockerOutageCannotCertifyAppOrEdgeRecovery(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	w.OpenAfter = 1
	body := json.RawMessage(`{"app":"hello","workloads":{"work":{"kind":"worker","image":"x"}}}`)
	if err := w.Store.SaveRevision(ctx, state.Revision{App: "hello", ID: "r1", Status: state.RevisionActive, Manifest: body, CreatedAt: *now}); err != nil {
		t.Fatal(err)
	}
	if err := w.Round(ctx, []Condition{down("hello"), {Key: "host:edge", Subject: "edge", Severity: state.SeverityCritical, Message: "edge is down"}}); err != nil {
		t.Fatal(err)
	}
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	for range 2 {
		*now = now.Add(time.Minute)
		if err := w.Round(ctx, p.Observe(ctx)); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"app:hello", "host:edge"} {
		if open, err := w.Store.OpenIncidentByKey(ctx, key); err != nil || open == nil {
			t.Fatalf("unobserved %s was reported recovered: %+v, %v", key, open, err)
		}
	}
}

// alterState changes the state database behind the store's back, the way
// a damaged row would look to it.
func alterState(t *testing.T, store *state.Store, query string) {
	t.Helper()
	db, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query); err != nil {
		t.Fatal(err)
	}
}

// failingWatch watches a site that answers 503 until it is told to be
// healthy, and returns the watch's incident key.
func failingWatch(t *testing.T, store *state.Store, now time.Time) (string, *atomic.Bool) {
	t.Helper()
	healthy := &atomic.Bool{}
	site := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			response.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(site.Close)
	if err := store.AddWatch(context.Background(), site.URL, now); err != nil {
		t.Fatal(err)
	}
	return "watch:" + site.URL, healthy
}

// toldResolved reports whether a recovery of key was sent.
func toldResolved(notifier *fakeNotifier, key string) bool {
	for _, n := range notifier.sent {
		if n.Key == key && n.Transition == TransitionResolved {
			return true
		}
	}
	return false
}

// A URL watched from the outside doesn't depend on the apps, so a state
// store that can't list their revisions still checks it: a watch that
// still fails stays open, and one that answers again recovers.
func TestUnreadableRevisionsStillCheckWatches(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	fake.Add(dockertest.Container{Name: "bedrock-edge", Running: true})
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	key, healthy := failingWatch(t, w.Store, *now)
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }
	round := func() map[string]Condition {
		t.Helper()
		*now = now.Add(time.Minute)
		conditions := p.Observe(ctx)
		if err := w.Round(ctx, conditions); err != nil {
			t.Fatal(err)
		}
		byKey := map[string]Condition{}
		for _, c := range conditions {
			byKey[c.Key] = c
		}
		return byKey
	}
	for range DefaultOpenAfter {
		round()
	}
	if open, err := w.Store.OpenIncidentByKey(ctx, key); err != nil || open == nil {
		t.Fatalf("a failing watch opened no incident: %v", err)
	}

	body := json.RawMessage(`{"app":"hello","workloads":{"work":{"kind":"worker","image":"x"}}}`)
	if err := w.Store.SaveRevision(ctx, state.Revision{App: "hello", ID: "r1", Status: state.RevisionActive, Manifest: body, CreatedAt: *now}); err != nil {
		t.Fatal(err)
	}
	alterState(t, w.Store, `UPDATE revisions SET containers = 'unreadable' WHERE app = 'hello'`)
	for range DefaultResolveAfter + 1 {
		found := round()
		if _, ok := found["host:state"]; !ok {
			t.Fatalf("the revisions were read: %+v", found)
		}
		if c := found[key]; c.Unknown || c.Severity != state.SeverityCritical {
			t.Fatalf("the watch wasn't checked: %+v", c)
		}
	}
	if open, err := w.Store.OpenIncidentByKey(ctx, key); err != nil || open == nil || toldResolved(notifier, key) {
		t.Fatalf("a watch that still fails was reported recovered: %+v, %v, %+v", open, err, notifier.sent)
	}

	healthy.Store(true)
	for range DefaultResolveAfter {
		round()
	}
	if open, err := w.Store.OpenIncidentByKey(ctx, key); err != nil || open != nil || !toldResolved(notifier, key) {
		t.Fatalf("a watch that answers again didn't recover: %+v, %v, %+v", open, err, notifier.sent)
	}
}

// A watch list that can't be read says nothing about the URLs on it, so
// their incidents are held rather than reported recovered.
func TestUnreadableWatchListHoldsWatchIncidents(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	key, _ := failingWatch(t, w.Store, *now)
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	round := func() []Condition {
		t.Helper()
		*now = now.Add(time.Minute)
		conditions := p.Observe(ctx)
		if err := w.Round(ctx, conditions); err != nil {
			t.Fatal(err)
		}
		var watches []Condition
		for _, c := range conditions {
			if strings.HasPrefix(c.Key, "watch:") {
				watches = append(watches, c)
			}
		}
		return watches
	}
	for range DefaultOpenAfter {
		round()
	}
	if open, err := w.Store.OpenIncidentByKey(ctx, key); err != nil || open == nil {
		t.Fatalf("a failing watch opened no incident: %v", err)
	}

	alterState(t, w.Store, `UPDATE watches SET added_at = 'unreadable'`)
	if _, err := w.Store.Watches(ctx); err == nil {
		t.Fatal("the watch list can still be read")
	}
	for range DefaultResolveAfter + 1 {
		if found := round(); len(found) != 1 || found[0].Key != key || !found[0].Unknown {
			t.Fatalf("the watch's incident wasn't held: %+v", found)
		}
	}
	if open, err := w.Store.OpenIncidentByKey(ctx, key); err != nil || open == nil || toldResolved(notifier, key) {
		t.Fatalf("a watch nobody could check was reported recovered: %+v, %v, %+v", open, err, notifier.sent)
	}
}

func TestAnOperationLockHeldTooLongRaisesAnAlertUntilReleased(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	unlock, err := api.LockOperations(ctx, w.Store.Path())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			unlock()
		}
	}()
	if err := w.Store.CreateOperation(ctx, state.NewOperation{ID: "op-backup", Kind: "backup", Target: "bedrock", Input: json.RawMessage(`{}`), Plan: json.RawMessage(`[]`), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	lock, held, err := api.HeldOperationLock(w.Store.Path())
	if err != nil || !held {
		t.Fatalf("lock: %v %v", held, err)
	}
	*now = lock.AcquiredAt.Add(time.Hour)
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	p.OperationLockStale = 2 * time.Hour
	lockConditions := func() []Condition {
		var out []Condition
		for _, c := range p.Observe(ctx) {
			if c.Key == "host:operations" {
				out = append(out, c)
			}
		}
		return out
	}
	if found := lockConditions(); len(found) != 0 {
		t.Fatalf("an operation inside the limit is not a problem: %+v", found)
	}

	*now = lock.AcquiredAt.Add(3 * time.Hour)
	for range DefaultOpenAfter {
		*now = now.Add(time.Minute)
		if err := w.Round(ctx, p.Observe(ctx)); err != nil {
			t.Fatal(err)
		}
	}
	open, err := w.Store.OpenIncidentByKey(ctx, "host:operations")
	if err != nil || open == nil {
		t.Fatalf("a stuck operation lock raised no incident: %v", err)
	}
	if !strings.Contains(open.Message, "held for 3.0 h") || !strings.Contains(open.Message, "backup bedrock (op-backup)") || !strings.Contains(open.Message, "wait until it is released") {
		t.Fatalf("the alert must say how long and by what: %q", open.Message)
	}
	sent := false
	for _, n := range notifier.sent {
		if strings.Contains(n.Subject, "machine operations has a problem") {
			sent = true
		}
	}
	if !sent {
		t.Fatalf("no one was told: %+v", notifier.sent)
	}

	unlock()
	released = true
	if found := lockConditions(); len(found) != 0 {
		t.Fatalf("a released lock is still reported: %+v", found)
	}
	for range DefaultResolveAfter {
		*now = now.Add(time.Minute)
		if err := w.Round(ctx, p.Observe(ctx)); err != nil {
			t.Fatal(err)
		}
	}
	if open, err := w.Store.OpenIncidentByKey(ctx, "host:operations"); err != nil || open != nil {
		t.Fatalf("the incident did not resolve after the lock was released: %+v %v", open, err)
	}
}

func TestAnUndatedOperationLockIsNeverJudged(t *testing.T) {
	ctx := context.Background()
	w, _ := newWatcher(t, &fakeNotifier{})
	if err := os.MkdirAll(filepath.Join(filepath.Dir(w.Store.Path()), "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Releases before 0.7.11 lock the file without saying since when, as
	// does a holder between taking the lock and writing its record.
	f, err := os.OpenFile(filepath.Join(filepath.Dir(w.Store.Path()), "locks", "operations.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return time.Now().Add(100 * OperationLockStale) }
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	for _, c := range p.Observe(ctx) {
		if c.Key == "host:operations" {
			t.Fatalf("an undated lock was judged: %+v", c)
		}
	}
}

func TestRetentionDeferredOnEveryBackupForTooLongIsAProblem(t *testing.T) {
	ctx := context.Background()
	w, _ := newWatcher(t, &fakeNotifier{})
	start := time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC)
	record := func(day int, detail string, ok bool) {
		t.Helper()
		at := start.Add(time.Duration(day) * 24 * time.Hour)
		id, err := w.Store.StartBackupRun(ctx, manifest.ReservedApp, state.BackupRunBackup, at)
		if err != nil {
			t.Fatal(err)
		}
		run := state.BackupRun{FinishedAt: at.Add(time.Hour), OK: ok, Snapshot: strings.Repeat("a", 64), Detail: detail}
		if !ok {
			run.Error = "upload failed"
		}
		if err := w.Store.FinishBackupRun(ctx, id, run); err != nil {
			t.Fatal(err)
		}
	}
	deferred := func(why string) string { return "3 files; " + app.RetentionDeferred + ": " + why }
	record(0, "3 files", true)
	record(1, deferred("restic prune did not finish within 1h0m0s and was stopped"), true)
	record(2, "", false)
	record(3, deferred("restic prune did not finish within 1h0m0s and was stopped"), true)
	record(4, deferred("repository is already locked exclusively"), true)

	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	retention := func(now time.Time) []Condition {
		p.Now = func() time.Time { return now }
		var out []Condition
		for _, c := range p.Observe(ctx) {
			if c.Key == "host:backup-retention" {
				out = append(out, c)
			}
		}
		return out
	}
	// The streak began on day 1; a failed run in between neither ends nor
	// restarts it.
	if found := retention(start.Add(24*time.Hour + RetentionDeferredStale - time.Minute)); len(found) != 0 {
		t.Fatalf("a short run of deferrals is not yet a problem: %+v", found)
	}
	found := retention(start.Add(24*time.Hour + RetentionDeferredStale + time.Minute))
	if len(found) != 1 || found[0].Subject != "machine backups" || !strings.Contains(found[0].Message, "since 2026-10-11 03:00") || !strings.Contains(found[0].Message, "already locked exclusively") {
		t.Fatalf("retention deferred for days must be reported with its last reason: %+v", found)
	}
	if why := p.retentionProblem(ctx, "elsewhere", start.Add(30*24*time.Hour)); why != "" {
		t.Fatalf("another app's deferrals were counted: %q", why)
	}

	// Retention that completes clears it.
	record(5, "3 files", true)
	if found := retention(start.Add(30 * 24 * time.Hour)); len(found) != 0 {
		t.Fatalf("completed retention is still reported: %+v", found)
	}
}

func TestAMachineWithoutAGoodBackupForADayAndAHalfIsAWarning(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	// run is one machine backup that started ago before now; an hour
	// later it finished unless running, with err when it failed, or
	// failed with no error recorded.
	type run struct {
		ago     time.Duration
		running bool
		err     string
		failed  bool
	}
	machineBackup := func(runs ...run) []Condition {
		t.Helper()
		w, _ := newWatcher(t, &fakeNotifier{})
		for _, r := range runs {
			at := now.Add(-r.ago)
			id, err := w.Store.StartBackupRun(ctx, manifest.ReservedApp, state.BackupRunBackup, at)
			if err != nil {
				t.Fatal(err)
			}
			if r.running {
				continue
			}
			if err := w.Store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: at.Add(time.Hour), OK: r.err == "" && !r.failed, Error: r.err}); err != nil {
				t.Fatal(err)
			}
		}
		p := NewProber(w.Store)
		p.Root = t.TempDir()
		p.Now = func() time.Time { return now }
		p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
		var out []Condition
		for _, c := range p.Observe(ctx) {
			if c.Key == "host:machine-backup" {
				out = append(out, c)
			}
		}
		return out
	}
	const refused = "copy the pinned app data into the machine backup: restoring needs 54.2 GB plus a 15.0 GB reserve; free space and back up the machine again\nrestic output the alert leaves out"

	// Machine backups wait for storage, so a machine that never tried one
	// has nothing to say yet.
	if found := machineBackup(); len(found) != 0 {
		t.Fatalf("a machine that never tried a backup is warned: %+v", found)
	}
	if found := machineBackup(run{ago: 10 * time.Hour}); len(found) != 0 {
		t.Fatalf("a good machine backup 10 hours ago is warned: %+v", found)
	}
	// A backup counts from when it started, as an app's does, so one that
	// finished within the day and a half but started before it is stale.
	if found := machineBackup(run{ago: BackupStale}); len(found) != 0 {
		t.Fatalf("a good machine backup that started a day and a half ago is warned: %+v", found)
	}
	found := machineBackup(run{ago: BackupStale + time.Minute})
	if len(found) != 1 || found[0].Message != "no successful machine backup for 36.0 h (the last was 2026-10-18 23:59)" {
		t.Fatalf("a good machine backup that started over a day and a half ago must be a warning: %+v", found)
	}
	found = machineBackup(run{ago: 40 * time.Hour}, run{ago: 16 * time.Hour, err: refused})
	want := "no successful machine backup for 40.0 h (the last was 2026-10-18 20:00); the last one, started 2026-10-19 20:00, failed: copy the pinned app data into the machine backup: restoring needs 54.2 GB plus a 15.0 GB reserve; free space and back up the machine again"
	if len(found) != 1 || found[0].Subject != "machine backups" || found[0].Severity != state.SeverityWarning || found[0].Message != want {
		t.Fatalf("a machine backup 40 hours stale must be a warning that says why the last one failed: %+v", found)
	}
	found = machineBackup(run{ago: 3 * time.Hour, err: refused})
	if len(found) != 1 || !strings.HasPrefix(found[0].Message, "no machine backup has succeeded yet; the last one, started 2026-10-20 09:00, failed: copy the pinned app data") {
		t.Fatalf("a machine whose only backup failed must be warned: %+v", found)
	}
	// A failure that recorded no error has nothing to quote.
	found = machineBackup(run{ago: 3 * time.Hour, failed: true})
	if len(found) != 1 || found[0].Message != "no machine backup has succeeded yet" {
		t.Fatalf("a machine backup that failed without an error must be a warning that quotes nothing: %+v", found)
	}
	if found := machineBackup(run{ago: 30 * time.Minute, running: true}); len(found) != 0 {
		t.Fatalf("a first machine backup still running is warned: %+v", found)
	}
	// A retry that hasn't finished yet has fixed nothing, so the warning
	// stays rather than resolving as a recovery while it runs.
	found = machineBackup(run{ago: 27 * time.Hour, err: refused}, run{ago: 30 * time.Minute, running: true})
	if len(found) != 1 || !strings.HasPrefix(found[0].Message, "no machine backup has succeeded yet; the last one, started 2026-10-19 09:00, failed:") {
		t.Fatalf("a failed machine backup must stay a warning while the next one runs: %+v", found)
	}
}

func TestARecoveredMachineCountsADayAndAHalfFromItsRecovery(t *testing.T) {
	ctx := context.Background()
	const refused = "copy the pinned app data into the machine backup: restoring needs 54.2 GB plus a 15.0 GB reserve; free space and back up the machine again"
	// recovered imports a machine backup taken two hours ago into a new
	// machine. Its state store holds that backup's own run still open, as
	// every machine backup's does. With good, the source's backup before
	// it succeeded that long before, and started at goodAt.
	recovered := func(t *testing.T, good time.Duration) (store *state.Store, imported, goodAt time.Time) {
		t.Helper()
		taken := time.Now().UTC().Add(-2 * time.Hour)
		path := filepath.Join(t.TempDir(), "source.db")
		source, err := state.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if good != 0 {
			goodAt = taken.Add(-good).Truncate(time.Millisecond)
			id, err := source.StartBackupRun(ctx, manifest.ReservedApp, state.BackupRunBackup, goodAt)
			if err != nil {
				t.Fatal(err)
			}
			if err := source.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: goodAt.Add(time.Hour), OK: true}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := source.StartBackupRun(ctx, manifest.ReservedApp, state.BackupRunBackup, taken); err != nil {
			t.Fatal(err)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		w, _ := newWatcher(t, &fakeNotifier{})
		if err := w.Store.ImportMachineRecovery(ctx, path, "recovery-1", nil, nil); err != nil {
			t.Fatal(err)
		}
		imported, err = w.Store.LastMachineRecoveryImportedAt(ctx)
		if err != nil || imported.IsZero() {
			t.Fatalf("the recovery's import time is %v: %v", imported, err)
		}
		return w.Store, imported, goodAt
	}
	warning := func(t *testing.T, store *state.Store, now time.Time) string {
		t.Helper()
		p := NewProber(store)
		p.Root = t.TempDir()
		p.Now = func() time.Time { return now }
		p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
		for _, c := range p.Observe(ctx) {
			if c.Key == "host:machine-backup" {
				return c.Message
			}
		}
		return ""
	}
	for _, tc := range []struct {
		name string
		good time.Duration
	}{
		{"after a good backup on the source", 72 * time.Hour},
		{"after a good backup on the source that morning", 10 * time.Hour},
		{"from the source's first machine backup", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, imported, goodAt := recovered(t, tc.good)
			// The backup that captured the machine is recorded as
			// interrupted on the source, which is no failure here.
			if found := warning(t, store, imported.Add(time.Hour)); found != "" {
				t.Fatalf("a machine recovered an hour ago is warned about the backup it was recovered from: %q", found)
			}
			if found := warning(t, store, imported.Add(BackupStale)); found != "" {
				t.Fatalf("a machine recovered a day and a half ago is warned: %q", found)
			}
			if found := warning(t, store, imported.Add(BackupStale+time.Minute)); found == "" {
				t.Fatal("a machine without a backup for over a day and a half since its recovery isn't warned")
			}
			id, err := store.StartBackupRun(ctx, manifest.ReservedApp, state.BackupRunBackup, imported.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if found := warning(t, store, imported.Add(2*time.Hour)); found != "" {
				t.Fatalf("a recovered machine whose first backup is still running is warned: %q", found)
			}
			// A backup that fails here is this machine's own failure, and
			// it ends the grace. It is told at once unless the backup good
			// on the source is still fresh, which keeps the warning quiet
			// until it is a day and a half old, as on any machine.
			if err := store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: imported.Add(2 * time.Hour), Error: refused}); err != nil {
				t.Fatal(err)
			}
			told := imported.Add(3 * time.Hour)
			if fresh := goodAt.Add(BackupStale); fresh.After(told) {
				if found := warning(t, store, told); found != "" {
					t.Fatalf("a failure was told while the source's good backup is fresh: %q", found)
				}
				if found := warning(t, store, fresh); found != "" {
					t.Fatalf("a failure was told while the source's good backup is a day and a half old: %q", found)
				}
				told = fresh.Add(time.Minute)
			}
			if found := warning(t, store, told); !strings.HasSuffix(found, "failed: "+refused) {
				t.Fatalf("a recovered machine whose first backup failed must be warned with why: %q", found)
			}
		})
	}
}
