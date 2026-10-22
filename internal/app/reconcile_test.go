package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/state"
)

// jobFixture is Docker as job runs see it: containers by name, with the
// exit code each running one will end with.
type jobFixture struct {
	containers   []docker.Info
	exits        map[string]int
	mu           sync.Mutex // adopted runs settle from their own goroutines
	removed      []string
	inspectError error
}

func (f *jobFixture) Owned(context.Context) ([]docker.Info, error) {
	for i := range f.containers {
		if f.containers[i].ID == "" {
			f.containers[i].ID = f.containers[i].Name
		}
	}
	return f.containers, nil
}
func (f *jobFixture) Inspect(_ context.Context, name string) (*docker.Info, error) {
	if f.inspectError != nil {
		return nil, f.inspectError
	}
	for i := range f.containers {
		if f.containers[i].Name == name || f.containers[i].ID == name {
			return &f.containers[i], nil
		}
	}
	return nil, errdefs.ErrNotFound
}
func (f *jobFixture) WaitExit(ctx context.Context, name string) (int, error) {
	if code, ok := f.exits[name]; ok {
		return code, nil
	}
	<-ctx.Done()
	return -1, ctx.Err()
}
func (f *jobFixture) LogTail(context.Context, string, int) string { return "last words\n" }
func (f *jobFixture) Remove(_ context.Context, name string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name)
	return nil
}

func TestJobRunsADeadDaemonLeftOpenAreSettledAtStart(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	start := func(workload, container string) int64 {
		t.Helper()
		id, err := store.StartJobRun(ctx, state.JobRun{App: "test", Workload: workload, Revision: "r1", Kind: JobCron, StartedAt: t0, Container: container})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	running := start("report", "bedrock-test-report-job-1")
	exited := start("report", "bedrock-test-report-job-2")
	gone := start("report", "bedrock-test-report-job-3")
	unnamed := start("nightly", "")
	done := start("report", "bedrock-test-report-job-5")
	if err := store.FinishJobRun(ctx, done, 0, "", "", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	labels := func(workload string) map[string]string {
		return imageLabels("test", workload, "r1")
	}
	e := &jobFixture{
		containers: []docker.Info{
			{Name: "bedrock-test-report-job-1", Running: true, Labels: labels("report")},
			{Name: "bedrock-test-report-job-2", Running: false, ExitCode: 0, Labels: labels("report")},
			{Name: "bedrock-test-nightly-job-4", Running: true, Labels: labels("nightly")},
		},
		exits: map[string]int{"bedrock-test-report-job-1": 3, "bedrock-test-nightly-job-4": 0},
	}
	now := t0.Add(time.Hour)
	adopted, err := reconcileJobRuns(ctx, store, e, mustOpen(t, store), now, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	adopted.Wait()
	runs := map[int64]state.JobRun{}
	for _, r := range mustRuns(t, store) {
		runs[r.ID] = r
	}
	if r := runs[running]; !r.FinishedAt.After(t0) || r.ExitCode != 3 || r.Error != "exited with code 3" || r.Output != "last words\n" {
		t.Fatalf("the adopted run: %+v", r)
	}
	if r := runs[exited]; !r.FinishedAt.Equal(now) || r.ExitCode != 0 || r.Error != "" {
		t.Fatalf("the exited run: %+v", r)
	}
	if r := runs[gone]; !r.FinishedAt.Equal(now) || r.ExitCode != -1 || r.Error != "interrupted by a daemon restart" {
		t.Fatalf("the run whose container is gone: %+v", r)
	}
	if r := runs[unnamed]; !r.FinishedAt.After(t0) || r.ExitCode != 0 || r.Error != "" {
		t.Fatalf("the unnamed run found by its labels: %+v", r)
	}
	if r := runs[done]; !r.FinishedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("a finished run was touched: %+v", r)
	}
	slices.Sort(e.removed)
	if want := []string{"bedrock-test-nightly-job-4", "bedrock-test-report-job-1", "bedrock-test-report-job-2"}; !slices.Equal(e.removed, want) {
		t.Fatalf("removed %v, want %v", e.removed, want)
	}
	if open := mustOpen(t, store); len(open) != 0 {
		t.Fatalf("still open: %+v", open)
	}
}

func mustOpen(t *testing.T, store *state.Store) []state.JobRun {
	t.Helper()
	open, err := store.OpenJobRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return open
}

func mustRuns(t *testing.T, store *state.Store) []state.JobRun {
	t.Helper()
	runs, err := store.JobRuns(context.Background(), "test", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

func TestJobReconciliationDoesNotMistakeInspectionFailureForADeletedContainer(t *testing.T) {
	for _, problem := range []error{errors.New("Docker is temporarily unavailable"), context.Canceled} {
		t.Run(problem.Error(), func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			if _, err := store.StartJobRun(ctx, state.JobRun{App: "site", Workload: "nightly", Revision: "r1", Kind: JobCron, Container: "still-running", StartedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			e := &jobFixture{inspectError: problem}
			adopted, err := reconcileJobRuns(ctx, store, e, mustOpen(t, store), time.Now(), func(string, ...any) {})
			adopted.Wait()
			if !errors.Is(err, problem) {
				t.Fatalf("inspection error lost: %v", err)
			}
			if open := mustOpen(t, store); len(open) != 1 {
				t.Fatalf("transient inspection retired a running job: %+v", open)
			}
		})
	}
}

func TestStartupJobReconciliationRetriesTransientInspectionWithoutRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := releaseTestStore(t)
	if _, err := store.StartJobRun(ctx, state.JobRun{App: "site", Workload: "nightly", Revision: "r1", Kind: JobCron, Container: "retry-job", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	fake := dockertest.New(t)
	fake.Add(dockertest.Container{Name: "retry-job", Labels: imageLabels("site", "nightly", "r1"), ExitCode: 0})
	var inspections atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		if path == "/containers/retry-job/json" && inspections.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"temporary Docker failure"}`))
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	wait, err := StartJobReconciliation(ctx, store, func(string, ...any) {})
	if err == nil {
		t.Fatal("fixture did not exercise the initial inspection error")
	}
	done := make(chan struct{})
	go func() { wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatal("transient inspection was not retried")
	}
	if open := mustOpen(t, store); len(open) != 0 {
		t.Fatalf("recovered Docker left cron suppressed until another daemon restart: %+v", open)
	}
}

func TestJobReconciliationRefusesAReplacedForeignContainer(t *testing.T) {
	for _, changed := range []string{docker.LabelOwner, docker.LabelApp, docker.LabelWorkload, docker.LabelRevision} {
		t.Run(changed, func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			if _, err := store.StartJobRun(ctx, state.JobRun{App: "site", Workload: "nightly", Revision: "r1", Kind: JobCron, Container: "reused-name", StartedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			labels := imageLabels("site", "nightly", "r1")
			labels[changed] = "foreign"
			e := &jobFixture{containers: []docker.Info{{ID: "foreign-id", Name: "reused-name", Labels: labels}}}
			adopted, err := reconcileJobRuns(ctx, store, e, mustOpen(t, store), time.Now(), func(string, ...any) {})
			adopted.Wait()
			if err == nil || len(e.removed) != 0 || len(mustOpen(t, store)) != 1 {
				t.Fatalf("foreign container was settled or removed: err=%v removed=%v", err, e.removed)
			}
		})
	}
}

func TestJobReconciliationUsesImmutableContainerID(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	if _, err := store.StartJobRun(ctx, state.JobRun{App: "site", Workload: "nightly", Revision: "r1", Kind: JobCron, Container: "reused-name", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	e := &jobFixture{containers: []docker.Info{{ID: "original-id", Name: "reused-name", Labels: imageLabels("site", "nightly", "r1")}}}
	adopted, err := reconcileJobRuns(ctx, store, e, mustOpen(t, store), time.Now(), func(string, ...any) {})
	adopted.Wait()
	if err != nil || !slices.Equal(e.removed, []string{"original-id"}) {
		t.Fatalf("job cleanup followed a mutable name: %v %v", e.removed, err)
	}
}

func TestLegacyJobReconciliationDoesNotAdoptAnotherRevision(t *testing.T) {
	run := state.JobRun{App: "site", Workload: "nightly", Revision: "r1"}
	owned := []docker.Info{{ID: "newer-id", Name: "bedrock-site-nightly-job-newer", Running: true, Labels: imageLabels("site", "nightly", "r2")}}
	if got, err := jobContainerOf(owned, run); got != "" || err != nil {
		t.Fatalf("legacy job adopted newer revision: %s", got)
	}
}

func TestAdoptedCronKeepsItsOriginalWorkloadDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	w := m.Workloads["web"]
	w.Timeout = "10ms"
	m.Workloads["web"] = w
	releaseTestRevision(t, store, m, "r1", state.RevisionActive, time.Now())
	if _, err := store.StartJobRun(ctx, state.JobRun{App: m.App, Workload: "web", Revision: "r1", Kind: JobCron, Container: "still-running", StartedAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	e := &jobFixture{containers: []docker.Info{{ID: "original-id", Name: "still-running", Running: true, Labels: imageLabels(m.App, "web", "r1")}}}
	adopted, err := reconcileJobRuns(ctx, store, e, mustOpen(t, store), time.Now(), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { adopted.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("daemon restart reset the workload deadline")
	}
	runs, err := store.JobRuns(context.Background(), m.App, "web", 1)
	if err != nil || len(runs) != 1 || runs[0].Error != "timed out" || runs[0].FinishedAt.IsZero() || !slices.Equal(e.removed, []string{"original-id"}) {
		t.Fatalf("expired job was not stopped and recorded: %+v %v removed=%v", runs, err, e.removed)
	}
}

func TestAdoptedCronDaemonCancellationKeepsItsRunOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := releaseTestStore(t)
	if _, err := store.StartJobRun(ctx, state.JobRun{App: "site", Workload: "nightly", Revision: "r1", Kind: JobCron, Container: "still-running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	e := &jobFixture{containers: []docker.Info{{ID: "original-id", Name: "still-running", Running: true, Labels: imageLabels("site", "nightly", "r1")}}}
	adopted, err := reconcileJobRuns(ctx, store, e, mustOpen(t, store), time.Now(), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	adopted.Wait()
	if len(mustOpen(t, store)) != 1 || len(e.removed) != 0 {
		t.Fatalf("daemon cancellation settled or removed an unfinished cron: %v", e.removed)
	}
}

func TestAmbiguousLegacyCronContainersKeepTheirRunOpen(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	if _, err := store.StartJobRun(ctx, state.JobRun{App: "test", Workload: "nightly", Revision: "r1", Kind: JobCron, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	e := &jobFixture{containers: []docker.Info{
		{ID: "first-id", Name: "bedrock-test-nightly-job-first", Running: true, Labels: imageLabels("test", "nightly", "r1")},
		{ID: "second-id", Name: "bedrock-test-nightly-job-second", Running: true, Labels: imageLabels("test", "nightly", "r1")},
	}}
	adopted, err := reconcileJobRuns(ctx, store, e, mustOpen(t, store), time.Now(), func(string, ...any) {})
	adopted.Wait()
	if err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("ambiguous writers were treated as a missing container: %v", err)
	}
	if len(mustOpen(t, store)) != 1 || len(e.removed) != 0 {
		t.Fatalf("ambiguous writers lost their overlap guard: open=%+v removed=%v", mustOpen(t, store), e.removed)
	}
}
