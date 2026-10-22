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

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

func TestQueuedJobsRefuseARevisionThatIsNoLongerActive(t *testing.T) {
	for _, kind := range []string{JobCron, JobRun} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			m := releaseTestManifest()
			old := releaseTestRevision(t, store, m, "old-revision", state.RevisionRetired, time.Now().Add(-time.Hour))
			releaseTestRevision(t, store, m, "new-revision", state.RevisionActive, time.Now())
			fake := dockertest.New(t)
			fake.OnCreate = func(c dockertest.Container) { fake.Update(c.Name, func(c *dockertest.Container) { c.ExitAfter = 1 }) }
			_, err := NewJobs(store, newSecrets(t)).Run(ctx, old, "web", nil, kind, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "no longer active") {
				t.Fatalf("queued %s started stale code: %v", kind, err)
			}
			runs, err := store.JobRuns(ctx, m.App, "", 10)
			if err != nil || len(runs) != 0 {
				t.Fatalf("stale job was recorded or started: %+v %v", runs, err)
			}
		})
	}
}

func TestInterruptedOneOffCommandIsNeverAutomaticallyReplayed(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	at := time.Now().UTC()
	releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, at)
	definition := RunDefinition{Jobs: NewJobs(store, newSecrets(t))}
	registry := kernel.Registry{}
	registry.Add(definition)
	engine := kernel.New(store, registry, "old-daemon", kernel.WithClock(func() time.Time { return at }))
	raw := json.RawMessage(`{"app":"site","workload":"web","command":["charge-customer"]}`)
	view, err := engine.PlanOnly(ctx, RunKind, raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(view)
	if err := store.CreateOperation(ctx, state.NewOperation{ID: "op-command", Kind: RunKind, Target: view.Target, Input: raw, Plan: encoded, PlanDigest: view.Digest, Recovery: string(view.Recovery), StepNames: []string{"run"}, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, "op-command", "old-daemon", at, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.StepStarted(ctx, "op-command", 0, at); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	recovered := kernel.New(store, registry, "new-daemon", kernel.WithClock(func() time.Time { return at.Add(2 * time.Minute) }))
	if _, err := recovered.Recover(ctx, func(kernel.Event) {}); err != nil {
		t.Fatal(err)
	}
	receipt, err := recovered.ReceiptOf(ctx, "op-command")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "not replayed automatically") {
		t.Fatalf("uncertain arbitrary command was replayed: %+v", receipt)
	}
}

func TestCronDoesNotOverlapAnAdoptedRunAfterDaemonRestart(t *testing.T) {
	for _, newerFinished := range []bool{false, true} {
		t.Run(map[bool]string{false: "latest-open", true: "older-open"}[newerFinished], func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			m := releaseTestManifest()
			w := m.Workloads["web"]
			w.Kind, w.Schedule = "cron", "* * * * *"
			m.Workloads["web"] = w
			now := time.Now().UTC()
			rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, now.Add(-2*time.Hour))
			if _, err := store.StartJobRun(ctx, state.JobRun{App: m.App, Workload: "web", Revision: rev.ID, Kind: JobCron, StartedAt: now.Add(-time.Hour), Container: "adopted-job"}); err != nil {
				t.Fatal(err)
			}
			if newerFinished {
				id, err := store.StartJobRun(ctx, state.JobRun{App: m.App, Workload: "web", Revision: rev.ID, Kind: JobRun, StartedAt: now.Add(-30 * time.Minute)})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.FinishJobRun(ctx, id, 0, "", "", now.Add(-29*time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			unlock, err := lockAppData(ctx, store.Path(), m.App, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
			jobs := NewJobs(store, newSecrets(t))
			done := make(chan struct{}, 1)
			jobs.Tick(ctx, now, func(string, ...any) { done <- struct{}{} })
			jobs.mu.Lock()
			started := jobs.running[m.App+"/web"]
			jobs.mu.Unlock()
			unlock()
			if started {
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("unexpected job did not stop")
				}
				t.Fatal("new scheduler overlapped the cron container being adopted by reconciliation")
			}
		})
	}
}

func TestCronCancellationLeavesTheRunningContainerForReconciliation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, time.Now())
	fake := dockertest.New(t)
	created := make(chan string, 1)
	fake.OnCreate = func(c dockertest.Container) { created <- c.Name }
	done := make(chan error, 1)
	go func() {
		_, err := NewJobs(store, newSecrets(t)).Run(ctx, rev, "web", nil, JobCron, io.Discard)
		done <- err
	}()
	var name string
	select {
	case name = <-created:
	case <-time.After(3 * time.Second):
		t.Fatal("cron container did not start")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, exists := fake.Container(name)
		if exists && c.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cron container did not become running")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled tracker did not stop")
	}
	c, exists := fake.Container(name)
	if !exists || !c.Running {
		t.Fatal("daemon cancellation removed the still-running cron container")
	}
	open, err := store.OpenJobRuns(context.Background())
	if err != nil || len(open) != 1 || open[0].Container != name {
		t.Fatalf("daemon cancellation lost the durable adopted run: %+v %v", open, err)
	}
}

func TestCronDaemonDeadlineLeavesTheRunningContainerForReconciliation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, time.Now())
	fake := dockertest.New(t)
	created := make(chan string, 1)
	fake.OnCreate = func(c dockertest.Container) { created <- c.Name }
	done := make(chan error, 1)
	go func() {
		_, err := NewJobs(store, newSecrets(t)).Run(ctx, rev, "web", nil, JobCron, io.Discard)
		done <- err
	}()
	var name string
	select {
	case name = <-created:
	case <-time.After(3 * time.Second):
		t.Fatal("cron container did not start")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, exists := fake.Container(name)
		if exists && c.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cron container did not become running")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled tracker did not stop")
	}
	c, exists := fake.Container(name)
	if !exists || !c.Running {
		t.Fatal("daemon cancellation removed the still-running cron container")
	}
	open, err := store.OpenJobRuns(context.Background())
	if err != nil || len(open) != 1 || open[0].Container != name {
		t.Fatalf("daemon cancellation lost the durable adopted run: %+v %v", open, err)
	}
}

func TestJobCleanupDoesNotRemoveAForeignContainerRejectedAtStart(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, time.Now())
	fake := dockertest.New(t)
	var removed atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		if strings.Contains(path, "-job-") {
			if r.Method == http.MethodDelete {
				removed.Add(1)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if strings.HasSuffix(path, "/json") {
				json.NewEncoder(w).Encode(map[string]any{"Id": "foreign-id", "Name": "/foreign-job", "State": map[string]any{"Running": true}, "Config": map[string]any{"Labels": map[string]string{docker.LabelOwner: "someone-else"}}, "NetworkSettings": map[string]any{"Networks": map[string]any{}}})
				return
			}
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	_, err := NewJobs(store, newSecrets(t)).Run(ctx, rev, "web", nil, JobRun, io.Discard)
	if err == nil || removed.Load() != 0 {
		t.Fatalf("failed job removed a foreign container: %v removes=%d", err, removed.Load())
	}
}

func TestConcurrentJobsHaveDistinctContainerNames(t *testing.T) {
	m := releaseTestManifest()
	seen := map[string]bool{}
	for range 100 {
		spec, err := jobSpec(m, "r1", "web", m.Workloads["web"], "image", nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[spec.Name] {
			t.Fatalf("two jobs share container name %s", spec.Name)
		}
		seen[spec.Name] = true
	}
}

func TestJobInspectionFailureKeepsTheUnknownWriterForReconciliation(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, time.Now())
	fake := dockertest.New(t)
	created := make(chan string, 1)
	fake.OnCreate = func(c dockertest.Container) { created <- c.Name }
	var inspections atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v"+dockertest.APIVersion)
		if strings.Contains(path, "-job-") && strings.HasSuffix(path, "/json") && inspections.Add(1) == 2 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"temporary inspection failure after start"}`))
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	_, err := NewJobs(store, newSecrets(t)).Run(ctx, rev, "web", nil, JobCron, io.Discard)
	if err == nil {
		t.Fatal("fixture did not fail the ownership inspection")
	}
	var name string
	select {
	case name = <-created:
	default:
		t.Fatal("fixture did not start the job")
	}
	container, ok := fake.Container(name)
	if !ok || !container.Running || len(mustOpen(t, store)) != 1 {
		t.Fatalf("unresolved writer lost its durable open run: container=%+v open=%+v", container, mustOpen(t, store))
	}
	fake.Update(name, func(c *dockertest.Container) { c.Running = false; c.ExitCode = 0 })
	wait, err := StartJobReconciliation(ctx, store, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	wait()
	if len(mustOpen(t, store)) != 0 {
		t.Fatal("later reconciliation could not settle the preserved unknown writer")
	}
}

func TestQueuedCronHonorsAHoldPlacedWhileWaitingForDataAccess(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	w := m.Workloads["web"]
	w.Kind, w.Schedule = "cron", "* * * * *"
	m.Workloads["web"] = w
	now := time.Now().UTC()
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, now.Add(-2*time.Hour))
	fake := dockertest.New(t)
	fake.OnCreate = func(c dockertest.Container) { fake.Update(c.Name, func(c *dockertest.Container) { c.ExitAfter = 1 }) }
	unlock, err := lockAppData(ctx, store.Path(), m.App, true)
	if err != nil {
		t.Fatal(err)
	}
	jobs := NewJobs(store, newSecrets(t))
	jobs.Tick(ctx, now, func(string, ...any) {})
	jobs.mu.Lock()
	queued := jobs.running[m.App+"/web"]
	jobs.mu.Unlock()
	if !queued {
		unlock()
		t.Fatal("fixture did not queue a due cron run")
	}
	_, err = store.HoldJob(ctx, m.App, "web", rev.ID, now, now.Add(time.Hour), "maintenance")
	unlock()
	jobs.Wait()
	if err != nil {
		t.Fatal(err)
	}
	runs, err := store.JobRuns(ctx, m.App, "web", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.Kind == JobCron {
			t.Fatalf("a queued cron started after its workload was held: %+v", run)
		}
	}
}

func TestJobDeadlineDuringStartupIsRecordedAsTimedOut(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	w := m.Workloads["web"]
	w.Timeout = "40ms"
	m.Workloads["web"] = w
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, time.Now())
	fake := dockertest.New(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/start") {
			<-r.Context().Done()
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(proxy.URL, "http"))
	_, err := NewJobs(store, newSecrets(t)).Run(ctx, rev, "web", nil, JobRun, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("startup deadline was not reported as a job timeout: %v", err)
	}
	runs, err := store.JobRuns(ctx, m.App, "web", 1)
	if err != nil || len(runs) != 1 || runs[0].Error != "timed out" || runs[0].FinishedAt.IsZero() {
		t.Fatalf("startup deadline lost its timeout receipt: %+v %v", runs, err)
	}
	if len(mustOpen(t, store)) != 0 {
		t.Fatal("timed out startup kept the run open after cleanup")
	}
}
