package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// jobEngine is what settling a job run needs of Docker.
type jobEngine interface {
	Owned(context.Context) ([]docker.Info, error)
	Inspect(context.Context, string) (*docker.Info, error)
	WaitExit(context.Context, string) (int, error)
	LogTail(context.Context, string, int) string
	Remove(context.Context, string, time.Duration) error
}

// ReconcileJobRuns settles the job runs a daemon that died left open, at
// the next daemon's start. A run whose container still runs is adopted:
// waited for and recorded as if the daemon had never gone. One whose
// container has exited is recorded from what it left behind. One with no
// container is finished as interrupted, so it stops reading as running.
//
// It returns once every run has been looked at; adopted runs are waited
// for in the background, and log says what became of each.
func ReconcileJobRuns(ctx context.Context, store *state.Store, log func(string, ...any)) error {
	wait, err := StartJobReconciliation(ctx, store, log)
	go wait()
	return err
}

// StartJobReconciliation returns a drain function for every adopted tracker.
// The daemon cancels ctx, then waits before closing its state store.
func StartJobReconciliation(ctx context.Context, store *state.Store, log func(string, ...any)) (func(), error) {
	open, err := store.OpenJobRuns(ctx)
	if err != nil || len(open) == 0 {
		return func() {}, err
	}
	e, firstErr := docker.Connect(ctx)
	pending := open
	adopted := &sync.WaitGroup{}
	if firstErr == nil {
		_, unresolved, err := reconcileJobRunBatch(ctx, store, e, open, time.Now().UTC(), log, adopted)
		pending, firstErr = unresolved, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			adopted.Wait()
			if e != nil {
				e.Close()
			}
		}()
		for len(pending) > 0 {
			if !waitJobRetry(ctx) {
				return
			}
			if e == nil {
				var err error
				e, err = docker.Connect(ctx)
				if err != nil {
					log("job reconciliation: %v; retrying", err)
					continue
				}
			}
			_, unresolved, err := reconcileJobRunBatch(ctx, store, e, pending, time.Now().UTC(), log, adopted)
			pending = unresolved
			if err != nil && ctx.Err() == nil {
				log("job reconciliation: %v; retrying", err)
			}
		}
	}()
	return func() { <-done }, firstErr
}

func waitJobRetry(ctx context.Context) bool {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func reconcileJobRuns(ctx context.Context, store *state.Store, e jobEngine, open []state.JobRun, now time.Time, log func(string, ...any)) (*sync.WaitGroup, error) {
	adopted, _, err := reconcileJobRunBatch(ctx, store, e, open, now, log, &sync.WaitGroup{})
	return adopted, err
}

// Retry only unresolved IDs. An adopted container already has one tracker,
// even while its durable run remains open for the scheduler's overlap guard.
func reconcileJobRunBatch(ctx context.Context, store *state.Store, e jobEngine, open []state.JobRun, now time.Time, log func(string, ...any), adopted *sync.WaitGroup) (*sync.WaitGroup, []state.JobRun, error) {
	owned, err := e.Owned(ctx)
	if err != nil {
		return adopted, open, err
	}
	var failures []error
	var pending []state.JobRun
	for _, run := range open {
		name := run.Container
		if name == "" {
			var err error
			name, err = jobContainerOf(owned, run)
			if err != nil {
				failures = append(failures, err)
				pending = append(pending, run)
				continue
			}
		}
		var info *docker.Info
		var inspectErr error
		if name != "" {
			info, inspectErr = e.Inspect(ctx, name)
		}
		switch {
		case name != "" && inspectErr != nil && !docker.IsNotFound(inspectErr):
			failures = append(failures, fmt.Errorf("inspect job %s/%s run %d: %w", run.App, run.Workload, run.ID, inspectErr))
			pending = append(pending, run)
		case name == "" || docker.IsNotFound(inspectErr):
			log("job %s/%s run %d: its container is gone; recorded as interrupted", run.App, run.Workload, run.ID)
			if err := store.FinishJobRun(ctx, run.ID, -1, "interrupted by a daemon restart", "", now); err != nil {
				failures = append(failures, err)
				pending = append(pending, run)
			}
		case !jobContainerMatches(info, run):
			failures = append(failures, fmt.Errorf("job %s/%s run %d: container %s does not match its recorded ownership and revision", run.App, run.Workload, run.ID, name))
			pending = append(pending, run)
		case info.Running:
			deadline, err := adoptedJobDeadline(ctx, store, run)
			if err != nil {
				failures = append(failures, err)
				pending = append(pending, run)
				continue
			}
			name = info.ID
			log("job %s/%s run %d: still running as %s; waiting for it", run.App, run.Workload, run.ID, name)
			adopted.Add(1)
			go func(run state.JobRun, name string) {
				defer adopted.Done()
				runCtx, cancel := context.WithDeadline(ctx, deadline)
				defer cancel()
				var timedOutOutput string
				capturedOutput := false
				for {
					code, err := e.WaitExit(runCtx, name)
					if ctx.Err() != nil {
						return
					}
					if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
						if !capturedOutput {
							cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
							timedOutOutput = e.LogTail(cleanup, name, 40)
							cancel()
							capturedOutput = true
						}
						if err = expireJobRun(store, e, run, name, timedOutOutput, log); err == nil {
							return
						}
					} else if err == nil {
						if err = settleJobRun(store, e, run, name, code, time.Now().UTC(), log); err == nil {
							return
						}
					} else if docker.IsNotFound(err) {
						if err = store.FinishJobRun(ctx, run.ID, -1, "container disappeared after a daemon restart", "", time.Now().UTC()); err == nil {
							return
						}
					}
					log("job %s/%s run %d: %v; retrying", run.App, run.Workload, run.ID, err)
					if !waitJobRetry(ctx) {
						return
					}
				}
			}(run, name)
		default:
			if err := settleJobRun(store, e, run, info.ID, info.ExitCode, now, log); err != nil {
				failures = append(failures, err)
				pending = append(pending, run)
			}
		}
	}
	return adopted, pending, errors.Join(failures...)
}

func adoptedJobDeadline(ctx context.Context, store *state.Store, run state.JobRun) (time.Time, error) {
	rev, err := store.GetRevision(ctx, run.App, run.Revision)
	if errors.Is(err, state.ErrNotFound) {
		return run.StartedAt.Add(defaultJobTimeout), nil
	}
	if err != nil {
		return time.Time{}, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return time.Time{}, fmt.Errorf("job run %d revision manifest: %w", run.ID, err)
	}
	w, ok := m.Workloads[run.Workload]
	if !ok {
		return time.Time{}, fmt.Errorf("job run %d revision has no workload %s", run.ID, run.Workload)
	}
	return run.StartedAt.Add(jobTimeout(w)), nil
}

// A workload deadline must stop its writer before finishing the durable run
// makes the scheduler eligible to start another one. Removal failures retry.
func expireJobRun(store *state.Store, e jobEngine, run state.JobRun, id, output string, log func(string, ...any)) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.Remove(cleanup, id, 5*time.Second); err != nil && !docker.IsNotFound(err) {
		return err
	}
	if err := store.FinishJobRun(cleanup, run.ID, -1, "timed out", output, time.Now().UTC()); err != nil {
		return err
	}
	log("job %s/%s run %d: timed out after the daemon restarted", run.App, run.Workload, run.ID)
	return nil
}

func jobContainerMatches(info *docker.Info, run state.JobRun) bool {
	return info != nil && info.ID != "" && info.Labels[docker.LabelOwner] == docker.OwnerValue &&
		info.Labels[docker.LabelApp] == run.App && info.Labels[docker.LabelWorkload] == run.Workload && info.Labels[docker.LabelRevision] == run.Revision
}

// jobContainerOf finds the one running job container that carries a run's
// app and workload, for a run recorded before the container's name was
// kept. Two candidates mean neither can be called this run's.
func jobContainerOf(owned []docker.Info, run state.JobRun) (string, error) {
	name := ""
	for _, c := range owned {
		if !c.Running || !strings.Contains(c.Name, "-job-") || !jobContainerMatches(&c, run) {
			continue
		}
		if name != "" {
			return "", fmt.Errorf("job %s/%s run %d has multiple matching running containers; inspect them before releasing its overlap guard", run.App, run.Workload, run.ID)
		}
		name = c.ID
	}
	return name, nil
}

// settleJobRun records how a run the daemon lost track of ended and removes
// its container, as RunWith would have.
func settleJobRun(store *state.Store, e jobEngine, run state.JobRun, name string, code int, finished time.Time, log func(string, ...any)) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output := e.LogTail(cleanup, name, 40)
	errText := ""
	if code != 0 {
		errText = fmt.Sprintf("exited with code %d", code)
	}
	if err := store.FinishJobRun(cleanup, run.ID, code, errText, output, finished); err != nil {
		log("job %s/%s run %d: %v", run.App, run.Workload, run.ID, err)
		return err
	}
	_ = e.Remove(cleanup, name, 5*time.Second)
	log("job %s/%s run %d: finished after the daemon restarted (exit %d)", run.App, run.Workload, run.ID, code)
	return nil
}
