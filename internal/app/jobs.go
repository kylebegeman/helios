package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// RunKind runs a one-off command in a workload's environment.
const RunKind = "app.run"

// Job kinds as job_runs records them.
const (
	JobCron    = "cron"
	JobRun     = "run"
	JobRelease = "release"
)

// Jobs runs cron workloads and one-off commands.
type Jobs struct {
	Store   *state.Store
	Secrets *secrets.Store
	mu      sync.Mutex
	running map[string]bool
	waiting sync.WaitGroup
}

// NewJobs returns a job runner.
func NewJobs(store *state.Store, sec *secrets.Store) *Jobs {
	return &Jobs{Store: store, Secrets: sec, running: map[string]bool{}}
}

// JobOptions are what a one-off command adds to its workload's setup.
type JobOptions struct {
	// Secrets are more of the app's secrets for the command, beyond the
	// workload's own.
	Secrets []string
	// Stdin is copied to the command's standard input, and never
	// recorded anywhere.
	Stdin io.Reader
}

// Run executes one job: a container from the workload's image with the
// revision's environment, secrets and mounts, waited for and removed.
// Output streams to out; the last lines and the exit code are recorded.
func (j *Jobs) Run(ctx context.Context, rev *state.Revision, workload string, command []string, kind string, out io.Writer) (int, error) {
	return j.RunWith(ctx, rev, workload, command, kind, JobOptions{}, out)
}

// RunWith is Run with more secrets or a standard input.
func (j *Jobs) RunWith(ctx context.Context, rev *state.Revision, workload string, command []string, kind string, opts JobOptions, out io.Writer) (int, error) {
	unlock, err := AcquireDataAccess(ctx, j.Store.Path(), rev.App)
	if err != nil {
		return -1, err
	}
	defer unlock()
	// A cron tick or approved command may have waited behind a backup or
	// checkpoint restore. Never admit its captured older code to newer data.
	if kind == JobCron || kind == JobRun {
		active, err := j.Store.RevisionWithStatus(ctx, rev.App, state.RevisionActive)
		if err != nil {
			return -1, err
		}
		if active == nil || active.ID != rev.ID {
			return -1, fmt.Errorf("revision %s of %s is no longer active; review the command against the active revision", rev.ID, rev.App)
		}
	}
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return -1, err
	}
	w, ok := m.Workloads[workload]
	if !ok {
		return -1, fmt.Errorf("%s has no workload named %s", rev.App, workload)
	}
	image := rev.Images[workload]
	if image == "" {
		return -1, fmt.Errorf("no image recorded for %s", workload)
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return -1, err
	}
	defer e.Close()
	values, err := j.Secrets.Load(rev.App, rev.SecretsVersion)
	if err != nil {
		return -1, err
	}
	spec, err := jobSpec(&m, rev.ID, workload, w, image, values)
	if err != nil {
		return -1, err
	}
	for _, name := range opts.Secrets {
		v, ok := values[name]
		if !ok {
			return -1, fmt.Errorf("%s has no secret named %s", rev.App, name)
		}
		spec.Env = append(spec.Env, name+"="+v)
	}
	spec.Stdin = opts.Stdin
	if len(command) > 0 {
		spec.Cmd = command
	}
	u, err := isolate(ctx, e, &spec, w, image)
	if err != nil {
		return -1, err
	}
	if kind == JobRelease {
		// A release runs before the start step readies the volumes.
		if err := ownVolumes(ctx, e, &m, w, u, out); err != nil {
			return -1, err
		}
	}
	if kind == JobRun {
		// A one-off command is the operator's: it may write where it
		// likes, and is gone when it ends.
		spec.ReadOnly = false
	}
	started := time.Now().UTC()
	id, err := j.Store.StartJobRun(ctx, state.JobRun{App: rev.App, Workload: workload, Revision: rev.ID, Kind: kind, StartedAt: started, Container: spec.Name})
	if err != nil {
		return -1, err
	}
	runCtx, cancel := context.WithTimeout(ctx, jobTimeout(w))
	defer cancel()
	code, containerID, runErr := j.executeOwned(runCtx, e, spec, out)
	if kind == JobCron && ctx.Err() != nil {
		// The daemon is leaving, but Docker can finish this cron container.
		// Keep its open run so the next daemon adopts it without replaying.
		return code, runErr
	}
	if errors.Is(runErr, errJobOwnershipUnknown) {
		// Docker may have started a writer whose ID could not be inspected.
		// Preserve the durable guard until reconciliation verifies its outcome.
		return code, runErr
	}
	// Removal and the record use fresh contexts: the job's may have ended.
	output := ""
	if containerID != "" {
		tail, cancelTail := context.WithTimeout(context.Background(), 30*time.Second)
		output = e.LogTail(tail, containerID, 40)
		cancelTail()
		if code < 0 {
			// An uncertain or timed out job may still write. Keep the run open
			// until its exact container is stopped, so cron cannot overlap it.
			if err := removeUncertainJob(ctx, e, containerID); err != nil {
				return code, errors.Join(runErr, err)
			}
		}
	}
	cleanup, cancelCleanup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelCleanup()
	errText := ""
	if runErr != nil {
		errText = runErr.Error()
	}
	if err := j.Store.FinishJobRun(cleanup, id, code, errText, output, time.Now().UTC()); err != nil {
		return code, err
	}
	if containerID != "" && code >= 0 {
		_ = e.Remove(cleanup, containerID, 5*time.Second)
	}
	return code, runErr
}

const defaultJobTimeout = time.Hour

// jobRemoveRetry is how long a job that timed out waits between attempts
// to remove a container Docker wouldn't remove.
var jobRemoveRetry = 5 * time.Second

// removeUncertainJob removes the container of a job that timed out or
// whose outcome is unknown, retrying while Docker refuses. Giving up after
// one refusal would leave the run open with no one to finish it: listed as
// running, holding cron off and failing every backup. Only the caller's
// cancellation stops the retries; the open run is then the next daemon's
// to reconcile, against the same deadline.
func removeUncertainJob(ctx context.Context, e *docker.Engine, id string) error {
	for {
		attempt, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := e.Remove(attempt, id, 5*time.Second)
		cancel()
		if err == nil || docker.IsNotFound(err) {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(jobRemoveRetry):
		}
	}
}

func jobTimeout(w manifest.Workload) time.Duration {
	if w.Timeout != "" {
		if timeout, err := time.ParseDuration(w.Timeout); err == nil && timeout > 0 {
			return timeout
		}
	}
	return defaultJobTimeout
}

func (j *Jobs) execute(ctx context.Context, e *docker.Engine, spec docker.Spec, out io.Writer) (int, error) {
	code, _, err := j.executeOwned(ctx, e, spec, out)
	return code, err
}

var errJobOwnershipUnknown = errors.New("the job container could not be identified; inspect helios jobs before rerunning")

func (j *Jobs) executeOwned(ctx context.Context, e *docker.Engine, spec docker.Spec, out io.Writer) (int, string, error) {
	runErr := e.Run(ctx, spec)
	// Run can fail after creation, or refuse an existing foreign container.
	// Inspect with a cleanup context even when the caller was cancelled, and
	// retain an immutable ID only when every requested ownership label matches.
	inspection, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	info, inspectErr := e.Inspect(inspection, spec.Name)
	cancel()
	if inspectErr != nil {
		if !docker.IsNotFound(inspectErr) {
			return -1, "", errors.Join(errJobOwnershipUnknown, runErr, inspectErr)
		}
		return -1, "", errors.Join(runErr, inspectErr)
	}
	expected := state.JobRun{App: spec.Labels[docker.LabelApp], Workload: spec.Labels[docker.LabelWorkload], Revision: spec.Labels[docker.LabelRevision]}
	if !jobContainerMatches(info, expected) {
		mismatch := errors.New("job container does not match its requested ownership and revision")
		if runErr == nil {
			mismatch = errors.Join(errJobOwnershipUnknown, mismatch)
		}
		return -1, "", errors.Join(runErr, mismatch)
	}
	for name, value := range spec.Labels {
		if info.Labels[name] != value {
			mismatch := fmt.Errorf("job container has another %s identity", name)
			if runErr == nil {
				mismatch = errors.Join(errJobOwnershipUnknown, mismatch)
			}
			return -1, "", errors.Join(runErr, mismatch)
		}
	}
	if runErr != nil {
		return -1, info.ID, runErr
	}
	id := info.ID
	// The log copy may outlive the wait by a moment; once the job is done
	// it writes nowhere, so the step's output is never written after it ends.
	guarded := &closingWriter{w: out}
	defer guarded.close()
	logs := make(chan error, 1)
	go func() { logs <- e.Logs(ctx, id, true, "all", guarded) }()
	code, err := e.WaitExit(ctx, id)
	if errors.Is(err, context.DeadlineExceeded) {
		return -1, id, errors.New("timed out")
	}
	if err != nil {
		return -1, id, err
	}
	select {
	case <-logs:
	case <-time.After(3 * time.Second):
	}
	if code != 0 {
		return code, id, fmt.Errorf("exited with code %d", code)
	}
	return 0, id, nil
}

// Tick runs every cron workload of every active revision that is due.
// Each workload runs one at a time; a run still going when the next is
// due is skipped.
func (j *Jobs) Tick(ctx context.Context, now time.Time, log func(string, ...any)) {
	active, err := j.Store.ActiveRevisions(ctx)
	if err != nil {
		log("cron: %v", err)
		return
	}
	// Reconciliation may be waiting for a surviving cron container from the
	// previous daemon. Its run is durable even though this runner's map is new.
	open, err := j.Store.OpenJobRuns(ctx)
	if err != nil {
		log("cron: %v", err)
		return
	}
	adopted := map[string]bool{}
	for _, run := range open {
		if run.Kind == JobCron {
			adopted[run.App+"/"+run.Workload] = true
		}
	}
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			continue
		}
		for _, name := range m.WorkloadNames() {
			w := m.Workloads[name]
			if w.Kind != manifest.Cron {
				continue
			}
			sched, err := manifest.ParseSchedule(w.Schedule)
			if err != nil {
				continue
			}
			last, err := j.Store.LastJobRun(ctx, rev.App, name)
			if err != nil {
				log("cron: %v", err)
				continue
			}
			since := rev.CreatedAt
			if last != nil && last.StartedAt.After(since) {
				since = last.StartedAt
			}
			hold, err := j.Store.LastJobHold(ctx, rev.App, name)
			if err != nil {
				log("cron: %v", err)
				continue
			}
			if hold != nil {
				if now.Before(hold.FinishedAt) {
					continue
				}
				// A hold resumes the schedule where it ends, with no run to
				// catch up on the ones it held.
				if hold.FinishedAt.After(since) {
					since = hold.FinishedAt
				}
			}
			if sched.Next(since).After(now) {
				continue
			}
			key := rev.App + "/" + name
			if adopted[key] {
				continue
			}
			j.mu.Lock()
			busy := j.running[key]
			if !busy {
				j.running[key] = true
			}
			j.mu.Unlock()
			if busy {
				continue
			}
			rev := rev
			j.waiting.Add(1)
			go func() {
				defer j.waiting.Done()
				defer func() {
					if p := recover(); p != nil {
						log("cron %s: panic: %v\n%s", key, p, debug.Stack())
					}
					j.mu.Lock()
					delete(j.running, key)
					j.mu.Unlock()
				}()
				// Stop tracking on daemon cancellation while Docker finishes the
				// job. Its open durable run is adopted by the next daemon.
				code, err := j.Run(ctx, &rev, name, nil, JobCron, io.Discard)
				if err != nil {
					log("cron %s: %v (exit %d)", key, err, code)
					return
				}
				log("cron %s: ok", key)
			}()
		}
	}
}

// Wait drains cron trackers after the scheduler has stopped calling Tick.
// Cancel the daemon context first; existing Docker jobs remain adoptable.
func (j *Jobs) Wait() { j.waiting.Wait() }

// RunDefinition is the Definition for RunKind.
type RunDefinition struct {
	Jobs *Jobs
}

// RunInput says what to run.
type RunInput struct {
	App      string   `json:"app"`
	Workload string   `json:"workload,omitempty"`
	Command  []string `json:"command"`
	// Secrets are more of the app's secrets the command gets, by name.
	Secrets []string `json:"secrets,omitempty"`
}

// Kind implements kernel.Definition.
func (RunDefinition) Kind() string { return RunKind }

// Plan implements kernel.Definition.
func (r RunDefinition) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in RunInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("run input: %w", err)
	}
	if len(in.Command) == 0 {
		return nil, errors.New("nothing to run")
	}
	rev, err := r.Jobs.Store.RevisionWithStatus(ctx, in.App, state.RevisionActive)
	if err != nil {
		return nil, err
	}
	if rev == nil {
		return nil, fmt.Errorf("%s isn't deployed", in.App)
	}
	workload, err := RunWorkload(rev, in.Workload)
	if err != nil {
		return nil, err
	}
	note := "revision " + rev.ID
	if len(in.Secrets) > 0 {
		note += ", with " + strings.Join(in.Secrets, ", ")
	}
	return &kernel.Plan{Target: in.App + " " + workload, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "run", Change: fmt.Sprintf("run %s in %s's environment", strings.Join(in.Command, " "), workload),
		Note: note,
		Apply: func(ctx context.Context, out io.Writer) error {
			// Arbitrary commands can commit effects before an interruption.
			// Reconciliation adopts the existing job; recovery must not create
			// a second job when the previous outcome is uncertain.
			if kernel.Attempt(ctx) > 1 {
				return errors.New("the one-off command was interrupted and is not replayed automatically; inspect helios jobs before deliberately running it again")
			}
			_, err := r.Jobs.RunWith(ctx, rev, workload, in.Command, JobRun, JobOptions{Secrets: in.Secrets}, out)
			return err
		},
	}}}, nil
}

// RunWorkload picks the workload a one-off command runs as: the one
// named, or the app's only one.
func RunWorkload(rev *state.Revision, workload string) (string, error) {
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return "", err
	}
	if workload == "" {
		names := m.WorkloadNames()
		if len(names) != 1 {
			return "", fmt.Errorf("%s has several workloads; name one of %s", rev.App, strings.Join(names, ", "))
		}
		workload = names[0]
	}
	if _, ok := m.Workloads[workload]; !ok {
		return "", fmt.Errorf("%s has no workload named %s", rev.App, workload)
	}
	return workload, nil
}

// closingWriter forwards writes until it is closed, then drops them.
type closingWriter struct {
	mu     sync.Mutex
	w      io.Writer
	closed bool
}

func (c *closingWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return len(p), nil
	}
	return c.w.Write(p)
}

func (c *closingWriter) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

// jobSpec is the container a one-off job runs in: the workload's own, made
// into something that runs once beside it.
func jobSpec(m *manifest.Manifest, revision, workload string, w manifest.Workload, image string, values map[string]string) (docker.Spec, error) {
	spec, err := containerSpec(m, workload, w, revision, image, values)
	if err != nil {
		return spec, err
	}
	spec.Name = fmt.Sprintf("bedrock-%s-%s-job-%s", m.App, workload, rand.Text())
	spec.Restart = false
	// A job never takes traffic: it stays on the app's own network, and
	// answers to none of the workload's names, which belong to the
	// workload's running containers. Its ports on the machine are theirs
	// too, and are already taken.
	spec.Networks = []string{docker.AppNetwork(m.App)}
	spec.Aliases = nil
	spec.Publish = nil
	return spec, nil
}
