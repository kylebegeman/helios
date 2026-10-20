package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// rollout is one revision of an app being brought up: what its steps
// share, and each step as a method. A deploy and a rollback are both
// rollouts; a rollback has nothing to build from (from is nil), so it
// records, makes and builds nothing and runs no releases.
type rollout struct {
	d            Deploy
	m            *manifest.Manifest
	manifestJSON []byte
	revision     string
	from         *buildFrom
	store        *state.Store
	stateDir     string
	// images and containers name what the revision runs, by workload.
	images     map[string]string
	containers map[string]string
	hosts      []string
	// engine is Docker, opened by the first step that needs it and kept
	// for the ones after.
	engine *docker.Engine
}

// rollout is the plan both deploy and rollback share.
func (d Deploy) rollout(ctx context.Context, m *manifest.Manifest, revision string, from *buildFrom) (*kernel.Plan, error) {
	if err := d.CloudflareOnly.checkRoutes(m); err != nil {
		return nil, err
	}
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	r := &rollout{d: d, m: m, manifestJSON: manifestJSON, revision: revision, from: from, store: d.Store,
		stateDir: d.StateDir, images: map[string]string{}, containers: map[string]string{}, hosts: m.Hosts()}
	if r.stateDir == "" {
		r.stateDir = defaultStateDir
	}
	if from == nil {
		rev, err := r.store.GetRevision(ctx, m.App, revision)
		if err != nil {
			return nil, fmt.Errorf("revision %s of %s: %w", revision, m.App, err)
		}
		r.images = rev.Images
	}
	// A port another app already holds on the machine would fail the new
	// container at start, after the build and the releases. Refuse it
	// while it is still only a plan.
	if err := checkPublishedPorts(ctx, r.store, m); err != nil {
		return nil, err
	}
	if err := CheckRouteConflicts(ctx, r.store, m); err != nil {
		return nil, err
	}
	for _, name := range m.WorkloadNames() {
		if m.Workloads[name].LongRunning() {
			r.containers[name] = docker.ContainerName(m.App, name, revision)
		}
	}
	// The target and the changes name no revision: the digest is meant to
	// pin the plan, not the moment it was made. The revision is a note.
	plan := &kernel.Plan{Target: m.App, Recovery: kernel.Resume}
	add := func(st kernel.Step) { plan.Steps = append(plan.Steps, st) }

	if from != nil {
		add(r.recordStep())
	}
	add(r.edgeStep())
	// Names first: a record that points at another machine stops the
	// deploy before it costs a build.
	if len(r.hosts) > 0 {
		add(r.dnsStep())
	}
	if from != nil && from.secretsFrom != "" {
		add(r.inheritStep())
	}
	// Secrets the manifest asks helios to make come before the data: the
	// database starts with its password, and derived values name it.
	if from != nil && (m.PostgresVersion() != "" || m.HasObjects() || m.Secrets != nil) {
		add(r.secretsStep())
	}
	if m.Data != nil {
		add(r.dataStep())
	}
	if from != nil {
		for _, group := range buildGroups(m) {
			add(r.imageStep(group))
		}
	}
	// Release workloads run once, in order, against the data the new
	// revision will use, while the old one still serves. A rollback never
	// runs them: an older release step against newer data is the wrong
	// way round.
	if releases := m.ReleaseWorkloads(); from != nil && len(releases) > 0 {
		if m.HasData() && m.ReleaseCompatibility() != manifest.DataBackwardCompatible {
			add(r.releaseCheckpointStep())
		}
		add(r.releaseStep(releases))
	}
	add(r.startStep())
	add(r.readyStep())
	if len(verificationChecks(m).application) > 0 {
		add(r.checksStep())
	}
	// Activation and certificate failures need the same recovery as a
	// failed public check.
	add(r.recoverOnFailure(r.switchStep()))
	if len(r.hosts) > 0 {
		add(r.recoverOnFailure(r.certificatesStep()))
	}
	if checks := verificationChecks(m); len(checks.edge)+len(checks.guards) > 0 {
		add(r.verifyStep())
	}
	add(r.retireStep())
	return plan, nil
}

// connect opens Docker once for every step of the rollout.
func (r *rollout) connect(ctx context.Context) (*docker.Engine, error) {
	if r.engine != nil {
		return r.engine, nil
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return nil, err
	}
	r.engine = e
	return e, nil
}

// abandon takes down a revision that never went live: its containers go,
// the singletons they replaced start again, and it stays failed.
func (r *rollout) abandon(_ context.Context, e *docker.Engine, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var failures []error
	for _, c := range r.containers {
		if err := e.Remove(ctx, c, 5*time.Second); err != nil {
			failures = append(failures, err)
		}
	}
	if err := r.store.SetRevisionStatus(ctx, r.m.App, r.revision, state.RevisionFailed); err != nil {
		failures = append(failures, err)
	}
	// Never restart a singleton while its failed replacement may still run.
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	current, err := r.store.RevisionWithStatus(ctx, r.m.App, state.RevisionActive)
	if err != nil {
		return err
	}
	if current != nil {
		unsafe, err := unsafeReleaseBoundaries(ctx, r.store, current)
		if err != nil {
			return err
		}
		if len(unsafe) > 0 {
			return unsafeRollbackError(r.m.App, unsafe)
		}
	}
	return restartStoppedWorkloads(ctx, e, r.store, r.m.App, r.revision, out)
}

// pin fixes the secrets a revision runs with: a deploy takes the current
// version, a rollback keeps the one it had.
func (r *rollout) pin(ctx context.Context) (*state.Revision, map[string]string, int, error) {
	rev, err := r.store.GetRevision(ctx, r.m.App, r.revision)
	if err != nil {
		return nil, nil, 0, err
	}
	values, version, err := r.d.secretsFor(rev, r.from == nil || rev.SecretsVersion > 0)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := checkSecrets(r.m, values); err != nil {
		return nil, nil, 0, err
	}
	if err := checkVerificationSecrets(r.m, values); err != nil {
		return nil, nil, 0, err
	}
	if rev.SecretsVersion != version {
		rev.SecretsVersion = version
		if err := r.store.SaveRevision(ctx, *rev); err != nil {
			return nil, nil, 0, err
		}
	}
	return rev, values, version, nil
}

func (r *rollout) recordStep() kernel.Step {
	return kernel.Step{
		Name: "record", Change: "record a new revision of " + r.m.App,
		Note: notes("revision "+r.revision, noteCommit(r.from.commit), noteSigner(r.from.signer)),
		Apply: func(ctx context.Context, out io.Writer) error {
			existing, err := r.store.GetRevision(ctx, r.m.App, r.revision)
			if err == nil {
				if kernel.Attempt(ctx) < 2 {
					return fmt.Errorf("revision %s of %s already exists; choose a new revision", r.revision, r.m.App)
				}
				if !bytes.Equal(existing.Manifest, r.manifestJSON) || !maps.Equal(existing.Containers, r.containers) || existing.Source != r.from.commit {
					return errors.New("recorded revision does not match this interrupted deployment")
				}
				fmt.Fprintf(out, "revision %s already recorded\n", r.revision)
				return nil
			}
			if !errors.Is(err, state.ErrNotFound) {
				return err
			}
			rev := state.Revision{App: r.m.App, ID: r.revision, Status: state.RevisionFailed, Manifest: r.manifestJSON,
				Images: r.images, Containers: r.containers, Source: r.from.commit, CreatedAt: time.Now().UTC()}
			if err := r.store.CreateRevision(ctx, rev); err != nil {
				return err
			}
			fmt.Fprintf(out, "revision %s\n", r.revision)
			return nil
		},
	}
}

func (r *rollout) edgeStep() kernel.Step {
	return kernel.Step{
		Name: "edge", Change: "run the edge, the app's own network and the one it shares with the edge alone",
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := r.connect(ctx)
			if err != nil {
				return err
			}
			boot, err := EdgeConfig(ctx, r.store, r.d.Secrets)
			if err != nil {
				return err
			}
			if err := edge.Ensure(ctx, e, boot, out); err != nil {
				return err
			}
			if err := e.EnsureNetwork(ctx, docker.AppNetwork(r.m.App)); err != nil {
				return err
			}
			if servesAny(r.m) {
				return edge.Join(ctx, e, r.m.App)
			}
			return nil
		},
	}
}

func (r *rollout) dnsStep() kernel.Step {
	change := "confirm " + strings.Join(r.hosts, ", ") + " point at this machine"
	if managed := r.m.ManagedHosts(); len(managed) > 0 {
		change = "keep the DNS records for " + strings.Join(sortedKeys(managed), ", ") + " and confirm every host points here"
	}
	return kernel.Step{
		Name: "dns", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			return keepRecords(ctx, r.d.Secrets, r.m, r.d.Addresses(ctx), out)
		},
	}
}

// inheritStep copies what a preview's parent was given by hand before the
// preview's own secrets are made, so the values its code expects are there
// to derive from. It is a step of its own: shown in the plan, journaled,
// and done by whoever holds the key.
func (r *rollout) inheritStep() kernel.Step {
	parent := r.from.secretsFrom
	return kernel.Step{
		Name: "inherit", Change: fmt.Sprintf("copy %s's secrets to %s, which runs its code", parent, r.m.App),
		Apply: func(_ context.Context, out io.Writer) error {
			copied, err := r.d.Secrets.CopyAll(parent, r.m.App)
			if err != nil {
				return err
			}
			if len(copied) == 0 {
				fmt.Fprintf(out, "%s already holds what %s has\n", r.m.App, parent)
				return nil
			}
			fmt.Fprintf(out, "copied %d secret(s) from %s: %s\n", len(copied), parent, strings.Join(copied, ", "))
			return nil
		},
	}
}

func (r *rollout) secretsStep() kernel.Step {
	return kernel.Step{
		Name: "secrets", Change: "make the secrets the manifest asks for" + secretsSummary(r.m),
		Apply: func(ctx context.Context, out io.Writer) error {
			return ensureAppSecrets(r.d.Secrets, r.m, out)
		},
	}
}

func (r *rollout) dataStep() kernel.Step {
	var restore Restore
	source := ""
	if r.from != nil {
		restore, source = r.from.restore, r.from.source
	}
	return kernel.Step{
		Name: "data", Change: "keep the app's data" + dataSummary(r.m),
		Note: restoreNote(restore),
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := r.connect(ctx)
			if err != nil {
				return err
			}
			initDir, err := prepareInit(r.m, source, r.stateDir)
			if err != nil {
				return err
			}
			return ensureData(ctx, e, r.d.Secrets, r.m, initDir, restore, out)
		},
	}
}

// imageStep builds or pulls the image one group of workloads shares.
func (r *rollout) imageStep(group []string) kernel.Step {
	name, w := group[0], r.m.Workloads[group[0]]
	ref := docker.ImageRef(r.m.App, name, r.revision)
	switch {
	case w.Kind == manifest.Static:
		return kernel.Step{
			Name: "build-" + name, Change: fmt.Sprintf("build %s from %s (static files)", name, w.Dir),
			Apply: func(ctx context.Context, out io.Writer) error {
				context, err := docker.StaticContext(r.from.source, w.Dir)
				if err != nil {
					return err
				}
				defer os.RemoveAll(context)
				if err := docker.Build(ctx, docker.BuildSpec{Ref: ref, Context: context, Labels: imageLabels(r.m.App, name, r.revision)}, filtered(out)); err != nil {
					return err
				}
				return recordImage(ctx, r.store, r.connect, r.m.App, r.revision, group, ref, r.images, out)
			},
		}
	case w.Build != nil:
		change := fmt.Sprintf("build %s from %s", name, orDot(w.Build.Context))
		if len(group) > 1 {
			change = fmt.Sprintf("build %s's image from %s, for %s", name, orDot(w.Build.Context), strings.Join(group, ", "))
		}
		if w.Build.Target != "" {
			change += " (target " + w.Build.Target + ")"
		}
		return kernel.Step{
			Name: "build-" + name, Change: change,
			Apply: func(ctx context.Context, out io.Writer) error {
				spec := docker.BuildSpec{Ref: ref, Context: filepath.Join(r.from.source, orDot(w.Build.Context)), Dockerfile: w.Build.Dockerfile, Target: w.Build.Target, Args: w.Build.Args, Labels: imageLabels(r.m.App, name, r.revision)}
				if err := docker.Build(ctx, spec, filtered(out)); err != nil {
					return err
				}
				return recordImage(ctx, r.store, r.connect, r.m.App, r.revision, group, ref, r.images, out)
			},
		}
	default:
		return kernel.Step{
			Name: "pull-" + name, Change: fmt.Sprintf("use image %s for %s", w.Image, strings.Join(group, ", ")),
			Apply: func(ctx context.Context, out io.Writer) error {
				e, err := r.connect(ctx)
				if err != nil {
					return err
				}
				if !e.HasImage(ctx, w.Image) {
					if err := e.Pull(ctx, w.Image, out); err != nil {
						return err
					}
				}
				return recordImage(ctx, r.store, r.connect, r.m.App, r.revision, group, w.Image, r.images, out)
			},
		}
	}
}

func (r *rollout) releaseStep(releases []string) kernel.Step {
	return kernel.Step{
		Name: "release", Change: "run " + strings.Join(releases, ", ") + ", once each, before anything new starts",
		Apply: func(ctx context.Context, out io.Writer) error {
			rev, _, _, err := r.pin(ctx)
			if err != nil {
				return err
			}
			boundary, err := r.prepareReleaseBoundary(ctx)
			if err != nil {
				return err
			}
			if boundary.Status == state.ReleaseCompleted {
				fmt.Fprintln(out, "release jobs already completed; not replayed")
				return nil
			}
			if boundary.Status != state.ReleasePrepared {
				return fmt.Errorf("release %s has an uncertain or failed prior attempt (%s); release jobs are not replayed automatically; inspect the recorded jobs, rehearse a new candidate or restore checkpoint %s", r.revision, boundary.Status, boundary.Snapshot)
			}
			started, err := r.store.StartPreparedReleaseBoundary(ctx, r.m.App, r.revision, time.Now().UTC())
			if err != nil {
				return err
			}
			if !started {
				return errors.New("release boundary changed; refusing to replay release jobs")
			}
			jobs := NewJobs(r.store, r.d.Secrets)
			for _, name := range releases {
				fmt.Fprintf(out, "%s:\n", name)
				if _, err := jobs.Run(ctx, rev, name, nil, JobRelease, out); err != nil {
					failed := fmt.Errorf("release workload %s: %w; release may already have changed data; checkpoint %s", name, err, boundary.Snapshot)
					cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					return errors.Join(failed, r.store.FinishReleaseBoundary(cleanup, r.m.App, r.revision, state.ReleaseFailed, failed.Error(), time.Now().UTC()))
				}
			}
			return r.store.FinishReleaseBoundary(ctx, r.m.App, r.revision, state.ReleaseCompleted, "", time.Now().UTC())
		},
	}
}

func (r *rollout) startStep() kernel.Step {
	return kernel.Step{
		Name: "start", Change: fmt.Sprintf("start %d container(s)", len(r.containers)) + publishedSummary(r.m),
		Note: notes("revision "+r.revision, secretsNote(r.m)),
		Apply: func(ctx context.Context, out io.Writer) (startErr error) {
			e, err := r.connect(ctx)
			if err != nil {
				return err
			}
			defer func() {
				if startErr != nil {
					startErr = errors.Join(startErr, r.abandon(ctx, e, out))
				}
			}()
			rev, values, version, err := r.pin(ctx)
			if err != nil {
				return err
			}
			// The revision this one replaces, whose singletons stop first.
			current, err := r.store.RevisionWithStatus(ctx, r.m.App, state.RevisionActive)
			if err != nil {
				return err
			}
			for _, name := range r.m.WorkloadNames() {
				if err := r.startWorkload(ctx, e, name, rev, values, current, out); err != nil {
					return err
				}
			}
			if version > 0 {
				fmt.Fprintf(out, "secrets version %d\n", version)
			}
			return nil
		},
	}
}

// startWorkload readies one workload's volumes and, when it stays up
// between deploys, starts its container, stopping a singleton's
// predecessor first.
func (r *rollout) startWorkload(ctx context.Context, e *docker.Engine, name string, rev *state.Revision, values map[string]string, current *state.Revision, out io.Writer) error {
	w := r.m.Workloads[name]
	if w.Kind == manifest.Release {
		return nil
	}
	image := rev.Images[name]
	if image == "" {
		return fmt.Errorf("no image recorded for %s", name)
	}
	spec, err := containerSpec(r.m, name, w, r.revision, image, values)
	if err != nil {
		return err
	}
	u, err := isolate(ctx, e, &spec, w, image)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	// Cron workloads start later, but their volumes are readied now, once,
	// instead of on every run.
	if err := ownVolumes(ctx, e, r.m, w, u, out); err != nil {
		return err
	}
	if !w.LongRunning() {
		return nil
	}
	if w.Singleton && current != nil && current.ID != r.revision {
		if old := current.Containers[name]; old != "" {
			if err := e.Stop(ctx, old, graceOf(current, name)); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s stopped first: %s is a singleton\n", old, name)
		}
	}
	if err := e.Run(ctx, spec); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s running as %s%s\n", spec.Name, u, isolationWord(w))
	return nil
}

func (r *rollout) readyStep() kernel.Step {
	return kernel.Step{
		Name: "ready", Change: "wait until every workload answers",
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := r.connect(ctx)
			if err != nil {
				return err
			}
			for _, name := range r.m.WorkloadNames() {
				w := r.m.Workloads[name]
				if !w.LongRunning() {
					continue
				}
				if err := waitReady(ctx, e, r.containers[name], w); err != nil {
					showLastLines(ctx, e, r.containers[name], name, out)
					// The new containers never went live; take them down.
					return errors.Join(fmt.Errorf("%s: %w", name, err), r.abandon(ctx, e, out))
				}
				fmt.Fprintf(out, "%s ready\n", name)
			}
			return nil
		},
	}
}

func (r *rollout) checksStep() kernel.Step {
	checks := verificationChecks(r.m).application
	return kernel.Step{
		Name: "checks", Change: fmt.Sprintf("run %d check(s) against the new containers", len(checks)),
		// Before any traffic reaches it: a revision that answers wrong
		// never goes live.
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := r.connect(ctx)
			if err != nil {
				return err
			}
			for _, c := range checks {
				if err := runCheckDirect(ctx, e, r.m, r.containers, c); err != nil {
					return errors.Join(err, r.abandon(ctx, e, out))
				}
				fmt.Fprintf(out, "%s ok\n", c.URL)
			}
			return nil
		},
	}
}

func (r *rollout) switchStep() kernel.Step {
	return kernel.Step{
		Name: "switch", Change: "route the edge to the new revision",
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := r.store.Activate(ctx, r.m.App, r.revision, time.Now().UTC()); err != nil {
				return err
			}
			cfg, err := edgeConfig(ctx, r.store, r.d.Secrets)
			if err != nil {
				return err
			}
			if err := edge.NewAdmin().Load(ctx, cfg); err != nil {
				return err
			}
			fmt.Fprintf(out, "edge routes to %s\n", r.revision)
			return nil
		},
	}
}

func (r *rollout) certificatesStep() kernel.Step {
	return kernel.Step{
		Name: "certificates", Change: "wait for certificates for " + strings.Join(r.hosts, ", "),
		Apply: func(ctx context.Context, out io.Writer) error {
			for _, host := range r.hosts {
				why, err := edge.WaitCertificate(ctx, host, "127.0.0.1:443", 3*time.Minute)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%s: %s\n", host, why)
			}
			return nil
		},
	}
}

// recoverOnFailure wraps a step that runs once the edge may be pointed at
// the new revision: when it fails, a revision that went live is switched
// back, and one that didn't is abandoned. The recovery gets a fresh
// context, even when the deploy was cancelled.
func (r *rollout) recoverOnFailure(step kernel.Step) kernel.Step {
	apply := step.Apply
	step.Apply = func(ctx context.Context, out io.Writer) error {
		err := apply(ctx, out)
		if err == nil {
			return nil
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		current, lookupErr := r.store.RevisionWithStatus(cleanup, r.m.App, state.RevisionActive)
		if lookupErr != nil {
			return errors.Join(err, lookupErr)
		}
		if current == nil || current.ID != r.revision {
			if e, connectErr := r.connect(cleanup); connectErr == nil {
				return errors.Join(err, r.abandon(cleanup, e, out))
			}
			return err
		}
		previous, lookupErr := r.store.RevisionWithStatus(cleanup, r.m.App, state.RevisionPrevious)
		if lookupErr != nil {
			return errors.Join(err, lookupErr)
		}
		if previous != nil {
			unsafe, gateErr := unsafeReleaseBoundaries(cleanup, r.store, previous)
			if gateErr != nil {
				return errors.Join(err, gateErr)
			}
			if len(unsafe) > 0 {
				return errors.Join(err, unsafeRollbackError(r.m.App, unsafe))
			}
		}
		message, recoveryErr := revertSwitch(cleanup, r.store, r.d.Secrets, r.connect, r.m.App, r.revision, r.containers)
		if recoveryErr != nil {
			return fmt.Errorf("%w; recovery failed: %v", err, recoveryErr)
		}
		return fmt.Errorf("%w; %s", err, message)
	}
	return step
}

func (r *rollout) verifyStep() kernel.Step {
	checks := verificationChecks(r.m)
	change := fmt.Sprintf("run %d check(s) through the edge", len(checks.edge))
	if len(checks.guards) > 0 {
		change += fmt.Sprintf(" and verify %d sign-in guard(s) deny anonymous requests", len(checks.guards))
	}
	return r.recoverOnFailure(kernel.Step{
		Name: "verify", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			for _, c := range checks.guards {
				if err := runGuardCheck(ctx, c); err != nil {
					return err
				}
				fmt.Fprintf(out, "%s: sign-in guard denied anonymous access\n", c.URL)
			}
			var values map[string]string
			if len(CheckSecretNames(r.m)) > 0 {
				_, loaded, _, err := r.pin(ctx)
				if err != nil {
					return err
				}
				values = loaded
			}
			for _, c := range checks.edge {
				if err := runEdgeCheck(ctx, c, values); err != nil {
					return err
				}
				fmt.Fprintf(out, "%s ok\n", c.URL)
			}
			return nil
		},
	})
}

func (r *rollout) retireStep() kernel.Step {
	return kernel.Step{
		Name: "retire", Change: "stop the revision this one replaces",
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := r.connect(ctx)
			if err != nil {
				return err
			}
			revs, err := r.store.Revisions(ctx, r.m.App)
			if err != nil {
				return err
			}
			for _, old := range revs {
				if old.ID == r.revision || old.Status == state.RevisionActive {
					continue
				}
				for _, name := range sortedKeys(old.Containers) {
					if err := e.Remove(ctx, old.Containers[name], graceOf(&old, name)); err != nil {
						return err
					}
				}
				if old.Status == state.RevisionPrevious {
					fmt.Fprintf(out, "%s stopped, kept for rollback\n", old.ID)
				}
			}
			return pruneRecords(ctx, r.store, r.d.Secrets, r.m.App, r.d.Addresses(ctx), out)
		},
	}
}
