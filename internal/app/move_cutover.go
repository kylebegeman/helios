package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

const MoveCutoverKind = "app.move.cutover"

type MoveCutover struct{ Deploy Deploy }
type MoveCutoverInput struct {
	App       string `json:"app"`
	Migration string `json:"migration"`
	Revision  string `json:"revision"`
	Snapshot  string `json:"snapshot,omitempty"`
}

func (MoveCutover) Kind() string { return MoveCutoverKind }

func (c MoveCutover) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in MoveCutoverInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if err := checkReleaseStoreAccess(ctx, c.Deploy.Store, in.App); err != nil {
		return nil, err
	}
	record, err := readMigration(c.Deploy.Store.Path(), in.App)
	if err != nil {
		return nil, err
	}
	if record == nil || record.Role != "target" || record.Handoff.Phase != "final" || record.Handoff.Migration != in.Migration || record.TargetRevision != in.Revision || record.Handoff.Snapshot != in.Snapshot {
		return nil, errors.New("cutover requires the reviewed migration, staged target revision and exact final snapshot")
	}
	if record.Phase != "staged" && record.Phase != "cutting-over" && record.Phase != "cutover" {
		return nil, errors.New("target has not finished staging and validation")
	}
	rev, err := c.Deploy.Store.GetRevision(ctx, in.App, in.Revision)
	if err != nil {
		return nil, err
	}
	if rev.Status != revisionStaged && rev.Status != state.RevisionActive {
		return nil, errors.New("target revision is no longer staged or active for this migration")
	}
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return nil, err
	}
	if manifestDigest(&m) != record.Handoff.ManifestDigest {
		return nil, errors.New("staged manifest changed after final capture")
	}
	if err := CheckRouteConflicts(ctx, c.Deploy.Store, &m); err != nil {
		return nil, err
	}
	if err := checkPublishedPorts(ctx, c.Deploy.Store, &m); err != nil {
		return nil, err
	}
	// A CA trusted when the move was staged can have been forgotten since:
	// forget guards only what the edge already serves.
	if rev.Status == revisionStaged {
		if err := checkMovedOriginPullTrust(ctx, c.Deploy.Store, &m, c.Deploy.Secrets, time.Now(), "cut over again"); err != nil {
			return nil, err
		}
	}
	r := &rollout{d: c.Deploy, m: &m, manifestJSON: rev.Manifest, revision: in.Revision, store: c.Deploy.Store, stateDir: c.Deploy.StateDir, images: rev.Images, containers: map[string]string{}, hosts: m.Hosts()}
	for _, name := range m.WorkloadNames() {
		if m.Workloads[name].LongRunning() {
			r.containers[name] = docker.ContainerName(m.App, name, in.Revision)
		}
	}
	identity := fmt.Sprintf("%s from %s to %s, source %s, target %s, final snapshot %s", record.Handoff.Migration, record.Handoff.From, record.Handoff.To, record.Handoff.Revision, in.Revision, orStateless(in.Snapshot))
	plan := &kernel.Plan{Target: in.App, Recovery: kernel.Resume}
	ready := moveStageReady(r)
	ready.Name = "cutover-ready"
	ready.Change += " for " + identity
	checks := moveStageChecks(r)
	checks.Name = "cutover-checks"
	checks.Change += " for " + identity
	for _, step := range []*kernel.Step{&ready, &checks} {
		apply := step.Apply
		step.Apply = func(ctx context.Context, out io.Writer) error {
			current, err := targetMigration(r.store.Path(), record.Handoff, in.Revision)
			if err != nil {
				return err
			}
			if current.Phase != "staged" {
				return nil
			}
			return apply(ctx, out)
		}
	}
	plan.Steps = append(plan.Steps, ready, checks, kernel.Step{Name: "admit-target-writers", Change: "start destination writers and normal published ports for " + identity + "; source rollback after this may lose target writes unless data is moved back", Apply: func(ctx context.Context, out io.Writer) error {
		current, err := targetMigration(r.store.Path(), record.Handoff, in.Revision)
		if err != nil {
			return err
		}
		if current.Phase == "cutover" {
			return nil
		}
		e, err := r.connect(ctx)
		if err != nil {
			return err
		}
		if current.Phase == "staged" {
			current.Phase = "cutting-over"
			if err := saveMigration(r.store.Path(), current); err != nil {
				return err
			}
		}
		if current.LiveContainers == nil {
			current.LiveContainers = map[string]bool{}
		}
		rev, values, _, err := r.pin(ctx)
		if err != nil {
			return err
		}
		rev.Containers = r.containers
		if err := r.store.SaveRevision(ctx, *rev); err != nil {
			return err
		}
		for _, name := range m.WorkloadNames() {
			w := m.Workloads[name]
			if stageServes(w) && !current.LiveContainers[name] {
				// A replay repeats only containers whose normal live spec
				// was not durably acknowledged after replacing staging.
				if err := e.Remove(ctx, r.containers[name], w.GraceOr(10*time.Second)); err != nil {
					return err
				}
			}
			if err := r.startWorkload(ctx, e, name, rev, values, nil, out); err != nil {
				return err
			}
			if w.LongRunning() {
				current.LiveContainers[name] = true
				if err := saveMigration(r.store.Path(), current); err != nil {
					return err
				}
			}
		}
		for _, name := range m.WorkloadNames() {
			if w := m.Workloads[name]; w.LongRunning() {
				if err := waitReady(ctx, e, r.containers[name], w); err != nil {
					return fmt.Errorf("destination %s: %w", name, err)
				}
			}
		}
		return nil
	}})
	// Every failure after admitting destination writers leaves the source
	// fenced and the target intact. Repointing to stale source data is not an
	// automatic rollback, because the target may already have accepted writes.
	switchStep := r.switchStep()
	switchStep.Name = "cutover-route"
	switchStep.Change += " for " + identity
	plan.Steps = append(plan.Steps, switchStep)
	for _, host := range sortedKeys(m.ManagedHosts()) {
		point := Point{AllowMigration: record.Handoff.Migration, Store: r.store, Secrets: r.d.Secrets, Addresses: r.d.Addresses, CloudflareOnly: r.d.CloudflareOnly}
		pointInput, _ := json.Marshal(PointInput{Host: host, Proxied: m.ManagedHosts()[host] == manifest.DNSProxied})
		pointPlan, err := point.Plan(ctx, pointInput)
		if err != nil {
			return nil, err
		}
		for _, step := range pointPlan.Steps {
			step.Name = "dns-" + host
			step.Change += " for " + identity
			plan.Steps = append(plan.Steps, step)
		}
	}
	if len(m.Hosts()) > 0 {
		cert := r.certificatesStep()
		cert.Name = "cutover-certificates"
		cert.Change += " for " + identity
		plan.Steps = append(plan.Steps, cert)
	}
	verification := verificationChecks(&m)
	if len(verification.edge)+len(verification.guards) > 0 {
		plan.Steps = append(plan.Steps, kernel.Step{Name: "cutover-verify", Change: "verify live content and anonymous guard denial for " + identity, Apply: func(ctx context.Context, out io.Writer) error {
			_, values, _, err := r.pin(ctx)
			if err != nil {
				return err
			}
			for _, guard := range verification.guards {
				if err := runGuardCheck(ctx, guard); err != nil {
					return err
				}
			}
			for _, check := range verification.edge {
				if err := runEdgeCheck(ctx, check, values); err != nil {
					return err
				}
			}
			return nil
		}})
	}
	plan.Steps = append(plan.Steps, kernel.Step{Name: "cutover-complete", Change: "allow target jobs and retain frozen source for an explicit, data-aware rollback window for " + identity, Apply: func(ctx context.Context, out io.Writer) error {
		current, err := targetMigration(r.store.Path(), record.Handoff, in.Revision)
		if err != nil {
			return err
		}
		current.Phase = "cutover"
		if err := saveMigration(r.store.Path(), current); err != nil {
			return err
		}
		fmt.Fprintln(out, "cutover complete; source remains fenced. Returning to source data requires stopping the target and deliberately resuming the source; target writes require a reverse move to preserve them.")
		return nil
	}})
	return guardReleaseRestoreSteps(plan, c.Deploy.Store), nil
}

// MigrationCutoverInput resolves the durable target record so the CLI cannot
// accidentally cut over whichever revision happened to deploy last.
func MigrationCutoverInput(stateFile, app string) (MoveCutoverInput, error) {
	record, err := readMigration(stateFile, app)
	if err != nil {
		return MoveCutoverInput{}, err
	}
	if record == nil || record.Role != "target" {
		return MoveCutoverInput{}, errors.New("no staged migration on this target")
	}
	return MoveCutoverInput{App: app, Migration: record.Handoff.Migration, Revision: record.TargetRevision, Snapshot: record.Handoff.Snapshot}, nil
}
