package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

const MoveTestKind = "app.move.test"

// MoveTest proves a rehearsal snapshot on a clean destination using only
// scratch volumes and an internal network. It never admits production routes.
type MoveTest struct {
	Deploy   Deploy
	Hostname func() string
}

func (MoveTest) Kind() string { return MoveTestKind }

func (t MoveTest) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in MoveStageInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	h := in.Handoff
	target := ""
	if t.Hostname != nil {
		target = t.Hostname()
	} else {
		target, _ = os.Hostname()
	}
	if err := checkMigrationHandoff(h, target, "rehearsal"); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(in.Source) || !revisionPattern.MatchString(in.Revision) {
		return nil, errors.New("move test needs an absolute source and reviewed candidate revision")
	}
	stateDir := t.Deploy.StateDir
	if stateDir == "" {
		stateDir = filepath.Dir(t.Deploy.Store.Path())
	}
	workspace := filepath.Join(stateDir, "moves", h.App, "tests", in.Revision)
	reservation := workspace + ".json"
	cached, err := readMoveTestReservation(reservation, in)
	if err != nil {
		return nil, err
	}
	var m *manifest.Manifest
	var commit string
	if cached != nil {
		// Compensation needs the captured manifest even when a temporary
		// uploaded checkout, storage or credentials disappeared.
		m, commit = &cached.Manifest, cached.Commit
	} else {
		name := in.Manifest
		if name == "" {
			name = manifest.FileName
		}
		m, err = manifest.LoadFile(in.Source, name)
		if err != nil {
			return nil, err
		}
		commit = sourceCommit(ctx, in.Source)
		if in.Commit != "" {
			if commit != "" && commit != in.Commit {
				return nil, errors.New("provided source commit differs from target checkout")
			}
			commit = in.Commit
		}
		if err := checkMoveTestAdmission(ctx, t.Deploy.Store, m.App); err != nil {
			return nil, err
		}
		if err := CheckDeploySecrets(m, t.Deploy.Secrets); err != nil {
			return nil, err
		}
		if h.HasData {
			st, err := integration.LoadStorage(t.Deploy.Secrets)
			if err != nil {
				return nil, err
			}
			if err := h.Check(m.App, st); err != nil {
				return nil, err
			}
			if err := requireRestoreSecrets(t.Deploy.Secrets, m); err != nil {
				return nil, err
			}
		}
	}
	if m.App != h.App || manifestDigest(m) != h.ManifestDigest || m.HasData() != h.HasData {
		return nil, errors.New("rehearsal source manifest differs from captured source revision")
	}
	if h.SourceCommit != "" && h.SourceCommit != commit {
		return nil, errors.New("rehearsal source commit differs from captured source revision")
	}
	for name, w := range m.Workloads {
		if w.Privileged {
			return nil, fmt.Errorf("cannot rehearse privileged workload %s on scratch data", name)
		}
	}
	if previous, err := t.Deploy.Store.GetRevision(ctx, m.App, in.Revision); err == nil {
		if manifestDigestFromRaw(previous.Manifest) != h.ManifestDigest || previous.Source != commit || previous.Status != state.RevisionFailed {
			return nil, errors.New("test revision already belongs to other app history")
		}
	} else if !errors.Is(err, state.ErrNotFound) {
		return nil, err
	}
	manifestJSON, _ := json.Marshal(m)
	r := &rollout{d: t.Deploy, m: m, manifestJSON: manifestJSON, revision: in.Revision, from: &buildFrom{source: in.Source, commit: commit}, store: t.Deploy.Store, stateDir: stateDir, images: map[string]string{}, containers: map[string]string{}}
	d := &drillState{dr: Drill{Store: r.store, Secrets: r.d.Secrets, StateDir: stateDir}, app: m.App, snapshot: h.Snapshot, m: *m, run: &backupRun{store: r.store, app: m.App, kind: state.BackupRunDrill}, names: rehearsalNames(workspace, m, "move-test-"+in.Revision), advice: "free space and run the move test again"}
	// Background workers must not consume restored queues in a move test.
	for name := range d.names.containers {
		if !stageServes(m.Workloads[name]) {
			delete(d.names.containers, name)
		}
	}
	identity := fmt.Sprintf("%s from %s to %s, source %s, test %s, exact snapshot %s", h.Migration, h.From, h.To, h.Revision, in.Revision, orStateless(h.Snapshot))
	cleanup := func(ctx context.Context) error {
		return cleanupMoveTest(ctx, r, d.names, workspace, reservation)
	}
	reserve := kernel.Step{Name: "reserve-test", Change: "persist scratch ownership and candidate manifest for interruption cleanup", Apply: func(ctx context.Context, out io.Writer) error {
		if err := checkMoveTestAdmission(ctx, r.store, m.App); err != nil {
			return err
		}
		if err := cleanup(ctx); err != nil {
			return err
		}
		return writeRehearsalJSON(reservation, moveTestReservation{Input: in, Manifest: *m, Commit: commit})
	}, Undo: func(_ context.Context, out io.Writer) error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := cleanup(ctx); err != nil {
			return err
		}
		if err := d.run.begin(ctx); err != nil {
			return err
		}
		d.run.fail(errors.New("destination move rehearsal failed or was interrupted; scratch resources removed"))
		return nil
	}}
	plan := &kernel.Plan{Target: m.App, Recovery: kernel.Compensate, Steps: []kernel.Step{reserve, r.recordStep()}}
	if m.Secrets != nil {
		plan.Steps = append(plan.Steps, r.secretsStep())
	}
	for _, group := range buildGroups(m) {
		plan.Steps = append(plan.Steps, r.imageStep(group))
	}
	pin := kernel.Step{Name: "pin-test-images", Change: "pin source images and original credentials for scratch rehearsal", Apply: func(ctx context.Context, out io.Writer) error {
		rev, _, _, err := r.pin(ctx)
		if err != nil {
			return err
		}
		d.rev = rev
		return nil
	}}
	plan.Steps = append(plan.Steps, pin)
	if h.HasData {
		restore := d.restoreStep()
		original := restore.Apply
		restore.Apply = func(ctx context.Context, out io.Writer) error {
			if err := original(ctx, out); err != nil {
				return err
			}
			data, err := os.ReadFile(filepath.Join(d.names.dir, "manifest.json"))
			if err != nil {
				return err
			}
			if manifestDigestFromRaw(data) != h.ManifestDigest {
				return errors.New("rehearsal snapshot manifest does not match source")
			}
			return writeRestoreSnapshot(d.names.dir, d.found)
		}
		plan.Steps = append(plan.Steps, restore)
		if m.PostgresVersion() != "" {
			plan.Steps = append(plan.Steps, d.databaseStep())
		}
		if m.HasObjects() {
			plan.Steps = append(plan.Steps, d.objectsStep())
		}
	}
	appStep := d.appStep()
	start := appStep.Apply
	appStep.Apply = func(ctx context.Context, out io.Writer) error {
		if d.rev == nil {
			rev, _, _, err := r.pin(ctx)
			if err != nil {
				return err
			}
			d.rev = rev
		}
		if err := start(ctx, out); err != nil {
			return err
		}
		e, err := docker.Connect(ctx)
		if err != nil {
			return err
		}
		defer e.Close()
		for _, check := range verificationChecks(m).application {
			if err := runCheckDirect(ctx, e, m, d.names.containers, check); err != nil {
				return errors.Join(err, d.names.cleanup(e))
			}
		}
		return nil
	}
	plan.Steps = append(plan.Steps, appStep)
	plan.Steps = append(plan.Steps, kernel.Step{Name: "test-cleanup", Change: "remove every scratch container and volume after successful rehearsal; production remains on source", Apply: func(ctx context.Context, out io.Writer) error {
		if err := cleanup(ctx); err != nil {
			return err
		}
		if err := d.run.begin(ctx); err != nil {
			return err
		}
		return d.run.done(ctx, state.BackupRun{Snapshot: h.Snapshot, SnapshotAt: h.TakenAt, Detail: "destination move rehearsal passed without production activation"})
	}})
	for i := range plan.Steps {
		plan.Steps[i].Change += " for " + identity
	}
	return guardReleaseRestoreSteps(plan, t.Deploy.Store), nil
}
