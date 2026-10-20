package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

const MoveStageKind = "app.move.stage"
const revisionStaged state.RevisionStatus = "staged"

// MoveStage restores the exact final snapshot and checks a destination revision
// without admitting jobs, workers, published ports or production routes.
type MoveStage struct {
	Deploy   Deploy
	Hostname func() string
}

type MoveStageInput struct {
	Source   string  `json:"source"`
	Manifest string  `json:"manifest,omitempty"`
	Revision string  `json:"revision"`
	Commit   string  `json:"commit,omitempty"`
	Handoff  Handoff `json:"handoff"`
}

var snapshotIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var migrationIDPattern = regexp.MustCompile(`^move-[a-f0-9]{16}$`)

func checkMigrationHandoff(h Handoff, target, phase string) error {
	if !manifest.ValidApp(h.App) || h.Phase != phase || !migrationIDPattern.MatchString(h.Migration) || h.From == "" || h.To == "" || h.From == h.To || h.Revision == "" || !snapshotIDPattern.MatchString(h.ManifestDigest) {
		return fmt.Errorf("safe move requires a complete %s handoff from move %s", phase, phase)
	}
	if target != "" && h.To != target {
		return fmt.Errorf("this handoff targets %s, but this machine identifies as %s", h.To, target)
	}
	if h.HasData && !snapshotIDPattern.MatchString(h.Snapshot) {
		return errors.New("safe move needs an exact snapshot ID; latest is not a migration recovery point")
	}
	return nil
}

func (s MoveStage) Kind() string { return MoveStageKind }

func (s MoveStage) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in MoveStageInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	h := in.Handoff
	target := ""
	if s.Hostname != nil {
		target = s.Hostname()
	} else {
		target, _ = os.Hostname()
	}
	if err := checkMigrationHandoff(h, target, "final"); err != nil {
		return nil, err
	}
	if err := checkReleaseStoreAccess(ctx, s.Deploy.Store, h.App); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(in.Source) || !revisionPattern.MatchString(in.Revision) {
		return nil, errors.New("move stage needs an absolute source directory and a target revision")
	}
	name := in.Manifest
	if name == "" {
		name = manifest.FileName
	}
	m, err := manifest.LoadFile(in.Source, name)
	if err != nil {
		return nil, err
	}
	if m.App != h.App || manifestDigest(m) != h.ManifestDigest || m.HasData() != h.HasData {
		return nil, errors.New("target source manifest differs from the final source handoff")
	}
	commit := sourceCommit(ctx, in.Source)
	if in.Commit != "" {
		if commit != "" && commit != in.Commit {
			return nil, errors.New("provided source commit differs from the target checkout")
		}
		commit = in.Commit
	}
	if h.SourceCommit != "" && commit != h.SourceCommit {
		return nil, fmt.Errorf("target source commit %s differs from captured source commit %s", commit, h.SourceCommit)
	}
	if err := s.Deploy.CloudflareOnly.checkRoutes(m); err != nil {
		return nil, err
	}
	if err := CheckRouteConflicts(ctx, s.Deploy.Store, m); err != nil {
		return nil, err
	}
	if err := CheckDeploySecrets(m, s.Deploy.Secrets); err != nil {
		return nil, err
	}
	if len(m.GuardedRoutes()) > 0 {
		guard, err := loomGuard(s.Deploy.Secrets)
		if err != nil {
			return nil, err
		}
		if guard == nil {
			return nil, errors.New("guarded staging requires the loom integration before cutover")
		}
	}
	if err := checkMovedOriginPullTrust(ctx, s.Deploy.Store, m, s.Deploy.Secrets, time.Now(), "stage again"); err != nil {
		return nil, err
	}
	if m.HasData() {
		st, err := integration.LoadStorage(s.Deploy.Secrets)
		if err != nil {
			return nil, err
		}
		if err := h.Check(m.App, st); err != nil {
			return nil, err
		}
	}
	record, err := readMigration(s.Deploy.Store.Path(), m.App)
	if err != nil {
		return nil, err
	}
	if record != nil && (record.Role != "target" || !sameMigration(record.Handoff, h) || record.Handoff.Snapshot != h.Snapshot || record.TargetRevision != in.Revision) {
		return nil, errors.New("target already holds another migration; do not overwrite its data")
	}
	if record != nil && (record.Phase == "cutting-over" || record.Phase == "cutover") {
		return nil, errors.New("target cutover has already begun; retry move cutover instead of staging its live data again")
	}
	if active, err := s.Deploy.Store.RevisionWithStatus(ctx, m.App, state.RevisionActive); err != nil {
		return nil, err
	} else if active != nil {
		return nil, fmt.Errorf("%s is already active here; safe staging requires a clean target", m.App)
	}
	if previous, err := s.Deploy.Store.GetRevision(ctx, m.App, in.Revision); err == nil && (manifestDigestFromRaw(previous.Manifest) != h.ManifestDigest || previous.Source != commit) {
		return nil, errors.New("target revision already belongs to different source")
	}
	stateDir := s.Deploy.StateDir
	if stateDir == "" {
		stateDir = filepath.Dir(s.Deploy.Store.Path())
	}
	manifestJSON, _ := json.Marshal(m)
	r := &rollout{d: s.Deploy, m: m, manifestJSON: manifestJSON, revision: in.Revision, from: &buildFrom{source: in.Source, commit: commit}, store: s.Deploy.Store, stateDir: stateDir, images: map[string]string{}, containers: map[string]string{}, hosts: m.Hosts()}
	for _, name := range m.WorkloadNames() {
		if stageServes(m.Workloads[name]) {
			r.containers[name] = docker.ContainerName(m.App, name, in.Revision)
		}
	}
	identity := fmt.Sprintf("%s, %s to %s, source %s, target %s, exact snapshot %s", h.Migration, h.From, h.To, h.Revision, in.Revision, orStateless(h.Snapshot))
	plan := &kernel.Plan{Target: m.App, Recovery: kernel.Resume}
	plan.Steps = append(plan.Steps, kernel.Step{Name: "stage-fence", Change: "reserve clean target data and refuse other writers for " + identity,
		Apply: func(ctx context.Context, out io.Writer) error {
			unlock, err := lockAppData(ctx, r.store.Path(), m.App, true)
			if err != nil {
				return err
			}
			defer unlock()
			existing, err := readMigration(r.store.Path(), m.App)
			if err != nil {
				return err
			}
			if existing != nil {
				if existing.Role == "target" && sameMigration(existing.Handoff, h) && existing.Handoff.Snapshot == h.Snapshot && existing.TargetRevision == in.Revision {
					if existing.Phase == "cutting-over" || existing.Phase == "cutover" {
						return errors.New("target cutover has already begun; retry move cutover instead of staging its live data again")
					}
					return nil
				}
				return errors.New("target migration changed")
			}
			e, err := r.connect(ctx)
			if err != nil {
				return err
			}
			owned, err := e.Owned(ctx)
			if err != nil {
				return err
			}
			for _, container := range owned {
				if container.Labels[docker.LabelApp] == m.App && container.Running {
					return fmt.Errorf("target still has running container %s for %s; staging requires an empty, stopped destination", container.Name, m.App)
				}
			}
			return saveMigration(r.store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: "restoring", TargetRevision: in.Revision, RestoringVolumes: map[string]bool{}, RestoredVolumes: map[string]bool{}})
		}})
	if h.HasData {
		x := &restoring{r: RestoreDef{Store: r.store, Secrets: r.d.Secrets, StateDir: stateDir}, app: m.App, asked: h.Snapshot, staging: filepath.Join(stateDir, "moves", m.App, "restore"), run: &backupRun{store: r.store, app: m.App, kind: state.BackupRunRestore}}
		fetch := x.fetchStep()
		fetch.Name = "restore-fetch"
		fetch.Change += " for " + identity
		apply := fetch.Apply
		fetch.Apply = func(ctx context.Context, out io.Writer) error {
			if err := apply(ctx, out); err != nil {
				return err
			}
			snapshotManifest, err := x.manifest()
			if err != nil {
				return err
			}
			if manifestDigest(snapshotManifest) != h.ManifestDigest {
				return errors.New("snapshot manifest differs from the captured source revision")
			}
			return nil
		}
		plan.Steps = append(plan.Steps, fetch, x.pinned(moveRestoreVolumes(x, h, in.Revision)), x.pinned(moveRestoreDatabase(x, h, in.Revision)))
		plan.Steps = append(plan.Steps, x.pinned(kernel.Step{Name: "restore-record", Change: "record completion of exact final restore " + h.Snapshot, Apply: func(ctx context.Context, out io.Writer) error {
			detail := "exact final move snapshot restored under destination fence"
			if mf, err := x.manifest(); err == nil {
				detail += createdEmptyNote(mf)
			}
			return x.run.done(ctx, state.BackupRun{Snapshot: h.Snapshot, SnapshotAt: h.TakenAt, Detail: detail})
		}}))
	}
	recordStep := r.recordStep()
	recordStep.Change += " staged for " + identity
	plan.Steps = append(plan.Steps, recordStep)
	if m.PostgresVersion() != "" || m.HasObjects() || m.Secrets != nil {
		plan.Steps = append(plan.Steps, r.secretsStep())
	}
	if m.Data != nil {
		plan.Steps = append(plan.Steps, r.dataStep())
	}
	for _, group := range buildGroups(m) {
		plan.Steps = append(plan.Steps, r.imageStep(group))
	}
	plan.Steps = append(plan.Steps, moveStageStart(r), moveStageReady(r), moveStageChecks(r))
	plan.Steps = append(plan.Steps, kernel.Step{Name: "staged", Change: "record validated target revision without activating routes or DNS for " + identity,
		Apply: func(ctx context.Context, out io.Writer) error {
			record, err := targetMigration(r.store.Path(), h, in.Revision)
			if err != nil {
				return err
			}
			if err := r.store.SetRevisionStatus(ctx, m.App, in.Revision, revisionStaged); err != nil {
				return err
			}
			record.Phase = "staged"
			if err := saveMigration(r.store.Path(), record); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s staged at %s; source remains frozen, target routes and DNS require move cutover\n", m.App, in.Revision)
			return nil
		}})
	return guardReleaseRestoreSteps(plan, s.Deploy.Store), nil
}

func manifestDigestFromRaw(raw json.RawMessage) string {
	var m manifest.Manifest
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return manifestDigest(&m)
}
func stageServes(w manifest.Workload) bool {
	return w.Kind == manifest.Web || w.Kind == manifest.Static
}
func orStateless(snapshot string) string {
	if snapshot == "" {
		return "none (stateless)"
	}
	return snapshot
}

func targetMigration(stateFile string, h Handoff, revision string) (*migrationRecord, error) {
	record, err := readMigration(stateFile, h.App)
	if err != nil {
		return nil, err
	}
	if record == nil || record.Role != "target" || !sameMigration(record.Handoff, h) || record.Handoff.Snapshot != h.Snapshot || record.TargetRevision != revision {
		return nil, errors.New("target migration identity or exact snapshot changed")
	}
	return record, nil
}

func moveStageStart(r *rollout) kernel.Step {
	return kernel.Step{Name: "stage-start", Change: "start web and static workloads on restored target data with no published ports, workers, cron or release jobs", Apply: func(ctx context.Context, out io.Writer) error {
		e, err := r.connect(ctx)
		if err != nil {
			return err
		}
		if err := e.EnsureNetwork(ctx, docker.AppNetwork(r.m.App)); err != nil {
			return err
		}
		if err := e.EnsureNetwork(ctx, docker.EdgeNetwork); err != nil {
			return err
		}
		rev, values, _, err := r.pin(ctx)
		if err != nil {
			return err
		}
		for _, name := range r.m.WorkloadNames() {
			w := r.m.Workloads[name]
			if !stageServes(w) {
				continue
			}
			spec, err := containerSpec(r.m, name, w, r.revision, rev.Images[name], values)
			if err != nil {
				return err
			}
			spec.Publish = nil
			spec.Restart = false
			u, err := isolate(ctx, e, &spec, w, rev.Images[name])
			if err != nil {
				return err
			}
			if err := ownVolumes(ctx, e, r.m, w, u, out); err != nil {
				return err
			}
			if err := e.Run(ctx, spec); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s staged for direct checks\n", spec.Name)
		}
		return nil
	}}
}

func moveStageReady(r *rollout) kernel.Step {
	return kernel.Step{Name: "stage-ready", Change: "wait for staged web and static workloads to answer directly", Apply: func(ctx context.Context, out io.Writer) error {
		e, err := r.connect(ctx)
		if err != nil {
			return err
		}
		for _, name := range r.m.WorkloadNames() {
			w := r.m.Workloads[name]
			if stageServes(w) {
				if err := waitReady(ctx, e, r.containers[name], w); err != nil {
					return fmt.Errorf("staged %s: %w", name, err)
				}
			}
		}
		return nil
	}}
}

func moveStageChecks(r *rollout) kernel.Step {
	return kernel.Step{Name: "stage-checks", Change: "assert application content directly while production routes and DNS still remain on the source", Apply: func(ctx context.Context, out io.Writer) error {
		e, err := r.connect(ctx)
		if err != nil {
			return err
		}
		for _, c := range verificationChecks(r.m).application {
			if err := runCheckDirect(ctx, e, r.m, r.containers, c); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s: staged application check passed\n", c.URL)
		}
		return nil
	}}
}

// MoveTargetRevision is stable across planning, approval and replay.
func MoveTargetRevision(h Handoff) string {
	snapshot := h.Snapshot
	if snapshot == "" {
		snapshot = "stateless"
	}
	if len(snapshot) > 8 {
		snapshot = snapshot[:8]
	}
	return h.Migration + "-" + snapshot
}
