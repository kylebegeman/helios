package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

// ErrReleaseRestorePending distinguishes an intentional writer fence from state corruption.
var ErrReleaseRestorePending = errors.New("checkpoint restoration is pending")

// releaseCheckpointStep always has the same place in a data release plan. On
// replay it adopts the durable checkpoint, never substitutes a newer snapshot.
func (r *rollout) releaseCheckpointStep() kernel.Step {
	return kernel.Step{Name: "release-checkpoint", Change: "capture and retain a quiesced checkpoint before a data release with compatibility " + r.m.ReleaseCompatibility() + " data release", Apply: func(ctx context.Context, out io.Writer) error {
		boundary, err := r.store.ReleaseBoundary(ctx, r.m.App, r.revision)
		if err != nil {
			return err
		}
		if boundary != nil {
			return nil
		}
		previous, err := r.store.RevisionWithStatus(ctx, r.m.App, state.RevisionActive)
		if err != nil {
			return err
		}
		b := state.ReleaseBoundary{App: r.m.App, Revision: r.revision, Compatibility: r.m.ReleaseCompatibility(), StartedAt: time.Now().UTC()}
		if previous == nil {
			return r.store.PrepareReleaseBoundary(ctx, b)
		}
		b.PreviousRevision = previous.ID
		var m manifest.Manifest
		if err := json.Unmarshal(previous.Manifest, &m); err != nil {
			return err
		}
		if !m.HasData() {
			return r.store.PrepareReleaseBoundary(ctx, b)
		}
		storage, err := integration.LoadStorage(r.d.Secrets)
		if err != nil {
			return fmt.Errorf("data-changing release needs a rollback checkpoint: %w", err)
		}
		x := &backingUp{b: Backup{Store: r.store, Secrets: r.d.Secrets, StateDir: r.stateDir}, owner: m.App, target: m.App, bucket: storage.Bucket(m.App), staging: filepath.Join(r.stateDir, "release-checkpoints", m.App, r.revision), run: &backupRun{store: r.store, app: m.App, kind: "release-checkpoint"}}
		defer os.RemoveAll(x.staging)
		if err := x.appPrepareStep(previous, &m).Apply(ctx, out); err != nil {
			return err
		}
		e, repo, err := x.repo(ctx)
		if err != nil {
			return x.run.fail(err)
		}
		defer e.Close()
		if err := x.ensure(ctx, repo, out); err != nil {
			return x.run.fail(err)
		}
		repo.BackupTags = []string{restic.ReleaseCheckpointTag}
		mounts := []string{restic.DirMount(x.staging, true)}
		for _, v := range m.DataVolumes() {
			mounts = append(mounts, restic.VolumeMount(docker.VolumeName(m.App, v), v, true))
		}
		err = withQuiescedWriters(ctx, e, r.store.Path(), &m, out, func(ctx context.Context) error {
			if m.PostgresVersion() != "" {
				if err := x.dump(ctx, e, &m, out); err != nil {
					return err
				}
			}
			var err error
			x.summary, err = repo.Backup(ctx, m.App, mounts, restic.DataRoot)
			return err
		})
		if err != nil {
			return x.run.fail(err)
		}
		if !fullSnapshotID.MatchString(x.summary.SnapshotID) {
			return x.run.fail(errors.New("release checkpoint did not return an exact snapshot identity"))
		}
		b.Snapshot = x.summary.SnapshotID
		if err := r.store.PrepareReleaseBoundary(ctx, b); err != nil {
			return x.run.fail(err)
		}
		if err := x.run.done(ctx, state.BackupRun{Snapshot: b.Snapshot, SnapshotAt: x.summary.BackupStart, Files: x.summary.TotalFiles, Bytes: x.summary.TotalBytes, Detail: "retained rollback checkpoint before release " + r.revision}); err != nil {
			return err
		}
		fmt.Fprintf(out, "retained rollback checkpoint %s for revision %s\n", b.Snapshot, previous.ID)
		return nil
	}}
}

func (r *rollout) prepareReleaseBoundary(ctx context.Context) (*state.ReleaseBoundary, error) {
	b, err := r.store.ReleaseBoundary(ctx, r.m.App, r.revision)
	if err != nil {
		return nil, err
	}
	if b != nil {
		return b, nil
	}
	previous, err := r.store.RevisionWithStatus(ctx, r.m.App, state.RevisionActive)
	if err != nil {
		return nil, err
	}
	compatibility := r.m.ReleaseCompatibility()
	if !r.m.HasData() {
		compatibility = manifest.DataBackwardCompatible
	}
	b = &state.ReleaseBoundary{App: r.m.App, Revision: r.revision, Compatibility: compatibility, StartedAt: time.Now().UTC()}
	if previous != nil {
		b.PreviousRevision = previous.ID
	}
	if r.m.HasData() && previous != nil && compatibility != manifest.DataBackwardCompatible {
		return nil, errors.New("data-changing release has no prepared checkpoint; refusing to run release jobs")
	}
	if err := r.store.PrepareReleaseBoundary(ctx, *b); err != nil {
		return nil, err
	}
	return r.store.ReleaseBoundary(ctx, r.m.App, r.revision)
}

// unsafeReleaseBoundaries includes failed candidates that never went active.
func unsafeReleaseBoundaries(ctx context.Context, store *state.Store, target *state.Revision) ([]state.ReleaseBoundary, error) {
	boundaries, err := store.ReleaseBoundaries(ctx, target.App)
	if err != nil {
		return nil, err
	}
	var unsafe []state.ReleaseBoundary
	known := map[string]bool{}
	for _, b := range boundaries {
		known[b.Revision] = true
		if b.Revision == target.ID || b.Status == state.ReleaseRestored || b.Status == state.ReleasePrepared || b.Compatibility == manifest.DataBackwardCompatible || (!target.CreatedAt.IsZero() && b.StartedAt.Before(target.CreatedAt)) {
			continue
		}
		unsafe = append(unsafe, b)
	}
	// Existing releases from before boundary journaling are uncertain too. An
	// omitted compatibility policy must never silently become a safe rollback.
	revisions, err := store.Revisions(ctx, target.App)
	if err != nil {
		return nil, err
	}
	for _, rev := range revisions {
		if rev.ID == target.ID || known[rev.ID] || (!target.CreatedAt.IsZero() && !rev.CreatedAt.After(target.CreatedAt)) {
			continue
		}
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return nil, err
		}
		if m.HasData() && len(m.ReleaseWorkloads()) > 0 && m.ReleaseCompatibility() != manifest.DataBackwardCompatible {
			unsafe = append(unsafe, state.ReleaseBoundary{App: rev.App, Revision: rev.ID, Compatibility: manifest.DataCompatibilityUnknown, Status: state.ReleaseFailed, StartedAt: rev.CreatedAt})
		}
	}
	return unsafe, nil
}

func unsafeRollbackError(app string, unsafe []state.ReleaseBoundary) error {
	var details []string
	for _, b := range unsafe {
		detail := b.Revision + " (" + b.Compatibility + ", " + b.Status + ")"
		if b.Snapshot != "" {
			detail += "; checkpoint " + b.Snapshot
		}
		details = append(details, detail)
	}
	return fmt.Errorf("code-only rollback of %s is unsafe after %s; use helios rollback %s --to <checkpoint's previous revision> --restore-data <exact-checkpoint> to replace data and discard writes since that checkpoint", app, strings.Join(details, ", "), app)
}

func checkReleaseStoreAccess(ctx context.Context, store *state.Store, app string) error {
	boundaries, err := store.ReleaseBoundaries(ctx, app)
	if err != nil {
		return err
	}
	for _, b := range boundaries {
		if b.Status == state.ReleaseRestoring {
			return fmt.Errorf("%w: %s is fenced while checkpoint %s is restored; retry the same rollback --restore-data %s", ErrReleaseRestorePending, b.App, b.Snapshot, b.Snapshot)
		}
	}
	return nil
}

// CheckReleaseDataAccess blocks jobs and interactive commands during a
// persistent checkpoint restore, even after the daemon or host restarts.
func CheckReleaseDataAccess(ctx context.Context, stateFile, app string) error {
	if _, err := os.Stat(stateFile); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	store, err := state.OpenReadOnly(stateFile)
	if err != nil {
		return err
	}
	defer store.Close()
	return checkReleaseStoreAccess(ctx, store, app)
}

func removeReleaseRestoreContainers(ctx context.Context, e *docker.Engine, app string) error {
	owned, err := e.Owned(ctx)
	if err != nil {
		return err
	}
	for _, c := range owned {
		if c.Labels[docker.LabelApp] != app {
			continue
		}
		if err := e.SetRestartPolicy(ctx, c.ID, docker.RestartPolicy{Name: "no"}); err != nil && !docker.IsNotFound(err) {
			return err
		}
		if err := e.Remove(ctx, c.ID, 30*time.Second); err != nil {
			return err
		}
	}
	return nil
}

// EnforceReleaseRestores runs before startup recovery and background jobs. A
// restore fence never lets surviving Docker restart policies revive old code.
func EnforceReleaseRestores(ctx context.Context, store *state.Store) error {
	boundaries, err := store.ReleaseBoundaries(ctx, "")
	if err != nil {
		return err
	}
	apps := map[string]bool{}
	for _, b := range boundaries {
		if b.Status == state.ReleaseRestoring {
			apps[b.App] = true
		}
	}
	if len(apps) == 0 {
		return nil
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	for app := range apps {
		unlock, err := lockAppData(ctx, store.Path(), app, true)
		if err != nil {
			return err
		}
		err = removeReleaseRestoreContainers(ctx, e, app)
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// rollbackCheckpointStep is a single replayable data replacement. The durable
// fence admits no jobs between attempts, and each replay clears partial data
// before restoring the same exact checkpoint. Images/history/secrets survive.
func rollbackCheckpointStep(d Deploy, target *state.Revision, b state.ReleaseBoundary) kernel.Step {
	return kernel.Step{Name: "restore-release-checkpoint", Change: "replace live data with exact checkpoint " + b.Snapshot + " for revision " + target.ID + "; discard all writes since the checkpoint", Apply: func(ctx context.Context, out io.Writer) error {
		store := d.Store
		existing, err := store.ReleaseBoundary(ctx, b.App, b.Revision)
		if err != nil {
			return err
		}
		if existing != nil && existing.Status == state.ReleaseRestored {
			return nil
		}
		unlock, err := lockAppData(ctx, store.Path(), b.App, true)
		if err != nil {
			return err
		}
		defer unlock()
		stateDir := d.StateDir
		if stateDir == "" {
			stateDir = defaultStateDir
		}
		workspace := filepath.Join(stateDir, "rollback-restores", b.App, b.Revision)
		pinned, err := copyPinnedRehearsalSecrets(d.Secrets, target, workspace)
		if err != nil {
			return err
		}
		x := &restoring{r: RestoreDef{Store: store, Secrets: pinned, StateDir: stateDir}, app: b.App, asked: b.Snapshot, staging: filepath.Join(workspace, "restore"), run: &backupRun{store: store, app: b.App, kind: "rollback-restore"}}
		e, err := docker.Connect(ctx)
		if err != nil {
			return err
		}
		defer e.Close()
		repo, _, err := openRepo(pinned, e, b.App, b.App, nil)
		if err != nil {
			return err
		}
		snaps, err := repo.Snapshots(ctx, b.App)
		if err != nil {
			return err
		}
		snapshot, err := resolveRecoverySnapshot(snaps, b.Snapshot)
		if err != nil {
			return err
		}
		if snapshot.ID != b.Snapshot {
			return errors.New("rollback restore needs the exact checkpoint identity")
		}
		// The snapshot found here carries its summary, so the restore is
		// sized without listing the repository again while the app is down.
		x.snapshot = snapshot
		if err := x.fetchStep().Apply(ctx, out); err != nil {
			return err
		}
		m, err := x.manifest()
		if err != nil {
			return err
		}
		var expected manifest.Manifest
		if err := json.Unmarshal(target.Manifest, &expected); err != nil {
			return err
		}
		if manifestDigest(m) != manifestDigest(&expected) {
			return x.run.fail(errors.New("checkpoint manifest does not match the requested rollback revision"))
		}
		if err := store.BeginReleaseRestore(ctx, b.App, b.Revision, b.Snapshot); err != nil {
			return err
		}
		// Restore the original current values as a new secret version, preserving
		// all prior versions and the target revision's pinned credentials.
		values, err := d.Secrets.Load(b.App, target.SecretsVersion)
		if err != nil {
			return err
		}
		current, _, err := d.Secrets.LoadCurrent(b.App)
		if err != nil {
			return err
		}
		changes := map[string]*string{}
		for name := range current {
			if _, ok := values[name]; !ok {
				changes[name] = nil
			}
		}
		for name, value := range values {
			changes[name] = new(value)
		}
		if _, err := d.Secrets.SetAll(b.App, changes); err != nil {
			return err
		}
		if err := removeReleaseRestoreContainers(ctx, e, b.App); err != nil {
			return err
		}
		// Remove every declared volume from all revisions, including additions made
		// by a failed release. Nothing outside this app's named data is touched.
		volumes := map[string]bool{}
		revisions, err := store.Revisions(ctx, b.App)
		if err != nil {
			return err
		}
		for _, rev := range revisions {
			var rm manifest.Manifest
			if err := json.Unmarshal(rev.Manifest, &rm); err != nil {
				return err
			}
			for _, v := range rm.DataVolumes() {
				volumes[docker.VolumeName(b.App, v)] = true
			}
			if rm.PostgresVersion() != "" {
				volumes[docker.VolumeName(b.App, postgresWorkload)] = true
			}
		}
		for _, volume := range sortedKeys(volumes) {
			if _, err := e.RemoveVolume(ctx, volume); err != nil {
				return err
			}
		}
		if err := x.volumesStep().Apply(ctx, out); err != nil {
			return err
		}
		if err := x.databaseStep().Apply(ctx, out); err != nil {
			return err
		}
		if m.HasObjects() {
			if err := ensureObjects(ctx, e, pinned, m, out); err != nil {
				return err
			}
		}
		if err := store.CompleteReleaseRestore(ctx, b, time.Now().UTC()); err != nil {
			return err
		}
		if err := x.run.done(ctx, state.BackupRun{Snapshot: b.Snapshot, SnapshotAt: snapshot.Time, Detail: "checkpoint restored before older code activation"}); err != nil {
			return err
		}
		if err := os.RemoveAll(workspace); err != nil {
			return err
		}
		fmt.Fprintf(out, "checkpoint %s restored; revision %s may now start\n", b.Snapshot, target.ID)
		return nil
	}}
}
