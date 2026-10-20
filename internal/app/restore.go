package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// RestoreKind brings an app's data back from its bucket onto this
// machine, before the app is deployed here: the real thing, for a new
// machine or after a loss. The app's volumes and database must be empty.
const RestoreKind = "app.restore"

// RestoreDef is the Definition for RestoreKind.
type RestoreDef struct {
	Store    *state.Store
	Secrets  *secrets.Store
	StateDir string
}

// RestoreInput says which app and which snapshot; empty means the latest.
type RestoreInput struct {
	App      string `json:"app"`
	Snapshot string `json:"snapshot,omitempty"`
}

// Kind implements kernel.Definition.
func (RestoreDef) Kind() string { return RestoreKind }

// restoring is one restore being planned: what its steps share, and each
// step as a method.
type restoring struct {
	r        RestoreDef
	app      string
	asked    string // the snapshot asked for: an id, or latest
	staging  string
	run      *backupRun
	m        *manifest.Manifest
	snapshot *restic.Snapshot
}

// Plan implements kernel.Definition.
func (r RestoreDef) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in RestoreInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("restore input: %w", err)
	}
	if in.App == "" {
		return nil, errors.New("which app?")
	}
	if in.App == manifest.ReservedApp {
		return nil, errors.New("recover the machine with helios recover <source-machine> --snapshot <machine-snapshot> --identity-file <protected-file>; use --rehearsal to test privately")
	}
	if err := checkReleaseStoreAccess(ctx, r.Store, in.App); err != nil {
		return nil, err
	}
	if err := CheckMigrationAccess(r.Store.Path(), in.App); err != nil {
		return nil, err
	}
	if in.Snapshot == "" {
		in.Snapshot = "latest"
	}
	if rev, err := r.Store.RevisionWithStatus(ctx, in.App, state.RevisionActive); err != nil {
		return nil, err
	} else if rev != nil {
		return nil, fmt.Errorf("%s is deployed on this machine; a restore is for a machine that doesn't run it yet (helios remove %s --data first), or run helios drill %s to test the backup", in.App, in.App, in.App)
	}
	x := &restoring{r: r, app: in.App, asked: in.Snapshot, staging: filepath.Join(r.StateDir, "restore", in.App),
		run: &backupRun{store: r.Store, app: in.App, kind: state.BackupRunRestore}}
	// Recovery must use the same snapshot as fetch, even if a newer backup
	// appeared while the daemon was down, so every step after it reads the
	// one fetch pinned, and adopts the backup run again.
	plan := &kernel.Plan{Target: in.App, Recovery: kernel.Resume, Steps: []kernel.Step{
		x.fetchStep(),
		x.pinned(x.volumesStep()),
		x.pinned(x.databaseStep()),
		x.pinned(x.doneStep()),
	}}
	return guardReleaseRestoreSteps(plan, r.Store), nil
}

// id is the snapshot the restore reads: the one fetch found, or the one
// asked for.
func (x *restoring) id() string {
	if x.snapshot != nil {
		return x.snapshot.ID
	}
	return x.asked
}

// manifest is the app's manifest as the snapshot holds it, read once from
// what fetch staged and checked before anything is restored.
func (x *restoring) manifest() (*manifest.Manifest, error) {
	if x.m != nil {
		return x.m, nil
	}
	data, err := os.ReadFile(filepath.Join(x.staging, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("the fetched manifest is missing: %w", err)
	}
	var parsed manifest.Manifest
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	if err := parsed.Validate(); err != nil {
		return nil, fmt.Errorf("snapshot manifest: %w", err)
	}
	if parsed.App != x.app {
		return nil, fmt.Errorf("snapshot belongs to %s, not %s", parsed.App, x.app)
	}
	if err := requireRestoreSecrets(x.r.Secrets, &parsed); err != nil {
		return nil, err
	}
	x.m = &parsed
	return x.m, nil
}

// pinned wraps a step after fetch: it adopts the backup run and reads the
// snapshot fetch pinned before doing anything.
func (x *restoring) pinned(step kernel.Step) kernel.Step {
	apply := step.Apply
	step.Apply = func(ctx context.Context, out io.Writer) error {
		if err := x.run.begin(ctx); err != nil {
			return err
		}
		var err error
		x.snapshot, err = readRestoreSnapshot(x.staging)
		if err != nil {
			return x.run.fail(err)
		}
		return apply(ctx, out)
	}
	return step
}

func (x *restoring) fetchStep() kernel.Step {
	return kernel.Step{
		Name: "fetch", Change: fmt.Sprintf("fetch snapshot %s's manifest and database dump from the app's bucket", x.asked),
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := x.run.begin(ctx); err != nil {
				return err
			}
			e, err := docker.Connect(ctx)
			if err != nil {
				return x.run.fail(err)
			}
			defer e.Close()
			rs, _, err := openRepo(x.r.Secrets, e, x.app, x.app, nil)
			if err != nil {
				return x.run.fail(err)
			}
			if x.asked == "latest" {
				x.snapshot, err = rs.Latest(ctx, x.app)
				if errors.Is(err, restic.ErrNoRepository) {
					return x.run.fail(fmt.Errorf("no backups of %s in the storage this machine is set up with", x.app))
				}
				if err != nil {
					return x.run.fail(err)
				}
			}
			if err := resetDir(x.staging); err != nil {
				return x.run.fail(err)
			}
			id := x.id()
			if _, err := rs.Restore(ctx, id, x.app, []string{restic.DirMount(x.staging, false)}, restic.DataRoot+"/manifest.json", restic.DataRoot+"/postgres.dump", restic.DataRoot+"/"+initSnapshotDir); err != nil {
				return x.run.fail(err)
			}
			mf, err := x.manifest()
			if err != nil {
				return x.run.fail(err)
			}
			if x.snapshot == nil {
				x.snapshot = x.resolve(ctx, rs, id)
			}
			if err := writeRestoreSnapshot(x.staging, x.snapshot); err != nil {
				return x.run.fail(err)
			}
			when := ""
			if !x.snapshot.Time.IsZero() {
				when = " from " + x.snapshot.Time.Local().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(out, "snapshot %s%s: %s\n", short(id), when, describeData(mf))
			return nil
		},
	}
}

func (x *restoring) volumesStep() kernel.Step {
	return kernel.Step{
		Name: "volumes", Change: "restore the volumes the snapshot holds into empty volumes",
		Apply: func(ctx context.Context, out io.Writer) error {
			mf, err := x.manifest()
			if err != nil {
				return x.run.fail(err)
			}
			if len(mf.DataVolumes()) == 0 {
				fmt.Fprintln(out, "no volumes")
				return nil
			}
			e, err := docker.Connect(ctx)
			if err != nil {
				return x.run.fail(err)
			}
			defer e.Close()
			var mounts, includes []string
			for _, v := range mf.DataVolumes() {
				vol := docker.VolumeName(x.app, v)
				if err := e.EnsureVolume(ctx, vol); err != nil {
					return x.run.fail(err)
				}
				empty, err := e.VolumeEmpty(ctx, vol)
				if err != nil {
					return x.run.fail(err)
				}
				if !empty {
					return x.run.fail(fmt.Errorf("volume %s already has files; a restore is for an empty volume", v))
				}
			}
			for _, v := range mf.BackedUpVolumes() {
				mounts = append(mounts, restic.VolumeMount(docker.VolumeName(x.app, v), v, false))
				includes = append(includes, restic.VolumePath(v))
			}
			if len(mounts) > 0 {
				rs, _, err := openRepo(x.r.Secrets, e, x.app, x.app, nil)
				if err != nil {
					return x.run.fail(err)
				}
				if err := x.checkVolumesSpace(ctx, e, rs, mf.BackedUpVolumes(), out); err != nil {
					return x.run.fail(err)
				}
				sum, err := rs.Restore(ctx, x.id(), x.app, mounts, includes...)
				if err != nil {
					return x.run.fail(err)
				}
				fmt.Fprintf(out, "%d volume(s) restored: %d files, %s\n", len(mounts), sum.FilesRestored, HumanBytes(sum.BytesRestored))
			}
			createdEmpty(out, mf)
			return nil
		},
	}
}

// createdEmpty says which volumes a restore made without restoring
// anything into them, because the app's backups leave them out.
func createdEmpty(out io.Writer, m *manifest.Manifest) {
	for _, v := range m.VolumesOutOfBackups() {
		fmt.Fprintf(out, "volume %s created empty: backup: false leaves it out of backups\n", v)
	}
}

// createdEmptyNote names the volumes a restore created empty, for its
// record; with none, it is empty.
func createdEmptyNote(m *manifest.Manifest) string {
	var note string
	for _, v := range m.VolumesOutOfBackups() {
		note += "; volume " + v + " created empty"
	}
	return note
}

// resolve finds the snapshot fetched by id with the summary its backup
// recorded, which sizes the restore without restic walking its tree. A
// snapshot it can't find that way is known by its id alone.
func (x *restoring) resolve(ctx context.Context, rs restic.Runner, id string) *restic.Snapshot {
	if snaps, err := rs.Snapshots(ctx, x.app); err == nil {
		if found, err := resolveRecoverySnapshot(snaps, id); err == nil {
			return found
		}
	}
	return &restic.Snapshot{ID: id, ShortID: short(id)}
}

// checkVolumesSpace refuses a restore of the snapshot's volumes that can't
// fit on the disk under them, and otherwise says what that disk keeps
// free. Only a drill fails closed: a restore whose room can't be checked
// goes ahead, as it did before there was a check. The volumes must exist.
func (x *restoring) checkVolumesSpace(ctx context.Context, e *docker.Engine, r restoreSizer, volumes []string, out io.Writer) error {
	if len(volumes) == 0 {
		return nil
	}
	err := x.volumesFit(ctx, e, r, volumes, out)
	var space *SpaceError
	if errors.As(err, &space) {
		return fmt.Errorf("snapshot %s: %w; free space on this machine and try again", short(x.id()), err)
	}
	if err != nil {
		fmt.Fprintf(out, "restoring without a space check: %v\n", err)
	}
	return nil
}

// volumesFit is checkVolumesSpace's check, as a SpaceError when the
// snapshot's volumes can't fit.
func (x *restoring) volumesFit(ctx context.Context, e *docker.Engine, r restoreSizer, volumes []string, out io.Writer) error {
	need, err := x.volumesNeed(ctx, r)
	if err != nil {
		return err
	}
	var paths []string
	for _, v := range volumes {
		dir, err := e.VolumeMountpoint(ctx, docker.VolumeName(x.app, v))
		if err != nil {
			return fmt.Errorf("finding volume %s: %w", v, err)
		}
		paths = append(paths, dir)
	}
	if err := checkRestoreSpace(paths, need, 0); err != nil {
		return err
	}
	if left := spaceLeft(paths[0], need); left != "" {
		fmt.Fprintln(out, left)
	}
	return nil
}

// volumesNeed is how many bytes restoring the snapshot's volumes writes:
// the whole snapshot, less what fetch already staged from it. It counts
// no blocks for the files, so a refusal is a restore that certainly can't
// fit.
func (x *restoring) volumesNeed(ctx context.Context, r restoreSizer) (int64, error) {
	s := x.snapshot
	if s == nil {
		s = &restic.Snapshot{ID: x.id()}
	}
	size, err := snapshotSize(ctx, r, s, x.app)
	if err != nil {
		return 0, err
	}
	total := size.Bytes
	var staged int64
	err = filepath.WalkDir(x.staging, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() || path == filepath.Join(x.staging, "restore-snapshot.json") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		staged += info.Size()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("measuring the staged snapshot: %w", err)
	}
	return max(total-staged, 0), nil
}

func (x *restoring) databaseStep() kernel.Step {
	return kernel.Step{
		Name: "database", Change: "start the app's database and load the dump, when the snapshot holds one",
		Apply: func(ctx context.Context, out io.Writer) error {
			mf, err := x.manifest()
			if err != nil {
				return x.run.fail(err)
			}
			if mf.PostgresVersion() == "" {
				fmt.Fprintln(out, "no database")
				return nil
			}
			dump := filepath.Join(x.staging, "postgres.dump")
			if _, err := os.Stat(dump); err != nil {
				return x.run.fail(errors.New("the snapshot holds no postgres.dump"))
			}
			e, err := docker.Connect(ctx)
			if err != nil {
				return x.run.fail(err)
			}
			defer e.Close()
			if err := e.EnsureNetwork(ctx, docker.AppNetwork(x.app)); err != nil {
				return x.run.fail(err)
			}
			// Original credentials were required before touching any
			// volumes. Only constants and derived values may be filled in.
			if err := ensureAppSecrets(x.r.Secrets, mf, out); err != nil {
				return x.run.fail(err)
			}
			initDir, err := restoreInit(x.staging, x.r.StateDir, x.app)
			if err != nil {
				return x.run.fail(err)
			}
			if keepsOwners(mf) && initDir == "" {
				return x.run.fail(errors.New("the snapshot holds no database init scripts"))
			}
			if err := ensurePostgres(ctx, e, x.r.Secrets, mf, initDir, dump, out); err != nil {
				return x.run.fail(err)
			}
			return nil
		},
	}
}

func (x *restoring) doneStep() kernel.Step {
	return kernel.Step{
		Name: "done", Change: "record the restore; the app is ready to deploy",
		Apply: func(ctx context.Context, out io.Writer) error {
			result := state.BackupRun{Detail: "data restored; deploy the app to run it"}
			if mf, err := x.manifest(); err == nil {
				result.Detail = "data restored" + createdEmptyNote(mf) + "; deploy the app to run it"
			}
			if x.snapshot != nil {
				result.Snapshot, result.SnapshotAt = x.snapshot.ShortID, x.snapshot.Time
			} else {
				result.Snapshot = short(x.asked)
			}
			if err := x.run.done(ctx, result); err != nil {
				return err
			}
			if err := os.RemoveAll(x.staging); err != nil {
				fmt.Fprintf(out, "the staged snapshot at %s stays: %v\n", x.staging, err)
			}
			fmt.Fprintf(out, "%s's data is on this machine; deploy it with helios deploy <its source directory>\n", x.app)
			return nil
		},
	}
}

func writeRestoreSnapshot(staging string, snapshot *restic.Snapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(staging, "restore-snapshot.json"), data, 0o600)
}

func readRestoreSnapshot(staging string) (*restic.Snapshot, error) {
	data, err := os.ReadFile(filepath.Join(staging, "restore-snapshot.json"))
	if err != nil {
		return nil, fmt.Errorf("restore snapshot identity is missing; fetch the snapshot again: %w", err)
	}
	var snapshot restic.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.ID == "" || snapshot.ID == "latest" {
		return nil, errors.New("restore needs a pinned snapshot identity")
	}
	return &snapshot, nil
}

// describeData says what an app keeps, for a restore's first line.
func describeData(m *manifest.Manifest) string {
	if m.Data == nil {
		return "no data"
	}
	var parts []string
	if v := m.PostgresVersion(); v != "" {
		parts = append(parts, "postgres "+v)
	}
	if n := len(m.DataVolumes()); n == 1 {
		parts = append(parts, "1 volume")
	} else if n > 1 {
		parts = append(parts, fmt.Sprintf("%d volumes", n))
	}
	if len(parts) == 0 {
		return "no data"
	}
	return joinWords(parts)
}

func joinWords(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return parts[0] + " and " + parts[1]
	}
}

// initSnapshotDir is where a snapshot keeps the database's first-run
// scripts, which a restore on a new machine runs again before the dump.
const initSnapshotDir = "postgres-init"

// restoreInit puts the first-run scripts a snapshot holds where the
// database mounts them, and returns that directory, or "" without any.
func restoreInit(staging, stateDir, app string) (string, error) {
	from := filepath.Join(staging, initSnapshotDir)
	if !dirExists(from) {
		return "", nil
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return "", err
	}
	dir := InitDir(stateDir, app)
	if err := resetDir(dir); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), data, 0o644); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// requireRestoreSecrets prevents a restore from silently replacing encryption
// keys or credentials embedded in restored data. App snapshots deliberately
// omit secrets; recover the sealed store from the machine backup first.
func requireRestoreSecrets(store *secrets.Store, m *manifest.Manifest) error {
	values, _, err := store.LoadCurrent(m.App)
	if err != nil {
		return err
	}
	required := map[string]bool{}
	if m.Secrets != nil {
		for name, format := range m.Secrets.Generate {
			f, err := manifest.ParseSecretFormat(format)
			if err != nil {
				return err
			}
			if f.Kind != "value" {
				required[name] = true
			}
		}
	}
	for _, w := range m.Workloads {
		for _, name := range w.Secrets {
			required[name] = true
		}
	}
	if m.PostgresVersion() != "" {
		required[postgresPasswordName] = true
		for _, name := range m.Data.Postgres.Secrets {
			required[name] = true
		}
	}
	if m.HasObjects() {
		required[ObjectsUserName], required[ObjectsPasswordName] = true, true
	}
	if m.Secrets != nil {
		for name := range m.Secrets.Derive {
			delete(required, name)
		}
		for name, format := range m.Secrets.Generate {
			f, _ := manifest.ParseSecretFormat(format)
			if f.Kind == "value" {
				delete(required, name)
			}
		}
	}
	// The conventional URL can be rebuilt from the original service password.
	if m.InjectsDatabaseURL() {
		delete(required, DatabaseURLName)
	}
	var missing []string
	for _, name := range sortedKeys(required) {
		if values[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("restore %s's original secrets from the sealed machine backup before restoring data; missing: %s", m.App, strings.Join(missing, ", "))
	}
	return nil
}
