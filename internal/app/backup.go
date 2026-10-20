package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

// BackupKind snapshots an app's data into its own bucket: a database
// dump and every volume, deduplicated and encrypted, with retention.
const BackupKind = "app.backup"

// Backup is the Definition for BackupKind.
type Backup struct {
	Store    *state.Store
	Secrets  *secrets.Store
	StateDir string
	// Hostname names the machine, for its own backup.
	Hostname func() string
	// Profile is the machine's profile file, kept in its own backup when
	// there is one.
	Profile string
	// Deadlines bound the repository calls; zero fields take restic's
	// defaults. Tests shorten them.
	Deadlines restic.Deadlines
}

// RetentionDeferred marks a run whose snapshot was kept while retention
// failed or ran out of time. The next backup applies retention again, and
// the watcher reports retention that stays deferred.
const RetentionDeferred = "retention deferred"

// BackupInput says what to back up: an app, or helios's own name for the
// machine's state.
type BackupInput struct {
	App string `json:"app"`
}

// Kind implements kernel.Definition.
func (Backup) Kind() string { return BackupKind }

// MachineTarget is the host name the machine's own snapshots carry.
func MachineTarget(hostname string) string { return "machine-" + hostname }

// openRepo prepares restic for one bucket.
func openRepo(sec *secrets.Store, e *docker.Engine, owner, bucketName string, log func(string)) (restic.Runner, *integration.Storage, error) {
	st, err := integration.LoadStorage(sec)
	if err != nil {
		return restic.Runner{}, nil, fmt.Errorf("backups need the storage integration: %w", err)
	}
	bucket := st.Bucket(bucketName)
	return restic.Runner{Engine: e, Owner: owner, Log: log, Repo: restic.Repo{Repository: st.Repository(bucket), Password: st.Password, Env: st.Env()}}, st, nil
}

// backupRun is the record a backup keeps as its steps go by.
type backupRun struct {
	store *state.Store
	app   string
	kind  string
	id    int64
}

// begin starts a run record, or adopts one a previous attempt left open.
func (r *backupRun) begin(ctx context.Context) error {
	if r.id != 0 {
		return nil
	}
	if last, err := r.store.LastBackupRun(ctx, r.app, r.kind); err == nil && last != nil && !last.Finished() {
		r.id = last.ID
		return nil
	}
	id, err := r.store.StartBackupRun(ctx, r.app, r.kind, time.Now().UTC())
	r.id = id
	return err
}

// fail records a failed run and returns the error.
func (r *backupRun) fail(err error) error {
	if r.id != 0 {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = r.store.FinishBackupRun(cleanup, r.id, state.BackupRun{FinishedAt: time.Now().UTC(), Error: err.Error()})
	}
	return err
}

// done records a successful run.
func (r *backupRun) done(ctx context.Context, result state.BackupRun) error {
	result.OK = true
	result.FinishedAt = time.Now().UTC()
	return r.store.FinishBackupRun(ctx, r.id, result)
}

// Plan implements kernel.Definition.
func (b Backup) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in BackupInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("backup input: %w", err)
	}
	if in.App == "" {
		return nil, errors.New("which app?")
	}
	st, err := integration.LoadStorage(b.Secrets)
	if err != nil {
		return nil, fmt.Errorf("backups need the storage integration: %w", err)
	}
	if in.App == manifest.ReservedApp {
		if b.Store != nil {
			if err := checkReleaseStoreAccess(ctx, b.Store, ""); err != nil {
				return nil, err
			}
		}
		return b.machinePlan(st)
	}
	if b.Store != nil {
		if err := CheckMigrationAccess(b.Store.Path(), in.App); err != nil {
			return nil, err
		}
		if err := checkReleaseStoreAccess(ctx, b.Store, in.App); err != nil {
			return nil, err
		}
	}
	rev, err := b.Store.RevisionWithStatus(ctx, in.App, state.RevisionActive)
	if err != nil {
		return nil, err
	}
	if rev == nil {
		return nil, fmt.Errorf("%s isn't deployed", in.App)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return nil, err
	}
	if !m.HasData() {
		return nil, fmt.Errorf("%s keeps no data; there is nothing to back up", in.App)
	}
	if m.Backup != nil && m.Backup.Off {
		return nil, fmt.Errorf("backups are off for %s in its helios.yaml", in.App)
	}
	return b.appPlan(st, rev, &m)
}

// backingUp is one backup as its plan is built and applied: where it
// stages, which repository it writes, and the record it keeps. An app's
// backup and the machine's own share it; only their first two steps differ.
type backingUp struct {
	b Backup
	// owner holds the storage secrets; target names the bucket and tags
	// the snapshots.
	owner, target string
	staging       string
	bucket        string
	keep          restic.Keep
	run           *backupRun
	summary       *restic.Summary
	// Receipts stay outside shared staging so another backup cannot replace
	// the operation and snapshot this run must finish. Empty for other users
	// of the capture helpers, which keep their own durable snapshot records.
	receiptDir string
	receipt    *backupSnapshotReceipt
	// detail says what a finished run holds.
	detail func() string
}

func (b Backup) appPlan(st *integration.Storage, rev *state.Revision, m *manifest.Manifest) (*kernel.Plan, error) {
	app := rev.App
	keep := m.KeepPolicy()
	x := &backingUp{
		b: b, owner: app, target: app, receiptDir: filepath.Join(b.StateDir, "backups", ".receipts"),
		staging: filepath.Join(b.StateDir, "backups", app),
		bucket:  st.Bucket(app),
		keep:    restic.Keep{Daily: keep.Daily, Weekly: keep.Weekly, Monthly: keep.Monthly},
		run:     &backupRun{store: b.Store, app: app, kind: state.BackupRunBackup},
	}
	x.detail = func() string {
		detail := fmt.Sprintf("%d files, %s", x.summary.TotalFiles, HumanBytes(x.summary.TotalBytes))
		if m.PostgresVersion() != "" {
			detail = "database and " + detail
		}
		return detail
	}
	return &kernel.Plan{Target: app, Recovery: kernel.Resume, Steps: []kernel.Step{
		x.appPrepareStep(rev, m),
		x.appSnapshotStep(rev, m),
		x.retentionStep(),
	}}, nil
}

// machinePlan backs up what makes this machine itself: the state store,
// the sealed secrets and the host profile, into a bucket of its own. The
// secrets key stays on the machine; the recovery identity opens them.
func (b Backup) machinePlan(st *integration.Storage) (*kernel.Plan, error) {
	hostname := b.Hostname()
	target := MachineTarget(hostname)
	x := &backingUp{
		b: b, owner: manifest.ReservedApp, target: target, receiptDir: filepath.Join(b.StateDir, "backups", ".receipts"),
		staging: filepath.Join(b.StateDir, "backups", "machine"),
		bucket:  st.Bucket(target),
		keep:    restic.Keep{Daily: 7, Weekly: 4, Monthly: 6},
		run:     &backupRun{store: b.Store, app: manifest.ReservedApp, kind: state.BackupRunBackup},
		detail:  func() string { return "state, secrets and profile" },
	}
	return &kernel.Plan{Target: "this machine", Recovery: kernel.Resume, Steps: []kernel.Step{
		x.machinePrepareStep(hostname),
		x.machineSnapshotStep(),
		x.retentionStep(),
	}}, nil
}

// backupSnapshotReceipt binds a run and its complete capture result to one
// kernel operation. It survives staging cleanup and a completed run, because
// the retention step may succeed before the kernel journals that success.
type backupSnapshotReceipt struct {
	Operation  string          `json:"operation"`
	Owner      string          `json:"owner"`
	Target     string          `json:"target"`
	Bucket     string          `json:"bucket"`
	Kind       string          `json:"kind"`
	RunID      int64           `json:"run_id"`
	RunStarted time.Time       `json:"run_started"`
	Started    bool            `json:"capture_started,omitempty"`
	Summary    *restic.Summary `json:"summary,omitempty"`
}

func (x *backingUp) receiptPath(ctx context.Context) string {
	identity, _ := json.Marshal([]string{kernel.OperationID(ctx), x.owner, x.target, x.run.kind})
	hash := sha256.Sum256(identity)
	return filepath.Join(x.receiptDir, hex.EncodeToString(hash[:])+".json")
}

func (x *backingUp) readReceipt(ctx context.Context) (*backupSnapshotReceipt, error) {
	path := x.receiptPath(ctx)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("backup capture receipt must be a plain file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var receipt backupSnapshotReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, fmt.Errorf("read backup capture receipt: %w", err)
	}
	if receipt.Operation != kernel.OperationID(ctx) || receipt.Owner != x.owner || receipt.Target != x.target || receipt.Bucket != x.bucket || receipt.Kind != x.run.kind || receipt.RunID <= 0 || (x.run.id != 0 && receipt.RunID != x.run.id) {
		return nil, errors.New("backup capture receipt belongs to another operation or run")
	}
	if s := receipt.Summary; s != nil && (!receipt.Started || !fullSnapshotID.MatchString(s.SnapshotID) || s.BackupStart.IsZero() || s.TotalFiles < 0 || s.TotalBytes < 0) {
		return nil, errors.New("backup capture receipt has no exact snapshot identity")
	}
	run, err := x.run.store.BackupRun(ctx, receipt.RunID)
	if err != nil {
		return nil, fmt.Errorf("read backup capture run: %w", err)
	}
	if run.App != x.run.app || run.Kind != receipt.Kind || !run.StartedAt.Equal(receipt.RunStarted) {
		return nil, errors.New("backup capture receipt belongs to another recorded run")
	}
	if run.OK && (receipt.Summary == nil || run.Snapshot != receipt.Summary.SnapshotID) {
		return nil, errors.New("backup capture receipt differs from its completed run")
	}
	return &receipt, nil
}

func (x *backingUp) beginBackup(ctx context.Context) error {
	if x.receiptDir == "" {
		return x.run.begin(ctx)
	}
	receipt, err := x.readReceipt(ctx)
	if err != nil {
		return err
	}
	if receipt == nil {
		if kernel.Attempt(ctx) > 1 {
			return errors.New("interrupted backup has no capture receipt; inspect the repository and start a fresh backup")
		}
		started := time.Now().UTC().Truncate(time.Millisecond)
		id, err := x.run.store.StartBackupRun(ctx, x.run.app, x.run.kind, started)
		if err != nil {
			return err
		}
		x.run.id = id
		receipt = &backupSnapshotReceipt{Operation: kernel.OperationID(ctx), Owner: x.owner, Target: x.target, Bucket: x.bucket, Kind: x.run.kind, RunID: id, RunStarted: started}
		if err := writeRecoveryJSON(x.receiptPath(ctx), receipt); err != nil {
			return x.run.fail(fmt.Errorf("persist backup capture receipt: %w", err))
		}
	}
	x.receipt, x.run.id, x.summary = receipt, receipt.RunID, receipt.Summary
	return nil
}

// Only prepare may create a receipt. A legacy operation whose prepare step
// already succeeded must not claim shared staging when its snapshot resumes.
func (x *backingUp) preparedBackup(ctx context.Context) error {
	if x.receiptDir == "" {
		return x.run.begin(ctx)
	}
	receipt, err := x.readReceipt(ctx)
	if err != nil {
		return err
	}
	if receipt == nil {
		return errors.New("backup has no prepared capture receipt; inspect the repository and start a fresh backup")
	}
	x.receipt, x.run.id, x.summary = receipt, receipt.RunID, receipt.Summary
	return nil
}

func (x *backingUp) requireSnapshotStaging(ctx context.Context) error {
	if x.receiptDir == "" {
		return nil
	}
	if x.receipt.Started {
		return errors.New("backup capture was interrupted without an exact snapshot receipt; inspect the repository and start a fresh backup")
	}
	owned, err := x.ownsStaging(ctx)
	if err != nil {
		return err
	}
	if !owned {
		return errors.New("backup staging belongs to another operation; start a fresh backup")
	}
	return nil
}

func (x *backingUp) captureSnapshot(ctx context.Context, r restic.Runner, mounts []string) error {
	if x.receiptDir != "" {
		if err := x.requireSnapshotStaging(ctx); err != nil {
			return err
		}
		x.receipt.Started = true
		if err := writeRecoveryJSON(x.receiptPath(ctx), x.receipt); err != nil {
			return err
		}
	}
	summary, err := r.Backup(ctx, x.target, mounts, restic.DataRoot)
	if err != nil {
		return err
	}
	if x.receiptDir != "" {
		if summary == nil || !fullSnapshotID.MatchString(summary.SnapshotID) || summary.BackupStart.IsZero() {
			return errors.New("backup did not return an exact snapshot identity")
		}
		x.receipt.Summary = summary
		if err := writeRecoveryJSON(x.receiptPath(ctx), x.receipt); err != nil {
			return fmt.Errorf("persist exact backup snapshot %s: %w", summary.SnapshotID, err)
		}
	}
	x.summary = summary
	return nil
}

func (x *backingUp) resumeBackup(ctx context.Context) (bool, error) {
	if x.receiptDir == "" {
		if x.summary == nil {
			return false, errors.New("backup has no exact snapshot receipt; start a fresh backup")
		}
		return false, x.run.begin(ctx)
	}
	receipt, err := x.readReceipt(ctx)
	if err != nil {
		return false, err
	}
	if receipt == nil || receipt.Summary == nil {
		return false, errors.New("backup has no exact snapshot receipt; inspect the repository and start a fresh backup")
	}
	x.receipt, x.run.id, x.summary = receipt, receipt.RunID, receipt.Summary
	run, err := x.run.store.BackupRun(ctx, receipt.RunID)
	return run.OK && run.Finished(), err
}

func (x *backingUp) ownsStaging(ctx context.Context) (bool, error) {
	data, err := os.ReadFile(x.staging + ".operation.json")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var owner backupSnapshotReceipt
	if err := json.Unmarshal(data, &owner); err != nil {
		return false, fmt.Errorf("read backup staging owner: %w", err)
	}
	return owner.Operation == kernel.OperationID(ctx) && owner.RunID == x.run.id && owner.Owner == x.owner && owner.Target == x.target && owner.Bucket == x.bucket && owner.Kind == x.run.kind, nil
}

func (x *backingUp) discardStaging(ctx context.Context) error {
	if x.receiptDir != "" {
		owned, err := x.ownsStaging(ctx)
		if err != nil || !owned {
			return err
		}
	}
	if err := os.RemoveAll(x.staging); err != nil {
		return err
	}
	if x.receiptDir != "" {
		return os.Remove(x.staging + ".operation.json")
	}
	return nil
}

// repo connects to Docker and opens the backup's repository. The caller
// closes the engine.
func (x *backingUp) repo(ctx context.Context) (*docker.Engine, restic.Runner, error) {
	e, err := docker.Connect(ctx)
	if err != nil {
		return nil, restic.Runner{}, err
	}
	r, _, err := openRepo(x.b.Secrets, e, x.owner, x.target, nil)
	if err != nil {
		e.Close()
		return nil, restic.Runner{}, err
	}
	r.Deadlines = x.b.Deadlines
	return e, r, nil
}

// ensure makes the bucket and its repository the first time. On an existing
// repository it clears stale locks, such as the exclusive lock of a prune
// stopped at its deadline or killed by hand, which would otherwise refuse
// this backup. restic's plain unlock removes only locks nobody holds; a
// failure is reported and the backup goes on to say what it finds.
func (x *backingUp) ensure(ctx context.Context, r restic.Runner, out io.Writer) error {
	created, err := r.Ensure(ctx)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(out, "made bucket %s and its repository\n", x.bucket)
		return nil
	}
	if err := r.Unlock(ctx); err != nil {
		if ctx.Err() != nil {
			return err
		}
		fmt.Fprintf(out, "could not clear stale repository locks: %v\n", err)
	}
	return nil
}

func (x *backingUp) appPrepareStep(rev *state.Revision, m *manifest.Manifest) kernel.Step {
	change := "write the manifest"
	if m.PostgresVersion() != "" {
		change += " and preserve its initialization scripts"
	}
	change += fmt.Sprintf(" for revision %s, secret version %d, manifest %s", rev.ID, rev.SecretsVersion, backupManifestHash(rev.Manifest))
	return kernel.Step{
		Name: "prepare", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := x.beginBackup(ctx); err != nil {
				return err
			}
			if err := resetDir(x.staging); err != nil {
				return x.run.fail(err)
			}
			if x.receiptDir != "" {
				if err := writeRecoveryJSON(x.staging+".operation.json", x.receipt); err != nil {
					return x.run.fail(err)
				}
			}
			if err := os.WriteFile(filepath.Join(x.staging, "manifest.json"), append(rev.Manifest, '\n'), 0o600); err != nil {
				return x.run.fail(err)
			}
			// The volumes mount over these inside the read-only tree, so
			// the mountpoints have to be there already.
			for _, v := range m.BackedUpVolumes() {
				if err := os.MkdirAll(filepath.Join(x.staging, "volumes", v), 0o700); err != nil {
					return x.run.fail(err)
				}
			}
			if m.PostgresVersion() == "" {
				return nil
			}
			// The database's first-run scripts go with it: a restore on a
			// new machine runs them again before it loads the dump.
			if init := InitDir(x.b.StateDir, x.target); keepsOwners(m) && dirExists(init) {
				if out, err := exec.CommandContext(ctx, "cp", "-a", init, filepath.Join(x.staging, initSnapshotDir)).CombinedOutput(); err != nil {
					return x.run.fail(fmt.Errorf("copy the database's first-run scripts: %s", strings.TrimSpace(string(out))))
				}
			}
			return nil
		},
	}
}

func (x *backingUp) appSnapshotStep(rev *state.Revision, m *manifest.Manifest) kernel.Step {
	app := x.target
	return kernel.Step{
		Name: "snapshot", Change: fmt.Sprintf("pause writers, dump and snapshot consistent data into bucket %s, then resume (30m limit)", x.bucket) + leftOut(m),
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := checkReleaseStoreAccess(ctx, x.b.Store, app); err != nil {
				return err
			}
			if err := x.preparedBackup(ctx); err != nil {
				return err
			}
			if x.receiptDir != "" && x.summary != nil {
				e, err := docker.Connect(ctx)
				if err != nil {
					return x.run.fail(err)
				}
				defer e.Close()
				unlock, err := lockAppData(ctx, x.b.Store.Path(), app, true)
				if err != nil {
					return x.run.fail(err)
				}
				defer unlock()
				return resumeWriters(ctx, e, quiesceFile(x.b.Store.Path(), app))
			}
			if err := x.requireSnapshotStaging(ctx); err != nil {
				return x.run.fail(err)
			}
			e, r, err := x.repo(ctx)
			if err != nil {
				return x.run.fail(err)
			}
			defer e.Close()
			if err := x.ensure(ctx, r, out); err != nil {
				return x.run.fail(err)
			}
			mounts := snapshotMounts(x.staging, app, m)
			err = withQuiescedWriters(ctx, e, x.b.Store.Path(), m, out, func(ctx context.Context) error {
				if err := checkReleaseStoreAccess(ctx, x.b.Store, app); err != nil {
					return err
				}
				if err := x.requireSnapshotStaging(ctx); err != nil {
					return err
				}
				if m.PostgresVersion() != "" {
					if err := x.dump(ctx, e, m, out); err != nil {
						return err
					}
				}
				active, err := x.b.Store.RevisionWithStatus(ctx, app, state.RevisionActive)
				if err != nil {
					return err
				}
				if active == nil || active.ID != rev.ID || active.SecretsVersion != rev.SecretsVersion || backupManifestHash(active.Manifest) != backupManifestHash(rev.Manifest) {
					return errors.New("the active revision changed after this backup was prepared; start a fresh app backup")
				}
				if err := writeAppBackupProvenance(x.staging, *rev, time.Now().UTC()); err != nil {
					return err
				}
				return x.captureSnapshot(ctx, r, mounts)
			})
			if err != nil {
				return x.run.fail(err)
			}
			_ = x.b.Store.RecordIntegrationUse(ctx, integration.StorageName, "backup "+app, time.Now().UTC())
			fmt.Fprintf(out, "snapshot %s: %d files, %s, %s new\n", short(x.summary.SnapshotID), x.summary.TotalFiles, HumanBytes(x.summary.TotalBytes), HumanBytes(x.summary.DataAdded))
			return nil
		},
	}
}

// snapshotMounts are what an app snapshot reads: the staging tree, read
// only, with each volume in backups over its mountpoint.
func snapshotMounts(staging, app string, m *manifest.Manifest) []string {
	mounts := []string{restic.DirMount(staging, true)}
	for _, v := range m.BackedUpVolumes() {
		mounts = append(mounts, restic.VolumeMount(docker.VolumeName(app, v), v, true))
	}
	return mounts
}

// leftOut names the volumes an app snapshot leaves out, for its plan;
// with none, it is empty and the plan reads as it always has.
func leftOut(m *manifest.Manifest) string {
	out := m.VolumesOutOfBackups()
	switch len(out) {
	case 0:
		return ""
	case 1:
		return "; volume " + out[0] + " is left out (backup: false)"
	default:
		return "; volumes " + strings.Join(out, ", ") + " are left out (backup: false)"
	}
}

// dump writes the app's database into the staging tree.
func (x *backingUp) dump(ctx context.Context, e *docker.Engine, m *manifest.Manifest, out io.Writer) error {
	values, _, err := x.b.Secrets.LoadCurrent(x.target)
	if err != nil {
		return err
	}
	svc, err := postgresService(m, values, "")
	if err != nil {
		return err
	}
	size, err := dumpDatabase(ctx, e, svc, filepath.Join(x.staging, "postgres.dump"))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "database dumped: %s\n", HumanBytes(size))
	return nil
}

func (x *backingUp) machinePrepareStep(hostname string) kernel.Step {
	b := x.b
	return kernel.Step{
		Name: "prepare", Change: "copy the state store, the sealed secrets and the host profile",
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := checkReleaseStoreAccess(ctx, x.b.Store, ""); err != nil {
				return err
			}
			if err := x.beginBackup(ctx); err != nil {
				return err
			}
			if err := resetDir(x.staging); err != nil {
				return x.run.fail(err)
			}
			if x.receiptDir != "" {
				if err := writeRecoveryJSON(x.staging+".operation.json", x.receipt); err != nil {
					return x.run.fail(err)
				}
			}
			if err := b.Store.BackupTo(ctx, filepath.Join(x.staging, "state.db")); err != nil {
				return x.run.fail(fmt.Errorf("copy the state store: %w", err))
			}
			if secretsDir := b.Secrets.Dir; dirExists(secretsDir) {
				if out, err := exec.CommandContext(ctx, "cp", "-a", secretsDir, filepath.Join(x.staging, "secrets")).CombinedOutput(); err != nil {
					return x.run.fail(fmt.Errorf("copy the secrets: %s", strings.TrimSpace(string(out))))
				}
			}
			for _, f := range []string{b.Profile, b.Secrets.KeyPath + ".pub"} {
				if f == "" {
					continue
				}
				if data, err := os.ReadFile(f); err == nil {
					if err := os.WriteFile(filepath.Join(x.staging, filepath.Base(f)), data, 0o600); err != nil {
						return x.run.fail(err)
					}
				}
			}
			info, _ := json.MarshalIndent(map[string]any{"hostname": hostname, "bedrock": version.Current().Version, "taken_at": time.Now().UTC()}, "", "  ")
			if err := os.WriteFile(filepath.Join(x.staging, "machine.json"), append(info, '\n'), 0o600); err != nil {
				return x.run.fail(err)
			}
			if err := b.prepareMachineRecoveryCatalog(ctx, hostname, x.staging, out); err != nil {
				return x.run.fail(err)
			}
			fmt.Fprintln(out, "state, secrets, profile and workload images copied")
			return nil
		},
	}
}

func (x *backingUp) machineSnapshotStep() kernel.Step {
	return kernel.Step{
		Name: "snapshot", Change: fmt.Sprintf("snapshot them into bucket %s", x.bucket),
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := checkReleaseStoreAccess(ctx, x.b.Store, ""); err != nil {
				return err
			}
			if err := x.preparedBackup(ctx); err != nil {
				return err
			}
			if x.receiptDir != "" && x.summary != nil {
				return nil
			}
			if err := x.requireSnapshotStaging(ctx); err != nil {
				return x.run.fail(err)
			}
			e, r, err := x.repo(ctx)
			if err != nil {
				return x.run.fail(err)
			}
			defer e.Close()
			if err := x.ensure(ctx, r, out); err != nil {
				return x.run.fail(err)
			}
			if err := x.captureSnapshot(ctx, r, []string{restic.DirMount(x.staging, true)}); err != nil {
				return x.run.fail(err)
			}
			_ = x.b.Store.RecordIntegrationUse(ctx, integration.StorageName, "backup of the machine", time.Now().UTC())
			fmt.Fprintf(out, "snapshot %s: %d files, %s\n", short(x.summary.SnapshotID), x.summary.TotalFiles, HumanBytes(x.summary.TotalBytes))
			return nil
		},
	}
}

// retentionStep forgets snapshots the policy no longer keeps, then closes
// the run record with the snapshot this backup took. The snapshot already
// exists, so retention that fails or runs out of time is deferred rather
// than failing the backup: the run is recorded with its snapshot and a
// note, the operation lock is released, and the next backup applies the
// policy again. Only the operation's own interruption leaves the step to
// be resumed.
func (x *backingUp) retentionStep() kernel.Step {
	return kernel.Step{
		// Change is part of the plan digest, which recovery compares: an
		// operation interrupted under an older release must still resume.
		Name: "retention", Change: fmt.Sprintf("keep %d daily, %d weekly and %d monthly snapshots", x.keep.Daily, x.keep.Weekly, x.keep.Monthly),
		Apply: func(ctx context.Context, out io.Writer) error {
			complete, err := x.resumeBackup(ctx)
			if err != nil {
				return err
			}
			if complete {
				return x.discardStaging(ctx)
			}
			removed, err := x.forget(ctx)
			detail := x.detail()
			if err != nil {
				if ctx.Err() != nil {
					return x.run.fail(err)
				}
				reason := firstLine(err.Error())
				detail += "; " + RetentionDeferred + ": " + reason
				fmt.Fprintf(out, "%s: %s\nthe snapshot is kept, and the next backup applies retention again\n", RetentionDeferred, reason)
			}
			s := x.summary
			if err := x.run.done(ctx, state.BackupRun{Snapshot: s.SnapshotID, SnapshotAt: s.BackupStart, Files: s.TotalFiles, Bytes: s.TotalBytes, Detail: detail}); err != nil {
				return err
			}
			if err := x.discardStaging(ctx); err != nil {
				return err
			}
			switch {
			case removed > 0:
				fmt.Fprintf(out, "removed %d old snapshot(s)\n", removed)
			case err == nil:
				fmt.Fprintln(out, "nothing old enough to remove")
			}
			return nil
		},
	}
}

// forget applies the retention policy to this backup's repository.
func (x *backingUp) forget(ctx context.Context) (int, error) {
	e, r, err := x.repo(ctx)
	if err != nil {
		return 0, err
	}
	defer e.Close()
	return r.Forget(ctx, x.target, x.keep)
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// dumpDatabase writes an app's database as a pg_dump custom-format file.
func dumpDatabase(ctx context.Context, e *docker.Engine, p pgService, path string) (int64, error) {
	f, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	stderr, err := e.ExecToEnv(ctx, p.Container, map[string]string{"PGPASSWORD": p.Password}, f, "pg_dump", "-Fc", "-h", "127.0.0.1", "-U", p.User, "-d", p.Database)
	f.Close()
	if err != nil {
		_ = os.Remove(path + ".tmp")
		return 0, fmt.Errorf("pg_dump: %w\n%s", err, tail(stderr, 3))
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func resetDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o700)
}

func dirExists(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// short is a snapshot's id as restic shows it: its first eight characters.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// HumanBytes says a size the way people do.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
