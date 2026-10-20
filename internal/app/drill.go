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
	"strconv"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// DrillKind proves a backup: it restores the latest snapshot beside the
// app, into scratch volumes and a scratch database, starts the app's
// long-running workloads on them, checks what came back, and cleans up.
const DrillKind = "app.drill"

// Drill is the Definition for DrillKind.
type Drill struct {
	Store    *state.Store
	Secrets  *secrets.Store
	StateDir string
}

// DrillInput says which app and which snapshot; empty means the latest.
type DrillInput struct {
	App      string `json:"app"`
	Snapshot string `json:"snapshot,omitempty"`
}

// Kind implements kernel.Definition.
func (Drill) Kind() string { return DrillKind }

// drillAdvice is what to do about a drill without room for its restore.
func drillAdvice(app string) string {
	return "free space, or skip it: helios drill " + app + " --skip-next --reason <text>"
}

// drillNames are the scratch things a drill makes.
type drillNames struct {
	dir, network, postgres, postgresVolume, objects string
	volumes                                         map[string]string // app volume name -> drill volume
	containers                                      map[string]string // workload -> drill container
}

func newDrillNames(stateDir string, m *manifest.Manifest) drillNames {
	app := m.App
	// A dot can't appear in an app's name, so these never collide with
	// another app's volumes, which the cleanup would otherwise remove.
	prefix := drillPrefix(app)
	n := drillNames{
		dir:            filepath.Join(stateDir, "drills", app),
		network:        prefix,
		postgres:       prefix + ".postgres",
		postgresVolume: prefix + ".postgres",
		objects:        prefix + ".objects",
		volumes:        map[string]string{},
		containers:     map[string]string{},
	}
	for _, v := range m.DataVolumes() {
		n.volumes[v] = prefix + "." + v
	}
	for _, w := range m.WorkloadNames() {
		if m.Workloads[w].LongRunning() {
			n.containers[w] = prefix + "." + w
		}
	}
	return n
}

// cleanup removes everything a drill made. It never fails loudly: what
// it can't remove, the next drill removes first.
func (n drillNames) cleanup(e *docker.Engine) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, c := range n.containers {
		_ = e.Remove(ctx, c, 5*time.Second)
	}
	_ = e.Remove(ctx, n.postgres, 10*time.Second)
	_ = e.Remove(ctx, n.objects, 10*time.Second)
	_ = e.RemoveNetwork(ctx, n.network)
	_, _ = e.RemoveVolume(ctx, n.postgresVolume)
	for _, v := range n.volumes {
		_, _ = e.RemoveVolume(ctx, v)
	}
	_ = os.RemoveAll(n.dir)
}

// drillState is one drill being planned: what its steps share, and each
// step as a method.
type drillState struct {
	dr       Drill
	app      string
	snapshot string // as asked: an id, or latest
	rev      *state.Revision
	m        manifest.Manifest
	run      *backupRun
	names    drillNames
	found    *restic.Snapshot
	restored *restic.RestoreSummary
	details  []string
	started  time.Time
	advice   string // what a restore that won't fit tells the operator to do
}

func (d *drillState) abort(e *docker.Engine, err error) error {
	d.names.cleanup(e)
	return d.run.fail(err)
}

// Plan implements kernel.Definition.
func (dr Drill) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in DrillInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("drill input: %w", err)
	}
	if in.App == "" {
		return nil, errors.New("which app?")
	}
	if in.Snapshot == "" {
		in.Snapshot = "latest"
	}
	rev, err := dr.Store.RevisionWithStatus(ctx, in.App, state.RevisionActive)
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
		return nil, fmt.Errorf("%s keeps no data; there is nothing to drill", in.App)
	}
	for name, workload := range m.Workloads {
		if workload.LongRunning() && workload.Privileged {
			return nil, fmt.Errorf("cannot safely drill privileged workload %s: it could escape the scratch network", name)
		}
	}
	d := &drillState{dr: dr, app: in.App, snapshot: in.Snapshot, rev: rev, m: m,
		run: &backupRun{store: dr.Store, app: in.App, kind: state.BackupRunDrill}, names: newDrillNames(dr.StateDir, &m),
		advice: drillAdvice(in.App)}
	plan := &kernel.Plan{Target: in.App, Recovery: kernel.Resume}
	plan.Steps = append(plan.Steps, d.restoreStep())
	if len(d.names.volumes) > 0 {
		plan.Steps = append(plan.Steps, d.sqliteStep())
	}
	// The scratch services answer, on the drill's own network, to the
	// names the app's services have on the app's: the app's secrets,
	// DATABASE_URL and every derived URL included, work unchanged against
	// the restored copies, and can't reach the real ones.
	if m.PostgresVersion() != "" {
		plan.Steps = append(plan.Steps, d.databaseStep())
	}
	if m.HasObjects() {
		plan.Steps = append(plan.Steps, d.objectsStep())
	}
	if len(d.names.containers) > 0 {
		plan.Steps = append(plan.Steps, d.appStep())
	}
	plan.Steps = append(plan.Steps, d.cleanupStep())
	return plan, nil
}

func (d *drillState) restoreStep() kernel.Step {
	return kernel.Step{
		Name: "restore", Change: fmt.Sprintf("restore snapshot %s into scratch volumes beside the app", d.snapshot),
		Apply: func(ctx context.Context, out io.Writer) error {
			d.started = time.Now().UTC()
			if err := d.run.begin(ctx); err != nil {
				return err
			}
			e, err := docker.Connect(ctx)
			if err != nil {
				return d.run.fail(err)
			}
			defer e.Close()
			d.names.cleanup(e)
			if err := os.MkdirAll(d.names.dir, 0o700); err != nil {
				return d.abort(e, err)
			}
			r, _, err := openRepo(d.dr.Secrets, e, d.app, d.app, nil)
			if err != nil {
				return d.abort(e, err)
			}
			if d.found, err = d.pick(ctx, r); err != nil {
				return d.abort(e, err)
			}
			mounts := []string{restic.DirMount(d.names.dir, false)}
			for _, v := range sortedKeys(d.names.volumes) {
				if err := os.MkdirAll(filepath.Join(d.names.dir, "volumes", v), 0o700); err != nil {
					return d.abort(e, err)
				}
				if err := e.EnsureVolume(ctx, d.names.volumes[v]); err != nil {
					return d.abort(e, err)
				}
				mounts = append(mounts, restic.VolumeMount(d.names.volumes[v], v, false))
			}
			if err := d.checkSpace(ctx, e, r); err != nil {
				return d.abort(e, err)
			}
			d.restored, err = r.Restore(ctx, d.found.ID, d.app, mounts)
			if err != nil {
				return d.abort(e, err)
			}
			d.details = append(d.details, fmt.Sprintf("%d files (%s) restored", d.restored.FilesRestored, HumanBytes(d.restored.BytesRestored)))
			fmt.Fprintf(out, "snapshot %s from %s: %s\n", d.found.ShortID, d.found.Time.Local().Format("2006-01-02 15:04"), d.details[0])
			return nil
		},
	}
}

// checkSpace refuses a restore that would leave less than the reserve
// free on the disk under the drill's files, any of its scratch volumes or
// its scratch database: a drill that fills the disk takes the running app
// down with it.
func (d *drillState) checkSpace(ctx context.Context, e *docker.Engine, r restoreSizer) error {
	size, err := snapshotSize(ctx, r, d.found, d.app)
	if err != nil {
		return err
	}
	paths := []string{d.names.dir}
	for _, v := range sortedKeys(d.names.volumes) {
		dir, err := e.VolumeMountpoint(ctx, d.names.volumes[v])
		if err != nil {
			return fmt.Errorf("finding scratch volume %s: %w", v, err)
		}
		paths = append(paths, dir)
	}
	// The dump loads into the scratch database's volume, which can be on
	// another disk from the drill's files. The database step starts on the
	// volume made here, and cleanup removes it.
	if d.m.PostgresVersion() != "" {
		if err := e.EnsureVolume(ctx, d.names.postgresVolume); err != nil {
			return err
		}
		dir, err := e.VolumeMountpoint(ctx, d.names.postgresVolume)
		if err != nil {
			return fmt.Errorf("finding the scratch database's volume: %w", err)
		}
		paths = append(paths, dir)
	}
	err = checkRestoreSpace(paths, allocated(size), restoreFreeReserve)
	var space *SpaceError
	if errors.As(err, &space) && d.advice != "" {
		return fmt.Errorf("snapshot %s: %w; %s", short(d.found.ID), err, d.advice)
	}
	if err != nil {
		return fmt.Errorf("snapshot %s: %w", short(d.found.ID), err)
	}
	return nil
}

// restoreSizer counts what restoring a snapshot writes. restic.Runner is
// one.
type restoreSizer interface {
	RestoreSize(ctx context.Context, snapshot, host string) (restic.Size, error)
}

// snapshotSize is what restoring a snapshot writes: what its backup
// recorded reading, or restic's count of its tree when the snapshot
// doesn't say. Without either, nothing is restored.
func snapshotSize(ctx context.Context, r restoreSizer, s *restic.Snapshot, host string) (restic.Size, error) {
	if s.Summary != nil && s.Summary.TotalBytes > 0 {
		return restic.Size{Bytes: s.Summary.TotalBytes, Files: max(s.Summary.TotalFiles, 0)}, nil
	}
	n, err := r.RestoreSize(ctx, s.ID, host)
	if err != nil {
		return restic.Size{}, fmt.Errorf("counting what snapshot %s restores: %w", short(s.ID), err)
	}
	return n, nil
}

// pick finds the snapshot the drill restores: the latest, or the one
// whose id starts with what was asked for.
func (d *drillState) pick(ctx context.Context, r restic.Runner) (*restic.Snapshot, error) {
	if d.snapshot == "latest" {
		found, err := r.Latest(ctx, d.app)
		if errors.Is(err, restic.ErrNoRepository) {
			return nil, fmt.Errorf("%s has no backups yet; run helios backup %s first", d.app, d.app)
		}
		return found, err
	}
	snaps, err := r.Snapshots(ctx, d.app)
	if err != nil {
		return nil, err
	}
	return resolveRecoverySnapshot(snaps, d.snapshot)
}

// sqliteMax is how many SQLite databases one drill checks. The rest are
// counted in the drill's record, unchecked.
const sqliteMax = 64

// sqliteNamed is how many checked databases the drill's record names.
const sqliteNamed = 3

func (d *drillState) sqliteStep() kernel.Step {
	return kernel.Step{
		Name: "sqlite", Change: "run an integrity check on every SQLite database in the scratch volumes",
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return d.run.fail(err)
			}
			defer e.Close()
			var checked, uncheckable []string
			unchecked := 0
			for _, v := range sortedKeys(d.names.volumes) {
				dir, err := e.VolumeMountpoint(ctx, d.names.volumes[v])
				if err != nil {
					return d.abort(e, fmt.Errorf("finding scratch volume %s: %w", v, err))
				}
				found, err := sqliteFiles(dir)
				if err != nil {
					return d.abort(e, fmt.Errorf("looking for SQLite databases in volume %s: %w", v, err))
				}
				for _, file := range found {
					if len(checked) == sqliteMax {
						unchecked++
						continue
					}
					where := fmt.Sprintf("%s in volume %s", file, v)
					problems, err := state.IntegrityCheck(ctx, filepath.Join(dir, file))
					if name, ok := appCollation(err); ok {
						// SQLite can't check an index without its
						// collation, and only the app defines this one.
						uncheckable = append(uncheckable, fmt.Sprintf("%s, which sorts by its app's collation %s", where, name))
						continue
					}
					if err != nil {
						return d.abort(e, fmt.Errorf("the restored SQLite database %s won't open: %w", where, err))
					}
					if len(problems) > 0 {
						return d.abort(e, fmt.Errorf("the restored SQLite database %s is corrupt: %s", where, strings.Join(problems, "; ")))
					}
					checked = append(checked, where)
				}
			}
			detail := sqliteDetail(checked, uncheckable, unchecked)
			d.details = append(d.details, detail)
			fmt.Fprintln(out, detail)
			return nil
		},
	}
}

// appCollation is the collation a check stopped at because the database
// sorts by one its app defines, which no other program has.
func appCollation(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	_, name, ok := strings.Cut(err.Error(), "no such collation sequence: ")
	name, _, _ = strings.Cut(name, " (")
	return name, ok && name != ""
}

// sqliteDetail sums up a drill's SQLite checks for its record: the
// databases checked, those only their app can check, and how many past
// the cap went unchecked.
func sqliteDetail(checked, uncheckable []string, unchecked int) string {
	var b strings.Builder
	switch len(checked) {
	case 0:
		b.WriteString("no SQLite databases")
	case 1:
		b.WriteString("1 SQLite database intact (" + checked[0])
	default:
		fmt.Fprintf(&b, "%d SQLite databases intact (%s", len(checked), strings.Join(checked[:min(len(checked), sqliteNamed)], ", "))
		if len(checked) > sqliteNamed {
			fmt.Fprintf(&b, " and %d more", len(checked)-sqliteNamed)
		}
	}
	if len(checked) > 0 {
		b.WriteString(")")
	}
	if len(uncheckable) > 0 {
		b.WriteString("; not checked: " + strings.Join(uncheckable, "; "))
	}
	if unchecked > 0 {
		fmt.Fprintf(&b, "; %d more past the first %d not checked", unchecked, sqliteMax)
	}
	return b.String()
}

// sqliteHeader starts every SQLite database file.
const sqliteHeader = "SQLite format 3\x00"

// sqliteFiles finds the SQLite databases under dir, by their header, as
// paths relative to it, sorted. It follows no links, and leaves out the
// logs and journals beside a database, which SQLite reads with it.
func sqliteFiles(dir string) ([]string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var found []string
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if strings.HasSuffix(path, suffix) {
				return nil
			}
		}
		f, err := root.Open(filepath.FromSlash(path))
		if err != nil {
			return err
		}
		defer f.Close()
		header := make([]byte, len(sqliteHeader))
		if _, err := io.ReadFull(f, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if string(header) == sqliteHeader {
			found = append(found, filepath.FromSlash(path))
		}
		return nil
	})
	return found, err
}

func (d *drillState) databaseStep() kernel.Step {
	verifySQL, atLeast := d.m.VerifyQuery()
	change := "start a scratch database and load the dump"
	if verifySQL != "" {
		change += ", then run the verify query"
	}
	return kernel.Step{
		Name: "database", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return d.run.fail(err)
			}
			defer e.Close()
			if err := e.EnsureInternalNetwork(ctx, d.names.network); err != nil {
				return d.abort(e, err)
			}
			values, err := d.dr.Secrets.Load(d.app, d.rev.SecretsVersion)
			if err != nil {
				return d.abort(e, err)
			}
			// The first-run scripts make the roles the dump names.
			svc, err := postgresService(&d.m, values, filepath.Join(d.names.dir, initSnapshotDir))
			if err != nil {
				return d.abort(e, err)
			}
			if !keepsOwners(&d.m) {
				svc.InitDir = ""
			} else if !dirExists(svc.InitDir) {
				return d.abort(e, errors.New("the snapshot holds no database init scripts"))
			}
			svc.Container, svc.Volume, svc.Network = d.names.postgres, d.names.postgresVolume, d.names.network
			svc.Labels = map[string]string{docker.LabelApp: d.app, docker.LabelWorkload: "drill"}
			svc.Aliases = []string{PostgresContainer(d.app)}
			if err := svc.start(ctx, e, out); err != nil {
				return d.abort(e, err)
			}
			dump := filepath.Join(d.names.dir, "postgres.dump")
			if _, err := os.Stat(dump); err != nil {
				return d.abort(e, errors.New("the snapshot holds no postgres.dump"))
			}
			tables, err := restoreDump(ctx, e, svc, dump, keepsOwners(&d.m))
			if err != nil {
				return d.abort(e, err)
			}
			if n, _ := strconv.Atoi(tables); n == 0 {
				return d.abort(e, errors.New("the restored database has no tables"))
			}
			d.details = append(d.details, tables+" tables")
			fmt.Fprintf(out, "database restored: %s tables\n", tables)
			if verifySQL == "" {
				return nil
			}
			got, err := scalar(ctx, e, svc, verifySQL)
			if err != nil {
				return d.abort(e, fmt.Errorf("verify query: %w", err))
			}
			n, err := strconv.Atoi(got)
			if err != nil {
				return d.abort(e, fmt.Errorf("the verify query returned %q, not a number", got))
			}
			if n < atLeast {
				return d.abort(e, fmt.Errorf("the verify query returned %d, below %d", n, atLeast))
			}
			d.details = append(d.details, fmt.Sprintf("verify query %d (at least %d)", n, atLeast))
			fmt.Fprintf(out, "verify query: %d\n", n)
			return nil
		},
	}
}

func (d *drillState) objectsStep() kernel.Step {
	return kernel.Step{
		Name: "objects", Change: "start a scratch object store on the restored files",
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return d.run.fail(err)
			}
			defer e.Close()
			if err := e.EnsureInternalNetwork(ctx, d.names.network); err != nil {
				return d.abort(e, err)
			}
			values, err := d.dr.Secrets.Load(d.app, d.rev.SecretsVersion)
			if err != nil {
				return d.abort(e, err)
			}
			o := objectsServiceFor(&d.m, values)
			o.Container, o.Volume, o.Network = d.names.objects, d.names.volumes[manifest.ObjectsVolume], d.names.network
			if empty, err := e.VolumeEmpty(ctx, o.Volume); err != nil {
				return d.abort(e, err)
			} else if empty {
				return d.abort(e, errors.New("the snapshot holds no object store files"))
			}
			o.Labels = map[string]string{docker.LabelApp: d.app, docker.LabelWorkload: "drill"}
			o.Aliases = []string{ObjectsContainer(d.app)}
			if err := o.start(ctx, e, out); err != nil {
				return d.abort(e, err)
			}
			d.details = append(d.details, "object store answered")
			fmt.Fprintln(out, "object store answered on the restored files")
			return nil
		},
	}
}

func (d *drillState) appStep() kernel.Step {
	return kernel.Step{
		Name: "app", Change: "start the app's long-running workloads on the restored data and wait for them",
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return d.run.fail(err)
			}
			defer e.Close()
			if err := e.EnsureInternalNetwork(ctx, d.names.network); err != nil {
				return d.abort(e, err)
			}
			values, err := d.dr.Secrets.Load(d.app, d.rev.SecretsVersion)
			if err != nil {
				return d.abort(e, err)
			}
			for _, name := range sortedKeys(d.names.containers) {
				if err := d.startScratch(ctx, e, name, values); err != nil {
					return d.abort(e, err)
				}
			}
			// Dependencies must all be running before any readiness probe.
			for _, name := range sortedKeys(d.names.containers) {
				started := time.Now()
				if err := waitReady(ctx, e, d.names.containers[name], d.m.Workloads[name]); err != nil {
					return d.abort(e, fmt.Errorf("%s on the restored data: %w", name, err))
				}
				took := time.Since(started).Round(100 * time.Millisecond)
				d.details = append(d.details, fmt.Sprintf("%s answered in %s", name, took))
				fmt.Fprintf(out, "%s answered in %s\n", name, took)
			}
			return nil
		},
	}
}

// startScratch starts one long-running workload on the scratch network
// and volumes, never restarted, isolated as the real one is.
func (d *drillState) startScratch(ctx context.Context, e *docker.Engine, name string, values map[string]string) error {
	w := d.m.Workloads[name]
	image := d.rev.Images[name]
	if image == "" {
		return fmt.Errorf("no image recorded for %s", name)
	}
	spec, err := drillSpec(&d.m, d.rev.ID, name, image, values, d.names)
	if err != nil {
		return err
	}
	u, err := isolate(ctx, e, &spec, w, image)
	if err != nil {
		return err
	}
	mountpoint := func(volume string) (string, error) { return e.VolumeMountpoint(ctx, volume) }
	if err := restoredWritable(name, w, u, d.names.volumes, mountpoint); err != nil {
		return err
	}
	return e.Run(ctx, spec)
}

// restoredWritable fails the drill when a workload can't write what was
// restored into its volumes. Such a backup brings back an app that answers
// its health check and then fails its first save, which is no recovery.
func restoredWritable(name string, w manifest.Workload, u docker.User, volumes map[string]string, mountpoint func(string) (string, error)) error {
	var problems []string
	seen := map[string]bool{}
	for _, mt := range w.Mounts {
		if seen[mt.Volume] {
			continue
		}
		seen[mt.Volume] = true
		dir, err := mountpoint(volumes[mt.Volume])
		if err != nil {
			return fmt.Errorf("finding %s's restored volume %s: %w", name, mt.Volume, err)
		}
		x, err := docker.UnwritableBy(dir, u)
		if err != nil {
			return fmt.Errorf("checking %s's restored volume %s: %w", name, mt.Volume, err)
		}
		if why := x.Problem(name, u, mt.Volume); why != "" {
			problems = append(problems, why)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s; the backup holds files the app can't save to, and helios doctor names the live ones and how to give them back", strings.Join(problems, "; "))
}

func (d *drillState) cleanupStep() kernel.Step {
	return kernel.Step{
		Name: "cleanup", Change: "remove the scratch volumes, database and containers, and record the drill",
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return d.run.fail(err)
			}
			defer e.Close()
			d.names.cleanup(e)
			if d.found == nil {
				// Resumed past the restore step: the record can't say more.
				return d.run.fail(errors.New("the drill was interrupted; run it again"))
			}
			point := time.Since(d.found.Time).Round(time.Minute)
			d.details = append(d.details, fmt.Sprintf("recovery point %s before the drill, recovery time %s", point, time.Since(d.started).Round(time.Second)))
			result := state.BackupRun{Snapshot: d.found.ShortID, SnapshotAt: d.found.Time, Detail: strings.Join(d.details, "; ")}
			if d.restored != nil {
				result.Files, result.Bytes = d.restored.FilesRestored, d.restored.BytesRestored
			}
			if err := d.run.done(ctx, result); err != nil {
				return err
			}
			fmt.Fprintln(out, result.Detail)
			return nil
		},
	}
}

// drillSpec is a workload's container started on the restored data: on
// the drill's own network and volumes, and published nowhere on the
// machine, where the app's running containers already hold its ports.
func drillSpec(m *manifest.Manifest, revision, name, image string, values map[string]string, names drillNames) (docker.Spec, error) {
	w := m.Workloads[name]
	spec, err := containerSpec(m, name, w, revision, image, values)
	if err != nil {
		return spec, err
	}
	spec.Name = names.containers[name]
	spec.Networks = []string{names.network}
	spec.Restart = false
	spec.Publish = nil
	spec.Mounts = nil
	for _, mt := range w.Mounts {
		spec.Mounts = append(spec.Mounts, names.volumes[mt.Volume]+":"+mt.Path)
	}
	return spec, nil
}
