package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

func (x *machineRecovering) names(m *manifest.Manifest) drillNames {
	prefix := "bedrock.recovery." + x.in.ID + "." + m.App
	n := drillNames{app: m.App, dir: filepath.Join(x.stage(), machineAppDataDir, m.App), network: prefix, postgres: prefix + ".postgres", postgresVolume: prefix + ".postgres", objects: prefix + ".objects", volumes: map[string]string{}, containers: map[string]string{}}
	if !x.in.Rehearsal {
		n.postgres = PostgresContainer(m.App)
		n.postgresVolume = docker.VolumeName(m.App, postgresWorkload)
		n.objects = ObjectsContainer(m.App)
	}
	for _, v := range m.DataVolumes() {
		n.volumes[v] = prefix + "." + v
		if !x.in.Rehearsal {
			n.volumes[v] = docker.VolumeName(m.App, v)
		}
	}
	for name, w := range m.Workloads {
		if w.LongRunning() {
			n.containers[name] = prefix + "." + name
			if !x.in.Rehearsal {
				n.containers[name] = docker.ContainerName(m.App, name, recoveryRevisionID(x.in.ID))
			}
		}
	}
	return n
}

func (x *machineRecovering) claimResources(ctx context.Context, rec *machineRecoveryRecord, e *docker.Engine) error {
	if rec.ResourcesClaimed {
		return nil
	}
	volumes, err := e.Volumes(ctx, "")
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for _, v := range volumes {
		existing[v] = true
	}
	for _, rev := range rec.Catalog.Revisions {
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		n := x.names(&m)
		if exists, err := e.NetworkExists(ctx, n.network); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("recovery refuses existing target network %s", n.network)
		}
		wanted := make([]string, 0, len(n.volumes)+1)
		for _, v := range n.volumes {
			wanted = append(wanted, v)
		}
		if m.PostgresVersion() != "" {
			wanted = append(wanted, n.postgresVolume)
		}
		for _, v := range wanted {
			if existing[v] {
				return fmt.Errorf("recovery refuses existing target volume %s; use a clean target", v)
			}
		}
		containers := make([]string, 0, len(n.containers)+2)
		for _, c := range n.containers {
			containers = append(containers, c)
		}
		if m.PostgresVersion() != "" {
			containers = append(containers, n.postgres)
		}
		if m.HasObjects() {
			containers = append(containers, n.objects)
		}
		for _, c := range containers {
			if _, err := e.Inspect(ctx, c); err == nil {
				return fmt.Errorf("recovery refuses existing target container %s", c)
			} else if !docker.IsNotFound(err) {
				return err
			}
		}
	}
	// Ownership is durable before the first creation. Only these exact
	// resources can be reset after an interrupted restore.
	rec.ResourcesClaimed = true
	return x.save(rec)
}

func (x *machineRecovering) data(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil {
		return err
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	if err := x.claimResources(ctx, rec, e); err != nil {
		return err
	}
	for _, rev := range rec.Catalog.Revisions {
		if rec.DataReady[rev.App] {
			continue
		}
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		n := x.names(&m)
		if !m.HasData() {
			rec.DataReady[rev.App] = true
			if err := x.save(rec); err != nil {
				return err
			}
			continue
		}
		if err := requireRestoreSecrets(x.stagedSecrets(), &m); err != nil {
			return err
		}
		if err := e.EnsureInternalNetwork(ctx, n.network); err != nil {
			return err
		}
		if err := os.MkdirAll(n.dir, 0o700); err != nil {
			return err
		}
		mounts := []string{restic.DirMount(n.dir, false)}
		target := rev.App
		snapshot := rec.Catalog.AppSnapshots[rev.App]
		var includes []string
		if rec.Catalog.EmbeddedData {
			target = MachineTarget(x.in.Source)
			snapshot = rec.Snapshot.ID
			mounts = []string{restic.DirMount(x.stage(), false)}
			includes = []string{restic.DataRoot + "/" + machineAppDataDir + "/" + rev.App}
		}
		for _, v := range sortedKeys(n.volumes) {
			// An unfinished restore resets only resources claimed before
			// creation. Completed restored volumes are never reset.
			if _, err := e.RemoveVolume(ctx, n.volumes[v]); err != nil {
				return err
			}
			if err := e.EnsureVolume(ctx, n.volumes[v]); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Join(n.dir, "volumes", v), 0o700); err != nil {
				return err
			}
			mount := restic.VolumeMount(n.volumes[v], v, false)
			if rec.Catalog.EmbeddedData {
				mount = n.volumes[v] + ":" + restic.DataRoot + "/" + machineAppDataDir + "/" + rev.App + "/volumes/" + v
			}
			mounts = append(mounts, mount)
		}
		r, _, err := openRepo(x.r.Secrets, e, manifest.ReservedApp, target, nil)
		if err != nil {
			return err
		}
		if !fullSnapshotID.MatchString(snapshot) {
			return fmt.Errorf("%s has no exact pinned data recovery point", rev.App)
		}
		if _, err := r.Restore(ctx, snapshot, target, mounts, includes...); err != nil {
			return err
		}
		// An old backup must restore the same data layout. A machine
		// catalog can otherwise pair new service versions with older data.
		data, err := os.ReadFile(filepath.Join(n.dir, "manifest.json"))
		if err != nil {
			return err
		}
		var backed manifest.Manifest
		if json.Unmarshal(data, &backed) != nil {
			return errors.New("invalid restored app manifest")
		}
		if err := compatibleRecoveryData(&m, &backed); err != nil {
			return err
		}
		provenance, err := readAppBackupProvenance(n.dir, rev)
		if err != nil {
			return err
		}
		if recorded := rec.Catalog.AppData[rev.App]; provenance.Revision != recorded.Revision || provenance.SecretsVersion != recorded.SecretsVersion || provenance.ManifestSHA256 != recorded.ManifestSHA256 || !provenance.CapturedAt.Equal(recorded.CapturedAt) {
			return errors.New("restored app data provenance differs from its machine recovery catalog")
		}
		rec.DataReady[rev.App] = true
		if err := x.save(rec); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s data restored from pinned snapshot %s\n", rev.App, snapshot)
	}
	return nil
}

func compatibleRecoveryData(current, backed *manifest.Manifest) error {
	a, b := current.DataVolumes(), backed.DataVolumes()
	slices.Sort(a)
	slices.Sort(b)
	if current.App != backed.App || current.PostgresVersion() != backed.PostgresVersion() || current.HasObjects() != backed.HasObjects() || !slices.Equal(a, b) {
		return fmt.Errorf("%s's pinned data snapshot has a different service version or volume layout; take a matching data backup before the machine backup", current.App)
	}
	return nil
}

func (x *machineRecovering) ready(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil {
		return err
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	for _, rev := range rec.Catalog.Revisions {
		if !rec.DataReady[rev.App] {
			return fmt.Errorf("%s's data restore is incomplete", rev.App)
		}
		if err := x.startPrivate(ctx, rec, e, rev, out); err != nil {
			return err
		}
		rec.Ready[rev.App] = true
		if err := x.save(rec); err != nil {
			return err
		}
	}
	return nil
}

func (x *machineRecovering) startPrivate(ctx context.Context, rec *machineRecoveryRecord, e *docker.Engine, rev state.Revision, out io.Writer) error {
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return err
	}
	n := x.names(&m)
	if err := x.checkRecoveryContainers(ctx, e, &m, n, false); err != nil {
		return err
	}
	if err := e.EnsureInternalNetwork(ctx, n.network); err != nil {
		return err
	}
	values, err := x.stagedSecrets().Load(rev.App, rev.SecretsVersion)
	if err != nil {
		return err
	}
	if err := checkSecrets(&m, values); err != nil {
		return err
	}
	if m.PostgresVersion() != "" {
		svc, err := postgresService(&m, values, filepath.Join(n.dir, initSnapshotDir))
		if err != nil {
			return err
		}
		if !keepsOwners(&m) {
			svc.InitDir = ""
		} else if !dirExists(svc.InitDir) {
			return fmt.Errorf("%s's snapshot holds no database init scripts", rev.App)
		}
		svc.Container, svc.Volume, svc.Network = n.postgres, n.postgresVolume, n.network
		svc.Aliases = []string{PostgresContainer(rev.App)}
		svc.Labels = map[string]string{docker.LabelApp: rev.App, docker.LabelWorkload: "recovery", "bedrock.recovery": x.in.ID}
		if !rec.DatabaseReady[rev.App] {
			if err := e.Remove(ctx, n.postgres, 5*time.Second); err != nil {
				return err
			}
			if _, err := e.RemoveVolume(ctx, n.postgresVolume); err != nil {
				return err
			}
		}
		if err := svc.start(ctx, e, out); err != nil {
			return err
		}
		if !rec.DatabaseReady[rev.App] {
			dump := filepath.Join(n.dir, "postgres.dump")
			if err := recoveryPlainFile(dump); err != nil {
				return fmt.Errorf("%s snapshot has no database dump", rev.App)
			}
			if _, err := restoreDump(ctx, e, svc, dump, keepsOwners(&m)); err != nil {
				return err
			}
			if query, atLeast := m.VerifyQuery(); query != "" {
				got, err := scalar(ctx, e, svc, query)
				if err != nil {
					return fmt.Errorf("%s verify query: %w", rev.App, err)
				}
				count, err := strconv.Atoi(got)
				if err != nil || count < atLeast {
					return fmt.Errorf("%s restored database did not meet the verify query minimum of %d", rev.App, atLeast)
				}
			}
			rec.DatabaseReady[rev.App] = true
			if err := x.save(rec); err != nil {
				return err
			}
		}
	}
	if m.HasObjects() {
		o := objectsServiceFor(&m, values)
		o.Container, o.Volume, o.Network = n.objects, n.volumes[manifest.ObjectsVolume], n.network
		o.Aliases = []string{ObjectsContainer(rev.App)}
		o.Labels = map[string]string{docker.LabelApp: rev.App, docker.LabelWorkload: "recovery", "bedrock.recovery": x.in.ID}
		if err := o.start(ctx, e, out); err != nil {
			return err
		}
	}
	// Start every dependency before probing any workload. Private specs
	// contain no published ports, edge network, cron or release jobs.
	for _, name := range sortedKeys(n.containers) {
		spec, err := drillSpec(&m, recoveryRevisionID(x.in.ID), name, rev.Images[name], values, n)
		if err != nil {
			return err
		}
		spec.Labels["bedrock.recovery"] = x.in.ID
		u, err := isolate(ctx, e, &spec, m.Workloads[name], rev.Images[name])
		if err != nil {
			return err
		}
		// Volumes excluded from backups are fresh, just as in a drill.
		// Give only those empty volumes to the workload; restored file
		// ownership must remain the ownership captured in the snapshot.
		for _, mt := range m.Workloads[name].Mounts {
			if slices.Contains(m.VolumesOutOfBackups(), mt.Volume) {
				if _, err := e.EnsureVolumeOwner(ctx, n.volumes[mt.Volume], u); err != nil {
					return err
				}
			}
		}
		if err := restoredWritable(name, m.Workloads[name], u, n.volumes, func(v string) (string, error) { return e.VolumeMountpoint(ctx, v) }); err != nil {
			return err
		}
		if err := e.Run(ctx, spec); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(n.containers) {
		if err := waitReady(ctx, e, n.containers[name], m.Workloads[name]); err != nil {
			return fmt.Errorf("%s/%s private recovery readiness: %w", rev.App, name, err)
		}
	}
	fmt.Fprintf(out, "%s passed private recovery readiness\n", rev.App)
	return nil
}

// Recorded names reserve resources, but a container or network can be
// replaced outside Helios between attempts. Validate every existing private
// resource before removing any container or restored volume.
func (x *machineRecovering) checkPrivateResources(ctx context.Context, rec *machineRecoveryRecord, e *docker.Engine) error {
	for _, rev := range rec.Catalog.Revisions {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return err
		}
		n := x.names(&m)
		if err := x.checkRecoveryContainers(ctx, e, &m, n, false); err != nil {
			return err
		}
		if found, err := e.NetworkExists(ctx, n.network); err != nil {
			return err
		} else if found {
			owned, err := e.Networks(ctx, n.network)
			if err != nil {
				return err
			}
			if !slices.Contains(owned, n.network) {
				return fmt.Errorf("recovery network %s is no longer owned by helios", n.network)
			}
		}
	}
	return nil
}

func (x *machineRecovering) checkRecoveryContainers(ctx context.Context, e *docker.Engine, m *manifest.Manifest, n drillNames, allowLive bool) error {
	containers := make([]string, 0, len(n.containers)+2)
	roles := map[string]string{n.postgres: postgresWorkload, n.objects: objectsWorkload}
	for _, name := range sortedKeys(n.containers) {
		containers = append(containers, n.containers[name])
		roles[n.containers[name]] = name
	}
	if m.PostgresVersion() != "" {
		containers = append(containers, n.postgres)
	}
	if m.HasObjects() {
		containers = append(containers, n.objects)
	}
	for _, name := range containers {
		info, err := e.Inspect(ctx, name)
		if docker.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		owned := info.Labels[docker.LabelOwner] == docker.OwnerValue && info.Labels[docker.LabelApp] == m.App
		privateRole := roles[name]
		if name == n.postgres || name == n.objects {
			privateRole = "recovery"
		}
		private := owned && info.Labels["bedrock.recovery"] == x.in.ID && info.Labels[docker.LabelWorkload] == privateRole
		if name != n.postgres && name != n.objects {
			private = private && info.Labels[docker.LabelRevision] == recoveryRevisionID(x.in.ID)
		}
		if private {
			continue
		}
		// Earlier interrupted cutovers already used normal live specs.
		// Their exact app/revision labels remain ownership evidence, while
		// private rehearsal resources always require their recovery ID.
		live := allowLive && !x.in.Rehearsal && info.Labels["bedrock.recovery"] == "" &&
			owned && info.Labels[docker.LabelWorkload] == roles[name]
		if name != n.postgres && name != n.objects {
			live = live && info.Labels[docker.LabelRevision] == recoveryRevisionID(x.in.ID)
		}
		if !live {
			return fmt.Errorf("refusing to change container %s because its recovery ownership changed", name)
		}
	}
	return nil
}

func (x *machineRecovering) cleanup(rec *machineRecoveryRecord, e *docker.Engine) error {
	if !rec.ResourcesClaimed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := x.checkPrivateResources(ctx, rec, e); err != nil {
		return err
	}
	var failures []error
	for _, rev := range rec.Catalog.Revisions {
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		n := x.names(&m)
		for _, name := range sortedKeys(n.containers) {
			failures = append(failures, e.Remove(ctx, n.containers[name], 5*time.Second))
		}
		if m.PostgresVersion() != "" {
			failures = append(failures, e.Remove(ctx, n.postgres, 5*time.Second))
		}
		if m.HasObjects() {
			failures = append(failures, e.Remove(ctx, n.objects, 5*time.Second))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err // Retain all restored data while any writer could still run.
	}
	for _, rev := range rec.Catalog.Revisions {
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		n := x.names(&m)
		if m.PostgresVersion() != "" {
			_, err := e.RemoveVolume(ctx, n.postgresVolume)
			failures = append(failures, err)
		}
		failures = append(failures, e.RemoveNetwork(ctx, n.network))
		for _, name := range sortedKeys(n.volumes) {
			_, err := e.RemoveVolume(ctx, n.volumes[name])
			failures = append(failures, err)
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	for _, rev := range rec.Catalog.Revisions {
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		failures = append(failures, os.RemoveAll(x.names(&m).dir))
	}
	return errors.Join(failures...)
}
