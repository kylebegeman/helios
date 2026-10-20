package app

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/restic"
)

// A target fence makes repeat restore writes safe: each named volume was
// verified empty before the first attempt, and no application or operator
// writer is admitted until restoration and staging finish.
func moveRestoreVolumes(x *restoring, h Handoff, revision string) kernel.Step {
	return kernel.Step{Name: "restore-volumes", Change: "restore exact final snapshot " + h.Snapshot + " into reserved empty target volumes", Apply: func(ctx context.Context, out io.Writer) error {
		m, err := x.manifest()
		if err != nil {
			return err
		}
		record, err := targetMigration(x.r.Store.Path(), h, revision)
		if err != nil {
			return err
		}
		if record.RestoringVolumes == nil {
			record.RestoringVolumes = map[string]bool{}
		}
		if record.RestoredVolumes == nil {
			record.RestoredVolumes = map[string]bool{}
		}
		e, err := docker.Connect(ctx)
		if err != nil {
			return err
		}
		defer e.Close()
		rs, _, err := openRepo(x.r.Secrets, e, x.app, x.app, nil)
		if err != nil {
			return err
		}
		if len(record.RestoringVolumes) == 0 && len(record.RestoredVolumes) == 0 {
			// Before any volume has begun, the whole restore must fit; once
			// one has, part of it is on the disk already.
			for _, v := range m.DataVolumes() {
				if err := e.EnsureVolume(ctx, docker.VolumeName(x.app, v)); err != nil {
					return err
				}
			}
			if err := x.checkVolumesSpace(ctx, e, rs, m.BackedUpVolumes(), out); err != nil {
				return err
			}
		}
		for _, v := range m.DataVolumes() {
			if record.RestoredVolumes[v] {
				continue
			}
			vol := docker.VolumeName(x.app, v)
			if err := e.EnsureVolume(ctx, vol); err != nil {
				return err
			}
			if !record.RestoringVolumes[v] {
				empty, err := e.VolumeEmpty(ctx, vol)
				if err != nil {
					return err
				}
				if !empty {
					return fmt.Errorf("target volume %s already has files; refusing to overwrite existing data", v)
				}
				record.RestoringVolumes[v] = true
				if err := saveMigration(x.r.Store.Path(), record); err != nil {
					return err
				}
			}
			backedUp := slices.Contains(m.BackedUpVolumes(), v)
			if backedUp {
				if _, err := rs.Restore(ctx, h.Snapshot, x.app, []string{restic.VolumeMount(vol, v, false)}, restic.VolumePath(v)); err != nil {
					return err
				}
			}
			record.RestoredVolumes[v] = true
			if err := saveMigration(x.r.Store.Path(), record); err != nil {
				return err
			}
			if backedUp {
				fmt.Fprintf(out, "%s restored from exact final snapshot %s\n", v, short(h.Snapshot))
			} else {
				fmt.Fprintf(out, "volume %s created empty: backup: false leaves it out of backups\n", v)
			}
		}
		return nil
	}}
}

func moveRestoreDatabase(x *restoring, h Handoff, revision string) kernel.Step {
	return kernel.Step{Name: "restore-database", Change: "restore the final database in one transaction while target writers remain fenced", Apply: func(ctx context.Context, out io.Writer) error {
		m, err := x.manifest()
		if err != nil {
			return err
		}
		if m.PostgresVersion() == "" {
			return nil
		}
		record, err := targetMigration(x.r.Store.Path(), h, revision)
		if err != nil {
			return err
		}
		if record.DatabaseRestored {
			return nil
		}
		e, err := docker.Connect(ctx)
		if err != nil {
			return err
		}
		defer e.Close()
		if err := e.EnsureNetwork(ctx, docker.AppNetwork(x.app)); err != nil {
			return err
		}
		initDir, err := restoreInit(x.staging, x.r.StateDir, x.app)
		if err != nil {
			return err
		}
		if keepsOwners(m) && initDir == "" {
			return fmt.Errorf("final snapshot holds no database init scripts")
		}
		if err := ensurePostgres(ctx, e, x.r.Secrets, m, initDir, "", out); err != nil {
			return err
		}
		values, _, err := x.r.Secrets.LoadCurrent(x.app)
		if err != nil {
			return err
		}
		service, err := postgresService(m, values, initDir)
		if err != nil {
			return err
		}
		tables, err := tableCount(ctx, e, service)
		if err != nil {
			return err
		}
		if !record.DatabaseStarted {
			if tables > 0 {
				return fmt.Errorf("target database already has %d tables; refusing to overwrite existing data", tables)
			}
			record.DatabaseStarted = true
			if err := saveMigration(x.r.Store.Path(), record); err != nil {
				return err
			}
		} else if tables > 0 {
			// pg_restore uses --single-transaction. Under this persistent
			// target fence, nonempty means the complete prior restore
			// committed after its initially empty check, before journaling.
			record.DatabaseRestored = true
			return saveMigration(x.r.Store.Path(), record)
		}
		if _, err := restoreDump(ctx, e, service, filepath.Join(x.staging, "postgres.dump"), keepsOwners(m)); err != nil {
			return err
		}
		record.DatabaseRestored = true
		if err := saveMigration(x.r.Store.Path(), record); err != nil {
			return err
		}
		return nil
	}}
}
