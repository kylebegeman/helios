package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

const MoveCaptureKind = "app.move.capture"
const MoveResumeKind = "app.move.resume"

type MoveCapture struct{ Backup Backup }
type MoveCaptureInput struct {
	App       string `json:"app"`
	From      string `json:"from"`
	To        string `json:"to"`
	Revision  string `json:"revision"`
	Migration string `json:"migration,omitempty"`
	Final     bool   `json:"final,omitempty"`
}

func manifestDigest(m *manifest.Manifest) string {
	data, _ := json.Marshal(m)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func migrationHandoff(rev *state.Revision, m *manifest.Manifest, in MoveCaptureInput) Handoff {
	sum := sha256.Sum256([]byte(in.App + "\x00" + in.From + "\x00" + in.To + "\x00" + rev.ID))
	migration := in.Migration
	if migration == "" {
		migration = "move-" + hex.EncodeToString(sum[:])[:16]
	}
	phase := "rehearsal"
	if in.Final {
		phase = "final"
	}
	return Handoff{App: in.App, From: in.From, To: in.To, Migration: migration, Phase: phase,
		Revision: rev.ID, ManifestDigest: manifestDigest(m), SourceCommit: rev.Source, HasData: m.HasData(), Hosts: m.Hosts(), Repo: m.Repo, At: time.Now().UTC()}
}

func (MoveCapture) Kind() string { return MoveCaptureKind }

func (c MoveCapture) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in MoveCaptureInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if err := checkReleaseStoreAccess(ctx, c.Backup.Store, in.App); err != nil {
		return nil, err
	}
	if in.From == "" || in.To == "" || in.From == in.To || in.Revision == "" {
		return nil, errors.New("move capture needs distinct source and target machine names and the reviewed source revision")
	}
	rev, err := c.Backup.Store.RevisionWithStatus(ctx, in.App, state.RevisionActive)
	if err != nil {
		return nil, err
	}
	if rev == nil || rev.ID != in.Revision {
		return nil, fmt.Errorf("%s's running revision changed; review capture again", in.App)
	}
	m, err := manifest.Parse(rev.Manifest)
	if err != nil {
		return nil, err
	}
	h := migrationHandoff(rev, m, in)
	if h.HasData {
		st, err := integration.LoadStorage(c.Backup.Secrets)
		if err != nil {
			return nil, fmt.Errorf("move capture needs shared storage: %w", err)
		}
		h.Bucket = st.Bucket(in.App)
	}
	if !migrationIDPattern.MatchString(h.Migration) {
		return nil, errors.New("invalid migration ID")
	}
	if resumed, err := readResumedMigration(c.Backup.Store.Path(), in.App, h.Migration); err != nil {
		return nil, err
	} else if resumed != nil {
		return nil, errors.New("this migration was deliberately resumed; review a new capture before freezing the source again")
	}
	if existing, err := readMigration(c.Backup.Store.Path(), in.App); err != nil {
		return nil, err
	} else if existing != nil && !(existing.Role == "target" && existing.Phase == "cutover") && (!in.Final || !sameMigration(existing.Handoff, h)) {
		return nil, fmt.Errorf("%s is already fenced for migration; resume it deliberately before a new capture", in.App)
	}
	plan := &kernel.Plan{Target: in.App, Recovery: kernel.Resume}
	identity := fmt.Sprintf("%s from %s to %s, source revision %s, manifest %s", h.Migration, h.From, h.To, h.Revision, h.ManifestDigest)
	if h.HasData {
		identity += ", bucket " + h.Bucket
	}
	if h.SourceCommit != "" {
		identity += ", source commit " + h.SourceCommit
	}
	if in.Final {
		plan.Steps = append(plan.Steps, kernel.Step{Name: "fence", Change: "persist a write fence and stop every source writer for " + identity,
			Apply: func(ctx context.Context, out io.Writer) error {
				current, err := c.Backup.Store.RevisionWithStatus(ctx, in.App, state.RevisionActive)
				if err != nil {
					return err
				}
				if current == nil || current.ID != in.Revision {
					return fmt.Errorf("source revision changed before fencing")
				}
				e, err := docker.Connect(ctx)
				if err != nil {
					return err
				}
				defer e.Close()
				return fenceMigration(ctx, e, c.Backup.Store.Path(), m, h, out)
			}})
	}
	if h.HasData {
		stateDir := c.Backup.StateDir
		if stateDir == "" {
			stateDir = filepath.Dir(c.Backup.Store.Path())
		}
		x := &backingUp{b: c.Backup, owner: in.App, target: in.App, staging: filepath.Join(stateDir, "moves", in.App, "capture"), bucket: h.Bucket,
			run: &backupRun{store: c.Backup.Store, app: in.App, kind: state.BackupRunBackup}}
		prepare := x.appPrepareStep(rev, m)
		prepare.Change += " for " + identity
		plan.Steps = append(plan.Steps, prepare)
		if !in.Final {
			step := x.appSnapshotStep(rev, m)
			step.Change += " for rehearsal " + identity
			capture := step.Apply
			step.Apply = func(ctx context.Context, out io.Writer) error {
				if err := capture(ctx, out); err != nil {
					return err
				}
				if x.summary == nil || !snapshotIDPattern.MatchString(x.summary.SnapshotID) {
					return x.run.fail(errors.New("rehearsal capture returned no exact snapshot identity"))
				}
				h.Snapshot, h.TakenAt = x.summary.SnapshotID, x.summary.BackupStart
				if err := writeMoveHandoff(c.Backup.Store.Path(), h); err != nil {
					return x.run.fail(err)
				}
				return nil
			}
			plan.Steps = append(plan.Steps, step)
		} else {
			plan.Steps = append(plan.Steps, kernel.Step{Name: "snapshot", Change: "capture the final database and volumes while the source remains fenced for " + identity + leftOut(m),
				Apply: func(ctx context.Context, out io.Writer) (captureErr error) {
					if err := x.run.begin(ctx); err != nil {
						return err
					}
					defer func() {
						if captureErr != nil {
							captureErr = x.run.fail(captureErr)
						}
					}()
					record, err := readMigration(c.Backup.Store.Path(), in.App)
					if err != nil {
						return err
					}
					if record == nil || !sameMigration(record.Handoff, h) {
						return fmt.Errorf("source migration fence is missing or changed")
					}
					if record.Handoff.Snapshot != "" {
						h = record.Handoff
						return nil
					}
					unlock, err := lockAppData(ctx, c.Backup.Store.Path(), in.App, true)
					if err != nil {
						return err
					}
					defer unlock()
					e, err := docker.Connect(ctx)
					if err != nil {
						return err
					}
					defer e.Close()
					r, storage, err := openRepo(c.Backup.Secrets, e, in.App, in.App, nil)
					if err != nil {
						return err
					}
					if storage.Bucket(in.App) != h.Bucket {
						return errors.New("storage bucket changed after capture was reviewed; source remains fenced")
					}
					if err := enforceMigration(ctx, e, record); err != nil {
						return err
					}
					if err := x.ensure(ctx, r, out); err != nil {
						return err
					}
					if m.PostgresVersion() != "" {
						if err := x.dump(ctx, e, m, out); err != nil {
							return err
						}
					}
					if err := writeAppBackupProvenance(x.staging, *rev, time.Now().UTC()); err != nil {
						return err
					}
					x.summary, err = r.Backup(ctx, in.App, snapshotMounts(x.staging, in.App, m), restic.DataRoot)
					if err != nil {
						return err
					}
					if x.summary == nil || !snapshotIDPattern.MatchString(x.summary.SnapshotID) {
						return errors.New("final capture returned no exact snapshot identity")
					}
					h.Snapshot, h.TakenAt = x.summary.SnapshotID, x.summary.BackupStart
					record.Handoff, record.Phase = h, "captured"
					if err := saveMigration(c.Backup.Store.Path(), record); err != nil {
						return err
					}
					fmt.Fprintf(out, "final snapshot %s; source remains fenced\n", short(h.Snapshot))
					return nil
				}})
		}
		plan.Steps = append(plan.Steps, kernel.Step{Name: "handoff", Change: "record the exact captured snapshot for " + identity,
			Apply: func(ctx context.Context, out io.Writer) error {
				if in.Final {
					record, err := readMigration(c.Backup.Store.Path(), in.App)
					if err != nil {
						return err
					}
					if record == nil || record.Handoff.Snapshot == "" {
						return errors.New("final snapshot is missing")
					}
					h = record.Handoff
				} else {
					captured, err := ReadMoveHandoff(c.Backup.Store.Path(), in.App, "rehearsal")
					if err != nil {
						return err
					}
					if !sameMigration(*captured, h) {
						return errors.New("rehearsal snapshot belongs to another migration")
					}
					h = *captured
				}
				if err := x.run.begin(ctx); err != nil {
					return err
				}
				if err := x.run.done(ctx, state.BackupRun{Snapshot: h.Snapshot, SnapshotAt: h.TakenAt, Detail: "migration " + h.Phase + " capture for " + h.To}); err != nil {
					return err
				}
				return WriteHandoff(out, &h)
			}})
	} else {
		plan.Steps = append(plan.Steps, kernel.Step{Name: "handoff", Change: "record stateless " + h.Phase + " handoff for " + identity,
			Apply: func(ctx context.Context, out io.Writer) error {
				if in.Final {
					record, err := readMigration(c.Backup.Store.Path(), in.App)
					if err != nil {
						return err
					}
					if record == nil {
						return errors.New("source fence missing")
					}
					record.Handoff, record.Phase = h, "captured"
					if err := saveMigration(c.Backup.Store.Path(), record); err != nil {
						return err
					}
				} else if err := writeMoveHandoff(c.Backup.Store.Path(), h); err != nil {
					return err
				}
				return WriteHandoff(out, &h)
			}})
	}
	return guardReleaseRestoreSteps(plan, c.Backup.Store), nil
}

// MoveCaptureInputFor selects a stable capture identity. A deliberately resumed
// migration starts a new identity even when its code revision stayed the same.
func MoveCaptureInputFor(ctx context.Context, store *state.Store, app, from, to string, final bool) (MoveCaptureInput, error) {
	if err := checkReleaseStoreAccess(ctx, store, app); err != nil {
		return MoveCaptureInput{}, err
	}
	rev, err := store.RevisionWithStatus(ctx, app, state.RevisionActive)
	if err != nil {
		return MoveCaptureInput{}, err
	}
	if rev == nil {
		return MoveCaptureInput{}, fmt.Errorf("%s is not running here", app)
	}
	m, err := manifest.Parse(rev.Manifest)
	if err != nil {
		return MoveCaptureInput{}, err
	}
	in := MoveCaptureInput{App: app, From: from, To: to, Revision: rev.ID, Final: final}
	h := migrationHandoff(rev, m, in)
	for {
		resumed, err := readResumedMigration(store.Path(), app, h.Migration)
		if err != nil {
			return MoveCaptureInput{}, err
		}
		if resumed == nil {
			break
		}
		sum := sha256.Sum256([]byte(h.Migration + "/next"))
		h.Migration = "move-" + hex.EncodeToString(sum[:])[:16]
	}
	in.Migration = h.Migration
	return in, nil
}
