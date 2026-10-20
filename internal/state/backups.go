package state

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Backup run kinds.
const (
	BackupRunBackup  = "backup"
	BackupRunDrill   = "drill"
	BackupRunRestore = "restore"
	// BackupRunDrillSkip is a scheduled drill an operator skipped. It
	// starts and finishes at the skipped occurrence, and its detail is the
	// operator's reason.
	BackupRunDrillSkip = "drill-skip"
)

// BackupRun is one backup, drill or restore of an app's data.
type BackupRun struct {
	ID         int64     `json:"id"`
	App        string    `json:"app"`
	Kind       string    `json:"kind"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	OK         bool      `json:"ok"`
	// Snapshot is the restic snapshot the run made or used.
	Snapshot string `json:"snapshot,omitempty"`
	// SnapshotAt is when that snapshot was taken: the recovery point.
	SnapshotAt time.Time `json:"snapshot_at,omitempty"`
	Files      int64     `json:"files"`
	Bytes      int64     `json:"bytes"`
	// Detail is one line about what was kept or verified.
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Finished reports whether the run ended, one way or the other.
func (r BackupRun) Finished() bool { return !r.FinishedAt.IsZero() }

func (s *Store) migrateBackups(ctx context.Context, q migrationDB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS backup_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app         TEXT NOT NULL,
  kind        TEXT NOT NULL,
  started_at  INTEGER NOT NULL,
  finished_at INTEGER NOT NULL DEFAULT 0,
  ok          INTEGER NOT NULL DEFAULT 0,
  snapshot    TEXT NOT NULL DEFAULT '',
  snapshot_at INTEGER NOT NULL DEFAULT 0,
  files       INTEGER NOT NULL DEFAULT 0,
  bytes       INTEGER NOT NULL DEFAULT 0,
  detail      TEXT NOT NULL DEFAULT '',
  error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS backup_runs_app ON backup_runs (app, kind, started_at DESC);`
	_, err := q.ExecContext(ctx, schema)
	return err
}

// StartBackupRun records that a run began and returns its id.
func (s *Store) StartBackupRun(ctx context.Context, app, kind string, started time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO backup_runs (app, kind, started_at) VALUES (?, ?, ?)`, app, kind, unix(started))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishBackupRun records how a run ended.
func (s *Store) FinishBackupRun(ctx context.Context, id int64, r BackupRun) error {
	_, err := s.db.ExecContext(ctx, `UPDATE backup_runs SET finished_at = ?, ok = ?, snapshot = ?, snapshot_at = ?, files = ?, bytes = ?, detail = ?, error = ? WHERE id = ?`,
		unix(r.FinishedAt), r.OK, r.Snapshot, unix(r.SnapshotAt), r.Files, r.Bytes, r.Detail, r.Error, id)
	return err
}

// SkipDrill records that the drill scheduled at occurrence is skipped, and
// why.
func (s *Store) SkipDrill(ctx context.Context, app string, occurrence time.Time, reason string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO backup_runs (app, kind, started_at, finished_at, ok, detail) VALUES (?, ?, ?, ?, 1, ?)`,
		app, BackupRunDrillSkip, unix(occurrence), unix(occurrence), reason)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const backupRunColumns = `id, app, kind, started_at, finished_at, ok, snapshot, snapshot_at, files, bytes, detail, error`

// BackupRun returns the recorded run identified by id.
func (s *Store) BackupRun(ctx context.Context, id int64) (BackupRun, error) {
	var r BackupRun
	var started, finished, snapshotAt int64
	err := s.db.QueryRowContext(ctx, `SELECT `+backupRunColumns+` FROM backup_runs WHERE id = ?`, id).Scan(
		&r.ID, &r.App, &r.Kind, &started, &finished, &r.OK, &r.Snapshot, &snapshotAt, &r.Files, &r.Bytes, &r.Detail, &r.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupRun{}, ErrNotFound
	}
	if err != nil {
		return BackupRun{}, err
	}
	r.StartedAt, r.FinishedAt, r.SnapshotAt = fromUnix(started), fromUnix(finished), fromUnix(snapshotAt)
	return r, nil
}

// BackupRuns lists runs newest first. An empty app means every app; an
// empty kind means every kind.
func (s *Store) BackupRuns(ctx context.Context, app, kind string, limit int) ([]BackupRun, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `SELECT ` + backupRunColumns + ` FROM backup_runs WHERE 1 = 1`
	var args []any
	if app != "" {
		query += ` AND app = ?`
		args = append(args, app)
	}
	if kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	query += ` ORDER BY started_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupRun
	for rows.Next() {
		var r BackupRun
		var started, finished, snapshotAt int64
		if err := rows.Scan(&r.ID, &r.App, &r.Kind, &started, &finished, &r.OK, &r.Snapshot, &snapshotAt, &r.Files, &r.Bytes, &r.Detail, &r.Error); err != nil {
			return nil, err
		}
		r.StartedAt, r.FinishedAt, r.SnapshotAt = fromUnix(started), fromUnix(finished), fromUnix(snapshotAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastBackupRun returns the newest run of a kind for an app, whatever
// its outcome, or nil.
func (s *Store) LastBackupRun(ctx context.Context, app, kind string) (*BackupRun, error) {
	runs, err := s.BackupRuns(ctx, app, kind, 1)
	if err != nil || len(runs) == 0 {
		return nil, err
	}
	return &runs[0], nil
}

// LastGoodBackupRun returns the newest run of a kind that succeeded, or nil.
func (s *Store) LastGoodBackupRun(ctx context.Context, app, kind string) (*BackupRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+backupRunColumns+` FROM backup_runs WHERE app = ? AND kind = ? AND ok = 1 ORDER BY started_at DESC, id DESC LIMIT 1`, app, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var r BackupRun
	var started, finished, snapshotAt int64
	if err := rows.Scan(&r.ID, &r.App, &r.Kind, &started, &finished, &r.OK, &r.Snapshot, &snapshotAt, &r.Files, &r.Bytes, &r.Detail, &r.Error); err != nil {
		return nil, err
	}
	r.StartedAt, r.FinishedAt, r.SnapshotAt = fromUnix(started), fromUnix(finished), fromUnix(snapshotAt)
	return &r, nil
}
