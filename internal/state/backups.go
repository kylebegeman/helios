package state

import (
	"context"
	"database/sql"
	"errors"
	"strings"
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

// RecordSnapshotMade records, on a run that is still open or already
// closed, the id restic returned for the snapshot the run wrote into its
// repository. It is recorded the moment restic answers, apart from how the
// run ends, because a run can still fail after that and its snapshot is in
// the repository all the same.
//
// The id is kept apart from the run's snapshot on purpose. A failed run has
// no snapshot to restore, verify, keep or report, and everything that reads
// a run goes on finding none. Only SnapshotsMade reads this: whose a
// snapshot is does not depend on whether its run went on to succeed.
//
// Only a full snapshot id is taken. It decides whether a bucket may be
// deleted, and anything shorter could stand for a snapshot nobody named.
func (s *Store) RecordSnapshotMade(ctx context.Context, id int64, snapshot string) error {
	if !fullSnapshotID(snapshot) {
		return errors.New("a snapshot a run made is recorded by its full id")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE backup_runs SET snapshot_made = ? WHERE id = ?`, snapshot, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// fullSnapshotID reports whether id is a restic snapshot id in full: 64
// lowercase hexadecimal characters.
func fullSnapshotID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// SnapshotsMade returns the id of every snapshot that a run of one of the
// given kinds made for an app on this machine: the snapshot a successful run
// recorded, and the snapshot restic returned to a run whatever became of it
// (see RecordSnapshotMade). Pass the kinds that write a snapshot: a drill or
// a restore records the snapshot it read, which may be one another machine
// made. A run that a machine recovery copied from another machine's state
// does not count either: it is that machine's record. The runs of a removed
// app are kept, so this still answers after the app is gone.
func (s *Store) SnapshotsMade(ctx context.Context, app string, kinds ...string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(kinds) == 0 {
		return out, nil
	}
	of := `FROM backup_runs WHERE app = ? AND imported = 0 AND kind IN (?` + strings.Repeat(", ?", len(kinds)-1) + `)`
	args := []any{app}
	for _, kind := range kinds {
		args = append(args, kind)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot `+of+` AND ok = 1 AND snapshot != '' UNION SELECT snapshot_made `+of+` AND snapshot_made != ''`, append(args, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SnapshotsFailedRunsMade returns the id of every snapshot restic returned
// to a run of the given kind that then ended in failure, for an app on this
// machine. A run that has not ended is left out: what it wrote may yet be
// recorded by whatever the run is for, such as a release boundary.
func (s *Store) SnapshotsFailedRunsMade(ctx context.Context, app, kind string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot_made FROM backup_runs WHERE app = ? AND imported = 0 AND kind = ? AND finished_at != 0 AND ok = 0 AND snapshot_made != ''`, app, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
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
