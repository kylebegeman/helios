package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RevisionStatus is where a revision is in its life.
type RevisionStatus string

const (
	// RevisionActive is the one the edge routes to.
	RevisionActive RevisionStatus = "active"
	// RevisionPrevious is kept ready for rollback.
	RevisionPrevious RevisionStatus = "previous"
	// RevisionRetired is history; its containers are gone.
	RevisionRetired RevisionStatus = "retired"
	// RevisionFailed never went live.
	RevisionFailed RevisionStatus = "failed"
)

// Revision is one deployed version of an app.
type Revision struct {
	App        string            `json:"app"`
	ID         string            `json:"id"`
	Status     RevisionStatus    `json:"status"`
	Manifest   json.RawMessage   `json:"manifest"`
	Images     map[string]string `json:"images"`
	Containers map[string]string `json:"containers"`
	Source     string            `json:"source,omitempty"`
	// SecretsVersion is the version of the app's secrets the revision was
	// started with, so a rollback restores them too.
	SecretsVersion int       `json:"secrets_version"`
	CreatedAt      time.Time `json:"created_at"`
}

// App is one app helios runs.
type App struct {
	Name           string    `json:"name"`
	ActiveRevision string    `json:"active_revision,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (s *Store) migrateApps(ctx context.Context, q migrationDB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS apps (
  name            TEXT PRIMARY KEY,
  active_revision TEXT NOT NULL DEFAULT '',
  updated_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS revisions (
  app        TEXT NOT NULL,
  id         TEXT NOT NULL,
  status     TEXT NOT NULL,
  manifest   TEXT NOT NULL,
  images     TEXT NOT NULL,
  containers TEXT NOT NULL,
  source     TEXT NOT NULL DEFAULT '',
  secrets_version INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (app, id)
);
CREATE TABLE IF NOT EXISTS job_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app         TEXT NOT NULL,
  workload    TEXT NOT NULL,
  revision    TEXT NOT NULL,
  kind        TEXT NOT NULL,
  started_at  INTEGER NOT NULL,
  finished_at INTEGER NOT NULL DEFAULT 0,
  exit_code   INTEGER NOT NULL DEFAULT -1,
  error       TEXT NOT NULL DEFAULT '',
  output      TEXT NOT NULL DEFAULT '',
  container   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS job_runs_app ON job_runs (app, workload, started_at DESC);`
	if _, err := q.ExecContext(ctx, schema); err != nil {
		return err
	}
	// Columns added after a table first shipped.
	if err := ensureColumn(ctx, q, "revisions", "secrets_version", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return ensureColumn(ctx, q, "job_runs", "container", "TEXT NOT NULL DEFAULT ''")
}

// ensureColumn adds a column to a table that predates it.
func ensureColumn(ctx context.Context, q migrationDB, table, column, definition string) error {
	rows, err := q.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, definition))
	return err
}

// SaveRevision records a revision, replacing one with the same app and id.
func (s *Store) SaveRevision(ctx context.Context, r Revision) error {
	images, err := json.Marshal(r.Images)
	if err != nil {
		return err
	}
	containers, err := json.Marshal(r.Containers)
	if err != nil {
		return err
	}
	if r.Manifest == nil {
		r.Manifest = json.RawMessage(`{}`)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO revisions (app, id, status, manifest, images, containers, source, secrets_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(app, id) DO UPDATE SET status = excluded.status, manifest = excluded.manifest, images = excluded.images, containers = excluded.containers, source = excluded.source, secrets_version = excluded.secrets_version`,
		r.App, r.ID, string(r.Status), string(r.Manifest), string(images), string(containers), r.Source, r.SecretsVersion, unix(r.CreatedAt))
	return err
}

// CreateRevision records a new revision without replacing existing authority.
func (s *Store) CreateRevision(ctx context.Context, r Revision) error {
	images, err := json.Marshal(r.Images)
	if err != nil {
		return err
	}
	containers, err := json.Marshal(r.Containers)
	if err != nil {
		return err
	}
	if r.Manifest == nil {
		r.Manifest = json.RawMessage(`{}`)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO revisions (app, id, status, manifest, images, containers, source, secrets_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.App, r.ID, string(r.Status), string(r.Manifest), string(images), string(containers), r.Source, r.SecretsVersion, unix(r.CreatedAt))
	return err
}

// SetRevisionStatus changes one revision's status.
func (s *Store) SetRevisionStatus(ctx context.Context, app, id string, status RevisionStatus) error {
	_, err := s.db.ExecContext(ctx, `UPDATE revisions SET status = ? WHERE app = ? AND id = ?`, string(status), app, id)
	return err
}

// Activate makes a revision the app's active one: the old active becomes
// previous, the old previous becomes retired.
func (s *Store) Activate(ctx context.Context, app, id string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM revisions WHERE app = ? AND id = ?`, app, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE revisions SET status = ? WHERE app = ? AND status = ? AND id <> ?`, string(RevisionRetired), app, string(RevisionPrevious), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE revisions SET status = ? WHERE app = ? AND status = ? AND id <> ?`, string(RevisionPrevious), app, string(RevisionActive), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE revisions SET status = ? WHERE app = ? AND id = ?`, string(RevisionActive), app, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO apps (name, active_revision, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET active_revision = excluded.active_revision, updated_at = excluded.updated_at`, app, id, unix(now)); err != nil {
		return err
	}
	return tx.Commit()
}

// GetRevision returns one revision.
func (s *Store) GetRevision(ctx context.Context, app, id string) (*Revision, error) {
	row := s.db.QueryRowContext(ctx, `SELECT app, id, status, manifest, images, containers, source, secrets_version, created_at FROM revisions WHERE app = ? AND id = ?`, app, id)
	return scanRevision(row)
}

// Revisions lists an app's revisions, newest first.
func (s *Store) Revisions(ctx context.Context, app string) ([]Revision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT app, id, status, manifest, images, containers, source, secrets_version, created_at FROM revisions WHERE app = ? ORDER BY created_at DESC, id DESC`, app)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		r, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// FirstRevisionCreatedAt returns the earliest recorded revision timestamp for
// an app, across all statuses. It returns ErrNotFound when the app has no
// revisions; a recorded zero timestamp is returned without an error.
func (s *Store) FirstRevisionCreatedAt(ctx context.Context, app string) (time.Time, error) {
	var created sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(created_at) FROM revisions WHERE app = ?`, app).Scan(&created); err != nil {
		return time.Time{}, err
	}
	if !created.Valid {
		return time.Time{}, ErrNotFound
	}
	return fromUnix(created.Int64), nil
}

// RevisionWithStatus returns an app's revision in a status, or nil.
func (s *Store) RevisionWithStatus(ctx context.Context, app string, status RevisionStatus) (*Revision, error) {
	row := s.db.QueryRowContext(ctx, `SELECT app, id, status, manifest, images, containers, source, secrets_version, created_at FROM revisions WHERE app = ? AND status = ? ORDER BY created_at DESC LIMIT 1`, app, string(status))
	r, err := scanRevision(row)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// Apps lists every app, with its active revision.
func (s *Store) Apps(ctx context.Context) ([]App, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, active_revision, updated_at FROM apps ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		var updated int64
		if err := rows.Scan(&a.Name, &a.ActiveRevision, &updated); err != nil {
			return nil, err
		}
		a.UpdatedAt = fromUnix(updated)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AppNames lists every app with a revision, deployed or not.
func (s *Store) AppNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT app FROM revisions ORDER BY app`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ActiveRevisions returns every app's active revision, ordered by app and id.
func (s *Store) ActiveRevisions(ctx context.Context) ([]Revision, error) {
	// Unary + keeps SQLite from traversing the (app, id) index and looking up
	// every historical row just to preserve app order. Scan the table once and
	// sort only the active rows. A future index on status can still be used.
	rows, err := s.db.QueryContext(ctx, `SELECT app, id, status, manifest, images, containers, source, secrets_version, created_at FROM revisions WHERE status = ? ORDER BY +app, id`, string(RevisionActive))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		r, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// RemoveApp forgets an app: its revisions, release boundaries, job runs,
// signals, incident and webhook. Release fences cannot survive their removed
// revision history. Backup runs stay, because they say where its data went.
func (s *Store) RemoveApp(ctx context.Context, app string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct{ query, arg string }{
		{`DELETE FROM revisions WHERE app = ?`, app},
		{`DELETE FROM release_boundaries WHERE app = ?`, app},
		{`DELETE FROM apps WHERE name = ?`, app},
		{`DELETE FROM job_runs WHERE app = ?`, app},
		{`DELETE FROM signals WHERE app = ?`, app},
		{`DELETE FROM incidents WHERE key = ?`, "app:" + app},
		{`DELETE FROM git_hooks WHERE app = ?`, app},
	} {
		if _, err := tx.ExecContext(ctx, q.query, q.arg); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanRevision(row scanner) (*Revision, error) {
	var r Revision
	var manifest, images, containers string
	var created int64
	err := row.Scan(&r.App, &r.ID, &r.Status, &manifest, &images, &containers, &r.Source, &r.SecretsVersion, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Manifest = json.RawMessage(manifest)
	if err := json.Unmarshal([]byte(images), &r.Images); err != nil {
		return nil, fmt.Errorf("revision %s/%s images: %w", r.App, r.ID, err)
	}
	if err := json.Unmarshal([]byte(containers), &r.Containers); err != nil {
		return nil, fmt.Errorf("revision %s/%s containers: %w", r.App, r.ID, err)
	}
	r.CreatedAt = fromUnix(created)
	return &r, nil
}

// ForgetRevision drops a revision's record.
func (s *Store) ForgetRevision(ctx context.Context, app, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM revisions WHERE app = ? AND id = ? AND status <> ?`, app, id, string(RevisionActive))
	return err
}

// JobRun is one run of a cron workload or a one-off command.
type JobRun struct {
	ID       int64  `json:"id"`
	App      string `json:"app"`
	Workload string `json:"workload"`
	Revision string `json:"revision"`
	Kind     string `json:"kind"`
	// Container is the name of the container the run is in, so a daemon
	// that starts while the run is going can find it again.
	Container  string    `json:"container,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	ExitCode   int       `json:"exit_code"`
	Error      string    `json:"error,omitempty"`
	Output     string    `json:"output,omitempty"`
}

// StartJobRun records that a run began and returns its id.
func (s *Store) StartJobRun(ctx context.Context, run JobRun) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO job_runs (app, workload, revision, kind, started_at, container) VALUES (?, ?, ?, ?, ?, ?)`, run.App, run.Workload, run.Revision, run.Kind, unix(run.StartedAt), run.Container)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishJobRun records how a run ended.
func (s *Store) FinishJobRun(ctx context.Context, id int64, exitCode int, runErr, output string, finished time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE job_runs SET finished_at = ?, exit_code = ?, error = ?, output = ? WHERE id = ?`, unix(finished), exitCode, runErr, output, id)
	return err
}

// JobHold is the kind of the job_runs row that holds a cron workload. It
// starts when an operator placed it and finishes when it ends; its output
// is the operator's reason. It is never a run.
const JobHold = "hold"

// LastJobRun returns the newest run of a workload, or nil. Holds are not
// runs.
func (s *Store) LastJobRun(ctx context.Context, app, workload string) (*JobRun, error) {
	rows, err := s.queryJobRuns(ctx, selectJobRun+` WHERE app = ? AND workload = ? AND kind <> ? ORDER BY started_at DESC, id DESC LIMIT 1`, app, workload, JobHold)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// HoldJob records an operator's hold on a cron workload from placed until
// until, and why.
func (s *Store) HoldJob(ctx context.Context, app, workload, revision string, placed, until time.Time, reason string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO job_runs (app, workload, revision, kind, started_at, finished_at, exit_code, output) VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		app, workload, revision, JobHold, unix(placed), unix(until), reason)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LastJobHold returns the newest hold placed on a workload, ended or not,
// or nil.
func (s *Store) LastJobHold(ctx context.Context, app, workload string) (*JobRun, error) {
	rows, err := s.queryJobRuns(ctx, selectJobRun+` WHERE app = ? AND workload = ? AND kind = ? ORDER BY started_at DESC, id DESC LIMIT 1`, app, workload, JobHold)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// EndJobHold ends a hold early, at at.
func (s *Store) EndJobHold(ctx context.Context, id int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE job_runs SET finished_at = ? WHERE id = ? AND kind = ?`, unix(at), id, JobHold)
	return err
}

// JobRuns lists runs and holds, newest first. An empty workload means
// every workload.
func (s *Store) JobRuns(ctx context.Context, app, workload string, limit int) ([]JobRun, error) {
	if limit <= 0 {
		limit = 20
	}
	query := selectJobRun + ` WHERE app = ?`
	args := []any{app}
	if workload != "" {
		query += ` AND workload = ?`
		args = append(args, workload)
	}
	query += ` ORDER BY started_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	return s.queryJobRuns(ctx, query, args...)
}

// OpenJobRuns lists the runs that haven't finished, oldest first: what a
// daemon that starts finds left over from the one before.
func (s *Store) OpenJobRuns(ctx context.Context) ([]JobRun, error) {
	return s.queryJobRuns(ctx, selectJobRun+` WHERE finished_at = 0 ORDER BY started_at, id`)
}

const selectJobRun = `SELECT id, app, workload, revision, kind, started_at, finished_at, exit_code, error, output, container FROM job_runs`

func (s *Store) queryJobRuns(ctx context.Context, query string, args ...any) ([]JobRun, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRun
	for rows.Next() {
		var r JobRun
		var started, finished int64
		if err := rows.Scan(&r.ID, &r.App, &r.Workload, &r.Revision, &r.Kind, &started, &finished, &r.ExitCode, &r.Error, &r.Output, &r.Container); err != nil {
			return nil, err
		}
		r.StartedAt, r.FinishedAt = fromUnix(started), fromUnix(finished)
		out = append(out, r)
	}
	return out, rows.Err()
}
