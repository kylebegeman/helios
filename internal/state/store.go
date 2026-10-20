// Package state is helios's one store: a SQLite file that journals every
// operation and its steps, so a crash can be resumed or undone and every
// change leaves a receipt.
package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/compat"

	_ "modernc.org/sqlite" // the pure-Go driver keeps the binary static
)

// Store is an open state database.
type Store struct {
	db       *sql.DB
	path     string
	readOnly bool
}

// Open opens or creates the database at path, creating its directory with
// mode 0700. WAL mode lets the daemon write while the CLI reads.
func Open(path string) (*Store, error) {
	// Check an existing file through a read-only connection before WAL or
	// migrations can change it. Older binaries must fail closed on newer state.
	if _, err := InspectVersion(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	// SQLite creates files with the process umask. Reserve it privately before
	// connecting so custom state directories do not expose the journal.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	// Existing SQLite sidecars keep their original mode when the main file
	// is tightened. Older state must protect its uncheckpointed writes too.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("state sidecar %s: %w", suffix, err)
		}
	}

	// The path goes in as a file: URI, with what a URI would misread
	// escaped, so a "?" or "#" in it isn't taken for the query that
	// carries the pragmas; SQLite decodes the escapes itself.
	dsn := "file:" + dsnPath.Replace(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state: %w", err)
	}
	// One connection: SQLite serializes writers anyway, and this avoids
	// lock contention inside a single process.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// dsnPath escapes the characters a file: URI would read as its own.
var dsnPath = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")

// Path is where the database lives.
func (s *Store) Path() string { return s.path }

// BackupTo writes a consistent copy of the database to path.
func (s *Store) BackupTo(ctx context.Context, path string) error {
	sourceAbs, err := filepath.Abs(s.path)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if sourceAbs == targetAbs {
		return errors.New("state backup destination is the live database")
	}
	if destination, err := os.Stat(path); err == nil {
		if source, err := os.Stat(s.path); err == nil && os.SameFile(source, destination) {
			return errors.New("state backup destination refers to the live database")
		}
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".state-copy-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	defer os.Remove(tmp)
	// VACUUM INTO accepts an empty file. Keep the reservation and its 0600
	// mode while writing, then replace the destination only after success.
	query := "VACUUM INTO '" + strings.ReplaceAll(tmp, "'", "''") + "'"
	finish := func() error {
		file, err := os.OpenFile(tmp, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		// VACUUM INTO does not sync its output. Flush the complete copy
		// before the rename, then persist the destination directory entry.
		if err := errors.Join(file.Chmod(0o600), file.Sync(), file.Close()); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		return errors.Join(dir.Sync(), dir.Close())
	}
	if s.readOnly {
		// VACUUM INTO writes only its new destination. mode=ro continues to
		// protect the source while query_only is relaxed on this held connection.
		conn, err := s.db.Conn(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, "PRAGMA query_only=OFF"); err != nil {
			return err
		}
		defer conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA query_only=ON")
		if _, err = conn.ExecContext(ctx, query); err != nil {
			return err
		}
		return finish()
	}
	if _, err = s.db.ExecContext(ctx, query); err != nil {
		return err
	}
	return finish()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

type migrationDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return err
	}
	if current > compat.StateVersion {
		return fmt.Errorf("state version %d is newer than this binary supports (%d)", current, compat.StateVersion)
	}
	if current == compat.StateVersion {
		return tx.Commit()
	}
	const schema = `
CREATE TABLE IF NOT EXISTS operations (
  id            TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,
  target        TEXT NOT NULL,
  input         TEXT NOT NULL,
  plan          TEXT NOT NULL,
  plan_digest   TEXT NOT NULL,
  recovery      TEXT NOT NULL,
  status        TEXT NOT NULL,
  error         TEXT NOT NULL DEFAULT '',
  receipt       TEXT NOT NULL DEFAULT '',
  lease_owner   TEXT NOT NULL DEFAULT '',
  lease_until   INTEGER NOT NULL DEFAULT 0,
  interruptions INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  started_at    INTEGER NOT NULL DEFAULT 0,
  finished_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS operations_created ON operations (created_at DESC);
CREATE TABLE IF NOT EXISTS steps (
  operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
  idx          INTEGER NOT NULL,
  name         TEXT NOT NULL,
  status       TEXT NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  error        TEXT NOT NULL DEFAULT '',
  output       TEXT NOT NULL DEFAULT '',
  started_at   INTEGER NOT NULL DEFAULT 0,
  finished_at  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (operation_id, idx)
);`
	_, err = tx.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("migrate state: %w", err)
	}
	for _, step := range []func(context.Context, migrationDB) error{s.migrateApps, s.migrateBackups, s.migrateIncidents, s.migrateSignals, s.migrateGitHooks, s.migrateReleaseBoundaries} {
		if err := step(ctx, tx); err != nil {
			return fmt.Errorf("migrate state: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, recoveryImportSchema); err != nil {
		return fmt.Errorf("migrate state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", compat.StateVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// OperationStatus is where an operation is in its life.
type OperationStatus string

const (
	// Planned means the plan is recorded and nothing has been applied.
	Planned OperationStatus = "planned"
	// Applying means steps are running, or were when the daemon died.
	Applying OperationStatus = "applying"
	// Succeeded means every step applied.
	Succeeded OperationStatus = "succeeded"
	// Failed means a step failed and nothing was undone.
	Failed OperationStatus = "failed"
	// Compensated means a step failed or the daemon died, and the completed
	// steps were undone.
	Compensated OperationStatus = "compensated"
)

// Final reports whether the status is terminal.
func (s OperationStatus) Final() bool {
	return s == Succeeded || s == Failed || s == Compensated
}

// StepStatus is where a step is in its life.
type StepStatus string

const (
	StepPending   StepStatus = "pending"
	StepRunning   StepStatus = "running"
	StepSucceeded StepStatus = "succeeded"
	StepFailed    StepStatus = "failed"
	// StepUndone means the step had succeeded and was then undone.
	StepUndone StepStatus = "undone"
)

// Operation is one journaled operation.
type Operation struct {
	ID            string
	Kind          string
	Target        string
	Input         json.RawMessage
	Plan          json.RawMessage
	PlanDigest    string
	Recovery      string
	Status        OperationStatus
	Error         string
	Receipt       json.RawMessage
	LeaseOwner    string
	LeaseUntil    time.Time
	Interruptions int
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
}

// Step is one journaled step of an operation.
type Step struct {
	OperationID string
	Index       int
	Name        string
	Status      StepStatus
	Attempts    int
	Error       string
	Output      string
	StartedAt   time.Time
	FinishedAt  time.Time
}

// NewOperation is what CreateOperation needs.
type NewOperation struct {
	ID         string
	Kind       string
	Target     string
	Input      json.RawMessage
	Plan       json.RawMessage
	PlanDigest string
	Recovery   string
	StepNames  []string
	CreatedAt  time.Time
}

// ErrNotFound is returned for an operation, revision, backup or job run,
// incident, watch or webhook the store doesn't have; callers say which.
var ErrNotFound = errors.New("not found")

// ErrLeased is returned when another owner holds a live lease.
var ErrLeased = errors.New("operation is leased by another owner")

// CreateOperation records a planned operation and its pending steps.
func (s *Store) CreateOperation(ctx context.Context, op NewOperation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO operations (id, kind, target, input, plan, plan_digest, recovery, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.Kind, op.Target, string(op.Input), string(op.Plan), op.PlanDigest, op.Recovery, string(Planned), unix(op.CreatedAt))
	if err != nil {
		return fmt.Errorf("record operation: %w", err)
	}
	for i, name := range op.StepNames {
		if _, err := tx.ExecContext(ctx, `INSERT INTO steps (operation_id, idx, name, status) VALUES (?, ?, ?, ?)`, op.ID, i, name, string(StepPending)); err != nil {
			return fmt.Errorf("record step: %w", err)
		}
	}
	return tx.Commit()
}

// Claim takes the lease on an operation for owner until `until`, marks it
// applying, and counts an interruption when a previous owner had it. It
// fails with ErrLeased while another owner's lease is live.
func (s *Store) Claim(ctx context.Context, id, owner string, now, until time.Time) (*Operation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	op, err := scanOperation(tx.QueryRowContext(ctx, selectOperation+` WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if op.Status.Final() {
		return nil, fmt.Errorf("operation %s is already %s", id, op.Status)
	}
	if op.LeaseOwner != "" && op.LeaseOwner != owner && op.LeaseUntil.After(now) {
		return nil, ErrLeased
	}
	interrupted := op.LeaseOwner != "" && op.LeaseOwner != owner
	interruptions := op.Interruptions
	if interrupted {
		interruptions++
	}
	startedAt := op.StartedAt
	if startedAt.IsZero() {
		startedAt = now
	}
	_, err = tx.ExecContext(ctx, `UPDATE operations SET status = ?, lease_owner = ?, lease_until = ?, interruptions = ?, started_at = ? WHERE id = ?`,
		string(Applying), owner, unix(until), interruptions, unix(startedAt), id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	op.Status = Applying
	op.LeaseOwner = owner
	op.LeaseUntil = until
	op.Interruptions = interruptions
	op.StartedAt = startedAt
	return op, nil
}

// Renew extends owner's lease. It fails when the lease was lost.
func (s *Store) Renew(ctx context.Context, id, owner string, until time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE operations SET lease_until = ? WHERE id = ? AND lease_owner = ? AND status = ?`, unix(until), id, owner, string(Applying))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrLeased
	}
	return nil
}

// StepStarted marks a step running and counts the attempt.
func (s *Store) StepStarted(ctx context.Context, id string, index int, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE steps SET status = ?, attempts = attempts + 1, started_at = ?, error = '' WHERE operation_id = ? AND idx = ?`,
		string(StepRunning), unix(now), id, index)
	return err
}

// StepFinished records how a step ended and the tail of its output.
func (s *Store) StepFinished(ctx context.Context, id string, index int, status StepStatus, stepErr string, output string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE steps SET status = ?, error = ?, output = ?, finished_at = ? WHERE operation_id = ? AND idx = ?`,
		string(status), stepErr, output, unix(now), id, index)
	return err
}

// Finish records the operation's outcome and receipt and releases the lease.
func (s *Store) Finish(ctx context.Context, id string, status OperationStatus, opErr string, receipt json.RawMessage, now time.Time) error {
	if !status.Final() {
		return fmt.Errorf("%s is not a final status", status)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE operations SET status = ?, error = ?, receipt = ?, lease_owner = '', lease_until = 0, finished_at = ? WHERE id = ?`,
		string(status), opErr, string(receipt), unix(now), id)
	return err
}

// Get returns one operation and its steps.
func (s *Store) Get(ctx context.Context, id string) (*Operation, []Step, error) {
	op, err := scanOperation(s.db.QueryRowContext(ctx, selectOperation+` WHERE id = ?`, id))
	if err != nil {
		return nil, nil, err
	}
	steps, err := s.Steps(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return op, steps, nil
}

// Steps returns an operation's steps in order.
func (s *Store) Steps(ctx context.Context, id string) ([]Step, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT operation_id, idx, name, status, attempts, error, output, started_at, finished_at FROM steps WHERE operation_id = ? ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var steps []Step
	for rows.Next() {
		var st Step
		var started, finished int64
		if err := rows.Scan(&st.OperationID, &st.Index, &st.Name, &st.Status, &st.Attempts, &st.Error, &st.Output, &started, &finished); err != nil {
			return nil, err
		}
		st.StartedAt, st.FinishedAt = fromUnix(started), fromUnix(finished)
		steps = append(steps, st)
	}
	return steps, rows.Err()
}

// OperationFilter selects history before the result limit is applied.
// Failed includes compensated operations because their requested changes did
// not succeed. Since includes operations created at or after that instant,
// and Until those created at or before it.
type OperationFilter struct {
	Target string
	Kind   string
	Failed bool
	Since  time.Time
	Until  time.Time
	Limit  int
}

// List returns the most recent operations, newest first.
func (s *Store) List(ctx context.Context, limit int) ([]Operation, error) {
	return s.ListFiltered(ctx, OperationFilter{Limit: limit})
}

// ListFiltered returns matching operations, newest first. Empty filters
// retain List's behavior, including its default limit of 50.
func (s *Store) ListFiltered(ctx context.Context, filter OperationFilter) ([]Operation, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	var clauses []string
	var args []any
	if filter.Target != "" {
		clauses = append(clauses, "target = ?")
		args = append(args, filter.Target)
	}
	if filter.Kind != "" {
		clauses = append(clauses, "kind = ?")
		args = append(args, filter.Kind)
	}
	if filter.Failed {
		clauses = append(clauses, "status IN (?, ?)")
		args = append(args, string(Failed), string(Compensated))
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, "created_at >= ?")
		args = append(args, unix(filter.Since))
	}
	if !filter.Until.IsZero() {
		clauses = append(clauses, "created_at <= ?")
		args = append(args, unix(filter.Until))
	}
	query := selectOperation
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, filter.Limit)
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ops []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		ops = append(ops, *op)
	}
	return ops, rows.Err()
}

// LastOfKind returns the most recent operation of a kind, or nil when the
// machine has never run one. It is how a schedule knows whether work that
// keeps no records of its own is due.
func (s *Store) LastOfKind(ctx context.Context, kind string) (*Operation, error) {
	rows, err := s.db.QueryContext(ctx, selectOperation+` WHERE kind = ? ORDER BY created_at DESC, id DESC LIMIT 1`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanOperation(rows)
}

// Orphaned returns operations that were applying under a lease that has
// expired: the owner died or lost the lease. Oldest first.
func (s *Store) Orphaned(ctx context.Context, now time.Time) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, selectOperation+` WHERE status = ? AND lease_until < ? ORDER BY created_at`, string(Applying), unix(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ops []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		ops = append(ops, *op)
	}
	return ops, rows.Err()
}

const selectOperation = `SELECT id, kind, target, input, plan, plan_digest, recovery, status, error, receipt, lease_owner, lease_until, interruptions, created_at, started_at, finished_at FROM operations`

type scanner interface {
	Scan(dest ...any) error
}

func scanOperation(row scanner) (*Operation, error) {
	var op Operation
	var input, plan, receipt string
	var leaseUntil, createdAt, startedAt, finishedAt int64
	err := row.Scan(&op.ID, &op.Kind, &op.Target, &input, &plan, &op.PlanDigest, &op.Recovery, &op.Status, &op.Error, &receipt,
		&op.LeaseOwner, &leaseUntil, &op.Interruptions, &createdAt, &startedAt, &finishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	op.Input, op.Plan = json.RawMessage(input), json.RawMessage(plan)
	if receipt != "" {
		op.Receipt = json.RawMessage(receipt)
	}
	op.LeaseUntil, op.CreatedAt, op.StartedAt, op.FinishedAt = fromUnix(leaseUntil), fromUnix(createdAt), fromUnix(startedAt), fromUnix(finishedAt)
	return &op, nil
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromUnix(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}
