package state

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// The storage watch keeps three small tables: tombstones for the buckets of
// removed apps, nightly size samples, and when each repository last had a
// full prune.
//
// They are created on every writable open instead of by a numbered
// migration. Raising the state version would make every older binary refuse
// the store, and an upgrade refuse to start without a coordinated migration,
// for tables an older binary never reads. Everything here is additive: an
// older binary ignores the tables, and losing them only costs a week of
// growth history and the 30 day clock of a removed app's bucket, which then
// simply stays.
const storageSchema = `
CREATE TABLE IF NOT EXISTS storage_tombstones (
  app        TEXT PRIMARY KEY,
  bucket     TEXT NOT NULL,
  removed_at INTEGER NOT NULL,
  kept_at    INTEGER NOT NULL DEFAULT 0,
  account    TEXT NOT NULL DEFAULT '',
  problem    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS storage_samples (
  bucket                TEXT NOT NULL,
  taken_at              INTEGER NOT NULL,
  owner                 TEXT NOT NULL DEFAULT '',
  kind                  TEXT NOT NULL,
  stored_bytes          INTEGER NOT NULL DEFAULT -1,
  files                 INTEGER NOT NULL DEFAULT -1,
  used_bytes            INTEGER NOT NULL DEFAULT -1,
  snapshots             INTEGER NOT NULL DEFAULT -1,
  newest_snapshot_at    INTEGER NOT NULL DEFAULT 0,
  oldest_snapshot_at    INTEGER NOT NULL DEFAULT 0,
  newest_snapshot_bytes INTEGER NOT NULL DEFAULT -1,
  last_write_at         INTEGER NOT NULL DEFAULT 0,
  note                  TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (bucket, taken_at)
);
CREATE TABLE IF NOT EXISTS storage_prunes (
  bucket       TEXT PRIMARY KEY,
  attempted_at INTEGER NOT NULL DEFAULT 0,
  completed_at INTEGER NOT NULL DEFAULT 0
);
CREATE TRIGGER IF NOT EXISTS storage_tombstone_cleared_by_revision
AFTER INSERT ON revisions
BEGIN
  DELETE FROM storage_tombstones WHERE app = NEW.app;
END;`

// ensureStorage creates the storage watch's tables. The trigger is the
// guard that matters: whatever records a revision for an app, a deploy, a
// move's staging or a machine recovery, the app is back and its bucket is
// in use, so the tombstone that would delete that bucket goes in the same
// write. No code path has to remember to clear it.
func (s *Store) ensureStorage(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, storageSchema)
	return err
}

// Storage sample kinds: whose bucket a sample describes.
const (
	// StorageApp is the bucket of an app this machine runs and backs up.
	StorageApp = "app"
	// StorageMachine is this machine's own recovery repository.
	StorageMachine = "machine"
	// StorageRemoved is the bucket of an app this machine removed, waiting
	// for its tombstone to expire.
	StorageRemoved = "removed"
	// StorageForeign is a bucket that carries this machine's prefix and
	// that this machine does not own. It is only ever reported.
	StorageForeign = "foreign"
)

// StorageUnknown is a sample's value for a figure the sweep could not read.
const StorageUnknown = -1

// StorageTombstone says this machine removed an app and its bucket is
// waiting to expire. Only a bucket with a tombstone is ever deleted.
type StorageTombstone struct {
	App       string    `json:"app"`
	Bucket    string    `json:"bucket"`
	RemovedAt time.Time `json:"removed_at"`
	// KeptAt is when an operator cancelled the expiry. The row stays, so
	// the report still shows the bucket and it can still be purged by hand.
	KeptAt time.Time `json:"kept_at,omitempty"`
	// Account is the storage account the bucket was first seen in, so a
	// changed storage integration never deletes a same-named bucket in
	// another account.
	Account string `json:"account,omitempty"`
	// Problem is why the last sweep refused to delete the bucket.
	Problem string `json:"problem,omitempty"`
}

// Kept reports whether an operator cancelled the expiry.
func (t StorageTombstone) Kept() bool { return !t.KeptAt.IsZero() }

// StorageSample is one night's reading of one bucket.
type StorageSample struct {
	Bucket  string    `json:"bucket"`
	TakenAt time.Time `json:"taken_at"`
	// Owner is the app, or the machine target, the bucket belongs to; empty
	// for a foreign bucket.
	Owner string `json:"owner,omitempty"`
	Kind  string `json:"kind"`
	// StoredBytes is every file version in the bucket: what is billed.
	StoredBytes int64 `json:"stored_bytes"`
	Files       int64 `json:"files"`
	// UsedBytes is what the repository's snapshots still reference.
	UsedBytes           int64     `json:"used_bytes"`
	Snapshots           int64     `json:"snapshots"`
	NewestSnapshotAt    time.Time `json:"newest_snapshot_at,omitempty"`
	OldestSnapshotAt    time.Time `json:"oldest_snapshot_at,omitempty"`
	NewestSnapshotBytes int64     `json:"newest_snapshot_bytes"`
	// LastWriteAt is the newest upload the object store reports.
	LastWriteAt time.Time `json:"last_write_at,omitempty"`
	// Note says what could not be read, and why.
	Note string `json:"note,omitempty"`
}

// StoragePrune is when a repository's weekly full prune last ran.
type StoragePrune struct {
	Bucket      string    `json:"bucket"`
	AttemptedAt time.Time `json:"attempted_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// missingStorage reports a store an older binary made and no current daemon
// has opened for writing yet: a read-only command then finds no tables, and
// that reads as nothing recorded.
func missingStorage(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table: storage_")
}

// RemoveAppLeavingTombstone forgets an app as RemoveApp does and, in the
// same transaction, records that its bucket may expire. Recording the two
// together is the point: a tombstone exists only for an app this machine
// held and removed, and an app that is still recorded never has one.
func (s *Store) RemoveAppLeavingTombstone(ctx context.Context, app, bucket string, at time.Time) error {
	if app == "" || bucket == "" || at.IsZero() {
		return errors.New("a storage tombstone needs an app, a bucket and a time")
	}
	return s.removeApp(ctx, app, &StorageTombstone{App: app, Bucket: bucket, RemovedAt: at})
}

func recordTombstone(ctx context.Context, tx *sql.Tx, t StorageTombstone) error {
	// A second removal restarts the clock and withdraws an earlier keep or
	// refusal: the newest removal is the one the operator saw.
	_, err := tx.ExecContext(ctx, `INSERT INTO storage_tombstones (app, bucket, removed_at) VALUES (?, ?, ?)
		ON CONFLICT(app) DO UPDATE SET bucket = excluded.bucket, removed_at = excluded.removed_at, kept_at = 0, account = '', problem = ''`,
		t.App, t.Bucket, unix(t.RemovedAt))
	return err
}

const selectTombstone = `SELECT app, bucket, removed_at, kept_at, account, problem FROM storage_tombstones`

func scanTombstone(row scanner) (*StorageTombstone, error) {
	var t StorageTombstone
	var removed, kept int64
	if err := row.Scan(&t.App, &t.Bucket, &removed, &kept, &t.Account, &t.Problem); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.RemovedAt, t.KeptAt = fromUnix(removed), fromUnix(kept)
	return &t, nil
}

// StorageTombstones lists the buckets of removed apps, by app.
func (s *Store) StorageTombstones(ctx context.Context) ([]StorageTombstone, error) {
	rows, err := s.db.QueryContext(ctx, selectTombstone+` ORDER BY app`)
	if missingStorage(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StorageTombstone
	for rows.Next() {
		t, err := scanTombstone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// StorageTombstone returns a removed app's tombstone, or ErrNotFound.
func (s *Store) StorageTombstone(ctx context.Context, app string) (*StorageTombstone, error) {
	t, err := scanTombstone(s.db.QueryRowContext(ctx, selectTombstone+` WHERE app = ?`, app))
	if missingStorage(err) {
		return nil, ErrNotFound
	}
	return t, err
}

func (s *Store) changeTombstone(ctx context.Context, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
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

// KeepStorageTombstone cancels a bucket's expiry. ErrNotFound when the app
// has no tombstone.
func (s *Store) KeepStorageTombstone(ctx context.Context, app string, at time.Time) error {
	return s.changeTombstone(ctx, `UPDATE storage_tombstones SET kept_at = ?, problem = '' WHERE app = ?`, unix(at), app)
}

// BindStorageTombstone records the account a tombstoned bucket was seen in.
// It binds once: a tombstone already bound keeps its account.
func (s *Store) BindStorageTombstone(ctx context.Context, app, account string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE storage_tombstones SET account = ? WHERE app = ? AND account = ''`, account, app)
	return err
}

// SetStorageTombstoneProblem records why a bucket was not deleted, or
// clears it with an empty problem.
func (s *Store) SetStorageTombstoneProblem(ctx context.Context, app, problem string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE storage_tombstones SET problem = ? WHERE app = ?`, problem, app)
	return err
}

// DeleteStorageTombstone drops a tombstone: its bucket is gone, or the app
// is back.
func (s *Store) DeleteStorageTombstone(ctx context.Context, app string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM storage_tombstones WHERE app = ?`, app)
	return err
}

// StorageSamplesPerBucket bounds one bucket's history however often a sweep
// runs: two a day for the whole retention window.
const StorageSamplesPerBucket = 70

// AddStorageSamples records one sweep's readings and drops every sample
// older than keepSince, so the table stays a bounded window.
func (s *Store) AddStorageSamples(ctx context.Context, samples []StorageSample, keepSince time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, m := range samples {
		if m.Bucket == "" || m.TakenAt.IsZero() || m.Kind == "" {
			return errors.New("a storage sample needs a bucket, a kind and a time")
		}
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO storage_samples
			(bucket, taken_at, owner, kind, stored_bytes, files, used_bytes, snapshots, newest_snapshot_at, oldest_snapshot_at, newest_snapshot_bytes, last_write_at, note)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			m.Bucket, unix(m.TakenAt), m.Owner, m.Kind, m.StoredBytes, m.Files, m.UsedBytes, m.Snapshots,
			unix(m.NewestSnapshotAt), unix(m.OldestSnapshotAt), m.NewestSnapshotBytes, unix(m.LastWriteAt), m.Note)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM storage_samples WHERE bucket = ? AND taken_at NOT IN
			(SELECT taken_at FROM storage_samples WHERE bucket = ? ORDER BY taken_at DESC LIMIT ?)`, m.Bucket, m.Bucket, StorageSamplesPerBucket); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM storage_samples WHERE taken_at < ?`, unix(keepSince)); err != nil {
		return err
	}
	return tx.Commit()
}

// StorageSamples returns every sample taken at or after since, by bucket
// and then oldest first.
func (s *Store) StorageSamples(ctx context.Context, since time.Time) ([]StorageSample, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT bucket, taken_at, owner, kind, stored_bytes, files, used_bytes, snapshots, newest_snapshot_at, oldest_snapshot_at, newest_snapshot_bytes, last_write_at, note
		FROM storage_samples WHERE taken_at >= ? ORDER BY bucket, taken_at`, unix(since))
	if missingStorage(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StorageSample
	for rows.Next() {
		var m StorageSample
		var taken, newest, oldest, written int64
		if err := rows.Scan(&m.Bucket, &taken, &m.Owner, &m.Kind, &m.StoredBytes, &m.Files, &m.UsedBytes, &m.Snapshots, &newest, &oldest, &m.NewestSnapshotBytes, &written, &m.Note); err != nil {
			return nil, err
		}
		m.TakenAt, m.NewestSnapshotAt, m.OldestSnapshotAt, m.LastWriteAt = fromUnix(taken), fromUnix(newest), fromUnix(oldest), fromUnix(written)
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteStorageSamples drops a bucket's samples, once the bucket is gone.
func (s *Store) DeleteStorageSamples(ctx context.Context, bucket string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM storage_samples WHERE bucket = ?`, bucket)
	return err
}

// StoragePruneOf returns when a repository's full prune last ran: the zero
// value when it never has.
func (s *Store) StoragePruneOf(ctx context.Context, bucket string) (StoragePrune, error) {
	p := StoragePrune{Bucket: bucket}
	var attempted, completed int64
	err := s.db.QueryRowContext(ctx, `SELECT attempted_at, completed_at FROM storage_prunes WHERE bucket = ?`, bucket).Scan(&attempted, &completed)
	if errors.Is(err, sql.ErrNoRows) || missingStorage(err) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	p.AttemptedAt, p.CompletedAt = fromUnix(attempted), fromUnix(completed)
	return p, nil
}

// StoragePruneAttempted records that a full prune is starting. It is written
// before the prune so one that dies with the daemon still counts as this
// week's attempt.
func (s *Store) StoragePruneAttempted(ctx context.Context, bucket string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO storage_prunes (bucket, attempted_at) VALUES (?, ?)
		ON CONFLICT(bucket) DO UPDATE SET attempted_at = excluded.attempted_at`, bucket, unix(at))
	return err
}

// StoragePruneCompleted records that a full prune finished.
func (s *Store) StoragePruneCompleted(ctx context.Context, bucket string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO storage_prunes (bucket, attempted_at, completed_at) VALUES (?, ?, ?)
		ON CONFLICT(bucket) DO UPDATE SET completed_at = excluded.completed_at`, bucket, unix(at), unix(at))
	return err
}
