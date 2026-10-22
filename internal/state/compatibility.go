package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kylebegeman/helios/internal/compat"
)

// SchemaVersion is the latest transactional on-disk migration this binary knows.
const SchemaVersion = compat.StateVersion

// OpenReadOnly opens existing state without creating directories, changing the
// journal mode, or migrating it. This connection also rejects every SQL write.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+dsnPath.Replace(path)+"?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path, readOnly: true}
	v, err := s.Version(context.Background())
	if err == nil && v > SchemaVersion {
		err = fmt.Errorf("state version %d is newer than this binary supports (%d); use a compatible binary", v, SchemaVersion)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// InspectVersion returns nil for an absent database, without creating it.
func InspectVersion(path string) (*int, error) {
	s, err := OpenReadOnly(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer s.Close()
	v, err := s.Version(context.Background())
	return &v, err
}

func (s *Store) Version(ctx context.Context) (int, error) {
	var version int
	err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	return version, err
}

// Checkpoint writes one consistent, private state copy before a binary switch.
// A successful previous attempt is retained during operation recovery.
func (s *Store) Checkpoint(ctx context.Context, path string) error {
	if _, err := os.Lstat(path); err == nil {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("upgrade checkpoint must be a regular file")
		}
		saved, err := OpenReadOnly(path)
		if err != nil {
			return err
		}
		defer saved.Close()
		expected, err := s.Version(ctx)
		if err != nil {
			return err
		}
		actual, err := saved.Version(ctx)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("upgrade checkpoint state version %d does not match %d", actual, expected)
		}
		var result string
		if err := saved.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
			return err
		}
		if result != "ok" {
			return fmt.Errorf("upgrade checkpoint is invalid: %s", result)
		}
		// Retain the original snapshot on recovery, with the same privacy
		// guarantee as a newly written checkpoint.
		return os.Chmod(path, 0o600)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return err
	}
	tmp := temp.Name()
	temp.Close()
	defer os.Remove(tmp)
	if err := s.BackupTo(ctx, tmp); err != nil {
		return fmt.Errorf("checkpoint state: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

const recoveryImportSchema = `CREATE TABLE IF NOT EXISTS machine_recoveries (
 id TEXT PRIMARY KEY,
 digest TEXT NOT NULL,
 imported_at INTEGER NOT NULL
);`
