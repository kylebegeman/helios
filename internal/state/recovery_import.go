package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type recoveryTable struct {
	name    string
	columns []string
	rows    [][]any
}

// ImportMachineRecovery adds app records from an immutable machine snapshot to
// this store. The destination's journal, integrations and existing apps remain
// authoritative. Source containers never become active on another host. The
// caller supplies newly restored private revisions; activation is a later step.
func (s *Store) ImportMachineRecovery(ctx context.Context, sourceDBPath, recoveryID string, secretVersions map[string]map[int]int, appRevisions []Revision) error {
	if strings.TrimSpace(recoveryID) == "" {
		return errors.New("machine recovery needs an ID")
	}
	source, err := OpenReadOnly(sourceDBPath)
	if err != nil {
		return err
	}
	defer source.Close()
	v, err := source.Version(ctx)
	if err != nil {
		return err
	}
	if v < SchemaVersion {
		// Migrate a private consistent copy, preserving the archived source.
		scratch, err := os.MkdirTemp("", "bedrock-state-import-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(scratch)
		path := filepath.Join(scratch, "state.db")
		if err := source.BackupTo(ctx, path); err != nil {
			return err
		}
		migrated, err := Open(path)
		if err != nil {
			return fmt.Errorf("migrate historical machine snapshot copy: %w", err)
		}
		defer migrated.Close()
		source = migrated
	}
	tables := []recoveryTable{
		{name: "apps", columns: []string{"name", "active_revision", "updated_at"}},
		{name: "revisions", columns: []string{"app", "id", "status", "manifest", "images", "containers", "source", "secrets_version", "created_at"}},
		{name: "job_runs", columns: []string{"app", "workload", "revision", "kind", "started_at", "finished_at", "exit_code", "error", "output", "container"}},
		{name: "backup_runs", columns: []string{"app", "kind", "started_at", "finished_at", "ok", "snapshot", "snapshot_at", "files", "bytes", "detail", "error"}},
		{name: "git_hooks", columns: []string{"app", "repo", "branch", "created_at", "last_commit", "last_result", "last_at"}},
		{name: "signals", columns: []string{"hour", "app", "key", "metric", "value", "samples"}},
		{name: "release_boundaries", columns: []string{"app", "revision", "previous_revision", "compatibility", "snapshot", "status", "started_at", "finished_at", "error"}},
		{name: "watches", columns: []string{"url", "added_at"}},
		{name: "incidents", columns: []string{"key", "subject", "severity", "message", "opened_at", "resolved_at", "notified_at", "notify_error", "observations"}},
	}
	sourceTx, err := source.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer sourceTx.Rollback()
	for i := range tables {
		rows, err := sourceTx.QueryContext(ctx, "SELECT "+strings.Join(tables[i].columns, ",")+" FROM "+tables[i].name+" ORDER BY "+strings.Join(tables[i].columns, ","))
		if err != nil {
			return err
		}
		for rows.Next() {
			values := make([]any, len(tables[i].columns))
			ptrs := make([]any, len(values))
			for j := range values {
				ptrs[j] = &values[j]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return err
			}
			for j, value := range values {
				checked, err := checkRecoveryValue(tables[i].columns[j], value)
				if err != nil {
					rows.Close()
					return fmt.Errorf("invalid recovery snapshot %s.%s: %w", tables[i].name, tables[i].columns[j], err)
				}
				values[j] = checked
			}
			tables[i].rows = append(tables[i].rows, values)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	if err := sourceTx.Commit(); err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Rows      [][][]any
		Secrets   map[string]map[int]int
		Revisions []Revision
	}{Rows: recoveryRows(tables), Secrets: secretVersions, Revisions: appRevisions})
	if err != nil {
		return err
	}
	hash := sha256.Sum256(body)
	digest := hex.EncodeToString(hash[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var imported string
	err = tx.QueryRowContext(ctx, "SELECT digest FROM machine_recoveries WHERE id=?", recoveryID).Scan(&imported)
	if err == nil {
		if imported != digest {
			return errors.New("machine recovery ID already belongs to different snapshot or revisions")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	apps := map[string]bool{}
	for _, table := range tables {
		if table.name == "apps" || table.name == "revisions" {
			for _, row := range table.rows {
				apps[row[0].(string)] = true
			}
		}
	}
	for app := range apps {
		var count int
		err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM apps WHERE name=?) + (SELECT COUNT(*) FROM revisions WHERE app=?) + (SELECT COUNT(*) FROM git_hooks WHERE app=?)`, app, app, app).Scan(&count)
		if err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("machine recovery refuses to overwrite existing app %s", app)
		}
	}
	now := unix(time.Now().UTC())
	for _, table := range tables {
		query := "INSERT INTO " + table.name + " (" + strings.Join(table.columns, ",") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(table.columns)), ",") + ")"
		if table.name == "watches" {
			query += " ON CONFLICT(url) DO NOTHING"
		}
		for _, row := range table.rows {
			switch table.name {
			case "apps":
				row[1] = ""
			case "revisions":
				if row[2] == string(RevisionActive) || row[2] == string(RevisionPrevious) {
					row[2] = string(RevisionRetired)
				}
				row[5] = "{}"
				original := int(row[7].(int64))
				if original > 0 {
					mapped, ok := secretVersions[row[0].(string)][original]
					if !ok || mapped <= 0 {
						return fmt.Errorf("missing resealed secrets version %d for %s", original, row[0])
					}
					row[7] = mapped
				}
			case "job_runs":
				row[9] = ""
				if row[5].(int64) == 0 {
					row[5] = now
					row[6] = int64(-1)
					row[7] = "interrupted on source machine before recovery"
				}
			case "backup_runs":
				if row[3].(int64) == 0 {
					row[3] = now
					row[4] = int64(0)
					row[10] = "interrupted on source machine before recovery"
				}
			case "release_boundaries":
				if row[5] == "started" || row[5] == "restoring" {
					row[5] = "failed"
					row[7] = now
					row[8] = "interrupted on source machine before recovery"
				}
			case "incidents":
				if row[5].(int64) == 0 {
					row[5] = now
				}
			case "signals":
				// Host disk rows describe the source machine's root
				// filesystem. The target samples its own from the moment it
				// starts, so the same hours would collide, and the rest would
				// fit two machines' disks into one forecast.
				if row[3] == SignalHostDiskUsed {
					continue
				}
			}
			if _, err := tx.ExecContext(ctx, query, row...); err != nil {
				return fmt.Errorf("import %s: %w", table.name, err)
			}
		}
	}
	for app := range apps {
		if _, err := tx.ExecContext(ctx, "INSERT INTO apps(name,active_revision,updated_at) VALUES(?,'',?) ON CONFLICT(name) DO NOTHING", app, now); err != nil {
			return err
		}
	}
	for _, r := range appRevisions {
		if !apps[r.App] || r.ID == "" {
			return fmt.Errorf("recovery revision %s/%s has no source app", r.App, r.ID)
		}
		r.Status = RevisionFailed
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
		_, err = tx.ExecContext(ctx, `INSERT INTO revisions(app,id,status,manifest,images,containers,source,secrets_version,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, r.App, r.ID, r.Status, string(r.Manifest), string(images), string(containers), r.Source, r.SecretsVersion, unix(r.CreatedAt))
		if err != nil {
			return fmt.Errorf("record private recovery revision %s/%s: %w", r.App, r.ID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO machine_recoveries(id,digest,imported_at) VALUES(?,?,?)", recoveryID, digest, now); err != nil {
		return err
	}
	return tx.Commit()
}
func recoveryRows(tables []recoveryTable) [][][]any {
	out := make([][][]any, len(tables))
	for i, t := range tables {
		out[i] = t.rows
	}
	return out
}

func checkRecoveryValue(column string, value any) (any, error) {
	switch column {
	case "updated_at", "created_at", "secrets_version", "started_at", "finished_at", "exit_code", "ok", "snapshot_at", "files", "bytes", "hour", "samples", "added_at", "opened_at", "resolved_at", "notified_at", "last_at", "observations":
		if _, ok := value.(int64); !ok {
			return nil, errors.New("expected an integer")
		}
		return value, nil
	case "value":
		switch number := value.(type) {
		case float64:
			return number, nil
		case int64:
			return float64(number), nil
		default:
			return nil, errors.New("expected a number")
		}
	default:
		if bytes, ok := value.([]byte); ok {
			value = string(bytes)
		}
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("expected text")
		}
		if column == "manifest" || column == "images" || column == "containers" {
			if !json.Valid([]byte(text)) {
				return nil, errors.New("expected valid JSON")
			}
		}
		return text, nil
	}
}

// MachineRecoveryImported reports whether this recovery's transactional import
// completed, even when the caller's later filesystem record save was interrupted.
func (s *Store) MachineRecoveryImported(ctx context.Context, recoveryID string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM machine_recoveries WHERE id=?)", recoveryID).Scan(&exists)
	return exists, err
}

// LastMachineRecoveryImportedAt is when this store last imported a machine
// recovery, or the zero time when it never has.
func (s *Store) LastMachineRecoveryImportedAt(ctx context.Context) (time.Time, error) {
	var at sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT MAX(imported_at) FROM machine_recoveries").Scan(&at); err != nil {
		return time.Time{}, err
	}
	return fromUnix(at.Int64), nil
}
