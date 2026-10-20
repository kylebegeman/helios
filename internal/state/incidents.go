package state

import (
	"context"
	"fmt"
	"time"
)

// Incident severities. A notice is something an operator chose, such as a
// skipped drill or a held cron workload: worth seeing, never an alert.
const (
	SeverityNotice   = "notice"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Incident is a condition the watcher found and kept finding: an app
// down, a disk filling, a backup gone stale. One per key at a time.
type Incident struct {
	ID int64 `json:"id"`
	// Key names the condition, such as app:dragon-writer or host:disk.
	Key      string `json:"key"`
	Subject  string `json:"subject"`
	Severity string `json:"severity"`
	// Message is the latest observation, in plain words.
	Message    string    `json:"message"`
	OpenedAt   time.Time `json:"opened_at"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
	// NotifiedAt is when the last notice about it went out.
	NotifiedAt  time.Time `json:"notified_at,omitempty"`
	NotifyError string    `json:"notify_error,omitempty"`
	// Observations counts the rounds that saw it.
	Observations int `json:"observations"`
}

// Open reports whether the incident is still going.
func (i Incident) Open() bool { return i.ResolvedAt.IsZero() }

func (s *Store) migrateIncidents(ctx context.Context, q migrationDB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS incidents (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  key          TEXT NOT NULL,
  subject      TEXT NOT NULL,
  severity     TEXT NOT NULL,
  message      TEXT NOT NULL,
  opened_at    INTEGER NOT NULL,
  resolved_at  INTEGER NOT NULL DEFAULT 0,
  notified_at  INTEGER NOT NULL DEFAULT 0,
  notify_error TEXT NOT NULL DEFAULT '',
  observations INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_open ON incidents (resolved_at, key);
CREATE TABLE IF NOT EXISTS watches (
  url      TEXT PRIMARY KEY,
  added_at INTEGER NOT NULL
);`
	_, err := q.ExecContext(ctx, schema)
	return err
}

const incidentColumns = `id, key, subject, severity, message, opened_at, resolved_at, notified_at, notify_error, observations`

// OpenIncident records a new incident and returns its id.
func (s *Store) OpenIncident(ctx context.Context, i Incident) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO incidents (key, subject, severity, message, opened_at, observations) VALUES (?, ?, ?, ?, ?, ?)`,
		i.Key, i.Subject, i.Severity, i.Message, unix(i.OpenedAt), i.Observations)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateIncident saves an incident's changing fields.
func (s *Store) UpdateIncident(ctx context.Context, i Incident) error {
	_, err := s.db.ExecContext(ctx, `UPDATE incidents SET severity = ?, message = ?, resolved_at = ?, notified_at = ?, notify_error = ?, observations = ? WHERE id = ?`,
		i.Severity, i.Message, unix(i.ResolvedAt), unix(i.NotifiedAt), i.NotifyError, i.Observations, i.ID)
	return err
}

// OpenIncidents lists what is going on right now, oldest first.
func (s *Store) OpenIncidents(ctx context.Context) ([]Incident, error) {
	return s.queryIncidents(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE resolved_at = 0 ORDER BY opened_at, id`)
}

// PendingResolvedIncidentNotices retains failed recovery notices until the
// watcher successfully delivers them and clears notify_error.
func (s *Store) PendingResolvedIncidentNotices(ctx context.Context) ([]Incident, error) {
	return s.queryIncidents(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE resolved_at != 0 AND notify_error != '' ORDER BY resolved_at, id`)
}

// OpenIncidentByKey returns the open incident for a key, or nil.
func (s *Store) OpenIncidentByKey(ctx context.Context, key string) (*Incident, error) {
	rows, err := s.queryIncidents(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE resolved_at = 0 AND key = ? ORDER BY id DESC LIMIT 1`, key)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// Incidents lists incidents newest first, open ones included.
func (s *Store) Incidents(ctx context.Context, limit int) ([]Incident, error) {
	if limit <= 0 {
		limit = 20
	}
	return s.queryIncidents(ctx, `SELECT `+incidentColumns+` FROM incidents ORDER BY opened_at DESC, id DESC LIMIT ?`, limit)
}

// IncidentHistory includes every open incident plus the newest resolved
// incidents, bounded by pastLimit. A history limit never hides a live problem.
// Zero shows only open incidents.
func (s *Store) IncidentHistory(ctx context.Context, pastLimit int) ([]Incident, error) {
	if pastLimit < 0 {
		return nil, fmt.Errorf("the incident history limit must be zero or more")
	}
	return s.queryIncidents(ctx, `SELECT `+incidentColumns+` FROM incidents
		WHERE resolved_at = 0 OR id IN (
			SELECT id FROM incidents WHERE resolved_at != 0
			ORDER BY opened_at DESC, id DESC LIMIT ?
		)
		ORDER BY opened_at DESC, id DESC`, pastLimit)
}

func (s *Store) queryIncidents(ctx context.Context, query string, args ...any) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var i Incident
		var opened, resolved, notified int64
		if err := rows.Scan(&i.ID, &i.Key, &i.Subject, &i.Severity, &i.Message, &opened, &resolved, &notified, &i.NotifyError, &i.Observations); err != nil {
			return nil, err
		}
		i.OpenedAt, i.ResolvedAt, i.NotifiedAt = fromUnix(opened), fromUnix(resolved), fromUnix(notified)
		out = append(out, i)
	}
	return out, rows.Err()
}

// Watch is a public URL this machine checks from the outside, so a dead
// host elsewhere can't hide.
type Watch struct {
	URL     string    `json:"url"`
	AddedAt time.Time `json:"added_at"`
}

// AddWatch records a URL to keep checking.
func (s *Store) AddWatch(ctx context.Context, url string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO watches (url, added_at) VALUES (?, ?) ON CONFLICT(url) DO NOTHING`, url, unix(now))
	return err
}

// RemoveWatch stops checking a URL. ErrNotFound when it wasn't watched.
func (s *Store) RemoveWatch(ctx context.Context, url string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM watches WHERE url = ?`, url)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Watches lists the URLs being checked.
func (s *Store) Watches(ctx context.Context) ([]Watch, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT url, added_at FROM watches ORDER BY added_at, url`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Watch
	for rows.Next() {
		var w Watch
		var added int64
		if err := rows.Scan(&w.URL, &added); err != nil {
			return nil, err
		}
		w.AddedAt = fromUnix(added)
		out = append(out, w)
	}
	return out, rows.Err()
}
