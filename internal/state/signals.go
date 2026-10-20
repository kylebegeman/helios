package state

import (
	"context"
	"errors"
	"math"
	"time"
)

// Signal metric names. Traffic ones are keyed by host, resource ones by
// workload; every row is an hourly rollup.
const (
	// SignalRequests counts requests; SignalErrors those answered 5xx;
	// SignalObserved those the latency histogram saw complete.
	SignalRequests = "requests"
	SignalErrors   = "errors"
	SignalObserved = "observed"
	// SignalDurationMS is the sum of response times, in milliseconds.
	SignalDurationMS = "duration_ms"
	// SignalBytes is the sum of response sizes.
	SignalBytes = "bytes"
	// SignalBucketPrefix + a latency bound, such as le_0.25, counts
	// requests answered within that many seconds.
	SignalBucketPrefix = "le_"
	// SignalCPUPercent sums CPU use in percent of one core, over samples,
	// so value/samples is the average.
	SignalCPUPercent = "cpu_percent"
	// SignalMemoryBytes sums memory use over samples; SignalMemoryMax is
	// the largest sample.
	SignalMemoryBytes = "memory_bytes"
	SignalMemoryMax   = "memory_max"
	// SignalDiskBytes is what the app's volumes and database take on disk.
	SignalDiskBytes = "disk_bytes"
	// SignalHostDiskUsed is the most bytes in use on the machine's root
	// filesystem in the hour, kept under the reserved app with the key
	// SignalHostDiskRoot.
	SignalHostDiskUsed = "host_disk_used"
	SignalHostDiskRoot = "root"
)

// Signal is one hourly rollup.
type Signal struct {
	Hour    time.Time `json:"hour"`
	App     string    `json:"app"`
	Key     string    `json:"key"`
	Metric  string    `json:"metric"`
	Value   float64   `json:"value"`
	Samples int       `json:"samples"`
}

func (s *Store) migrateSignals(ctx context.Context, q migrationDB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS signals (
  hour    INTEGER NOT NULL,
  app     TEXT NOT NULL,
  key     TEXT NOT NULL,
  metric  TEXT NOT NULL,
  value   REAL NOT NULL,
  samples INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (hour, app, key, metric)
);
CREATE INDEX IF NOT EXISTS signals_app ON signals (app, hour);
CREATE TABLE IF NOT EXISTS integration_uses (
  name    TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  used_at INTEGER NOT NULL
);`
	_, err := q.ExecContext(ctx, schema)
	return err
}

// AddSignal adds a sample to an hour's rollup: the value is summed and the
// sample count grows, so averages come out as value/samples.
func (s *Store) AddSignal(ctx context.Context, sig Signal) error {
	if math.IsNaN(sig.Value) || math.IsInf(sig.Value, 0) {
		return errors.New("signal value must be finite")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO signals (hour, app, key, metric, value, samples) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(hour, app, key, metric) DO UPDATE SET value = value + excluded.value, samples = samples + excluded.samples WHERE ABS(value + excluded.value) <= ?`,
		unix(sig.Hour.Truncate(time.Hour)), sig.App, sig.Key, sig.Metric, sig.Value, sig.Samples, math.MaxFloat64)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("signal rollup value must stay finite")
	}
	return nil
}

// MaxSignal keeps the largest value seen in an hour.
func (s *Store) MaxSignal(ctx context.Context, sig Signal) error {
	if math.IsNaN(sig.Value) || math.IsInf(sig.Value, 0) {
		return errors.New("signal value must be finite")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO signals (hour, app, key, metric, value, samples) VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(hour, app, key, metric) DO UPDATE SET value = MAX(value, excluded.value)`,
		unix(sig.Hour.Truncate(time.Hour)), sig.App, sig.Key, sig.Metric, sig.Value)
	return err
}

// Signals returns an app's rollups since a time, oldest first. An empty
// app means every app.
func (s *Store) Signals(ctx context.Context, app string, since time.Time) ([]Signal, error) {
	query := `SELECT hour, app, key, metric, value, samples FROM signals WHERE hour >= ?`
	args := []any{unix(since)}
	if app != "" {
		query += ` AND app = ?`
		args = append(args, app)
	}
	return s.querySignals(ctx, query+` ORDER BY hour, app, key, metric`, args...)
}

// MetricSignals returns one metric's rollups for every app since a time,
// oldest first.
func (s *Store) MetricSignals(ctx context.Context, metric string, since time.Time) ([]Signal, error) {
	return s.querySignals(ctx, `SELECT hour, app, key, metric, value, samples FROM signals WHERE hour >= ? AND metric = ? ORDER BY hour, app, key`, unix(since), metric)
}

func (s *Store) querySignals(ctx context.Context, query string, args ...any) ([]Signal, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Signal
	for rows.Next() {
		var sig Signal
		var hour int64
		if err := rows.Scan(&hour, &sig.App, &sig.Key, &sig.Metric, &sig.Value, &sig.Samples); err != nil {
			return nil, err
		}
		sig.Hour = fromUnix(hour)
		out = append(out, sig)
	}
	return out, rows.Err()
}

// PruneSignals drops rollups older than a time.
func (s *Store) PruneSignals(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM signals WHERE hour < ?`, unix(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// IntegrationUse is the last time an integration's credentials were used.
type IntegrationUse struct {
	Name    string    `json:"name"`
	Purpose string    `json:"purpose"`
	UsedAt  time.Time `json:"used_at"`
}

// RecordIntegrationUse notes that an integration was just used.
func (s *Store) RecordIntegrationUse(ctx context.Context, name, purpose string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO integration_uses (name, purpose, used_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET purpose = excluded.purpose, used_at = excluded.used_at`, name, purpose, unix(at))
	return err
}

// IntegrationUses returns the last use of every integration, by name.
func (s *Store) IntegrationUses(ctx context.Context) (map[string]IntegrationUse, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, purpose, used_at FROM integration_uses`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]IntegrationUse{}
	for rows.Next() {
		var u IntegrationUse
		var used int64
		if err := rows.Scan(&u.Name, &u.Purpose, &used); err != nil {
			return nil, err
		}
		u.UsedAt = fromUnix(used)
		out[u.Name] = u
	}
	return out, rows.Err()
}
