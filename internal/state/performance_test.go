package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// These benchmarks use the same file-backed SQLite, WAL settings and schema as
// the daemon. Fleet size and retained history vary independently so a bounded
// current-state read can be distinguished from a history-dependent one. Fixture
// construction and correctness checks are outside the measured loop.
func BenchmarkStateRevisionReads(b *testing.B) {
	for _, size := range stateBenchmarkSizes {
		b.Run(size.name(), func(b *testing.B) {
			s := benchmarkStateStore(b)
			want := benchmarkRevisionFixture(b, s, size.apps, size.history)
			ctx := context.Background()
			b.Run("ActiveRevisions", func(b *testing.B) {
				var got []Revision
				b.ReportAllocs()
				for b.Loop() {
					var err error
					got, err = s.ActiveRevisions(ctx)
					if err != nil {
						b.Fatal(err)
					}
				}
				if !reflect.DeepEqual(got, want.active) {
					b.Fatal("active revision results differ from the fixture")
				}
			})
			for _, status := range []RevisionStatus{RevisionActive, RevisionPrevious} {
				b.Run("RevisionWithStatus/"+string(status), func(b *testing.B) {
					var got *Revision
					b.ReportAllocs()
					for b.Loop() {
						var err error
						got, err = s.RevisionWithStatus(ctx, want.app, status)
						if err != nil {
							b.Fatal(err)
						}
					}
					if got == nil || !reflect.DeepEqual(*got, want.byStatus[status]) {
						b.Fatal("status revision differs from the fixture")
					}
				})
			}
			b.Run("Revisions", func(b *testing.B) {
				var got []Revision
				b.ReportAllocs()
				for b.Loop() {
					var err error
					got, err = s.Revisions(ctx, want.app)
					if err != nil {
						b.Fatal(err)
					}
				}
				if !reflect.DeepEqual(got, want.history) {
					b.Fatal("revision history differs from the fixture")
				}
			})
		})
	}
}

func BenchmarkStateBackupReads(b *testing.B) {
	for _, size := range stateBenchmarkSizes {
		b.Run(size.name(), func(b *testing.B) {
			s := benchmarkStateStore(b)
			all := benchmarkBackupFixture(b, s, size.apps, size.history)
			ctx := context.Background()
			app := benchmarkAppName(size.apps / 2)
			for _, tc := range []struct {
				name, app, kind string
				limit           int
			}{
				{"LatestForApp", app, BackupRunBackup, 1},
				{"AppHistory", app, "", 20},
				{"FleetHistory", "", "", 20},
				{"FleetBackupHistory", "", BackupRunBackup, 20},
			} {
				want := benchmarkExpectedBackups(all, tc.app, tc.kind, tc.limit, false)
				b.Run(tc.name, func(b *testing.B) {
					var got []BackupRun
					b.ReportAllocs()
					for b.Loop() {
						var err error
						got, err = s.BackupRuns(ctx, tc.app, tc.kind, tc.limit)
						if err != nil {
							b.Fatal(err)
						}
					}
					if !reflect.DeepEqual(got, want) {
						b.Fatal("backup history differs from the fixture")
					}
				})
			}
			b.Run("LastGoodBackupRun", func(b *testing.B) {
				want := benchmarkExpectedBackups(all, app, BackupRunBackup, 1, true)
				var got *BackupRun
				b.ReportAllocs()
				for b.Loop() {
					var err error
					got, err = s.LastGoodBackupRun(ctx, app, BackupRunBackup)
					if err != nil {
						b.Fatal(err)
					}
				}
				if got == nil || !reflect.DeepEqual(*got, want[0]) {
					b.Fatal("last successful backup differs from the fixture")
				}
			})
		})
	}
}

type stateBenchmarkSize struct{ apps, history int }

var stateBenchmarkSizes = []stateBenchmarkSize{
	{apps: 1, history: 32},
	{apps: 25, history: 32},
	{apps: 25, history: 512},
	{apps: 100, history: 512},
}

func (s stateBenchmarkSize) name() string {
	return fmt.Sprintf("apps=%d/history=%d", s.apps, s.history)
}

func benchmarkAppName(i int) string { return fmt.Sprintf("app-%03d", i) }

func benchmarkStateStore(b *testing.B) *Store {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := s.Close(); err != nil {
			b.Error(err)
		}
	})
	return s
}

type benchmarkRevisionResults struct {
	app      string
	active   []Revision
	history  []Revision
	byStatus map[RevisionStatus]Revision
}

func benchmarkRevisionFixture(b *testing.B, s *Store, apps, history int) benchmarkRevisionResults {
	b.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO revisions (app, id, status, manifest, images, containers, source, secrets_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		b.Fatal(err)
	}
	defer stmt.Close()
	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	out := benchmarkRevisionResults{app: benchmarkAppName(apps / 2), byStatus: make(map[RevisionStatus]Revision)}
	for a := range apps {
		app := benchmarkAppName(a)
		for h := range history {
			id := fmt.Sprintf("r-%06d", h)
			status := RevisionRetired
			switch {
			case h == history-1:
				status = RevisionActive
			case h == history-2:
				status = RevisionPrevious
			case h%11 == 0:
				status = RevisionFailed
			}
			manifest := json.RawMessage(fmt.Sprintf(`{"app":%q,"owner":"platform","workloads":{"web":{"kind":"web","image":"ghcr.io/example/web:latest","port":8080,"routes":[{"host":%q}],"health":{"path":"/healthz"},"resources":{"memory":"512m","cpus":0.5}},"worker":{"kind":"worker","image":"ghcr.io/example/worker:latest"},"nightly":{"kind":"cron","image":"ghcr.io/example/jobs:latest","schedule":"0 2 * * *"}},"data":{"postgres":{"version":"17"},"volumes":{"files":{"description":"uploads"}}},"backup":{"schedule":"0 3 * * *","keep":{"daily":7,"weekly":4,"monthly":6}}}`, app, app+".example.com"))
			r := Revision{
				App: app, ID: id, Status: status, Manifest: manifest,
				Images:     map[string]string{"web": "sha256:web-" + id, "worker": "sha256:worker-" + id, "nightly": "sha256:jobs-" + id},
				Containers: map[string]string{"web": app + "-web-" + id, "worker": app + "-worker-" + id},
				Source:     "a0b1c2d3e4f5", SecretsVersion: h + 1, CreatedAt: base.Add(time.Duration(h) * time.Hour),
			}
			images, err := json.Marshal(r.Images)
			if err != nil {
				b.Fatal(err)
			}
			containers, err := json.Marshal(r.Containers)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkExec(b, stmt, r.App, r.ID, string(r.Status), string(manifest), string(images), string(containers), r.Source, r.SecretsVersion, unix(r.CreatedAt))
			if status == RevisionActive {
				out.active = append(out.active, r)
			}
			if app == out.app {
				out.history = append(out.history, r)
				out.byStatus[status] = r
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO apps (name, active_revision, updated_at) VALUES (?, ?, ?)`, app, fmt.Sprintf("r-%06d", history-1), unix(base.Add(time.Duration(history-1)*time.Hour))); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	sort.Slice(out.history, func(i, j int) bool { return out.history[i].CreatedAt.After(out.history[j].CreatedAt) })
	return out
}

func benchmarkBackupFixture(b *testing.B, s *Store, apps, history int) []BackupRun {
	b.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO backup_runs (app, kind, started_at, finished_at, ok, snapshot, snapshot_at, files, bytes, detail, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		b.Fatal(err)
	}
	defer stmt.Close()
	base := time.Date(2025, 1, 1, 3, 0, 0, 0, time.UTC)
	var out []BackupRun
	for a := range apps {
		for h := range history {
			for _, kind := range []string{BackupRunBackup, BackupRunDrill, BackupRunRestore} {
				if kind == BackupRunDrill && h%7 != 0 || kind == BackupRunRestore && h%29 != 0 {
					continue
				}
				started := base.Add(time.Duration(h) * 24 * time.Hour)
				r := BackupRun{
					App: benchmarkAppName(a), Kind: kind, StartedAt: started, FinishedAt: started.Add(2 * time.Minute),
					OK: h%11 != 0 && h != history-1, Snapshot: fmt.Sprintf("snapshot-%03d-%06d", a, h), SnapshotAt: started,
					Files: 2500, Bytes: 64 << 20, Detail: "postgres dump and uploaded files, verified and retained",
				}
				if !r.OK {
					r.Error = "storage temporarily unavailable"
				}
				r.ID = benchmarkExec(b, stmt, r.App, r.Kind, unix(r.StartedAt), unix(r.FinishedAt), r.OK, r.Snapshot, unix(r.SnapshotAt), r.Files, r.Bytes, r.Detail, r.Error)
				out = append(out, r)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return out
}

func benchmarkExpectedBackups(all []BackupRun, app, kind string, limit int, good bool) []BackupRun {
	var out []BackupRun
	for _, r := range all {
		if app != "" && r.App != app || kind != "" && r.Kind != kind || good && !r.OK {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out[:min(limit, len(out))]
}

func benchmarkExec(b *testing.B, stmt *sql.Stmt, args ...any) int64 {
	b.Helper()
	res, err := stmt.ExecContext(context.Background(), args...)
	if err != nil {
		b.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		b.Fatal(err)
	}
	return id
}
