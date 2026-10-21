package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
)

func TestMachineRecoveryImportsInactiveAppAndHistoryWithoutReplacingAuthority(t *testing.T) {
	ctx := context.Background()
	source := open(t)
	target := open(t)
	now := time.Now().UTC()
	original := Revision{App: "site", ID: "old", Status: RevisionActive, Manifest: json.RawMessage(`{"app":"site"}`), Containers: map[string]string{"web": "source-container"}, Images: map[string]string{"web": "image"}, SecretsVersion: 3, CreatedAt: now}
	source.SaveRevision(ctx, original)
	source.Activate(ctx, "site", "old", now)
	source.SaveGitHook(ctx, GitHook{App: "site", Repo: "repo", Branch: "main", CreatedAt: now})
	source.AddWatch(ctx, "https://site.example.com", now)
	source.StartBackupRun(ctx, "site", BackupRunBackup, now)
	source.StartJobRun(ctx, JobRun{App: "site", Workload: "cron", Revision: "old", Kind: "cron", Container: "old-job", StartedAt: now})
	target.CreateOperation(ctx, NewOperation{ID: "recovery-operation", Kind: "machine.recover", Target: "machine", Input: json.RawMessage(`{}`), Plan: json.RawMessage(`{}`), StepNames: []string{"import"}, CreatedAt: now})
	target.RecordIntegrationUse(ctx, "target-integration", "keep", now)
	candidate := Revision{App: "site", ID: "recovered", Status: RevisionActive, Manifest: original.Manifest, Containers: map[string]string{"web": "private-target-container"}, Images: original.Images, SecretsVersion: 3, CreatedAt: now}
	mapping := map[string]map[int]int{"site": {3: 3}}
	for i := 0; i < 2; i++ {
		if err := target.ImportMachineRecovery(ctx, source.Path(), "snapshot-one", mapping, []Revision{candidate}); err != nil {
			t.Fatal(err)
		}
	}
	apps, _ := target.Apps(ctx)
	if len(apps) != 1 || apps[0].ActiveRevision != "" {
		t.Fatalf("recovered app routed too soon: %+v", apps)
	}
	recovered, _ := target.GetRevision(ctx, "site", "recovered")
	old, _ := target.GetRevision(ctx, "site", "old")
	if recovered.Status != RevisionFailed || recovered.Containers["web"] != "private-target-container" || old.Status != RevisionRetired || len(old.Containers) != 0 || old.SecretsVersion != 3 {
		t.Fatalf("recovered %+v old %+v", recovered, old)
	}
	sourceOld, _ := source.GetRevision(ctx, "site", "old")
	if sourceOld.Status != RevisionActive || sourceOld.Containers["web"] != "source-container" {
		t.Fatal("source history mutated")
	}
	operations, _ := target.List(ctx, 10)
	if len(operations) != 1 || operations[0].ID != "recovery-operation" {
		t.Fatalf("target journal replaced: %+v", operations)
	}
	integrations, _ := target.IntegrationUses(ctx)
	if integrations["target-integration"].Purpose != "keep" {
		t.Fatal("integration authority lost")
	}
	runs, _ := target.BackupRuns(ctx, "site", "", 10)
	if len(runs) != 1 || runs[0].FinishedAt.IsZero() {
		t.Fatalf("backup history duplicated or left running: %+v", runs)
	}
	jobs, _ := target.JobRuns(ctx, "site", "", 10)
	if len(jobs) != 1 || jobs[0].Container != "" || jobs[0].FinishedAt.IsZero() {
		t.Fatalf("source job resurrected: %+v", jobs)
	}
}
func TestMachineRecoveryConflictsAndMissingSecretsRollBackEverything(t *testing.T) {
	ctx := context.Background()
	source := open(t)
	now := time.Now().UTC()
	source.SaveRevision(ctx, Revision{App: "site", ID: "old", Status: RevisionActive, SecretsVersion: 2, CreatedAt: now})
	source.Activate(ctx, "site", "old", now)
	target := open(t)
	if err := target.ImportMachineRecovery(ctx, source.Path(), "snapshot", nil, nil); err == nil || !strings.Contains(err.Error(), "resealed secrets") {
		t.Fatalf("%v", err)
	}
	apps, _ := target.Apps(ctx)
	if len(apps) != 0 {
		t.Fatal("failed import wrote app")
	}
	target.SaveRevision(ctx, Revision{App: "site", ID: "target", Status: RevisionFailed, CreatedAt: now})
	if err := target.ImportMachineRecovery(ctx, source.Path(), "snapshot", map[string]map[int]int{"site": {2: 2}}, nil); err == nil || !strings.Contains(err.Error(), "existing app") {
		t.Fatalf("%v", err)
	}
	revisions, _ := target.Revisions(ctx, "site")
	if len(revisions) != 1 || revisions[0].ID != "target" {
		t.Fatalf("target overwritten: %+v", revisions)
	}
}

func TestMachineRecoveryKeepsTheTargetsOwnHostDiskHistory(t *testing.T) {
	ctx := context.Background()
	source, target := open(t), open(t)
	hour := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	hostDisk := func(store *Store, at time.Time, used float64) {
		t.Helper()
		if err := store.MaxSignal(ctx, Signal{Hour: at, App: manifest.ReservedApp, Key: SignalHostDiskRoot, Metric: SignalHostDiskUsed, Value: used}); err != nil {
			t.Fatal(err)
		}
	}
	// The target came up and began sampling before the source's last backup,
	// so both hold the root disk for 11:00 and 12:00.
	for i := range 3 {
		hostDisk(source, hour.Add(time.Duration(i)*time.Hour), 100)
	}
	for i := 1; i < 4; i++ {
		hostDisk(target, hour.Add(time.Duration(i)*time.Hour), 40)
	}
	if err := source.AddSignal(ctx, Signal{Hour: hour, App: "site", Key: "site.example.com", Metric: SignalRequests, Value: 7, Samples: 1}); err != nil {
		t.Fatal(err)
	}
	if err := target.ImportMachineRecovery(ctx, source.Path(), "host-disk", nil, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := target.Signals(ctx, manifest.ReservedApp, hour)
	if err != nil || len(rows) != 3 {
		t.Fatalf("root disk rollups: %+v, %v", rows, err)
	}
	for i, row := range rows {
		if !row.Hour.Equal(hour.Add(time.Duration(i+1)*time.Hour)) || row.Value != 40 {
			t.Fatalf("source disk history mixed into the target's: %+v", rows)
		}
	}
	traffic, err := target.Signals(ctx, "site", hour)
	if err != nil || len(traffic) != 1 || traffic[0].Value != 7 {
		t.Fatalf("app signals not imported: %+v, %v", traffic, err)
	}
}

func TestHistoricalRecoveryMigratesOnlyAnIsolatedCopy(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "historical.db")
	db, _ := sql.Open("sqlite", path)
	_, err := db.Exec(`CREATE TABLE revisions(app TEXT NOT NULL,id TEXT NOT NULL,status TEXT NOT NULL,manifest TEXT NOT NULL,images TEXT NOT NULL,containers TEXT NOT NULL,source TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,PRIMARY KEY(app,id));INSERT INTO revisions VALUES('site','old','active','{}','{}','{}','source',123);`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, _ := os.ReadFile(path)
	target := open(t)
	if err := target.ImportMachineRecovery(ctx, path, "historical", nil, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("historical archive migrated in place")
	}
	revision, err := target.GetRevision(ctx, "site", "old")
	if err != nil || revision.Status != RevisionRetired || revision.SecretsVersion != 0 {
		t.Fatalf("%+v %v", revision, err)
	}
}

func TestMachineRecoveryFinalizesInterruptedReleaseAndRestoreHistory(t *testing.T) {
	ctx := context.Background()
	source := open(t)
	target := open(t)
	now := time.Now().UTC()
	for _, status := range []string{ReleaseStarted, ReleaseRestoring} {
		if err := source.BeginReleaseBoundary(ctx, ReleaseBoundary{App: "notes", Revision: status, Compatibility: "restore-required", StartedAt: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := source.db.ExecContext(ctx, "UPDATE release_boundaries SET status=? WHERE app=? AND revision=?", status, "notes", status); err != nil {
			t.Fatal(err)
		}
	}
	if err := target.ImportMachineRecovery(ctx, source.Path(), "interrupted-release-history", nil, nil); err != nil {
		t.Fatal(err)
	}
	boundaries, err := target.ReleaseBoundaries(ctx, "notes")
	if err != nil || len(boundaries) != 2 {
		t.Fatalf("boundaries %v, error %v", boundaries, err)
	}
	for _, boundary := range boundaries {
		if boundary.Status != ReleaseFailed || boundary.FinishedAt.IsZero() || !strings.Contains(boundary.Error, "interrupted on source machine") {
			t.Fatalf("source work remained resumable on target: %+v", boundary)
		}
	}
	original, err := source.ReleaseBoundaries(ctx, "notes")
	if err != nil {
		t.Fatal(err)
	}
	for _, boundary := range original {
		if boundary.Status != boundary.Revision || !boundary.FinishedAt.IsZero() {
			t.Fatalf("source archive was changed: %+v", boundary)
		}
	}
}

func TestMachineRecoveryTimestampsPreserveChronologyAndRetryHistory(t *testing.T) {
	ctx := context.Background()
	source, target := open(t), open(t)
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	completed := started.Add(time.Minute)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// A revision without an apps row exercises the recovered app's new timestamp.
	must(source.SaveRevision(ctx, Revision{App: "orphan", ID: "old", Status: RevisionFailed, CreatedAt: started}))
	for _, workload := range []string{"pending", "completed"} {
		id, err := source.StartJobRun(ctx, JobRun{App: "orphan", Workload: workload, Revision: "old", Kind: "cron", StartedAt: started})
		must(err)
		if workload == "completed" {
			must(source.FinishJobRun(ctx, id, 0, "", "", completed))
		}
	}
	for _, kind := range []string{BackupRunBackup, BackupRunRestore} {
		id, err := source.StartBackupRun(ctx, "orphan", kind, started)
		must(err)
		if kind == BackupRunRestore {
			must(source.FinishBackupRun(ctx, id, BackupRun{FinishedAt: completed, OK: true}))
		}
	}
	for _, status := range []string{ReleaseStarted, ReleaseRestoring, ReleaseCompleted} {
		must(source.BeginReleaseBoundary(ctx, ReleaseBoundary{App: "orphan", Revision: status, Compatibility: "restore-required", StartedAt: started}))
		switch status {
		case ReleaseRestoring:
			must(source.BeginReleaseRestore(ctx, "orphan", status, ""))
		case ReleaseCompleted:
			must(source.FinishReleaseBoundary(ctx, "orphan", status, status, "", completed))
		}
	}
	for _, key := range []string{"pending", "completed"} {
		incident := Incident{Key: key, Subject: "orphan", Severity: SeverityWarning, OpenedAt: started}
		id, err := source.OpenIncident(ctx, incident)
		must(err)
		if key == "completed" {
			incident.ID, incident.ResolvedAt = id, completed
			must(source.UpdateIncident(ctx, incident))
		}
	}
	readTimes := func(store *Store, recoveryID string) map[string]time.Time {
		t.Helper()
		times := make(map[string]time.Time)
		jobs, err := store.JobRuns(ctx, "orphan", "", 10)
		must(err)
		for _, run := range jobs {
			times["job:"+run.Workload] = run.FinishedAt
		}
		backups, err := store.BackupRuns(ctx, "orphan", "", 10)
		must(err)
		for _, run := range backups {
			times["backup:"+run.Kind] = run.FinishedAt
		}
		releases, err := store.ReleaseBoundaries(ctx, "orphan")
		must(err)
		for _, boundary := range releases {
			times["release:"+boundary.Revision] = boundary.FinishedAt
		}
		incidents, err := store.Incidents(ctx, 10)
		must(err)
		for _, incident := range incidents {
			times["incident:"+incident.Key] = incident.ResolvedAt
		}
		apps, err := store.Apps(ctx)
		must(err)
		for _, app := range apps {
			times["app:"+app.Name] = app.UpdatedAt
		}
		if recoveryID != "" {
			var importedAt int64
			must(store.db.QueryRowContext(ctx, "SELECT imported_at FROM machine_recoveries WHERE id=?", recoveryID).Scan(&importedAt))
			times["import"] = time.UnixMilli(importedAt).UTC()
		}
		return times
	}
	sourceBefore := readTimes(source, "")
	before := time.Now().UTC().Truncate(time.Millisecond)
	must(target.ImportMachineRecovery(ctx, source.Path(), "timestamp-contract", nil, nil))
	after := time.Now().UTC().Truncate(time.Millisecond)
	imported := readTimes(target, "timestamp-contract")
	for _, field := range []string{
		"job:pending", "backup:backup", "release:started", "release:restoring",
		"incident:pending", "app:orphan", "import",
	} {
		got, exists := imported[field]
		if !exists || got.Before(before) || got.After(after) || got.Before(started) {
			t.Errorf("%s timestamp %s outside import range [%s, %s]", field, got, before, after)
		}
	}
	for _, field := range []string{"job:completed", "backup:restore", "release:completed", "incident:completed"} {
		if got := imported[field]; !got.Equal(completed) {
			t.Errorf("%s completed timestamp changed: got %s, want %s", field, got, completed)
		}
	}
	revision, err := target.GetRevision(ctx, "orphan", "old")
	must(err)
	if !revision.CreatedAt.Equal(started) {
		t.Errorf("source revision timestamp changed: got %s, want %s", revision.CreatedAt, started)
	}
	must(target.ImportMachineRecovery(ctx, source.Path(), "timestamp-contract", nil, nil))
	if retried := readTimes(target, "timestamp-contract"); !maps.Equal(imported, retried) {
		t.Errorf("retry changed imported timestamps: before %v, after %v", imported, retried)
	}
	if sourceAfter := readTimes(source, ""); !maps.Equal(sourceBefore, sourceAfter) {
		t.Errorf("import changed source timestamps: before %v, after %v", sourceBefore, sourceAfter)
	}
}
