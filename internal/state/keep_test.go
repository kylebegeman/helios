package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBackupRunsRememberTheLastGoodOne(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	t0 := time.Date(2026, 9, 19, 3, 0, 0, 0, time.UTC)
	id1, err := s.StartBackupRun(ctx, "dw", BackupRunBackup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishBackupRun(ctx, id1, BackupRun{OK: true, Snapshot: "abcd1234", SnapshotAt: t0, Files: 3, Bytes: 4096, Detail: "database and 3 files", FinishedAt: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	id2, _ := s.StartBackupRun(ctx, "dw", BackupRunBackup, t0.Add(24*time.Hour))
	_ = s.FinishBackupRun(ctx, id2, BackupRun{Error: "bucket unreachable", FinishedAt: t0.Add(24*time.Hour + time.Second)})
	id3, _ := s.StartBackupRun(ctx, "dw", BackupRunDrill, t0.Add(25*time.Hour))
	_ = id3
	last, err := s.LastBackupRun(ctx, "dw", BackupRunBackup)
	if err != nil || last == nil || last.ID != id2 || last.OK || last.Error != "bucket unreachable" {
		t.Fatalf("last: %+v %v", last, err)
	}
	good, err := s.LastGoodBackupRun(ctx, "dw", BackupRunBackup)
	if err != nil || good == nil || good.ID != id1 || good.Snapshot != "abcd1234" || good.Bytes != 4096 || !good.SnapshotAt.Equal(t0) {
		t.Fatalf("good: %+v %v", good, err)
	}
	byID, err := s.BackupRun(ctx, id1)
	if err != nil || byID != *good {
		t.Fatalf("run by ID: %+v %v; want %+v", byID, err, good)
	}
	if _, err := s.BackupRun(ctx, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run ID: %v", err)
	}
	drill, _ := s.LastBackupRun(ctx, "dw", BackupRunDrill)
	if drill == nil || drill.Finished() {
		t.Fatalf("an unfinished drill: %+v", drill)
	}
	all, _ := s.BackupRuns(ctx, "", "", 10)
	if len(all) != 3 || all[0].Kind != BackupRunDrill {
		t.Fatalf("all runs newest first: %+v", all)
	}
	if none, _ := s.LastGoodBackupRun(ctx, "other", BackupRunBackup); none != nil {
		t.Fatal("found a run for an unknown app")
	}
}

func TestIncidentsOpenUpdateAndResolve(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	id, err := s.OpenIncident(ctx, Incident{Key: "app:hello", Subject: "hello", Severity: SeverityCritical, Message: "web isn't running", OpenedAt: t0, Observations: 3})
	if err != nil {
		t.Fatal(err)
	}
	inc, err := s.OpenIncidentByKey(ctx, "app:hello")
	if err != nil || inc == nil || inc.ID != id || !inc.Open() || inc.Observations != 3 {
		t.Fatalf("%+v %v", inc, err)
	}
	if other, _ := s.OpenIncidentByKey(ctx, "app:other"); other != nil {
		t.Fatal("found an incident for another key")
	}
	inc.Message = "web isn't running; the check fails"
	inc.NotifiedAt = t0.Add(time.Minute)
	inc.Observations = 4
	if err := s.UpdateIncident(ctx, *inc); err != nil {
		t.Fatal(err)
	}
	open, _ := s.OpenIncidents(ctx)
	if len(open) != 1 || open[0].Message != inc.Message || !open[0].NotifiedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("%+v", open)
	}
	inc.ResolvedAt = t0.Add(10 * time.Minute)
	_ = s.UpdateIncident(ctx, *inc)
	if open, _ := s.OpenIncidents(ctx); len(open) != 0 {
		t.Fatal("still open")
	}
	history, _ := s.Incidents(ctx, 5)
	if len(history) != 1 || history[0].Open() {
		t.Fatalf("%+v", history)
	}
}

// An incident is read by its id, resolved or not, and a key's history is
// its incidents opened before a time, newest first, so the incident being
// looked at is never its own history.
func TestAnIncidentIsReadByIDAndAKeysHistoryStopsBeforeIt(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	var ids []int64
	for _, inc := range []Incident{
		{Key: "app:hello", Subject: "hello", Severity: SeverityWarning, Message: "web is slow", OpenedAt: t0},
		{Key: "app:other", Subject: "other", Severity: SeverityCritical, Message: "web isn't running", OpenedAt: t0.Add(time.Hour)},
		{Key: "app:hello", Subject: "hello", Severity: SeverityCritical, Message: "web isn't running", OpenedAt: t0.Add(2 * time.Hour)},
		{Key: "app:hello", Subject: "hello", Severity: SeverityCritical, Message: "web isn't running again", OpenedAt: t0.Add(3 * time.Hour)},
	} {
		id, err := s.OpenIncident(ctx, inc)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := s.UpdateIncident(ctx, Incident{ID: ids[0], Severity: SeverityWarning, Message: "web is slow", ResolvedAt: t0.Add(30 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	resolved, err := s.Incident(ctx, ids[0])
	if err != nil || resolved.ID != ids[0] || resolved.Key != "app:hello" || resolved.Open() || !resolved.ResolvedAt.Equal(t0.Add(30*time.Minute)) {
		t.Fatalf("incident %d: %+v %v", ids[0], resolved, err)
	}
	if open, err := s.Incident(ctx, ids[3]); err != nil || !open.Open() || open.Message != "web isn't running again" {
		t.Fatalf("incident %d: %+v %v", ids[3], open, err)
	}
	if _, err := s.Incident(ctx, ids[3]+1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown incident: %v", err)
	}

	history, err := s.IncidentsByKey(ctx, "app:hello", t0.Add(3*time.Hour), 10)
	if err != nil || len(history) != 2 || history[0].ID != ids[2] || history[1].ID != ids[0] {
		t.Fatalf("app:hello before incident %d: %+v %v; want %d then %d", ids[3], history, err, ids[2], ids[0])
	}
	if newest, _ := s.IncidentsByKey(ctx, "app:hello", t0.Add(3*time.Hour), 1); len(newest) != 1 || newest[0].ID != ids[2] {
		t.Fatalf("limit 1: %+v", newest)
	}
	if first, err := s.IncidentsByKey(ctx, "app:hello", t0, 10); err != nil || len(first) != 0 {
		t.Fatalf("a first incident has no history: %+v %v", first, err)
	}
}

// A run or a hold is read back by its id with what it recorded, so a log
// reader can find the run's container; an unknown id is ErrNotFound.
func TestAJobRunIsReadByID(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	id, err := s.StartJobRun(ctx, JobRun{App: "hello", Workload: "tick", Revision: "r1", Kind: "cron", StartedAt: t0, Container: "bedrock-hello-tick-job-a1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishJobRun(ctx, id, 2, "exited 2", "tick failed\n", t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartJobRun(ctx, JobRun{App: "hello", Workload: "tick", Revision: "r1", Kind: "cron", StartedAt: t0.Add(time.Minute), Container: "bedrock-hello-tick-job-b2"}); err != nil {
		t.Fatal(err)
	}
	hold, err := s.HoldJob(ctx, "hello", "tick", "r1", t0.Add(time.Hour), t0.Add(48*time.Hour), "the volume is being moved")
	if err != nil {
		t.Fatal(err)
	}

	run, err := s.JobRun(ctx, id)
	if err != nil || run.ID != id || run.App != "hello" || run.Workload != "tick" || run.Container != "bedrock-hello-tick-job-a1" ||
		run.ExitCode != 2 || run.Error != "exited 2" || run.Output != "tick failed\n" || !run.FinishedAt.Equal(t0.Add(time.Second)) {
		t.Fatalf("run %d: %+v %v", id, run, err)
	}
	if held, err := s.JobRun(ctx, hold); err != nil || held.Kind != JobHold || held.Output != "the volume is being moved" {
		t.Fatalf("hold %d: %+v %v", hold, held, err)
	}
	if _, err := s.JobRun(ctx, hold+1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
}

func TestWatchesAndIntegrationUses(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	if err := s.AddWatch(ctx, "https://core.begam.in/healthz", t0); err != nil {
		t.Fatal(err)
	}
	_ = s.AddWatch(ctx, "https://core.begam.in/healthz", t0.Add(time.Hour)) // again is fine
	ws, _ := s.Watches(ctx)
	if len(ws) != 1 || !ws[0].AddedAt.Equal(t0) {
		t.Fatalf("%+v", ws)
	}
	if err := s.RemoveWatch(ctx, "https://nowhere/"); err != ErrNotFound {
		t.Fatalf("removing an unknown watch: %v", err)
	}
	if err := s.RemoveWatch(ctx, "https://core.begam.in/healthz"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIntegrationUse(ctx, "storage", "backup dw", t0); err != nil {
		t.Fatal(err)
	}
	_ = s.RecordIntegrationUse(ctx, "storage", "backup hello", t0.Add(time.Hour))
	uses, _ := s.IntegrationUses(ctx)
	if u := uses["storage"]; u.Purpose != "backup hello" || !u.UsedAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("%+v", uses)
	}
}

func TestSignalsRollUpAndPrune(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	hour := time.Date(2026, 9, 19, 16, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := s.AddSignal(ctx, Signal{Hour: hour.Add(time.Duration(i) * 10 * time.Minute), App: "hello", Key: "hello.lane.begam.in", Metric: SignalRequests, Value: 10, Samples: 1}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.MaxSignal(ctx, Signal{Hour: hour, App: "hello", Key: "web", Metric: SignalMemoryMax, Value: 100})
	_ = s.MaxSignal(ctx, Signal{Hour: hour, App: "hello", Key: "web", Metric: SignalMemoryMax, Value: 80})
	_ = s.AddSignal(ctx, Signal{Hour: hour.Add(-100 * 24 * time.Hour), App: "hello", Key: "x", Metric: SignalRequests, Value: 1, Samples: 1})
	rows, _ := s.Signals(ctx, "hello", hour.Add(-time.Hour))
	if len(rows) != 2 || rows[0].Value != 30 || rows[0].Samples != 3 || rows[1].Value != 100 {
		t.Fatalf("%+v", rows)
	}
	n, err := s.PruneSignals(ctx, hour.Add(-90*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if err := s.BackupTo(ctx, s.Path()+".copy"); err != nil {
		t.Fatal(err)
	}
	copy, err := Open(s.Path() + ".copy")
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if rows, _ := copy.Signals(ctx, "hello", hour.Add(-time.Hour)); len(rows) != 2 {
		t.Fatalf("the copy: %+v", rows)
	}
}
