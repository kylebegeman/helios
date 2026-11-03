package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func TestARestartDoesNotPostponeAnOverdueMachineBackup(t *testing.T) {
	store := drillTestStore(t)
	ctx := context.Background()
	previous := time.Date(2026, 10, 20, 3, 30, 0, 0, time.UTC)
	id, err := store.StartBackupRun(ctx, manifest.ReservedApp, state.BackupRunBackup, previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishBackupRun(ctx, id, state.BackupRun{OK: true, FinishedAt: previous.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	started := previous.Add(25 * time.Hour)
	s := &Scheduler{Store: store, Started: started}
	if !s.due(ctx, manifest.ReservedApp, state.BackupRunBackup, MachineBackupSchedule, started, started) {
		t.Fatal("a restart after the backup's hour postponed the missed backup until tomorrow")
	}
}

// The machine backup refuses an app whose newest backup predates its active
// revision, so a deploy after the app's own backup hour would fail that
// night's machine backup. The app is backed up first, once.
func TestAnAppDeployedSinceItsLastBackupIsBackedUpBeforeTheMachine(t *testing.T) {
	store := drillTestStore(t)
	ctx := context.Background()
	s := &Scheduler{Store: store, Log: func(string, ...any) {}}
	m := manifest.Manifest{App: "hello", Backup: &manifest.Backup{Schedule: "0 4 * * *"}}
	rev := state.Revision{App: "hello", ID: "r2", CreatedAt: time.Date(2026, 11, 2, 0, 44, 0, 0, time.UTC)}
	recordBackupRun(t, store, state.BackupRunBackup, rev.CreatedAt.Add(-2*time.Minute), state.BackupRun{OK: true})
	machine := time.Date(2026, 11, 2, 3, 30, 0, 0, time.UTC)

	if s.backupDue(ctx, rev, m, false, machine) {
		t.Fatal("the app's backup ran before its own hour with no machine backup due")
	}
	if !s.backupDue(ctx, rev, m, true, machine) {
		t.Fatal("the machine backup ran without first backing up an app deployed since its last backup")
	}
	recordBackupRun(t, store, state.BackupRunBackup, machine, state.BackupRun{Error: "dump failed"})
	if s.backupDue(ctx, rev, m, true, machine.Add(time.Minute)) {
		t.Fatal("a failed catch-up backup ran again on the next tick")
	}
}

func TestARestartDoesNotPostponeOverdueGarbageCollection(t *testing.T) {
	store := drillTestStore(t)
	ctx := context.Background()
	previous := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	if err := store.CreateOperation(ctx, state.NewOperation{ID: "old-gc", Kind: app.GCKind, Input: []byte(`{}`), Plan: []byte(`{}`), CreatedAt: previous}); err != nil {
		t.Fatal(err)
	}
	started := previous.Add(25 * time.Hour)
	s := &Scheduler{Store: store, Started: started}
	if !s.dueOp(ctx, app.GCKind, MachineGCSchedule, started, started) {
		t.Fatal("a restart after collection's hour postponed the missed collection until tomorrow")
	}
}
