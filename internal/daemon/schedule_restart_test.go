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
