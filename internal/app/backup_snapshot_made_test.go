package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

// resticSummary is what restic prints when a backup has written snapshot.
func resticSummary(snapshot string, at time.Time) string {
	body, _ := json.Marshal(struct {
		Type string `json:"message_type"`
		restic.Summary
	}{"summary", restic.Summary{SnapshotID: snapshot, BackupStart: at, BackupEnd: at.Add(time.Second), TotalFiles: 3, TotalBytes: 30}})
	return string(body)
}

// madeHere is the snapshots this machine has on record as its own for an
// app, as the storage watch reads them before it deletes a bucket.
func madeHere(t *testing.T, store *state.Store, app string) []string {
	t.Helper()
	made, err := store.SnapshotsMade(context.Background(), app, snapshotRunKinds...)
	if err != nil {
		t.Fatal(err)
	}
	return sortedKeys(made)
}

// abandonedBackup runs an app's backup against a repository that answers
// each backup with summary, stops it when restic is asked for stopAt, and
// then has Recover end its operation because the plan changed. It returns
// the store and the run that was closed as failed.
func abandonedBackup(t *testing.T, stopAt, summary string) (*state.Store, state.BackupRun) {
	t.Helper()
	b, raw := backupIdentityFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	at := time.Now().UTC().Truncate(time.Second)
	fake := dockertest.New(t)
	fake.OnCreate = func(c dockertest.Container) {
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "init":
				c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: config file already exists"}`
			case "backup":
				c.Logs = summary
			}
			if c.Cmd[0] == stopAt {
				c.ExitAfter = 0
				cancel()
			}
		})
	}
	reg := kernel.Registry{}
	reg.Add(b)
	if _, err := kernel.New(b.Store, reg, "old-daemon", kernel.WithClock(func() time.Time { return at })).Run(ctx, BackupKind, raw, func(kernel.Event) {}); err == nil {
		t.Fatal("the backup was not stopped")
	}
	stopped := runOpen(t, b.Store, "hello")
	next, err := b.Store.RevisionWithStatus(context.Background(), "hello", state.RevisionActive)
	if err != nil {
		t.Fatal(err)
	}
	next.ID = "next-code"
	if err := b.Store.SaveRevision(context.Background(), *next); err != nil {
		t.Fatal(err)
	}
	if err := b.Store.Activate(context.Background(), "hello", next.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	recovered := kernel.New(b.Store, reg, "new-daemon", kernel.WithClock(func() time.Time { return at.Add(time.Minute) }))
	if n, err := recovered.Recover(context.Background(), func(kernel.Event) {}); err != nil || n != 1 {
		t.Fatalf("recovered %d operation(s): %v", n, err)
	}
	lastRunFailed(t, b.Store, "hello", "interrupted, and the plan changed since it started")
	run, err := b.Store.BackupRun(context.Background(), stopped.ID)
	if err != nil {
		t.Fatal(err)
	}
	return b.Store, run
}

// A backup stopped during retention has already written its snapshot. When
// its operation is then ended instead of resumed, the run is closed as
// failed with no snapshot, and the snapshot is still on record as one this
// machine made: otherwise it would hold the app's bucket for good once the
// app is removed.
func TestABackupAbandonedAfterItsCaptureKeepsTheSnapshotItWroteOnRecord(t *testing.T) {
	snapshot := strings.Repeat("e", 64)
	store, run := abandonedBackup(t, "forget", resticSummary(snapshot, time.Now().UTC().Truncate(time.Second)))
	if run.OK || run.Snapshot != "" || !run.SnapshotAt.IsZero() {
		t.Fatalf("the abandoned run reads as having a snapshot: %+v", run)
	}
	if last, err := store.LastGoodBackupRun(context.Background(), "hello", state.BackupRunBackup); err != nil || last != nil {
		t.Fatalf("the abandoned run reads as a good backup: %+v %v", last, err)
	}
	if got := madeHere(t, store, "hello"); len(got) != 1 || got[0] != snapshot {
		t.Fatalf("snapshots on record as made here: %v, want the one the capture returned", got)
	}
}

// No id is on record for a capture that returned none: a backup stopped
// before restic was asked for a snapshot, and one restic answered without
// an exact id.
func TestABackupWhoseCaptureReturnedNoSnapshotRecordsNone(t *testing.T) {
	t.Run("stopped before its capture", func(t *testing.T) {
		store, run := abandonedBackup(t, "init", resticSummary(strings.Repeat("e", 64), time.Now().UTC()))
		if got := madeHere(t, store, "hello"); run.Snapshot != "" || len(got) != 0 {
			t.Fatalf("snapshots on record as made here: %v, run %+v", got, run)
		}
	})
	for name, id := range map[string]string{"a short id": "abcd1234", "no id": ""} {
		t.Run(name, func(t *testing.T) {
			b, raw := backupIdentityFixture(t, false)
			repositoryWhoseBackup(t, func(c *dockertest.Container) { c.Logs = resticSummary(id, time.Now().UTC()) })
			reg := kernel.Registry{}
			reg.Add(b)
			receipt, err := kernel.New(b.Store, reg, "daemon").Run(context.Background(), BackupKind, raw, func(kernel.Event) {})
			if err != nil || receipt.Status != state.Failed {
				t.Fatalf("a backup without an exact snapshot id must fail: %+v %v", receipt, err)
			}
			lastRunFailed(t, b.Store, "hello", "backup did not return an exact snapshot identity")
			if got := madeHere(t, b.Store, "hello"); len(got) != 0 {
				t.Fatalf("snapshots on record as made here: %v, want none", got)
			}
		})
	}
}

// A backup stopped after its capture and then resumed closes its run with
// the snapshot the capture returned, and that one snapshot is all that is
// on record for it.
func TestAResumedBackupThatSucceedsHasItsOneSnapshotOnRecord(t *testing.T) {
	b, raw := backupIdentityFixture(t, false)
	at := time.Now().UTC().Truncate(time.Second)
	snapshot := strings.Repeat("a", 64)
	fake := dockertest.New(t)
	fake.OnCreate = func(c dockertest.Container) {
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "backup":
				c.Logs = resticSummary(snapshot, at)
			case "forget":
				c.Logs = `[]`
			}
		})
	}
	reg := kernel.Registry{}
	reg.Add(b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := kernel.New(b.Store, reg, "old-daemon", kernel.WithClock(func() time.Time { return at })).Run(ctx, BackupKind, raw, func(ev kernel.Event) {
		if ev.Type == kernel.EventStepFinished && ev.Step.Name == "snapshot" && ev.Step.Status == state.StepSucceeded {
			cancel()
		}
	})
	if err == nil {
		t.Fatal("the backup was not stopped after its capture")
	}
	stopped := runOpen(t, b.Store, "hello")
	if got := madeHere(t, b.Store, "hello"); stopped.Snapshot != "" || len(got) != 1 || got[0] != snapshot {
		t.Fatalf("with the run still open: snapshots on record %v, run %+v", got, stopped)
	}
	recovered := kernel.New(b.Store, reg, "new-daemon", kernel.WithClock(func() time.Time { return at.Add(time.Minute) }))
	if n, err := recovered.Recover(context.Background(), func(kernel.Event) {}); err != nil || n != 1 {
		t.Fatalf("recovered %d operation(s): %v", n, err)
	}
	run, err := b.Store.BackupRun(context.Background(), stopped.ID)
	if err != nil || !run.OK || run.Snapshot != snapshot {
		t.Fatalf("the resumed run: %+v %v", run, err)
	}
	if got := madeHere(t, b.Store, "hello"); len(got) != 1 || got[0] != snapshot {
		t.Fatalf("snapshots on record as made here: %v, want the run's one", got)
	}
}

// A release checkpoint whose boundary cannot be recorded after restic wrote
// the checkpoint fails its run, and the checkpoint is still on record as a
// snapshot this machine made.
func TestAReleaseCheckpointThatFailsAfterItsCaptureKeepsTheSnapshotItWroteOnRecord(t *testing.T) {
	ctx := context.Background()
	fixture, _ := recoveryFixture(t)
	store := fixture.Store
	m := recoveryManifest()
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"uploads": {}}}
	body, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: "active-code", Manifest: body, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(ctx, m.App, "active-code", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// The state store refuses the boundary, as a full disk would.
	db, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER no_boundary BEFORE INSERT ON release_boundaries BEGIN SELECT RAISE(ABORT, 'the boundary could not be written'); END`); err != nil {
		t.Fatal(err)
	}
	snapshot := strings.Repeat("c", 64)
	captured := false
	repositoryWhoseBackup(t, func(c *dockertest.Container) {
		captured = true
		c.Logs = resticSummary(snapshot, time.Now().UTC())
	})
	r := &rollout{d: Deploy{Store: store, Secrets: fixture.Secrets}, store: store, m: &m, revision: "candidate-code", stateDir: fixture.StateDir}
	err = r.releaseCheckpointStep().Apply(ctx, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "the boundary could not be written") || !captured {
		t.Fatalf("the checkpoint step, captured %v: %v", captured, err)
	}
	run, err := store.LastBackupRun(ctx, m.App, releaseCheckpointRun)
	if err != nil || run == nil || !run.Finished() || run.OK || run.Snapshot != "" {
		t.Fatalf("the checkpoint's run must be closed as failed with no snapshot: %+v %v", run, err)
	}
	if boundary, err := store.ReleaseBoundary(ctx, m.App, "candidate-code"); err != nil || boundary != nil {
		t.Fatalf("a boundary was recorded: %+v %v", boundary, err)
	}
	if got := madeHere(t, store, m.App); len(got) != 1 || got[0] != snapshot {
		t.Fatalf("snapshots on record as made here: %v, want the checkpoint restic returned", got)
	}
}

// A move's final capture has written its snapshot before its handoff closes
// the run. The snapshot is on record from the moment restic returns it, so
// a capture that goes no further still leaves a snapshot this machine made.
func TestAMovesFinalCaptureHasItsSnapshotOnRecordBeforeItsRunIsClosed(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	store, m, _, _ := safeMoveFixture(t)
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}}
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: "source-r1", Status: state.RevisionActive, Manifest: data, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	addMoveWriter(fake, "bedrock-site-web-live", "web", true)
	sec := newSecrets(t)
	setStorage(t, sec, "source", "fixture")
	snapshot := strings.Repeat("f", 64)
	fake.OnCreate = func(c dockertest.Container) {
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "init":
				c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: config file already exists"}`
			case "backup":
				c.Logs = resticSummary(snapshot, time.Now().UTC())
			}
		})
	}
	capture := MoveCapture{Backup: Backup{Store: store, Secrets: sec, StateDir: filepath.Dir(store.Path())}}
	input, err := MoveCaptureInputFor(ctx, store, m.App, "source", "target", true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(input)
	plan, err := capture.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if err := step.Apply(ctx, io.Discard); err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
		if step.Name == "snapshot" {
			break
		}
	}
	run, err := store.LastBackupRun(ctx, m.App, state.BackupRunBackup)
	if err != nil || run == nil || run.Finished() || run.Snapshot != "" {
		t.Fatalf("the capture's run must still be open, with no snapshot of its own yet: %+v %v", run, err)
	}
	if got := madeHere(t, store, m.App); len(got) != 1 || got[0] != snapshot {
		t.Fatalf("snapshots on record as made here: %v, want the final capture's", got)
	}
}
