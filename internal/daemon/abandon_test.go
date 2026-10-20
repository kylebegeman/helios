package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// stoppedDaemon is a daemon's state directory, with storage set up and
// hello running a revision that keeps a volume, whose operations run and
// recover through the registry the daemon and the CLI build.
type stoppedDaemon struct {
	stateDir string
	store    *state.Store
	sec      *secrets.Store
	at       time.Time
}

func newStoppedDaemon(t *testing.T) *stoppedDaemon {
	t.Helper()
	dockertest.New(t)
	stateDir := t.TempDir()
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sec := secrets.DefaultStore(stateDir)
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "https://storage.example.test", "key_id": "key-id", "key": "storage-key", "bucket_prefix": "first", "password": "backup-password"}); err != nil {
		t.Fatal(err)
	}
	d := &stoppedDaemon{stateDir: stateDir, store: store, sec: sec, at: time.Now().UTC().Truncate(time.Second)}
	d.activate(t, "active-code")
	return d
}

// activate makes id hello's running revision.
func (d *stoppedDaemon) activate(t *testing.T, id string) {
	t.Helper()
	m := manifest.Manifest{App: "hello", Workloads: map[string]manifest.Workload{
		"web": {Kind: manifest.Web, Singleton: true, Image: "nginx:alpine", Port: 8080, Routes: []manifest.Route{{Host: "hello.example.test"}}},
	}, Data: &manifest.Data{Volumes: map[string]manifest.Volume{"uploads": {}}}}
	body, _ := json.Marshal(m)
	ctx := context.Background()
	if err := d.store.SaveRevision(ctx, state.Revision{App: "hello", ID: id, Manifest: body, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := d.store.Activate(ctx, "hello", id, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

// stop runs an operation through the registry until its prepare step has
// succeeded, then stops it as a daemon stopping would.
func (d *stoppedDaemon) stop(t *testing.T, kind string, input any) {
	t.Helper()
	raw, _ := json.Marshal(input)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := kernel.New(d.store, Registry(d.store, d.sec, "", d.stateDir), "old-daemon", kernel.WithClock(func() time.Time { return d.at }))
	_, err := engine.Run(ctx, kind, raw, func(ev kernel.Event) {
		if ev.Type == kernel.EventStepFinished && ev.Step.Name == "prepare" && ev.Step.Status == state.StepSucceeded {
			cancel()
		}
	})
	if err == nil {
		t.Fatalf("%s was not stopped", kind)
	}
}

// recover runs Recover through the registry once the stopped daemon's
// lease is over, and wants it to end the one operation as failed, saying
// why.
func (d *stoppedDaemon) recover(t *testing.T, why string) {
	t.Helper()
	ctx := context.Background()
	engine := kernel.New(d.store, Registry(d.store, d.sec, "", d.stateDir), "new-daemon", kernel.WithClock(func() time.Time { return d.at.Add(time.Minute) }))
	if n, err := engine.Recover(ctx, func(kernel.Event) {}); err != nil || n != 1 {
		t.Fatalf("recovered %d operation(s): %v", n, err)
	}
	ops, err := d.store.List(ctx, 1)
	if err != nil || len(ops) != 1 || ops[0].Status != state.Failed || !strings.HasPrefix(ops[0].Error, why) {
		t.Fatalf("Recover must end the operation as failed with %q: %+v %v", why, ops, err)
	}
}

// runClosedWith wants hello's one backup run closed as failed with the
// reason Recover ended its operation with.
func (d *stoppedDaemon) runClosedWith(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	ops, err := d.store.List(ctx, 1)
	if err != nil || len(ops) != 1 {
		t.Fatalf("operations: %+v %v", ops, err)
	}
	runs, err := d.store.BackupRuns(ctx, "hello", state.BackupRunBackup, 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("hello's backup runs are %+v, want the stopped operation's alone: %v", runs, err)
	}
	if run := runs[0]; !run.Finished() || run.OK || run.Error != ops[0].Error {
		t.Fatalf("the run must be closed as failed with Recover's reason %q: %+v", ops[0].Error, run)
	}
}

// The daemon and the CLI's local fallback recover operations through
// Registry, which wraps every definition in its recovery guard. A backup
// stopped with its daemon leaves its run open for its resumed attempt, and
// when its plan changes, or can't be rebuilt, before Recover finds it,
// Recover ends the operation instead, so the backup has to be told through
// that guard to close the run, or it shows as running for good.
func TestRecoverThroughTheDaemonsRegistryClosesTheRunOfABackupItEnds(t *testing.T) {
	for _, end := range []struct {
		name, why string
		change    func(t *testing.T, d *stoppedDaemon)
	}{
		{"the plan changed", "interrupted, and the plan changed since it started", func(t *testing.T, d *stoppedDaemon) {
			d.activate(t, "next-code")
		}},
		{"the plan can't be rebuilt", "interrupted, and the plan can't be rebuilt: plan app.backup: backups need the storage integration", func(t *testing.T, d *stoppedDaemon) {
			if _, err := integration.Remove(d.sec, integration.StorageName); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(end.name, func(t *testing.T) {
			d := newStoppedDaemon(t)
			d.stop(t, app.BackupKind, app.BackupInput{App: "hello"})
			run, err := d.store.LastBackupRun(context.Background(), "hello", state.BackupRunBackup)
			if err != nil || run == nil || run.Finished() {
				t.Fatalf("the stopped backup must leave its run open: %+v %v", run, err)
			}
			end.change(t, d)
			d.recover(t, end.why)
			d.runClosedWith(t)
		})
	}
}
