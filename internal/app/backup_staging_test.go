package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

// machinePrepare is the machine backup's prepare step, as its plan builds
// it.
func machinePrepare(t *testing.T, r RecoverMachine) kernel.Step {
	t.Helper()
	b := Backup{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir, Hostname: func() string { return "old-host" }}
	raw, _ := json.Marshal(BackupInput{App: manifest.ReservedApp})
	plan, err := b.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return plan.Steps[0]
}

// onDisk says whether path is there.
func onDisk(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// stagingKept fails a test unless a backup's staging and its owner file
// are where kept says, and the backup's one receipt is still there.
func stagingKept(t *testing.T, stateDir, staging string, kept bool) {
	t.Helper()
	for _, path := range []string{staging, staging + ".operation.json"} {
		if onDisk(t, path) != kept {
			t.Errorf("%s on disk: %t, want %t", path, !kept, kept)
		}
	}
	receipts, err := filepath.Glob(filepath.Join(stateDir, "backups", ".receipts", "*.json"))
	if err != nil || len(receipts) != 1 {
		t.Errorf("the backup's receipts are %v, want its one: %v", receipts, err)
	}
}

// lastRunFailed fails a test unless app's last backup run is closed as
// failed, saying why.
func lastRunFailed(t *testing.T, store *state.Store, app, why string) {
	t.Helper()
	run, err := store.LastBackupRun(context.Background(), app, state.BackupRunBackup)
	if err != nil || run == nil || !run.Finished() || run.OK || !strings.Contains(run.Error, why) {
		t.Fatalf("the backup run must be closed as failed with %q: %+v %v", why, run, err)
	}
}

// A machine backup that refuses while preparing ends there, and a prepare
// that runs again starts from nothing, so nothing it staged is worth
// keeping: not its copy of the state, nor the owner file. Its receipt
// stays.
func TestAMachineBackupThatRefusesWhilePreparingRemovesWhatItStaged(t *testing.T) {
	r, _ := recoveryFixture(t)
	activateApps(t, r, stagedApp{name: "hello", data: true, size: restic.Size{Bytes: 12, Files: 1}, finished: time.Now().UTC().Add(-time.Hour)})
	rev, err := r.Store.GetRevision(context.Background(), "hello", "active-code")
	if err != nil {
		t.Fatal(err)
	}
	err = machinePrepare(t, r).Apply(context.Background(), io.Discard)
	want := freshRecoveryBackupRequired(*rev).Error()
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	stagingKept(t, r.StateDir, filepath.Join(r.StateDir, "backups", "machine"), false)
	lastRunFailed(t, r.Store, manifest.ReservedApp, want)
}

// cpThatFails puts a cp on PATH that refuses with why, for the length of
// a test.
func cpThatFails(t *testing.T, why string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "cp"), []byte("#!/bin/sh\necho \""+why+"\" >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A copy that fails while a backup prepares ends the backup, so what it
// staged goes: an app's backup copying its database's first-run scripts,
// and the machine's copying its sealed secrets.
func TestABackupWhoseCopyFailsWhilePreparingRemovesWhatItStaged(t *testing.T) {
	const why = "cp: cannot open 'schema.sql' for reading: Permission denied"
	ctx := context.Background()
	t.Run("app", func(t *testing.T) {
		r, _ := recoveryFixture(t)
		m := recoveryManifest()
		m.Data = &manifest.Data{Postgres: &manifest.Postgres{Init: "db"}}
		body, _ := json.Marshal(m)
		if err := r.Store.SaveRevision(ctx, state.Revision{App: m.App, ID: "active-code", Manifest: body, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		if err := r.Store.Activate(ctx, m.App, "active-code", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		init := InitDir(r.StateDir, m.App)
		if err := os.MkdirAll(init, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(init, "schema.sql"), []byte("create table notes (body text);"), 0o600); err != nil {
			t.Fatal(err)
		}
		b := Backup{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}
		raw, _ := json.Marshal(BackupInput{App: m.App})
		plan, err := b.Plan(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		cpThatFails(t, why)
		want := "copy the database's first-run scripts: " + why
		if err := plan.Steps[0].Apply(ctx, io.Discard); err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
		stagingKept(t, r.StateDir, filepath.Join(r.StateDir, "backups", m.App), false)
		lastRunFailed(t, r.Store, m.App, want)
	})
	t.Run("machine", func(t *testing.T) {
		r, _ := recoveryFixture(t)
		cpThatFails(t, why)
		want := "copy the secrets: " + why
		if err := machinePrepare(t, r).Apply(ctx, io.Discard); err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
		stagingKept(t, r.StateDir, filepath.Join(r.StateDir, "backups", "machine"), false)
		lastRunFailed(t, r.Store, manifest.ReservedApp, want)
	})
}

// An interrupted prepare keeps what it staged, since its operation
// resumes and the resumed prepare starts again from nothing. Removing a
// large copy as the daemon stops would run past its stop budget.
func TestAnInterruptedMachineBackupPrepareLeavesItsStagingToTheResumedPrepare(t *testing.T) {
	r, _ := recoveryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	saved := recoveryImageSizes
	recoveryImageSizes = func(ctx context.Context, _ func() (*docker.Engine, error), _ []string) (int64, error) {
		cancel()
		return 0, ctx.Err()
	}
	t.Cleanup(func() { recoveryImageSizes = saved })
	prepare := machinePrepare(t, r)
	if err := prepare.Apply(ctx, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want the prepare interrupted", err)
	}
	staging := filepath.Join(r.StateDir, "backups", "machine")
	stagingKept(t, r.StateDir, staging, true)
	lastRunFailed(t, r.Store, manifest.ReservedApp, context.Canceled.Error())

	partial := filepath.Join(staging, machineAppDataDir, "hello", "partial")
	if err := os.MkdirAll(filepath.Dir(partial), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partial, []byte("an app copy cut short"), 0o600); err != nil {
		t.Fatal(err)
	}
	recoveryImageSizes = func(context.Context, func() (*docker.Engine, error), []string) (int64, error) { return 0, nil }
	if err := prepare.Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if onDisk(t, partial) || !onDisk(t, filepath.Join(staging, "state.db")) {
		t.Error("the resumed prepare didn't stage the machine again from nothing")
	}
	stagingKept(t, r.StateDir, staging, true)
}

// repositoryWhoseBackup answers restic as an existing repository would,
// with each backup doing what backup says to its container.
func repositoryWhoseBackup(t *testing.T, backup func(c *dockertest.Container)) {
	t.Helper()
	fake := dockertest.New(t)
	fake.OnCreate = func(c dockertest.Container) {
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "init":
				c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: config file already exists"}`
			case "backup":
				backup(c)
			}
		})
	}
}

// backupStaging is where an app's backup, or the machine's, stages.
func backupStaging(b backupIdentityDefinition, machine bool) string {
	if machine {
		return filepath.Join(b.StateDir, "backups", "machine")
	}
	return filepath.Join(b.StateDir, "backups", "hello")
}

// A snapshot that fails while its operation is alive ends the operation,
// so nothing will snapshot its staging again.
func TestABackupWhoseSnapshotFailsRemovesWhatItStaged(t *testing.T) {
	for _, machine := range []bool{false, true} {
		t.Run(map[bool]string{false: "app", true: "machine"}[machine], func(t *testing.T) {
			b, raw := backupIdentityFixture(t, machine)
			const why = "unable to save snapshot: no space left on device"
			repositoryWhoseBackup(t, func(c *dockertest.Container) {
				c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: `+why+`"}`
			})
			reg := kernel.Registry{}
			reg.Add(b)
			receipt, err := kernel.New(b.Store, reg, "daemon").Run(context.Background(), BackupKind, raw, func(kernel.Event) {})
			if err != nil || receipt.Status != state.Failed || !strings.Contains(receipt.Error, why) {
				t.Fatalf("the failed snapshot must fail the backup: %+v %v", receipt, err)
			}
			stagingKept(t, b.StateDir, backupStaging(b, machine), false)
			lastRunFailed(t, b.Store, map[bool]string{false: "hello", true: manifest.ReservedApp}[machine], why)
		})
	}
}

// dockerDown points Docker at an address nothing answers, for the length
// of a test.
func dockerDown(t *testing.T) {
	t.Helper()
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(gone.URL, "http"))
	t.Setenv("DOCKER_API_VERSION", dockertest.APIVersion)
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
}

// A snapshot that can't reach Docker to open its repository fails before
// it reads anything, and ends the operation all the same.
func TestABackupThatCantReachDockerToSnapshotRemovesWhatItStaged(t *testing.T) {
	for _, machine := range []bool{false, true} {
		t.Run(map[bool]string{false: "app", true: "machine"}[machine], func(t *testing.T) {
			b, raw := backupIdentityFixture(t, machine)
			dockerDown(t)
			reg := kernel.Registry{}
			reg.Add(b)
			const why = "docker isn't answering"
			receipt, err := kernel.New(b.Store, reg, "daemon").Run(context.Background(), BackupKind, raw, func(kernel.Event) {})
			if err != nil || receipt.Status != state.Failed || !strings.Contains(receipt.Error, why) {
				t.Fatalf("a snapshot without Docker must fail the backup: %+v %v", receipt, err)
			}
			stagingKept(t, b.StateDir, backupStaging(b, machine), false)
			lastRunFailed(t, b.Store, map[bool]string{false: "hello", true: manifest.ReservedApp}[machine], why)
		})
	}
}

// A move's capture writes no owner file and keeps no receipts: the move
// owns its staging and removes it with the move. So a capture that fails
// leaves it in place.
func TestAMovesCaptureThatFailsLeavesItsStagingToTheMove(t *testing.T) {
	ctx := context.Background()
	store, m, _, _ := safeMoveFixture(t)
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"files": {}}}
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: "source-r1", Status: state.RevisionActive, Manifest: data, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	sec := newSecrets(t)
	if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "https://storage.example.com", "key_id": "fixture", "key": "fixture", "bucket_prefix": "source", "password": "fixture"}); err != nil {
		t.Fatal(err)
	}
	capture := MoveCapture{Backup: Backup{Store: store, Secrets: sec, StateDir: filepath.Dir(store.Path())}}
	input, err := MoveCaptureInputFor(ctx, store, m.App, "source", "target", false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(input)
	plan, err := capture.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Steps[0].Name != "prepare" || plan.Steps[1].Name != "snapshot" {
		t.Fatalf("the rehearsal capture's steps changed: %s, %s", plan.Steps[0].Name, plan.Steps[1].Name)
	}
	if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
	dockerDown(t)
	if err := plan.Steps[1].Apply(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "docker isn't answering") {
		t.Fatalf("got %v, want the capture to fail without Docker", err)
	}
	staging := filepath.Join(filepath.Dir(store.Path()), "moves", m.App, "capture")
	if !onDisk(t, filepath.Join(staging, "manifest.json")) {
		t.Error("a failed capture removed the staging its move owns")
	}
	lastRunFailed(t, store, m.App, "docker isn't answering")
}

// An interrupted operation resumes, and a resumed snapshot reads the tree
// its prepare staged, so a snapshot interrupted mid-backup keeps it. The
// resumed snapshot can't know what the interrupted one wrote, so it
// refuses, and only then removes the staging.
func TestABackupInterruptedMidSnapshotKeepsItsStagingUntilItResumes(t *testing.T) {
	for _, machine := range []bool{false, true} {
		t.Run(map[bool]string{false: "app", true: "machine"}[machine], func(t *testing.T) {
			b, raw := backupIdentityFixture(t, machine)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			repositoryWhoseBackup(t, func(c *dockertest.Container) {
				// The backup never finishes; the daemon stops first.
				c.ExitAfter, c.Logs = 0, `{"message_type":"status"}`
				cancel()
			})
			reg := kernel.Registry{}
			reg.Add(b)
			at := time.Now().UTC()
			var operation string
			_, err := kernel.New(b.Store, reg, "old-daemon", kernel.WithClock(func() time.Time { return at })).Run(ctx, BackupKind, raw, func(ev kernel.Event) {
				if ev.Type == kernel.EventPlanned {
					operation = ev.Operation
				}
			})
			if err == nil || operation == "" {
				t.Fatalf("the backup was not interrupted: %v", err)
			}
			staging := backupStaging(b, machine)
			stagingKept(t, b.StateDir, staging, true)

			recovered := kernel.New(b.Store, reg, "new-daemon", kernel.WithClock(func() time.Time { return at.Add(time.Minute) }))
			if n, err := recovered.Recover(context.Background(), func(kernel.Event) {}); err != nil || n != 1 {
				t.Fatalf("recovered %d operation(s): %v", n, err)
			}
			receipt, err := recovered.ReceiptOf(context.Background(), operation)
			if err != nil || receipt.Status != state.Failed || !strings.Contains(receipt.Error, "interrupted without an exact snapshot receipt") {
				t.Fatalf("the resumed snapshot must refuse an uncertain capture: %+v %v", receipt, err)
			}
			stagingKept(t, b.StateDir, staging, false)
		})
	}
}

// A daemon killed while a failed snapshot removes its staging leaves part
// of the tree, and the step's failure unjournaled, so its operation
// resumes the snapshot. The owner file goes first, so the resumed snapshot
// refuses what is left rather than recording it as a backup.
func TestASnapshotWhoseStagingRemovalStopsPartwayLeavesNothingToResume(t *testing.T) {
	for _, machine := range []bool{false, true} {
		t.Run(map[bool]string{false: "app", true: "machine"}[machine], func(t *testing.T) {
			b, raw := backupIdentityFixture(t, machine)
			ctx := context.Background()
			plan, err := b.Plan(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Steps[0].Apply(ctx, io.Discard); err != nil {
				t.Fatal(err)
			}
			staging := backupStaging(b, machine)
			copied := filepath.Join(staging, "copied")
			if err := os.WriteFile(copied, []byte("what prepare copied"), 0o600); err != nil {
				t.Fatal(err)
			}
			var bucketDown atomic.Bool
			var backups atomic.Int32
			bucketDown.Store(true)
			at := time.Now().UTC().Truncate(time.Second)
			summary, _ := json.Marshal(struct {
				Type string `json:"message_type"`
				restic.Summary
			}{"summary", restic.Summary{SnapshotID: strings.Repeat("c", 64), BackupStart: at, BackupEnd: at.Add(time.Second), TotalFiles: 1, TotalBytes: 19}})
			fake := dockertest.New(t)
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.ExitAfter = 1
					switch c.Cmd[0] {
					case "init":
						c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: config file already exists"}`
						if bucketDown.Load() {
							c.Logs = `{"message_type":"exit_error","code":1,"message":"Fatal: create repository at s3:https://storage.example.test failed: dial tcp 192.0.2.10:443: i/o timeout"}`
						}
					case "backup":
						backups.Add(1)
						c.Logs = string(summary)
					}
				})
			}
			// The removal stops partway, as it would with the daemon killed
			// in it.
			removeStaging = func(string) error {
				if err := os.Remove(copied); err != nil {
					t.Error(err)
				}
				return errors.New("killed")
			}
			t.Cleanup(func() { removeStaging = os.RemoveAll })
			if err := plan.Steps[1].Apply(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "i/o timeout") {
				t.Fatalf("got %v, want the bucket's failure", err)
			}
			if onDisk(t, staging+".operation.json") {
				t.Error("the owner file outlived a removal that stopped partway")
			}

			removeStaging = os.RemoveAll
			bucketDown.Store(false)
			resumed, err := b.Plan(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			const want = "backup staging belongs to another operation; start a fresh backup"
			if err := resumed.Steps[1].Apply(ctx, io.Discard); err == nil || err.Error() != want {
				t.Fatalf("the resumed snapshot got %v, want %q", err, want)
			}
			if n := backups.Load(); n != 0 {
				t.Errorf("the resumed snapshot took %d snapshot(s) of a partial staging", n)
			}
			if good, err := b.Store.LastGoodBackupRun(ctx, map[bool]string{false: "hello", true: manifest.ReservedApp}[machine], state.BackupRunBackup); err != nil || good != nil {
				t.Errorf("a partial staging was recorded as a backup: %+v %v", good, err)
			}
		})
	}
}
