package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
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

// An interrupted prepare also starts again from nothing when its
// operation resumes, so it removes what it staged too.
func TestAnInterruptedMachineBackupPrepareRemovesWhatItStaged(t *testing.T) {
	r, _ := recoveryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	saved := recoveryImageSizes
	recoveryImageSizes = func(ctx context.Context, _ func() (*docker.Engine, error), _ []string) (int64, error) {
		cancel()
		return 0, ctx.Err()
	}
	t.Cleanup(func() { recoveryImageSizes = saved })
	if err := machinePrepare(t, r).Apply(ctx, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want the prepare interrupted", err)
	}
	stagingKept(t, r.StateDir, filepath.Join(r.StateDir, "backups", "machine"), false)
	lastRunFailed(t, r.Store, manifest.ReservedApp, context.Canceled.Error())
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
