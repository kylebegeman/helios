package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

// retentionRepository answers restic as an existing repository would, with
// retention behaving as the test says: "hang" is a forget that never exits,
// "fail" a forget that exits with restic's error, "prune hang" a forget
// that succeeds and a prune that never exits; anything else succeeds.
func retentionRepository(t *testing.T, summary restic.Summary, forget *string) (*dockertest.Server, *[]string) {
	t.Helper()
	fake := dockertest.New(t)
	var commands []string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, c.Cmd[0])
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "init":
				c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: config file already exists"}`
			case "backup":
				body, _ := json.Marshal(struct {
					Type string `json:"message_type"`
					restic.Summary
				}{"summary", summary})
				c.Logs = string(body)
			case "prune":
				if *forget == "prune hang" {
					c.ExitAfter, c.Logs = 0, `{"message_type":"status"}`
				}
			case "forget":
				switch *forget {
				case "hang":
					c.ExitAfter, c.Logs = 0, `{"message_type":"status"}`
				case "fail":
					c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: unable to create lock in backend: repository is already locked exclusively"}`
				default:
					c.Logs = `[{"remove":[{"id":"old"}]}]`
				}
			}
		})
	}
	return fake, &commands
}

func TestBackupDefersRetentionThatFailsOrRunsOutOfTime(t *testing.T) {
	for _, machine := range []bool{false, true} {
		for _, forget := range []string{"hang", "fail", "prune hang"} {
			t.Run(map[bool]string{false: "app", true: "machine"}[machine]+" "+forget, func(t *testing.T) {
				b, raw := backupIdentityFixture(t, machine)
				b.Deadlines = restic.Deadlines{Forget: 50 * time.Millisecond, Prune: 50 * time.Millisecond}
				at := time.Now().UTC().Truncate(time.Second)
				summary := restic.Summary{SnapshotID: strings.Repeat("c", 64), BackupStart: at, BackupEnd: at.Add(time.Second), TotalFiles: 3, TotalBytes: 300}
				behavior := forget
				fake, commands := retentionRepository(t, summary, &behavior)
				reg := kernel.Registry{}
				reg.Add(b)
				engine := kernel.New(b.Store, reg, "daemon")
				var lines []string
				// Without the deadlines the safety context ends the run, which
				// the assertions below reject.
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				receipt, err := engine.Run(ctx, BackupKind, raw, func(ev kernel.Event) {
					if ev.Line != "" {
						lines = append(lines, ev.Line)
					}
				})
				if err != nil || receipt.Status != state.Succeeded {
					t.Fatalf("a kept snapshot must not fail the backup: %+v %v", receipt, err)
				}
				want := []string{"init", "unlock", "backup", "forget"}
				if forget == "prune hang" {
					want = append(want, "prune")
				}
				if !slices.Equal(*commands, want) {
					t.Fatalf("stale locks must be cleared before the capture: %v, want %v", *commands, want)
				}
				runs, err := b.Store.BackupRuns(context.Background(), "", state.BackupRunBackup, 10)
				if err != nil || len(runs) != 1 {
					t.Fatalf("runs: %+v %v", runs, err)
				}
				run := runs[0]
				wantReason := map[string]string{"hang": "restic forget did not finish within 50ms and was stopped", "fail": "repository is already locked exclusively", "prune hang": "restic prune did not finish within 50ms and was stopped"}[forget]
				if !run.OK || !run.Finished() || run.Error != "" || run.Snapshot != summary.SnapshotID || !strings.Contains(run.Detail, RetentionDeferred+": ") || !strings.Contains(run.Detail, wantReason) {
					t.Fatalf("the run must keep its snapshot and say retention was deferred: %+v", run)
				}
				if output := strings.Join(lines, "\n"); !strings.Contains(output, RetentionDeferred) || !strings.Contains(output, "next backup applies retention again") {
					t.Fatalf("the operation output must explain the deferral: %q", output)
				}
				for _, call := range fake.Calls() {
					if strings.Contains(call, "--remove-all") {
						t.Fatalf("live locks must never be forced: %s", call)
					}
				}
				created, removed := 0, 0
				for _, call := range fake.Calls() {
					switch {
					case strings.HasPrefix(call, "POST /containers/create"):
						created++
					case strings.HasPrefix(call, "DELETE /containers/"):
						removed++
					}
				}
				if created == 0 || removed < created {
					t.Fatalf("a restic helper outlived the backup: %d created, %d removed", created, removed)
				}

				// The next backup applies retention again.
				behavior = "succeed"
				*commands = nil
				second, err := kernel.New(b.Store, reg, "daemon").Run(context.Background(), BackupKind, raw, func(kernel.Event) {})
				if err != nil || second.Status != state.Succeeded {
					t.Fatalf("next backup: %+v %v", second, err)
				}
				if !slices.Contains(*commands, "forget") || !slices.Contains(*commands, "prune") {
					t.Fatalf("the next backup did not retry retention: %v", *commands)
				}
				last, err := b.Store.LastBackupRun(context.Background(), runs[0].App, state.BackupRunBackup)
				if err != nil || last == nil || !last.OK || strings.Contains(last.Detail, RetentionDeferred) {
					t.Fatalf("a completed retention must not carry the old deferral: %+v %v", last, err)
				}
			})
		}
	}
}

func TestBackupRetentionInterruptedByTheOperationIsNotDeferred(t *testing.T) {
	b, raw := backupIdentityFixture(t, true)
	at := time.Now().UTC().Truncate(time.Second)
	summary := restic.Summary{SnapshotID: strings.Repeat("d", 64), BackupStart: at, TotalFiles: 1, TotalBytes: 1}
	behavior := "hang"
	fake, _ := retentionRepository(t, summary, &behavior)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previous := fake.OnCreate
	fake.OnCreate = func(c dockertest.Container) {
		previous(c)
		// A daemon shutdown during retention is an interruption to resume,
		// not a deferral to record.
		if c.Cmd[0] == "forget" {
			cancel()
		}
	}
	reg := kernel.Registry{}
	reg.Add(b)
	var lines []string
	receipt, err := kernel.New(b.Store, reg, "daemon").Run(ctx, BackupKind, raw, func(ev kernel.Event) {
		if ev.Line != "" {
			lines = append(lines, ev.Line)
		}
	})
	if err == nil && receipt != nil && receipt.Status == state.Succeeded {
		t.Fatal("an interrupted retention must not complete the operation")
	}
	if output := strings.Join(lines, "\n"); strings.Contains(output, RetentionDeferred) {
		t.Fatalf("an interruption was reported as a deferral: %q", output)
	}
	// Only the interruption path closes the run, with its error; a deferral
	// would have tried to record success with the cancelled context and
	// left the run open.
	last, err := b.Store.LastBackupRun(context.Background(), "bedrock", state.BackupRunBackup)
	if err != nil || last == nil || last.OK || !last.Finished() || last.Error == "" || strings.Contains(last.Detail, RetentionDeferred) {
		t.Fatalf("an interruption was recorded as a deferral: %+v %v", last, err)
	}
}

func TestMachineBackupStopsAnAppDataCopyAtItsDeadline(t *testing.T) {
	r, _ := recoveryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m := recoveryManifest()
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"uploads": {}}}
	body, _ := json.Marshal(m)
	rev := state.Revision{App: m.App, ID: "active-code", Manifest: body, CreatedAt: time.Now().UTC()}
	if err := r.Store.SaveRevision(ctx, rev); err != nil {
		t.Fatal(err)
	}
	if err := r.Store.Activate(ctx, m.App, rev.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	snapshot := strings.Repeat("e", 64)
	id, err := r.Store.StartBackupRun(ctx, m.App, state.BackupRunBackup, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: time.Now().UTC(), OK: true, Snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := r.Store.BackupTo(ctx, filepath.Join(stage, "state.db")); err != nil {
		t.Fatal(err)
	}
	fake := dockertest.New(t)
	var commands []string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, c.Cmd[0])
		fake.Update(c.Name, func(c *dockertest.Container) {
			if c.Cmd[0] == "snapshots" {
				c.ExitAfter, c.Logs = 1, snapshotList(snapshot, `{"total_files_processed":1,"total_bytes_processed":12}`)
				return
			}
			// The app's pinned data never finishes downloading.
			c.Logs = `{"message_type":"status"}`
		})
	}
	roomToRestore(t)
	b := Backup{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir, Deadlines: restic.Deadlines{Restore: 50 * time.Millisecond}}
	err = b.prepareMachineRecoveryCatalog(ctx, "old-host", stage, io.Discard)
	var deadline *restic.DeadlineError
	if !errors.As(err, &deadline) || deadline.Action != "restore" {
		t.Fatalf("a machine backup's data copy must stop at its deadline: %v", err)
	}
	if !slices.Equal(commands, []string{"snapshots", "restore"}) {
		t.Fatalf("unexpected restic runs: %v", commands)
	}
}

// A machine backup copies each app's last good snapshot onto the machine's
// own disk. One that can't fit beside the running apps with the reserve
// left refuses before copying it.
func TestAMachineBackupWithoutRoomForAnAppsDataRefuses(t *testing.T) {
	r, _ := recoveryFixture(t)
	ctx := context.Background()
	m := recoveryManifest()
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"uploads": {}}}
	body, _ := json.Marshal(m)
	rev := state.Revision{App: m.App, ID: "active-code", Manifest: body, CreatedAt: time.Now().UTC()}
	if err := r.Store.SaveRevision(ctx, rev); err != nil {
		t.Fatal(err)
	}
	if err := r.Store.Activate(ctx, m.App, rev.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	snapshot := strings.Repeat("e", 64)
	id, err := r.Store.StartBackupRun(ctx, m.App, state.BackupRunBackup, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Store.FinishBackupRun(ctx, id, state.BackupRun{FinishedAt: time.Now().UTC(), OK: true, Snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := r.Store.BackupTo(ctx, filepath.Join(stage, "state.db")); err != nil {
		t.Fatal(err)
	}
	fake := dockertest.New(t)
	var commands []string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, c.Cmd[0])
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			if c.Cmd[0] == "snapshots" {
				c.Logs = snapshotList(snapshot, `{"total_files_processed":1,"total_bytes_processed":`+strconv.FormatInt(90<<30, 10)+`}`)
			}
		})
	}
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 8 << 30}, nil })
	b := Backup{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}
	err = b.prepareMachineRecoveryCatalog(ctx, "old-host", stage, io.Discard)
	want := "copy hello's snapshot eeeeeeee into the machine backup: restoring needs 90.0 GB plus a 5.0 GB reserve on " +
		filepath.Join(stage, machineAppDataDir, m.App) + ", which has 8.0 GB free; free space and back up the machine again"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	if !slices.Equal(commands, []string{"snapshots"}) {
		t.Fatalf("a machine backup with no room went on to %v", commands)
	}
}
