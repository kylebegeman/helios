package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

// stagedApp is one active app in a machine backup's staged state. An app
// with data has a good backup that pinned pinOf(name) and recorded size.
type stagedApp struct {
	name  string
	data  bool
	size  restic.Size
	image string // what its web workload runs, if anything
	// finished is when its backup finished; zero is after its revision.
	finished time.Time
}

// pinOf is the snapshot an app's last good backup pinned.
func pinOf(app string) string {
	sum := sha256.Sum256([]byte(app))
	return hex.EncodeToString(sum[:])
}

// stageMachineBackup activates each app and records its backup, then
// copies the state into a staging directory, as the machine backup's
// prepare step does before its catalog runs.
func stageMachineBackup(t *testing.T, r RecoverMachine, apps ...stagedApp) string {
	t.Helper()
	activateApps(t, r, apps...)
	stage := t.TempDir()
	if err := r.Store.BackupTo(context.Background(), filepath.Join(stage, "state.db")); err != nil {
		t.Fatal(err)
	}
	return stage
}

// activateApps activates each app and records its backup.
func activateApps(t *testing.T, r RecoverMachine, apps ...stagedApp) {
	t.Helper()
	ctx := context.Background()
	for _, a := range apps {
		m := recoveryManifest()
		m.App = a.name
		if a.data {
			m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"uploads": {}}}
		}
		body, _ := json.Marshal(m)
		rev := state.Revision{App: a.name, ID: "active-code", Manifest: body, CreatedAt: time.Now().UTC()}
		if a.image != "" {
			rev.Images = map[string]string{"web": a.image}
		}
		if err := r.Store.SaveRevision(ctx, rev); err != nil {
			t.Fatal(err)
		}
		if err := r.Store.Activate(ctx, a.name, rev.ID, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if !a.data {
			continue
		}
		finished := a.finished
		if finished.IsZero() {
			finished = time.Now().UTC()
		}
		id, err := r.Store.StartBackupRun(ctx, a.name, state.BackupRunBackup, finished.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		run := state.BackupRun{FinishedAt: finished, OK: true, Snapshot: pinOf(a.name), Files: a.size.Files, Bytes: a.size.Bytes}
		if err := r.Store.FinishBackupRun(ctx, id, run); err != nil {
			t.Fatal(err)
		}
	}
}

// pinnedRepository answers restic as each app's repository would: its
// snapshots list the app's pin, or what listed names for it, with the
// size its backup recorded, and anything else exits at once. It returns
// the restic commands run.
func pinnedRepository(t *testing.T, apps []stagedApp, listed map[string]string) *[]string {
	t.Helper()
	fake := dockertest.New(t)
	var commands []string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, c.Cmd[0])
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			if c.Cmd[0] != "snapshots" {
				return
			}
			host := c.Cmd[slices.Index(c.Cmd, "--host")+1]
			for _, a := range apps {
				if a.name != host {
					continue
				}
				id := pinOf(host)
				if other, ok := listed[host]; ok {
					id = other
				}
				c.Logs = snapshotList(id, fmt.Sprintf(`{"total_files_processed":%d,"total_bytes_processed":%d}`, a.size.Files, a.size.Bytes))
			}
		})
	}
	return &commands
}

// dockerCLI puts a docker command that runs script on PATH, for the
// length of a test.
func dockerCLI(t *testing.T, script string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// nothingCopied fails a test whose machine backup ran restic or made its
// app data directory before it refused.
func nothingCopied(t *testing.T, stage string, commands []string) {
	t.Helper()
	if len(commands) != 0 {
		t.Errorf("the machine backup ran restic %v before it refused", commands)
	}
	if _, err := os.Stat(filepath.Join(stage, machineAppDataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the machine backup made its app data directory before it refused: %v", err)
	}
}

func prepareCatalog(r RecoverMachine, stage string) error {
	b := Backup{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}
	return b.prepareMachineRecoveryCatalog(context.Background(), "old-host", stage, io.Discard)
}

// Each app's data fits on its own, so checking one copy at a time would
// copy the first and refuse the second with the first still on disk.
func TestAMachineBackupRefusesAppsThatFitAloneButNotTogether(t *testing.T) {
	r, _ := recoveryFixture(t)
	apps := []stagedApp{
		{name: "hello", data: true, size: restic.Size{Bytes: 8 << 30, Files: 1}},
		{name: "other", data: true, size: restic.Size{Bytes: 8 << 30, Files: 1}},
	}
	stage := stageMachineBackup(t, r, apps...)
	commands := pinnedRepository(t, apps, nil)
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 20 << 30}, nil })
	err := prepareCatalog(r, stage)
	want := "copy the pinned app data into the machine backup: restoring needs 16.0 GB plus a 5.0 GB reserve on " + stage +
		", which has 20.0 GB free (hello 8.0 GB, other 8.0 GB); no app data was copied; free space and back up the machine again"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	nothingCopied(t, stage, *commands)
}

func TestAMachineBackupCountsItsImageArchiveBeforeCopyingAnyData(t *testing.T) {
	r, _ := recoveryFixture(t)
	apps := []stagedApp{{name: "hello", data: true, size: restic.Size{Bytes: 8 << 30, Files: 1}, image: "nginx:alpine"}}
	stage := stageMachineBackup(t, r, apps...)
	commands := pinnedRepository(t, apps, nil)
	id := "sha256:" + strings.Repeat("c", 64)
	dockerCLI(t, "echo "+id)
	saved := recoveryImageSizes
	var sized []string
	recoveryImageSizes = func(_ context.Context, ids []string) (int64, error) {
		sized = ids
		return 9 << 30, nil
	}
	t.Cleanup(func() { recoveryImageSizes = saved })
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 20 << 30}, nil })
	err := prepareCatalog(r, stage)
	want := "copy the pinned app data into the machine backup: restoring needs 17.0 GB plus a 5.0 GB reserve on " + stage +
		", which has 20.0 GB free (hello 8.0 GB, workload images up to 9.0 GB); no app data was copied; free space and back up the machine again"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	if !slices.Equal(sized, []string{id}) {
		t.Errorf("sized images %v, want the resolved %s", sized, id)
	}
	nothingCopied(t, stage, *commands)
}

// With no app data to copy, the image archive checks its own room before
// it is written.
func TestAMachineBackupWithoutRoomForItsImagesRefusesBeforeArchivingThem(t *testing.T) {
	r, _ := recoveryFixture(t)
	stage := stageMachineBackup(t, r, stagedApp{name: "site", image: "nginx:alpine"})
	dockerCLI(t, "if [ \"$2\" = save ]; then printf archive > \"$4\"; else echo sha256:"+strings.Repeat("c", 64)+"; fi")
	saved := recoveryImageSizes
	recoveryImageSizes = func(context.Context, []string) (int64, error) { return 9 << 30, nil }
	t.Cleanup(func() { recoveryImageSizes = saved })
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 12 << 30}, nil })
	err := prepareCatalog(r, stage)
	want := "archive the machine's workload images: restoring needs 9.0 GB plus a 5.0 GB reserve on " + stage +
		", which has 12.0 GB free; free space and back up the machine again"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	if _, err := os.Stat(filepath.Join(stage, machineImagesFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the images were archived without room for them: %v", err)
	}
}

// helios watch calls a disk critical below a tenth of it free, so on a
// big disk the machine backup keeps that much rather than 5 GB.
func TestAMachineBackupKeepsATenthOfABigDiskFree(t *testing.T) {
	r, _ := recoveryFixture(t)
	apps := []stagedApp{{name: "hello", data: true, size: restic.Size{Bytes: 12 << 30, Files: 1}}}
	stage := stageMachineBackup(t, r, apps...)
	commands := pinnedRepository(t, apps, nil)
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 30 << 30, total: 200 << 30}, nil })
	err := prepareCatalog(r, stage)
	want := "copy the pinned app data into the machine backup: restoring needs 12.0 GB plus a 20.0 GB reserve on " + stage +
		", which has 30.0 GB free (hello 12.0 GB); no app data was copied; free space and back up the machine again"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	nothingCopied(t, stage, *commands)
}

// An app without data has nothing to pin, so it needs no backup and takes
// no room in the plan.
func TestAMachineBackupPlansOnlyTheAppsWithData(t *testing.T) {
	r, _ := recoveryFixture(t)
	apps := []stagedApp{{name: "hello", data: true, size: restic.Size{Bytes: 8 << 30, Files: 1}}, {name: "site"}}
	stage := stageMachineBackup(t, r, apps...)
	commands := pinnedRepository(t, apps, nil)
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 12 << 30}, nil })
	err := prepareCatalog(r, stage)
	want := "copy the pinned app data into the machine backup: restoring needs 8.0 GB plus a 5.0 GB reserve on " + stage +
		", which has 12.0 GB free (hello 8.0 GB); no app data was copied; free space and back up the machine again"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	nothingCopied(t, stage, *commands)
}

func TestAMachineBackupTooBigToAddUpIsRefused(t *testing.T) {
	r, _ := recoveryFixture(t)
	huge := restic.Size{Bytes: math.MaxInt64 - 10, Files: 5}
	apps := []stagedApp{{name: "hello", data: true, size: huge}, {name: "other", data: true, size: huge}}
	stage := stageMachineBackup(t, r, apps...)
	commands := pinnedRepository(t, apps, nil)
	roomToRestore(t)
	err := prepareCatalog(r, stage)
	var space *SpaceError
	if !errors.As(err, &space) || space.Need < 0 {
		t.Fatalf("a machine backup too big to add up wasn't refused for its size: %#v", err)
	}
	nothingCopied(t, stage, *commands)
}

// A backup that finished before the active revision was created can't
// carry that revision's provenance, so it is refused before its data is
// copied only to fail the check after the copy.
func TestAMachineBackupRefusesAStalePinBeforeCopyingIt(t *testing.T) {
	r, _ := recoveryFixture(t)
	apps := []stagedApp{{name: "hello", data: true, size: restic.Size{Bytes: 12, Files: 1}, finished: time.Now().UTC().Add(-time.Hour)}}
	stage := stageMachineBackup(t, r, apps...)
	commands := pinnedRepository(t, apps, nil)
	roomToRestore(t)
	rev, err := r.Store.GetRevision(context.Background(), "hello", "active-code")
	if err != nil {
		t.Fatal(err)
	}
	err = prepareCatalog(r, stage)
	if want := freshRecoveryBackupRequired(*rev).Error(); err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	nothingCopied(t, stage, *commands)
}

// Retention can remove a pin after its backup recorded it. Every pin is
// found in its repository before any is copied, so the apps ahead of the
// missing one aren't copied for nothing.
func TestAMachineBackupFindsEveryPinBeforeCopyingAny(t *testing.T) {
	r, _ := recoveryFixture(t)
	apps := []stagedApp{
		{name: "hello", data: true, size: restic.Size{Bytes: 12, Files: 1}},
		{name: "other", data: true, size: restic.Size{Bytes: 12, Files: 1}},
	}
	stage := stageMachineBackup(t, r, apps...)
	commands := pinnedRepository(t, apps, map[string]string{"other": strings.Repeat("d", 64)})
	roomToRestore(t)
	err := prepareCatalog(r, stage)
	if want := "pin other's data recovery point: snapshot " + pinOf("other") + " was not found"; err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	if !slices.Equal(*commands, []string{"snapshots", "snapshots"}) {
		t.Errorf("a machine backup missing a pin ran restic %v", *commands)
	}
	if _, err := os.Stat(filepath.Join(stage, machineAppDataDir, "hello")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("hello's data was copied before other's pin was found: %v", err)
	}
}

// The machine backup holds the operation lock, so it waits only so long
// for Docker to answer each call.
func TestAMachineBackupStopsWaitingForADockerThatDoesNotAnswer(t *testing.T) {
	// answered runs call with a short limit on each Docker call, and fails
	// the test if it waited for Docker much longer than that.
	answered := func(t *testing.T, call func(ctx context.Context) error) error {
		t.Helper()
		saved := machineDockerTimeout
		machineDockerTimeout = 50 * time.Millisecond
		t.Cleanup(func() { machineDockerTimeout = saved })
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		started := time.Now()
		err := call(ctx)
		if waited := time.Since(started); waited > time.Second {
			t.Errorf("waited %s for docker", waited)
		}
		return err
	}
	prepare := func(t *testing.T, app stagedApp) error {
		t.Helper()
		r, _ := recoveryFixture(t)
		stage := stageMachineBackup(t, r, app)
		roomToRestore(t)
		b := Backup{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}
		return answered(t, func(ctx context.Context) error {
			return b.prepareMachineRecoveryCatalog(ctx, "old-host", stage, io.Discard)
		})
	}
	t.Run("resolving an image", func(t *testing.T) {
		dockerCLI(t, "exec sleep 5")
		err := prepare(t, stagedApp{name: "hello", image: "nginx:alpine"})
		if want := "hello/web recovery image: resolve the recorded recovery image: docker did not answer within 50ms"; err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
	})
	t.Run("sizing the images", func(t *testing.T) {
		dockerCLI(t, "exec sleep 5")
		err := answered(t, func(ctx context.Context) error {
			_, err := recoveryImageSizes(ctx, []string{"sha256:" + strings.Repeat("c", 64)})
			return err
		})
		if want := "size the workload images: docker did not answer within 50ms"; err == nil || err.Error() != want {
			t.Fatalf("got %v, want %q", err, want)
		}
	})
	t.Run("connecting", func(t *testing.T) {
		silent := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		t.Cleanup(silent.Close)
		t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(silent.URL, "http"))
		t.Setenv("DOCKER_API_VERSION", dockertest.APIVersion)
		t.Setenv("DOCKER_TLS_VERIFY", "")
		t.Setenv("DOCKER_CERT_PATH", "")
		// A record without a size sends the plan to the repository.
		err := prepare(t, stagedApp{name: "hello", data: true})
		if err == nil || !strings.Contains(err.Error(), "docker isn't answering") {
			t.Fatalf("got %v, want docker not answering", err)
		}
	})
}

// The archive is bigger than the images it holds, so their sizes are
// counted with room for it on top.
func TestWorkloadImagesAreSizedWithRoomForTheirArchive(t *testing.T) {
	dir := t.TempDir()
	answer, asked := filepath.Join(dir, "answer"), filepath.Join(dir, "asked")
	dockerCLI(t, "printf '%s\\n' \"$@\" > '"+asked+"'\ncat '"+answer+"'")
	ctx := context.Background()
	if n, err := recoveryImageSizes(ctx, nil); n != 0 || err != nil {
		t.Fatalf("no images were sized at %d: %v", n, err)
	}
	if _, err := os.Stat(asked); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sizing no images ran docker: %v", err)
	}
	ids := []string{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64)}
	for _, tc := range []struct {
		answer string
		want   int64
		err    string
	}{
		// The sum, a tenth of it and 64 MiB.
		{answer: "1000\n2000\n", want: 3000 + 300 + 64<<20},
		{answer: fmt.Sprintf("%d\n%d\n", int64(math.MaxInt64), int64(math.MaxInt64)), want: math.MaxInt64},
		{answer: "1000\n", err: "size the workload images: docker reported 1 sizes for 2 images"},
		{answer: "1000\n-1\n", err: `size the workload images: docker reported "-1" as an image's size`},
		{answer: "1000\nsha256:x\n", err: `size the workload images: docker reported "sha256:x" as an image's size`},
	} {
		if err := os.WriteFile(answer, []byte(tc.answer), 0o600); err != nil {
			t.Fatal(err)
		}
		n, err := recoveryImageSizes(ctx, ids)
		if tc.err != "" {
			if err == nil || err.Error() != tc.err {
				t.Errorf("docker answering %q: got %d, %v, want %q", tc.answer, n, err, tc.err)
			}
			continue
		}
		if err != nil || n != tc.want {
			t.Errorf("docker answering %q: got %d, %v, want %d", tc.answer, n, err, tc.want)
		}
	}
	args, err := os.ReadFile(asked)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(append([]string{"image", "inspect", "--format={{.Size}}"}, ids...), "\n") + "\n"; string(args) != want {
		t.Errorf("docker was asked %q, want %q", args, want)
	}
}
