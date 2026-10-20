package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

// onDisks makes statDisk answer from disks, for the length of a test.
func onDisks(t *testing.T, disks func(path string) (disk, error)) {
	t.Helper()
	saved := statDisk
	statDisk = disks
	t.Cleanup(func() { statDisk = saved })
}

// roomToRestore puts every path on one disk with far more free than any
// test restores.
func roomToRestore(t *testing.T) {
	t.Helper()
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 1 << 50}, nil })
}

func TestARestoreThatWontFitNamesThePathWhatItNeedsAndWhatIsFree(t *testing.T) {
	const state, volume, big = "/var/lib/helios/drills/hello", "/var/lib/docker/volumes/x/_data", "/mnt/big"
	onDisks(t, func(path string) (disk, error) {
		switch path {
		case state, volume:
			return disk{dev: 1, free: 8 << 30}, nil
		case big:
			return disk{dev: 2, free: 200 << 30}, nil
		}
		return disk{}, errors.New("no such file or directory")
	})

	// The state directory and the volume share a disk: it holds the
	// restore once, not twice.
	if err := checkRestoreSpace([]string{state, volume}, 3<<30, 5<<30); err != nil {
		t.Fatalf("a restore that fits a shared disk was refused: %v", err)
	}
	err := checkRestoreSpace([]string{big, state, volume}, 4<<30, 5<<30)
	var space *SpaceError
	if !errors.As(err, &space) || space.Path != state || space.Need != 4<<30 || space.Reserve != 5<<30 || space.Free != 8<<30 {
		t.Fatalf("the full disk wasn't the one named: %#v", err)
	}
	if want := "restoring needs 4.0 GB plus a 5.0 GB reserve on " + state + ", which has 8.0 GB free"; err.Error() != want {
		t.Errorf("got %q, want %q", err, want)
	}

	// Without a reserve a restore may fill the disk exactly, and no more.
	if err := checkRestoreSpace([]string{state}, 8<<30, 0); err != nil {
		t.Fatalf("a restore of exactly the free space was refused: %v", err)
	}
	err = checkRestoreSpace([]string{state}, 8<<30+1, 0)
	if err == nil || strings.Contains(err.Error(), "reserve") {
		t.Fatalf("a restore one byte too big: %v", err)
	}

	if err := checkRestoreSpace([]string{state}, math.MaxInt64, 5<<30); !errors.As(err, &space) {
		t.Fatalf("a restore too big to add up wasn't refused: %v", err)
	}
	if err := checkRestoreSpace([]string{"/gone"}, 1, 0); err == nil || !strings.Contains(err.Error(), "checking free space for the restore") {
		t.Fatalf("a disk that can't be read must refuse the restore: %v", err)
	}
	if err := checkRestoreSpace([]string{state}, -1, 0); err == nil {
		t.Fatal("a negative size was taken at its word")
	}
}

// helios watch warns below 5 GB free or below a tenth of the disk, so on
// a disk over 50 GB a restore that keeps a reserve keeps the tenth. One
// that keeps none still keeps none.
func TestARestoreKeepsATenthOfABigDiskFree(t *testing.T) {
	const path = "/var/lib/helios/drills/hello"
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 30 << 30, total: 200 << 30}, nil })
	err := checkRestoreSpace([]string{path}, 11<<30, 5<<30)
	var space *SpaceError
	if !errors.As(err, &space) || space.Need != 11<<30 || space.Reserve != 200<<30/100*10+10 || space.Free != 30<<30 {
		t.Fatalf("a restore into the disk's last tenth wasn't refused: %#v", err)
	}
	if want := "restoring needs 11.0 GB plus a 20.0 GB reserve on " + path + ", which has 30.0 GB free"; err.Error() != want {
		t.Errorf("got %q, want %q", err, want)
	}
	if err := checkRestoreSpace([]string{path}, 9<<30, 5<<30); err != nil {
		t.Fatalf("a restore that leaves a tenth free was refused: %v", err)
	}
	if err := checkRestoreSpace([]string{path}, 30<<30, 0); err != nil {
		t.Fatalf("a restore without a reserve kept one: %v", err)
	}

	// A disk whose size a hundred doesn't divide still keeps a whole tenth:
	// the largest restore that fits leaves at least that.
	const total, free int64 = 200<<30 + 99, 30 << 30
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: free, total: total}, nil })
	reserve := reserveOn(disk{total: total}, 5<<30)
	if reserve*10 < total {
		t.Fatalf("a reserve of %d leaves under a tenth of %d free", reserve, total)
	}
	if err := checkRestoreSpace([]string{path}, free-reserve, 5<<30); err != nil {
		t.Fatalf("the largest restore that fits was refused: %v", err)
	}
	if err := checkRestoreSpace([]string{path}, free-reserve+1, 5<<30); err == nil {
		t.Fatal("a restore one byte into the disk's last tenth was taken")
	}

	// On a small disk a tenth is less than 5 GB, and the 5 GB stays.
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 8 << 30, total: 20 << 30}, nil })
	err = checkRestoreSpace([]string{path}, 4<<30, 5<<30)
	if !errors.As(err, &space) || space.Reserve != 5<<30 {
		t.Fatalf("a small disk didn't keep the 5 GB reserve: %#v", err)
	}
	if err := checkRestoreSpace([]string{path}, 3<<30, 5<<30); err != nil {
		t.Fatalf("a restore that leaves 5 GB of a small disk was refused: %v", err)
	}
}

func TestTheFreeSpaceOfARealDirectoryIsReadFromItsFilesystem(t *testing.T) {
	dir := t.TempDir()
	a, err := statDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := statDisk(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if a.free <= 0 || a.total <= 0 || a.total < a.free || a.dev != b.dev {
		t.Fatalf("a temporary directory and its parent: %+v, %+v", a, b)
	}
	if _, err := statDisk(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing path has no disk")
	}
}

func TestARestoreSaysWhatItsDiskKeepsFree(t *testing.T) {
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 12 << 30}, nil })
	if got, want := spaceLeft("/srv", 2<<30), "10.0 GB free on /srv after the restore"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := spaceLeft("/srv", 13<<30); got != "" {
		t.Errorf("a restore that can't fit claimed space left: %q", got)
	}
}

// An operator's restore refuses only what can't fit at all, and otherwise
// says what the disk keeps free. What fetch staged from the snapshot is on
// the disk already, so it isn't counted twice.
func TestARestoreRefusesOnlyWhatCantFitAndSaysWhatIsLeft(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	fake.AddVolume(docker.VolumeName("hello", "uploads"), nil)
	e, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	staging := t.TempDir()
	if err := os.WriteFile(filepath.Join(staging, "postgres.dump"), make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "restore-snapshot.json"), make([]byte, 4<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 64)
	x := &restoring{app: "hello", asked: id, staging: staging,
		snapshot: &restic.Snapshot{ID: id, Summary: &restic.Summary{TotalBytes: 3<<30 + 1<<20}}}
	mountpoint := fake.VolumeDir(docker.VolumeName("hello", "uploads"))

	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 4 << 30}, nil })
	var out bytes.Buffer
	if err := x.checkVolumesSpace(ctx, e, nil, []string{"uploads"}, &out); err != nil {
		t.Fatal(err)
	}
	if want := "1.0 GB free on " + mountpoint + " after the restore\n"; out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}

	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 2 << 30}, nil })
	err = x.checkVolumesSpace(ctx, e, nil, []string{"uploads"}, io.Discard)
	if want := "snapshot bbbbbbbb: restoring needs 3.0 GB on " + mountpoint + ", which has 2.0 GB free; free space on this machine and try again"; err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	// The dump is on the disk already; the record of which snapshot was
	// fetched isn't part of it.
	var space *SpaceError
	if !errors.As(err, &space) || space.Need != 3<<30 {
		t.Fatalf("the restore needs exactly the snapshot less the staged dump: %#v", err)
	}
}

// failingCount is a repository that can't say what a restore writes.
type failingCount struct{}

func (failingCount) RestoreSize(context.Context, string, string) (restic.Size, error) {
	return restic.Size{}, errors.New("repository is locked")
}

// Only a drill fails closed. An operator's restore whose room can't be
// counted goes ahead and says it wasn't checked.
func TestARestoreWhoseRoomCantBeCountedGoesAheadUnchecked(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	fake.AddVolume(docker.VolumeName("hello", "uploads"), nil)
	e, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	id := strings.Repeat("b", 64)
	x := &restoring{app: "hello", asked: id, staging: t.TempDir(), snapshot: &restic.Snapshot{ID: id}}
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 2 << 30}, nil })
	var out bytes.Buffer
	if err := x.checkVolumesSpace(ctx, e, failingCount{}, []string{"uploads"}, &out); err != nil {
		t.Fatalf("a restore that couldn't be counted was refused: %v", err)
	}
	if want := "restoring without a space check: counting what snapshot bbbbbbbb restores: repository is locked\n"; out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

// A drill keeps its reserve against the blocks a restore takes, not just
// its bytes: every file takes at least one.
func TestARestoreTakesABlockForEveryFile(t *testing.T) {
	for _, c := range []struct {
		size restic.Size
		want int64
	}{
		{restic.Size{}, 0},
		{restic.Size{Bytes: 5 << 30}, 5 << 30},
		{restic.Size{Bytes: 2 << 30, Files: 1 << 20}, 6 << 30},
		{restic.Size{Bytes: math.MaxInt64 - 1, Files: 1}, math.MaxInt64},
		{restic.Size{Bytes: 1, Files: math.MaxInt64}, math.MaxInt64},
	} {
		if got := allocated(c.size); got != c.want {
			t.Errorf("%+v takes %d, want %d", c.size, got, c.want)
		}
	}
}

// restoreFixture is an operator's restore of the given snapshot of an app
// keeping an uploads volume, with Docker's CLI saying every volume is
// empty.
func restoreFixture(t *testing.T, snapshot *restic.Snapshot) (*restoring, *dockertest.Server) {
	t.Helper()
	r, _ := recoveryFixture(t)
	m := recoveryManifest()
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"uploads": {}}}
	x := &restoring{r: RestoreDef{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}, app: m.App, asked: snapshot.ID,
		staging: t.TempDir(), run: &backupRun{store: r.Store, app: m.App, kind: state.BackupRunRestore}, m: &m, snapshot: snapshot}
	if err := x.run.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return x, dockertest.New(t)
}

// helios restore, a release rollback and a move's restore each check the
// room before restoring a volume, and refuse what can't fit without
// restoring any of it.
func TestARestoreThatCantFitRestoresNoVolume(t *testing.T) {
	big := func() *restic.Snapshot {
		return &restic.Snapshot{ID: strings.Repeat("b", 64), Summary: &restic.Summary{TotalBytes: 90 << 30, TotalFiles: 41000}}
	}
	const refusal = "snapshot bbbbbbbb: restoring needs 90.0 GB on "
	steps := map[string]func(x *restoring) kernel.Step{
		"restore": func(x *restoring) kernel.Step { return x.volumesStep() },
		"move": func(x *restoring) kernel.Step {
			h := Handoff{App: x.app, From: "old.example.test", To: "new.example.test", Migration: "move-0123456789abcdef", Phase: "final",
				Revision: "source-r1", ManifestDigest: manifestDigest(x.m), HasData: true, Bucket: "example-hello", Snapshot: x.snapshot.ID}
			record := &migrationRecord{Handoff: h, Role: "target", Phase: "restoring", TargetRevision: "target-r1"}
			if err := saveMigration(x.r.Store.Path(), record); err != nil {
				t.Fatal(err)
			}
			return moveRestoreVolumes(x, h, "target-r1")
		},
	}
	for _, name := range sortedKeys(steps) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			x, fake := restoreFixture(t, big())
			step := steps[name](x)
			var ran []string
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.ExitAfter = 1
					ran = append(ran, c.Cmd[0])
					if c.Cmd[0] == "restore" {
						c.Logs = `{"message_type":"summary","files_restored":1,"total_files":1,"bytes_restored":12,"total_bytes":12}`
					}
				})
			}

			onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 8 << 30}, nil })
			err := step.Apply(ctx, io.Discard)
			if err == nil || !strings.Contains(err.Error(), refusal) || !strings.HasSuffix(err.Error(), "which has 8.0 GB free; free space on this machine and try again") {
				t.Fatalf("a restore with no room wasn't refused: %v", err)
			}
			if len(ran) > 0 {
				t.Fatalf("a refused restore went on to %v", ran)
			}
			if name == "move" {
				record, err := readMigration(x.r.Store.Path(), x.app)
				if err != nil || record == nil || len(record.RestoringVolumes) > 0 {
					t.Fatalf("a refused move marked a volume as restoring: %+v, %v", record, err)
				}
			} else {
				run, err := x.r.Store.LastBackupRun(ctx, x.app, state.BackupRunRestore)
				if err != nil || run == nil || run.OK || !strings.Contains(run.Error, refusal) {
					t.Fatalf("the refusal wasn't recorded as a failed restore: %+v, %v", run, err)
				}
			}

			x.run = &backupRun{store: x.r.Store, app: x.app, kind: state.BackupRunRestore}
			if err := x.run.begin(ctx); err != nil {
				t.Fatal(err)
			}
			onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 100 << 30}, nil })
			var out bytes.Buffer
			if err := step.Apply(ctx, &out); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ran, []string{"restore"}) || !strings.Contains(out.String(), "10.0 GB free on ") {
				t.Fatalf("a restore with room ran %v and said %q", ran, out.String())
			}
		})
	}
}
