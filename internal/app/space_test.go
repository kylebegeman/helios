package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/restic"
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
	const state, volume, big = "/var/lib/helios/drills/loom", "/var/lib/docker/volumes/x/_data", "/mnt/big"
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
	if a.free <= 0 || a.dev != b.dev {
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
}
