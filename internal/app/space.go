package app

import (
	"errors"
	"fmt"
	"math"

	"golang.org/x/sys/unix"

	"github.com/kylebegeman/helios/internal/restic"
)

// restoreFreeReserve is the free space a drill leaves on every disk it
// restores to. It is watch.DiskFreeMin, the floor under which helios
// watch calls the disk a problem, so a drill never takes the machine's
// running apps below it.
const restoreFreeReserve = 5 << 30

// restoreFileBlock is the block most Linux filesystems allocate: a
// restored file takes whole blocks, however few bytes it holds.
const restoreFileBlock = 4 << 10

// allocated is the most room a restore's files take: their bytes, and a
// block for each file to round up into. A drill keeps its reserve against
// this, so a volume of many small files can't fill a disk its bytes alone
// would fit. A size that can't be added up is as big as can be.
func allocated(s restic.Size) int64 {
	if s.Bytes < 0 || s.Files <= 0 {
		return s.Bytes
	}
	if s.Files > (math.MaxInt64-s.Bytes)/restoreFileBlock {
		return math.MaxInt64
	}
	return s.Bytes + s.Files*restoreFileBlock
}

// disk is one filesystem: which device it is and how much of it is free.
type disk struct {
	dev  uint64
	free int64
}

// statDisk reports the filesystem a path is on. Tests replace it.
var statDisk = func(path string) (disk, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return disk{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return disk{}, err
	}
	block := uint64(fs.Bsize)
	free := uint64(fs.Bavail)
	if block == 0 || free > math.MaxInt64/block {
		return disk{}, fmt.Errorf("%s reports an invalid capacity", path)
	}
	return disk{dev: uint64(st.Dev), free: int64(free * block)}, nil
}

// SpaceError is a restore that doesn't fit: the disk under Path has Free,
// and the restore needs Need with Reserve left over.
type SpaceError struct {
	Path                string
	Need, Reserve, Free int64
}

func (e *SpaceError) Error() string {
	if e.Reserve == 0 {
		return fmt.Sprintf("restoring needs %s on %s, which has %s free", HumanBytes(e.Need), e.Path, HumanBytes(e.Free))
	}
	return fmt.Sprintf("restoring needs %s plus a %s reserve on %s, which has %s free", HumanBytes(e.Need), HumanBytes(e.Reserve), e.Path, HumanBytes(e.Free))
}

// checkRestoreSpace refuses a restore of need bytes that would leave less
// than reserve free on the disk under any of paths. Paths on one disk are
// checked once, as the first of them: each disk must hold the whole
// restore, since what lands where isn't known before it runs.
func checkRestoreSpace(paths []string, need, reserve int64) error {
	if need < 0 || reserve < 0 {
		return errors.New("a restore can't need negative space")
	}
	seen := map[uint64]bool{}
	for _, path := range paths {
		d, err := statDisk(path)
		if err != nil {
			return fmt.Errorf("checking free space for the restore: %w", err)
		}
		if seen[d.dev] {
			continue
		}
		seen[d.dev] = true
		if need > math.MaxInt64-reserve || d.free < need+reserve {
			return &SpaceError{Path: path, Need: need, Reserve: reserve, Free: d.free}
		}
	}
	return nil
}

// spaceLeft says how much a disk keeps free after a restore of need bytes,
// for the line an operator reads before it runs.
func spaceLeft(path string, need int64) string {
	d, err := statDisk(path)
	if err != nil || d.free < need {
		return ""
	}
	return fmt.Sprintf("%s free on %s after the restore", HumanBytes(d.free-need), path)
}
