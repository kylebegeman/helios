package app

import (
	"errors"
	"fmt"
	"math"

	"golang.org/x/sys/unix"

	"github.com/kylebegeman/helios/internal/restic"
)

// restoreFreeReserve is the free space a drill leaves on every disk it
// restores to, or restoreFreePercent of the disk when that is more. They
// are watch.DiskFreeMin and watch.DiskFreePercentMin, the floors under
// which helios watch calls the disk a problem, so a drill never takes the
// machine's running apps below either.
const restoreFreeReserve = 5 << 30

// restoreFreePercent is watch.DiskFreePercentMin: the share of a disk
// helios watch keeps free. A restore that keeps a reserve keeps the
// larger of restoreFreeReserve and this share of the disk it writes to.
const restoreFreePercent = 10

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

// disk is one filesystem: which device it is, how much of it is free and
// how big it is.
type disk struct {
	dev         uint64
	free, total int64
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
	blocks := uint64(fs.Blocks)
	if block == 0 || free > math.MaxInt64/block || blocks > math.MaxInt64/block {
		return disk{}, fmt.Errorf("%s reports an invalid capacity", path)
	}
	return disk{dev: uint64(st.Dev), free: int64(free * block), total: int64(blocks * block)}, nil
}

// reserveOn is what a restore leaves free on d: reserve, raised to
// restoreFreePercent of the disk, rounded up so the watcher's share
// can't be crossed by rounding. A restore that keeps no reserve
// (helios restore, a move's restore, a release rollback) keeps none.
func reserveOn(d disk, reserve int64) int64 {
	if reserve <= 0 {
		return reserve
	}
	return max(reserve, d.total/100*restoreFreePercent+restoreFreePercent)
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
// than reserve, raised by reserveOn for that disk, free on the disk under
// any of paths. Paths on one disk are checked once, as the first of them:
// each disk must hold the whole restore, since what lands where isn't
// known before it runs.
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
		r := reserveOn(d, reserve)
		if need > math.MaxInt64-r || d.free < need+r {
			return &SpaceError{Path: path, Need: need, Reserve: r, Free: d.free}
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
