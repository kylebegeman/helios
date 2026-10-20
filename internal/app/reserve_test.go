package app_test

import (
	"testing"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/watch"
)

// A drill leaves every disk it restores to above the floor helios watch
// warns at, so a drill that passes never raises a disk warning of its own.
// watch imports app, so app keeps its own copy of the number.
func TestTheRestoreReserveMatchesTheWatchDiskFloor(t *testing.T) {
	if app.RestoreFreeReserve != watch.DiskFreeMin {
		t.Fatalf("the restore reserve is %d bytes and the watch floor %d", app.RestoreFreeReserve, watch.DiskFreeMin)
	}
}
