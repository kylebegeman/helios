package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

func TestRestoreRejectsInvalidAppNamesBeforePlanningFilesystemChanges(t *testing.T) {
	r, _ := recoveryFixture(t)
	def := RestoreDef{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}
	for _, name := range []string{"../outside", "hello/../../outside", "/absolute", "hello.world", "HELLO"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(RestoreInput{App: name})
			if _, err := def.Plan(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "valid app name") {
				t.Fatalf("restore accepted an unsafe app directory name %q: %v", name, err)
			}
		})
	}
}

func TestRestorePinnedStepRecordsDownstreamFailure(t *testing.T) {
	r, _ := recoveryFixture(t)
	x := &restoring{r: RestoreDef{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}, app: "hello", staging: t.TempDir(),
		run: &backupRun{store: r.Store, app: "hello", kind: state.BackupRunRestore}}
	if err := writeRestoreSnapshot(x.staging, &restic.Snapshot{ID: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("downstream restore failed")
	step := x.pinned(kernel.Step{Name: "downstream", Apply: func(context.Context, io.Writer) error { return failure }})
	if err := step.Apply(context.Background(), io.Discard); !errors.Is(err, failure) {
		t.Fatalf("restore lost the downstream error: %v", err)
	}
	run, err := r.Store.LastBackupRun(context.Background(), x.app, state.BackupRunRestore)
	if err != nil || run == nil || !run.Finished() || run.OK || run.Error != failure.Error() {
		t.Fatalf("failed restore left its run open or lost its outcome: %+v, %v", run, err)
	}
}
