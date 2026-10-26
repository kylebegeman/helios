package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

func TestMachineRecoveryRetryReservesTheHostAfterAPreclaimFailure(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean target", true: "target acquired app history"}[dirty], func(t *testing.T) {
			r, _ := recoveryFixture(t)
			in := recoveryInput(false)
			x := &machineRecovering{r: r, in: in, dir: RecoveryDirectory(r.StateDir, in.ID)}
			rec := &machineRecoveryRecord{Input: in, Fetched: true, Snapshot: resticSnapshot(in.Snapshot)}
			if err := x.save(rec); err != nil {
				t.Fatal(err)
			}
			if err := x.reserve(rec); err != nil {
				t.Fatal(err)
			}
			failed := x.step("images", "load images", func(context.Context, io.Writer) error { return errors.New("image load failed") })
			if err := failed.Apply(context.Background(), io.Discard); err == nil {
				t.Fatal("missing expected preclaim failure")
			}
			if err := CheckMachineRecoveryWriteAccess(r.Store.Path()); err != nil {
				t.Fatal("preclaim failure should release its reservation:", err)
			}
			if dirty {
				if err := r.Store.SaveRevision(context.Background(), state.Revision{App: "other", ID: "new-app", CreatedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			retry := x.step("data", "restore data", func(context.Context, io.Writer) error {
				called = true
				if err := CheckMachineRecoveryWriteAccess(r.Store.Path()); err == nil {
					return errors.New("recovery resumed without reserving the host")
				}
				return nil
			})
			err := retry.Apply(context.Background(), io.Discard)
			if dirty {
				if err == nil || called {
					t.Fatalf("recovery resumed onto a target that is no longer clean: called=%v, error=%v", called, err)
				}
			} else if err != nil || !called {
				t.Fatalf("recovery failed to reacquire its reservation: called=%v, error=%v", called, err)
			}
		})
	}
}

func TestMachineCutoverRetryChecksOwnershipAfterItsReadinessMarker(t *testing.T) {
	r, _ := recoveryFixture(t)
	in := recoveryInput(false)
	x := &machineRecovering{r: r, in: in, dir: RecoveryDirectory(r.StateDir, in.ID)}
	m := manifest.Manifest{App: "hello", Workloads: map[string]manifest.Workload{"worker": {Kind: manifest.Worker, Image: "worker:1", User: "0:0"}}}
	body, _ := json.Marshal(m)
	rec := &machineRecoveryRecord{Input: in, FinishedAt: time.Now().UTC(), StateInstalled: true, CutoverStarted: true,
		Catalog: machineRecoveryCatalog{Revisions: []state.Revision{{App: m.App, Manifest: body, Images: map[string]string{"worker": "worker:1"}}}},
		Ready:   map[string]bool{m.App: true}, CutoverReady: map[string]bool{m.App: true}}
	if err := x.save(rec); err != nil {
		t.Fatal(err)
	}
	fake := dockertest.New(t)
	name := x.names(&m).containers["worker"]
	fake.Add(dockertest.Container{Name: name, Labels: map[string]string{
		docker.LabelOwner: docker.OwnerValue, docker.LabelApp: m.App, docker.LabelWorkload: "worker", docker.LabelRevision: recoveryRevisionID(in.ID), "bedrock.recovery": "another-recovery",
	}})
	raw, _ := json.Marshal(RecoverCutoverInput{ID: in.ID})
	plan, err := (RecoverCutover{Recovery: r}).Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Name == "runtime" {
			err = step.Apply(context.Background(), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "ownership") {
				t.Fatalf("retry adopted another recovery's container: %v", err)
			}
		}
	}
	if c, ok := fake.Container(name); !ok || c.Running {
		t.Fatal("retry started or removed a replacement container")
	}
}

func TestMachineRecoveryGivesOnlyExcludedEmptyVolumesToTheirWorkloads(t *testing.T) {
	for _, rehearsal := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery", true: "rehearsal"}[rehearsal], func(t *testing.T) {
			r, _ := recoveryFixture(t)
			in := recoveryInput(rehearsal)
			x := &machineRecovering{r: r, in: in, dir: RecoveryDirectory(r.StateDir, in.ID)}
			off := false
			m := manifest.Manifest{App: "hello", Data: &manifest.Data{Volumes: map[string]manifest.Volume{"saved": {}, "cache": {Backup: &off}}},
				Workloads: map[string]manifest.Workload{"worker": {Kind: manifest.Worker, Image: "worker:1", Mounts: []manifest.Mount{{Volume: "saved", Path: "/saved"}, {Volume: "cache", Path: "/cache"}}}}}
			body, _ := json.Marshal(m)
			rev := state.Revision{App: m.App, Manifest: body, Images: map[string]string{"worker": "worker:1"}}
			fake := dockertest.New(t)
			n := x.names(&m)
			for _, v := range n.volumes {
				fake.AddVolume(v, nil)
				if err := os.MkdirAll(fake.VolumeDir(v), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(fake.VolumeDir(n.volumes["saved"]), 0o777); err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(t.TempDir(), "ownership-calls")
			t.Setenv("MACHINE_TEST_CALLS", calls)
			t.Setenv("MACHINE_TEST_VOLUME", fake.VolumeDir(n.volumes["cache"]))
			dockerCLI(t, "printf '%s\\n' \"$@\" >> \"$MACHINE_TEST_CALLS\"\nchmod 777 \"$MACHINE_TEST_VOLUME\"\necho changed")
			e, err := docker.Connect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if err := x.startPrivate(context.Background(), &machineRecoveryRecord{}, e, rev, io.Discard); err != nil {
				t.Fatal("fresh excluded volume prevented private readiness:", err)
			}
			invoked, err := os.ReadFile(calls)
			if err != nil || !strings.Contains(string(invoked), n.volumes["cache"]+":/v") || strings.Contains(string(invoked), n.volumes["saved"]+":/v") {
				t.Fatalf("ownership did not distinguish fresh excluded and restored volumes: %s, %v", invoked, err)
			}
		})
	}
}

// Every volume of an app whose backups are off starts empty, so each goes
// to its workload's user as on the app's first deploy.
func TestMachineRecoveryGivesEveryVolumeOfAnAppWhoseBackupsAreOffToItsWorkload(t *testing.T) {
	r, _ := recoveryFixture(t)
	in := recoveryInput(true)
	x := &machineRecovering{r: r, in: in, dir: RecoveryDirectory(r.StateDir, in.ID)}
	m := manifest.Manifest{App: "scratch", Data: &manifest.Data{Volumes: map[string]manifest.Volume{"saved": {}}}, Backup: &manifest.Backup{Off: true},
		Workloads: map[string]manifest.Workload{"worker": {Kind: manifest.Worker, Image: "worker:1", Mounts: []manifest.Mount{{Volume: "saved", Path: "/saved"}}}}}
	body, _ := json.Marshal(m)
	rev := state.Revision{App: m.App, Manifest: body, Images: map[string]string{"worker": "worker:1"}}
	fake := dockertest.New(t)
	volume := x.names(&m).volumes["saved"]
	fake.AddVolume(volume, nil)
	if err := os.MkdirAll(fake.VolumeDir(volume), 0o700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(t.TempDir(), "ownership-calls")
	t.Setenv("MACHINE_TEST_CALLS", calls)
	t.Setenv("MACHINE_TEST_VOLUME", fake.VolumeDir(volume))
	dockerCLI(t, "printf '%s\\n' \"$@\" >> \"$MACHINE_TEST_CALLS\"\nchmod 777 \"$MACHINE_TEST_VOLUME\"\necho changed")
	e, err := docker.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := x.startPrivate(context.Background(), &machineRecoveryRecord{}, e, rev, io.Discard); err != nil {
		t.Fatal("an empty volume of an app whose backups are off prevented private readiness:", err)
	}
	if invoked, err := os.ReadFile(calls); err != nil || !strings.Contains(string(invoked), volume+":/v") {
		t.Fatalf("the empty volume wasn't given to its workload: %s, %v", invoked, err)
	}
}
