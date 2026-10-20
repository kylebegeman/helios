package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

const createdEmptyLine = "volume scratch created empty: backup: false leaves it out of backups"

// withScratch keeps state in the app's backups and leaves scratch out.
func withScratch(m *manifest.Manifest) {
	out := false
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"state": {}, "scratch": {Backup: &out}}}
}

// A volume marked backup: false is never mounted into the snapshot, and the
// backup's plan names it. Without the key, every volume is snapshotted and
// the plan reads as it always has.
func TestAVolumeLeftOutOfBackupsIsNotSnapshotted(t *testing.T) {
	for _, optOut := range []bool{true, false} {
		t.Run(map[bool]string{true: "backup false", false: "no key"}[optOut], func(t *testing.T) {
			r, _ := recoveryFixture(t)
			b := Backup{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir, Hostname: func() string { return "box" }}
			m := recoveryManifest()
			withScratch(&m)
			if !optOut {
				m.Data.Volumes["scratch"] = manifest.Volume{}
			}
			body, _ := json.Marshal(m)
			rev := state.Revision{App: m.App, ID: "active-code", Manifest: body, CreatedAt: time.Now().UTC()}
			if err := r.Store.SaveRevision(context.Background(), rev); err != nil {
				t.Fatal(err)
			}
			if err := r.Store.Activate(context.Background(), m.App, rev.ID, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			fake := dockertest.New(t)
			var binds []string
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.ExitAfter = 1
					switch c.Cmd[0] {
					case "backup":
						binds = c.HostConfig.Binds
						at := time.Now().UTC()
						body, _ := json.Marshal(struct {
							Type string `json:"message_type"`
							restic.Summary
						}{"summary", restic.Summary{SnapshotID: strings.Repeat("a", 64), BackupStart: at, BackupEnd: at.Add(time.Second), TotalFiles: 3, TotalBytes: 12}})
						c.Logs = string(body)
					case "snapshots", "forget":
						c.Logs = `[]`
					}
				})
			}
			reg := kernel.Registry{}
			reg.Add(b)
			var change string
			raw, _ := json.Marshal(BackupInput{App: m.App})
			receipt, err := kernel.New(b.Store, reg, "daemon").Run(context.Background(), BackupKind, raw, func(ev kernel.Event) {
				if ev.Type == kernel.EventPlanned {
					for _, s := range ev.Plan.Steps {
						if s.Name == "snapshot" {
							change = s.Change
						}
					}
				}
			})
			if err != nil || receipt.Status != state.Succeeded {
				t.Fatalf("backup failed: %+v, %v", receipt, err)
			}
			kept := restic.VolumeMount(docker.VolumeName(m.App, "state"), "state", true)
			scratch := docker.VolumeName(m.App, "scratch")
			if !slices.Contains(binds, kept) {
				t.Fatalf("the backed-up volume wasn't snapshotted: %v", binds)
			}
			snapshotted := slices.ContainsFunc(binds, func(b string) bool { return strings.HasPrefix(b, scratch+":") })
			names := strings.Contains(change, "volume scratch is left out (backup: false)")
			if optOut && (snapshotted || !names) {
				t.Fatalf("scratch was snapshotted (%v) or the plan doesn't name it: %q", binds, change)
			}
			if !optOut && (!snapshotted || strings.Contains(change, "left out")) {
				t.Fatalf("without the key every volume is snapshotted and the plan is unchanged: %v, %q", binds, change)
			}
		})
	}
}

// helios restore and a move's restore create a volume left out of backups
// empty, restore only the rest, and say so.
func TestARestoreCreatesAVolumeLeftOutOfBackupsEmpty(t *testing.T) {
	steps := map[string]func(t *testing.T, x *restoring) kernel.Step{
		"restore": func(t *testing.T, x *restoring) kernel.Step { return x.volumesStep() },
		"move": func(t *testing.T, x *restoring) kernel.Step {
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
			x, fake := restoreFixture(t, &restic.Snapshot{ID: strings.Repeat("b", 64), Summary: &restic.Summary{TotalBytes: 12, TotalFiles: 1}})
			withScratch(x.m)
			roomToRestore(t)
			var restores [][]string
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.ExitAfter = 1
					if c.Cmd[0] == "restore" {
						restores = append(restores, c.HostConfig.Binds)
						c.Logs = `{"message_type":"summary","files_restored":1,"total_files":1,"bytes_restored":12,"total_bytes":12}`
					}
				})
			}
			var out bytes.Buffer
			if err := steps[name](t, x).Apply(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			scratch := docker.VolumeName(x.app, "scratch")
			if !slices.Contains(fake.VolumeNames(), scratch) {
				t.Fatalf("scratch wasn't created: %v", fake.VolumeNames())
			}
			if len(restores) == 0 {
				t.Fatal("the backed-up volume wasn't restored")
			}
			for _, binds := range restores {
				if slices.ContainsFunc(binds, func(b string) bool { return strings.HasPrefix(b, scratch+":") }) {
					t.Fatalf("scratch was restored into: %v", binds)
				}
			}
			if !strings.Contains(out.String(), createdEmptyLine) {
				t.Fatalf("the restore doesn't say scratch was created empty:\n%s", out.String())
			}
			if name == "restore" {
				if err := x.doneStep().Apply(context.Background(), io.Discard); err != nil {
					t.Fatal(err)
				}
				run, err := x.r.Store.LastBackupRun(context.Background(), x.app, state.BackupRunRestore)
				if err != nil || run == nil || run.Detail != "data restored; volume scratch created empty; deploy the app to run it" {
					t.Fatalf("the restore's record doesn't name scratch: %+v, %v", run, err)
				}
			}
		})
	}
}

// A drill creates a volume left out of backups empty beside the app, says
// so in its plan, output and record, and restores only the rest.
func TestADrillCreatesAVolumeLeftOutOfBackupsEmpty(t *testing.T) {
	d, fake := drillFixture(t, "state")
	withScratch(&d.m)
	d.names = newDrillNames(d.dr.StateDir, &d.m)
	roomToRestore(t)
	if step := d.restoreStep(); !strings.HasSuffix(step.Change, "; volume scratch starts empty (backup: false)") {
		t.Fatalf("the drill's plan doesn't name scratch: %q", step.Change)
	}
	var restore dockertest.Container
	fake.OnCreate = func(c dockertest.Container) {
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "snapshots":
				c.Logs = snapshotList(d.snapshot, `{"total_bytes_processed":12,"total_files_processed":1}`)
			case "restore":
				restore = *c
				c.Logs = `{"message_type":"summary","files_restored":1,"total_files":1,"bytes_restored":12,"total_bytes":12}`
			}
		})
	}
	var out bytes.Buffer
	if err := d.restoreStep().Apply(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fake.VolumeNames(), d.names.volumes["scratch"]) {
		t.Fatalf("the drill didn't create scratch: %v", fake.VolumeNames())
	}
	if slices.ContainsFunc(restore.HostConfig.Binds, func(b string) bool { return strings.HasPrefix(b, d.names.volumes["scratch"]+":") }) {
		t.Fatalf("the drill restored into scratch: %v", restore.HostConfig.Binds)
	}
	if !slices.Contains(restore.HostConfig.Binds, restic.VolumeMount(d.names.volumes["state"], "state", false)) {
		t.Fatalf("the drill didn't restore state: %v", restore.HostConfig.Binds)
	}
	if _, err := os.Stat(filepath.Join(d.names.dir, "volumes", "scratch")); !os.IsNotExist(err) {
		t.Fatalf("the drill made a restore path for scratch: %v", err)
	}
	if !strings.Contains(out.String(), createdEmptyLine) || !slices.Contains(d.details, "volume scratch created empty") {
		t.Fatalf("the drill doesn't say scratch was created empty: %q, %v", out.String(), d.details)
	}
	if err := d.cleanupStep().Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fake.VolumeNames(), []string{docker.VolumeName(d.app, "state")}) {
		t.Fatalf("the drill left scratch volumes behind: %v", fake.VolumeNames())
	}
}

// A drill gives a volume left out of backups to its workload's user before
// starting it, as a deploy does, and leaves the restored ones as they came.
func TestADrillGivesAVolumeLeftOutOfBackupsToItsWorkload(t *testing.T) {
	ctx := context.Background()
	d, fake := drillFixture(t, "state")
	withScratch(&d.m)
	w := d.m.Workloads["web"]
	w.User = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	w.Mounts = []manifest.Mount{{Volume: "state", Path: "/state"}, {Volume: "scratch", Path: "/cache"}}
	d.m.Workloads["web"] = w
	d.names = newDrillNames(d.dr.StateDir, &d.m)
	d.rev = &state.Revision{ID: "r1", Images: map[string]string{"web": "example.test/hello:1"}}
	bin, calls := t.TempDir(), filepath.Join(t.TempDir(), "calls")
	script := "#!/bin/sh\necho \"$@\" >> " + calls + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	e, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range sortedKeys(d.names.volumes) {
		if err := e.EnsureVolume(ctx, d.names.volumes[v]); err != nil {
			t.Fatal(err)
		}
	}
	fake.OnCreate = func(c dockertest.Container) {}
	if err := d.startScratch(ctx, e, "web", nil); err != nil {
		t.Fatal(err)
	}
	ran, _ := os.ReadFile(calls)
	if !strings.Contains(string(ran), "-v "+d.names.volumes["scratch"]+":/v ") || strings.Contains(string(ran), d.names.volumes["state"]) {
		t.Fatalf("the drill should give scratch, and only scratch, to its workload:\n%s", ran)
	}
}
