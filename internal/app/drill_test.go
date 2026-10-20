package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

// A backup of files the app can't write restores an app that answers and
// can't save, so the drill fails and says which files.
func TestADrillFailsWhenTheWorkloadCantWriteWhatWasRestored(t *testing.T) {
	stuck, open := t.TempDir(), t.TempDir()
	for _, dir := range []string{stuck, open} {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	for dir, mode := range map[string]os.FileMode{stuck: 0o644, open: 0o666} {
		path := filepath.Join(dir, "app.sqlite")
		if err := os.WriteFile(path, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	mountpoints := map[string]string{"scratch-data": stuck, "scratch-uploads": open}
	mountpoint := func(v string) (string, error) {
		if dir, ok := mountpoints[v]; ok {
			return dir, nil
		}
		return "", errors.New("no such volume")
	}
	volumes := map[string]string{"data": "scratch-data", "uploads": "scratch-uploads", "gone": "scratch-gone"}
	w := manifest.Workload{Mounts: []manifest.Mount{{Volume: "data", Path: "/data"}, {Volume: "data", Path: "/also"}, {Volume: "uploads", Path: "/uploads"}}}
	someoneElse := docker.User{UID: os.Getuid() + 1, GID: os.Getgid() + 1}

	err := restoredWritable("web", w, someoneElse, volumes, mountpoint)
	if err == nil || !strings.Contains(err.Error(), "can't write 1 file or directory in volume data, such as app.sqlite") {
		t.Fatalf("the drill should fail on data: %v", err)
	}
	if strings.Count(err.Error(), "volume data") != 1 || strings.Contains(err.Error(), "volume uploads") {
		t.Fatalf("names each stuck volume once and only those: %v", err)
	}
	if err := restoredWritable("web", w, docker.User{UID: os.Getuid(), GID: os.Getgid()}, volumes, mountpoint); err != nil {
		t.Fatalf("the owner can write it all: %v", err)
	}
	if err := restoredWritable("web", w, docker.User{}, volumes, mountpoint); err != nil {
		t.Fatalf("root can write it all: %v", err)
	}
	lost := manifest.Workload{Mounts: []manifest.Mount{{Volume: "gone", Path: "/gone"}}}
	if err := restoredWritable("web", lost, someoneElse, volumes, mountpoint); err == nil {
		t.Fatal("a restored volume that can't be found is a failed drill, not a pass")
	}
}

func TestDrillUsesVerifiedRestoreSuccessAndCleansVerificationFailures(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(map[bool]string{false: "ancestor progress counters", true: "verification failure"}[fails], func(t *testing.T) {
			r, _ := recoveryFixture(t)
			m := recoveryManifest()
			m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{"uploads": {}}}
			snapshot := strings.Repeat("a", 64)
			d := &drillState{dr: Drill{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}, app: m.App, snapshot: snapshot, m: m,
				run: &backupRun{store: r.Store, app: m.App, kind: state.BackupRunDrill}, names: newDrillNames(r.StateDir, &m)}
			fake := dockertest.New(t)
			roomToRestore(t)
			liveVolume := docker.VolumeName(m.App, "uploads")
			fake.AddVolume(liveVolume, nil)
			var restore dockertest.Container
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.ExitAfter = 1
					switch c.Cmd[0] {
					case "snapshots":
						c.Logs = snapshotList(snapshot, `{"total_bytes_processed":12}`)
					case "restore":
						restore = *c
						c.Logs = `{"message_type":"summary","files_restored":8,"total_files":6,"bytes_restored":12,"total_bytes":12}`
						if fails {
							c.ExitCode = 1
							c.Logs += "\n" + `{"message_type":"exit_error","message":"verification failed"}`
						}
					}
				})
			}
			err := d.restoreStep().Apply(context.Background(), io.Discard)
			if !slices.Contains(restore.Cmd, "--verify") {
				t.Error("drill restore must verify restored content")
			}
			if fails {
				if err == nil || !strings.Contains(err.Error(), "verification failed") {
					t.Fatalf("verification failure was accepted: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal("verified restore was rejected because of progress counters:", err)
				}
				if d.restored.FilesRestored != 8 || d.restored.TotalFiles != 6 {
					t.Fatalf("raw restore counters were changed: %+v", d.restored)
				}
				if err := d.cleanupStep().Apply(context.Background(), io.Discard); err != nil {
					t.Fatal(err)
				}
			}
			run, err := r.Store.LastBackupRun(context.Background(), m.App, state.BackupRunDrill)
			if err != nil || run == nil || !run.Finished() || run.OK == fails {
				t.Fatalf("drill receipt lost the verified outcome: %+v, %v", run, err)
			}
			if !fails && (run.Files != 8 || run.Bytes != 12) {
				t.Fatalf("drill receipt lost raw progress counters: %+v", run)
			}
			if fails && !strings.Contains(run.Error, "verification failed") {
				t.Fatalf("drill receipt lost verification error: %+v", run)
			}
			if !slices.Equal(fake.VolumeNames(), []string{liveVolume}) {
				t.Fatalf("scratch cleanup changed live data or leaked a volume: %v", fake.VolumeNames())
			}
			if _, err := os.Stat(d.names.dir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("scratch files outlived drill cleanup: %v", err)
			}
		})
	}
}

// drillFixture is a drill of an app keeping the given volumes, beside the
// app's live copies of them.
func drillFixture(t *testing.T, volumes ...string) (*drillState, *dockertest.Server) {
	t.Helper()
	r, _ := recoveryFixture(t)
	m := recoveryManifest()
	m.Data = &manifest.Data{Volumes: map[string]manifest.Volume{}}
	for _, v := range volumes {
		m.Data.Volumes[v] = manifest.Volume{}
	}
	d := &drillState{dr: Drill{Store: r.Store, Secrets: r.Secrets, StateDir: r.StateDir}, app: m.App, snapshot: strings.Repeat("a", 64), m: m,
		run: &backupRun{store: r.Store, app: m.App, kind: state.BackupRunDrill}, names: newDrillNames(r.StateDir, &m)}
	fake := dockertest.New(t)
	for _, v := range volumes {
		fake.AddVolume(docker.VolumeName(m.App, v), nil)
	}
	return d, fake
}

// liveVolumes are the app's own volumes, which a drill never touches.
func liveVolumes(d *drillState) []string {
	var names []string
	for _, v := range sortedKeys(d.names.volumes) {
		names = append(names, docker.VolumeName(d.app, v))
	}
	return names
}

// snapshotList is restic's list of one snapshot, with a summary when one
// is given, as restic 0.17 and later write it.
func snapshotList(id, summary string) string {
	list := `[{"id":"` + id + `","short_id":"` + id[:8] + `","time":"` + time.Now().UTC().Format(time.RFC3339) + `"`
	if summary != "" {
		list += `,"summary":` + summary
	}
	return list + `}]`
}

// A 90 GB snapshot restored onto a disk with 8 GB free fills the disk under
// the running apps. The drill refuses before restoring anything, removes
// what it made, and records a failed drill that says why.
func TestADrillWithoutRoomForItsRestoreRefuses(t *testing.T) {
	ctx := context.Background()
	d, fake := drillFixture(t, "uploads")
	onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 8 << 30}, nil })
	var ran []string
	fake.OnCreate = func(c dockertest.Container) {
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			ran = append(ran, c.Cmd[0])
			if c.Cmd[0] == "snapshots" {
				c.Logs = snapshotList(d.snapshot, `{"total_files_processed":41000,"total_bytes_processed":`+strconv.FormatInt(90<<30, 10)+`}`)
			}
		})
	}
	err := d.restoreStep().Apply(ctx, io.Discard)
	for _, want := range []string{"snapshot aaaaaaaa", "90.0 GB plus a 5.0 GB reserve", "which has 8.0 GB free", "free space or skip this drill"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal should say %q: %v", want, err)
		}
	}
	if slices.Contains(ran, "restore") || slices.Contains(ran, "stats") {
		t.Fatalf("a drill with no room went on to %v", ran)
	}
	if got := fake.VolumeNames(); !slices.Equal(got, liveVolumes(d)) {
		t.Fatalf("the refused drill left scratch volumes or touched live ones: %v", got)
	}
	if _, err := os.Stat(d.names.dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("scratch files outlived the refusal: %v", err)
	}
	run, err := d.dr.Store.LastBackupRun(ctx, d.app, state.BackupRunDrill)
	if err != nil || run == nil || !run.Finished() || run.OK || !strings.Contains(run.Error, "90.0 GB") || !strings.Contains(run.Error, "8.0 GB free") {
		t.Fatalf("the refusal wasn't recorded as a failed drill naming both sizes: %+v, %v", run, err)
	}
}

// A snapshot that doesn't say how much it holds, as restic before 0.17
// wrote them, is counted by restic before the drill restores it. A drill
// that can't count it doesn't restore it.
func TestADrillCountsASnapshotWithoutASummaryBeforeRestoringIt(t *testing.T) {
	for _, counts := range []bool{true, false} {
		t.Run(map[bool]string{true: "counted", false: "the count fails"}[counts], func(t *testing.T) {
			ctx := context.Background()
			d, fake := drillFixture(t, "uploads")
			roomToRestore(t)
			var stats []string
			restored := false
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.ExitAfter = 1
					switch c.Cmd[0] {
					case "snapshots":
						c.Logs = snapshotList(d.snapshot, "")
					case "stats":
						stats = c.Cmd
						c.Logs = `{"total_size":12,"total_file_count":1,"snapshots_count":1}`
						if !counts {
							c.ExitCode = 1
							c.Logs = `{"message_type":"exit_error","code":1,"message":"Fatal: repository is locked"}`
						}
					case "restore":
						restored = true
						c.Logs = `{"message_type":"summary","files_restored":1,"total_files":1,"bytes_restored":12,"total_bytes":12}`
					}
				})
			}
			err := d.restoreStep().Apply(ctx, io.Discard)
			if !slices.Equal(stats, []string{"stats", d.snapshot, "--mode", "restore-size", "--json"}) {
				t.Fatalf("restic wasn't asked what restoring the snapshot writes: %q", stats)
			}
			if counts {
				if err != nil || !restored {
					t.Fatalf("a counted snapshot that fits wasn't restored: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "counting what snapshot aaaaaaaa restores") || restored {
				t.Fatalf("a snapshot that couldn't be counted was restored or the failure lost: %v", err)
			}
			if got := fake.VolumeNames(); !slices.Equal(got, liveVolumes(d)) {
				t.Fatalf("scratch volumes outlived the failed count: %v", got)
			}
			run, err := d.dr.Store.LastBackupRun(ctx, d.app, state.BackupRunDrill)
			if err != nil || run == nil || run.OK || !strings.Contains(run.Error, "counting what snapshot") {
				t.Fatalf("the failed count wasn't recorded as a failed drill: %+v, %v", run, err)
			}
		})
	}
}

// sqliteDatabase writes a small SQLite database at path, its notes
// indexed.
func sqliteDatabase(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT); CREATE INDEX notes_body ON notes (body)`); err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		if _, err := db.Exec(`INSERT INTO notes (body) VALUES (?)`, fmt.Sprintf("note %04d", i)); err != nil {
			t.Fatal(err)
		}
	}
}

// A drill that restores a database the app can't read hasn't proved the
// backup. Every SQLite database in the restored volumes is checked, a
// corrupt one fails the drill by its path in its volume, and the drill's
// record lists the sound ones.
func TestADrillFailsOnACorruptRestoredSQLiteDatabase(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "sound", true: "corrupt"}[corrupt], func(t *testing.T) {
			ctx := context.Background()
			d, fake := drillFixture(t, "data", "uploads")
			if err := d.run.begin(ctx); err != nil {
				t.Fatal(err)
			}
			for _, v := range d.names.volumes {
				fake.AddVolume(v, nil)
			}
			data, uploads := fake.VolumeDir(d.names.volumes["data"]), fake.VolumeDir(d.names.volumes["uploads"])
			sqliteDatabase(t, filepath.Join(data, "db", "app.db"))
			cache := filepath.Join(uploads, "cache.sqlite")
			sqliteDatabase(t, cache)
			if corrupt {
				// One flipped byte in a note: the table and its index no
				// longer agree.
				b, err := os.ReadFile(cache)
				if err != nil {
					t.Fatal(err)
				}
				i := bytes.Index(b, []byte("note 0042"))
				if i < 0 {
					t.Fatal("the note isn't in the file")
				}
				b[i+8] = '7'
				if err := os.WriteFile(cache, b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// None of these is a database to check: text, a file too short
			// to be one, a journal left without its database, and a link,
			// which the drill doesn't follow, to a database that won't open.
			outside := filepath.Join(t.TempDir(), "elsewhere.db")
			if err := os.WriteFile(outside, []byte(sqliteHeader+"not a database"), 0o600); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{"notes.txt": "plain text", "short.db": "SQLite", "old.db-journal": sqliteHeader + "journal"} {
				if err := os.WriteFile(filepath.Join(data, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, filepath.Join(data, "linked.db")); err != nil {
				t.Fatal(err)
			}

			err := d.sqliteStep().Apply(ctx, io.Discard)
			if corrupt {
				if err == nil || !strings.Contains(err.Error(), "the restored SQLite database cache.sqlite in volume uploads is corrupt: ") {
					t.Fatalf("a corrupt database passed the drill: %v", err)
				}
				if got := fake.VolumeNames(); !slices.Equal(got, liveVolumes(d)) {
					t.Fatalf("scratch volumes outlived the failed drill: %v", got)
				}
				run, err := d.dr.Store.LastBackupRun(ctx, d.app, state.BackupRunDrill)
				if err != nil || run == nil || run.OK || !strings.Contains(run.Error, "cache.sqlite in volume uploads") {
					t.Fatalf("the corrupt database wasn't recorded as a failed drill: %+v, %v", run, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			d.found = &restic.Snapshot{ID: d.snapshot, ShortID: short(d.snapshot), Time: time.Now().Add(-time.Hour)}
			d.started = time.Now()
			if err := d.cleanupStep().Apply(ctx, io.Discard); err != nil {
				t.Fatal(err)
			}
			run, err := d.dr.Store.LastBackupRun(ctx, d.app, state.BackupRunDrill)
			want := "2 SQLite databases intact (" + filepath.Join("db", "app.db") + " in volume data, cache.sqlite in volume uploads)"
			if err != nil || run == nil || !run.OK || !strings.Contains(run.Detail, want) {
				t.Fatalf("the drill's record doesn't list the sound databases as %q: %+v, %v", want, run, err)
			}
		})
	}
}

func TestADrillsRecordSumsUpItsSQLiteChecks(t *testing.T) {
	many := []string{"a.db in volume data", "b.db in volume data", "c.db in volume data", "d.db in volume data", "e.db in volume data"}
	for _, c := range []struct {
		checked   []string
		unchecked int
		want      string
	}{
		{nil, 0, "no SQLite databases"},
		{many[:1], 0, "1 SQLite database intact (a.db in volume data)"},
		{many[:3], 0, "3 SQLite databases intact (a.db in volume data, b.db in volume data, c.db in volume data)"},
		{many, 2, "5 SQLite databases intact (a.db in volume data, b.db in volume data, c.db in volume data and 2 more); 2 more past the first 64 not checked"},
	} {
		if got := sqliteDetail(c.checked, c.unchecked); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}
