package incident

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

func TestSavedEvidenceLoadsBackForItsIncidentOnly(t *testing.T) {
	stateDir := t.TempDir()
	e := full()
	if err := Save(stateDir, e); err != nil {
		t.Fatal(err)
	}
	inc := state.Incident{ID: e.Incident.ID, OpenedAt: opened}
	got, err := Load(stateDir, inc)
	if err != nil {
		t.Fatal(err)
	}
	if Size(got) != Size(e) || got.Logs[1].Lines[399].Text != "line 399" {
		t.Fatalf("loaded %d bytes of %d", Size(got), Size(e))
	}
	assertPrivate(t, Dir(stateDir, e.Incident.ID), filepath.Join(Dir(stateDir, e.Incident.ID), EvidenceFile))

	if _, err := Load(stateDir, state.Incident{ID: inc.ID, OpenedAt: opened.Add(time.Second)}); !errors.Is(err, ErrStale) {
		t.Fatalf("an earlier incident's evidence loaded: %v", err)
	}
	if _, err := Load(stateDir, state.Incident{ID: inc.ID + 1, OpenedAt: opened}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("evidence never saved: %v", err)
	}
}

func TestEvidenceOverTheCapLeavesTheSavedFile(t *testing.T) {
	stateDir := t.TempDir()
	e := full()
	if err := Save(stateDir, e); err != nil {
		t.Fatal(err)
	}
	big := e.Clone()
	big.Incident.Message = strings.Repeat("m", FileMax)
	if err := Save(stateDir, big); err == nil || !strings.Contains(err.Error(), "over 256 KiB") {
		t.Fatalf("saved evidence over the cap: %v", err)
	}
	got, err := Load(stateDir, state.Incident{ID: e.Incident.ID, OpenedAt: opened})
	if err != nil || got.Incident.Message != e.Incident.Message {
		t.Fatalf("the saved evidence changed: %v", err)
	}
}

func TestWriteFileReplacesAFileWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marker.json")
	for _, data := range []string{`{"state":"sending"}`, `{"state":"sent"}`} {
		if err := WriteFile(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Fatalf("read %q, %v", got, err)
		}
	}
	assertPrivate(t, "", path)
	if err := WriteFile(filepath.Join(dir, "missing", "marker.json"), []byte("{}")); err == nil {
		t.Fatal("wrote into a directory that isn't there")
	}
}

func TestCreateExclusiveLeavesWhatIsThere(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "incidents", "42")
	path := filepath.Join(dir, "loom.json")
	if err := CreateExclusive(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := CreateExclusive(path, []byte("second")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second create: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "first" {
		t.Fatalf("read %q, %v", got, err)
	}
	assertPrivate(t, dir, path)
}

// assertPrivate fails unless dir, when given, and file are their
// owner's alone, and dir holds nothing but file.
func assertPrivate(t *testing.T, dir, file string) {
	t.Helper()
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s is %v", filepath.Base(file), info.Mode().Perm())
	}
	if dir == "" {
		dir = filepath.Dir(file)
	} else {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("the directory is %v", info.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(file) {
		t.Fatalf("the directory holds %v", entries)
	}
}
