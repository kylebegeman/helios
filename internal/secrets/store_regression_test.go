package secrets

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestStoreRejectsInvalidAppBeforeFilesystemAccess(t *testing.T) {
	store := DefaultStore(t.TempDir())
	for _, app := range []string{"", "..", "../escaped", "/tmp/escaped", "a/b"} {
		t.Run(app, func(t *testing.T) {
			if _, err := store.Current(app); err == nil {
				t.Fatal("Current accepted invalid app")
			}
			if _, err := store.Load(app, 0); err == nil {
				t.Fatal("Load accepted invalid app")
			}
			if _, err := store.Versions(app); err == nil {
				t.Fatal("Versions accepted invalid app")
			}
			if _, err := store.Set(app, "TOKEN", "v"); err == nil {
				t.Fatal("Set accepted invalid app")
			}
		})
	}
	if _, err := os.Stat(store.Dir); !os.IsNotExist(err) {
		t.Fatalf("invalid mutation touched filesystem: %v", err)
	}
}

func TestNamesFollowCommittedCurrentVersion(t *testing.T) {
	store := DefaultStore(t.TempDir())
	if _, _, _, err := store.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set("notes", "COMMITTED", "v"); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(VersionInfo{Version: 2, Names: []string{"UNCOMMITTED"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "notes", "v2.meta"), data, 0600); err != nil {
		t.Fatal(err)
	}
	names, version, err := store.Names("notes")
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 || !reflect.DeepEqual(names, []string{"COMMITTED"}) {
		t.Fatalf("reported uncommitted metadata: %v version %d", names, version)
	}
}

func TestStoreRejectsInvalidCommittedVersionAndMismatchedCiphertext(t *testing.T) {
	store := DefaultStore(t.TempDir())
	if _, _, _, err := store.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set("notes", "TOKEN", "v"); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(store.Dir, "notes", "current")
	for _, value := range []string{"0", "-1"} {
		if err := os.WriteFile(current, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Current("notes"); err == nil {
			t.Fatalf("invalid committed version %s accepted", value)
		}
	}
	data, err := os.ReadFile(filepath.Join(store.Dir, "notes", "v1.age"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "notes", "v2.age"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("notes", 2); err == nil {
		t.Fatal("ciphertext from another version accepted")
	}
}

func TestAnUpdateWithNoChangesKeepsTheCommittedVersion(t *testing.T) {
	store := newStore(t)
	if _, _, _, err := store.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []int{0, 1} {
		if expected == 1 {
			if _, err := store.Set("notes", "TOKEN", "fixture"); err != nil {
				t.Fatal(err)
			}
		}
		version, err := store.Update("notes", func(current map[string]string) (map[string]*string, error) {
			current["IGNORED"] = "callback snapshot only"
			return nil, nil
		})
		if err != nil || version != expected {
			t.Fatalf("empty update returned version %d, want %d: %v", version, expected, err)
		}
		values, version, err := store.LoadCurrent("notes")
		if err != nil || version != expected {
			t.Fatalf("empty update changed committed version: %d, %v", version, err)
		}
		if _, exists := values["IGNORED"]; exists {
			t.Fatal("callback modified the stored snapshot without returning a change")
		}
	}
}

func TestRemovingAnAppDoesNotSplitItsWritersAcrossTwoLocks(t *testing.T) {
	store := newStore(t)
	if _, _, _, err := store.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set("notes", "TOKEN", "fixture"); err != nil {
		t.Fatal(err)
	}
	// A writer can open the lock before removal, then wait to acquire it.
	waiting, err := os.OpenFile(store.lockPath("notes"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer waiting.Close()
	if err := store.RemoveApp("notes"); err != nil {
		t.Fatal(err)
	}
	release, err := store.lock("notes")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	err = syscall.Flock(int(waiting.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		syscall.Flock(int(waiting.Fd()), syscall.LOCK_UN)
		t.Fatal("a writer waiting before removal can race a new writer on a different lock")
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("unexpected lock failure: %v", err)
	}
}
