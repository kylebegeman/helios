package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveRejectsOversizedProfileWithoutChangingExistingFile(t *testing.T) {
	_, input, _ := bootstrapFixture(t)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := Save(path, input.Profile); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	input.Profile.Helios.Version = strings.Repeat("x", 1<<20)
	if err := Save(path, input.Profile); err == nil {
		t.Fatal("Save accepted a profile larger than Load permits")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected profile changed the existing file")
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("existing profile no longer loads: %v", err)
	}
}

func TestSaveReplacesProfileWithoutFollowingExistingSymlink(t *testing.T) {
	_, input, _ := bootstrapFixture(t)
	dir := t.TempDir()
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("unrelated contents"), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.json")
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, input.Profile); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "unrelated contents" {
		t.Fatal("saving a profile overwrote the symlink target")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("saved profile mode = %v", info.Mode())
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}
