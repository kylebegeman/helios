package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type bootstrapCacheErrorReader struct{ err error }

func (r bootstrapCacheErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestBootstrapCacheReadFailurePreservesExistingCopy(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "regular"
		if symlink {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "checksum")
			original := "verified recovery binary"
			if symlink {
				target := filepath.Join(t.TempDir(), "referent")
				if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			readErr := errors.New("source interrupted")
			source := io.MultiReader(strings.NewReader("incomplete binary"), bootstrapCacheErrorReader{readErr})
			if err := writeBootstrapCache(path, source); !errors.Is(err, readErr) {
				t.Fatalf("error = %v, want source error", err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != original {
				t.Errorf("existing copy = %q, want %q", body, original)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode()&os.ModeSymlink != 0; got != symlink {
				t.Errorf("symlink = %v, want %v", got, symlink)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "checksum" {
				t.Errorf("failed copy left temporary files: %v", entries)
			}
		})
	}
}

func TestBootstrapCachePublicationReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "referent")
	path := filepath.Join(dir, "checksum")
	original := "unrelated file"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeBootstrapCache(path, strings.NewReader("complete verified binary")); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != original {
		t.Errorf("symlink referent = %q, want %q", body, original)
	}
	body, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "complete verified binary" {
		t.Errorf("cache copy = %q", body)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("cache mode = %v, want regular 0600", info.Mode())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("successful copy left temporary files: %v", entries)
	}
}
