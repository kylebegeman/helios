package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceUploadRefusesTrackedFilesBeneathAnEscapingDirectoryLink(t *testing.T) {
	source, outside := t.TempDir(), t.TempDir()
	trackedDir := filepath.Join(source, "assets")
	if err := os.Mkdir(trackedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trackedDir, "config"), []byte("tracked fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "assets/config"}} {
		if output, err := exec.Command("git", append([]string{"-C", source}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "config"), []byte("private external fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(trackedDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, trackedDir); err != nil {
		t.Fatal(err)
	}

	archive, _, err := snapshotSource(context.Background(), source)
	if archive != nil {
		archive.Close()
		os.Remove(archive.Name())
	}
	if err == nil {
		t.Fatal("source upload followed a replaced tracked directory outside the source tree")
	}
}

func TestSourceUploadDoesNotBypassGitSelectionWhenGitRefusesTheRepository(t *testing.T) {
	source := t.TempDir()
	if output, err := exec.Command("git", "-C", source, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(source, ".gitignore"), []byte("private.key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "private.key"), []byte("private ignored fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Git's ownership guard is an ordinary reason ls-files refuses a checkout.
	t.Setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
	if _, err := exec.Command("git", "-C", source, "ls-files").Output(); err == nil {
		t.Skip("Git ownership guard is disabled in this environment")
	}
	if files, err := sourceFiles(context.Background(), source); err == nil {
		t.Fatalf("Git failure fell back to unfiltered source files: %v", files)
	}
}
