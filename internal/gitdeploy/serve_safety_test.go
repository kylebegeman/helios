package gitdeploy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestHookReplacementDoesNotReuseAnotherWritersTemporaryPath(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "other-writer")
	if err := os.WriteFile(protected, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pre-receive")
	if err := os.Symlink(protected, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	const hook = "#!/bin/sh\nexit 0\n"
	if err := writeHook(path, hook); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(protected); err != nil || string(got) != "keep" {
		t.Fatalf("hook replacement overwrote another writer's temporary path: %q %v", got, err)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 {
		t.Fatalf("hook is not an executable regular file: %v %v", info, err)
	}
}

func TestConcurrentHookRefreshesLeaveACompleteExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-receive")
	const hook = "#!/bin/sh\nexit 0\n"
	var writers sync.WaitGroup
	for range 20 {
		writers.Go(func() {
			if err := writeHook(path, hook); err != nil {
				t.Error(err)
			}
		})
	}
	writers.Wait()
	if got, err := os.ReadFile(path); err != nil || string(got) != hook {
		t.Fatalf("hook was left incomplete: %q %v", got, err)
	}
}
