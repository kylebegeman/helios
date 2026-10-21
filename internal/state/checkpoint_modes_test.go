package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReusingACheckpointRestoresItsPrivateModeWithoutReplacingIt(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if err := s.AddWatch(ctx, "https://before.example.com", at); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "checkpoint.db")
	if err := s.Checkpoint(ctx, path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWatch(ctx, "https://after.example.com", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(ctx, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("reused checkpoint is readable by others: %o", info.Mode().Perm())
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("retry replaced the checkpoint: %v", err)
	}
}
