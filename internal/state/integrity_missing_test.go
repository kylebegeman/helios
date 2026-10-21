package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrityCheckRefusesAMissingDatabaseWithoutCreatingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if problems, err := IntegrityCheck(context.Background(), path); err == nil {
		t.Errorf("missing database passed its check: %v", problems)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("integrity check created the missing database: %v", err)
	}
}
