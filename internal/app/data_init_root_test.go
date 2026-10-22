package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresInitCanUseTheSourceRoot(t *testing.T) {
	m, source := loadCore(t)
	m.Data.Postgres.Init = "."
	const script = "select 42;\n"
	if err := os.WriteFile(filepath.Join(source, "010-root.sql"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	got, err := prepareInit(m, source, stateDir)
	if err != nil {
		t.Fatalf("valid source-root init was refused: %v", err)
	}
	if got != InitDir(stateDir, m.App) {
		t.Fatalf("unexpected init directory: %s", got)
	}
	if data, err := os.ReadFile(filepath.Join(got, "010-root.sql")); err != nil || string(data) != script {
		t.Fatalf("source-root script not copied: %q, %v", data, err)
	}
	if entries, err := os.ReadDir(got); err != nil || len(entries) != 1 {
		t.Fatalf("source-root init copied unrelated files: %v, %v", entries, err)
	}
}
