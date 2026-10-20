package state

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sqliteFile writes a small database of a few pages with one table.
func sqliteFile(t *testing.T, path, journal string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dsnPath.Replace(path)+"?_pragma=journal_mode("+journal+")")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT); CREATE INDEX notes_body ON notes (body)`); err != nil {
		t.Fatal(err)
	}
	for i := range 200 {
		if _, err := db.Exec(`INSERT INTO notes (body) VALUES (?)`, strings.Repeat("note ", 20)+string(rune('a'+i%26))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnIntegrityCheckPassesASoundDatabaseAndNamesACorruptOnesProblems(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sound := filepath.Join(dir, "sound #1?.db")
	sqliteFile(t, sound, "DELETE")
	if problems, err := IntegrityCheck(ctx, sound); err != nil || len(problems) != 0 {
		t.Fatalf("a sound database failed its check: %v, %v", problems, err)
	}

	corrupt := filepath.Join(dir, "corrupt.db")
	sqliteFile(t, corrupt, "DELETE")
	data, err := os.ReadFile(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	// Past the first page, which holds the schema, every byte of the
	// second goes bad: the table's or index's b-tree no longer holds up.
	for i := 4096 + 16; i < 8192 && i < len(data); i++ {
		data[i] = 0xa5
	}
	if err := os.WriteFile(corrupt, data, 0o600); err != nil {
		t.Fatal(err)
	}
	problems, err := IntegrityCheck(ctx, corrupt)
	if err == nil && len(problems) == 0 {
		t.Fatal("a corrupt database passed its check")
	}
	if len(problems) > integrityLimit {
		t.Errorf("the check reported %d problems, more than its limit of %d", len(problems), integrityLimit)
	}
}

func TestCheckingARestoredCopyKeepsWhatItsWriteAheadLogHolds(t *testing.T) {
	ctx := context.Background()
	live, restored := filepath.Join(t.TempDir(), "app.db"), filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite", "file:"+dsnPath.Replace(live)+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0; CREATE TABLE notes (body TEXT); INSERT INTO notes VALUES ('only in the log')`); err != nil {
		t.Fatal(err)
	}
	// A backup of a running app copies the database and its log as they
	// are, without the shared-memory index.
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(live + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(restored+suffix, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if problems, err := IntegrityCheck(ctx, restored); err != nil || len(problems) != 0 {
		t.Fatalf("a restored copy with its log failed its check: %v, %v", problems, err)
	}
	again, err := sql.Open("sqlite", "file:"+dsnPath.Replace(restored))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	var body string
	if err := again.QueryRow(`SELECT body FROM notes`).Scan(&body); err != nil || body != "only in the log" {
		t.Fatalf("the check lost what the log held: %q, %v", body, err)
	}
}
