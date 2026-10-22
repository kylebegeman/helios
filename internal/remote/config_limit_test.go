package remote

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsOversizedTargetConfigEvenAfterCompleteJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	data := `{"version":1,"targets":{}}` + strings.Repeat(" ", 1<<20)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("oversized configuration accepted after bounded reader truncated trailing whitespace")
	}
}

func TestSaveRejectsOversizedConfigWithoutReplacingExistingTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	original := Config{Version: ConfigVersion, Targets: map[string]Target{"fixture": {SSH: "fixture"}}}
	if err := Save(path, original); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oversized := Config{Version: ConfigVersion, Targets: map[string]Target{"fixture": {SSH: "fixture", MachineID: strings.Repeat("x", 1<<20)}}}
	if err := Save(path, oversized); err == nil {
		t.Fatal("saved a target configuration that Load cannot read")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("oversized save replaced the existing targets")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "targets.json" {
		t.Fatalf("save left temporary files: %v", entries)
	}
}

func TestSaveSizeLimitIncludesFinalNewline(t *testing.T) {
	const limit = 1 << 20
	config := Config{Version: ConfigVersion, Targets: map[string]Target{"fixture": {SSH: "fixture"}}}
	// Adding a machine identity also adds its field's JSON framing.
	target := config.Targets["fixture"]
	target.MachineID = "x"
	config.Targets["fixture"] = target
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	target.MachineID = strings.Repeat("x", limit-len(data))
	config.Targets["fixture"] = target
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := Save(path, config); err != nil {
		t.Fatalf("rejected configuration exactly at the limit: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != limit {
		t.Fatalf("fixture size %d, want %d", info.Size(), limit)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("saved configuration does not load: %v", err)
	}
	target.MachineID += "x"
	config.Targets["fixture"] = target
	if err := Save(path, config); err == nil {
		t.Fatal("final newline was omitted from the saved size limit")
	}
}
