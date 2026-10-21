package gitdeploy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestANullSigningPolicyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policyName), []byte("null\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckTree(dir, "hello"); err == nil {
		t.Fatal("a null signing policy silently allowed unsigned tree deployments")
	}
}
