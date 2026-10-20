//go:build !darwin

package cli

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Off macOS there is no launchd: helios peer observe --install and
// --uninstall refuse and point at cron, and run nothing and write nothing.
func TestObserveInstallRefusedOffDarwin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var calls [][]string
	launchctl = func(_ context.Context, args ...string) error {
		calls = append(calls, args)
		return nil
	}
	t.Cleanup(func() { launchctl = nil })
	for _, flag := range []string{"--install", "--uninstall"} {
		out, errOut, code := run(t, t.TempDir(), "peer", "observe", flag)
		if code != 1 || out != "" || !strings.Contains(errOut, "the launch agent is for macOS; run helios peer observe from cron instead") {
			t.Fatalf("%s: code %d, out %q, err %q", flag, code, out, errOut)
		}
	}
	if calls != nil {
		t.Fatalf("ran launchctl %q", calls)
	}
	if entries, err := os.ReadDir(home); err != nil || len(entries) != 0 {
		t.Fatalf("wrote %v under HOME (%v)", entries, err)
	}
}
