package cli

import (
	"io"
	"testing"
)

func TestTargetCommandsPreserveStdinUnlessTheirWorkflowReadsIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		reads bool
	}{
		{"version", []string{"version"}, false},
		{"status", []string{"status"}, false},
		{"history", []string{"history"}, false},
		{"run", []string{"run", "site", "--", "true"}, false},
		{"run stdin", []string{"run", "site", "--stdin", "--", "cat"}, true},
		{"psql", []string{"psql", "site"}, true},
		{"secret set", []string{"secret", "set", "site", "TOKEN"}, true},
		{"secret import", []string{"secret", "import", "site", "TOKEN"}, true},
		{"integration set", []string{"integration", "set", "email"}, true},
		{"integration import", []string{"integration", "import", "email"}, true},
		{"move export", []string{"move", "secrets", "site", "--to", "fixture-recipient"}, false},
		{"move import", []string{"move", "secrets", "site", "--accept"}, true},
		{"git key argument", []string{"git", "allow", "site", "fixture-public-key"}, false},
		{"git key stdin", []string{"git", "allow", "site"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, _, sent := originPullTarget(t)
			const payload = "next-command\n"
			stdin := stdinOf(t, payload, false)
			if _, stderr, code := targetRun(t, config, tc.args...); code != 0 {
				t.Fatalf("target command exited %d: %s", code, stderr)
			}
			wantSent, wantLeft := "", payload
			if tc.reads {
				wantSent, wantLeft = payload, ""
			}
			if got := read(t, sent); got != wantSent {
				t.Errorf("sent %q, want %q", got, wantSent)
			}
			left, err := io.ReadAll(stdin)
			if err != nil || string(left) != wantLeft {
				t.Errorf("stdin left %q, want %q: %v", left, wantLeft, err)
			}
		})
	}
}
