package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// execFixture is a state directory where site's one workload runs as
// bedrock-site-web-r1 beside its database, and a docker on PATH that keeps
// its arguments and whatever it could read from its standard input.
func execFixture(t *testing.T) (stateDir, arguments, input string) {
	t.Helper()
	stateDir = t.TempDir()
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw, _ := json.Marshal(manifest.Manifest{App: "site", Workloads: map[string]manifest.Workload{"web": {Kind: manifest.Web, Image: "site:r1", Port: 80}}, Data: &manifest.Data{Postgres: &manifest.Postgres{}}})
	if err := store.SaveRevision(context.Background(), state.Revision{App: "site", ID: "r1", Status: state.RevisionActive, Manifest: raw, Containers: map[string]string{"web": "bedrock-site-web-r1"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	arguments, input = filepath.Join(bin, "arguments"), filepath.Join(bin, "stdin")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$HELIOS_TEST_DOCKER_ARGS\"\n/bin/cat > \"$HELIOS_TEST_DOCKER_STDIN\"\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("HELIOS_TEST_DOCKER_ARGS", arguments)
	t.Setenv("HELIOS_TEST_DOCKER_STDIN", input)
	return stateDir, arguments, input
}

// stdinOf makes this process's standard input a pipe holding text, as
// when helios runs in a script, and says whether it is a terminal. The
// returned end shows what nobody read.
func stdinOf(t *testing.T, text string, terminal bool) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(text); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	original, wasTerminal := os.Stdin, stdinIsTerminal
	os.Stdin, stdinIsTerminal = reader, func() bool { return terminal }
	t.Cleanup(func() {
		os.Stdin, stdinIsTerminal = original, wasTerminal
		reader.Close()
	})
	return reader
}

// execAt runs helios exec with stdout a terminal or not.
func execAt(t *testing.T, stateDir string, tty bool, args ...string) {
	t.Helper()
	cmd := newExec(&app{stateDir: stateDir, stdout: io.Discard, stderr: io.Discard, tty: tty})
	cmd.SetArgs(args)
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestExecInAScriptLeavesTheScriptsNextLinesAlone(t *testing.T) {
	stateDir, arguments, input := execFixture(t)
	stdin := stdinOf(t, "next-command\n", false)
	execAt(t, stateDir, true, "site", "--", "true")
	if got := read(t, arguments); got != "exec\nbedrock-site-web-r1\ntrue\n" {
		t.Fatalf("docker ran with %q", got)
	}
	if got := read(t, input); got != "" {
		t.Fatalf("the command read %q", got)
	}
	if left, _ := io.ReadAll(stdin); string(left) != "next-command\n" {
		t.Fatalf("the script was left %q", left)
	}
}

func TestExecWithIHandsTheCommandWhatIsPipedToIt(t *testing.T) {
	stateDir, arguments, input := execFixture(t)
	stdinOf(t, "row 1\nrow 2\n", false)
	// docker refuses -t with a stdin that is no terminal.
	execAt(t, stateDir, true, "-i", "site", "--", "true")
	if got := read(t, arguments); got != "exec\n-i\nbedrock-site-web-r1\ntrue\n" {
		t.Fatalf("docker ran with %q", got)
	}
	if got := read(t, input); got != "row 1\nrow 2\n" {
		t.Fatalf("the command read %q", got)
	}
}

func TestExecAtATerminalReadsWhatIsTypedWithoutI(t *testing.T) {
	for _, c := range []struct {
		tty  bool
		want string
	}{
		{true, "exec\n-i\n-t\nbedrock-site-web-r1\nsh\n"},
		{false, "exec\n-i\nbedrock-site-web-r1\nsh\n"},
	} {
		stateDir, arguments, input := execFixture(t)
		stdinOf(t, "ls\n", true)
		execAt(t, stateDir, c.tty, "site", "--", "sh")
		if got := read(t, arguments); got != c.want {
			t.Fatalf("stdout a terminal %v: docker ran with %q", c.tty, got)
		}
		if got := read(t, input); got != "ls\n" {
			t.Fatalf("stdout a terminal %v: the command read %q", c.tty, got)
		}
	}
}

// A target's exec has SSH's stdin, never a terminal, so the client says
// whether the command reads it, and sends it only then.
func TestExecOnATargetSendsStdinOnlyWhenTheCommandReadsIt(t *testing.T) {
	interactive := []string{execInteractiveCapability}
	for _, c := range []struct {
		name         string
		capabilities []string
		terminal     bool
		args         []string
		wantArgs     string
		read         bool
	}{
		{"piped", interactive, false, []string{"site", "--", "true"}, "exec\nsite\n--\ntrue\n", false},
		{"piped with -i", interactive, false, []string{"-i", "site", "--", "true"}, "exec\nsite\n--interactive\n--\ntrue\n", true},
		{"typed at a terminal", interactive, true, []string{"site", "--", "true"}, "exec\nsite\n--interactive\n--\ntrue\n", true},
		{"piped to an older target", nil, false, []string{"site", "--", "true"}, "exec\nsite\n--\ntrue\n", false},
		// An older target has no -i and always reads its stdin.
		{"piped with -i to an older target", nil, false, []string{"-i", "site", "--", "true"}, "exec\nsite\n--\ntrue\n", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			config, record, sent := originPullTarget(t, c.capabilities...)
			stdin := stdinOf(t, "row 1\n", c.terminal)
			if _, stderr, code := targetRun(t, config, append([]string{"exec"}, c.args...)...); code != 0 {
				t.Fatalf("code %d: %s", code, stderr)
			}
			if got := read(t, record); got != c.wantArgs {
				t.Fatalf("the target ran %q", got)
			}
			wantSent, wantLeft := "", "row 1\n"
			if c.read {
				wantSent, wantLeft = wantLeft, wantSent
			}
			if got := read(t, sent); got != wantSent {
				t.Fatalf("the target was sent %q", got)
			}
			if left, _ := io.ReadAll(stdin); string(left) != wantLeft {
				t.Fatalf("the script was left %q", left)
			}
		})
	}
}

// psql at a terminal gets one only when stdin is that terminal too: a dump
// redirected into it, typed at an interactive shell, would make docker
// refuse -t.
func TestPsqlAsksForATerminalOnlyWhenSomeoneIsTyping(t *testing.T) {
	for _, c := range []struct {
		terminal bool
		want     string
	}{
		{true, "exec\n-i\n-e\nPGPASSWORD\n-t\nbedrock-site-postgres\npsql\n-h\n127.0.0.1\n-U\nsite\n-d\nsite\n"},
		{false, "exec\n-i\n-e\nPGPASSWORD\nbedrock-site-postgres\npsql\n-h\n127.0.0.1\n-U\nsite\n-d\nsite\n"},
	} {
		stateDir, arguments, input := execFixture(t)
		stdinOf(t, "select 1;\n", c.terminal)
		cmd := newPsql(&app{stateDir: stateDir, stdout: io.Discard, stderr: io.Discard, tty: true})
		cmd.SetArgs([]string{"site"})
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := read(t, arguments); got != c.want {
			t.Fatalf("stdin a terminal %v: docker ran with %q", c.terminal, got)
		}
		if got := read(t, input); got != "select 1;\n" {
			t.Fatalf("stdin a terminal %v: psql read %q", c.terminal, got)
		}
	}
}
