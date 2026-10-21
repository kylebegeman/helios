package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDaemonUnitKeepsTheExecutableAsOneLiteralPath(t *testing.T) {
	for _, tc := range []struct {
		name, executable, command string
	}{
		{"ordinary", "/usr/local/bin/helios", `ExecStart=":/bin/sh" "-c" "exec \"$@\"" "sh" "/usr/local/bin/helios" "daemon" "run"`},
		{"spaces", "/opt/Helios Tools/helios", `ExecStart=":/bin/sh" "-c" "exec \"$@\"" "sh" "/opt/Helios Tools/helios" "daemon" "run"`},
		{"quotes", `/opt/"Kyle's tools"/helios`, `ExecStart=":/bin/sh" "-c" "exec \"$@\"" "sh" "/opt/\"Kyle's tools\"/helios" "daemon" "run"`},
		{"specifiers", "/opt/%h/%n/helios", `ExecStart=":/bin/sh" "-c" "exec \"$@\"" "sh" "/opt/%%h/%%n/helios" "daemon" "run"`},
		{"environment", "/opt/${HOME}/$USER/helios", `ExecStart=":/bin/sh" "-c" "exec \"$@\"" "sh" "/opt/${HOME}/$USER/helios" "daemon" "run"`},
		{"backslash", `/opt/tools\bin/helios`, `ExecStart=":/bin/sh" "-c" "exec \"$@\"" "sh" "/opt/tools\\bin/helios" "daemon" "run"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unit := daemonUnit(tc.executable)
			var commands []string
			for line := range strings.SplitSeq(unit, "\n") {
				if strings.HasPrefix(line, "ExecStart=") {
					commands = append(commands, line)
				}
			}
			if len(commands) != 1 || commands[0] != tc.command {
				t.Fatalf("rendered command = %q, want %q", commands, tc.command)
			}
		})
	}
}

func TestDaemonUnitExecPreservesArgumentsAndPID(t *testing.T) {
	// These characters must stay in the filename, never become shell syntax.
	executable := filepath.Join(t.TempDir(), "Helios \"Kyle's tools\" %h ${HOME} $USER \\bin ; $(exit 23)\n\té", "helios")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf '%s\\000' \"$$\" \"$0\" \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, command, ok := strings.Cut(daemonUnit(executable), "ExecStart=")
	if !ok {
		t.Fatal("unit has no ExecStart")
	}
	command, _, _ = strings.Cut(command, "\n")
	// Decode the quoted arguments emitted by daemonUnit to exercise the shell
	// boundary locally. This does not substitute for systemd's Linux parser.
	var args []string
	reader := strings.NewReader(command)
	for reader.Len() > 0 {
		var arg string
		if _, err := fmt.Fscanf(reader, "%q", &arg); err != nil {
			t.Fatalf("decode command argument: %v", err)
		}
		args = append(args, strings.ReplaceAll(arg, "%%", "%"))
	}
	if len(args) == 0 || args[0] != ":/bin/sh" {
		t.Fatalf("command must disable systemd environment expansion and use /bin/sh: %q", args)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, strings.TrimPrefix(args[0], ":"), args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run rendered command: %v: %s", err, output)
	}
	want := []string{strconv.Itoa(cmd.Process.Pid), executable, "daemon", "run", ""}
	if got := strings.Split(string(output), "\x00"); !slices.Equal(got, want) {
		t.Fatalf("PID, executable and arguments = %q, want %q", got, want)
	}
}
