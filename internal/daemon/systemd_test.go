package daemon

import (
	"strings"
	"testing"
)

func TestDaemonUnitKeepsTheExecutableAsOneLiteralPath(t *testing.T) {
	for _, tc := range []struct {
		name, executable, command string
	}{
		{"ordinary", "/usr/local/bin/helios", `ExecStart=":/usr/local/bin/helios" daemon run`},
		{"spaces", "/opt/Helios Tools/helios", `ExecStart=":/opt/Helios Tools/helios" daemon run`},
		{"quotes", `/opt/"Kyle's tools"/helios`, `ExecStart=":/opt/\"Kyle's tools\"/helios" daemon run`},
		{"specifiers", "/opt/%h/%n/helios", `ExecStart=":/opt/%%h/%%n/helios" daemon run`},
		{"environment", "/opt/${HOME}/$USER/helios", `ExecStart=":/opt/${HOME}/$USER/helios" daemon run`},
		{"backslash", `/opt/tools\bin/helios`, `ExecStart=":/opt/tools\\bin/helios" daemon run`},
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
