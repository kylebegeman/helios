package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// fakeLaunchctl stands in for launchctl: it keeps each call, and whether
// launchd would have the launch agent loaded.
type fakeLaunchctl struct {
	calls  [][]string
	loaded bool
}

// use has helios peer observe run the fake instead of launchctl until the
// test ends.
func (f *fakeLaunchctl) use(t *testing.T) {
	t.Helper()
	launchctl = func(_ context.Context, args ...string) error {
		f.calls = append(f.calls, args)
		switch args[0] {
		case "print":
			if !f.loaded {
				return errors.New("could not find service")
			}
		case "bootstrap":
			f.loaded = true
		case "bootout":
			f.loaded = false
		}
		return nil
	}
	t.Cleanup(func() { launchctl = nil })
}

// took is the calls since it was last asked.
func (f *fakeLaunchctl) took() [][]string {
	calls := f.calls
	f.calls = nil
	return calls
}

// launchAgentKeys is a launch agent as plutil reads it, the way launchd
// will.
type launchAgentKeys struct {
	Label             string
	ProgramArguments  []string
	StartInterval     int
	RunAtLoad         bool
	StandardOutPath   string
	StandardErrorPath string
}

func readLaunchAgent(t *testing.T, path string) launchAgentKeys {
	t.Helper()
	out, err := exec.Command("plutil", "-convert", "json", "-o", "-", path).Output()
	if err != nil {
		t.Fatalf("plutil can't read %s: %v", path, err)
	}
	var keys launchAgentKeys
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&keys); err != nil {
		t.Fatalf("%v in %s", err, out)
	}
	return keys
}

// helios peer observe --install has launchd run this helios with
// --changes on this state directory, by absolute path, every minute and
// once when loaded, logging to one file. Installing again replaces the
// agent launchd has loaded, and --uninstall unloads and removes it, once.
func TestObserveInstallWritesLaunchAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fake := &fakeLaunchctl{}
	fake.use(t)
	// launchd starts the agent from /, so a relative state directory is
	// kept as the absolute one it names here.
	t.Chdir(t.TempDir())
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if binary, err = filepath.Abs(binary); err != nil {
		t.Fatal(err)
	}
	const label = "com.kylebegeman.helios.peer-observe"
	agent := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	log := filepath.Join(home, "Library", "Logs", "helios-peer-observe.log")
	domain := "gui/" + strconv.Itoa(os.Getuid())
	service := domain + "/" + label

	if out := peerRun(t, "state", "peer", "observe", "--install"); out != "installed "+agent+"; launchd runs helios peer observe every minute and logs what changes to "+log+"\n" {
		t.Fatalf("install: %q", out)
	}
	want := launchAgentKeys{
		Label:             label,
		ProgramArguments:  []string{binary, "peer", "observe", "--changes", "--state-dir", filepath.Join(wd, "state")},
		StartInterval:     60,
		RunAtLoad:         true,
		StandardOutPath:   log,
		StandardErrorPath: log,
	}
	if got := readLaunchAgent(t, agent); !reflect.DeepEqual(got, want) {
		t.Fatalf("the launch agent is %+v, want %+v", got, want)
	}
	if got := fake.took(); !reflect.DeepEqual(got, [][]string{{"print", service}, {"bootstrap", domain, agent}}) {
		t.Fatalf("install ran launchctl %q", got)
	}

	peerRun(t, "state", "peer", "observe", "--install")
	if got := fake.took(); !reflect.DeepEqual(got, [][]string{{"print", service}, {"bootout", service}, {"bootstrap", domain, agent}}) {
		t.Fatalf("installing again ran launchctl %q", got)
	}

	if out := peerRun(t, "state", "peer", "observe", "--uninstall"); out != "removed "+agent+"; launchd no longer runs helios peer observe\n" {
		t.Fatalf("uninstall: %q", out)
	}
	if got := fake.took(); !reflect.DeepEqual(got, [][]string{{"print", service}, {"bootout", service}}) {
		t.Fatalf("uninstall ran launchctl %q", got)
	}
	if _, err := os.Stat(agent); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the launch agent is still there: %v", err)
	}
	if out := peerRun(t, "state", "peer", "observe", "--uninstall"); out != "no launch agent runs helios peer observe here\n" {
		t.Fatalf("uninstalling again: %q", out)
	}
	if got := fake.took(); !reflect.DeepEqual(got, [][]string{{"print", service}}) {
		t.Fatalf("uninstalling again ran launchctl %q", got)
	}
}
