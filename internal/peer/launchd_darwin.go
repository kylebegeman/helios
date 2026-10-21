package peer

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// The launch agent that runs helios peer observe for this user, every
// observeInterval seconds.
const (
	launchAgentLabel = "com.kylebegeman.helios.peer-observe"
	observeInterval  = 60
)

// InstallLaunchAgent has launchd run helios peer observe --changes as
// this user, from the state directory stateDir, every minute and as soon
// as it is loaded, so its log grows only when something changes. It
// writes the launch agent for the running helios, replaces one already
// loaded, loads it, and returns where the agent and its log are.
// launchctl runs launchctl; the real one when nil.
func InstallLaunchAgent(ctx context.Context, stateDir string, launchctl func(ctx context.Context, args ...string) error) (plist, log string, err error) {
	agent, err := launchAgentFiles()
	if err != nil {
		return "", "", err
	}
	// The path helios was started by, not where it resolves to: a link a
	// package manager moves on upgrade keeps the agent on the current one.
	binary, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	if binary, err = filepath.Abs(binary); err != nil {
		return "", "", err
	}
	if stateDir, err = filepath.Abs(stateDir); err != nil {
		return "", "", err
	}
	run := launchctlOr(launchctl)
	if _, err := bootout(ctx, run); err != nil {
		return "", "", err
	}
	for _, dir := range []string{filepath.Dir(agent.plist), filepath.Dir(agent.log)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", "", err
		}
	}
	content := launchAgent([]string{binary, "peer", "observe", "--changes", "--state-dir", stateDir}, agent.log)
	if err := replaceFile(agent.plist, content, 0o644); err != nil {
		return "", "", err
	}
	if err := run(ctx, "bootstrap", guiDomain(), agent.plist); err != nil {
		return "", "", err
	}
	return agent.plist, agent.log, nil
}

// UninstallLaunchAgent stops launchd running helios peer observe and
// removes the launch agent. It returns where the agent was, and whether
// there was one to remove. launchctl runs launchctl; the real one when
// nil.
func UninstallLaunchAgent(ctx context.Context, launchctl func(ctx context.Context, args ...string) error) (string, bool, error) {
	agent, err := launchAgentFiles()
	if err != nil {
		return "", false, err
	}
	loaded, err := bootout(ctx, launchctlOr(launchctl))
	if err != nil {
		return "", false, err
	}
	switch err := os.Remove(agent.plist); {
	case errors.Is(err, fs.ErrNotExist):
		return agent.plist, loaded, nil
	case err != nil:
		return "", false, err
	}
	return agent.plist, true, nil
}

// agentFiles are where the launch agent and its log live.
type agentFiles struct{ plist, log string }

func launchAgentFiles() (agentFiles, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return agentFiles{}, err
	}
	return agentFiles{
		plist: filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist"),
		log:   filepath.Join(home, "Library", "Logs", "helios-peer-observe.log"),
	}, nil
}

// bootout unloads the launch agent when launchd has it loaded, and
// reports whether it had.
func bootout(ctx context.Context, run func(ctx context.Context, args ...string) error) (bool, error) {
	if run(ctx, "print", launchAgentService()) != nil {
		return false, nil
	}
	return true, run(ctx, "bootout", launchAgentService())
}

// guiDomain is this user's login session to launchd, and
// launchAgentService the launch agent in it.
func guiDomain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

func launchAgentService() string { return guiDomain() + "/" + launchAgentLabel }

// launchctlOr is run, or launchctl itself when run is nil.
func launchctlOr(run func(ctx context.Context, args ...string) error) func(ctx context.Context, args ...string) error {
	if run != nil {
		return run
	}
	return func(ctx context.Context, args ...string) error {
		out, err := exec.CommandContext(ctx, "launchctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// launchAgent is the launch agent's property list: run args every
// observeInterval seconds and once when loaded, writing everything to
// log.
func launchAgent(args []string, log string) []byte {
	var b bytes.Buffer
	str := func(s string) {
		b.WriteString("<string>")
		_ = xml.EscapeText(&b, []byte(s))
		b.WriteString("</string>")
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	`)
	str(launchAgentLabel)
	b.WriteString("\n\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range args {
		b.WriteString("\t\t")
		str(arg)
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\t</array>\n\t<key>StartInterval</key>\n\t<integer>%d</integer>\n\t<key>RunAtLoad</key>\n\t<true/>\n", observeInterval)
	for _, key := range []string{"StandardOutPath", "StandardErrorPath"} {
		b.WriteString("\t<key>" + key + "</key>\n\t")
		str(log)
		b.WriteString("\n")
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}

// replaceFile writes path whole, so launchd never reads half of it.
func replaceFile(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".helios-tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
