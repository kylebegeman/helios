package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

// UpgradeKind replaces the helios binary with a staged one and restarts the
// daemon. If the new daemon can't start, systemd runs the rollback unit,
// which puts the previous binary back; the resumed operation then reports
// that.
const UpgradeKind = "host.upgrade"

// Where the binary and its spares live.
const (
	BinaryPath     = "/usr/local/bin/bedrock"
	LibDir         = "/usr/local/lib/bedrock"
	PreviousBinary = LibDir + "/previous"
	StagedMarker   = LibDir + "/staged"
	RollbackScript = LibDir + "/rollback.sh"
)

// Upgrade is the Definition for UpgradeKind.
type Upgrade struct {
	Env Env
	// Store is checkpointed before switching binaries.
	Store *state.Store
	// Socket is the daemon's, to ask it which build it runs.
	Socket string
	// DaemonVersion asks the daemon which build it runs, and says whether
	// one answered. Nil asks on Socket; a socket nobody answers on means
	// this process is the daemon, or there is none.
	DaemonVersion func(ctx context.Context) (version.Info, bool)
}

// running is the build this machine runs helios as: the daemon's answer
// when one answers, else this process's own. A resumed upgrade runs inside
// the new daemon before it listens, and the command line's local kernel
// runs beside the daemon it restarts; each is right about itself.
func (u Upgrade) running(ctx context.Context) version.Info {
	ask := u.DaemonVersion
	if ask == nil && u.Socket != "" {
		ask = askDaemon(u.Socket)
	}
	if ask != nil {
		if info, ok := ask(ctx); ok {
			return info
		}
	}
	return u.Env.RunningVersion()
}

// askDaemon asks the daemon on a socket which build it runs.
func askDaemon(socket string) func(context.Context) (version.Info, bool) {
	return func(ctx context.Context) (version.Info, bool) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		client := api.Dial(socket)
		defer client.Close()
		info, err := client.Version(ctx)
		return info, err == nil
	}
}

// UpgradeInput says which binary to install.
type UpgradeInput struct {
	// Path is a helios binary already on this machine.
	Path string `json:"path"`
	// Signer is the fingerprint of the Helios release key whose signature
	// vouched for the build, when it was fetched from a release.
	Signer string `json:"signer,omitempty"`
	// Unsigned says why a fetched build has no signer, when a pinned
	// checksum vouched for it instead.
	Unsigned string `json:"unsigned,omitempty"`
}

// vouched says what vouched for the build, for the plan.
func (in UpgradeInput) vouched() string {
	switch {
	case in.Signer != "":
		return ", signed by Helios release key " + in.Signer
	case in.Unsigned != "":
		return ", unsigned (" + in.Unsigned + ") and vouched for by its pinned checksum"
	}
	return ""
}

// Kind implements kernel.Definition.
func (Upgrade) Kind() string { return UpgradeKind }

// Plan implements kernel.Definition.
func (u Upgrade) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in UpgradeInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("upgrade input: %w", err)
	}
	if in.Path == "" || !filepath.IsAbs(in.Path) {
		return nil, errors.New("upgrade needs the absolute path of the new binary")
	}
	env := u.Env
	if !env.Privileged {
		return nil, errors.New("upgrading needs root")
	}
	running := u.running(ctx)
	target, err := probeVersion(ctx, env, in.Path)
	if err != nil {
		return nil, err
	}
	candidate, err := probeCapabilities(ctx, env, in.Path)
	if err != nil {
		return nil, err
	}
	stateVersion := state.SchemaVersion
	if u.Store != nil {
		stateVersion, err = u.Store.Version(ctx)
		if err != nil {
			return nil, err
		}
	}
	if err := candidate.AcceptsState(stateVersion); err != nil {
		return nil, fmt.Errorf("upgrade preflight: %w", err)
	}
	// The plan is re-built when the operation resumes on the new daemon, so
	// nothing in a step's Change may depend on which build is running now;
	// that goes in the notes.
	described := fmt.Sprintf("%s (%s)", target.Version, target.Commit)
	plan := &kernel.Plan{Target: BinaryPath, Recovery: kernel.Resume}
	plan.Steps = append(plan.Steps,
		kernel.Step{
			Name: "stage", Change: "keep the running binary as the previous one and stage " + described + in.vouched(),
			Note: doneIf(identity(target) == identity(running), "already the running build", fmt.Sprintf("replacing %s (%s)", running.Version, running.Commit)),
			Apply: func(ctx context.Context, out io.Writer) error {
				if u.Store == nil {
					return errors.New("upgrade needs an open state store for its checkpoint")
				}
				if _, err := checkpointUpgrade(ctx, u.Store, env, target); err != nil {
					return err
				}
				if err := os.MkdirAll(env.Path(LibDir), 0o755); err != nil {
					return err
				}
				if err := copyFile(env.Path(BinaryPath), env.Path(PreviousBinary)); err != nil {
					return fmt.Errorf("keep the previous binary: %w", err)
				}
				if _, err := env.WriteFile(StagedMarker, identity(target)+"\n", 0o644); err != nil {
					return err
				}
				fmt.Fprintf(out, "previous build kept at %s\n", PreviousBinary)
				return nil
			},
		},
		kernel.Step{
			Name: "switch", Change: "put the new binary at " + BinaryPath,
			Apply: func(_ context.Context, out io.Writer) error {
				tmp := env.Path(BinaryPath) + ".new"
				if err := copyFile(env.Path(in.Path), tmp); err != nil {
					return err
				}
				if err := os.Chmod(tmp, 0o755); err != nil {
					return err
				}
				if err := os.Rename(tmp, env.Path(BinaryPath)); err != nil {
					return err
				}
				fmt.Fprintf(out, "%s is now %s (%s)\n", BinaryPath, target.Version, target.Commit)
				return nil
			},
		},
		kernel.Step{
			Name: "restart", Change: "restart the daemon on the new binary",
			// Inside the daemon, the first attempt restarts it, which ends
			// this process, and the second attempt is the resumed operation:
			// on the new daemon (done), or on the old one that systemd's
			// rollback put back (failed). From the command line, the restart
			// returns once the new daemon is ready (the unit is Type=notify),
			// and the daemon is asked what it runs.
			Apply: func(ctx context.Context, out io.Writer) error {
				now := u.running(ctx)
				if identity(now) == identity(target) {
					fmt.Fprintf(out, "running %s (%s)\n", now.Version, now.Commit)
					return nil
				}
				if kernel.Attempt(ctx) <= 1 {
					fmt.Fprintln(out, "restarting the daemon; the operation resumes on the new build")
					_, err := env.Run(ctx, "systemctl", "restart", "bedrock.service")
					// A real restart ends the process before this returns.
					return err
				}
				return fmt.Errorf("the new build %s (%s) didn't start; systemd put %s (%s) back", target.Version, target.Commit, now.Version, now.Commit)
			},
		},
		kernel.Step{
			Name: "verify", Change: "confirm the daemon runs the new build",
			Apply: func(ctx context.Context, out io.Writer) error {
				now := u.running(ctx)
				if identity(now) != identity(target) {
					return fmt.Errorf("running %s (%s), not %s (%s)", now.Version, now.Commit, target.Version, target.Commit)
				}
				// The upgrade is over: a later crash is restarted, never
				// rolled back.
				if err := os.Remove(env.Path(StagedMarker)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				fmt.Fprintf(out, "upgraded to %s (%s)\n", now.Version, now.Commit)
				return nil
			},
		},
	)
	return plan, nil
}

// identity names a build. Two builds of one commit can differ (a release
// stamp, a lane fixture), so the version is part of it.
func identity(v version.Info) string { return v.Version + "@" + v.Commit }

// probeVersion runs a candidate binary's version command and checks that
// it is a helios build for this machine.
func probeVersion(ctx context.Context, env Env, path string) (version.Info, error) {
	out, err := env.Run(ctx, path, "version", "--json")
	if err != nil {
		return version.Info{}, fmt.Errorf("%s doesn't run as helios: %w", path, err)
	}
	var info version.Info
	if err := json.Unmarshal([]byte(lastLine(out)), &info); err != nil || info.Version == "" {
		return version.Info{}, fmt.Errorf("%s doesn't report a helios version", path)
	}
	running := env.RunningVersion()
	if info.OS != running.OS || info.Arch != running.Arch {
		return version.Info{}, fmt.Errorf("%s is built for %s/%s; this machine is %s/%s", path, info.OS, info.Arch, running.OS, running.Arch)
	}
	return info, nil
}

func copyFile(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	tmp := to + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, to)
}

// RollbackScriptContent is what systemd runs when the daemon fails. It
// puts the previous binary back only when an upgrade staged the running
// one within the last ten minutes: a daemon that crashes long after its
// upgrade verified is restarted, never downgraded. It must not depend on
// the helios binary, which may be the thing that's broken.
const RollbackScriptContent = `#!/bin/sh
# Installed by bedrock. Runs when bedrock.service fails.
set -eu
lib=/usr/local/lib/bedrock
if [ -f "$lib/staged" ] && [ -f "$lib/previous" ] && [ -n "$(find "$lib/staged" -mmin -10 2>/dev/null)" ]; then
  cp "$lib/previous" /usr/local/bin/bedrock.rollback
  chmod 755 /usr/local/bin/bedrock.rollback
  mv -f /usr/local/bin/bedrock.rollback /usr/local/bin/bedrock
  rm -f "$lib/staged"
  echo "bedrock: the upgrade didn't start; put the previous binary back"
else
  find "$lib" -maxdepth 1 -name 'staged*' -mmin +10 -delete 2>/dev/null || true
  echo "bedrock: the daemon failed with no upgrade in flight; the binary stays and systemd restarts it"
fi
systemctl reset-failed bedrock.service
systemctl start bedrock.service
`
