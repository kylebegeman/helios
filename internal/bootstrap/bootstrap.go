package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/kylebegeman/helios/internal/compat"
	"github.com/kylebegeman/helios/internal/host"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/release"
	"github.com/kylebegeman/helios/internal/remote"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/version"
)

const Kind = "client.bootstrap"

const maxRemoteResponse = 1 << 20

// Keep the buffer named so io.Copy cannot bypass Write through a promoted ReadFrom.
type boundedResponse struct {
	buffer *bytes.Buffer
}

func (b *boundedResponse) Write(p []byte) (int, error) {
	if len(p) > maxRemoteResponse-b.buffer.Len() {
		return 0, errors.New("remote structured response is too large")
	}
	return b.buffer.Write(p)
}

type Facts struct {
	MachineID string
	Arch      string
	OS        string
	OSVersion string
	Root      bool
	Systemd   bool
}
type Input struct {
	TargetName     string        `json:"target_name"`
	Target         remote.Target `json:"target"`
	Profile        Profile       `json:"profile"`
	Arch           string        `json:"arch"`
	BinaryPath     string        `json:"binary_path,omitempty"`
	SecretsVersion int           `json:"secrets_version,omitempty"`
	SecretsSHA256  string        `json:"secrets_sha256,omitempty"`
}
type Definition struct {
	Transport remote.Transport
	Secrets   *secrets.Store
	CacheDir  string
	Probe     func(context.Context, remote.Target) (Facts, error)
	Fetch     func(context.Context, string, string, string, string, string) (string, error)
}

func (Definition) Kind() string { return Kind }

// Probe uses only OS facts over the already pinned SSH connection.
func Probe(ctx context.Context, tr remote.Transport, t remote.Target) (Facts, error) {
	var out bytes.Buffer
	script := `set -eu
. /etc/os-release
printf '%s\n' "$(cat /etc/machine-id)" "$(uname -m)" "$ID" "$VERSION_ID" "$(id -u)" "$(cat /proc/1/comm)"`
	if t.Sudo {
		script = "sudo -n -- sh -c " + remote.Quote(script)
	}
	if err := tr.RunScript(ctx, t, script, nil, &boundedResponse{buffer: &out}, io.Discard); err != nil {
		return Facts{}, fmt.Errorf("target OS preflight: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 {
		return Facts{}, errors.New("target returned incomplete OS facts")
	}
	arch := ""
	switch lines[1] {
	case "aarch64":
		arch = "arm64"
	case "x86_64":
		arch = "amd64"
	}
	return Facts{MachineID: "linux:" + lines[0], Arch: arch, OS: lines[2], OSVersion: lines[3], Root: lines[4] == "0", Systemd: lines[5] == "systemd"}, nil
}
func (d Definition) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if !remote.ValidName(in.TargetName) {
		return nil, errors.New("invalid bootstrap target name")
	}
	if err := in.Target.Validate(); err != nil {
		return nil, err
	}
	if err := in.Profile.Validate(); err != nil {
		return nil, err
	}
	probe := d.Probe
	if probe == nil {
		probe = func(ctx context.Context, t remote.Target) (Facts, error) { return Probe(ctx, d.Transport, t) }
	}
	facts, err := probe(ctx, in.Target)
	if err != nil {
		return nil, err
	}
	if !facts.Root || !facts.Systemd || facts.Arch == "" {
		return nil, errors.New("bootstrap requires privileged SSH, systemd and Linux amd64/arm64")
	}
	supported := facts.OS == "ubuntu" && (facts.OSVersion == "22.04" || facts.OSVersion == "24.04") || facts.OS == "debian" && (facts.OSVersion == "12" || facts.OSVersion == "13")
	if !supported {
		return nil, errors.New("bootstrap supports Ubuntu 22.04/24.04 and Debian 12/13")
	}
	if in.Target.MachineID == "" || facts.MachineID != in.Target.MachineID || facts.Arch != in.Arch {
		return nil, errors.New("bootstrap target identity or architecture changed; prepare a new plan")
	}
	checksum := in.Profile.Helios.SHA256["linux_"+facts.Arch]
	if !checksumPattern.MatchString(checksum) {
		return nil, fmt.Errorf("profile has no checksum for linux_%s", facts.Arch)
	}
	if in.BinaryPath != "" {
		if err := verifyFile(in.BinaryPath, checksum); err != nil {
			return nil, err
		}
	} else if err := release.CheckVersion(in.Profile.Helios.Version); err != nil {
		return nil, err
	}
	if len(in.Profile.Integrations) > 0 {
		if d.Secrets == nil {
			return nil, errors.New("bootstrap integration source unavailable")
		}
		if err := integration.ValidateVersion(d.Secrets, in.Profile.Integrations, in.SecretsVersion); err != nil {
			return nil, err
		}
		digest, err := d.Secrets.SealedVersionSHA256(integration.App, in.SecretsVersion)
		if err != nil {
			return nil, err
		}
		if !checksumPattern.MatchString(in.SecretsSHA256) || digest != in.SecretsSHA256 {
			return nil, errors.New("bootstrap integration source changed or lacks a pinned ciphertext identity; prepare a new plan with the original source store")
		}
	}
	command := func(ctx context.Context, args []string, input io.Reader, out io.Writer) error {
		return d.Transport.Run(ctx, in.Target, args, input, out, out)
	}
	plan := &kernel.Plan{Target: in.TargetName, Recovery: kernel.Resume}
	add := func(name, change string, apply func(context.Context, io.Writer) error) {
		plan.Steps = append(plan.Steps, kernel.Step{Name: name, Change: change, Apply: apply})
	}
	add("install", fmt.Sprintf("install helios %s SHA-256 %s on %s (%s, linux_%s)", in.Profile.Helios.Version, checksum, in.Target.SSH, in.Target.MachineID, in.Arch)+"; connection "+(remote.Binding{Target: in.Target}).ScopeDigest("bootstrap"), func(ctx context.Context, out io.Writer) error {
		path := in.BinaryPath
		if path == "" {
			if err := os.MkdirAll(d.CacheDir, 0o700); err != nil {
				return err
			}
			fetch := d.Fetch
			if fetch == nil {
				// The profile pins the checksum, so the build installs
				// whether or not its release is signed.
				fetch = func(ctx context.Context, version, dir, sum, goos, goarch string) (string, error) {
					d, err := release.FetchPlatform(ctx, version, dir, sum, goos, goarch)
					return d.Path, err
				}
			}
			var err error
			path, err = fetch(ctx, in.Profile.Helios.Version, d.CacheDir, checksum, "linux", in.Arch)
			if err != nil {
				return err
			}
		}
		if err := verifyFile(path, checksum); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		binary := in.Target.Binary
		if binary == "" {
			binary = "/usr/local/bin/bedrock"
		}
		// Existing differing installations require the upgrade workflow and its
		// state compatibility checkpoint, rather than an unconditional overwrite.
		script := `set -eu
umask 077
binary=` + remote.Quote(binary) + `
want=` + remote.Quote(checksum) + `
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/bedrock"
printf '%s  %s\n' "$want" "$work/bedrock" | sha256sum -c - >/dev/null
chmod 755 "$work/bedrock"
if test -e "$binary"; then
 test "$(sha256sum "$binary" | cut -d ' ' -f 1)" = "$want" || { printf 'Target already has a different helios build; use helios upgrade first.\n' >&2; exit 1; }
 chmod 755 "$binary"
else
 install -d "$(dirname "$binary")"
 install -m 755 "$work/bedrock" "$binary.next"
 mv "$binary.next" "$binary"
fi
printf 'Pinned binary installed and checksum verified.\n'`
		if in.Target.Sudo {
			script = "sudo -n -- sh -c " + remote.Quote(script)
		}
		return d.Transport.RunScript(ctx, in.Target, script, file, out, out)
	})
	add("capabilities", "verify installed binary compatibility and stable machine identity", func(ctx context.Context, _ io.Writer) error {
		var out bytes.Buffer
		if err := d.Transport.Run(ctx, in.Target, []string{"capabilities", "--json"}, nil, &boundedResponse{buffer: &out}, io.Discard); err != nil {
			return err
		}
		var c compat.Info
		if json.Unmarshal(out.Bytes(), &c) != nil || c.MachineID != in.Target.MachineID {
			return errors.New("installed binary capabilities or machine identity are incompatible")
		}
		// A missing database starts at the candidate's own schema version.
		// An explicit zero still identifies existing unversioned state.
		persisted := c.StateVersion
		if c.PersistedStateVersion != nil {
			persisted = *c.PersistedStateVersion
		}
		if err := c.AcceptsState(persisted); err != nil {
			return fmt.Errorf("installed binary compatibility: %w", err)
		}
		out.Reset()
		if err := d.Transport.Run(ctx, in.Target, []string{"version", "--json"}, nil, &boundedResponse{buffer: &out}, io.Discard); err != nil {
			return err
		}
		var info version.Info
		if json.Unmarshal(out.Bytes(), &info) != nil || info.Version != in.Profile.Helios.Version || info.OS != "linux" || info.Arch != in.Arch {
			return errors.New("installed binary does not match profile version and target platform")
		}
		return nil
	})
	add("identity", "create target-owned encryption identity; private key remains on target", func(ctx context.Context, out io.Writer) error {
		var public bytes.Buffer
		if err := d.Transport.Run(ctx, in.Target, []string{"secret", "recipient"}, nil, &boundedResponse{buffer: &public}, io.Discard); err != nil {
			return err
		}
		if _, err := age.ParseX25519Recipient(strings.TrimSpace(public.String())); err != nil {
			return errors.New("target returned invalid encryption recipient")
		}
		fmt.Fprintln(out, "Target encryption identity is ready; retain its root-only recovery key deliberately.")
		return nil
	})
	if len(in.Profile.Integrations) > 0 {
		add("integrations", fmt.Sprintf("transfer only %s from sealed source version %d SHA-256 %s", strings.Join(in.Profile.Integrations, ", "), in.SecretsVersion, in.SecretsSHA256), func(ctx context.Context, out io.Writer) error {
			var public bytes.Buffer
			if err := d.Transport.Run(ctx, in.Target, []string{"secret", "recipient"}, nil, &boundedResponse{buffer: &public}, io.Discard); err != nil {
				return err
			}
			digest, err := d.Secrets.SealedVersionSHA256(integration.App, in.SecretsVersion)
			if err != nil {
				return err
			}
			if digest != in.SecretsSHA256 {
				return errors.New("pinned bootstrap integration source changed")
			}
			sealed, err := integration.ExportVersion(d.Secrets, in.Profile.Integrations, strings.TrimSpace(public.String()), in.SecretsVersion)
			if err != nil {
				return err
			}
			args := append([]string{"integration", "import"}, in.Profile.Integrations...)
			return command(ctx, args, strings.NewReader(sealed), out)
		})
	}
	p := in.Profile.Host
	if p.WebFrom == "" {
		p.WebFrom = host.WebFromAnyone
	}
	add("host", fmt.Sprintf("apply host profile %s, swap %d GiB, timezone %s, web %s", p.Hostname, p.SwapGiB, p.Timezone, p.WebFrom), func(ctx context.Context, out io.Writer) error {
		args := []string{"host", "setup", "--hostname=" + p.Hostname, fmt.Sprintf("--swap=%d", p.SwapGiB), "--timezone=" + p.Timezone, "--yes"}
		if p.WebFrom != "" {
			args = append(args, "--web-from="+p.WebFrom)
		}
		return command(ctx, args, nil, out)
	})
	add("daemon", "install and verify the systemd daemon", func(ctx context.Context, out io.Writer) error {
		return command(ctx, []string{"daemon", "install"}, nil, out)
	})
	add("verify", "verify daemon reachability and host readiness", func(ctx context.Context, out io.Writer) error {
		if err := command(ctx, []string{"daemon", "status"}, nil, out); err != nil {
			return err
		}
		return command(ctx, []string{"doctor"}, nil, out)
	})
	return plan, nil
}
func verifyFile(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(f, (256<<20)+1))
	if err != nil {
		return err
	}
	if n > 256<<20 || hex.EncodeToString(sum.Sum(nil)) != want {
		return errors.New("bootstrap binary does not match the pinned checksum")
	}
	return nil
}
