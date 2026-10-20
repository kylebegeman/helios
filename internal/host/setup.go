package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kylebegeman/helios/internal/cloudflare"
	"github.com/kylebegeman/helios/internal/gitdeploy"
	"github.com/kylebegeman/helios/internal/kernel"
)

// SetupKind is the operation that turns a fresh machine into a helios host,
// and brings a drifted one back. Every step is safe to run again.
const SetupKind = "host.setup"

// Setup is the Definition for SetupKind.
type Setup struct {
	Env    Env
	Socket string
	// EnsureEdge runs the web edge; nil skips it (tests).
	EnsureEdge func(ctx context.Context, out io.Writer) error
	// Routes lists the hosts the machine's apps route. Setup reads it
	// before taking the web only from Cloudflare, which a route that does
	// not go through Cloudflare's proxy cannot survive. Nil means none.
	Routes func(ctx context.Context) ([]Route, error)
	// CloudflareRanges reads the ranges Cloudflare's proxy connects from;
	// nil asks Cloudflare's public API.
	CloudflareRanges func(ctx context.Context) (cloudflare.Ranges, error)
}

// Kind implements kernel.Definition.
func (Setup) Kind() string { return SetupKind }

// Packages helios installs on every machine.
var basePackages = []string{"ca-certificates", "curl", "gnupg", "ufw", "fail2ban", "unattended-upgrades", "jq", "git"}

// Packages Docker's repository provides.
var dockerPackages = []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}

// Files helios writes. Each is complete: helios owns them.
const (
	dockerDaemonJSON = `{
  "log-driver": "json-file",
  "log-opts": {"max-size": "20m", "max-file": "5"},
  "live-restore": true
}
`
	autoUpgrades = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
`
	// Security updates install themselves; reboots wait for a maintenance
	// window, so apps come back in order and get checked.
	unattendedHelios = `Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
`
	// The journal keeps app and job logs after their containers are gone:
	// two weeks of them in at most 1G, on disk, with a rate limit loose
	// enough for a noisy app.
	journaldHelios = `[Journal]
Storage=persistent
SystemMaxUse=1G
MaxRetentionSec=14day
MaxFileSec=1day
RateLimitIntervalSec=30s
RateLimitBurst=50000
`
	sshdHelios = `# Written by bedrock host setup. Keys only.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
`
	fail2banHelios = `[sshd]
enabled = true
`
)

// RegistryImage is the local registry, pinned by digest.
const RegistryImage = "registry:3@sha256:fd374bae807c225661adfe2c0c1f9970a0b8fab1761fd7dfb91e0fd9a8748f9b"

// Plan implements kernel.Definition. It reads the machine to annotate each
// step and changes nothing.
func (s Setup) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	env := s.Env
	f := Gather(ctx, env, s.Socket)
	if !Supported(f) {
		return nil, fmt.Errorf("%s on %s isn't supported: helios needs Ubuntu 22.04 or 24.04, or Debian 12 or 13, on x86_64 or aarch64", orUnknown(f.OSName), orUnknown(f.Arch))
	}
	if !f.Privileged {
		return nil, errors.New("host setup needs root")
	}
	if !f.Systemd {
		return nil, errors.New("host setup needs systemd")
	}
	installed := installedPackages(ctx, env, append(append([]string{}, basePackages...), dockerPackages...))
	x := &setting{s: s, env: env, p: p, f: f, codename: osCodename(env), debArch: debianArch(ctx, env),
		missingBase: missing(installed, basePackages), missingDocker: missing(installed, dockerPackages)}
	if p.CloudflareOnly() {
		if err := s.checkRoutes(ctx); err != nil {
			return nil, err
		}
		ranges, err := s.fetchRanges(ctx)
		if err != nil {
			return nil, err
		}
		x.ranges = &ranges
	}

	plan := &kernel.Plan{Target: p.Hostname, Recovery: kernel.Resume}
	add := func(st kernel.Step) { plan.Steps = append(plan.Steps, st) }
	add(x.packagesStep())
	add(x.hostnameStep())
	if p.Timezone != "" {
		add(x.timezoneStep())
	}
	if p.SwapGiB > 0 {
		add(x.swapStep())
	}
	add(x.dockerStep())
	add(x.registryStep())
	// Before the edge, which reads the list when it is configured.
	add(x.rangesStep())
	add(x.edgeStep())
	add(x.securityUpdatesStep())
	add(x.journalStep())
	add(x.sshStep())
	add(x.firewallStep())
	add(x.fail2banStep())
	add(x.pushesStep())
	add(x.timeStep())
	add(x.profileStep())
	return plan, nil
}

// setting is one host setup being planned: the profile it applies, what
// the machine looked like, and each step as a method.
type setting struct {
	s                          Setup
	env                        Env
	p                          Profile
	f                          Facts
	codename, debArch          string
	missingBase, missingDocker []string
	// ranges are Cloudflare's, when the profile takes the web only from
	// Cloudflare; nil otherwise.
	ranges *cloudflareRanges
}

// checkRoutes refuses to close the web to everyone but Cloudflare while
// an app routes a host that does not go through Cloudflare's proxy.
func (s Setup) checkRoutes(ctx context.Context) error {
	if s.Routes == nil {
		return nil
	}
	routes, err := s.Routes(ctx)
	if err != nil {
		return fmt.Errorf("read the routes on this machine: %w", err)
	}
	return requireProxied(routes)
}

func (x *setting) packagesStep() kernel.Step {
	return kernel.Step{
		Name: "packages", Change: "install " + strings.Join(basePackages, ", "),
		Note: doneIf(len(x.missingBase) == 0, "all installed", "missing "+strings.Join(x.missingBase, ", ")),
		Apply: func(ctx context.Context, out io.Writer) error {
			if _, err := x.env.Run(ctx, "apt-get", "update"); err != nil {
				return err
			}
			_, err := x.env.Run(ctx, "apt-get", append([]string{"install", "-y", "--no-install-recommends"}, basePackages...)...)
			fmt.Fprintln(out, "packages present")
			return err
		},
	}
}

func (x *setting) hostnameStep() kernel.Step {
	return kernel.Step{
		Name: "hostname", Change: "set the hostname to " + x.p.Hostname,
		Note: doneIf(x.f.Hostname == x.p.Hostname, "already "+x.p.Hostname, "currently "+orUnknown(x.f.Hostname)),
		Apply: func(ctx context.Context, out io.Writer) error {
			if _, err := x.env.Run(ctx, "hostnamectl", "set-hostname", x.p.Hostname); err != nil {
				return err
			}
			return ensureHostsEntry(x.env, x.p.Hostname, out)
		},
	}
}

func (x *setting) timezoneStep() kernel.Step {
	return kernel.Step{
		Name: "timezone", Change: "set the timezone to " + x.p.Timezone,
		Note: doneIf(x.f.Timezone == x.p.Timezone, "already "+x.p.Timezone, "currently "+orUnknown(x.f.Timezone)),
		Apply: func(ctx context.Context, _ io.Writer) error {
			_, err := x.env.Run(ctx, "timedatectl", "set-timezone", x.p.Timezone)
			return err
		},
	}
}

func (x *setting) swapStep() kernel.Step {
	return kernel.Step{
		Name: "swap", Change: fmt.Sprintf("keep a %d GiB swap file", x.p.SwapGiB),
		Note: doneIf(x.f.SwapBytes > 0, "already "+gigs(x.f.SwapBytes), "none yet"),
		Apply: func(ctx context.Context, out io.Writer) error {
			return ensureSwap(ctx, x.env, x.p.SwapGiB, out)
		},
	}
}

func (x *setting) dockerStep() kernel.Step {
	return kernel.Step{
		Name: "docker", Change: "install Docker from Docker's repository, with compose and buildx",
		Note: doneIf(len(x.missingDocker) == 0 && x.f.Docker.Running, "already "+orUnknown(x.f.Docker.Version), "not installed"),
		Apply: func(ctx context.Context, out io.Writer) error {
			return ensureDocker(ctx, x.env, x.f.OSID, x.codename, x.debArch, len(x.missingDocker) > 0, out)
		},
	}
}

func (x *setting) registryStep() kernel.Step {
	return kernel.Step{
		Name: "registry", Change: "run the local image registry on 127.0.0.1:5000",
		Note: doneIf(x.f.Registry.Running, "already running", "not running"),
		Apply: func(ctx context.Context, out io.Writer) error {
			return ensureRegistry(ctx, x.env, out)
		},
	}
}

func (x *setting) edgeStep() kernel.Step {
	return kernel.Step{
		Name: "edge", Change: "run the web edge on ports 80 and 443",
		Note: doneIf(x.f.EdgeRunning, "already running", "not running"),
		Apply: func(ctx context.Context, out io.Writer) error {
			if x.s.EnsureEdge == nil {
				return nil
			}
			return x.s.EnsureEdge(ctx, out)
		},
	}
}

func (x *setting) securityUpdatesStep() kernel.Step {
	return kernel.Step{
		Name: "security-updates", Change: "install security updates automatically, without automatic reboots",
		Note: doneIf(x.f.UnattendedUpgrades, "already on", "off"),
		Apply: func(ctx context.Context, out io.Writer) error {
			if _, err := x.env.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", autoUpgrades, 0o644); err != nil {
				return err
			}
			_, err := x.env.WriteFile("/etc/apt/apt.conf.d/52bedrock-unattended", unattendedHelios, 0o644)
			return err
		},
	}
}

func (x *setting) journalStep() kernel.Step {
	return kernel.Step{
		Name: "journal", Change: "cap the system journal at 1G for 14 days",
		// Only the drop-in as setup writes it is done: an older one, such
		// as 500M kept for any age, is rewritten and journald restarted.
		Note: doneIf(x.f.JournalDropIn == journaldHelios, "already capped", journalNote(x.f)),
		Apply: func(ctx context.Context, _ io.Writer) error {
			changed, err := x.env.WriteFile("/etc/systemd/journald.conf.d/bedrock.conf", journaldHelios, 0o644)
			if err != nil || !changed {
				return err
			}
			_, err = x.env.Run(ctx, "systemctl", "restart", "systemd-journald")
			return err
		},
	}
}

// journalNote says how the journal is bounded before setup writes its
// drop-in.
func journalNote(f Facts) string {
	if f.JournalMaxUse == "" {
		return "unbounded"
	}
	return "currently capped at " + f.journalCap()
}

func (x *setting) sshStep() kernel.Step {
	return kernel.Step{
		Name: "ssh", Change: "allow only key logins over SSH",
		Note: doneIf(!x.f.SSH.PasswordAuth, "already keys only", "password logins on"),
		Apply: func(ctx context.Context, out io.Writer) error {
			return ensureSSHKeysOnly(ctx, x.env, out)
		},
	}
}

func (x *setting) firewallStep() kernel.Step {
	if x.ranges == nil {
		return kernel.Step{
			Name: "firewall", Change: "allow only ssh, 80 and 443 in",
			Note: x.firewallNote(nil, "already active"),
			Apply: func(ctx context.Context, out io.Writer) error {
				if err := ensureFirewall(ctx, x.env, out, nil); err != nil {
					return err
				}
				return removeWebGuard(ctx, x.env, out)
			},
		}
	}
	ranges := x.ranges.All()
	return kernel.Step{
		Name: "firewall", Change: "allow ssh in, and 80 and 443 only from Cloudflare, Docker's published ports included",
		Note: x.firewallNote(ranges, "already only from Cloudflare"),
		Apply: func(ctx context.Context, out io.Writer) error {
			// A deploy may have added a direct route since the plan.
			if err := x.s.checkRoutes(ctx); err != nil {
				return err
			}
			if err := ensureFirewall(ctx, x.env, out, ranges); err != nil {
				return err
			}
			return ensureWebGuard(ctx, x.env, out, ranges)
		},
	}
}

// rangesStep keeps Cloudflare's address ranges on the machine. The edge
// trusts them to say who a visitor behind Cloudflare's proxy is, on every
// machine, and a machine that takes the web only from Cloudflare lets only
// them in. A machine open to anyone reads the list as it applies and
// carries on without it; one closed to all but Cloudflare read it for the
// plan and cannot.
func (x *setting) rangesStep() kernel.Step {
	step := kernel.Step{
		Name: "cloudflare-ranges", Change: "keep Cloudflare's address ranges at " + RangesPath + ", which the edge trusts to name visitors behind its proxy",
	}
	if x.ranges != nil {
		step.Note = doneIf(x.ranges.fresh, "read from Cloudflare", "Cloudflare's list could not be read, so the copy kept is used")
		step.Apply = func(_ context.Context, out io.Writer) error {
			if !x.ranges.fresh {
				fmt.Fprintln(out, "kept the copy already here")
				return nil
			}
			if err := saveRanges(x.env, x.ranges.Ranges); err != nil {
				return err
			}
			fmt.Fprintf(out, "kept %d range(s)\n", len(x.ranges.All()))
			return nil
		}
		return step
	}
	step.Note = doneIf(x.env.Exists(RangesPath), "a copy is kept", "none kept yet")
	step.Apply = func(ctx context.Context, out io.Writer) error {
		ranges, err := x.s.fetchRanges(ctx)
		switch {
		case err != nil:
			fmt.Fprintf(out, "Cloudflare's list could not be read, so visitors behind its proxy show as Cloudflare's addresses until a later setup reads it: %v\n", err)
		case !ranges.fresh:
			fmt.Fprintln(out, "Cloudflare's list could not be read; kept the copy already here")
		default:
			if err := saveRanges(x.env, ranges.Ranges); err != nil {
				return err
			}
			fmt.Fprintf(out, "kept %d range(s)\n", len(ranges.All()))
		}
		return nil
	}
	return step
}

// firewallNote says how far the firewall is from what the profile asks.
func (x *setting) firewallNote(ranges []string, done string) string {
	f := x.f
	switch {
	case firewallDone(f, ranges):
		return done
	case !f.Firewall.Active:
		return "inactive"
	case ranges != nil && f.WebOpen():
		return "the web is open to anyone"
	case ranges != nil && !f.Firewall.WebGuard.InPlace():
		return "Docker's published web ports are open to anyone"
	case ranges != nil:
		return "Cloudflare's ranges changed"
	case len(f.CloudflareSources()) > 0 || f.Firewall.WebGuard.Present():
		return "the web is open only to Cloudflare"
	default:
		return "ssh, 80 or 443 not allowed"
	}
}

func (x *setting) fail2banStep() kernel.Step {
	return kernel.Step{
		Name: "fail2ban", Change: "ban repeated SSH failures",
		Note: doneIf(x.f.Fail2ban, "already active", "inactive"),
		Apply: func(ctx context.Context, _ io.Writer) error {
			if _, err := x.env.WriteFile("/etc/fail2ban/jail.d/bedrock.conf", fail2banHelios, 0o644); err != nil {
				return err
			}
			if _, err := x.env.Run(ctx, "systemctl", "enable", "--now", "fail2ban"); err != nil {
				return err
			}
			_, err := x.env.Run(ctx, "systemctl", "restart", "fail2ban")
			return err
		},
	}
}

func (x *setting) pushesStep() kernel.Step {
	return kernel.Step{
		Name: "pushes", Change: "keep the bedrock user, which receives git pushes; each of its keys deploys only the apps it names",
		Note: doneIf(x.f.PushUser, "already there", "no bedrock user yet"),
		Apply: func(ctx context.Context, out io.Writer) error {
			return ensurePushUser(ctx, x.env, x.s.Socket, out)
		},
	}
}

func (x *setting) timeStep() kernel.Step {
	return kernel.Step{
		Name: "time", Change: "keep the clock synchronized",
		Note: doneIf(x.f.TimeSynced, "already synchronized", "not synchronized"),
		Apply: func(ctx context.Context, _ io.Writer) error {
			_, err := x.env.Run(ctx, "systemctl", "enable", "--now", "systemd-timesyncd")
			return err
		},
	}
}

func (x *setting) profileStep() kernel.Step {
	return kernel.Step{
		Name: "profile", Change: "record the profile at " + ProfilePath,
		Apply: func(_ context.Context, _ io.Writer) error { return SaveProfile(x.env, x.p) },
	}
}

func doneIf(done bool, yes, no string) string {
	if done {
		return yes
	}
	return no
}

func osCodename(env Env) string {
	release, _ := env.ReadFile("/etc/os-release")
	return parseKeyValues(release)["VERSION_CODENAME"]
}

func debianArch(ctx context.Context, env Env) string {
	out, err := env.Run(ctx, "dpkg", "--print-architecture")
	if err != nil {
		return "amd64"
	}
	return strings.TrimSpace(out)
}

// installedPackages asks dpkg which of the packages are installed.
func installedPackages(ctx context.Context, env Env, packages []string) map[string]bool {
	installed := map[string]bool{}
	out, _ := env.Run(ctx, "dpkg-query", append([]string{"-W", "-f", "${binary:Package} ${Status}\n"}, packages...)...)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[len(fields)-1] == "installed" {
			installed[strings.SplitN(fields[0], ":", 2)[0]] = true
		}
	}
	return installed
}

func missing(installed map[string]bool, wanted []string) []string {
	var out []string
	for _, p := range wanted {
		if !installed[p] {
			out = append(out, p)
		}
	}
	return out
}

func ensureHostsEntry(env Env, hostname string, out io.Writer) error {
	hosts, _ := env.ReadFile("/etc/hosts")
	for _, line := range strings.Split(hosts, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "127.0.1.1" && fields[1] == hostname {
			return nil
		}
	}
	var kept []string
	for _, line := range strings.Split(strings.TrimRight(hosts, "\n"), "\n") {
		if fields := strings.Fields(line); len(fields) >= 1 && fields[0] == "127.0.1.1" {
			continue
		}
		kept = append(kept, line)
	}
	kept = append(kept, "127.0.1.1 "+hostname)
	if _, err := env.WriteFile("/etc/hosts", strings.Join(kept, "\n")+"\n", 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "hosts entry for %s\n", hostname)
	return nil
}

func ensureSwap(ctx context.Context, env Env, gib int, out io.Writer) error {
	if active, _ := env.Run(ctx, "swapon", "--show=SIZE", "--noheadings", "--bytes"); strings.TrimSpace(active) != "" {
		fmt.Fprintln(out, "swap already active")
		if env.Exists("/swapfile") {
			return persistSwap(env)
		}
		return nil
	}
	if !env.Exists("/swapfile") {
		if _, err := env.Run(ctx, "fallocate", "-l", fmt.Sprintf("%dG", gib), "/swapfile"); err != nil {
			return err
		}
	}
	for _, args := range [][]string{{"chmod", "600", "/swapfile"}, {"mkswap", "/swapfile"}, {"swapon", "/swapfile"}} {
		if _, err := env.Run(ctx, args[0], args[1:]...); err != nil {
			return err
		}
	}
	if err := persistSwap(env); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d GiB swap file active\n", gib)
	return nil
}

func persistSwap(env Env) error {
	fstab, err := env.ReadFile("/etc/fstab")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "/swapfile" && fields[2] == "swap" {
			return nil
		}
	}
	_, err = env.WriteFile("/etc/fstab", strings.TrimRight(fstab, "\n")+"\n/swapfile none swap sw 0 0\n", 0o644)
	return err
}

func ensureDocker(ctx context.Context, env Env, osID, codename, debArch string, install bool, out io.Writer) error {
	if install {
		if _, err := env.Run(ctx, "install", "-m", "0755", "-d", "/etc/apt/keyrings"); err != nil {
			return err
		}
		if _, err := env.Run(ctx, "curl", "-fsSL", "https://download.docker.com/linux/"+osID+"/gpg", "-o", "/etc/apt/keyrings/docker.asc"); err != nil {
			return err
		}
		if _, err := env.Run(ctx, "chmod", "a+r", "/etc/apt/keyrings/docker.asc"); err != nil {
			return err
		}
		list := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n", debArch, osID, codename)
		if _, err := env.WriteFile("/etc/apt/sources.list.d/docker.list", list, 0o644); err != nil {
			return err
		}
		if _, err := env.Run(ctx, "apt-get", "update"); err != nil {
			return err
		}
		if _, err := env.Run(ctx, "apt-get", append([]string{"install", "-y"}, dockerPackages...)...); err != nil {
			return err
		}
		fmt.Fprintln(out, "docker installed")
	}
	changed, err := env.WriteFile("/etc/docker/daemon.json", dockerDaemonJSON, 0o644)
	if err != nil {
		return err
	}
	if _, err := env.Run(ctx, "systemctl", "enable", "--now", "docker"); err != nil {
		return err
	}
	if changed {
		if _, err := env.Run(ctx, "systemctl", "restart", "docker"); err != nil {
			return err
		}
		fmt.Fprintln(out, "docker configured: bounded logs, live restore")
	}
	return nil
}

func ensureRegistry(ctx context.Context, env Env, out io.Writer) error {
	state, err := env.Run(ctx, "docker", "inspect", "-f", "{{.State.Running}}", RegistryContainer)
	switch {
	case err == nil && strings.TrimSpace(state) == "true":
		return nil
	case err == nil:
		_, err := env.Run(ctx, "docker", "start", RegistryContainer)
		return err
	}
	_, err = env.Run(ctx, "docker", "run", "-d", "--name", RegistryContainer, "--restart", "unless-stopped",
		"--label", "bedrock.owner=bedrock", "-p", "127.0.0.1:5000:5000", "-v", "bedrock-registry:/var/lib/registry",
		"-e", "REGISTRY_STORAGE_DELETE_ENABLED=true", RegistryImage)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "registry started")
	return nil
}

// SSHDropIn is helios's sshd configuration. sshd keeps the first value it
// reads and reads sshd_config.d in name order, so the name sorts before
// anything cloud-init or an image leaves there.
const SSHDropIn = "/etc/ssh/sshd_config.d/00-bedrock.conf"

// ensureSSHKeysOnly turns password logins off, but never before root has a
// key to get back in with.
func ensureSSHKeysOnly(ctx context.Context, env Env, out io.Writer) error {
	keys, _ := env.ReadFile("/root/.ssh/authorized_keys")
	if authorizedKeyCount(keys) == 0 {
		return errors.New("root has no SSH key in /root/.ssh/authorized_keys; turning passwords off would lock you out")
	}
	changed, err := env.WriteFile(SSHDropIn, sshdHelios, 0o644)
	if err != nil {
		return err
	}
	// An earlier helios wrote a name that lost to cloud-init's drop-in.
	if stale := env.Path("/etc/ssh/sshd_config.d/50-bedrock.conf"); env.Exists("/etc/ssh/sshd_config.d/50-bedrock.conf") {
		_ = os.Remove(stale)
		changed = true
	}
	if !changed {
		return nil
	}
	if _, err := env.Run(ctx, "sshd", "-t"); err != nil {
		return fmt.Errorf("sshd rejected the new config: %w", err)
	}
	if _, err := env.Run(ctx, "systemctl", "reload", "ssh"); err != nil {
		if _, err2 := env.Run(ctx, "systemctl", "reload", "sshd"); err2 != nil {
			return err
		}
	}
	fmt.Fprintln(out, "password logins off")
	return nil
}

// ensurePushUser keeps the system user pushes arrive as: no password, a
// home that only it and root read, and a key file helios writes.
func ensurePushUser(ctx context.Context, env Env, socket string, out io.Writer) error {
	if _, err := env.Run(ctx, "id", "-u", gitdeploy.User); err != nil {
		if _, err := env.Run(ctx, "useradd", "--system", "--user-group", "--create-home", "--home-dir", gitdeploy.Home, "--shell", "/bin/sh", "--comment", "helios receives git pushes", gitdeploy.User); err != nil {
			return err
		}
		fmt.Fprintln(out, "bedrock user made")
	}
	for dir, mode := range map[string]string{gitdeploy.Home: "0750", gitdeploy.Home + "/.ssh": "0700", gitdeploy.BuildsDir: "0750"} {
		if _, err := env.Run(ctx, "install", "-d", "-o", gitdeploy.User, "-g", gitdeploy.User, "-m", mode, dir); err != nil {
			return err
		}
	}
	if !env.Exists(gitdeploy.AuthorizedKeys) {
		if _, err := env.Run(ctx, "install", "-o", gitdeploy.User, "-g", gitdeploy.User, "-m", "0600", "/dev/null", gitdeploy.AuthorizedKeys); err != nil {
			return err
		}
	}
	// The signing policy is root's to write and the push hook's to read,
	// in /etc/bedrock, which helios otherwise keeps to root: the group may
	// pass through it, and list nothing.
	for _, args := range [][]string{{"install", "-d", "-o", "root", "-g", gitdeploy.User, "-m", "0750", gitdeploy.SigningDir}, {"chgrp", gitdeploy.User, filepath.Dir(gitdeploy.SigningDir)}, {"chmod", "g=x", filepath.Dir(gitdeploy.SigningDir)}} {
		if _, err := env.Run(ctx, args[0], args[1:]...); err != nil {
			return err
		}
	}
	// A push asks the daemon to deploy through its socket, which the
	// daemon shares with the helios group when it starts; one already
	// running is given to the group here.
	if socket != "" && env.Exists(socket) {
		for _, args := range [][]string{{"chgrp", gitdeploy.User, filepath.Dir(socket)}, {"chmod", "0750", filepath.Dir(socket)}, {"chgrp", gitdeploy.User, socket}} {
			if _, err := env.Run(ctx, args[0], args[1:]...); err != nil {
				return err
			}
		}
	}
	return nil
}
