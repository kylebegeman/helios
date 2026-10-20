package host

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
)

// Facts is what helios knows about the machine after looking, without
// changing anything.
type Facts struct {
	OSID      string `json:"os_id"`
	OSVersion string `json:"os_version"`
	OSName    string `json:"os_name"`
	Arch      string `json:"arch"`
	Hostname  string `json:"hostname"`
	CPUs      int    `json:"cpus"`
	// MemoryBytes and DiskFreeBytes are the machine's memory and the space
	// free on the root filesystem.
	MemoryBytes   uint64 `json:"memory_bytes"`
	DiskFreeBytes uint64 `json:"disk_free_bytes"`
	SwapBytes     uint64 `json:"swap_bytes"`
	Privileged    bool   `json:"privileged"`
	Systemd       bool   `json:"systemd"`

	Docker struct {
		Installed bool   `json:"installed"`
		Running   bool   `json:"running"`
		Version   string `json:"version,omitempty"`
		Compose   bool   `json:"compose"`
		Buildx    bool   `json:"buildx"`
	} `json:"docker"`
	Firewall FirewallFacts `json:"firewall"`
	// WebFrom is who the machine's profile lets reach 80 and 443; empty
	// when the machine has no profile.
	WebFrom string `json:"web_from,omitempty"`
	SSH     struct {
		PasswordAuth bool   `json:"password_auth"`
		RootLogin    string `json:"root_login"`
		RootKeys     int    `json:"root_keys"`
	} `json:"ssh"`
	RebootRequired     bool   `json:"reboot_required"`
	UpdatesPending     int    `json:"updates_pending"`
	TimeSynced         bool   `json:"time_synced"`
	Timezone           string `json:"timezone,omitempty"`
	UnattendedUpgrades bool   `json:"unattended_upgrades"`
	// JournalMaxUse and JournalMaxRetention are how big and how old
	// helios's journald drop-in lets the journal grow; JournalDropIn is the
	// drop-in itself, which setup rewrites unless it is exactly its own.
	JournalMaxUse       string `json:"journal_max_use,omitempty"`
	JournalMaxRetention string `json:"journal_max_retention,omitempty"`
	JournalDropIn       string `json:"-"`
	Fail2ban            bool   `json:"fail2ban"`
	Registry            struct {
		Present bool `json:"present"`
		Running bool `json:"running"`
	} `json:"registry"`
	// Published are the ports apps publish on the machine's public
	// addresses, which Docker opens whatever ufw says.
	Published []PublishedPort `json:"published,omitempty"`
	// Data are the volumes app workloads mount writable, and what in each
	// the workload's user can't write.
	Data          []DataAccess `json:"data,omitempty"`
	EdgeRunning   bool         `json:"edge_running"`
	DaemonAnswers bool         `json:"daemon_answers"`
	// PushUser is whether the bedrock user, which receives pushes, exists.
	PushUser bool `json:"push_user"`
}

// FirewallFacts are what ufw says.
type FirewallFacts struct {
	Installed bool `json:"installed"`
	Active    bool `json:"active"`
	// Allowed are the ports anyone may reach over IPv4.
	Allowed []string `json:"allowed,omitempty"`
	// Rules are every rule ufw lists, sources included.
	Rules []FirewallRule `json:"rules,omitempty"`
	// IPv6 is whether ufw filters IPv6 too.
	IPv6 bool `json:"ipv6"`
	// WebGuard is what stands between Docker's published web ports and
	// the internet, which ufw's rules do not reach.
	WebGuard WebGuard `json:"web_guard"`
}

// PublishedPort is a port an app's container publishes on the machine.
type PublishedPort struct {
	// Port is the machine's port and protocol, such as 3478/udp.
	Port string `json:"port"`
	// Container is the container that publishes it.
	Container string `json:"container,omitempty"`
	// App and Workload are whose it is. Helios's own containers, such
	// as the edge, have no workload.
	App      string `json:"app"`
	Workload string `json:"workload"`
}

// DataAccess is one volume a running workload mounts writable, walked for
// the files and directories its user can't write.
type DataAccess struct {
	App       string `json:"app"`
	Workload  string `json:"workload"`
	Container string `json:"container"`
	// User is who the workload runs as, uid:gid.
	User string `json:"user"`
	// Volume is the manifest's name for it; Source is where it lives on
	// the machine.
	Volume string `json:"volume"`
	Source string `json:"source"`
	// Unwritable is what the walk found; Error is set when it couldn't walk.
	Unwritable docker.Unwritable `json:"unwritable"`
	Error      string            `json:"error,omitempty"`
}

// Whose names what publishes the port, the way the doctor reads: the edge
// or the registry for helios's own, an app's workload for the rest, and
// the app or the container alone when a label is missing.
func (p PublishedPort) Whose() string {
	switch {
	case p.Container == edge.Container:
		return "the edge"
	case p.Container == RegistryContainer:
		return "the registry"
	case p.App != "" && p.Workload != "":
		return p.App + "'s " + p.Workload
	case p.App != "":
		return p.App
	case p.Container != "":
		return p.Container
	}
	return "a container"
}

// RegistryContainer is the local image registry every build lands in.
const RegistryContainer = "bedrock-registry"

// Gather looks at the machine. Every probe tolerates its command being
// missing; the facts just stay zero.
func Gather(ctx context.Context, env Env, socket string) Facts {
	var f Facts
	f.gatherSystem(ctx, env)
	f.gatherDocker(ctx, env)
	f.gatherFirewall(ctx, env)
	f.gatherSSH(ctx, env)
	f.gatherUpkeep(ctx, env, socket)
	return f
}

// gatherSystem reads what the machine is: its system, size and swap.
func (f *Facts) gatherSystem(ctx context.Context, env Env) {
	f.Privileged = env.Privileged
	f.Systemd = env.Exists("/run/systemd/system")
	if release, err := env.ReadFile("/etc/os-release"); err == nil {
		kv := parseKeyValues(release)
		f.OSID, f.OSVersion, f.OSName = kv["ID"], kv["VERSION_ID"], kv["PRETTY_NAME"]
	}
	f.Arch, _ = env.Run(ctx, "uname", "-m")
	f.Hostname, _ = env.Run(ctx, "hostname")
	if out, err := env.Run(ctx, "nproc"); err == nil {
		f.CPUs, _ = strconv.Atoi(strings.TrimSpace(out))
	}
	if meminfo, err := env.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(meminfo, "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, _ := strconv.ParseUint(fields[1], 10, 64)
					f.MemoryBytes = kb * 1024
				}
			}
		}
	}
	if out, err := env.Run(ctx, "df", "-Pk", "/"); err == nil {
		lines := strings.Split(out, "\n")
		if len(lines) >= 2 {
			if fields := strings.Fields(lines[1]); len(fields) >= 4 {
				kb, _ := strconv.ParseUint(fields[3], 10, 64)
				f.DiskFreeBytes = kb * 1024
			}
		}
	}
	if out, err := env.Run(ctx, "swapon", "--show=SIZE", "--noheadings", "--bytes"); err == nil {
		for _, line := range strings.Fields(out) {
			n, _ := strconv.ParseUint(line, 10, 64)
			f.SwapBytes += n
		}
	}
}

// gatherDocker reads Docker, the registry and the edge.
func (f *Facts) gatherDocker(ctx context.Context, env Env) {
	if _, err := env.Run(ctx, "docker", "--version"); err == nil {
		f.Docker.Installed = true
		if v, err := env.Run(ctx, "docker", "version", "--format", "{{.Server.Version}}"); err == nil && v != "" {
			f.Docker.Running, f.Docker.Version = true, v
		}
		_, err := env.Run(ctx, "docker", "compose", "version")
		f.Docker.Compose = err == nil
		_, err = env.Run(ctx, "docker", "buildx", "version")
		f.Docker.Buildx = err == nil
		if state, err := env.Run(ctx, "docker", "inspect", "-f", "{{.State.Running}}", RegistryContainer); err == nil {
			f.Registry.Present = true
			f.Registry.Running = strings.TrimSpace(state) == "true"
		}
		if state, err := env.Run(ctx, "docker", "inspect", "-f", "{{.State.Running}}", edge.Container); err == nil {
			f.EdgeRunning = strings.TrimSpace(state) == "true"
		}
		if out, err := env.Run(ctx, "docker", "ps", "--filter", "label=bedrock.app", "--format", publishedFormat); err == nil {
			f.Published = parsePublished(out)
		}
		f.Data = gatherData(ctx, env)
	}
}

// gatherFirewall reads ufw's rules and who the profile lets reach the web.
func (f *Facts) gatherFirewall(ctx context.Context, env Env) {
	if out, err := env.Run(ctx, "ufw", "status"); err == nil {
		f.Firewall.Installed = true
		f.Firewall.Active = strings.Contains(out, "Status: active")
		f.Firewall.Rules = parseUFW(out)
		f.Firewall.Allowed = openPorts(f.Firewall.Rules)
		f.Firewall.IPv6 = ufwIPv6(env)
	}
	f.Firewall.WebGuard = gatherWebGuard(ctx, env)
	if p, err := LoadProfile(env); err == nil {
		f.WebFrom = p.WebFrom
		if f.WebFrom == "" {
			f.WebFrom = WebFromAnyone
		}
	}
}

// gatherSSH reads how the machine takes SSH logins.
func (f *Facts) gatherSSH(ctx context.Context, env Env) {
	if out, err := env.Run(ctx, "sshd", "-T"); err == nil {
		kv := parseSSHDConfig(out)
		f.SSH.PasswordAuth = kv["passwordauthentication"] != "no"
		f.SSH.RootLogin = kv["permitrootlogin"]
	}
	if keys, err := env.ReadFile("/root/.ssh/authorized_keys"); err == nil {
		f.SSH.RootKeys = authorizedKeyCount(keys)
	}
}

func authorizedKeyCount(keys string) int {
	count := 0
	for _, line := range strings.Split(keys, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			count++
		}
	}
	return count
}

// gatherUpkeep reads updates, time, logs, the push user, fail2ban and
// whether the daemon answers on its socket.
func (f *Facts) gatherUpkeep(ctx context.Context, env Env, socket string) {
	f.RebootRequired = env.Exists("/var/run/reboot-required")
	f.UpdatesPending = -1
	if out, err := env.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"); err == nil {
		f.UpdatesPending = 0
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Inst ") {
				f.UpdatesPending++
			}
		}
	}
	if out, err := env.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
		f.TimeSynced = strings.TrimSpace(out) == "yes"
	}
	f.Timezone, _ = env.Run(ctx, "timedatectl", "show", "-p", "Timezone", "--value")
	if conf, err := env.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		f.UnattendedUpgrades = strings.Contains(conf, `Unattended-Upgrade "1"`)
	}
	if conf, err := env.ReadFile("/etc/systemd/journald.conf.d/bedrock.conf"); err == nil {
		kv := parseKeyValues(conf)
		f.JournalMaxUse, f.JournalMaxRetention, f.JournalDropIn = kv["SystemMaxUse"], kv["MaxRetentionSec"], conf
	}
	if _, err := env.Run(ctx, "id", "-u", "bedrock"); err == nil {
		f.PushUser = true
	}
	if out, err := env.Run(ctx, "systemctl", "is-active", "fail2ban"); err == nil {
		f.Fail2ban = strings.TrimSpace(out) == "active"
	}
	if socket != "" {
		if conn, err := net.DialTimeout("unix", socket, time.Second); err == nil {
			conn.Close()
			f.DaemonAnswers = true
		}
	}
}

// publishedFormat is what docker ps prints for each app container: its
// name, whose it is, and its ports as Docker writes them, such as
// "0.0.0.0:3478->3478/udp, [::]:3478->3478/udp".
const publishedFormat = "{{.Names}}\t{{.Label \"bedrock.app\"}}\t{{.Label \"bedrock.workload\"}}\t{{.Ports}}"

// parsePublished reads the ports app containers publish, once each however
// many addresses they are bound to. A port bound only to the loopback
// address is not reachable from outside and is left out, as is one the
// image exposes without publishing.
func parsePublished(text string) []PublishedPort {
	var out []PublishedPort
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			continue
		}
		name, app, workload := fields[0], fields[1], fields[2]
		for _, binding := range strings.Split(fields[3], ", ") {
			host, container, ok := strings.Cut(strings.TrimSpace(binding), "->")
			if !ok {
				continue
			}
			i := strings.LastIndex(host, ":")
			if i < 0 {
				continue
			}
			address := strings.Trim(host[:i], "[]")
			if ip := net.ParseIP(address); ip != nil && ip.IsLoopback() {
				continue
			}
			_, proto, _ := strings.Cut(container, "/")
			port := host[i+1:] + "/" + proto
			key := name + " " + port
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, PublishedPort{Port: port, Container: name, App: app, Workload: workload})
		}
	}
	return out
}

// dataFormat is what docker inspect says about each app container: its
// name, app, workload and user, then each named volume it mounts.
const dataFormat = "{{.Name}}\t{{index .Config.Labels \"bedrock.app\"}}\t{{index .Config.Labels \"bedrock.workload\"}}\t{{.Config.User}}" +
	"{{range .Mounts}}{{if eq .Type \"volume\"}}\t{{.Name}}={{.Source}}={{.RW}}{{end}}{{end}}"

// gatherData walks the volumes each running app workload mounts writable,
// as the workload's user. Root, a user helios didn't set, helios's own
// containers and a drill's scratch copies are left out.
func gatherData(ctx context.Context, env Env) []DataAccess {
	names, err := env.Run(ctx, "docker", "ps", "--filter", "label=bedrock.app", "--format", "{{.Names}}")
	if err != nil || strings.TrimSpace(names) == "" {
		return nil
	}
	out, err := env.Run(ctx, "docker", append([]string{"inspect", "--format", dataFormat}, strings.Fields(names)...)...)
	if err != nil {
		return nil
	}
	data := parseData(out)
	for i := range data {
		u, _ := docker.ParseUser(data[i].User)
		x, err := docker.UnwritableBy(filepath.Join(env.Root, data[i].Source), u)
		if err != nil {
			data[i].Error = err.Error()
			continue
		}
		data[i].Unwritable = x
	}
	return data
}

// parseData reads dataFormat lines into one entry per writable volume.
func parseData(text string) []DataAccess {
	var out []DataAccess
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 4 {
			continue
		}
		name, app, workload, user := strings.TrimPrefix(fields[0], "/"), fields[1], fields[2], fields[3]
		u, ok := docker.ParseUser(user)
		if !ok || u.Root() || workload == "" || workload == "drill" || strings.Contains(name, ".drill") {
			continue
		}
		for _, mount := range fields[4:] {
			parts := strings.Split(mount, "=")
			if len(parts) != 3 || parts[2] != "true" || parts[1] == "" {
				continue
			}
			out = append(out, DataAccess{App: app, Workload: workload, Container: name, User: u.Spec(),
				Volume: docker.AppVolume(app, parts[0]), Source: parts[1]})
		}
	}
	return out
}

// parseKeyValues reads KEY=value lines, unquoting values.
func parseKeyValues(text string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return kv
}

func parseSSHDConfig(text string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			kv[strings.ToLower(k)] = strings.TrimSpace(v)
		}
	}
	return kv
}

// Allows reports whether the firewall allows a port such as "22/tcp",
// including through a named application profile like OpenSSH.
func (f Facts) Allows(port string) bool {
	for _, rule := range f.Firewall.Allowed {
		// A rule without a protocol, such as 3478, allows both.
		number, _, _ := strings.Cut(port, "/")
		if rule == port || (port == "22/tcp" && (rule == "OpenSSH" || rule == "22")) || rule == number {
			return true
		}
	}
	return false
}

// journalCap is how far the journal may grow, as "1G for 14day", or as
// "500M" when the drop-in bounds only its size.
func (f Facts) journalCap() string {
	if f.JournalMaxRetention == "" {
		return f.JournalMaxUse
	}
	return f.JournalMaxUse + " for " + f.JournalMaxRetention
}

// Addresses returns the machine's public addresses, the ones DNS should
// point at: what has global scope and isn't private, carrier-grade NAT
// (100.64/10) or the machine's own.
func Addresses(ctx context.Context, env Env) []string {
	out, err := env.Run(ctx, "ip", "-o", "addr", "show", "scope", "global")
	if err != nil {
		return nil
	}
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || (fields[2] != "inet" && fields[2] != "inet6") {
			continue
		}
		addr, err := netip.ParseAddr(strings.SplitN(fields[3], "/", 2)[0])
		if err != nil || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || carrierNAT.Contains(addr) {
			continue
		}
		addrs = append(addrs, addr.String())
	}
	return addrs
}

// carrierNAT is the range a provider's NAT hands out: reachable by no one
// outside, however global its scope.
var carrierNAT = netip.MustParsePrefix("100.64.0.0/10")
