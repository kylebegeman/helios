package host

import (
	"fmt"
	"strings"

	"github.com/kylebegeman/helios/internal/docker"
)

// Verdict is how a check came out.
type Verdict string

const (
	Pass Verdict = "pass"
	Warn Verdict = "warn"
	Fail Verdict = "fail"
)

// Result is one check's outcome, with the fix when there is one.
type Result struct {
	Name    string  `json:"name"`
	Verdict Verdict `json:"verdict"`
	Detail  string  `json:"detail"`
	Fix     string  `json:"fix,omitempty"`
}

const (
	gib = 1 << 30
	gb  = 1_000_000_000
)

var supportedSystems = map[string][]string{
	"ubuntu": {"22.04", "24.04"},
	"debian": {"12", "13"},
}

// Supported reports whether helios runs on this OS and architecture.
func Supported(f Facts) bool {
	if f.Arch != "x86_64" && f.Arch != "aarch64" {
		return false
	}
	for _, v := range supportedSystems[f.OSID] {
		if v == f.OSVersion {
			return true
		}
	}
	return false
}

// Diagnose turns facts into verdicts. Fails block setup or mean something
// is broken; warns are worth fixing.
func Diagnose(f Facts) []Result {
	var out []Result
	for _, check := range []func(Facts) []Result{diagnoseSystem, diagnoseResources, diagnoseServices, diagnoseData, diagnoseAccess, diagnoseUpkeep} {
		out = append(out, check(f)...)
	}
	return out
}

// runSetup is the fix for most of what setup would have done.
const runSetup = "run helios host setup"

// results collects verdicts in the order they are added.
type results []Result

func (r *results) add(name string, v Verdict, detail, fix string) {
	*r = append(*r, Result{Name: name, Verdict: v, Detail: detail, Fix: fix})
}

func diagnoseSystem(f Facts) []Result {
	var r results
	if Supported(f) {
		r.add("system", Pass, fmt.Sprintf("%s on %s", f.OSName, f.Arch), "")
	} else {
		r.add("system", Fail, fmt.Sprintf("%s on %s", orUnknown(f.OSName), orUnknown(f.Arch)), "helios needs Ubuntu 22.04 or 24.04, or Debian 12 or 13, on x86_64 or aarch64")
	}
	if !f.Systemd {
		r.add("systemd", Fail, "not running", "helios's daemon needs systemd")
	} else {
		r.add("systemd", Pass, "running", "")
	}
	if !f.Privileged {
		r.add("privileges", Warn, "not root", "setup and the daemon need root")
	} else {
		r.add("privileges", Pass, "root", "")
	}
	return r
}

func diagnoseResources(f Facts) []Result {
	var r results
	switch {
	case f.CPUs < 2:
		r.add("cpu", Fail, fmt.Sprintf("%d cpu", f.CPUs), "helios needs at least 2")
	case f.CPUs < 4:
		r.add("cpu", Warn, fmt.Sprintf("%d cpus", f.CPUs), "builds are slow below 4")
	default:
		r.add("cpu", Pass, fmt.Sprintf("%d cpus", f.CPUs), "")
	}
	switch {
	case f.MemoryBytes < 2*gib:
		r.add("memory", Fail, gigs(f.MemoryBytes), "helios needs at least 2 GiB")
	case f.MemoryBytes < 8*gib:
		r.add("memory", Warn, gigs(f.MemoryBytes), "apps and builds share memory; 8 GiB or more is comfortable")
	default:
		r.add("memory", Pass, gigs(f.MemoryBytes), "")
	}
	switch {
	case f.DiskFreeBytes < 5*gb:
		r.add("disk", Fail, gigs(f.DiskFreeBytes)+" free", "less than 5 GB free; free space or run helios gc")
	case f.DiskFreeBytes < 20*gb:
		r.add("disk", Warn, gigs(f.DiskFreeBytes)+" free", "less than 20 GB free; images and backups need room")
	default:
		r.add("disk", Pass, gigs(f.DiskFreeBytes)+" free", "")
	}
	if f.SwapBytes == 0 {
		r.add("swap", Warn, "none", runSetup+" adds a swap file")
	} else {
		r.add("swap", Pass, gigs(f.SwapBytes), "")
	}
	return r
}

func diagnoseServices(f Facts) []Result {
	var r results
	switch {
	case !f.Docker.Installed:
		r.add("docker", Fail, "not installed", runSetup)
	case !f.Docker.Running:
		r.add("docker", Fail, "installed but not running", "systemctl start docker")
	case !f.Docker.Compose || !f.Docker.Buildx:
		r.add("docker", Warn, "running, plugins missing", runSetup+" installs compose and buildx")
	default:
		r.add("docker", Pass, "running, "+f.Docker.Version, "")
	}
	switch {
	case !f.Registry.Present:
		r.add("registry", Fail, "no local image registry", runSetup)
	case !f.Registry.Running:
		r.add("registry", Fail, "registry container stopped", "docker start "+RegistryContainer)
	default:
		r.add("registry", Pass, "running on 127.0.0.1:5000", "")
	}
	if f.Docker.Running {
		if f.EdgeRunning {
			r.add("edge", Pass, "running on 80 and 443", "")
		} else {
			r.add("edge", Fail, "not running", runSetup)
		}
	}
	return r
}

// diagnoseData fails each volume holding files its workload can't write:
// the app answers, but can't save. The fix gives them to the workload's
// user and restarts it; the doctor changes nothing itself.
func diagnoseData(f Facts) []Result {
	if len(f.Data) == 0 {
		return nil
	}
	var r results
	clean := 0
	for _, d := range f.Data {
		name := "data " + d.App + "/" + d.Volume
		switch {
		case d.Error != "":
			r.add(name, Warn, "couldn't walk it: "+d.Error, "")
		case d.Unwritable.Count > 0:
			u, _ := docker.ParseUser(d.User)
			r.add(name, Fail, d.Unwritable.Problem(d.App+"'s "+d.Workload, u, d.Volume),
				fmt.Sprintf("chown -R %s %s, then docker restart %s", d.User, d.Source, d.Container))
		default:
			clean++
		}
	}
	if clean > 0 {
		r.add("data", Pass, fmt.Sprintf("%d volume(s) writable by the workloads that mount them", clean), "")
	}
	return r
}

func diagnoseAccess(f Facts) []Result {
	r := results{diagnoseFirewall(f)}
	r = append(r, diagnosePublished(f)...)
	switch {
	case f.SSH.PasswordAuth && f.SSH.RootKeys == 0:
		r.add("ssh", Fail, "password login on, root has no key", "add a key to /root/.ssh/authorized_keys, then "+runSetup)
	case f.SSH.PasswordAuth:
		r.add("ssh", Fail, "password login on", runSetup+" turns it off")
	case f.SSH.RootKeys == 0:
		r.add("ssh", Warn, "key-only, but root has no key", "add a key to /root/.ssh/authorized_keys")
	default:
		r.add("ssh", Pass, fmt.Sprintf("key-only, %d root key(s)", f.SSH.RootKeys), "")
	}
	if !f.Fail2ban {
		r.add("fail2ban", Warn, "not active", runSetup)
	} else {
		r.add("fail2ban", Pass, "active", "")
	}
	return r
}

// diagnoseFirewall checks ufw against the profile: ssh always, and the web
// open to anyone or only to Cloudflare, as the machine was set up.
func diagnoseFirewall(f Facts) Result {
	const reconcile = "helios host reconcile"
	result := func(v Verdict, detail, fix string) Result {
		return Result{Name: "firewall", Verdict: v, Detail: detail, Fix: fix}
	}
	switch {
	case !f.Firewall.Installed:
		return result(Fail, "ufw not installed", runSetup)
	case !f.Firewall.Active:
		return result(Fail, "ufw inactive", runSetup)
	case !f.Allows("22/tcp"):
		return result(Fail, "active without ssh allowed", "ufw allow OpenSSH, before anything else")
	case f.CloudflareOnly() && f.WebOpen():
		return result(Fail, "the web is open to anyone, though this machine takes it only from Cloudflare", reconcile)
	case f.CloudflareOnly() && len(f.CloudflareSources()) == 0:
		return result(Fail, "80 and 443 are closed to Cloudflare too", reconcile)
	case f.CloudflareOnly() && !f.Firewall.WebGuard.InPlace():
		return result(Fail, "Docker forwards 80 and 443 past ufw, and helios's guard for them is not in place, so the edge answers anyone", reconcile)
	case f.CloudflareOnly() && !f.Firewall.IPv6:
		return result(Warn, "ufw leaves IPv6 alone (IPV6=no), so the web ports are not filtered there", "set IPV6=yes in "+ufwDefaults+", then "+reconcile)
	case f.CloudflareOnly():
		return result(Pass, fmt.Sprintf("active: ssh; 80 and 443 only from Cloudflare (%d ranges)", len(f.CloudflareSources())), "")
	case f.Firewall.WebGuard.Present():
		return result(Warn, "the edge takes the web only from Cloudflare, though this machine is set up to take it from anyone", reconcile)
	case !f.Allows("80/tcp") || !f.Allows("443/tcp"):
		return result(Warn, "active, web ports closed", runSetup+" opens 80 and 443")
	default:
		return result(Pass, "active: ssh, 80, 443", "")
	}
}

// diagnosePublished lists every port an app publishes on a public address
// against ufw. Docker opens a published port itself, ahead of ufw's rules,
// so anyone can reach it whatever ufw says; a rule open to anyone is how
// ufw status comes to say so. A rule for only some sources reads as open
// to them alone, which is not what happens, so it is no pass. And on a
// machine that takes the web only from Cloudflare, helios's guard holds
// 80 and 443 alone: a published port is outside it, and the doctor says so.
func diagnosePublished(f Facts) []Result {
	var r results
	guard := ""
	if f.CloudflareOnly() {
		guard = "; the Cloudflare-only guard covers 80 and 443 alone, not this port"
	}
	for _, p := range f.Published {
		name := "port " + p.Port
		whose := "published by " + p.Whose()
		allow := "ufw allow " + p.Port + ", so the firewall says what is open; Docker publishes it either way"
		open, sources := f.PortSources(p.Port)
		switch {
		case open:
			r.add(name, Pass, whose+", open to anyone, as ufw says"+guard, "")
		case len(sources) > 0:
			r.add(name, Warn, fmt.Sprintf("%s to anyone past ufw, which allows it only from %s", whose, strings.Join(sources, ", "))+guard,
				allow+". ufw can't narrow a port Docker publishes; to keep it off the internet, publish it on a private address (ports[].address)")
		default:
			r.add(name, Warn, whose+" to anyone past ufw, which has no rule for it"+guard, allow)
		}
	}
	return r
}

func diagnoseUpkeep(f Facts) []Result {
	var r results
	switch {
	case f.RebootRequired:
		r.add("updates", Warn, "a reboot is pending", "helios host maintain")
	case f.UpdatesPending > 0:
		r.add("updates", Warn, fmt.Sprintf("%d package(s) can be upgraded", f.UpdatesPending), "helios host maintain")
	case f.UpdatesPending < 0:
		r.add("updates", Warn, "unknown", "apt-get didn't answer")
	default:
		r.add("updates", Pass, "up to date", "")
	}
	if !f.UnattendedUpgrades {
		r.add("security updates", Warn, "automatic security updates off", runSetup)
	} else {
		r.add("security updates", Pass, "automatic", "")
	}
	if !f.TimeSynced {
		r.add("time", Warn, "clock not synchronized", "systemctl restart systemd-timesyncd")
	} else {
		r.add("time", Pass, "synchronized"+tz(f.Timezone), "")
	}
	if f.JournalMaxUse == "" {
		r.add("logs", Warn, "journal unbounded", runSetup+" caps it")
	} else {
		r.add("logs", Pass, "journal capped at "+f.journalCap(), "")
	}
	if f.Systemd {
		if !f.DaemonAnswers {
			r.add("daemon", Fail, "not answering", "helios daemon install")
		} else {
			r.add("daemon", Pass, "answering", "")
		}
	}
	return r
}

// Worst returns the worst verdict in a set.
func Worst(results []Result) Verdict {
	worst := Pass
	for _, r := range results {
		if r.Verdict == Fail {
			return Fail
		}
		if r.Verdict == Warn {
			worst = Warn
		}
	}
	return worst
}

func gigs(b uint64) string {
	return fmt.Sprintf("%.1f GiB", float64(b)/gib)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func tz(z string) string {
	if z == "" {
		return ""
	}
	return ", " + z
}
