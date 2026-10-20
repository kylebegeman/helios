package host

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

func profileJSON(t *testing.T, p Profile) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// allowEverything makes every mutating command succeed on the fake machine.
func allowEverything(m *fakeMachine) {
	for _, prefix := range []string{"apt-get", "hostnamectl", "timedatectl set-timezone", "fallocate", "chmod", "mkswap", "swapon /swapfile", "install", "curl", "systemctl", "docker run", "docker start", "sshd -t", "ufw", "dpkg --print-architecture", "useradd", "chgrp", "sh"} {
		m.answers[prefix+" *"] = ""
	}
	m.answers["dpkg --print-architecture"] = "amd64"
}

func planSteps(t *testing.T, m *fakeMachine, p Profile) (*kernel.PlanView, map[string]string) {
	t.Helper()
	engine := kernel.New(openStore(t), registryWith(m), "test")
	view, err := engine.PlanOnly(context.Background(), SetupKind, profileJSON(t, p))
	if err != nil {
		t.Fatal(err)
	}
	notes := map[string]string{}
	for _, st := range view.Steps {
		notes[st.Name] = st.Note
	}
	return view, notes
}

func openStore(t *testing.T) *state.Store {
	t.Helper()
	s, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func registryWith(m *fakeMachine) kernel.Registry {
	reg := kernel.Registry{}
	// Cloudflare's list is never fetched from a test.
	reg.Add(Setup{Env: m.env(), CloudflareRanges: rangesFrom(testRanges, nil)})
	return reg
}

func TestSetupPlansEveryStepAndSaysWhatEachWillChange(t *testing.T) {
	m := freshUbuntu(t)
	allowEverything(m)
	view, notes := planSteps(t, m, Profile{Hostname: "personal-vps", SwapGiB: 4})
	want := []string{"packages", "hostname", "swap", "docker", "registry", "cloudflare-ranges", "edge", "security-updates", "journal", "ssh", "firewall", "fail2ban", "pushes", "time", "profile"}
	var got []string
	for _, st := range view.Steps {
		got = append(got, st.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("steps %v, want %v", got, want)
	}
	for name, note := range map[string]string{"hostname": "currently srv1614602", "swap": "none yet", "docker": "not installed", "registry": "not running", "ssh": "password logins on", "firewall": "inactive", "pushes": "no bedrock user yet", "cloudflare-ranges": "none kept yet"} {
		if notes[name] != note {
			t.Errorf("%s note %q, want %q", name, notes[name], note)
		}
	}
	if !strings.HasPrefix(notes["packages"], "missing ") {
		t.Errorf("packages note %q", notes["packages"])
	}
	// Planning read the machine and changed nothing.
	if m.ranCommand("apt-get install") || m.ranCommand("ufw allow") || m.ranCommand("ufw --force") || m.read(ProfilePath) != "" || m.read(RangesPath) != "" {
		t.Fatalf("planning changed the machine: %v", m.commands())
	}
	// The same input plans to the same digest, notes aside.
	again, _ := planSteps(t, m, Profile{Hostname: "personal-vps", SwapGiB: 4})
	if again.Digest != view.Digest {
		t.Fatal("plan digest must not depend on what the machine looks like")
	}
}

func TestSetupAppliesInASafeOrderOnAFreshBox(t *testing.T) {
	m := freshUbuntu(t)
	allowEverything(m)
	engine := kernel.New(openStore(t), registryWith(m), "test")
	receipt, err := engine.Run(context.Background(), SetupKind, profileJSON(t, Profile{Hostname: "personal-vps", SwapGiB: 4, Timezone: "America/New_York"}), func(kernel.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Succeeded {
		t.Fatalf("receipt: %+v", receipt)
	}
	cmds := m.commands()
	index := func(prefix string) int {
		for i, c := range cmds {
			if strings.HasPrefix(c, prefix) {
				return i
			}
		}
		t.Fatalf("never ran %q in %v", prefix, cmds)
		return -1
	}
	// Docker comes from Docker's repository, and the registry after it.
	if index("curl -fsSL https://download.docker.com/linux/ubuntu/gpg") > index("apt-get install -y docker-ce") || index("apt-get install -y docker-ce") > index("docker run -d --name bedrock-registry") {
		t.Fatalf("docker order: %v", cmds)
	}
	if !strings.Contains(m.read("/etc/apt/sources.list.d/docker.list"), "https://download.docker.com/linux/ubuntu noble stable") {
		t.Fatalf("docker.list: %q", m.read("/etc/apt/sources.list.d/docker.list"))
	}
	// SSH is allowed through the firewall before it is enabled.
	if index("ufw allow OpenSSH") > index("ufw --force enable") || index("ufw default deny incoming") > index("ufw --force enable") {
		t.Fatalf("firewall order: %v", cmds)
	}
	// Files helios owns exist with the expected content.
	for path, want := range map[string]string{
		"/etc/docker/daemon.json":                   `"live-restore": true`,
		"/etc/ssh/sshd_config.d/00-bedrock.conf":    "PasswordAuthentication no",
		"/etc/systemd/journald.conf.d/bedrock.conf": "SystemMaxUse=1G\nMaxRetentionSec=14day",
		"/etc/apt/apt.conf.d/20auto-upgrades":       `Unattended-Upgrade "1"`,
		"/etc/apt/apt.conf.d/52bedrock-unattended":  `Automatic-Reboot "false"`,
		"/etc/fail2ban/jail.d/bedrock.conf":         "[sshd]",
		"/etc/hosts":                                "127.0.1.1 personal-vps",
		"/etc/fstab":                                "/swapfile none swap sw 0 0",
		ProfilePath:                                 `"hostname": "personal-vps"`,
	} {
		if !strings.Contains(m.read(path), want) {
			t.Errorf("%s: want %q in %q", path, want, m.read(path))
		}
	}
	index("hostnamectl set-hostname personal-vps")
	index("timedatectl set-timezone America/New_York")
	index("fallocate -l 4G /swapfile")
	index("sshd -t")
	index("useradd --system --user-group --create-home --home-dir /var/lib/bedrock-git --shell /bin/sh")
	index("install -o bedrock -g bedrock -m 0600 /dev/null /var/lib/bedrock-git/.ssh/authorized_keys")
	p, err := LoadProfile(m.env())
	if err != nil || p.Hostname != "personal-vps" || p.SwapGiB != 4 {
		t.Fatalf("profile: %v %+v", err, p)
	}
}

func TestSetupOnASetUpBoxChangesNothingHeavy(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.answers["dpkg-query *"] = "ca-certificates install ok installed\ncurl install ok installed\ngnupg install ok installed\nufw install ok installed\nfail2ban install ok installed\nunattended-upgrades install ok installed\njq install ok installed\ngit install ok installed\ndocker-ce install ok installed\ndocker-ce-cli install ok installed\ncontainerd.io install ok installed\ndocker-buildx-plugin install ok installed\ndocker-compose-plugin install ok installed\n"
	m.write("/etc/docker/daemon.json", dockerDaemonJSON)
	m.write(SSHDropIn, sshdHelios)
	m.write("/etc/hosts", "127.0.0.1 localhost\n127.0.1.1 personal-vps\n")
	_, notes := planSteps(t, m, Profile{Hostname: "personal-vps", SwapGiB: 4})
	for name, note := range map[string]string{"packages": "all installed", "hostname": "already personal-vps", "swap": "already 4.0 GiB", "docker": "already 29.5.2", "registry": "already running", "ssh": "already keys only", "firewall": "already active", "fail2ban": "already active", "journal": "already capped", "security-updates": "already on"} {
		if notes[name] != note {
			t.Errorf("%s note %q, want %q", name, notes[name], note)
		}
	}
	engine := kernel.New(openStore(t), registryWith(m), "test")
	receipt, err := engine.Run(context.Background(), SetupKind, profileJSON(t, Profile{Hostname: "personal-vps", SwapGiB: 4}), func(kernel.Event) {})
	if err != nil || receipt.Status != state.Succeeded {
		t.Fatalf("%v %+v", err, receipt)
	}
	for _, heavy := range []string{"apt-get install -y docker-ce", "curl", "docker run", "fallocate", "mkswap", "systemctl restart docker", "systemctl restart systemd-journald", "sshd -t"} {
		if m.ranCommand(heavy) {
			t.Errorf("reconcile ran %q on a box that didn't need it", heavy)
		}
	}
}

// A machine set up before the journal kept logs for two weeks has the
// older drop-in. Setup rewrites it and restarts journald once, then
// leaves both alone.
func TestSetupMovesAnOlderJournalCapAndRestartsJournaldOnce(t *testing.T) {
	m := setUpBox(t)
	allowEverything(m)
	m.write("/etc/systemd/journald.conf.d/bedrock.conf", "[Journal]\nSystemMaxUse=500M\n")
	restarts := func() int {
		n := 0
		for _, c := range m.commands() {
			if c == "systemctl restart systemd-journald" {
				n++
			}
		}
		return n
	}
	engine := kernel.New(openStore(t), registryWith(m), "test")
	for i, note := range []string{"currently capped at 500M", "already capped"} {
		if _, notes := planSteps(t, m, Profile{Hostname: "personal-vps", SwapGiB: 4}); notes["journal"] != note {
			t.Fatalf("setup %d: journal note %q, want %q", i+1, notes["journal"], note)
		}
		receipt, err := engine.Run(context.Background(), SetupKind, profileJSON(t, Profile{Hostname: "personal-vps", SwapGiB: 4}), func(kernel.Event) {})
		if err != nil || receipt.Status != state.Succeeded {
			t.Fatalf("setup %d: %v %+v", i+1, err, receipt)
		}
		if got := m.read("/etc/systemd/journald.conf.d/bedrock.conf"); got != journaldHelios {
			t.Fatalf("setup %d left the drop-in as %q", i+1, got)
		}
		if restarts() != 1 {
			t.Fatalf("setup %d: journald restarted %d times in all, want once", i+1, restarts())
		}
	}
}

func TestSetupRefusesToLockYouOut(t *testing.T) {
	m := freshUbuntu(t)
	allowEverything(m)
	m.write("/root/.ssh/authorized_keys", "\n")
	engine := kernel.New(openStore(t), registryWith(m), "test")
	receipt, err := engine.Run(context.Background(), SetupKind, profileJSON(t, Profile{Hostname: "personal-vps"}), func(kernel.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Failed || !strings.Contains(receipt.Error, "lock you out") {
		t.Fatalf("receipt: %+v", receipt)
	}
	if m.read(SSHDropIn) != "" {
		t.Fatal("the sshd drop-in must not be written without a root key")
	}
}

func TestSetupRefusesUnsupportedMachines(t *testing.T) {
	m := freshUbuntu(t)
	m.write("/etc/os-release", "ID=fedora\nVERSION_ID=42\nPRETTY_NAME=\"Fedora 42\"\n")
	engine := kernel.New(openStore(t), registryWith(m), "test")
	if _, err := engine.PlanOnly(context.Background(), SetupKind, profileJSON(t, Profile{Hostname: "x"})); err == nil || !strings.Contains(err.Error(), "isn't supported") {
		t.Fatalf("want an unsupported error, got %v", err)
	}
	if _, err := engine.PlanOnly(context.Background(), SetupKind, profileJSON(t, Profile{Hostname: "Not Valid"})); err == nil {
		t.Fatal("want a hostname error")
	}
}

func TestSwapReconcilePersistsAnAlreadyActiveManagedFile(t *testing.T) {
	m := setUpBox(t)
	m.write("/swapfile", "owned swap fixture")
	m.write("/etc/fstab", "# /swapfile needs to be kept after reboot\n")
	if err := ensureSwap(context.Background(), m.env(), 4, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.read("/etc/fstab"), "\n/swapfile none swap sw 0 0\n") {
		t.Fatalf("active swap was not persisted: %q", m.read("/etc/fstab"))
	}
	if m.ranCommand("mkswap") || m.ranCommand("swapon /swapfile") {
		t.Fatalf("reconcile reformatted running swap: %v", m.commands())
	}
}
func TestSSHRefusesCommentOnlyAuthorizedKeys(t *testing.T) {
	m := freshUbuntu(t)
	allowEverything(m)
	m.write("/root/.ssh/authorized_keys", "# add an SSH key here\n   # no keys yet\n")
	if err := ensureSSHKeysOnly(context.Background(), m.env(), io.Discard); err == nil || !strings.Contains(err.Error(), "lock you out") {
		t.Fatalf("comment-only keys: %v", err)
	}
	if m.read(SSHDropIn) != "" {
		t.Fatal("SSH was changed without a usable key entry")
	}
}
