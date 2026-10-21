package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kylebegeman/helios/internal/version"
)

// fakeMachine answers commands from a table and keeps files under a temp
// root, recording every command that runs.
type fakeMachine struct {
	t       *testing.T
	root    string
	answers map[string]string // "name args..." -> output; missing means the command fails
	mu      sync.Mutex
	ran     []string
}

func newFakeMachine(t *testing.T) *fakeMachine {
	t.Helper()
	return &fakeMachine{t: t, root: t.TempDir(), answers: map[string]string{}}
}

func (m *fakeMachine) env() Env {
	return Env{Run: m.run, Root: m.root, Privileged: true,
		Reboot: func(context.Context) error {
			m.mu.Lock()
			m.ran = append(m.ran, "reboot")
			m.mu.Unlock()
			return os.Remove(filepath.Join(m.root, "/var/run/reboot-required"))
		},
		RunningVersion: m.runningVersion,
	}
}

func (m *fakeMachine) runningVersion() version.Info {
	return version.Info{Version: "0.7.0-test", Commit: "aaaaaaaaaaaa", OS: "linux", Arch: "amd64"}
}

func (m *fakeMachine) run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	m.mu.Lock()
	m.ran = append(m.ran, key)
	m.mu.Unlock()
	if out, ok := m.answers[key]; ok {
		return out, nil
	}
	// Prefix answers let a test cover a family of commands.
	for k, out := range m.answers {
		if !strings.HasSuffix(k, "*") {
			continue
		}
		prefix := strings.TrimSpace(strings.TrimSuffix(k, "*"))
		if key == prefix || strings.HasPrefix(key, prefix+" ") {
			return out, nil
		}
	}
	return "", errors.New(key + ": not on this machine")
}

func (m *fakeMachine) write(path, content string) {
	m.t.Helper()
	full := filepath.Join(m.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		m.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		m.t.Fatal(err)
	}
}

func (m *fakeMachine) read(path string) string {
	m.t.Helper()
	b, err := os.ReadFile(filepath.Join(m.root, path))
	if err != nil {
		return ""
	}
	return string(b)
}

func (m *fakeMachine) commands() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.ran...)
}

func (m *fakeMachine) ranCommand(prefix string) bool {
	for _, c := range m.commands() {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// freshUbuntu is a box as Hostinger hands it over: nothing installed.
func freshUbuntu(t *testing.T) *fakeMachine {
	t.Helper()
	m := newFakeMachine(t)
	m.write("/etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nPRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\n")
	m.write("/proc/meminfo", "MemTotal:       16384000 kB\n")
	m.write("/run/systemd/system/.keep", "")
	m.write("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA test\n")
	m.answers["uname -m"] = "x86_64"
	m.answers["hostname"] = "srv1614602"
	m.answers["nproc"] = "4"
	m.answers["df -Pk /"] = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 200000000 9000000 190000000 5% /\n"
	m.answers["swapon --show=SIZE --noheadings --bytes"] = ""
	m.answers["ufw status"] = "Status: inactive"
	m.answers["sshd -T"] = "passwordauthentication yes\npermitrootlogin yes\n"
	m.answers["apt-get -s -o Debug::NoLocking=true upgrade"] = "Inst libc6 [2.39-0ubuntu8.4] (2.39-0ubuntu8.5)\nInst openssl\nConf libc6\n"
	m.answers["timedatectl show -p NTPSynchronized --value"] = "yes"
	m.answers["timedatectl show -p Timezone --value"] = "Etc/UTC"
	return m
}

// setUpBox is a machine after helios host setup.
func setUpBox(t *testing.T) *fakeMachine {
	t.Helper()
	m := freshUbuntu(t)
	m.answers["hostname"] = "personal-vps"
	m.answers["swapon --show=SIZE --noheadings --bytes"] = "4294967296"
	m.answers["docker --version"] = "Docker version 29.5.2, build abc"
	m.answers["docker version --format {{.Server.Version}}"] = "29.5.2"
	m.answers["docker compose version"] = "Docker Compose version v2.40.0"
	m.answers["docker buildx version"] = "github.com/docker/buildx v0.30.0"
	m.answers["docker inspect -f {{.State.Running}} "+RegistryContainer] = "true"
	m.answers["docker inspect -f {{.State.Running}} bedrock-edge"] = "true"
	m.answers["ufw status"] = "Status: active\n\nTo                         Action      From\n--                         ------      ----\nOpenSSH                    ALLOW       Anywhere\n80/tcp                     ALLOW       Anywhere\n443/tcp                    ALLOW       Anywhere\nOpenSSH (v6)               ALLOW       Anywhere (v6)\n"
	m.answers["sshd -T"] = "passwordauthentication no\npermitrootlogin prohibit-password\n"
	m.answers["apt-get -s -o Debug::NoLocking=true upgrade"] = "Reading package lists...\n"
	m.answers["systemctl is-active fail2ban"] = "active"
	m.write("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
	m.write("/etc/systemd/journald.conf.d/bedrock.conf", journaldHelios)
	return m
}
