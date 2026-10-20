// Package compat describes contracts a caller can check before changing a host.
package compat

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"filippo.io/age"
	"github.com/kylebegeman/helios/internal/version"
)

const (
	APIVersion      = 1
	ManifestVersion = 1
	StateVersion    = 1
	MinStateVersion = 0
)

// capabilities name what this build can do, for a client to check before
// asking a target to do it.
var capabilities = []string{"kernel.plan.v1", "kernel.apply.v1", "kernel.expect.v1", "operations.history.v1", "operations.output.v1", "manifest.check.v1", "remote.source.v1", "state.migrations.v1", "upgrade.checkpoint.v1", "api.errors.v1", "git.signed.v1", "release.signed.v1", "edge.origin-pull.v1"}

// Info is additive. Contract versions describe behavior, independently of the
// binary's release version. State range includes unversioned historical state.
type Info struct {
	APIVersion            int          `json:"api_version"`
	ManifestVersion       int          `json:"manifest_version"`
	StateVersion          int          `json:"state_version"`
	MinStateVersion       int          `json:"min_state_version"`
	MaxStateVersion       int          `json:"max_state_version"`
	PersistedStateVersion *int         `json:"persisted_state_version,omitempty"`
	MachineID             string       `json:"machine_id"`
	Capabilities          []string     `json:"capabilities"`
	Build                 version.Info `json:"build"`
}

// Current prefers Linux machine-id so bootstrap and later key creation keep
// the same identity. Other platforms use an existing public recipient or OS
// identity. It never creates a key, directory or state database.
func Current(keyPath string) (Info, error) {
	var id string
	var err error
	if runtime.GOOS == "linux" {
		id, err = operatingSystemID()
		if err == nil {
			id = "linux:" + strings.TrimSpace(id)
		}
	} else {
		id, err = MachineIdentity(keyPath, os.ReadFile, operatingSystemID)
	}
	if err != nil {
		return Info{}, err
	}
	return Info{
		APIVersion: APIVersion, ManifestVersion: ManifestVersion,
		StateVersion: StateVersion, MinStateVersion: MinStateVersion, MaxStateVersion: StateVersion,
		MachineID: id, Build: version.Current(),
		Capabilities: append([]string(nil), capabilities...),
	}, nil
}

// MachineIdentity uses injectable read-only sources so identity fallback can be
// checked without a dependency on the development machine.
func MachineIdentity(keyPath string, readFile func(string) ([]byte, error), osID func() (string, error)) (string, error) {
	if keyPath != "" {
		data, err := readFile(keyPath + ".pub")
		if err == nil {
			recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(data)))
			if err != nil {
				return "", fmt.Errorf("machine public recipient: %w", err)
			}
			return "age:" + recipient.String(), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("machine public recipient: %w", err)
		}
	}
	id, err := osID()
	if err != nil {
		return "", fmt.Errorf("read machine identity: %w", err)
	}
	if strings.TrimSpace(id) == "" {
		return "", errors.New("this machine has no OS identity or existing public secrets recipient")
	}
	digest := sha256.Sum256([]byte("bedrock-machine-v1\x00" + strings.TrimSpace(id)))
	return "os:" + hex.EncodeToString(digest[:]), nil
}

func operatingSystemID() (string, error) {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", err
		}
		matches := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`).FindSubmatch(out)
		if len(matches) != 2 {
			return "", errors.New("IOPlatformUUID is unavailable")
		}
		return string(matches[1]), nil
	}
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(data)) != "" {
			return string(data), nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return "", errors.New("OS machine-id is unavailable")
}

// AcceptsState refuses a candidate that cannot open the persisted schema.
func (i Info) AcceptsState(v int) error {
	if i.APIVersion != APIVersion || i.ManifestVersion != ManifestVersion {
		return fmt.Errorf("candidate contract is incompatible: API %d, manifest %d; require API %d, manifest %d", i.APIVersion, i.ManifestVersion, APIVersion, ManifestVersion)
	}
	if i.StateVersion < 0 || i.MinStateVersion < 0 || i.MaxStateVersion < i.MinStateVersion || i.StateVersion < i.MinStateVersion || i.StateVersion > i.MaxStateVersion {
		return errors.New("candidate reports an invalid state compatibility range")
	}
	if v < i.MinStateVersion || v > i.MaxStateVersion {
		return fmt.Errorf("candidate supports state versions %d..%d; this machine uses %d", i.MinStateVersion, i.MaxStateVersion, v)
	}
	// Automatic binary rollback must still be able to read state after startup.
	if i.StateVersion > StateVersion {
		return fmt.Errorf("candidate migrates state to %d beyond the running binary's supported %d; a coordinated migration is required", i.StateVersion, StateVersion)
	}
	return nil
}

// Problem retains the original error text while exposing stable machine fields.
type Problem struct {
	Error      string `json:"error"`
	Code       string `json:"code"`
	Retryable  bool   `json:"retryable"`
	APIVersion int    `json:"api_version"`
	Status     int    `json:"status,omitempty"`
}
