// Package bootstrap provisions explicitly named machines from portable profiles.
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/kylebegeman/helios/internal/host"
	"github.com/kylebegeman/helios/internal/integration"
)

const ProfileVersion = 1

const maxProfileSize = 1 << 20

var checksumPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Binary struct {
	Version string            `json:"version"`
	SHA256  map[string]string `json:"sha256"`
}
type Profile struct {
	Version      int          `json:"version"`
	Host         host.Profile `json:"host"`
	Helios       Binary       `json:"bedrock"`
	Integrations []string     `json:"integrations,omitempty"`
}

func (p Profile) Validate() error {
	if p.Version != ProfileVersion {
		return errors.New("unsupported bootstrap profile version")
	}
	if err := p.Host.Validate(); err != nil {
		return err
	}
	if p.Helios.Version == "" {
		return errors.New("profile must pin a helios version")
	}
	if len(p.Helios.SHA256) == 0 {
		return errors.New("profile must pin binary checksums")
	}
	for platform, sum := range p.Helios.SHA256 {
		if platform != "linux_amd64" && platform != "linux_arm64" {
			return errors.New("profile checksum platform must be linux_amd64 or linux_arm64")
		}
		if !checksumPattern.MatchString(sum) {
			return errors.New("profile contains an invalid SHA-256 checksum")
		}
	}
	seen := map[string]bool{}
	for _, n := range p.Integrations {
		if _, ok := integration.Lookup(n); !ok {
			return fmt.Errorf("unknown integration %q", n)
		}
		if seen[n] {
			return fmt.Errorf("integration %s repeated", n)
		}
		seen[n] = true
	}
	return nil
}
func Load(path string) (Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProfileSize+1))
	if err != nil {
		return Profile{}, err
	}
	if len(data) > maxProfileSize {
		return Profile{}, errors.New("bootstrap profile is oversized")
	}
	var p Profile
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, fmt.Errorf("bootstrap profile: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return p, errors.New("bootstrap profile is oversized or has trailing data")
	}
	return p, p.Validate()
}
func Save(path string, p Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxProfileSize {
		return errors.New("bootstrap profile is oversized")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".bootstrap-profile-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
