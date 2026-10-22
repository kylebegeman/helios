package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"
)

// Profile is what a machine is set up to be. It is the input of host.setup
// and is kept on the machine so reconcile can re-apply it.
type Profile struct {
	Hostname string `json:"hostname"`
	// SwapGiB is the swap file to keep, in GiB. Zero keeps none.
	SwapGiB int `json:"swap_gib"`
	// Timezone is an IANA name such as America/New_York. Empty leaves the
	// machine's setting alone.
	Timezone string `json:"timezone,omitempty"`
	// WebFrom is who may reach 80 and 443: WebFromAnyone (empty means the
	// same) or WebFromCloudflare.
	WebFrom string `json:"web_from,omitempty"`
}

// CloudflareOnly reports whether the machine takes the web only from
// Cloudflare's proxy.
func (p Profile) CloudflareOnly() bool { return p.WebFrom == WebFromCloudflare }

// ProfilePath is where the profile lives on the machine.
const ProfilePath = "/etc/bedrock/host.json"

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate checks a profile before it is planned.
func (p Profile) Validate() error {
	if !hostnamePattern.MatchString(p.Hostname) {
		return fmt.Errorf("hostname %q must be lowercase letters, digits and hyphens", p.Hostname)
	}
	if p.SwapGiB < 0 || p.SwapGiB > 64 {
		return errors.New("swap must be 0 to 64 GiB")
	}
	if p.Timezone != "" {
		if _, err := time.LoadLocation(p.Timezone); err != nil || p.Timezone == "Local" {
			return fmt.Errorf("timezone %q is not a known IANA timezone", p.Timezone)
		}
	}
	switch p.WebFrom {
	case "", WebFromAnyone, WebFromCloudflare:
	default:
		return fmt.Errorf("web from %q: it is %s or %s", p.WebFrom, WebFromAnyone, WebFromCloudflare)
	}
	return nil
}

// LoadProfile reads the machine's profile; ErrNoProfile when it has none.
func LoadProfile(env Env) (Profile, error) {
	text, err := env.ReadFile(ProfilePath)
	if errors.Is(err, os.ErrNotExist) {
		return Profile{}, ErrNoProfile
	}
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", ProfilePath, err)
	}
	return p, nil
}

// ErrNoProfile means the machine was never set up.
var ErrNoProfile = errors.New("this machine has no profile yet: run helios host setup")

// SaveProfile writes the profile where reconcile finds it.
func SaveProfile(env Env, p Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	_, err = env.WriteFile(ProfilePath, string(b)+"\n", 0o644)
	return err
}
