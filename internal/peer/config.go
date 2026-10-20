// Package peer lets Helios machines watch each other. A dead machine
// reports nothing about itself, so each one checks its peers and the
// healthy ones say what they saw.
//
// A machine's side of it is kept sealed in its secrets store, under
// helios's own name: the peers it watches, the key it presents to them,
// and the fingerprints of the machines allowed to read it. None of it is
// written to a repo, a manifest or a receipt.
package peer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/remote"
	"github.com/kylebegeman/helios/internal/secrets"
)

// The sealed names in helios's own secrets. The plaintext metadata lists
// only these, so peer names, addresses and URLs stay sealed.
const (
	// ListKey holds this machine and the peers it watches.
	ListKey = "PEER_LIST"
	// TokenKey holds the key this machine presents to every peer.
	TokenKey = "PEER_TOKEN"
	// ObserversKey holds the fingerprint of each machine allowed to read
	// this one, by name.
	ObserversKey = "PEER_OBSERVERS"
)

// ErrNotSet means peer watch hasn't been set up on this machine.
var ErrNotSet = errors.New("peer watch is not set up on this machine; run helios peer init --name <name>")

// Config is one machine's side of peer watch.
type Config struct {
	Self  Self   `json:"self"`
	Peers []Peer `json:"peers"`
	// Observers holds the fingerprint of each machine allowed to read
	// this one, by name. It is sealed apart from the list.
	Observers map[string]string `json:"-"`
	// Token is the key this machine presents to every peer. It is never
	// shown; its Fingerprint is what peers register.
	Token string `json:"-"`
}

// Self is this machine as its peers know it.
type Self struct {
	Name string `json:"name"`
	// Listen is where this machine answers its peers, empty when it
	// answers none, as on a Mac that only watches.
	Listen string `json:"listen,omitempty"`
	// Public are this machine's own public URLs, checked before it
	// judges a peer.
	Public []string `json:"public,omitempty"`
}

// Peer is a machine this one watches.
type Peer struct {
	Name string `json:"name"`
	// Mesh is where the peer answers on the mesh, as host:port.
	Mesh string `json:"mesh"`
	// Public are the peer's public URLs, through its edge provider.
	Public []string `json:"public"`
}

var (
	tokenPattern = regexp.MustCompile(`^hp1_[0-9a-f]{64}$`)
	keyPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// meshNamePattern is a host name the mesh's DNS answers, one label
	// or several.
	meshNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	// numericLabel is a label the system resolvers read as a number,
	// decimal, octal or hex, the way inet_aton does.
	numericLabel = regexp.MustCompile(`^([0-9]+|0[xX][0-9a-fA-F]*)$`)
)

// reservedNames name peer watch's own alerts, peer:self and
// peer:edge-provider, so no machine may take them.
var reservedNames = map[string]bool{selfName: true, edgeProviderName: true}

// meshRanges are where a listener may bind and a mesh address may point:
// loopback, and the tailnet's ranges.
var meshRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// ValidName reports whether name can name a machine to its peers: a
// target's name, lowercase letters, digits and hyphens starting with a
// letter, and not one of the names peer watch keeps for itself.
func ValidName(name string) bool { return remote.ValidName(name) && !reservedNames[name] }

// ValidKey reports whether key is a peer key's fingerprint as helios peer
// key prints it.
func ValidKey(key string) bool { return keyPattern.MatchString(key) }

// NewToken makes a key for this machine to present to its peers.
func NewToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "hp1_" + hex.EncodeToString(b[:]), nil
}

// Fingerprint is what a peer registers for a token. It is not a secret:
// it can travel on a command line, and the peer never holds the token.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ParseListen checks where this machine answers its peers: an IP address,
// never a name, so binding never waits on DNS; on the mesh or loopback,
// so never every address; and never one of the edge's ports. Errors never
// repeat the address.
func ParseListen(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, errors.New("must be an IP address and a port, not a name")
	}
	if !onMesh(ap.Addr()) {
		return netip.AddrPort{}, errors.New("must be an address on the mesh (100.64.0.0/10 or fc00::/7) or loopback")
	}
	if err := checkPort(int(ap.Port())); err != nil {
		return netip.AddrPort{}, err
	}
	return ap, nil
}

// ParseMesh checks where a peer answers on the mesh and returns it as
// host:port. The host may be a name, which the mesh's DNS resolves; an
// address must be on the mesh or loopback, and written as one, since the
// system resolvers read a name like 127.1 or 0x7f000001 as an address
// that was never checked. Errors never repeat it.
func ParseMesh(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return "", errors.New("must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", errors.New("must be host:port")
	}
	if err := checkPort(n); err != nil {
		return "", err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !onMesh(addr) {
			return "", errors.New("must be a name or an address on the mesh (100.64.0.0/10 or fc00::/7) or loopback")
		}
	} else if readsAsIPv4(host) {
		return "", errors.New("has a host that reads as an IP address; it must be written as one, on the mesh (100.64.0.0/10 or fc00::/7) or loopback")
	} else if !meshNamePattern.MatchString(host) {
		return "", errors.New("must name a host in lowercase letters, digits, hyphens and dots")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// readsAsIPv4 reports whether a resolver may take host for an IPv4
// address: one to four dot-separated labels, each a number.
func readsAsIPv4(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) > 4 {
		return false
	}
	for _, l := range labels {
		if !numericLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// ParsePublic checks a public URL: https, on a host name, with no
// credentials or fragment.
func ParsePublic(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || !manifest.ValidHost(u.Hostname()) {
		return "", errors.New("must be an https:// URL on a host name")
	}
	if u.User != nil || u.Fragment != "" {
		return "", errors.New("must not hold credentials or a fragment")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", errors.New("must have a port of 1 to 65535, or none")
		}
	}
	return u.String(), nil
}

func onMesh(addr netip.Addr) bool {
	for _, r := range meshRanges {
		if r.Contains(addr) {
			return true
		}
	}
	return false
}

// checkPort refuses the edge's ports: a peer is answered beside the edge,
// never in its place.
func checkPort(port int) error {
	switch {
	case port < 1 || port > 65535:
		return errors.New("needs a port of 1 to 65535")
	case port == 80 || port == 443:
		return errors.New("must not use port 80 or 443, which the edge serves")
	}
	return nil
}

// Validate checks a whole configuration, as it is saved and as it is read.
func (c Config) Validate() error {
	if !ValidName(c.Self.Name) {
		return errors.New("this machine has no valid peer name")
	}
	if !tokenPattern.MatchString(c.Token) {
		return errors.New("this machine's peer key is malformed")
	}
	if c.Self.Listen != "" {
		if _, err := ParseListen(c.Self.Listen); err != nil {
			return fmt.Errorf("this machine's listen address %w", err)
		}
		if len(c.Self.Public) == 0 {
			return errors.New("this machine answers peers but has no public URL to check itself by")
		}
	}
	for _, u := range c.Self.Public {
		if _, err := ParsePublic(u); err != nil {
			return fmt.Errorf("this machine's public URL %w", err)
		}
	}
	seen := map[string]bool{}
	for _, p := range c.Peers {
		if err := c.checkPeerName(p.Name); err != nil {
			return err
		}
		if seen[p.Name] {
			return fmt.Errorf("%s is listed twice", p.Name)
		}
		seen[p.Name] = true
		if _, err := ParseMesh(p.Mesh); err != nil {
			return fmt.Errorf("%s's mesh address %w", p.Name, err)
		}
		if len(p.Public) == 0 {
			return fmt.Errorf("%s has no public URL", p.Name)
		}
		for _, u := range p.Public {
			if _, err := ParsePublic(u); err != nil {
				return fmt.Errorf("%s's public URL %w", p.Name, err)
			}
		}
	}
	for name, key := range c.Observers {
		if err := c.checkPeerName(name); err != nil {
			return err
		}
		if !ValidKey(key) {
			return fmt.Errorf("%s's key is not a fingerprint", name)
		}
	}
	return nil
}

func (c Config) checkPeerName(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("%q can't name a peer", name)
	}
	if name == c.Self.Name {
		return fmt.Errorf("%s is this machine's own name", name)
	}
	return nil
}

// Load reads this machine's peer configuration. ErrNotSet when peer init
// hasn't run here.
func Load(store *secrets.Store) (Config, error) {
	values, _, err := store.LoadCurrent(manifest.ReservedApp)
	if err != nil {
		return Config{}, err
	}
	return unseal(values)
}

// unseal reads the configuration from helios's secrets.
func unseal(values map[string]string) (Config, error) {
	list, ok := values[ListKey]
	if !ok {
		return Config{}, ErrNotSet
	}
	var c Config
	if err := json.Unmarshal([]byte(list), &c); err != nil {
		return Config{}, errors.New("the sealed peer list is unreadable")
	}
	if observers, ok := values[ObserversKey]; ok {
		if err := json.Unmarshal([]byte(observers), &c.Observers); err != nil {
			return Config{}, errors.New("the sealed peer observers are unreadable")
		}
	}
	c.Token = values[TokenKey]
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("the sealed peer list: %w", err)
	}
	return c, nil
}

// Update changes this machine's peer configuration and seals it in one
// new version of helios's secrets. helios's secrets are held from the
// read to the write, so two commands at once each keep the other's
// change, and a key rotated meanwhile is never put back. Where peer
// watch isn't set up, change starts from nothing when create is set, and
// Update is ErrNotSet otherwise. The key is written only when change
// made or replaced it.
func Update(store *secrets.Store, create bool, change func(*Config) error) (Config, int, error) {
	var c Config
	version, err := store.Update(manifest.ReservedApp, func(values map[string]string) (map[string]*string, error) {
		var err error
		if c, err = unseal(values); err != nil && !(create && errors.Is(err, ErrNotSet)) {
			return nil, err
		}
		token := c.Token
		if err := change(&c); err != nil {
			return nil, err
		}
		return c.sealed(c.Token != token)
	})
	if err != nil {
		return Config{}, 0, err
	}
	return c, version, nil
}

// sealed is the configuration as the changes to helios's secrets that
// keep it: the list and the observers, and the key when withToken is set.
func (c Config) sealed(withToken bool) (map[string]*string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	list, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	listValue := string(list)
	changes := map[string]*string{ListKey: &listValue, ObserversKey: nil}
	if withToken {
		token := c.Token
		changes[TokenKey] = &token
	}
	if len(c.Observers) > 0 {
		observers, err := json.Marshal(c.Observers)
		if err != nil {
			return nil, err
		}
		observersValue := string(observers)
		changes[ObserversKey] = &observersValue
	}
	return changes, nil
}
