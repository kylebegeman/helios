package peer

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/secrets"
)

// in is the first address of a range: addresses here are made from their
// ranges, never written down.
func in(prefix string) netip.Addr { return netip.MustParsePrefix(prefix).Addr().Next() }

func at(addr netip.Addr, port uint16) string { return netip.AddrPortFrom(addr, port).String() }

// The listener binds where its peers reach it and nowhere else: an
// address on the mesh or loopback, never a name, never every address and
// never the edge's ports.
func TestListenAddressMustBeMeshOrLoopback(t *testing.T) {
	mesh := in("100.64.0.0/10")
	for _, ok := range []string{at(in("127.0.0.0/8"), 7700), at(netip.IPv6Loopback(), 7700), at(mesh, 7700), at(in("fc00::/7"), 7700)} {
		got, err := ParseListen(ok)
		if err != nil || got.String() != ok {
			t.Fatalf("%s was refused: %v", ok, err)
		}
	}
	for _, refused := range []struct{ listen, why string }{
		{"web1.example.test:7700", "not a name"},
		{mesh.String(), "not a name"},
		{"0.0.0.0:7700", "on the mesh"},
		{"[::]:7700", "on the mesh"},
		{at(in("192.0.2.0/24"), 7700), "on the mesh"},
		{at(in("2001:db8::/32"), 7700), "on the mesh"},
		{at(mesh, 80), "80 or 443"},
		{at(mesh, 443), "80 or 443"},
		{at(mesh, 0), "needs a port"},
	} {
		_, err := ParseListen(refused.listen)
		if err == nil || !strings.Contains(err.Error(), refused.why) {
			t.Fatalf("%s: got %v, want it refused as %q", refused.listen, err, refused.why)
		}
		if strings.Contains(err.Error(), refused.listen) {
			t.Fatalf("the refusal repeats the address: %v", err)
		}
	}
}

// A peer is reached at a name the mesh's DNS answers, or at an address
// on the mesh or loopback written as one. A name the system resolvers
// read as an IPv4 address, as inet_aton does, in decimal, octal or hex,
// whole or in fewer than four parts, would reach an address never
// checked, with this machine's key in the clear, so it is refused.
func TestMeshHostThatReadsAsAnAddressIsRefused(t *testing.T) {
	outside, loopback := in("192.0.2.0/24"), in("127.0.0.0/8")
	o := outside.As4()
	whole := func(addr netip.Addr, base int) string {
		return strconv.FormatUint(uint64(binary.BigEndian.Uint32(addr.AsSlice())), base)
	}
	for _, host := range []string{
		whole(outside, 10),
		"0x" + whole(outside, 16),
		"0X" + strings.ToUpper(whole(outside, 16)),
		"0" + whole(loopback, 8),
		fmt.Sprintf("%d.%d.%d.0%o", o[0], o[1], o[2], o[3]),
		fmt.Sprintf("0%o.%d.%d.%d", o[0], o[1], o[2], o[3]),
		"127.1",
		"0x",
	} {
		_, err := ParseMesh(host + ":7700")
		if err == nil || !strings.Contains(err.Error(), "reads as an IP address; it must be written as one, on the mesh") {
			t.Fatalf("%s: got %v, want it refused as an address", host, err)
		}
		if strings.Contains(err.Error(), host) {
			t.Fatalf("the refusal repeats the host: %v", err)
		}
	}
	for _, host := range []string{"web2", "web2.tailnet-name.example.test", "1password-host", "host-01", "0x-host", "10.web2.example.test"} {
		if got, err := ParseMesh(host + ":7700"); err != nil || got != host+":7700" {
			t.Fatalf("%s was refused: %v", host, err)
		}
	}
	if got, err := ParseMesh(at(loopback, 7700)); err != nil || got != at(loopback, 7700) {
		t.Fatalf("loopback written as an address was refused: %v", err)
	}
}

// keyedStore is a secrets store with its key, in the test's own
// directory.
func keyedStore(t *testing.T) *secrets.Store {
	t.Helper()
	dir := t.TempDir()
	store := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "secrets.key")}
	if _, _, _, err := store.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	return store
}

// setUp is a store where peer watch is set up as web1.
func setUp(t *testing.T) *secrets.Store {
	t.Helper()
	store := keyedStore(t)
	if _, _, err := Update(store, true, func(c *Config) error {
		var err error
		c.Self.Name = "web1"
		c.Token, err = NewToken()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

// Two peer commands at once each keep the other's change, whichever reads
// first: a peer added while the key rotates stays added, and the rotated
// key is never put back. The second waits for the first to be written.
func TestChangesAtOnceKeepEachOther(t *testing.T) {
	web2 := Peer{Name: "web2", Mesh: at(in("100.64.0.0/10"), 7700), Public: []string{"https://web2.example.test"}}
	var rotatedTo string
	add := func(c *Config) error {
		c.Peers = append(c.Peers, web2)
		return nil
	}
	rotate := func(c *Config) (err error) {
		c.Token, err = NewToken()
		rotatedTo = c.Token
		return err
	}
	for _, tc := range []struct {
		name          string
		first, second func(*Config) error
	}{
		{"a peer added while the key rotates", rotate, add},
		{"the key rotated while a peer is added", add, rotate},
	} {
		store := setUp(t)
		read, release := make(chan struct{}), make(chan struct{})
		var firstErr, secondErr error
		firstDone, secondDone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(firstDone)
			_, _, firstErr = Update(store, false, func(c *Config) error {
				close(read)
				<-release
				return tc.first(c)
			})
		}()
		<-read
		go func() {
			defer close(secondDone)
			_, _, secondErr = Update(store, false, tc.second)
		}()
		select {
		case <-secondDone:
			t.Errorf("%s: the second change was written while the first was under way", tc.name)
		case <-time.After(200 * time.Millisecond):
		}
		close(release)
		<-firstDone
		<-secondDone
		if firstErr != nil || secondErr != nil {
			t.Fatalf("%s: %v, %v", tc.name, firstErr, secondErr)
		}
		c, err := Load(store)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Peers) != 1 || c.Peers[0].Name != "web2" || c.Token != rotatedTo {
			t.Fatalf("%s: kept peers %+v, and the rotated key: %v", tc.name, c.Peers, c.Token == rotatedTo)
		}
	}
}
