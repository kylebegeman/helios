package peer

import (
	"net/netip"
	"strings"
	"testing"
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
