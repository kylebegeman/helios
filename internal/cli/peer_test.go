package cli

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/peer"
	"github.com/kylebegeman/helios/internal/secrets"
)

// peerKey is a fingerprint as helios peer key prints one.
func peerKey(digit string) string { return "sha256:" + strings.Repeat(digit, 64) }

// meshListen is an address on the mesh, made from its range rather than
// written down.
func meshListen(prefix string) string {
	return netip.AddrPortFrom(netip.MustParsePrefix(prefix).Addr().Next(), 7700).String()
}

func peerRun(t *testing.T, stateDir string, args ...string) string {
	t.Helper()
	out, errOut, code := run(t, stateDir, args...)
	if code != 0 {
		t.Fatalf("%s: code %d, err %q", strings.Join(args, " "), code, errOut)
	}
	return out
}

func listedPeers(t *testing.T, stateDir string) []peerRow {
	t.Helper()
	var rows []peerRow
	if err := json.Unmarshal([]byte(peerRun(t, stateDir, "peer", "ls", "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func sealedPeers(t *testing.T, stateDir string) peer.Config {
	t.Helper()
	c, err := peer.Load(secrets.DefaultStore(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPeersAreAddedUpdatedAndRemoved(t *testing.T) {
	dir := t.TempDir()
	peerRun(t, dir, "peer", "init", "--name", "web1")
	out := peerRun(t, dir, "peer", "add", "web2", "--mesh", "web2.mesh.example.test:7700", "--public", "https://web2.example.test", "--key", peerKey("a"))
	if !strings.Contains(out, "watching web2; web2 may read this machine") {
		t.Fatalf("add: %q", out)
	}
	peerRun(t, dir, "peer", "add", "mac", "--key", peerKey("b"))
	// Adding again replaces where the peer is reached and keeps its key.
	peerRun(t, dir, "peer", "add", "web2", "--mesh", "web2.mesh.example.test:7701", "--public", "https://web2.example.test/healthz", "--public", "https://shop.example.test")
	want := []peerRow{
		{Name: "mac", ReadsThisMachine: true},
		{Name: "web2", Watched: true, ReadsThisMachine: true, Public: []string{"https://web2.example.test/healthz", "https://shop.example.test"}},
	}
	if got := listedPeers(t, dir); !reflect.DeepEqual(got, want) {
		t.Fatalf("listed %+v, want %+v", got, want)
	}
	if c := sealedPeers(t, dir); len(c.Peers) != 1 || c.Peers[0].Mesh != "web2.mesh.example.test:7701" || c.Observers["web2"] != peerKey("a") {
		t.Fatalf("the update wasn't kept: %+v", c.Peers)
	}

	out = peerRun(t, dir, "peer", "rm", "web2")
	if !strings.Contains(out, "web2 removed") {
		t.Fatalf("rm: %q", out)
	}
	if got := listedPeers(t, dir); !reflect.DeepEqual(got, want[:1]) {
		t.Fatalf("after rm, listed %+v", got)
	}
	if _, errOut, code := run(t, dir, "peer", "rm", "web2"); code != 1 || !strings.Contains(errOut, "no peer named web2") {
		t.Fatalf("a second rm: code %d, err %q", code, errOut)
	}
	peerRun(t, dir, "peer", "rm", "mac")
	if c := sealedPeers(t, dir); len(c.Peers) != 0 || len(c.Observers) != 0 || c.Self.Name != "web1" {
		t.Fatalf("after removing every peer: %+v", c)
	}
}

func TestPeerListPrintsNamesAndPublicURLsOnly(t *testing.T) {
	dir := t.TempDir()
	const meshHost = "sentinel-mesh.example.test"
	listen := meshListen("100.64.0.0/10")
	peerRun(t, dir, "peer", "init", "--name", "web1", "--listen", listen, "--public", "https://web1.example.test")
	peerRun(t, dir, "peer", "add", "web2", "--mesh", meshHost+":7700", "--public", "https://web2.example.test", "--key", peerKey("a"))
	token := sealedPeers(t, dir).Token
	for _, args := range [][]string{{"peer", "ls"}, {"peer", "ls", "--json"}} {
		out := peerRun(t, dir, args...)
		if !strings.Contains(out, "web2") || !strings.Contains(out, "https://web2.example.test") {
			t.Fatalf("%s lacks the peer's name or public URL:\n%s", strings.Join(args, " "), out)
		}
		for _, hidden := range []string{meshHost, listen, ":7700", peerKey("a"), "sha256:", "hp1_", token, peer.Fingerprint(token)} {
			if strings.Contains(out, hidden) {
				t.Fatalf("%s shows a mesh address or a key:\n%s", strings.Join(args, " "), out)
			}
		}
	}
}

func TestNoPeersListAsAnEmptyJSONList(t *testing.T) {
	dir := t.TempDir()
	if out := peerRun(t, dir, "peer", "ls", "--json"); out != "[]\n" {
		t.Fatalf("before init: %q", out)
	}
	if out := peerRun(t, dir, "peer", "ls"); !strings.Contains(out, "not set up") {
		t.Fatalf("before init: %q", out)
	}
	peerRun(t, dir, "peer", "init", "--name", "web1")
	if out := peerRun(t, dir, "peer", "ls", "--json"); out != "[]\n" {
		t.Fatalf("with no peers: %q", out)
	}
	if out := peerRun(t, dir, "peer", "ls"); !strings.Contains(out, "no peers") {
		t.Fatalf("with no peers: %q", out)
	}
}

// Nothing peer watch keeps is readable at rest: not in the secrets'
// plaintext metadata, not in the state store, not anywhere under the
// state directory.
func TestPeerConfigIsSealed(t *testing.T) {
	dir := t.TempDir()
	peerRun(t, dir, "watch") // makes the state store, so it is read too
	listen := meshListen("fc00::/7")
	peerRun(t, dir, "peer", "init", "--name", "web1", "--listen", listen, "--public", "https://sentinel-self.example.test")
	peerRun(t, dir, "peer", "add", "web2", "--mesh", "sentinel-mesh.example.test:7700", "--public", "https://sentinel-public.example.test", "--key", peerKey("a"))
	peerRun(t, dir, "peer", "add", "mac", "--key", peerKey("b"))
	token := sealedPeers(t, dir).Token
	sentinels := []string{"sentinel-mesh", "sentinel-public", "sentinel-self", listen, "hp1_", token, peerKey("a"), peerKey("b")}
	files := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		for _, s := range sentinels {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("%s holds a peer's address, URL or key in the clear", strings.TrimPrefix(path, dir))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.db")); err != nil || files < 3 {
		t.Fatalf("read %d files; the state store: %v", files, err)
	}
	// The metadata shows the names alone.
	if out := peerRun(t, dir, "secret", "list", "bedrock"); !strings.Contains(out, peer.ListKey) || !strings.Contains(out, peer.TokenKey) || !strings.Contains(out, peer.ObserversKey) {
		t.Fatalf("secret list: %q", out)
	}
}

func TestPeerAddRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	if _, errOut, code := run(t, dir, "peer", "add", "web2", "--key", peerKey("a")); code != 1 || !strings.Contains(errOut, "helios peer init") {
		t.Fatalf("add before init: code %d, err %q", code, errOut)
	}
	peerRun(t, dir, "peer", "init", "--name", "web1")
	mesh, public := "web2.mesh.example.test:7700", "https://web2.example.test"
	outside := netip.MustParsePrefix("192.0.2.0/24").Addr().Next()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"Web2", "--key", peerKey("a")}, "starts with a lowercase letter"},
		{[]string{"self", "--key", peerKey("a")}, "self and edge-provider are taken"},
		{[]string{"edge-provider", "--key", peerKey("a")}, "self and edge-provider are taken"},
		{[]string{"web1", "--key", peerKey("a")}, "web1 is this machine's own name"},
		{[]string{"web2"}, "--key to let it read this machine"},
		{[]string{"web2", "--mesh", mesh}, "--mesh and --public go together"},
		{[]string{"web2", "--public", public}, "--mesh and --public go together"},
		{[]string{"web2", "--mesh", "web2.mesh.example.test", "--public", public}, "--mesh must be host:port"},
		{[]string{"web2", "--mesh", "web2.mesh.example.test:443", "--public", public}, "--mesh must not use port 80 or 443"},
		{[]string{"web2", "--mesh", "web2.mesh.example.test:80", "--public", public}, "--mesh must not use port 80 or 443"},
		{[]string{"web2", "--mesh", outside.String() + ":7700", "--public", public}, "on the mesh"},
		{[]string{"web2", "--mesh", "Web2.Mesh:7700", "--public", public}, "lowercase letters, digits, hyphens and dots"},
		{[]string{"web2", "--mesh", mesh, "--public", "http://web2.example.test"}, "--public must be an https:// URL"},
		{[]string{"web2", "--mesh", mesh, "--public", "https://" + outside.String()}, "--public must be an https:// URL on a host name"},
		{[]string{"web2", "--mesh", mesh, "--public", "https://user:pw@web2.example.test"}, "credentials"},
		{[]string{"web2", "--key", "sha256:abc"}, "--key must be the sha256:... fingerprint"},
		{[]string{"web2", "--key", "hp1_" + strings.Repeat("a", 64)}, "--key must be the sha256:... fingerprint"},
	} {
		args := append([]string{"peer", "add"}, c.args...)
		if _, errOut, code := run(t, dir, args...); code != 1 || !strings.Contains(errOut, c.want) {
			t.Fatalf("%s: code %d, err %q, want %q", strings.Join(args, " "), code, errOut, c.want)
		}
	}
	if got := listedPeers(t, dir); len(got) != 0 {
		t.Fatalf("a refused add was kept: %+v", got)
	}
}

func TestServerInitNeedsPublicWithListen(t *testing.T) {
	dir := t.TempDir()
	listen := meshListen("100.64.0.0/10")
	if _, errOut, code := run(t, dir, "peer", "init", "--name", "web1", "--listen", listen); code != 1 || !strings.Contains(errOut, "--listen needs --public") {
		t.Fatalf("listen without public: code %d, err %q", code, errOut)
	}
	if _, errOut, code := run(t, dir, "peer", "init", "--name", "web1", "--listen", "0.0.0.0:7700", "--public", "https://web1.example.test"); code != 1 || !strings.Contains(errOut, "--listen must be an address on the mesh") {
		t.Fatalf("listen on every address: code %d, err %q", code, errOut)
	}
	if out := peerRun(t, dir, "peer", "ls"); !strings.Contains(out, "not set up") {
		t.Fatalf("a refused init was kept: %q", out)
	}
	peerRun(t, dir, "peer", "init", "--name", "web1", "--listen", listen, "--public", "https://web1.example.test")
	if self := sealedPeers(t, dir).Self; self.Listen != listen || !reflect.DeepEqual(self.Public, []string{"https://web1.example.test"}) {
		t.Fatalf("kept %+v", self)
	}
	// A Mac watches and answers no one, so it needs neither.
	mac := t.TempDir()
	peerRun(t, mac, "peer", "init", "--name", "mac")
	if self := sealedPeers(t, mac).Self; self.Listen != "" || len(self.Public) != 0 {
		t.Fatalf("kept %+v", self)
	}
}

func TestPeerKeyRotateChangesFingerprint(t *testing.T) {
	dir := t.TempDir()
	if _, errOut, code := run(t, dir, "peer", "key"); code != 1 || !strings.Contains(errOut, "helios peer init") {
		t.Fatalf("key before init: code %d, err %q", code, errOut)
	}
	var outputs []string
	keyOf := func(out string) string {
		outputs = append(outputs, out)
		_, key, _ := strings.Cut(out, "key: ")
		return strings.TrimSpace(key)
	}
	first := keyOf(peerRun(t, dir, "peer", "init", "--name", "web1"))
	if !peer.ValidKey(first) || keyOf("key: "+peerRun(t, dir, "peer", "key")) != first {
		t.Fatalf("init printed %q", first)
	}
	// Running init again keeps the key.
	if again := keyOf(peerRun(t, dir, "peer", "init", "--name", "web1", "--listen", meshListen("100.64.0.0/10"), "--public", "https://web1.example.test")); again != first {
		t.Fatalf("init again changed the key: %q, then %q", first, again)
	}
	out, errOut, code := run(t, dir, "peer", "key", "--rotate")
	rotated := keyOf("key: " + out)
	if code != 0 || !peer.ValidKey(rotated) || rotated == first || !strings.Contains(errOut, "helios peer add web1 --key "+rotated) {
		t.Fatalf("rotate: code %d, out %q, err %q", code, out, errOut)
	}
	outputs = append(outputs, errOut)
	if now := keyOf("key: " + peerRun(t, dir, "peer", "key")); now != rotated {
		t.Fatalf("after rotating, key prints %q, want %q", now, rotated)
	}
	// What is printed is the fingerprint of the key kept, never the key.
	token := sealedPeers(t, dir).Token
	if peer.Fingerprint(token) != rotated {
		t.Fatalf("the printed fingerprint isn't the kept key's")
	}
	for _, out := range outputs {
		if strings.Contains(out, token) || strings.Contains(out, "hp1_") {
			t.Fatalf("the key itself was shown: %q", out)
		}
	}
}
