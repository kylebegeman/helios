package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/remote"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// mintedFile reads what mint wrote: the certificate, then its key, and
// nothing else, readable by its owner alone.
func mintedFile(t *testing.T, path string) (leaf *x509.Certificate, certPEM, keyPEM []byte) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s is %v, not 0600", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, rest := pem.Decode(data)
	if cert == nil || cert.Type != "CERTIFICATE" {
		t.Fatalf("the file doesn't start with the certificate:\n%s", data)
	}
	key, rest := pem.Decode(rest)
	if key == nil || key.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		t.Fatalf("the certificate isn't followed by its key alone:\n%s", data)
	}
	certPEM, keyPEM = pem.EncodeToMemory(cert), pem.EncodeToMemory(key)
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("the key isn't the certificate's: %v", err)
	}
	leaf, err = x509.ParseCertificate(cert.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, certPEM, keyPEM
}

// verifiesAgainst checks that leaf is a client certificate caPEM signed.
func verifiesAgainst(t *testing.T, leaf *x509.Certificate, caPEM string) {
	t.Helper()
	ca, err := edge.ParseOriginPullCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the edge wouldn't take the certificate: %v", err)
	}
}

// keyNotShown fails if any line of the key's body is in the output.
func keyNotShown(t *testing.T, keyPEM []byte, outputs ...string) {
	t.Helper()
	all := strings.Join(outputs, "\n")
	if strings.Contains(all, "PRIVATE KEY") {
		t.Fatalf("the key was shown:\n%s", all)
	}
	for _, line := range strings.Split(string(keyPEM), "\n") {
		if len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(all, line) {
			t.Fatalf("a line of the key was shown:\n%s", all)
		}
	}
}

func trusted(t *testing.T, stateDir, host string) []edge.OriginPullCA {
	t.Helper()
	trust, err := apps.LoadOriginPullTrust(secrets.DefaultStore(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	return trust[host]
}

func TestMintWritesTheCertificateAndKeyOnceAndTrustsOnlyTheCA(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(t.TempDir(), "shop.pem")
	out, errOut, code := run(t, stateDir, "edge", "origin-pull", "mint", "Shop.Example.com", "--out", path)
	if code != 0 {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	leaf, _, keyPEM := mintedFile(t, path)
	cas := trusted(t, stateDir, "shop.example.com")
	if len(cas) != 1 {
		t.Fatalf("trusted %d CAs, want 1", len(cas))
	}
	verifiesAgainst(t, leaf, cas[0].PEM)
	if leaf.Subject.CommonName != "shop.example.com" {
		t.Fatalf("the certificate names %q", leaf.Subject.CommonName)
	}
	fingerprint, err := apps.OriginPullFingerprint(cas[0].PEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{fingerprint, cas[0].NotAfter.UTC().Format(time.DateOnly), path, "per-hostname authenticated origin pull", "Full (strict)", "origin_pull: optional", "origin_pull: required", "Delete"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output lacks %q:\n%s", want, out)
		}
	}
	keyNotShown(t, keyPEM, out, errOut)
	raw, _, err := secrets.DefaultStore(stateDir).LoadCurrent(integration.App)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw[integration.OriginPullName], "PRIVATE KEY") {
		t.Fatal("a key was kept")
	}

	// A file already there is never written over, and nothing is trusted.
	before, _ := os.ReadFile(path)
	_, errOut, code = run(t, stateDir, "edge", "origin-pull", "mint", "shop.example.com", "--out", path)
	if code != 1 || !strings.Contains(errOut, "already exists") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the file was written over")
	}
	if n := len(trusted(t, stateDir, "shop.example.com")); n != 1 {
		t.Fatalf("a refused mint trusted a CA: %d", n)
	}

	// Minting again keeps the old CA, so the certificate Cloudflare has
	// keeps working until the new one replaces it.
	next := filepath.Join(t.TempDir(), "shop-next.pem")
	if _, errOut, code := run(t, stateDir, "edge", "origin-pull", "mint", "shop.example.com", "--out", next); code != 0 {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	if n := len(trusted(t, stateDir, "shop.example.com")); n != 2 {
		t.Fatalf("trusted %d CAs after a second mint, want 2", n)
	}
	_, errOut, code = run(t, stateDir, "edge", "origin-pull", "mint", "shop.example.com")
	if code != 1 || !strings.Contains(errOut, "give --out") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
}

func TestAMintWhoseCAIsntTrustedLeavesNoFile(t *testing.T) {
	stateDir := t.TempDir()
	sec := secrets.DefaultStore(stateDir)
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.Set(integration.App, integration.OriginPullName, "{not json"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "shop.pem")
	out, errOut, code := run(t, stateDir, "edge", "origin-pull", "mint", "shop.example.com", "--out", path)
	if code != 1 || !strings.Contains(errOut, "doesn't parse") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the file was left: %v", err)
	}
	if strings.Contains(out+errOut, "PRIVATE KEY") {
		t.Fatal("the key was shown")
	}
}

func TestTrustTakesOneCAFromAFileOrStdin(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now()
	one, err := edge.MintOriginPull("shop.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	two, err := edge.MintOriginPull("shop.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, []byte(one.CA.PEM), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, _ := apps.OriginPullFingerprint(one.CA.PEM)
	out, errOut, code := run(t, stateDir, "edge", "origin-pull", "trust", "shop.example.com", file)
	if code != 0 || !strings.Contains(out, "shop.example.com trusts CA "+fp) {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	out, errOut, code = withStdin(t, one.CA.PEM, stateDir, "edge", "origin-pull", "trust", "shop.example.com")
	if code != 0 || !strings.Contains(out, "already trusts CA "+fp) {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	out, errOut, code = withStdin(t, two.CA.PEM, stateDir, "edge", "origin-pull", "trust", "shop.example.com", "-")
	if code != 0 || !strings.Contains(out, "trusts CA") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	if n := len(trusted(t, stateDir, "shop.example.com")); n != 2 {
		t.Fatalf("trusted %d CAs, want 2", n)
	}
	for _, c := range []struct{ name, text, want string }{
		{"the leaf", string(one.LeafPEM), "not a CA's certificate"},
		{"two CAs", one.CA.PEM + two.CA.PEM, "nothing else"},
		{"a key", one.CA.PEM + string(one.KeyPEM), "nothing else"},
		{"nothing", "", "no certificate was given"},
	} {
		_, errOut, code := withStdin(t, c.text, stateDir, "edge", "origin-pull", "trust", "shop.example.com")
		if code != 1 || !strings.Contains(errOut, c.want) {
			t.Fatalf("%s: code %d, err %q", c.name, code, errOut)
		}
	}
	if n := len(trusted(t, stateDir, "shop.example.com")); n != 2 {
		t.Fatalf("a refused CA was trusted: %d", n)
	}
}

func TestListShowsEachHostsCAsAndForgetDropsThem(t *testing.T) {
	stateDir := t.TempDir()
	out, _, code := run(t, stateDir, "edge", "origin-pull", "list")
	if code != 0 || !strings.Contains(out, "no host uses origin pull") {
		t.Fatalf("code %d, out %q", code, out)
	}
	now := time.Now()
	var fingerprints []string
	for range 2 {
		m, err := edge.MintOriginPull("shop.example.com", now)
		if err != nil {
			t.Fatal(err)
		}
		if _, errOut, code := withStdin(t, m.CA.PEM, stateDir, "edge", "origin-pull", "trust", "shop.example.com"); code != 0 {
			t.Fatalf("code %d, err %q", code, errOut)
		}
		fp, _ := apps.OriginPullFingerprint(m.CA.PEM)
		fingerprints = append(fingerprints, fp)
	}
	out, _, code = run(t, stateDir, "edge", "origin-pull", "list")
	if code != 0 {
		t.Fatalf("code %d, out %q", code, out)
	}
	for _, want := range []string{"HOST", "MODE", "EXPIRES", "shop.example.com", "off", fingerprints[0], fingerprints[1], now.Add(edge.OriginPullLifetime).UTC().Format(time.DateOnly)} {
		if !strings.Contains(out, want) {
			t.Fatalf("list lacks %q:\n%s", want, out)
		}
	}
	out, _, code = run(t, stateDir, "--json", "edge", "origin-pull", "list")
	var rows []struct {
		Host     string `json:"host"`
		ValidCAs int    `json:"valid_cas"`
		CAs      []struct {
			Fingerprint string `json:"fingerprint"`
			PEM         string `json:"ca_pem"`
		} `json:"cas"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 || rows[0].ValidCAs != 2 || len(rows[0].CAs) != 2 {
		t.Fatalf("code %d, out %s", code, out)
	}
	for _, ca := range rows[0].CAs {
		if _, err := edge.ParseOriginPullCA(ca.PEM); err != nil {
			t.Fatalf("the JSON's CA can't be trusted elsewhere: %v", err)
		}
	}

	out, errOut, code := run(t, stateDir, "edge", "origin-pull", "forget", "shop.example.com", fingerprints[0])
	if code != 0 || !strings.Contains(out, "no longer trusts CA "+fingerprints[0]) {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	out, _, _ = run(t, stateDir, "edge", "origin-pull", "list")
	if strings.Contains(out, fingerprints[0]) || !strings.Contains(out, fingerprints[1]) {
		t.Fatalf("forget dropped the wrong CA:\n%s", out)
	}
	_, errOut, code = run(t, stateDir, "edge", "origin-pull", "forget", "shop.example.com", fingerprints[0])
	if code != 1 || !strings.Contains(errOut, "trusts no CA "+fingerprints[0]) {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	out, errOut, code = run(t, stateDir, "edge", "origin-pull", "forget", "shop.example.com")
	if code != 0 || !strings.Contains(out, "no longer trusts its CA") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	out, _, _ = run(t, stateDir, "edge", "origin-pull", "list")
	if !strings.Contains(out, "no host uses origin pull") {
		t.Fatalf("list after forgetting everything:\n%s", out)
	}
}

func TestListFlagsARequiredHostTheEdgeRefuses(t *testing.T) {
	stateDir := t.TempDir()
	m, err := manifest.Parse([]byte("app: shop\nworkloads: {web: {kind: web, image: example/shop:1, port: 8080, routes: [{host: shop.example.com, dns: proxied, origin_pull: required}, {host: www.example.com, dns: proxied, origin_pull: optional}]}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRevision(context.Background(), state.Revision{App: "shop", ID: "r1", Status: state.RevisionActive, Manifest: raw, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	out, _, code := run(t, stateDir, "edge", "origin-pull", "list")
	if code != 0 {
		t.Fatalf("code %d, out %q", code, out)
	}
	for _, want := range []string{"required", "optional", "none", "shop.example.com requires origin pull and trusts no CA that is still good, so the edge refuses every connection to it", "www.example.com checks no certificate yet"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list lacks %q:\n%s", want, out)
		}
	}
	path := filepath.Join(t.TempDir(), "shop.pem")
	if _, errOut, code := run(t, stateDir, "edge", "origin-pull", "mint", "shop.example.com", "--out", path); code != 0 {
		t.Fatalf("code %d, err %q", code, errOut)
	}
	out, _, _ = run(t, stateDir, "edge", "origin-pull", "list")
	if strings.Contains(out, "refuses every connection") {
		t.Fatalf("a host with a CA is still flagged:\n%s", out)
	}
	_, errOut, code := run(t, stateDir, "edge", "origin-pull", "forget", "shop.example.com")
	if code != 1 || !strings.Contains(errOut, "requires origin pull") {
		t.Fatalf("forgetting a required host's last CA: code %d, err %q", code, errOut)
	}
	if n := len(trusted(t, stateDir, "shop.example.com")); n != 1 {
		t.Fatalf("a refused forget dropped the CA: %d", n)
	}
}

// originPullTarget is a target that names capabilities, and keeps the
// arguments and stdin of the last command it ran other than capabilities.
func originPullTarget(t *testing.T, capabilities ...string) (config, record, stdin string) {
	t.Helper()
	dir := t.TempDir()
	record, stdin = filepath.Join(dir, "arguments"), filepath.Join(dir, "stdin")
	caps, _ := json.Marshal(append([]string{"remote.source.v1", "kernel.plan.v1", "kernel.apply.v1", "kernel.expect.v1"}, capabilities...))
	binary, ssh := filepath.Join(dir, "bedrock"), filepath.Join(dir, "ssh")
	script := `#!/bin/sh
case "$*" in
 *capabilities*) printf '%s\n' '{"api_version":1,"manifest_version":1,"state_version":1,"machine_id":"fixture-machine","capabilities":` + string(caps) + `}'; exit 0 ;;
esac
printf '%s\n' "$@" > "$BEDROCK_TEST_REMOTE_ARGS"
cat > "$BEDROCK_TEST_REMOTE_STDIN"
exit "${BEDROCK_TEST_REMOTE_EXIT:-0}"
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ssh, []byte("#!/bin/sh\nfor last do :; done\nexec /bin/sh -c \"$last\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEDROCK_SSH", ssh)
	t.Setenv("BEDROCK_TEST_REMOTE_ARGS", record)
	t.Setenv("BEDROCK_TEST_REMOTE_STDIN", stdin)
	config = filepath.Join(dir, "targets.json")
	if err := remote.Save(config, remote.Config{Version: 1, Targets: map[string]remote.Target{"one": {SSH: "fixture", Binary: binary}}}); err != nil {
		t.Fatal(err)
	}
	return config, record, stdin
}

func TestATargetWithoutOriginPullIsNotAskedToDoIt(t *testing.T) {
	config, record, _ := originPullTarget(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	minted, err := edge.MintOriginPull("shop.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, []byte(minted.CA.PEM), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "shop.pem")
	for _, args := range [][]string{
		{"edge", "origin-pull", "mint", "shop.example.com", "--out", out},
		{"edge", "origin-pull", "trust", "shop.example.com", ca},
		{"edge", "origin-pull", "list"},
		{"edge", "origin-pull", "forget", "shop.example.com"},
	} {
		if _, stderr, code := targetRun(t, config, args...); code == 0 || !strings.Contains(stderr, "does not support authenticated origin pulls; upgrade helios on the target") {
			t.Fatalf("%v: %d %s", args, code, stderr)
		}
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("the target was asked")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a refused mint wrote a file")
	}
}

func TestMintForATargetKeepsTheKeyHere(t *testing.T) {
	config, record, stdin := originPullTarget(t, "edge.origin-pull.v1")
	path := filepath.Join(t.TempDir(), "shop.pem")
	out, stderr, code := targetRun(t, config, "edge", "origin-pull", "mint", "Shop.Example.com", "--out", path)
	if code != 0 {
		t.Fatalf("code %d, out %q, err %q", code, out, stderr)
	}
	args, _ := os.ReadFile(record)
	if got := string(args); got != "edge\norigin-pull\ntrust\nshop.example.com\n" {
		t.Fatalf("the target ran %q", got)
	}
	sent, _ := os.ReadFile(stdin)
	if strings.Contains(string(sent), "PRIVATE KEY") {
		t.Fatal("the key went to the target")
	}
	leaf, _, keyPEM := mintedFile(t, path)
	verifiesAgainst(t, leaf, string(sent))
	fp, _ := apps.OriginPullFingerprint(string(sent))
	if !strings.Contains(out, fp) || !strings.Contains(out, path) {
		t.Fatalf("the output lacks the CA or the file:\n%s", out)
	}
	keyNotShown(t, keyPEM, out, stderr)

	// A target that won't trust the CA leaves no file behind.
	t.Setenv("BEDROCK_TEST_REMOTE_EXIT", "3")
	refused := filepath.Join(t.TempDir(), "refused.pem")
	if _, stderr, code := targetRun(t, config, "edge", "origin-pull", "mint", "shop.example.com", "--out", refused); code != 3 {
		t.Fatalf("code %d, err %q", code, stderr)
	}
	if _, err := os.Stat(refused); !os.IsNotExist(err) {
		t.Fatalf("the file was left: %v", err)
	}
}

func TestTrustForATargetSendsTheFileOnStdin(t *testing.T) {
	config, record, stdin := originPullTarget(t, "edge.origin-pull.v1")
	minted, err := edge.MintOriginPull("shop.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte(minted.CA.PEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := targetRun(t, config, "edge", "origin-pull", "trust", "shop.example.com", ca); code != 0 {
		t.Fatalf("code %d, err %q", code, stderr)
	}
	args, _ := os.ReadFile(record)
	sent, _ := os.ReadFile(stdin)
	if string(args) != "edge\norigin-pull\ntrust\nshop.example.com\n" || string(sent) != minted.CA.PEM {
		t.Fatalf("the target ran %q with %q", args, sent)
	}
}

func TestATargetWithoutOriginPullIsNotSentAManifestThatSetsIt(t *testing.T) {
	source := t.TempDir()
	pulled := "app: shop\nworkloads: {web: {kind: web, image: example/shop:1, port: 8080, routes: [{host: shop.example.com, dns: proxied, origin_pull: optional}]}}\n"
	if err := os.WriteFile(filepath.Join(source, manifest.FileName), []byte(pulled), 0o644); err != nil {
		t.Fatal(err)
	}
	const refusal = "the manifest sets origin_pull"
	config, record, _ := originPullTarget(t)
	for _, args := range [][]string{
		{"deploy", source, "--yes"},
		{"check", source},
		{"move", "stage", source, "--handoff", filepath.Join(source, "final.json"), "--yes"},
	} {
		if _, stderr, code := targetRun(t, config, args...); code == 0 || !strings.Contains(stderr, refusal) {
			t.Fatalf("%v: %d %s", args, code, stderr)
		}
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("the source was sent")
	}
	// A manifest without origin_pull, or a target that knows it, goes on.
	open := strings.Replace(pulled, ", origin_pull: optional", "", 1)
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, manifest.FileName), []byte(open), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, _ := targetRun(t, config, "deploy", plain, "--yes"); strings.Contains(stderr, refusal) {
		t.Fatalf("a manifest without origin_pull was refused: %s", stderr)
	}
	config, _, _ = originPullTarget(t, "edge.origin-pull.v1")
	if _, stderr, _ := targetRun(t, config, "deploy", source, "--yes"); strings.Contains(stderr, refusal) {
		t.Fatalf("a target that knows origin_pull was refused: %s", stderr)
	}
}
