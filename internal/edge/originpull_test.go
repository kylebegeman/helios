package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fixedCA is a CA certificate kept in testdata, base64 DER as the edge
// takes it, so a configuration built with it never changes. Its key was
// discarded when it was made.
func fixedCA(tb testing.TB, name string) string {
	tb.Helper()
	text, err := os.ReadFile(filepath.Join("testdata", "originpull-ca-"+name+".pem"))
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := ParseOriginPullCA(string(text))
	if err != nil {
		tb.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// testCA is a CA certificate valid from notBefore to notAfter, as PEM, and
// the key that signs with it. It is cheaper to make than a mint, which
// also makes an RSA leaf.
func testCA(t *testing.T, notBefore, notAfter time.Time) (string, *ecdsa.PrivateKey) {
	t.Helper()
	return selfSigned(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	})
}

// selfSigned is template signed by a new key of its own, as PEM.
func selfSigned(t *testing.T, template *x509.Certificate) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}

func TestMintMakesACAAndAClientCertificateItSigns(t *testing.T) {
	now := time.Now()
	minted, err := MintOriginPull("Pull.Example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseOriginPullCA(minted.CA.PEM)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Fatalf("the CA can sign more than one level of leaves, or none: %+v", ca)
	}
	if !minted.CA.NotAfter.Equal(ca.NotAfter) {
		t.Fatalf("the kept expiry %s is not the CA's %s", minted.CA.NotAfter, ca.NotAfter)
	}
	if life := ca.NotAfter.Sub(now); life < OriginPullLifetime-time.Second || life > OriginPullLifetime {
		t.Fatalf("the CA lasts %s, want a year", life)
	}
	if ca.NotBefore.After(now) {
		t.Fatalf("the CA isn't valid yet: %s", ca.NotBefore)
	}

	block, rest := pem.Decode(minted.LeafPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("leaf PEM: %q", minted.LeafPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if public, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || public.N.BitLen() != 2048 {
		t.Fatalf("the leaf's key is %T, want RSA-2048, the type Cloudflare documents", leaf.PublicKey)
	}
	if leaf.Subject.CommonName != "pull.example.com" || leaf.IsCA || !leaf.BasicConstraintsValid {
		t.Fatalf("leaf: CN %q, CA %t, basic constraints %t", leaf.Subject.CommonName, leaf.IsCA, leaf.BasicConstraintsValid)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("the leaf's extended key usage is %v, want client authentication", leaf.ExtKeyUsage)
	}
	if !leaf.NotAfter.Equal(ca.NotAfter) {
		t.Fatalf("the leaf runs out %s, the CA %s; the watch warns on the CA's", leaf.NotAfter, ca.NotAfter)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the leaf doesn't verify against its CA as a client: %v", err)
	}

	// The key is the leaf's, and is all a holder of the leaf can sign
	// with: a second mint's CA doesn't take the first one's leaf.
	pair, err := tls.X509KeyPair(minted.LeafPEM, minted.KeyPEM)
	if err != nil {
		t.Fatalf("the key doesn't match the leaf: %v", err)
	}
	if block, _ := pem.Decode(minted.KeyPEM); block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM: %q", minted.KeyPEM)
	}
	if _, ok := pair.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("the key is %T", pair.PrivateKey)
	}
	other, err := MintOriginPull("pull.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if other.CA.PEM == minted.CA.PEM {
		t.Fatal("two mints made the same CA")
	}
	otherCA, err := ParseOriginPullCA(other.CA.PEM)
	if err != nil {
		t.Fatal(err)
	}
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(otherCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: otherRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("another mint's CA takes this mint's leaf")
	}
}

func TestParseOriginPullCATakesOnlyOneCACertificate(t *testing.T) {
	minted, err := MintOriginPull("pull.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOriginPullCA("\n  " + minted.CA.PEM + "\n\n"); err != nil {
		t.Fatalf("surrounding blank space: %v", err)
	}
	for name, text := range map[string]string{
		"the leaf":          string(minted.LeafPEM),
		"the key":           string(minted.KeyPEM),
		"two certificates":  minted.CA.PEM + minted.CA.PEM,
		"trailing text":     minted.CA.PEM + "and then some",
		"not PEM":           "MIIB" + strings.Repeat("A", 40),
		"nothing":           "",
		"a damaged CA":      strings.Replace(minted.CA.PEM, "\nMII", "\nMIA", 1),
		"base64 DER, unPEM": base64.StdEncoding.EncodeToString([]byte(minted.CA.PEM)),
	} {
		if cert, err := ParseOriginPullCA(text); err == nil {
			t.Errorf("%s: took %s", name, cert.Subject)
		}
	}
}

func TestTrustKeepsEachCAOnceInExpiryOrder(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	later, _ := testCA(t, now, now.Add(48*time.Hour))
	sooner, _ := testCA(t, now, now.Add(24*time.Hour))
	trust := OriginPullTrust{}
	if !trust.Trust("Pull.Example.com", OriginPullCA{PEM: later, NotAfter: now.Add(48 * time.Hour)}) {
		t.Fatal("a new CA was not added")
	}
	if !trust.Trust("pull.example.com", OriginPullCA{PEM: sooner, NotAfter: now.Add(24 * time.Hour)}) {
		t.Fatal("a second CA was not added")
	}
	if trust.Trust("PULL.example.com", OriginPullCA{PEM: "\n" + strings.TrimSpace(later) + "\n\n", NotAfter: now.Add(48 * time.Hour)}) {
		t.Fatal("the same CA, spaced differently, was added again")
	}
	cas := trust["pull.example.com"]
	if len(trust) != 1 || len(cas) != 2 || cas[0].PEM != sooner || cas[1].PEM != later {
		t.Fatalf("trust: %+v", trust)
	}
}

func TestPruneForgetsWhatRanOutAndHostsLeftWithNothing(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	trust := OriginPullTrust{
		"keep.example.com": {
			{PEM: "old", NotAfter: now.Add(-time.Hour)},
			{PEM: "new", NotAfter: now.Add(time.Hour)},
		},
		"gone.example.com": {{PEM: "just now", NotAfter: now}},
	}
	if n := trust.Prune(now); n != 2 {
		t.Fatalf("forgot %d, want 2", n)
	}
	if len(trust) != 1 || len(trust["keep.example.com"]) != 1 || trust["keep.example.com"][0].PEM != "new" {
		t.Fatalf("trust: %+v", trust)
	}
}

func TestClientCAsAreOnlyTheOnesTheEdgeCanUseNow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	current, _ := testCA(t, now.Add(-time.Hour), now.Add(time.Hour))
	expired, _ := testCA(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	early, _ := testCA(t, now.Add(time.Hour), now.Add(2*time.Hour))
	minted, err := MintOriginPull("pull.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	// The stored expiry is not what counts: a record can say anything,
	// and the edge goes by the certificate.
	trust := OriginPullTrust{"pull.example.com": {
		{PEM: expired, NotAfter: now.Add(time.Hour)},
		{PEM: early, NotAfter: now.Add(2 * time.Hour)},
		{PEM: string(minted.LeafPEM), NotAfter: now.Add(time.Hour)},
		{PEM: "not a certificate", NotAfter: now.Add(time.Hour)},
		{PEM: current, NotAfter: now.Add(time.Hour)},
	}}
	got := trust.ClientCAs("Pull.Example.com", now)
	block, _ := pem.Decode([]byte(current))
	if len(got) != 1 || got[0] != base64.StdEncoding.EncodeToString(block.Bytes) {
		t.Fatalf("client CAs: %q", got)
	}
	if clientCA(got[0]) != got[0] {
		t.Fatal("the edge would leave out a CA the trust hands it")
	}
	if got := trust.ClientCAs("other.example.com", now); got != nil {
		t.Fatalf("a host with no trust: %q", got)
	}
}

func TestOriginPullTrustRoundTrips(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, _ := testCA(t, now, now.Add(48*time.Hour))
	b, _ := testCA(t, now, now.Add(24*time.Hour))
	c, _ := testCA(t, now, now.Add(72*time.Hour))
	trust := OriginPullTrust{
		"b.example.com": {{PEM: a, NotAfter: now.Add(48 * time.Hour)}, {PEM: b, NotAfter: now.Add(24 * time.Hour)}},
		"a.example.com": {{PEM: c, NotAfter: now.Add(72 * time.Hour)}},
	}
	text, err := trust.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, `{"a.example.com":[{"ca_pem":`) {
		t.Fatalf("encoded: %s", text)
	}
	parsed, err := ParseOriginPullTrust(text)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parsed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if again != text {
		t.Fatalf("round trip:\n%s\n%s", text, again)
	}
	if got := parsed["b.example.com"]; len(got) != 2 || got[0].PEM != b || !got[0].NotAfter.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("b.example.com: %+v", got)
	}
	for _, empty := range []string{"", "  \n", "null", "{}"} {
		parsed, err := ParseOriginPullTrust(empty)
		if err != nil || parsed == nil || len(parsed) != 0 {
			t.Fatalf("%q: %v, %v", empty, parsed, err)
		}
		// Trust must be able to add to what an empty value parses to.
		parsed.Trust("a.example.com", OriginPullCA{PEM: a})
	}
	if _, err := ParseOriginPullTrust("{"); err == nil || !strings.Contains(err.Error(), "origin-pull trust doesn't parse") {
		t.Fatalf("damaged trust: %v", err)
	}
}
