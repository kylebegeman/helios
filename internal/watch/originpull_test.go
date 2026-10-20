package watch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// trustReader stands in for the machine's credentials.
type trustReader struct {
	trust edge.OriginPullTrust
	err   error
	reads int
}

func (r *trustReader) read() (edge.OriginPullTrust, error) {
	r.reads++
	return r.trust, r.err
}

// originPullProber watches a machine without Docker, reading its
// origin-pull trust from reader.
func originPullProber(t *testing.T, store *state.Store, now *time.Time, reader *trustReader) *Prober {
	t.Helper()
	p := NewProber(store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	if reader != nil {
		p.OriginPullTrust = reader.read
	}
	return p
}

// saveOriginPullApp deploys an app whose web workload serves host behind
// Cloudflare with mode.
func saveOriginPullApp(t *testing.T, store *state.Store, appName, host string, mode manifest.OriginPullMode, at time.Time) {
	t.Helper()
	saveHoldsRevision(t, store, &manifest.Manifest{App: appName, Workloads: map[string]manifest.Workload{
		"web": {Kind: manifest.Web, Image: "example.test/" + appName + ":1", Port: 8080, Routes: []manifest.Route{
			{Host: host, DNS: manifest.DNSProxied, OriginPull: mode},
		}},
	}}, at)
}

// testOriginPullCA is a CA certificate valid from notBefore to notAfter.
func testOriginPullCA(t *testing.T, notBefore, notAfter time.Time) edge.OriginPullCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test origin pull CA"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return edge.OriginPullCA{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), NotAfter: notAfter}
}

// originPullFingerprint is what helios edge origin-pull forget takes for ca.
func originPullFingerprint(t *testing.T, ca edge.OriginPullCA) string {
	t.Helper()
	fingerprint, err := app.OriginPullFingerprint(ca.PEM)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

// originPullConditions is every origin-pull condition of one look.
func originPullConditions(p *Prober) []Condition {
	var out []Condition
	for _, c := range p.Observe(context.Background()) {
		if strings.HasPrefix(c.Key, originPullKey("")) {
			out = append(out, c)
		}
	}
	return out
}

// A prober the daemon gave no way to read the trust says nothing about
// origin pull, even for a host the edge refuses.
func TestOriginPullIsWatchedOnlyWithATrustReader(t *testing.T) {
	w, now := newWatcher(t, &fakeNotifier{})
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	p := originPullProber(t, w.Store, now, nil)
	if found := originPullConditions(p); len(found) != 0 {
		t.Fatalf("no reader, no origin-pull conditions: %+v", found)
	}
}

// A required host with no CA is down: the edge refuses Cloudflare and
// everyone else. The notice says how to mint one, and minting one
// resolves it.
func TestARequiredOriginPullHostWithoutACAIsDown(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	reader := &trustReader{trust: edge.OriginPullTrust{}}
	p := originPullProber(t, w.Store, now, reader)
	round := func() []Condition {
		t.Helper()
		*now = now.Add(time.Minute)
		found := originPullConditions(p)
		if err := w.Round(ctx, found); err != nil {
			t.Fatal(err)
		}
		return found
	}

	found := round()
	if len(found) != 1 || found[0].Key != "edge:origin-pull:www.example.com" || found[0].Subject != "www.example.com" || found[0].Severity != state.SeverityCritical {
		t.Fatalf("a required host without a CA is critical: %+v", found)
	}
	for _, want := range []string{"the edge refuses every connection to www.example.com", "trusts no CA for it", "helios edge origin-pull mint www.example.com --out FILE", "origin_pull: optional"} {
		if !strings.Contains(found[0].Message, want) {
			t.Fatalf("the message should say %q: %s", want, found[0].Message)
		}
	}
	round()
	round()
	if len(notifier.sent) != 1 || notifier.sent[0].Subject != "box: www.example.com is down" {
		t.Fatalf("one notice that the host is down: %+v", notifier.sent)
	}

	minted, err := edge.MintOriginPull("www.example.com", *now)
	if err != nil {
		t.Fatal(err)
	}
	reader.trust.Trust("www.example.com", minted.CA)
	if found := round(); len(found) != 0 {
		t.Fatalf("a freshly minted CA is a year from running out: %+v", found)
	}
	round()
	if len(notifier.sent) != 2 || notifier.sent[1].Transition != TransitionResolved || notifier.sent[1].Subject != "box: www.example.com recovered" {
		t.Fatalf("the incident resolves once a CA is trusted: %+v", notifier.sent)
	}
}

// A CA a host trusts warns 30 days before it runs out, whatever the mode.
// Minting a newer one doesn't quiet it, since Cloudflare presents the old
// certificate until the new one is uploaded: the warning then names the
// command that forgets the old CA, and stops once it is forgotten.
func TestAnOriginPullCAWarnsThirtyDaysBeforeItRunsOut(t *testing.T) {
	w, now := newWatcher(t, &fakeNotifier{})
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	saveOriginPullApp(t, w.Store, "docs", "docs.example.com", manifest.OriginPullOptional, now.Add(-time.Hour))
	issued := now.Add(-300 * 24 * time.Hour)
	reader := &trustReader{}
	p := originPullProber(t, w.Store, now, reader)

	reader.trust = edge.OriginPullTrust{
		"www.example.com":  {testOriginPullCA(t, issued, now.Add(31*24*time.Hour))},
		"docs.example.com": {testOriginPullCA(t, issued, now.Add(31*24*time.Hour))},
	}
	if found := originPullConditions(p); len(found) != 0 {
		t.Fatalf("31 days left is nothing yet: %+v", found)
	}

	reader.trust = edge.OriginPullTrust{
		"www.example.com":  {testOriginPullCA(t, issued, now.Add(29*24*time.Hour))},
		"docs.example.com": {testOriginPullCA(t, issued, now.Add(29*24*time.Hour))},
	}
	found := originPullConditions(p)
	if len(found) != 2 {
		t.Fatalf("both hosts warn with 29 days left: %+v", found)
	}
	for _, c := range found {
		host := strings.TrimPrefix(c.Key, originPullKey(""))
		if c.Severity != state.SeverityWarning {
			t.Fatalf("an expiry ahead is a warning: %+v", c)
		}
		for _, want := range []string{"the newest origin-pull CA " + host + " trusts runs out on 2026-10-18, in 29 days", "helios edge origin-pull mint " + host + " --out FILE", "at Cloudflare"} {
			if !strings.Contains(c.Message, want) {
				t.Fatalf("the warning should say %q: %s", want, c.Message)
			}
		}
	}

	// Rotation: the new CA is trusted beside the old one, and the old one
	// keeps warning, now about forgetting it rather than minting.
	oldFingerprint := originPullFingerprint(t, reader.trust["www.example.com"][0])
	reader.trust.Trust("www.example.com", testOriginPullCA(t, *now, now.Add(365*24*time.Hour)))
	found = originPullConditions(p)
	if len(found) != 2 || found[1].Subject != "www.example.com" || found[1].Severity != state.SeverityWarning {
		t.Fatalf("the old CA still warns beside a newer one: %+v", found)
	}
	for _, want := range []string{
		"www.example.com's CA " + oldFingerprint + " runs out on 2026-10-18, in 29 days",
		"if Cloudflare still presents its certificate then, the edge refuses every connection Cloudflare makes to www.example.com",
		"upload the certificate minted with a newer CA at Cloudflare",
		"once Cloudflare presents it, helios edge origin-pull forget www.example.com " + oldFingerprint + " clears this",
	} {
		if !strings.Contains(found[1].Message, want) {
			t.Fatalf("the warning should say %q: %s", want, found[1].Message)
		}
	}
	if strings.Contains(found[1].Message, "origin-pull mint") {
		t.Fatalf("a host with a newer CA needn't mint another: %s", found[1].Message)
	}

	reader.trust["www.example.com"] = reader.trust["www.example.com"][1:]
	found = originPullConditions(p)
	if len(found) != 1 || found[0].Subject != "docs.example.com" {
		t.Fatalf("forgetting the old CA quiets its host: %+v", found)
	}
}

// A rotation left half done: a newer CA is trusted, but nobody uploaded
// its certificate, so Cloudflare still presents the old one. When the old
// CA runs out the host is down in either mode, since the edge checks
// Cloudflare's certificate against the newer CA alone, and the warning
// already open says so as soon as the outage holds rather than at its
// next daily repeat. Forgetting the old CA is what clears it.
func TestAnOriginPullCAThatRunsOutBesideANewerOneIsAnOutage(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	saveOriginPullApp(t, w.Store, "docs", "docs.example.com", manifest.OriginPullOptional, now.Add(-time.Hour))
	// Hours before the end, so the warning was told well within the day
	// before its next repeat.
	issued := now.Add(-365 * 24 * time.Hour)
	runsOut := now.Add(12 * time.Hour)
	reader := &trustReader{trust: edge.OriginPullTrust{}}
	fingerprints := map[string]string{}
	for _, host := range []string{"www.example.com", "docs.example.com"} {
		old := testOriginPullCA(t, issued, runsOut)
		fingerprints[host] = originPullFingerprint(t, old)
		reader.trust.Trust(host, old)
		reader.trust.Trust(host, testOriginPullCA(t, *now, now.Add(365*24*time.Hour)))
	}
	p := originPullProber(t, w.Store, now, reader)
	round := func() []Condition {
		t.Helper()
		*now = now.Add(time.Minute)
		found := originPullConditions(p)
		if err := w.Round(ctx, found); err != nil {
			t.Fatal(err)
		}
		return found
	}
	told := func(subject string) int {
		n := 0
		for _, sent := range notifier.sent {
			if sent.Subject == subject {
				n++
			}
		}
		return n
	}

	for range DefaultOpenAfter {
		round()
	}
	if len(notifier.sent) != 2 || told("box: www.example.com has a problem") != 1 || told("box: docs.example.com has a problem") != 1 {
		t.Fatalf("each host warns once: %+v", notifier.sent)
	}

	*now = runsOut
	for range DefaultOpenAfter - 1 {
		round()
	}
	if len(notifier.sent) != 2 {
		t.Fatalf("the outage is told before it has held: %+v", notifier.sent)
	}
	found := round()
	if len(found) != 2 {
		t.Fatalf("both hosts are down: %+v", found)
	}
	for _, c := range found {
		if c.Severity != state.SeverityCritical {
			t.Fatalf("an old CA that ran out beside a newer one is an outage whatever the mode: %+v", c)
		}
		for _, want := range []string{
			c.Subject + "'s CA " + fingerprints[c.Subject] + " ran out on 2026-09-20",
			"if Cloudflare still presents its certificate, the edge refuses every connection Cloudflare makes to " + c.Subject,
			"upload the certificate minted with a newer CA at Cloudflare",
			"once Cloudflare presents it, helios edge origin-pull forget " + c.Subject + " " + fingerprints[c.Subject] + " clears this",
		} {
			if !strings.Contains(c.Message, want) {
				t.Fatalf("the outage should say %q: %s", want, c.Message)
			}
		}
	}
	if len(notifier.sent) != 4 || told("box: www.example.com is down") != 1 || told("box: docs.example.com is down") != 1 {
		t.Fatalf("a warning that became an outage is told as soon as the outage holds: %+v", notifier.sent)
	}
	round()
	if len(notifier.sent) != 4 {
		t.Fatalf("the outage is told once: %+v", notifier.sent)
	}

	for host := range fingerprints {
		reader.trust[host] = reader.trust[host][1:]
	}
	for range DefaultResolveAfter {
		if found := round(); len(found) != 0 {
			t.Fatalf("forgetting the old CA clears its host: %+v", found)
		}
	}
	if len(notifier.sent) != 6 || told("box: www.example.com recovered") != 1 || told("box: docs.example.com recovered") != 1 {
		t.Fatalf("both hosts recover: %+v", notifier.sent)
	}
}

// A required host whose only CA runs out goes from a warning to down, and
// the person hears that it is down once the outage has held as long as a
// new incident must, not at the warning's next daily repeat.
func TestARequiredOriginPullHostIsToldItIsDownOnceItsOutageHolds(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	runsOut := now.Add(12 * time.Hour)
	reader := &trustReader{trust: edge.OriginPullTrust{"www.example.com": {testOriginPullCA(t, now.Add(-365*24*time.Hour), runsOut)}}}
	p := originPullProber(t, w.Store, now, reader)
	round := func() {
		t.Helper()
		*now = now.Add(time.Minute)
		if err := w.Round(ctx, originPullConditions(p)); err != nil {
			t.Fatal(err)
		}
	}
	for range DefaultOpenAfter {
		round()
	}
	if len(notifier.sent) != 1 || notifier.sent[0].Subject != "box: www.example.com has a problem" {
		t.Fatalf("the expiry ahead is told as a warning: %+v", notifier.sent)
	}
	*now = runsOut
	for range DefaultOpenAfter - 1 {
		round()
	}
	if len(notifier.sent) != 1 {
		t.Fatalf("the outage is told before it has held: %+v", notifier.sent)
	}
	round()
	if len(notifier.sent) != 2 || notifier.sent[1].Subject != "box: www.example.com is down" || notifier.sent[1].Severity != state.SeverityCritical ||
		!strings.Contains(notifier.sent[1].Body, "the edge refuses every connection to www.example.com") {
		t.Fatalf("the outage is told in the round it has held: %+v", notifier.sent)
	}
}

// Trusting a CA for another host must not take out a CA that ran out
// beside a newer one: helios can't see that Cloudflare stopped presenting
// its certificate, so the outage stays open until forget takes the CA
// out, rather than closing as recovered while every connection Cloudflare
// makes is still refused.
func TestAnOriginPullOutageOutlastsTrustingAnotherCA(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	dir := t.TempDir()
	sec := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "key")}
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	runsOut := now.Add(12 * time.Hour)
	old := testOriginPullCA(t, now.Add(-365*24*time.Hour), runsOut)
	for _, ca := range []edge.OriginPullCA{old, testOriginPullCA(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))} {
		if _, err := app.TrustOriginPull(ctx, w.Store, sec, "www.example.com", ca.PEM, *now); err != nil {
			t.Fatal(err)
		}
	}
	p := originPullProber(t, w.Store, now, nil)
	p.OriginPullTrust = func() (edge.OriginPullTrust, error) { return app.LoadOriginPullTrust(sec) }
	round := func() []Condition {
		t.Helper()
		*now = now.Add(time.Minute)
		found := originPullConditions(p)
		if err := w.Round(ctx, found); err != nil {
			t.Fatal(err)
		}
		return found
	}

	*now = runsOut
	for range DefaultOpenAfter {
		round()
	}
	if len(notifier.sent) != 1 || notifier.sent[0].Subject != "box: www.example.com is down" {
		t.Fatalf("the old CA that ran out is an outage: %+v", notifier.sent)
	}
	other := testOriginPullCA(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if _, err := app.TrustOriginPull(ctx, w.Store, sec, "api.example.com", other.PEM, *now); err != nil {
		t.Fatal(err)
	}
	for range DefaultResolveAfter + 1 {
		if found := round(); len(found) != 1 || found[0].Severity != state.SeverityCritical || !strings.Contains(found[0].Message, originPullFingerprint(t, old)) {
			t.Fatalf("trusting another host's CA cleared the outage: %+v", found)
		}
	}
	if len(notifier.sent) != 1 {
		t.Fatalf("the outage was told as recovered while Cloudflare may still be refused: %+v", notifier.sent)
	}
}

// Once every CA of a host has run out, a required host is down and an
// optional one warns; a CA the edge can't use at all counts as none.
func TestAnOriginPullHostWhoseCAsRanOut(t *testing.T) {
	w, now := newWatcher(t, &fakeNotifier{})
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	saveOriginPullApp(t, w.Store, "docs", "docs.example.com", manifest.OriginPullOptional, now.Add(-time.Hour))
	saveOriginPullApp(t, w.Store, "shop", "shop.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	issued := now.Add(-400 * 24 * time.Hour)
	ranOut := func() []edge.OriginPullCA {
		return []edge.OriginPullCA{
			testOriginPullCA(t, issued, now.Add(-40*24*time.Hour)),
			testOriginPullCA(t, issued, now.Add(-2*24*time.Hour)),
		}
	}
	reader := &trustReader{trust: edge.OriginPullTrust{
		"www.example.com":  ranOut(),
		"docs.example.com": ranOut(),
		// A certificate that isn't a CA's, and a CA not valid yet.
		"shop.example.com": {
			{PEM: "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n", NotAfter: now.Add(200 * 24 * time.Hour)},
			testOriginPullCA(t, now.Add(time.Hour), now.Add(365*24*time.Hour)),
		},
	}}
	p := originPullProber(t, w.Store, now, reader)

	byHost := map[string]Condition{}
	for _, c := range originPullConditions(p) {
		byHost[c.Subject] = c
	}
	if len(byHost) != 3 {
		t.Fatalf("every host has a condition: %+v", byHost)
	}
	required := byHost["www.example.com"]
	if required.Severity != state.SeverityCritical || !strings.Contains(required.Message, "the edge refuses every connection to www.example.com: it requires origin pull, and the last CA it trusts for it ran out on 2026-09-17") {
		t.Fatalf("a required host whose CAs ran out is down: %+v", required)
	}
	optional := byHost["docs.example.com"]
	// The edge goes on refusing the expired certificate until the daemon
	// reloads it, so the warning says when it checks none.
	if optional.Severity != state.SeverityWarning || !strings.Contains(optional.Message, "the last origin-pull CA docs.example.com trusts ran out on 2026-09-17") ||
		!strings.Contains(optional.Message, "once the daemon has reloaded the edge, as it does when a CA runs out, the edge checks no certificate for docs.example.com, and until then it refuses the expired one Cloudflare presents") ||
		!strings.Contains(optional.Message, "helios edge origin-pull mint docs.example.com --out FILE") {
		t.Fatalf("an optional host whose CAs ran out warns: %+v", optional)
	}
	unusable := byHost["shop.example.com"]
	if unusable.Severity != state.SeverityCritical || !strings.Contains(unusable.Message, "none of the CAs it trusts for it is usable") {
		t.Fatalf("CAs the edge leaves out are none at all: %+v", unusable)
	}
}

// Trust that can't be read is critical for every host that sets
// origin_pull, since nothing says the edge can check Cloudflare's
// certificate. A machine where no app sets origin_pull never reads it.
func TestUnreadableOriginPullTrust(t *testing.T) {
	w, now := newWatcher(t, &fakeNotifier{})
	reader := &trustReader{err: errors.New("the origin-pull trust doesn't parse: unexpected end of JSON input")}
	p := originPullProber(t, w.Store, now, reader)
	if found := originPullConditions(p); len(found) != 0 || reader.reads != 0 {
		t.Fatalf("no app sets origin_pull, so nothing is read or said: %d reads, %+v", reader.reads, found)
	}

	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	saveOriginPullApp(t, w.Store, "docs", "docs.example.com", manifest.OriginPullOptional, now.Add(-time.Hour))
	found := originPullConditions(p)
	if len(found) != 2 || reader.reads != 1 {
		t.Fatalf("one read, one condition per host: %d reads, %+v", reader.reads, found)
	}
	effect := map[string]string{"www.example.com": "refuses every connection to www.example.com", "docs.example.com": "checks no certificate for docs.example.com"}
	// The required host goes down; the optional one is only served unchecked.
	severity := map[string]string{"www.example.com": state.SeverityCritical, "docs.example.com": state.SeverityWarning}
	for _, c := range found {
		if c.Severity != severity[c.Subject] || !strings.Contains(c.Message, "the CAs the edge trusts for origin pull can't be read: the origin-pull trust doesn't parse") || !strings.Contains(c.Message, effect[c.Subject]) {
			t.Fatalf("unreadable trust says why and what the edge does, as gravely as that is: %+v", c)
		}
	}
}

// Nothing is said where nothing would change: a host that trusts a CA no
// app asks it to check, however near its end, and an optional host that
// has no CA yet, whose edge checks nothing. That holds even for a CA that
// ran out beside a newer one, which only forget takes out of the trust:
// the edge asks such a host for no certificate, so nothing is refused.
func TestOriginPullStaysQuietWhereTheEdgeChecksNothing(t *testing.T) {
	w, now := newWatcher(t, &fakeNotifier{})
	saveOriginPullApp(t, w.Store, "docs", "docs.example.com", manifest.OriginPullOptional, now.Add(-time.Hour))
	saveOriginPullApp(t, w.Store, "old", "old.example.com", manifest.OriginPullOff, now.Add(-time.Hour))
	issued := now.Add(-360 * 24 * time.Hour)
	reader := &trustReader{trust: edge.OriginPullTrust{
		"old.example.com":    {testOriginPullCA(t, issued, now.Add(5*24*time.Hour))},
		"unused.example.com": {testOriginPullCA(t, issued, now.Add(-24*time.Hour))},
		"gone.example.com": {
			testOriginPullCA(t, issued, now.Add(-24*time.Hour)),
			testOriginPullCA(t, *now, now.Add(365*24*time.Hour)),
		},
	}}
	p := originPullProber(t, w.Store, now, reader)
	if found := originPullConditions(p); len(found) != 0 {
		t.Fatalf("no condition where the edge asks for no certificate: %+v", found)
	}
}

// When the apps' origin-pull modes can't be read, an open origin-pull
// incident is held, not resolved.
func TestUnreadableOriginPullModesHoldTheIncident(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	saveOriginPullApp(t, w.Store, "hello", "www.example.com", manifest.OriginPullRequired, now.Add(-time.Hour))
	p := originPullProber(t, w.Store, now, &trustReader{trust: edge.OriginPullTrust{}})
	round := func() []Condition {
		t.Helper()
		*now = now.Add(time.Minute)
		found := originPullConditions(p)
		if err := w.Round(ctx, found); err != nil {
			t.Fatal(err)
		}
		return found
	}
	for range DefaultOpenAfter {
		round()
	}
	if open, _ := w.Store.OpenIncidents(ctx); len(open) != 1 {
		t.Fatalf("the refused host opens an incident: %+v", open)
	}

	if err := w.Store.SaveRevision(ctx, state.Revision{App: "broken", ID: "r1", Status: state.RevisionActive, Manifest: json.RawMessage(`{"workloads": 7}`), CreatedAt: *now}); err != nil {
		t.Fatal(err)
	}
	for range DefaultResolveAfter + 2 {
		found := round()
		if len(found) != 1 || !found[0].Unknown || found[0].Key != "edge:origin-pull:www.example.com" {
			t.Fatalf("the incident is held while the modes can't be read: %+v", found)
		}
	}
	if open, _ := w.Store.OpenIncidents(ctx); len(open) != 1 || len(notifier.sent) != 1 {
		t.Fatalf("still open and told once: %d open, %+v", len(open), notifier.sent)
	}
}
