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
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/manifest"
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

// The newest CA a host trusts warns 30 days before it runs out, whatever
// the mode, and a newer one minted in time quiets it.
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

	// Rotation: the new CA is trusted beside the old one, which stays
	// until it runs out.
	reader.trust.Trust("www.example.com", testOriginPullCA(t, *now, now.Add(365*24*time.Hour)))
	found = originPullConditions(p)
	if len(found) != 1 || found[0].Key != "edge:origin-pull:docs.example.com" {
		t.Fatalf("a newer CA beyond 30 days quiets only its host: %+v", found)
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
	if optional.Severity != state.SeverityWarning || !strings.Contains(optional.Message, "the last origin-pull CA docs.example.com trusts ran out on 2026-09-17") || !strings.Contains(optional.Message, "helios edge origin-pull mint docs.example.com --out FILE") {
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
// has no CA yet, whose edge checks nothing.
func TestOriginPullStaysQuietWhereTheEdgeChecksNothing(t *testing.T) {
	w, now := newWatcher(t, &fakeNotifier{})
	saveOriginPullApp(t, w.Store, "docs", "docs.example.com", manifest.OriginPullOptional, now.Add(-time.Hour))
	saveOriginPullApp(t, w.Store, "old", "old.example.com", manifest.OriginPullOff, now.Add(-time.Hour))
	issued := now.Add(-360 * 24 * time.Hour)
	reader := &trustReader{trust: edge.OriginPullTrust{
		"old.example.com":    {testOriginPullCA(t, issued, now.Add(5*24*time.Hour))},
		"unused.example.com": {testOriginPullCA(t, issued, now.Add(-24*time.Hour))},
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
