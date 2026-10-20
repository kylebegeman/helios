package integration

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/secrets"
)

func transferStores(t *testing.T) (*secrets.Store, *secrets.Store, string) {
	t.Helper()
	one := &secrets.Store{Dir: filepath.Join(t.TempDir(), "secrets"), KeyPath: filepath.Join(t.TempDir(), "key")}
	two := &secrets.Store{Dir: filepath.Join(t.TempDir(), "secrets"), KeyPath: filepath.Join(t.TempDir(), "key")}
	if _, _, _, err := one.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	recipient, _, _, err := two.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	return one, two, recipient
}
func seedTransfer(t *testing.T, s *secrets.Store) {
	t.Helper()
	if _, _, err := Set(s, "storage", map[string]string{"kind": "s3", "endpoint": "https://objects.example.com", "key_id": "fixture", "key": "sensitive-key", "bucket_prefix": "fixture", "password": "existing-backup-password"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Set(s, "loom", map[string]string{"verify_url": "https://auth.example.com/verify"}); err != nil {
		t.Fatal(err)
	}
}
func TestIntegrationTransferPreservesPasswordScopeAndIdentity(t *testing.T) {
	source, target, recipient := transferStores(t)
	seedTransfer(t, source)
	source.Set(App, "DEPLOY_KEY_API", "private operational key")
	sealed, err := Export(source, []string{"storage", "loom"}, recipient)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sensitive-key", "existing-backup-password", "private operational key"} {
		if strings.Contains(sealed, secret) {
			t.Fatal("plaintext in transfer")
		}
	}
	stored, err := Import(target, []string{"loom", "storage"}, strings.NewReader(sealed), false)
	if err != nil || len(stored) != 2 {
		t.Fatalf("%v %v", stored, err)
	}
	got, err := Get(target, "storage")
	if err != nil || got["password"] != "existing-backup-password" {
		t.Fatalf("password changed: %v", err)
	}
	raw, version, err := target.LoadCurrent(App)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["DEPLOY_KEY_API"]; ok {
		t.Fatal("unselected operational key imported")
	}
	stored, err = Import(target, []string{"loom", "storage"}, strings.NewReader(sealed), false)
	_, same, _ := target.LoadCurrent(App)
	if err != nil || len(stored) != 0 || same != version {
		t.Fatal("import was not idempotent")
	}
	if _, err := source.ExportBundle(App, recipient); err == nil {
		t.Fatal("ordinary reserved-app transfer permitted")
	}
	if _, err := Import(target, []string{"storage"}, strings.NewReader(sealed), false); err == nil {
		t.Fatal("scope mismatch accepted")
	}
	_, other, otherRecipient := transferStores(t)
	_ = otherRecipient
	if _, err := Import(other, []string{"loom", "storage"}, strings.NewReader(sealed), false); err == nil {
		t.Fatal("wrong recipient accepted")
	}
}
func TestIntegrationTransferValidationIsAtomic(t *testing.T) {
	source, target, recipient := transferStores(t)
	seedTransfer(t, source)
	fields, _ := Get(source, "storage")
	fields["unknown"] = "do-not-log-this"
	bundle := transferBundle{Version: 1, Kind: "bedrock.integration-transfer", Expires: time.Now().Add(time.Minute), Names: []string{"loom", "storage"}, Values: map[string]map[string]string{"loom": {"verify_url": "https://auth.example.com/verify"}, "storage": fields}}
	raw, _ := json.Marshal(bundle)
	sealed, _ := secrets.SealDocument(recipient, raw)
	_, err := Import(target, bundle.Names, strings.NewReader(sealed), false)
	if err == nil || strings.Contains(err.Error(), "do-not-log-this") {
		t.Fatalf("unsafe validation: %v", err)
	}
	_, version, _ := target.LoadCurrent(App)
	if version != 0 {
		t.Fatal("invalid bundle partially changed target")
	}
	delete(fields, "unknown")
	bundle.Expires = time.Now().Add(-time.Second)
	raw, _ = json.Marshal(bundle)
	sealed, _ = secrets.SealDocument(recipient, raw)
	if _, err := Import(target, bundle.Names, strings.NewReader(sealed), false); err == nil {
		t.Fatal("expired transfer accepted")
	}
}
func TestIntegrationConflictAndRecoveryPreserveTargetConfiguration(t *testing.T) {
	source, target, recipient := transferStores(t)
	seedTransfer(t, source)
	seedTransfer(t, target)
	Set(target, "loom", map[string]string{"verify_url": "https://target.example.com/verify"})
	sealed, _ := Export(source, []string{"loom", "storage"}, recipient)
	_, version, _ := target.LoadCurrent(App)
	if _, err := Import(target, []string{"loom", "storage"}, bytes.NewBufferString(sealed), false); err == nil {
		t.Fatal("conflicting target replaced")
	}
	_, same, _ := target.LoadCurrent(App)
	if same != version {
		t.Fatal("conflict changed target")
	}
	if _, err := Import(target, []string{"loom", "storage"}, strings.NewReader(sealed), true); err != nil {
		t.Fatal(err)
	}
	Set(target, "loom", map[string]string{"verify_url": "https://target.example.com/verify"})
	target.Set(App, "DEPLOY_KEY_API", "target-key")
	source.Set(App, "DEPLOY_KEY_API", "source-key")
	source.Set(App, "WEBHOOK_SECRET_API", "source-hook")
	if _, err := RecoverMissing(target, source); err != nil {
		t.Fatal(err)
	}
	got, _ := Get(target, "loom")
	if got["verify_url"] != "https://target.example.com/verify" {
		t.Fatal("recovery changed target integration")
	}
	raw, _, _ := target.LoadCurrent(App)
	if raw["DEPLOY_KEY_API"] != "target-key" || raw["WEBHOOK_SECRET_API"] != "source-hook" {
		t.Fatal("recovery operational keys wrong")
	}
}

// A recovered machine keeps the CAs its origin-pull hosts trust: without
// them the edge would refuse every connection to a host that requires
// Cloudflare's certificate, and the CA's key is long gone, so they can't be
// minted again to match the certificate Cloudflare holds.
func TestRecoveryCarriesOriginPullTrustTheTargetLacks(t *testing.T) {
	source, target, _ := transferStores(t)
	now := time.Now()
	shop, api, www := mintedCA(t, "shop.example.com", now), mintedCA(t, "api.example.com", now), mintedCA(t, "www.example.com", now)
	setTrust(t, source, edge.OriginPullTrust{"shop.example.com": {shop}, "api.example.com": {api}})
	changed, err := RecoverMissing(target, source)
	if err != nil {
		t.Fatal(err)
	}
	got := loadTrust(t, target)
	if len(got) != 2 || !trustsOnly(got["shop.example.com"], shop) || !trustsOnly(got["api.example.com"], api) || len(changed) != 1 || changed[0] != "operational-keys" {
		t.Fatalf("trust not recovered: %v %v", caCounts(got), changed)
	}
	// A machine that trusts a host of its own, left by an app it ran once
	// or trusted ahead of the recovery, keeps it and still takes every
	// host the source trusts.
	setTrust(t, target, edge.OriginPullTrust{"www.example.com": {www}})
	if _, err := RecoverMissing(target, source); err != nil {
		t.Fatal(err)
	}
	got = loadTrust(t, target)
	if len(got) != 3 || !trustsOnly(got["www.example.com"], www) || !trustsOnly(got["shop.example.com"], shop) || !trustsOnly(got["api.example.com"], api) {
		t.Fatalf("recovery lost a host's trust: %v", caCounts(got))
	}
	// Once it trusts them all, recovering again writes nothing.
	_, version, _ := target.LoadCurrent(App)
	changed, err = RecoverMissing(target, source)
	if _, again, _ := target.LoadCurrent(App); err != nil || len(changed) != 0 || again != version {
		t.Fatalf("a recovery with nothing to add changed the target: %v %v, version %d to %d", changed, err, version, again)
	}
}

// A host both machines trust keeps the target's CA and gains the
// source's: the leaf Cloudflare presents may be either one's, and the
// edge takes a leaf any of the host's CAs signed.
func TestRecoveryAddsTheSourcesCAsBesideTheTargetsForTheSameHost(t *testing.T) {
	source, target, _ := transferStores(t)
	now := time.Now()
	ours, theirs := mintedCA(t, "shop.example.com", now), mintedCA(t, "shop.example.com", now.Add(time.Hour))
	ranOut := mintedCA(t, "shop.example.com", now.Add(-2*edge.OriginPullLifetime))
	setTrust(t, target, edge.OriginPullTrust{"shop.example.com": {ours}})
	// The source trusts the target's CA too, spaced as a hand-edited value
	// might hold it, which is still one certificate. It also trusts CAs
	// that ran out, for this host and for one it no longer serves.
	respaced := edge.OriginPullCA{PEM: "\n" + strings.TrimSpace(ours.PEM) + "\n\n", NotAfter: ours.NotAfter}
	setTrust(t, source, edge.OriginPullTrust{
		"shop.example.com": {respaced, theirs, ranOut},
		"old.example.com":  {ranOut},
	})
	if _, err := RecoverMissing(target, source); err != nil {
		t.Fatal(err)
	}
	got := loadTrust(t, target)
	if len(got) != 1 || !trustsOnly(got["shop.example.com"], ours, theirs) {
		t.Fatalf("CAs by host: %v", caCounts(got))
	}
}

// Neither value can be merged if it doesn't parse, and keeping either one
// whole is how a host's CAs get lost, so recovery stops before it changes
// anything on the target.
func TestRecoveryStopsOnOriginPullTrustThatDoesntParse(t *testing.T) {
	source, target, _ := transferStores(t)
	Set(source, "loom", map[string]string{"verify_url": "https://auth.example.com/verify"})
	source.Set(App, OriginPullName, "{not json")
	if _, err := RecoverMissing(target, source); err == nil || !strings.Contains(err.Error(), "the source's origin-pull trust") {
		t.Fatalf("err %v", err)
	}
	if _, version, _ := target.LoadCurrent(App); version != 0 {
		t.Fatal("a source trust that doesn't parse partly changed the target")
	}
	setTrust(t, source, edge.OriginPullTrust{"shop.example.com": {mintedCA(t, "shop.example.com", time.Now())}})
	target.Set(App, OriginPullName, "[")
	_, before, _ := target.LoadCurrent(App)
	if _, err := RecoverMissing(target, source); err == nil || !strings.Contains(err.Error(), "this machine's origin-pull trust") {
		t.Fatalf("err %v", err)
	}
	if raw, after, _ := target.LoadCurrent(App); after != before || raw[OriginPullName] != "[" {
		t.Fatalf("a target trust that doesn't parse was changed: %q, version %d to %d", raw[OriginPullName], before, after)
	}
	// With no CA to add, the target's value is no reason to stop.
	source.SetAll(App, map[string]*string{OriginPullName: nil})
	if _, err := RecoverMissing(target, source); err != nil {
		t.Fatal(err)
	}
	if got, err := Get(target, "loom"); err != nil || got["verify_url"] != "https://auth.example.com/verify" {
		t.Fatalf("loom not recovered: %v", err)
	}
}

// mintedCA is a CA helios edge origin-pull mint makes for host, lasting a
// year from now.
func mintedCA(t *testing.T, host string, now time.Time) edge.OriginPullCA {
	t.Helper()
	minted, err := edge.MintOriginPull(host, now)
	if err != nil {
		t.Fatal(err)
	}
	return minted.CA
}

func setTrust(t *testing.T, s *secrets.Store, trust edge.OriginPullTrust) {
	t.Helper()
	text, err := trust.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(App, OriginPullName, text); err != nil {
		t.Fatal(err)
	}
}

func loadTrust(t *testing.T, s *secrets.Store) edge.OriginPullTrust {
	t.Helper()
	raw, _, err := s.LoadCurrent(App)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := edge.ParseOriginPullTrust(raw[OriginPullName])
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

// caCounts is how many CAs each host trusts, for a failure message that
// doesn't print every certificate.
func caCounts(trust edge.OriginPullTrust) map[string]int {
	out := map[string]int{}
	for host, cas := range trust {
		out[host] = len(cas)
	}
	return out
}

// trustsOnly reports whether have is exactly want, in order.
func trustsOnly(have []edge.OriginPullCA, want ...edge.OriginPullCA) bool {
	if len(have) != len(want) {
		return false
	}
	for i := range want {
		if have[i].PEM != want[i].PEM {
			return false
		}
	}
	return true
}
