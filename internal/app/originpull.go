package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// LoadOriginPullTrust reads the CAs the edge's origin-pull hosts trust,
// kept with the machine's other credentials so a machine backup and a
// recovery carry them.
func LoadOriginPullTrust(sec *secrets.Store) (edge.OriginPullTrust, error) {
	if sec == nil {
		return edge.OriginPullTrust{}, nil
	}
	values, _, err := sec.LoadCurrent(integration.App)
	if err != nil {
		return nil, fmt.Errorf("the origin-pull trust doesn't load: %w", err)
	}
	return edge.ParseOriginPullTrust(values[integration.OriginPullName])
}

func saveOriginPullTrust(sec *secrets.Store, t edge.OriginPullTrust) error {
	change := map[string]*string{integration.OriginPullName: nil}
	if len(t) > 0 {
		text, err := t.Encode()
		if err != nil {
			return err
		}
		change[integration.OriginPullName] = &text
	}
	_, err := sec.SetAll(integration.App, change)
	return err
}

// OriginPullModes is each host's origin-pull mode across the apps the
// machine runs, for the hosts that set one: the strictest any active
// revision asks for.
func OriginPullModes(ctx context.Context, store *state.Store) (map[string]manifest.OriginPullMode, error) {
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]manifest.OriginPullMode{}
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return nil, fmt.Errorf("revision %s/%s manifest: %w", rev.App, rev.ID, err)
		}
		for host, mode := range m.OriginPullHosts() {
			if mode.Stricter(out[host]) {
				out[host] = mode
			}
		}
	}
	return out, nil
}

// originPullOf is the mode one route's origin_pull puts its host in, read
// as manifest.OriginPullHosts reads a whole manifest: a mode this helios
// doesn't know, from a newer helios's manifest, counts as required, so the
// edge fails closed rather than open.
func originPullOf(mode manifest.OriginPullMode) manifest.OriginPullMode {
	switch mode {
	case manifest.OriginPullOff, manifest.OriginPullOptional:
		return mode
	}
	return manifest.OriginPullRequired
}

// settleOriginPull gives every route of a host that sets origin pull the
// strictest mode any of the host's routes asks for, the webhook route
// helios adds included, and the CAs the host trusts. A TLS client is
// checked per host name, not per path, so no route of a host can ask
// less of a connection than another.
func settleOriginPull(routes []edge.Route, trust edge.OriginPullTrust, now time.Time) {
	modes := map[string]manifest.OriginPullMode{}
	for _, r := range routes {
		if mode := originPullOf(manifest.OriginPullMode(r.OriginPull)); mode.Stricter(modes[r.Host]) {
			modes[r.Host] = mode
		}
	}
	cas := map[string][]string{}
	for host := range modes {
		cas[host] = trust.ClientCAs(host, now)
	}
	for i, r := range routes {
		if mode, ok := modes[r.Host]; ok {
			routes[i].OriginPull = string(mode)
			routes[i].ClientCAs = cas[r.Host]
		}
	}
}

// asksOriginPull reports whether any route sets origin pull.
func asksOriginPull(routes []edge.Route) bool {
	for _, r := range routes {
		if r.OriginPull != "" {
			return true
		}
	}
	return false
}

// requiredOriginPull is each host of m that requires origin pull once m
// runs here, with the apps that require it, m first. That is every host m
// requires it for, and every host m shares with another active app that
// does: the edge checks a host by the strictest mode any app asks of it,
// so m asking less of a shared host, or nothing, leaves it required. m's
// own active revision is the one m replaces, so it counts for nothing.
func requiredOriginPull(ctx context.Context, store *state.Store, m *manifest.Manifest) (map[string][]string, error) {
	out := map[string][]string{}
	for host, mode := range m.OriginPullHosts() {
		if mode == manifest.OriginPullRequired {
			out[host] = []string{m.App}
		}
	}
	if store == nil {
		return out, nil
	}
	mine := map[string]bool{}
	for _, host := range m.Hosts() {
		mine[host] = true
	}
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return nil, err
	}
	for _, rev := range active {
		if rev.App == m.App {
			continue
		}
		var other manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &other); err != nil {
			return nil, fmt.Errorf("revision %s/%s manifest: %w", rev.App, rev.ID, err)
		}
		for host, mode := range other.OriginPullHosts() {
			if mine[host] && mode == manifest.OriginPullRequired {
				out[host] = append(out[host], other.App)
			}
		}
	}
	return out, nil
}

// requireOriginPull says which apps in required require origin pull on
// hosts, app first: "site requires origin pull", or "site and api require
// origin pull" when a host is shared.
func requireOriginPull(app string, required map[string][]string, hosts []string) string {
	mine := false
	seen := map[string]bool{}
	var others []string
	for _, host := range hosts {
		for _, a := range required[host] {
			if a == app {
				mine = true
			} else if !seen[a] {
				seen[a] = true
				others = append(others, a)
			}
		}
	}
	sort.Strings(others)
	apps := others
	if mine {
		apps = append([]string{app}, others...)
	}
	if len(apps) == 1 {
		return apps[0] + " requires origin pull"
	}
	return strings.Join(apps[:len(apps)-1], ", ") + " and " + apps[len(apps)-1] + " require origin pull"
}

// untrustedOriginPull lists, in order, the hosts of m that require origin
// pull once m runs here and have no CA this machine's edge trusts now, and
// says which apps require it of them. The edge would refuse every
// connection to those hosts, and a deploy would wait out its certificate
// step and then switch back.
func untrustedOriginPull(ctx context.Context, store *state.Store, m *manifest.Manifest, sec *secrets.Store, now time.Time) ([]string, string, error) {
	required, err := requiredOriginPull(ctx, store, m)
	if err != nil || len(required) == 0 {
		return nil, "", err
	}
	hosts := sortedKeys(required)
	trust, err := LoadOriginPullTrust(sec)
	if err != nil {
		return nil, "", fmt.Errorf("%s on %s, and %w", requireOriginPull(m.App, required, hosts), strings.Join(hosts, ", "), err)
	}
	var untrusted []string
	for _, host := range hosts {
		if len(trust.ClientCAs(host, now)) == 0 {
			untrusted = append(untrusted, host)
		}
	}
	if len(untrusted) == 0 {
		return nil, "", nil
	}
	return untrusted, requireOriginPull(m.App, required, untrusted), nil
}

// checkOriginPullTrust refuses to deploy m while a host that requires
// origin pull once it runs has no CA the edge here trusts now.
func checkOriginPullTrust(ctx context.Context, store *state.Store, m *manifest.Manifest, sec *secrets.Store, now time.Time) error {
	untrusted, who, err := untrustedOriginPull(ctx, store, m, sec, now)
	if err != nil || len(untrusted) == 0 {
		return err
	}
	mint := "helios edge origin-pull mint " + untrusted[0] + " --out FILE"
	if len(untrusted) > 1 {
		mint = "helios edge origin-pull mint <host> --out FILE for each"
	}
	return fmt.Errorf("%s on %s, but the edge trusts no CA for it, so it would refuse every connection: run %s, upload the leaf and key at Cloudflare, and deploy with origin_pull: optional first until Cloudflare presents it",
		who, strings.Join(untrusted, ", "), mint)
}

// checkMovedOriginPullTrust refuses to move m onto this machine while a
// host that requires origin pull once it runs has no CA the edge here
// trusts now. The CA has to be the one the source trusts: a new one minted
// here would need a new leaf at Cloudflare, which the source's edge would
// refuse until cutover. then is what to do once it is trusted.
func checkMovedOriginPullTrust(ctx context.Context, store *state.Store, m *manifest.Manifest, sec *secrets.Store, now time.Time, then string) error {
	untrusted, who, err := untrustedOriginPull(ctx, store, m, sec, now)
	if err != nil || len(untrusted) == 0 {
		return err
	}
	return fmt.Errorf("%s on %s, but the edge here trusts no CA for it, so it would refuse every connection after cutover: on this machine, trust the CA the source trusts with helios edge origin-pull trust <host> (helios edge origin-pull list on the source shows it), then %s",
		who, strings.Join(untrusted, ", "), then)
}

// checkRecoveredOriginPullTrust refuses to cut recovery id over to m while
// a host that requires origin pull once it runs has no CA the edge here
// trusts now. The trust a recovery brings is the source's as it was backed
// up, so a CA can be missing from it or have run out since. With the
// source gone, nothing presents the old leaf any more, and a CA minted
// here is as good as the source's.
func checkRecoveredOriginPullTrust(ctx context.Context, store *state.Store, m *manifest.Manifest, sec *secrets.Store, now time.Time, id string) error {
	untrusted, who, err := untrustedOriginPull(ctx, store, m, sec, now)
	if err != nil || len(untrusted) == 0 {
		return err
	}
	return fmt.Errorf("%s on %s, but the edge here trusts no CA for it, so it would refuse every connection after cutover: on this machine, trust the CA the source trusts with helios edge origin-pull trust <host>, or, with the source gone, run helios edge origin-pull mint <host> --out FILE and upload the leaf and key at Cloudflare; then run helios recover cutover %s again",
		who, strings.Join(untrusted, ", "), id)
}

// OriginPullFingerprint names a CA certificate: sha256: and the hex of its
// DER's SHA-256.
func OriginPullFingerprint(caPEM string) (string, error) {
	cert, err := edge.ParseOriginPullCA(caPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// TrustOriginPull has the edge take client certificates the CA in caPEM
// signs for host, keeping the host's other CAs so a leaf being replaced at
// Cloudflare keeps working until it is, and forgetting the ones that ran
// out. It reports false when host already trusted the CA. The edge is
// reloaded either way.
func TrustOriginPull(ctx context.Context, store *state.Store, sec *secrets.Store, host, caPEM string, now time.Time) (bool, error) {
	host = strings.ToLower(host)
	if !manifest.ValidHost(host) {
		return false, fmt.Errorf("%q is not a host name", host)
	}
	cert, err := edge.ParseOriginPullCA(caPEM)
	if err != nil {
		return false, err
	}
	if !now.Before(cert.NotAfter) {
		return false, fmt.Errorf("that CA ran out on %s; mint a new one with helios edge origin-pull mint %s", cert.NotAfter.UTC().Format(time.DateOnly), host)
	}
	if now.Before(cert.NotBefore) {
		// The edge would keep it and check nothing against it until then.
		return false, fmt.Errorf("that CA isn't valid until %s; check this machine's clock", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	t, err := LoadOriginPullTrust(sec)
	if err != nil {
		return false, err
	}
	t.Prune(now)
	added := t.Trust(host, edge.OriginPullCA{PEM: strings.TrimSpace(caPEM) + "\n", NotAfter: cert.NotAfter.UTC()})
	if err := saveOriginPullTrust(sec, t); err != nil {
		return false, err
	}
	return added, ReloadEdge(ctx, store, sec)
}

// ForgetOriginPull stops host trusting the CA with fingerprint, or every
// CA it trusts when fingerprint is empty, and reloads the edge. It
// refuses to leave a host an app requires origin pull for with nothing to
// check against, since the edge would then refuse every connection to it.
// It returns how many CAs it forgot.
func ForgetOriginPull(ctx context.Context, store *state.Store, sec *secrets.Store, host, fingerprint string, now time.Time) (int, error) {
	host = strings.ToLower(host)
	t, err := LoadOriginPullTrust(sec)
	if err != nil {
		return 0, err
	}
	var kept []edge.OriginPullCA
	forgot := 0
	for _, ca := range t[host] {
		fp, _ := OriginPullFingerprint(ca.PEM)
		if fingerprint == "" || strings.EqualFold(fp, fingerprint) {
			forgot++
			continue
		}
		kept = append(kept, ca)
	}
	if forgot == 0 {
		if fingerprint == "" {
			return 0, fmt.Errorf("%s trusts no origin-pull CA", host)
		}
		return 0, fmt.Errorf("%s trusts no CA %s; helios edge origin-pull list shows the ones it does", host, fingerprint)
	}
	modes, err := OriginPullModes(ctx, store)
	if err != nil {
		return 0, err
	}
	// Forgetting a CA that ran out changes nothing the edge does, so only
	// taking away the last one it still checks against is refused.
	if modes[host] == manifest.OriginPullRequired && len(t.ClientCAs(host, now)) > 0 && len(edge.OriginPullTrust{host: kept}.ClientCAs(host, now)) == 0 {
		return 0, fmt.Errorf("%s requires origin pull, and without a CA the edge would refuse every connection to it; deploy it with origin_pull: optional or without origin_pull first", host)
	}
	if len(kept) == 0 {
		delete(t, host)
	} else {
		t[host] = kept
	}
	if err := saveOriginPullTrust(sec, t); err != nil {
		return 0, err
	}
	return forgot, ReloadEdge(ctx, store, sec)
}

// OriginPullHost is one host in helios edge origin-pull list.
type OriginPullHost struct {
	Host string                  `json:"host"`
	Mode manifest.OriginPullMode `json:"mode,omitempty"`
	CAs  []OriginPullTrustedCA   `json:"cas"`
}

// OriginPullTrustedCA is one CA a host trusts.
type OriginPullTrustedCA struct {
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
	PEM         string    `json:"ca_pem"`
}

// OriginPullStatus lists every host that sets origin pull or trusts a CA,
// in order.
func OriginPullStatus(ctx context.Context, store *state.Store, sec *secrets.Store) ([]OriginPullHost, error) {
	modes, err := OriginPullModes(ctx, store)
	if err != nil {
		return nil, err
	}
	t, err := LoadOriginPullTrust(sec)
	if err != nil {
		return nil, err
	}
	hosts := map[string]bool{}
	for h := range modes {
		hosts[h] = true
	}
	for h := range t {
		hosts[h] = true
	}
	out := make([]OriginPullHost, 0, len(hosts))
	for h := range hosts {
		row := OriginPullHost{Host: h, Mode: modes[h], CAs: []OriginPullTrustedCA{}}
		for _, ca := range t[h] {
			fp, err := OriginPullFingerprint(ca.PEM)
			if err != nil {
				fp = "unreadable: " + err.Error()
			}
			row.CAs = append(row.CAs, OriginPullTrustedCA{Fingerprint: fp, NotAfter: ca.NotAfter, PEM: ca.PEM})
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}
