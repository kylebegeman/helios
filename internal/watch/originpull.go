package watch

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// originPullKey is the subject of one host's origin pull; with no host it
// is the prefix every such subject shares.
func originPullKey(host string) string { return "edge:origin-pull:" + host }

// originPull reports each host an app sets origin_pull for whose CAs the
// edge can't use, or soon can't. The edge checks the certificate
// Cloudflare presents against them, so a required host left without one
// is refused to everyone, and a CA that runs out takes the leaf minted
// with it, the one Cloudflare presents, along.
//
// Every CA a host trusts counts until it is forgotten, not only the
// newest, and only forget takes one out of the trust. helios can't see
// which leaf Cloudflare presents, and minting a new CA changes nothing
// there until its certificate is uploaded, so an old CA nearing its end
// warns even beside a newer one. One that runs out while a newer one is
// trusted beside it is critical in either mode: the edge then checks
// against the newer CA alone and refuses the old leaf, which Cloudflare
// keeps presenting, expired, until the new one replaces it. Forgetting
// the old CA once Cloudflare presents the new leaf clears either.
//
// A host that trusts a CA but that no app sets origin_pull for says
// nothing, however near its CA's end, and even with one that ran out
// beside a newer one, as when its app was removed or a CA was trusted
// ahead of the switch. The edge asks it for no certificate, so nothing
// is refused, and an alert would repeat about nothing; deploying it with
// origin_pull again brings back whatever its CAs then call for.
//
// A machine where no app sets origin_pull reads nothing but its active
// revisions.
func (p *Prober) originPull(ctx context.Context) []Condition {
	if p.OriginPullTrust == nil {
		return nil
	}
	modes, err := app.OriginPullModes(ctx, p.Store)
	if err != nil {
		return p.unobserved(ctx, originPullKey(""))
	}
	if len(modes) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(modes))
	for host := range modes {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	trust, readErr := p.OriginPullTrust()
	now := p.Now()
	var conditions []Condition
	for _, host := range hosts {
		// The edge takes a mode it doesn't know as required, and so does
		// the watch.
		required := modes[host] != manifest.OriginPullOptional
		c := Condition{Key: originPullKey(host), Subject: host}
		mint := fmt.Sprintf("run helios edge origin-pull mint %s --out FILE and upload the certificate and key it writes at Cloudflare", host)
		if readErr != nil {
			// The edge then trusts no CA for any host, rather than refuse
			// to load at all: a required host goes down, and an optional
			// one is served unchecked, as when its CAs ran out.
			effect, severity := "refuses every connection to", state.SeverityCritical
			if !required {
				effect, severity = "checks no certificate for", state.SeverityWarning
			}
			c.Severity = severity
			c.Message = fmt.Sprintf("the CAs the edge trusts for origin pull can't be read: %v; while they can't, the edge %s %s as soon as it reloads; fix that, then helios edge origin-pull list shows them", readErr, effect, host)
			conditions = append(conditions, c)
			continue
		}
		cas := trust[strings.ToLower(host)]
		usable, lapsed := originPullCAs(cas, now)
		if len(usable) > 0 {
			if rotation, found := originPullRotation(host, usable, lapsed, now, mint); found {
				conditions = append(conditions, rotation)
			}
			continue
		}
		var ranOut time.Time
		if len(lapsed) > 0 {
			ranOut = lapsed[len(lapsed)-1].notAfter
		}
		switch {
		case required && !ranOut.IsZero():
			c.Severity = state.SeverityCritical
			c.Message = fmt.Sprintf("the edge refuses every connection to %s: it requires origin pull, and the last CA it trusts for it ran out on %s, with the certificate Cloudflare presents; %s", host, ranOut.UTC().Format(time.DateOnly), mint)
		case required && len(cas) == 0:
			c.Severity = state.SeverityCritical
			c.Message = fmt.Sprintf("the edge refuses every connection to %s: it requires origin pull and trusts no CA for it; %s, or deploy it with origin_pull: optional until then", host, mint)
		case required:
			c.Severity = state.SeverityCritical
			c.Message = fmt.Sprintf("the edge refuses every connection to %s: it requires origin pull and none of the CAs it trusts for it is usable; %s", host, mint)
		case !ranOut.IsZero():
			// The daemon reloads the edge when a CA runs out, retrying
			// until it answers, and the edge then asks for no certificate
			// it can't check. Until then it still checks against the CA,
			// and refuses the expired leaf.
			c.Severity = state.SeverityWarning
			c.Message = fmt.Sprintf("the last origin-pull CA %s trusts ran out on %s, with the certificate Cloudflare presents; once the daemon has reloaded the edge, as it does when a CA runs out, the edge checks no certificate for %s, and until then it refuses the expired one Cloudflare presents; %s", host, ranOut.UTC().Format(time.DateOnly), host, mint)
		case len(cas) > 0:
			c.Severity = state.SeverityWarning
			c.Message = fmt.Sprintf("none of the origin-pull CAs %s trusts is usable, so the edge checks no certificate for it; %s", host, mint)
		default:
			// An optional host with no CA yet: the edge checks nothing for
			// it, and deploying it as required is refused until it has one.
			continue
		}
		conditions = append(conditions, c)
	}
	return conditions
}

// originPullRotation is the condition of a host the edge still has a CA
// to check against: critical for each CA that ran out while still
// trusted beside it, a warning for each that runs out within
// OriginPullWarn. found is false when neither is so.
func originPullRotation(host string, usable, lapsed []originPullCA, now time.Time, mint string) (c Condition, found bool) {
	c = Condition{Key: originPullKey(host), Subject: host, Severity: state.SeverityWarning}
	// Both cases are said plainly, since helios can't tell them apart:
	// Cloudflare still presents the old certificate, or already presents
	// a newer one and the old CA only waits to be forgotten.
	replace := func(ca originPullCA) string {
		return fmt.Sprintf("so upload the certificate minted with a newer CA at Cloudflare; once Cloudflare presents it, helios edge origin-pull forget %s %s clears this", host, ca.fingerprint)
	}
	var says []string
	for _, ca := range lapsed {
		c.Severity = state.SeverityCritical
		says = append(says, fmt.Sprintf("%s's CA %s ran out on %s: if Cloudflare still presents its certificate, the edge refuses every connection Cloudflare makes to %s, %s",
			host, ca.fingerprint, ca.notAfter.UTC().Format(time.DateOnly), host, replace(ca)))
	}
	for i, ca := range usable {
		if ca.notAfter.Sub(now) >= OriginPullWarn {
			continue
		}
		if i == len(usable)-1 {
			says = append(says, fmt.Sprintf("the newest origin-pull CA %s trusts runs out on %s, in %s, and the certificate Cloudflare presents with it: %s before then",
				host, ca.notAfter.UTC().Format(time.DateOnly), ago(now, ca.notAfter), mint))
			continue
		}
		says = append(says, fmt.Sprintf("%s's CA %s runs out on %s, in %s: if Cloudflare still presents its certificate then, the edge refuses every connection Cloudflare makes to %s, %s",
			host, ca.fingerprint, ca.notAfter.UTC().Format(time.DateOnly), ago(now, ca.notAfter), host, replace(ca)))
	}
	if len(says) == 0 {
		return Condition{}, false
	}
	c.Message = strings.Join(says, "; ")
	return c, true
}

// originPullCA is one CA a host trusts, by the fingerprint helios edge
// origin-pull forget takes, and when it runs out.
type originPullCA struct {
	fingerprint string
	notAfter    time.Time
}

// originPullCAs sorts cas into the ones the edge takes at now and the ones
// that already ran out, each oldest expiry first. The edge takes what
// edge.OriginPullTrust.ClientCAs gives it: CA certificates inside their
// validity. One that isn't a CA's certificate, or isn't valid yet, is in
// neither.
func originPullCAs(cas []edge.OriginPullCA, now time.Time) (usable, lapsed []originPullCA) {
	for _, ca := range cas {
		cert, err := edge.ParseOriginPullCA(ca.PEM)
		if err != nil || now.Before(cert.NotBefore) {
			continue
		}
		fingerprint, err := app.OriginPullFingerprint(ca.PEM)
		if err != nil {
			continue
		}
		trusted := originPullCA{fingerprint: fingerprint, notAfter: cert.NotAfter}
		if now.Before(cert.NotAfter) {
			usable = append(usable, trusted)
		} else {
			lapsed = append(lapsed, trusted)
		}
	}
	for _, list := range [][]originPullCA{usable, lapsed} {
		sort.SliceStable(list, func(i, j int) bool { return list[i].notAfter.Before(list[j].notAfter) })
	}
	return usable, lapsed
}
