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
// with it, the one Cloudflare presents, along. Only the latest CA counts:
// once a new one is minted, the old one is on its way out by design.
//
// A host that trusts a CA but that no app sets origin_pull for says
// nothing, however near its CA's end. The edge asks it for no
// certificate, so nothing changes when the CA runs out, and a warning
// would repeat daily about nothing; deploying it with origin_pull:
// required again is refused until it has a CA that hasn't run out.
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
		usable, lapsed := originPullExpiry(cas, now)
		switch {
		case !usable.IsZero():
			if usable.Sub(now) >= OriginPullWarn {
				continue
			}
			c.Severity = state.SeverityWarning
			c.Message = fmt.Sprintf("the newest origin-pull CA %s trusts runs out on %s, in %s, and the certificate Cloudflare presents with it; %s before then (the old CA stays trusted until it runs out)", host, usable.UTC().Format(time.DateOnly), ago(now, usable), mint)
		case required && !lapsed.IsZero():
			c.Severity = state.SeverityCritical
			c.Message = fmt.Sprintf("the edge refuses every connection to %s: it requires origin pull, and the last CA it trusts for it ran out on %s, with the certificate Cloudflare presents; %s", host, lapsed.UTC().Format(time.DateOnly), mint)
		case required && len(cas) == 0:
			c.Severity = state.SeverityCritical
			c.Message = fmt.Sprintf("the edge refuses every connection to %s: it requires origin pull and trusts no CA for it; %s, or deploy it with origin_pull: optional until then", host, mint)
		case required:
			c.Severity = state.SeverityCritical
			c.Message = fmt.Sprintf("the edge refuses every connection to %s: it requires origin pull and none of the CAs it trusts for it is usable; %s", host, mint)
		case !lapsed.IsZero():
			c.Severity = state.SeverityWarning
			c.Message = fmt.Sprintf("the last origin-pull CA %s trusts ran out on %s, and the certificate Cloudflare presents with it; %s", host, lapsed.UTC().Format(time.DateOnly), mint)
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

// originPullExpiry is when the latest of cas the edge takes at now runs
// out, zero when it takes none, and when the latest of those that already
// ran out did. The edge takes what edge.OriginPullTrust.ClientCAs gives
// it: CA certificates inside their validity.
func originPullExpiry(cas []edge.OriginPullCA, now time.Time) (usable, lapsed time.Time) {
	for _, ca := range cas {
		cert, err := edge.ParseOriginPullCA(ca.PEM)
		switch {
		case err != nil, now.Before(cert.NotBefore):
			// The edge leaves it out.
		case !now.Before(cert.NotAfter):
			if cert.NotAfter.After(lapsed) {
				lapsed = cert.NotAfter
			}
		case cert.NotAfter.After(usable):
			usable = cert.NotAfter
		}
	}
	return usable, lapsed
}
