package daemon

import (
	"context"
	"time"

	"github.com/kylebegeman/helios/internal/edge"
)

// originPullReloader reloads the edge when a CA it trusts for origin pull
// runs out. The edge takes a host's CAs as they stand when its
// configuration is built, and nothing else reloads it on a clock, so a CA
// that ran out would stay in the running configuration until the next
// deploy. An optional host whose last CA ran out would then keep refusing
// the expired certificate Cloudflare presents, rather than check none as
// the configuration built now says.
type originPullReloader struct {
	// Trust reads the CAs each host trusts.
	Trust func() (edge.OriginPullTrust, error)
	// Reload gives the edge the configuration the active revisions call
	// for now, and reports whether it took it.
	Reload func(context.Context) (bool, error)
	Log    func(format string, args ...any)
	// loaded is when the edge last took its configuration; zero when the
	// daemon doesn't know what it runs.
	loaded time.Time
}

// edgeLoadedAtStart gives the edge its configuration as the daemon starts
// at now, and returns when it counts as loaded: zero unless it took one,
// since an edge that wasn't answering yet runs the configuration it last
// took, which may hold a CA that ran out long ago.
func edgeLoadedAtStart(now time.Time, load func() (bool, error), logf func(string, ...any)) time.Time {
	loaded, err := load()
	if err != nil {
		logf("edge: %v", err)
	}
	if !loaded {
		return time.Time{}
	}
	return now
}

// Tick reloads the edge when a CA it trusts ran out after the edge was
// last loaded and by now. A reload that fails, or that finds the edge not
// answering, is tried again next tick.
func (r *originPullReloader) Tick(ctx context.Context, now time.Time) {
	trust, err := r.Trust()
	if err != nil {
		// The edge is then given no CA at all, so none can run out in
		// it, and the watch says why.
		return
	}
	if !ranOutBetween(trust, r.loaded, now) {
		return
	}
	loaded, err := r.Reload(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.Log("origin pull: a CA the edge trusts ran out, and reloading the edge failed: %v; trying again in a minute", err)
		}
		return
	}
	if !loaded {
		return
	}
	r.loaded = now
	r.Log("origin pull: reloaded the edge, since a CA it trusted ran out")
}

// ranOutBetween reports whether a CA in trust ran out after since, when
// the edge was last loaded and still took it, and by now. A CA the edge
// can't read was never in its configuration.
func ranOutBetween(trust edge.OriginPullTrust, since, now time.Time) bool {
	for _, cas := range trust {
		for _, ca := range cas {
			cert, err := edge.ParseOriginPullCA(ca.PEM)
			if err != nil {
				continue
			}
			if cert.NotAfter.After(since) && !now.Before(cert.NotAfter) {
				return true
			}
		}
	}
	return false
}
