package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/edge"
)

// caRunningOutAt is a CA minted for host that runs out at notAfter.
func caRunningOutAt(t *testing.T, host string, notAfter time.Time) edge.OriginPullCA {
	t.Helper()
	minted, err := edge.MintOriginPull(host, notAfter.Add(-edge.OriginPullLifetime))
	if err != nil {
		t.Fatal(err)
	}
	return minted.CA
}

// reloads counts the reloads an originPullReloader asks for and the lines
// it logs. An edge that is down doesn't answer, so it takes nothing.
type reloads struct {
	asked int
	fail  error
	down  bool
	logs  []string
}

func (r *reloads) reloader(trust *edge.OriginPullTrust, loaded time.Time) *originPullReloader {
	return &originPullReloader{
		Trust: func() (edge.OriginPullTrust, error) { return *trust, nil },
		Reload: func(context.Context) (bool, error) {
			r.asked++
			return r.fail == nil && !r.down, r.fail
		},
		Log:    r.log,
		loaded: loaded,
	}
}

func (r *reloads) log(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

// The edge keeps the CAs it was loaded with, so the daemon reloads it the
// moment one runs out: an optional host whose last CA ran out then checks
// no certificate rather than refuse the expired one Cloudflare presents.
// It reloads once for each CA, and tries a failed reload again.
func TestTheEdgeIsReloadedWhenAnOriginPullCARunsOut(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	trust := edge.OriginPullTrust{}
	trust.Trust("docs.example.com", caRunningOutAt(t, "docs.example.com", start.Add(10*time.Minute)))
	trust.Trust("www.example.com", caRunningOutAt(t, "www.example.com", start.Add(20*time.Minute)))
	trust.Trust("www.example.com", caRunningOutAt(t, "www.example.com", start.Add(365*24*time.Hour)))
	// One the edge can't read was never in its configuration.
	trust["shop.example.com"] = []edge.OriginPullCA{{PEM: "not a certificate", NotAfter: start.Add(5 * time.Minute)}}
	r := &reloads{}
	reloader := r.reloader(&trust, start)

	reloader.Tick(ctx, start.Add(9*time.Minute))
	if r.asked != 0 {
		t.Fatalf("nothing ran out yet: %d reloads", r.asked)
	}
	reloader.Tick(ctx, start.Add(10*time.Minute))
	if r.asked != 1 || len(r.logs) != 1 || !strings.Contains(r.logs[0], "reloaded the edge, since a CA it trusted ran out") {
		t.Fatalf("the edge is reloaded when docs.example.com's CA runs out: %d reloads, %q", r.asked, r.logs)
	}
	reloader.Tick(ctx, start.Add(11*time.Minute))
	if r.asked != 1 {
		t.Fatalf("a CA that ran out before the last reload asks for no other: %d reloads", r.asked)
	}

	r.fail = errors.New("the edge's admin API refused the configuration")
	reloader.Tick(ctx, start.Add(20*time.Minute))
	if r.asked != 2 || len(r.logs) != 2 || !strings.Contains(r.logs[1], "reloading the edge failed: the edge's admin API refused the configuration; trying again in a minute") {
		t.Fatalf("a failed reload says so: %d reloads, %q", r.asked, r.logs)
	}
	r.fail = nil
	reloader.Tick(ctx, start.Add(21*time.Minute))
	reloader.Tick(ctx, start.Add(22*time.Minute))
	if r.asked != 3 {
		t.Fatalf("a failed reload is tried again until it takes: %d reloads", r.asked)
	}
}

// A daemon whose edge took no configuration at start, failing or not yet
// answering, doesn't know what it runs: the edge may have booted from one
// that holds a CA that ran out while the machine was off. A CA that ran
// out at any time then reloads it once, as soon as it answers. Trust that
// can't be read gave the edge no CA to run out.
func TestAnEdgeNotLoadedAtStartIsReloadedOnceItAnswersForACAThatRanOutBefore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	trust := edge.OriginPullTrust{}
	trust.Trust("docs.example.com", caRunningOutAt(t, "docs.example.com", now.Add(-40*24*time.Hour)))
	r := &reloads{}
	notAnswering := func() (bool, error) { return false, nil }
	reloader := r.reloader(&trust, edgeLoadedAtStart(now, notAnswering, r.log))
	r.down = true
	reloader.Tick(ctx, now.Add(time.Minute))
	if r.asked != 1 || len(r.logs) != 0 {
		t.Fatalf("an edge not answering yet is asked and says nothing: %d reloads, %q", r.asked, r.logs)
	}
	r.down = false
	reloader.Tick(ctx, now.Add(2*time.Minute))
	reloader.Tick(ctx, now.Add(3*time.Minute))
	if r.asked != 2 || len(r.logs) != 1 || !strings.Contains(r.logs[0], "reloaded the edge") {
		t.Fatalf("one reload once the edge answers: %d reloads, %q", r.asked, r.logs)
	}

	failed := &reloads{}
	refused := func() (bool, error) { return false, errors.New("docker isn't running") }
	reloader = failed.reloader(&trust, edgeLoadedAtStart(now, refused, failed.log))
	reloader.Tick(ctx, now.Add(time.Minute))
	if failed.asked != 1 || len(failed.logs) != 2 || failed.logs[0] != "edge: docker isn't running" {
		t.Fatalf("a load that failed at start says so and reloads: %d reloads, %q", failed.asked, failed.logs)
	}

	took := &reloads{}
	tookIt := func() (bool, error) { return true, nil }
	reloader = took.reloader(&trust, edgeLoadedAtStart(now, tookIt, took.log))
	reloader.Tick(ctx, now.Add(time.Minute))
	if took.asked != 0 || len(took.logs) != 0 {
		t.Fatalf("an edge that took its configuration at start holds no CA that ran out before: %d reloads, %q", took.asked, took.logs)
	}

	unread := &reloads{}
	unreadable := unread.reloader(&trust, time.Time{})
	unreadable.Trust = func() (edge.OriginPullTrust, error) { return nil, errors.New("the origin-pull trust doesn't parse") }
	unreadable.Tick(ctx, now)
	if unread.asked != 0 || len(unread.logs) != 0 {
		t.Fatalf("unreadable trust reloads nothing: %d reloads, %q", unread.asked, unread.logs)
	}
}

// An edge that doesn't answer when a CA runs out takes nothing, so the
// daemon neither says it reloaded nor counts it loaded, and asks again
// each tick until it does.
func TestAReloadThatFindsTheEdgeNotAnsweringIsTriedAgainUntilItLoads(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	trust := edge.OriginPullTrust{}
	trust.Trust("docs.example.com", caRunningOutAt(t, "docs.example.com", start.Add(10*time.Minute)))
	r := &reloads{down: true}
	reloader := r.reloader(&trust, start)

	reloader.Tick(ctx, start.Add(10*time.Minute))
	reloader.Tick(ctx, start.Add(11*time.Minute))
	if r.asked != 2 || len(r.logs) != 0 {
		t.Fatalf("an edge not answering is asked again and no reload is claimed: %d reloads, %q", r.asked, r.logs)
	}
	r.down = false
	reloader.Tick(ctx, start.Add(12*time.Minute))
	reloader.Tick(ctx, start.Add(13*time.Minute))
	if r.asked != 3 || len(r.logs) != 1 || !strings.Contains(r.logs[0], "reloaded the edge, since a CA it trusted ran out") {
		t.Fatalf("the edge is reloaded once it answers: %d reloads, %q", r.asked, r.logs)
	}
}
