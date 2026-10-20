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
// it logs.
type reloads struct {
	asked int
	fail  error
	logs  []string
}

func (r *reloads) reloader(trust *edge.OriginPullTrust, loaded time.Time) *originPullReloader {
	return &originPullReloader{
		Trust:  func() (edge.OriginPullTrust, error) { return *trust, nil },
		Reload: func(context.Context) error { r.asked++; return r.fail },
		Log:    func(format string, args ...any) { r.logs = append(r.logs, fmt.Sprintf(format, args...)) },
		loaded: loaded,
	}
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

// A daemon that couldn't give the edge its configuration at start doesn't
// know what it runs, so a CA that ran out at any time reloads it once.
// Trust that can't be read gave the edge no CA to run out.
func TestAnEdgeNotLoadedAtStartIsReloadedForACAThatRanOutBefore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	trust := edge.OriginPullTrust{}
	trust.Trust("docs.example.com", caRunningOutAt(t, "docs.example.com", now.Add(-40*24*time.Hour)))
	r := &reloads{}
	reloader := r.reloader(&trust, time.Time{})
	reloader.Tick(ctx, now)
	reloader.Tick(ctx, now.Add(time.Minute))
	if r.asked != 1 {
		t.Fatalf("one reload for a CA that ran out before the daemon started: %d", r.asked)
	}

	unread := &reloads{}
	unreadable := unread.reloader(&trust, time.Time{})
	unreadable.Trust = func() (edge.OriginPullTrust, error) { return nil, errors.New("the origin-pull trust doesn't parse") }
	unreadable.Tick(ctx, now)
	if unread.asked != 0 || len(unread.logs) != 0 {
		t.Fatalf("unreadable trust reloads nothing: %d reloads, %q", unread.asked, unread.logs)
	}
}
