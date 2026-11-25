package edge

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// noCertificate is what a probe of Caddy reads for a host it holds no
// certificate for.
const noCertificate = "remote error: tls: internal error"

// edgeWithoutAClock is a deploy's certificate wait with no edge and no
// clock behind it: time passes only while the wait sleeps, served decides
// from the time gone and the restarts so far whether the host has its
// certificate, and restart, when set, is how the edge answers being asked
// to start over.
type edgeWithoutAClock struct {
	served      func(elapsed time.Duration, restarts int) bool
	restart     error
	elapsed     time.Duration
	restartedAt []time.Duration
	out         bytes.Buffer
}

func (e *edgeWithoutAClock) wait(ctx context.Context) (string, error) {
	start := time.Now()
	return certificateWait{
		limit: CertificateWait, quiet: certificateQuiet, poll: certificatePoll, restarts: certificateRestarts,
		ready: func(context.Context) (bool, string) {
			if e.served(e.elapsed, len(e.restartedAt)) {
				return true, "issued by Test Authority"
			}
			return false, noCertificate
		},
		restart: func(context.Context) error {
			e.restartedAt = append(e.restartedAt, e.elapsed)
			return e.restart
		},
		now:   func() time.Time { return start.Add(e.elapsed) },
		sleep: func(_ context.Context, d time.Duration) error { e.elapsed += d; return nil },
	}.run(ctx, "shop.example.com", &e.out)
}

// A host that serves its certificate is done waiting at that moment, and
// the edge is left alone: starting it over makes every app's routes load
// again, which a certificate on its way never needs.
func TestAServedCertificateEndsTheWaitWithoutStartingTheEdgeOver(t *testing.T) {
	for _, after := range []time.Duration{0, 75 * time.Second} {
		e := &edgeWithoutAClock{served: func(elapsed time.Duration, _ int) bool { return elapsed >= after }}
		why, err := e.wait(t.Context())
		if err != nil || why != "issued by Test Authority" {
			t.Fatalf("a certificate served after %s: %q, %v", after, why, err)
		}
		if e.elapsed != after || len(e.restartedAt) != 0 || e.out.Len() != 0 {
			t.Fatalf("a certificate served after %s: waited %s, started the edge over at %v, said %q", after, e.elapsed, e.restartedAt, e.out.String())
		}
	}
}

// Caddy ends a first issuance for good when its second try passes the
// issuer's staging service and then fails at the real one, about 70
// seconds in. A first deploy on 0.7.27 then waited out its whole limit
// and rolled back, and the next deploy's load of the edge had the
// certificate in four seconds.
func TestACertificateIssuedOnceTheEdgeStartsOverPasses(t *testing.T) {
	e := &edgeWithoutAClock{served: func(_ time.Duration, restarts int) bool { return restarts == 1 }}
	why, err := e.wait(t.Context())
	if err != nil || why != "issued by Test Authority" {
		t.Fatalf("the wait failed although the edge started over: %q, %v", why, err)
	}
	if !slices.Equal(e.restartedAt, []time.Duration{90 * time.Second}) {
		t.Fatalf("the edge was started over at %v, want once after 1m30s", e.restartedAt)
	}
	want := "shop.example.com: no certificate after 1m30s (" + noCertificate + "); asked the edge to start over (1 of 2)\n"
	if e.out.String() != want {
		t.Fatalf("the step said %q, want %q", e.out.String(), want)
	}
}

// A host that never gets a certificate, one whose challenge cannot reach
// the edge for instance, costs the edge two fresh starts and no more, and
// the wait still ends at its limit with what the last look found.
func TestAHostLeftWithoutACertificateStartsTheEdgeOverTwiceThenFails(t *testing.T) {
	e := &edgeWithoutAClock{served: func(time.Duration, int) bool { return false }}
	_, err := e.wait(t.Context())
	want := "no certificate for shop.example.com after 5m0s, though the edge was asked to start over twice: " + noCertificate
	if err == nil || err.Error() != want {
		t.Fatalf("the wait ended with %v, want %q", err, want)
	}
	if !slices.Equal(e.restartedAt, []time.Duration{90 * time.Second, 180 * time.Second}) || e.elapsed != CertificateWait {
		t.Fatalf("the edge was started over at %v in a wait of %s", e.restartedAt, e.elapsed)
	}
	if said := strings.Count(e.out.String(), "asked the edge to start over"); said != 2 {
		t.Fatalf("the step named %d of 2 restarts: %q", said, e.out.String())
	}
}

// An edge that cannot be asked, its admin socket gone for instance, is
// still asked no more than twice, and the failure says so rather than
// claim the edge started over.
func TestAnEdgeThatCannotStartOverIsNamedWhenTheWaitFails(t *testing.T) {
	e := &edgeWithoutAClock{served: func(time.Duration, int) bool { return false }, restart: errors.New("edge admin: no such socket")}
	_, err := e.wait(t.Context())
	want := "no certificate for shop.example.com after 5m0s: " + noCertificate + "; asking the edge to start over failed: edge admin: no such socket"
	if err == nil || err.Error() != want {
		t.Fatalf("the wait ended with %v, want %q", err, want)
	}
	if len(e.restartedAt) != certificateRestarts {
		t.Fatalf("the edge was asked %d times, want %d", len(e.restartedAt), certificateRestarts)
	}
}

// A cancelled deploy leaves the wait within its next sleep rather than at
// the end of it, and without asking anything more of the edge.
func TestACancelledCertificateWaitReturnsPromptly(t *testing.T) {
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nothingListens := gone.Addr().String()
	gone.Close()
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	began := time.Now()
	_, err = WaitCertificate(ctx, "shop.example.com", nothingListens, func(context.Context) error {
		t.Error("a cancelled wait started the edge over")
		return nil
	}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled wait ended with %v", err)
	}
	if took := time.Since(began); took >= certificatePoll {
		t.Fatalf("a cancelled wait took %s, a whole sleep of %s or more", took, certificatePoll)
	}
}

// Caddy takes a configuration identical to the one it runs as nothing to
// do, and says the load went fine, unless the request carries exactly
// this header. An ordinary load must not carry it: the daemon loads the
// edge often, and each forced load starts every app's routes again.
func TestLoadingTheEdgeAgainTellsCaddyNotToSkipAnUnchangedConfiguration(t *testing.T) {
	var cacheControl []string
	caddy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			t.Errorf("the edge got %s %s", r.Method, r.URL.Path)
		}
		cacheControl = append(cacheControl, strings.Join(r.Header.Values("Cache-Control"), ","))
	}))
	defer caddy.Close()
	admin := &Admin{Base: caddy.URL, http: caddy.Client()}
	if err := admin.Load(t.Context(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := admin.LoadAgain(t.Context(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cacheControl, []string{"", "must-revalidate"}) {
		t.Fatalf("Cache-Control on a load and on a load again: %q", cacheControl)
	}
}
