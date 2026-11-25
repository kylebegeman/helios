package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

// PublicResolver asks a public resolver directly, so a stale negative
// answer cached on the machine (from looking a name up before its record
// existed) doesn't hide a record the rest of the world already sees.
var PublicResolver = &net.Resolver{PreferGo: true, Dial: dialPublicResolver([]string{"1.1.1.1:53", "8.8.8.8:53"})}

// resolverDialTimeout leaves room for one resent SYN per resolver.
const resolverDialTimeout = 2 * time.Second

// dialPublicResolver reaches the first of servers that accepts a TCP
// connection. Over UDP every dial succeeds, so a resolver behind a lossy
// or broken path cost each query its whole timeout and the next one was
// never asked; TCP fails the dial instead and resends what the path drops.
// Each server gets an equal share of the query's time left, at most
// resolverDialTimeout, so a short resolv.conf timeout still reaches the last.
func dialPublicResolver(servers []string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var err error
		for i, server := range servers {
			d := net.Dialer{Timeout: resolverDialTimeout}
			if deadline, ok := ctx.Deadline(); ok {
				d.Timeout = min(d.Timeout, time.Until(deadline)/time.Duration(len(servers)-i))
			}
			var conn net.Conn
			if conn, err = d.DialContext(ctx, "tcp", server); err == nil {
				return conn, nil
			}
		}
		// The last server's error, like the old fallback's: one line, and
		// still a net.Error the resolver reports as a timeout.
		return nil, err
	}
}

// Resolves says whether host's DNS points at one of this machine's
// addresses, and what it points at when it doesn't.
func Resolves(ctx context.Context, host string, machineAddrs []string) (ok bool, pointsAt []string, err error) {
	ips, err := PublicResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false, nil, fmt.Errorf("%s doesn't resolve: %w", host, err)
	}
	mine := map[string]bool{}
	for _, a := range machineAddrs {
		mine[a] = true
	}
	for _, ip := range ips {
		pointsAt = append(pointsAt, ip.IP.String())
		if mine[ip.IP.String()] {
			ok = true
		}
	}
	sort.Strings(pointsAt)
	return ok, pointsAt, nil
}

// DNSProblem explains a host that doesn't point here, in plain words.
func DNSProblem(host string, pointsAt, machineAddrs []string) string {
	return fmt.Sprintf("%s points at %s; this machine is %s", host, strings.Join(pointsAt, " and "), strings.Join(machineAddrs, " and "))
}

// CertificateReady reports whether the edge at addr serves a real
// certificate for host: one that names the host, is currently valid, and
// chains to a trusted authority.
func CertificateReady(ctx context.Context, host, addr string) (bool, string) {
	ready, why, _, _ := Certificate(ctx, host, addr)
	return ready, why
}

// Certificate looks once at what the edge at addr serves for host: whether
// it is a real certificate for the host (why not, otherwise), and when it
// runs out. found is false when nothing could be read at all, which the
// edge's own condition covers.
func Certificate(ctx context.Context, host, addr string) (ready bool, why string, expiry time.Time, found bool) {
	certs, err := Serves(ctx, &net.Dialer{Timeout: 5 * time.Second}, host, addr)
	if err != nil {
		return false, err.Error(), time.Time{}, false
	}
	return certificateReadiness(host, certs, time.Now(), nil)
}

// Serves shakes hands once with the edge at addr as host, connecting
// through dialer, and returns the certificates it served, unchecked.
func Serves(ctx context.Context, dialer *net.Dialer, host, addr string) ([]*x509.Certificate, error) {
	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // we inspect the certificate ourselves
			// A host that requires an origin-pull certificate refuses
			// this probe, which has none. Under TLS 1.3 the refusal comes
			// after the handshake has given us the server's certificate;
			// under TLS 1.2 it comes first, and there would be nothing to
			// read.
			MinVersion: tls.VersionTLS13,
		},
	}
	conn, err := tlsDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState().PeerCertificates, nil
}

// The TLS probe reads an unverified chain so a failed certificate still has
// an expiry and useful diagnostics. Readiness requires browser-equivalent
// hostname, validity and trust checks against this machine's root store.
func certificateReadiness(host string, certs []*x509.Certificate, now time.Time, roots *x509.CertPool) (ready bool, why string, expiry time.Time, found bool) {
	if len(certs) == 0 {
		return false, "no certificate", time.Time{}, false
	}
	leaf := certs[0]
	expiry = leaf.NotAfter
	switch {
	case strings.Contains(leaf.Issuer.CommonName, "Caddy Local Authority"):
		return false, "only Caddy's local certificate so far", expiry, true
	case leaf.VerifyHostname(host) != nil:
		return false, "the certificate is for " + strings.Join(leaf.DNSNames, ", "), expiry, true
	case now.After(leaf.NotAfter):
		return false, "the certificate expired " + leaf.NotAfter.Format(time.DateOnly), expiry, true
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, CurrentTime: now, Roots: roots, Intermediates: intermediates}); err != nil {
		return false, "the certificate cannot be verified: " + err.Error(), expiry, true
	}
	return true, "issued by " + leaf.Issuer.CommonName, expiry, true
}

// How a deploy waits for a host's first certificate. Caddy tries a failed
// issuance again after a minute, the issuer's staging service first, and
// when that try passes staging and then fails at the real issuer it stops
// for good: one slow answer from the issuer can leave a new host with
// nothing on the way. So a host that has gone certificateQuiet without a
// certificate, long enough for Caddy's own second try to finish, has the
// edge asked to start over, at most certificateRestarts times, and
// CertificateWait leaves the last start the room the first one had.
const (
	CertificateWait     = 5 * time.Minute
	certificateQuiet    = 90 * time.Second
	certificateRestarts = 2
	certificatePoll     = 3 * time.Second
)

// WaitCertificate polls until the edge at addr serves a real certificate
// for host, or CertificateWait runs out. restart asks the edge to begin
// managing certificates again; each time it is used, out hears why. A nil
// restart only waits.
func WaitCertificate(ctx context.Context, host, addr string, restart func(context.Context) error, out io.Writer) (string, error) {
	return certificateWait{
		limit: CertificateWait, quiet: certificateQuiet, poll: certificatePoll, restarts: certificateRestarts,
		ready:   func(ctx context.Context) (bool, string) { return CertificateReady(ctx, host, addr) },
		restart: restart,
		now:     time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		},
	}.run(ctx, host, out)
}

// certificateWait is one host's wait, with the edge and the clock as
// values so a test needs neither.
type certificateWait struct {
	limit, quiet, poll time.Duration
	restarts           int
	ready              func(context.Context) (bool, string)
	restart            func(context.Context) error
	now                func() time.Time
	sleep              func(context.Context, time.Duration) error
}

func (w certificateWait) run(ctx context.Context, host string, out io.Writer) (string, error) {
	if out == nil {
		out = io.Discard
	}
	start := w.now()
	// quietSince is when the edge last began on the certificate: the
	// switch that came before this wait, then each restart.
	quietSince, tried, asked := start, 0, 0
	var restartErr error
	for {
		ok, why := w.ready(ctx)
		if ok {
			return why, nil
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		now := w.now()
		if now.Sub(start) >= w.limit {
			err := fmt.Errorf("no certificate for %s after %s%s: %s", host, w.limit, startedOver(asked), why)
			if restartErr != nil {
				err = fmt.Errorf("%w; asking the edge to start over failed: %v", err, restartErr)
			}
			return "", err
		}
		if w.restart != nil && tried < w.restarts && now.Sub(quietSince) >= w.quiet {
			tried++
			quietSince = now
			waited := now.Sub(start).Round(time.Second)
			if restartErr = w.restart(ctx); restartErr != nil {
				fmt.Fprintf(out, "%s: no certificate after %s (%s); asking the edge to start over failed: %v\n", host, waited, why, restartErr)
			} else {
				asked++
				fmt.Fprintf(out, "%s: no certificate after %s (%s); asked the edge to start over (%d of %d)\n", host, waited, why, tried, w.restarts)
			}
		}
		if err := w.sleep(ctx, w.poll); err != nil {
			return "", err
		}
	}
}

// startedOver says, for the error of a wait that ran out, how often the
// edge began again on the way.
func startedOver(asked int) string {
	switch asked {
	case 0:
		return ""
	case 1:
		return ", though the edge was asked to start over once"
	case 2:
		return ", though the edge was asked to start over twice"
	}
	return fmt.Sprintf(", though the edge was asked to start over %d times", asked)
}
