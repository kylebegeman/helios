package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// PublicResolver asks a public resolver directly, so a stale negative
// answer cached on the machine (from looking a name up before its record
// existed) doesn't hide a record the rest of the world already sees.
var PublicResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
		if err != nil {
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		}
		return conn, nil
	},
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

// WaitCertificate polls until the edge serves a real certificate for
// host, or the wait runs out.
func WaitCertificate(ctx context.Context, host, addr string, limit time.Duration) (string, error) {
	deadline := time.Now().Add(limit)
	var last string
	for {
		ok, why := CertificateReady(ctx, host, addr)
		if ok {
			return why, nil
		}
		last = why
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no certificate for %s after %s: %s", host, limit, last)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
