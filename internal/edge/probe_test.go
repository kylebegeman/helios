package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
)

func TestCertificateReadinessRequiresAValidTrustedChain(t *testing.T) {
	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := int64(0)
	issue := func(template, parent *x509.Certificate) *x509.Certificate {
		t.Helper()
		serial++
		template.SerialNumber = big.NewInt(serial)
		if parent == nil {
			parent = template
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	root := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "Test Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, nil)
	intermediate := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "Test Intermediate"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, root)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leaf := func(host string, before, after time.Time) *x509.Certificate {
		return issue(&x509.Certificate{Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: before, NotAfter: after}, intermediate)
	}
	valid := leaf("site.example.com", now.Add(-time.Minute), now.Add(time.Minute))
	cases := []struct {
		name  string
		certs []*x509.Certificate
		roots *x509.CertPool
		want  bool
	}{
		{"trusted with intermediate", []*x509.Certificate{valid, intermediate}, roots, true},
		{"untrusted issuer", []*x509.Certificate{valid, intermediate}, x509.NewCertPool(), false},
		{"missing intermediate", []*x509.Certificate{valid}, roots, false},
		{"not valid yet", []*x509.Certificate{leaf("site.example.com", now.Add(time.Minute), now.Add(time.Hour)), intermediate}, roots, false},
		{"expired", []*x509.Certificate{leaf("site.example.com", now.Add(-time.Hour), now.Add(-time.Minute)), intermediate}, roots, false},
		{"other host", []*x509.Certificate{leaf("other.example.com", now.Add(-time.Minute), now.Add(time.Minute)), intermediate}, roots, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, why, expiry, found := certificateReadiness("site.example.com", tt.certs, now, tt.roots)
			if got != tt.want || !found || expiry.IsZero() || why == "" {
				t.Fatalf("ready=%t, why=%q, expiry=%s, found=%t", got, why, expiry, found)
			}
		})
	}
}

// A host that requires an origin-pull certificate refuses the probe, which
// presents none, yet a deploy still waits on, and the watch still reads,
// the certificate it serves. The server here settles for TLS 1.2 whenever
// a client offers it, where the refusal would come before the probe saw
// anything.
func TestTheProbeReadsTheCertificateOfAHostThatRequiresOne(t *testing.T) {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pull.example.com"},
		DNSNames: []string{"pull.example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour).Truncate(time.Second)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := MintOriginPull("pull.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseOriginPullCA(minted.CA.PEM)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca)
	server := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			config := server.Clone()
			if slices.Contains(hello.SupportedVersions, tls.VersionTLS12) {
				config.MaxVersion = tls.VersionTLS12
			}
			return config, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	refused := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			refused <- err
			return
		}
		defer conn.Close()
		refused <- conn.(*tls.Conn).Handshake()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready, why, expiry, found := Certificate(ctx, "pull.example.com", listener.Addr().String())
	if !found || !expiry.Equal(template.NotAfter) {
		t.Fatalf("the probe read nothing: ready=%t, why=%q, expiry=%s, found=%t", ready, why, expiry, found)
	}
	if err := <-refused; err == nil {
		t.Fatal("the server took a connection without a client certificate")
	}
}

// The production path to 1.1.1.1 dropped about one packet in eight on
// 2026-11-21, and 1.0.0.1 answered nothing at all. A resolver that can't
// be reached has to hand over to the next one within a query's timeout.
func TestPublicResolverMovesOnFromAnUnreachableResolver(t *testing.T) {
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := gone.Addr().String()
	gone.Close()
	want := net.IPv4(192, 0, 2, 10)
	r := &net.Resolver{PreferGo: true, Dial: dialPublicResolver([]string{unreachable, serveDNS(t, want)})}
	ips, err := r.LookupIPAddr(t.Context(), "site.example.com")
	if err != nil {
		t.Fatalf("lookup through the second resolver failed: %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(want) {
		t.Fatalf("lookup = %v, want %v", ips, want)
	}
}

// serveDNS answers DNS over TCP on loopback: every A question with addr,
// any other question with no records.
func serveDNS(t *testing.T, addr net.IP) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				conn.Write(dnsAnswer(query, addr))
			}()
		}
	}()
	return l.Addr().String()
}

// dnsAnswer builds a length-prefixed reply that repeats query's header and
// question, dropping its EDNS record.
func dnsAnswer(query []byte, addr net.IP) []byte {
	end := 12
	for query[end] != 0 {
		end += int(query[end]) + 1
	}
	end += 5 // the root label, then the question's type and class
	msg := slices.Clone(query[:end])
	msg[2], msg[3] = 0x81, 0x80 // a response, recursion desired and available, no error
	clear(msg[6:12])            // no answer, authority or additional records yet
	if binary.BigEndian.Uint16(query[end-4:]) == 1 {
		msg[7] = 1
		msg = append(msg, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		msg = append(msg, addr.To4()...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}
