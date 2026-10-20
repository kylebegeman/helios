package edge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// Authenticated origin pulls let a host behind Cloudflare's proxy take only
// the connections that present the client certificate Cloudflare holds for
// it, so knowing the machine's address no longer gets anyone past
// Cloudflare. helios mints a CA and one leaf for the host, hands the leaf
// and its key to the person who uploads them to Cloudflare, keeps only the
// CA's certificate, and forgets the CA's key: nothing, helios included, can
// sign another certificate the edge would take.
const (
	// OriginPullOptional checks a certificate a connection presents and
	// lets one without a certificate through.
	OriginPullOptional = "optional"
	// OriginPullRequired lets through only a connection that presents a
	// certificate one of the host's CAs signed.
	OriginPullRequired = "required"
)

// OriginPullLifetime is how long a minted CA and its leaf last.
const OriginPullLifetime = 365 * 24 * time.Hour

// OriginPullCA is one CA certificate an origin-pull host trusts.
type OriginPullCA struct {
	// PEM is the CA's certificate.
	PEM string `json:"ca_pem"`
	// NotAfter is when the CA, and the leaf minted with it, run out.
	NotAfter time.Time `json:"not_after"`
}

// OriginPullTrust is the CAs each origin-pull host trusts, by lowercase
// host. A host keeps more than one while a new leaf replaces an old one
// at Cloudflare.
type OriginPullTrust map[string][]OriginPullCA

// ParseOriginPullTrust reads what Encode wrote. Empty text, or null, is
// no trust at all.
func ParseOriginPullTrust(text string) (OriginPullTrust, error) {
	t := OriginPullTrust{}
	if strings.TrimSpace(text) == "" {
		return t, nil
	}
	if err := json.Unmarshal([]byte(text), &t); err != nil {
		return nil, fmt.Errorf("the origin-pull trust doesn't parse: %w", err)
	}
	// JSON's null leaves the map nil, and Trust would then panic adding
	// to it.
	if t == nil {
		t = OriginPullTrust{}
	}
	return t, nil
}

// Encode is the trust as stored: hosts in order, each one's CAs oldest
// expiry first.
func (t OriginPullTrust) Encode() (string, error) {
	for host := range t {
		sortCAs(t[host])
	}
	b, err := json.Marshal(t)
	return string(b), err
}

// Trust adds ca to host's CAs. It reports false when the host already
// trusts that certificate.
func (t OriginPullTrust) Trust(host string, ca OriginPullCA) bool {
	host = strings.ToLower(host)
	for _, have := range t[host] {
		if samePEM(have.PEM, ca.PEM) {
			return false
		}
	}
	t[host] = append(t[host], ca)
	sortCAs(t[host])
	return true
}

// ClientCAs are host's CAs as the edge takes them, base64 DER, leaving out
// any that ran out or that isn't a CA's certificate. None means the host
// has nothing to check a client against.
func (t OriginPullTrust) ClientCAs(host string, now time.Time) []string {
	var out []string
	for _, ca := range t[strings.ToLower(host)] {
		cert, err := ParseOriginPullCA(ca.PEM)
		if err != nil || !now.Before(cert.NotAfter) || now.Before(cert.NotBefore) {
			continue
		}
		out = append(out, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	return out
}

// ParseOriginPullCA reads one PEM CA certificate, refusing anything that
// isn't one: a leaf here would trust nothing, and anything that isn't a
// certificate at all would stop the edge loading its configuration.
func ParseOriginPullCA(text string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(text)))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("give one PEM certificate, starting -----BEGIN CERTIFICATE-----")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("give one certificate, the CA's, and nothing else")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the certificate doesn't parse: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("that is not a CA's certificate; give the CA helios edge origin-pull mint made, not the leaf uploaded to Cloudflare")
	}
	return cert, nil
}

// MintedOriginPull is what a mint makes: the CA the edge keeps, and the
// leaf and its key for Cloudflare. The CA's key is gone by the time it is
// returned.
type MintedOriginPull struct {
	CA      OriginPullCA
	LeafPEM []byte
	KeyPEM  []byte
}

// MintOriginPull makes a CA for host and a client certificate it signs,
// both lasting OriginPullLifetime from now, and forgets the CA's key.
//
// The leaf is RSA-2048 with the client-auth key usage: the certificate
// type Cloudflare documents for origin pulls, and a leaf without that
// usage would be refused by the edge.
func MintOriginPull(host string, now time.Time) (*MintedOriginPull, error) {
	host = strings.ToLower(host)
	notBefore := now.Add(-time.Hour).UTC().Truncate(time.Second)
	notAfter := now.Add(OriginPullLifetime).UTC().Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caSerial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "helios origin pull CA for " + host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	leafSerial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	return &MintedOriginPull{
		CA:      OriginPullCA{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), NotAfter: ca.NotAfter},
		LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// serialNumber is a random 128-bit serial.
func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func samePEM(a, b string) bool {
	x, _ := pem.Decode([]byte(strings.TrimSpace(a)))
	y, _ := pem.Decode([]byte(strings.TrimSpace(b)))
	if x == nil || y == nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return bytes.Equal(x.Bytes, y.Bytes)
}

func sortCAs(cas []OriginPullCA) {
	sort.SliceStable(cas, func(i, j int) bool { return cas[i].NotAfter.Before(cas[j].NotAfter) })
}
