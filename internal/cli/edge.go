package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/remote"
)

// originPullCALimit bounds a CA certificate read from a file or stdin; one
// is a few kilobytes.
const originPullCALimit = 64 << 10

// newEdge is helios edge.
func newEdge(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edge",
		Short: "The edge in front of every app: which connections it takes.",
	}
	cmd.AddCommand(newEdgeOriginPull(a))
	return cmd
}

// newEdgeOriginPull is helios edge origin-pull.
func newEdgeOriginPull(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "origin-pull",
		Short: "Have a host behind Cloudflare's proxy take only the connections Cloudflare makes.",
		Long: `Have a host behind Cloudflare's proxy take only the connections Cloudflare makes.

Cloudflare presents a client certificate on every connection it makes to
the host, and the edge takes only those a CA it trusts for the host signed,
so knowing the machine's address gets nobody past Cloudflare.

  helios edge origin-pull mint shop.example.com --out shop.pem

Upload the file at Cloudflare as a per-hostname authenticated origin pull
certificate for the host, with the zone's SSL/TLS mode at Full (strict).
Deploy with origin_pull: optional on the host's routes, check that requests
through Cloudflare still succeed, then deploy with origin_pull: required.`,
	}
	mint, trust, forget := newEdgeOriginPullMint(a), newEdgeOriginPullTrust(a), newEdgeOriginPullForget(a)
	for _, mutation := range []*cobra.Command{mint, trust, forget} {
		a.guardSecretMutation(mutation, func([]string) string { return integration.App })
	}
	cmd.AddCommand(mint, trust, newEdgeOriginPullList(a), forget)
	return cmd
}

// newEdgeOriginPullMint is helios edge origin-pull mint.
func newEdgeOriginPullMint(a *app) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "mint <host>",
		Short: "Make the certificate Cloudflare presents for a host, trust its CA, and write the certificate and its key to a new file.",
		Long: `Make the certificate Cloudflare presents for a host, trust its CA, and
write the certificate and its key to a new file.

The CA and the certificate it signs last a year. The edge trusts the CA,
the file gets the certificate and then its key, readable by you alone, and
the CA's key is thrown away: nothing can sign another certificate the edge
takes, and the file holds the only copy of the key. Upload it to
Cloudflare, then delete it. With --target, the certificate is made here and
only the CA goes to the target.

Mint again to replace a certificate. The old CA stays trusted until it runs
out or helios edge origin-pull forget drops it, so the host keeps working
while Cloudflare takes the new one.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.mintOriginPull(args[0], out, func(caPEM string) (bool, error) {
				store, err := a.openState()
				if err != nil {
					return false, err
				}
				defer store.Close()
				sec := a.secretsStore()
				if err := a.ensureSecretsKey(sec); err != nil {
					return false, err
				}
				if _, err := apps.TrustOriginPull(cmd.Context(), store, sec, args[0], caPEM, time.Now()); err != nil {
					// The CA may be kept with only the edge's reload failing,
					// and then the certificate is still worth having.
					t, loadErr := apps.LoadOriginPullTrust(sec)
					return loadErr == nil && trustsCA(t, args[0], caPEM), err
				}
				return true, nil
			})
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "the new file for the certificate and its key")
	return cmd
}

// mintOriginPullOnTarget is mint under --target: the certificate and its
// key are made and written here, and the target is given only the CA.
func (a *app) mintOriginPullOnTarget(cmd *cobra.Command, t remote.Target, args []string) error {
	out, _ := cmd.Flags().GetString("out")
	err := a.mintOriginPull(args[0], out, func(caPEM string) (bool, error) {
		argv := append(a.targetStateArgs(), "edge", "origin-pull", "trust", strings.ToLower(args[0]))
		if err := targetTransport().Run(cmd.Context(), t, argv, strings.NewReader(caPEM), io.Discard, a.stderr); err != nil {
			return false, remoteExit(err)
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	return quietError{0}
}

// mintOriginPull makes host's CA and certificate, has trust keep the CA,
// and only then writes the certificate and its key to out. out is made
// before anything else, so a file already there stops the mint before
// any CA is trusted. trust reports whether it kept the CA, which it can
// have done even when it fails, if only the edge's reload did.
func (a *app) mintOriginPull(host, out string, trust func(caPEM string) (bool, error)) error {
	host = strings.ToLower(host)
	if !manifest.ValidHost(host) {
		return fmt.Errorf("%q is not a host name", host)
	}
	if out == "" || out == "-" {
		return errors.New("give --out, a new file for the certificate and key to upload to Cloudflare")
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; give --out a file that doesn't, so no key is written over", out)
	}
	if err != nil {
		return err
	}
	written := false
	defer func() {
		if !written {
			f.Close()
			os.Remove(out)
		}
	}()
	minted, err := edge.MintOriginPull(host, time.Now())
	if err != nil {
		return err
	}
	fingerprint, err := apps.OriginPullFingerprint(minted.CA.PEM)
	if err != nil {
		return err
	}
	kept, trustErr := trust(minted.CA.PEM)
	if !kept {
		if trustErr == nil {
			trustErr = errors.New("the CA wasn't trusted")
		}
		return trustErr
	}
	if err := writeOriginPull(f, minted); err != nil {
		return fmt.Errorf("%s trusts the new CA %s, but %s couldn't be written: %w; forget the CA with helios edge origin-pull forget %s %s and mint again", host, fingerprint, out, err, host, fingerprint)
	}
	written = true
	path, err := filepath.Abs(out)
	if err != nil {
		path = out
	}
	expires := minted.CA.NotAfter.UTC().Format(time.DateOnly)
	if a.json {
		if err := json.NewEncoder(a.stdout).Encode(map[string]any{"host": host, "fingerprint": fingerprint, "not_after": minted.CA.NotAfter, "file": path}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.stdout, "%s trusts a new origin-pull CA:\n  CA        %s\n  Expires   %s\n  File      %s, the certificate and then its key\n", host, fingerprint, expires, path)
	}
	fmt.Fprintf(a.prose(), `Next:
  1. At Cloudflare, under SSL/TLS, Origin Server, upload the file as a per-hostname authenticated origin pull certificate and associate it with %s.
  2. Set the zone's SSL/TLS mode to Full (strict).
  3. Deploy with origin_pull: optional on %s's routes, and check that requests through Cloudflare still succeed.
  4. Then deploy with origin_pull: required.
Delete %s once it is uploaded: it holds the only copy of the key.
`, host, host, path)
	if trustErr != nil {
		return fmt.Errorf("%s trusts the new CA, but the edge didn't reload: %w; it takes the CA when it next reloads", host, trustErr)
	}
	return nil
}

// writeOriginPull writes the certificate and then its key, and makes sure
// they are on disk.
func writeOriginPull(f *os.File, minted *edge.MintedOriginPull) error {
	if _, err := f.Write(minted.LeafPEM); err != nil {
		return err
	}
	if _, err := f.Write(minted.KeyPEM); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// trustsCA reports whether t holds caPEM for host.
func trustsCA(t edge.OriginPullTrust, host, caPEM string) bool {
	want, err := apps.OriginPullFingerprint(caPEM)
	if err != nil {
		return false
	}
	for _, ca := range t[strings.ToLower(host)] {
		if fp, err := apps.OriginPullFingerprint(ca.PEM); err == nil && fp == want {
			return true
		}
	}
	return false
}

// newEdgeOriginPullTrust is helios edge origin-pull trust.
func newEdgeOriginPullTrust(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust <host> [file]",
		Short: "Trust a CA's certificate for a host, from a file or stdin, as on a machine taking a host over.",
		Long: `Trust a CA's certificate for a host, from a file or stdin, as on a machine
taking a host over. The certificate is the CA's that helios edge origin-pull
mint made, as helios edge origin-pull list --json shows it, never the one
uploaded to Cloudflare.

  helios edge origin-pull trust shop.example.com ca.pem`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := strings.ToLower(args[0])
			if !manifest.ValidHost(host) {
				return fmt.Errorf("%q is not a host name", host)
			}
			path := ""
			if len(args) == 2 {
				path = args[1]
			}
			caPEM, err := readOriginPullCA(path)
			if err != nil {
				return err
			}
			cert, err := edge.ParseOriginPullCA(caPEM)
			if err != nil {
				return err
			}
			fingerprint, err := apps.OriginPullFingerprint(caPEM)
			if err != nil {
				return err
			}
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			sec := a.secretsStore()
			if err := a.ensureSecretsKey(sec); err != nil {
				return err
			}
			added, err := apps.TrustOriginPull(cmd.Context(), store, sec, host, caPEM, time.Now())
			if err != nil {
				return err
			}
			if !added {
				fmt.Fprintf(a.stdout, "%s already trusts CA %s\n", host, fingerprint)
				return nil
			}
			fmt.Fprintf(a.stdout, "%s trusts CA %s, until %s\n", host, fingerprint, cert.NotAfter.UTC().Format(time.DateOnly))
			return nil
		},
	}
	return cmd
}

// readOriginPullCA reads a CA certificate from path, or from stdin when
// path is empty or -.
func readOriginPullCA(path string) (string, error) {
	var r io.Reader
	if path == "" || path == "-" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return "", errors.New("pipe the CA's certificate in, or give its file")
		}
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, originPullCALimit+1))
	if err != nil {
		return "", err
	}
	if len(b) > originPullCALimit {
		return "", errors.New("that is too large to be one CA's certificate")
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", errors.New("no certificate was given; pipe the CA's certificate in, or give its file")
	}
	return string(b), nil
}

// newEdgeOriginPullList is helios edge origin-pull list.
func newEdgeOriginPullList(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the hosts that use origin pull, their mode, and the CAs they trust until when.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			hosts, err := apps.OriginPullStatus(cmd.Context(), store, a.secretsStore())
			if err != nil {
				return err
			}
			now := time.Now()
			if a.json {
				type row struct {
					apps.OriginPullHost
					// ValidCAs is how many CAs the edge checks the host's
					// connections against: none for a required host means
					// the edge refuses every connection to it.
					ValidCAs int `json:"valid_cas"`
				}
				out := make([]row, 0, len(hosts))
				for _, h := range hosts {
					out = append(out, row{h, validOriginPullCAs(h, now)})
				}
				return json.NewEncoder(a.stdout).Encode(out)
			}
			if len(hosts) == 0 {
				fmt.Fprintln(a.stdout, "no host uses origin pull; helios edge origin-pull mint <host> --out FILE makes a certificate for one")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "HOST\tMODE\tCA\tEXPIRES")
			var notes []string
			for _, h := range hosts {
				mode := string(h.Mode)
				if mode == "" {
					mode = "off"
				}
				if len(h.CAs) == 0 {
					fmt.Fprintf(w, "%s\t%s\tnone\t-\n", h.Host, mode)
				}
				for _, ca := range h.CAs {
					expires := ca.NotAfter.UTC().Format(time.DateOnly)
					if !now.Before(ca.NotAfter) {
						expires += " (ran out)"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", h.Host, mode, ca.Fingerprint, expires)
				}
				if validOriginPullCAs(h, now) > 0 {
					continue
				}
				switch h.Mode {
				case manifest.OriginPullOff:
				case manifest.OriginPullOptional:
					notes = append(notes, fmt.Sprintf("%s checks no certificate yet: it trusts no CA that is still good", h.Host))
				default:
					notes = append(notes, fmt.Sprintf("%s requires origin pull and trusts no CA that is still good, so the edge refuses every connection to it; helios edge origin-pull mint %s --out FILE makes one", h.Host, h.Host))
				}
			}
			if err := w.Flush(); err != nil {
				return err
			}
			for _, note := range notes {
				fmt.Fprintln(a.stdout, note)
			}
			return nil
		},
	}
}

// validOriginPullCAs is how many of h's CAs the edge would check a
// connection against now.
func validOriginPullCAs(h apps.OriginPullHost, now time.Time) int {
	cas := make([]edge.OriginPullCA, 0, len(h.CAs))
	for _, ca := range h.CAs {
		cas = append(cas, edge.OriginPullCA{PEM: ca.PEM, NotAfter: ca.NotAfter})
	}
	return len(edge.OriginPullTrust{h.Host: cas}.ClientCAs(h.Host, now))
}

// newEdgeOriginPullForget is helios edge origin-pull forget.
func newEdgeOriginPullForget(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "forget <host> [fingerprint]",
		Short: "Stop trusting one of a host's CAs, or all of them; refused if a host that requires origin pull would be left with none.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := strings.ToLower(args[0])
			fingerprint := ""
			if len(args) == 2 {
				fingerprint = args[1]
			}
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			n, err := apps.ForgetOriginPull(cmd.Context(), store, a.secretsStore(), host, fingerprint, time.Now())
			if err != nil {
				return err
			}
			if fingerprint != "" {
				fmt.Fprintf(a.stdout, "%s no longer trusts CA %s\n", host, fingerprint)
			} else if n == 1 {
				fmt.Fprintf(a.stdout, "%s no longer trusts its CA\n", host)
			} else {
				fmt.Fprintf(a.stdout, "%s no longer trusts its %d CAs\n", host, n)
			}
			return nil
		},
	}
	return cmd
}
