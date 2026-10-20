package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/host"
	"github.com/kylebegeman/helios/internal/release"
)

func newDoctor(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check this machine and say what to fix. Changes nothing.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			facts := host.Gather(cmd.Context(), host.RealEnv(), a.socket)
			results := host.Diagnose(facts)
			if a.json {
				if err := json.NewEncoder(a.stdout).Encode(struct {
					Facts   host.Facts    `json:"facts"`
					Results []host.Result `json:"results"`
					Worst   host.Verdict  `json:"worst"`
				}{facts, results, host.Worst(results)}); err != nil {
					return err
				}
				if host.Worst(results) == host.Fail {
					return quietError{code: 1}
				}
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			for _, r := range results {
				verdict := string(r.Verdict)
				if r.Verdict != host.Pass {
					verdict = strings.ToUpper(verdict)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, verdict, r.Detail, r.Fix)
			}
			w.Flush()
			switch host.Worst(results) {
			case host.Fail:
				return errors.New("this machine has problems; see the fixes above")
			case host.Warn:
				fmt.Fprintln(a.stdout, "nothing failing; the warnings are worth fixing")
			default:
				fmt.Fprintln(a.stdout, "all good")
			}
			return nil
		},
	}
}

func newHost(a *app) *cobra.Command {
	hostCmd := &cobra.Command{
		Use:   "host",
		Short: "Set up, keep and maintain this machine.",
	}

	var (
		profile  host.Profile
		planOnly bool
	)
	setup := &cobra.Command{
		Use:   "setup",
		Short: "Turn this machine into a helios host: Docker, firewall, key-only SSH, updates, swap, registry.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if profile.Hostname == "" {
				profile.Hostname, _ = os.Hostname()
			}
			// Who may reach the web is kept unless it is given: running
			// setup again must not quietly open a machine that was closed
			// to everyone but Cloudflare.
			if !cmd.Flags().Changed("web-from") {
				if current, err := host.LoadProfile(host.RealEnv()); err == nil {
					profile.WebFrom = current.WebFrom
				}
			}
			if err := profile.Validate(); err != nil {
				return err
			}
			return a.operate(cmd.Context(), host.SetupKind, profile, planOnly)
		},
	}
	setup.Flags().StringVar(&profile.Hostname, "hostname", "", "the machine's name (default: keep the current one)")
	setup.Flags().IntVar(&profile.SwapGiB, "swap", 4, "swap file size in GiB; 0 for none")
	setup.Flags().StringVar(&profile.Timezone, "timezone", "", "IANA timezone, such as America/New_York (default: leave it)")
	setup.Flags().StringVar(&profile.WebFrom, "web-from", "", "who may reach 80 and 443: anyone, or cloudflare for Cloudflare's proxy only, which needs every route to be dns: proxied (default: keep the machine's setting, anyone on a new one)")
	a.mutatingFlags(setup, &planOnly)

	var reconcilePlan bool
	reconcile := &cobra.Command{
		Use:   "reconcile",
		Short: "Re-apply this machine's profile, repairing whatever drifted.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := host.LoadProfile(host.RealEnv())
			if err != nil {
				return err
			}
			return a.operate(cmd.Context(), host.SetupKind, p, reconcilePlan)
		},
	}
	a.mutatingFlags(reconcile, &reconcilePlan)

	var (
		maintainIn   host.MaintainInput
		maintainPlan bool
	)
	maintain := &cobra.Command{
		Use:   "maintain",
		Short: "Install updates, reboot if allowed and needed, bring everything back and check it.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.operate(cmd.Context(), host.MaintainKind, maintainIn, maintainPlan)
		},
	}
	maintain.Flags().BoolVar(&maintainIn.Reboot, "reboot", false, "reboot when the machine asks for it")
	a.mutatingFlags(maintain, &maintainPlan)

	hostCmd.AddCommand(setup, reconcile, maintain)
	addHostBootstrap(hostCmd, a)
	return hostCmd
}

func newUpgrade(a *app) *cobra.Command {
	var (
		planOnly  bool
		toVersion string
		sha256Hex string
	)
	cmd := &cobra.Command{
		Use:   "upgrade [path-to-new-helios]",
		Short: "Replace helios with a new build and restart the daemon; systemd rolls back if it can't start.",
		Long: "Replace helios with a new build and restart the daemon; systemd rolls back if it can't start.\n\n" +
			"With --version the build is downloaded from the published release and checked\n" +
			"against the SHA256SUMS beside it, which counts only when a Helios release key\n" +
			"pinned in this build signed it. A release without that signature is refused.\n" +
			"Pass --sha256 with a checksum from reviewed source to pin the build instead;\n" +
			"that also installs a release from before releases were signed.\n\n" +
			"  helios upgrade --version 0.7.15\n" +
			"  helios upgrade --version 0.7.14 --sha256 <checksum>\n" +
			"  helios upgrade /tmp/helios-new",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case len(args) == 0 && toVersion == "":
				return fmt.Errorf("say what to upgrade to: --version 0.7.4, or the path of a build already here")
			case len(args) == 1 && toVersion != "":
				return fmt.Errorf("give either a path or --version, not both")
			}
			in := host.UpgradeInput{}
			if len(args) == 1 {
				if sha256Hex != "" {
					return fmt.Errorf("--sha256 goes with --version; check a local file yourself")
				}
				abs, err := filepath.Abs(args[0])
				if err != nil {
					return err
				}
				in.Path = abs
			} else {
				if err := release.CheckVersion(toVersion); err != nil {
					return err
				}
				// Into helios's own directory, not a temporary one: the
				// daemon restarts mid-upgrade and the plan is rebuilt when
				// the operation resumes, which reads this path again.
				if err := os.MkdirAll(host.LibDir, 0o755); err != nil {
					return err
				}
				fmt.Fprintf(a.stderr, "fetching helios %s\n", toVersion)
				got, err := release.Fetch(cmd.Context(), toVersion, host.LibDir, sha256Hex)
				if err != nil {
					return err
				}
				if got.Signer != "" {
					fmt.Fprintf(a.stderr, "signed by Helios release key %s\n", got.Signer)
				} else {
					fmt.Fprintf(a.stderr, "unsigned: %s; the pinned checksum vouches for it\n", got.Unsigned)
				}
				in = host.UpgradeInput{Path: got.Path, Signer: got.Signer, Unsigned: got.Unsigned}
			}
			return a.operate(cmd.Context(), host.UpgradeKind, in, planOnly)
		},
	}
	cmd.Flags().StringVar(&toVersion, "version", "", "a published release to fetch and install, such as 0.7.4")
	cmd.Flags().StringVar(&sha256Hex, "sha256", "", "the expected checksum of that release's build for this machine")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}
