package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/bootstrap"
	"github.com/kylebegeman/helios/internal/host"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

func addHostBootstrap(parent *cobra.Command, a *app) {
	var profilePath, binary, journal string
	var planOnly, resume bool
	cmd := &cobra.Command{Use: "bootstrap", Short: "Provision a named SSH target from a pinned portable profile, with resumable receipts.", Annotations: map[string]string{"client-only": "true"}, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if resume && (profilePath != "" || binary != "" || planOnly || a.digest != "") {
			return errors.New("--resume replays unfinished receipts; omit profile, binary, plan and digest")
		}
		journal, err := filepath.Abs(journal)
		if err != nil {
			return err
		}
		store, err := state.Open(filepath.Join(journal, "state.db"))
		if err != nil {
			return err
		}
		def := bootstrap.Definition{Transport: targetTransport(), Secrets: a.secretsStore(), CacheDir: filepath.Join(journal, "binaries")}
		reg := kernel.Registry{}
		reg.Add(def)
		engine := kernel.New(store, reg, fmt.Sprintf("bootstrap-%d", os.Getpid()))
		runner := &api.Local{Engine: engine, Store: store}
		local := *a
		local.targetName = ""
		local.stateDir = journal
		local.socket = ""
		if resume {
			defer runner.Close()
			count, err := runner.Recover(cmd.Context(), local.renderer().Event)
			if err != nil {
				return err
			}
			if count == 0 {
				return errors.New("no interrupted bootstrap receipt is ready to resume; an active lease must expire first")
			}
			fmt.Fprintf(local.prose(), "Recovered %d bootstrap receipt(s).\n", count)
			return nil
		}
		if a.targetName == "" || profilePath == "" {
			runner.Close()
			return errors.New("bootstrap requires --target NAME and --profile FILE")
		}
		profile, err := bootstrap.Load(profilePath)
		if err != nil {
			runner.Close()
			return err
		}
		target, err := a.loadTarget(a.targetName)
		if err != nil {
			runner.Close()
			return err
		}
		facts, err := bootstrap.Probe(cmd.Context(), targetTransport(), target)
		if err != nil {
			runner.Close()
			return err
		}
		if target.MachineID != "" && target.MachineID != facts.MachineID {
			runner.Close()
			return errors.New("bootstrap target identity does not match the pinned machine")
		}
		target.MachineID = facts.MachineID
		in := bootstrap.Input{TargetName: a.targetName, Target: target, Profile: profile, Arch: facts.Arch}
		if len(profile.Integrations) > 0 {
			in.SecretsVersion, err = a.secretsStore().Current(integration.App)
			if err != nil {
				runner.Close()
				return err
			}
			in.SecretsSHA256, err = a.secretsStore().SealedVersionSHA256(integration.App, in.SecretsVersion)
			if err != nil {
				runner.Close()
				return err
			}

		}
		if binary != "" {
			path, err := filepath.Abs(binary)
			if err != nil {
				runner.Close()
				return err
			}
			in.BinaryPath = path
			// Keep a checksum-addressed client copy for restart recovery once applying.
			if !planOnly {
				f, hash, err := snapshotFile(path)
				if err != nil {
					runner.Close()
					return err
				}
				defer f.Close()
				if hash != profile.Helios.SHA256["linux_"+facts.Arch] {
					runner.Close()
					return errors.New("local bootstrap binary does not match the profile checksum")
				}
				dir := filepath.Join(journal, "binaries")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					runner.Close()
					return err
				}
				dest := filepath.Join(dir, hash)
				if err := writeBootstrapCache(dest, f); err != nil {
					runner.Close()
					return err
				}
				in.BinaryPath = dest
			}
		}
		raw, err := json.Marshal(in)
		if err != nil {
			runner.Close()
			return err
		}
		fmt.Fprintf(a.stderr, "Bootstrap target %s (%s), machine %s\n", a.targetName, target.SSH, target.MachineID)
		return local.operateRaw(cmd.Context(), runner, bootstrap.Kind, raw, planOnly)
	}}
	cmd.Flags().StringVar(&profilePath, "profile", "", "local portable profile JSON")
	cmd.Flags().StringVar(&binary, "binary", "", "local Linux binary; must match profile version and SHA-256")
	cmd.Flags().StringVar(&journal, "journal-dir", envOr("BEDROCK_BOOTSTRAP_DIR", filepath.Join(filepath.Dir(defaultTargetsFile()), "bootstrap")), "local bootstrap receipt and recovery directory")
	cmd.Flags().BoolVar(&resume, "resume", false, "resume unfinished bootstrap receipts from the local journal")
	a.mutatingFlags(cmd, &planOnly)
	parent.AddCommand(cmd, newHostProfiles(a))
}
func newHostProfiles(a *app) *cobra.Command {
	cmd := &cobra.Command{Use: "profile", Short: "Create and validate portable nonsecret bootstrap profiles."}
	var p bootstrap.Profile
	var sums []string
	create := &cobra.Command{Use: "write <file>", Short: "Write a reusable profile with reviewed binary checksums and named integrations.", Annotations: map[string]string{"client-only": "true"}, Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if a.targetName != "" {
			return errors.New("profile write is local; omit --target")
		}
		p.Version = bootstrap.ProfileVersion
		p.Helios.SHA256 = map[string]string{}
		for _, value := range sums {
			platform, sum, ok := strings.Cut(value, "=")
			if !ok {
				return errors.New("--checksum expects linux_arm64=SHA256 or linux_amd64=SHA256")
			}
			if _, duplicate := p.Helios.SHA256[platform]; duplicate {
				return errors.New("checksum platform repeated")
			}
			p.Helios.SHA256[platform] = sum
		}
		if err := bootstrap.Save(args[0], p); err != nil {
			return err
		}
		fmt.Fprintf(a.prose(), "Wrote portable profile %s.\n", args[0])
		return nil
	}}
	create.Flags().StringVar(&p.Host.Hostname, "hostname", "", "target hostname")
	create.Flags().IntVar(&p.Host.SwapGiB, "swap", 4, "swap size in GiB")
	create.Flags().StringVar(&p.Host.Timezone, "timezone", "", "IANA timezone")
	create.Flags().StringVar(&p.Host.WebFrom, "web-from", host.WebFromAnyone, "who may reach the web: anyone or cloudflare")
	create.Flags().StringVar(&p.Helios.Version, "version", "", "exact binary version to install")
	create.Flags().StringArrayVar(&sums, "checksum", nil, "target platform=SHA256, repeatable")
	create.Flags().StringSliceVar(&p.Integrations, "integration", nil, "integrations to seal from this client's store")
	_ = create.MarkFlagRequired("hostname")
	_ = create.MarkFlagRequired("version")
	_ = create.MarkFlagRequired("checksum")
	check := &cobra.Command{Use: "check <file>", Short: "Validate and display a portable profile.", Annotations: map[string]string{"client-only": "true"}, Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if a.targetName != "" {
			return errors.New("profile check is local; omit --target")
		}
		p, err := bootstrap.Load(args[0])
		if err != nil {
			return err
		}
		return json.NewEncoder(a.stdout).Encode(p)
	}}
	cmd.AddCommand(create, check)
	return cmd
}

// Publish only complete, synced copies without following a destination symlink
// or modifying the recovery binary held open by another reader.
func writeBootstrapCache(path string, source io.Reader) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".bootstrap-cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = io.Copy(f, source); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
