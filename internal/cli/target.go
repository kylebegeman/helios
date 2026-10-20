package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/kylebegeman/helios/internal/gitdeploy"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/remote"
)

func defaultTargetsFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".bedrock/targets.json"
	}
	return filepath.Join(home, ".bedrock", "targets.json")
}

func configureTargets(root *cobra.Command, a *app) {
	root.PersistentFlags().StringVar(&a.targetName, "target", "", "operate on this explicitly named SSH target")
	root.PersistentFlags().StringVar(&a.targetsFile, "targets-file", envOr("BEDROCK_TARGETS_FILE", defaultTargetsFile()), "the local named-target configuration")
	root.AddCommand(newTarget(a), newRemoteArtifact(a))
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := validateEnvironmentAliases(cmd); err != nil {
			return err
		}
		a.remoteStateFlags = make([]string, 0, 2)
		if cmd.Flags().Changed("state-dir") || a.stateDir != defaultStateDir() {
			a.remoteStateFlags = append(a.remoteStateFlags, "--state-dir="+a.stateDir)
		}
		if cmd.Flags().Changed("socket") || a.socket != "/run/bedrock/bedrock.sock" {
			a.remoteStateFlags = append(a.remoteStateFlags, "--socket="+a.socket)
		}
		if a.targetName == "" || cmd.Annotations["client-only"] == "true" {
			return nil
		}
		if cmd.Parent() != nil && cmd.Parent().Name() == "target" {
			return errors.New("target management is local; omit --target")
		}
		if cmd.Name() == "_remote-artifact" || cmd.Name() == "daemon" {
			return errors.New("this command must run directly on the machine")
		}
		return a.dispatchTarget(cmd, args)
	}
}

func newTarget(a *app) *cobra.Command {
	cmd := &cobra.Command{Use: "target", Short: "Configure explicit SSH targets with pinned host-key verification."}
	var target remote.Target
	set := &cobra.Command{Use: "set <name>", Short: "Save a named SSH connection; host keys must already be trusted.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !remote.ValidName(args[0]) {
			return errors.New("target name must start with a lowercase letter and contain lowercase letters, digits or hyphens")
		}
		if err := target.Validate(); err != nil {
			return err
		}
		c, err := remote.Load(a.targetsFile)
		if err != nil {
			return err
		}
		c.Targets[args[0]] = target
		if err := remote.Save(a.targetsFile, c); err != nil {
			return err
		}
		fmt.Fprintf(a.prose(), "Saved target %s (%s). Use --target %s explicitly.\n", args[0], target.SSH, args[0])
		return nil
	}}
	set.Flags().StringVar(&target.SSH, "ssh", "", "SSH configuration alias or user@host")
	set.Flags().IntVar(&target.Port, "port", 0, "SSH port, or use the SSH configuration")
	set.Flags().StringVar(&target.IdentityFile, "identity", "", "SSH identity file")
	set.Flags().StringVar(&target.KnownHostsFile, "known-hosts", "", "pinned known-hosts file, or the SSH default")
	set.Flags().StringVar(&target.Binary, "binary", "", "absolute path of helios on the target")
	set.Flags().BoolVar(&target.Sudo, "sudo", false, "run helios through noninteractive sudo")
	set.Flags().StringVar(&target.MachineID, "machine-id", "", "expected machine identity from capabilities")
	_ = set.MarkFlagRequired("ssh")
	list := &cobra.Command{Use: "list", Short: "List saved targets.", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		c, err := remote.Load(a.targetsFile)
		if err != nil {
			return err
		}
		if a.json {
			return json.NewEncoder(a.stdout).Encode(c)
		}
		names := make([]string, 0, len(c.Targets))
		for n := range c.Targets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(a.stdout, "%s\t%s\n", n, c.Targets[n].SSH)
		}
		if len(names) == 0 {
			fmt.Fprintln(a.stdout, "No targets. Add one with helios target set <name> --ssh user@host.")
		}
		return nil
	}}
	show := &cobra.Command{Use: "show <name>", Short: "Show a target's nonsecret connection settings.", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		t, err := a.loadTarget(args[0])
		if err != nil {
			return err
		}
		return json.NewEncoder(a.stdout).Encode(t)
	}}
	remove := &cobra.Command{Use: "remove <name>", Short: "Remove a local target entry.", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		c, err := remote.Load(a.targetsFile)
		if err != nil {
			return err
		}
		if _, ok := c.Targets[args[0]]; !ok {
			return fmt.Errorf("unknown target %q", args[0])
		}
		delete(c.Targets, args[0])
		return remote.Save(a.targetsFile, c)
	}}
	verify := &cobra.Command{Use: "verify <name>", Short: "Verify SSH and pin the machine's reported identity.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remote.Load(a.targetsFile)
		if err != nil {
			return err
		}
		t, ok := c.Targets[args[0]]
		if !ok {
			return fmt.Errorf("unknown target %q", args[0])
		}
		caps, err := a.targetCapabilities(cmd.Context(), t)
		if err != nil {
			return err
		}
		if t.MachineID != "" && t.MachineID != caps.MachineID {
			return errors.New("target machine identity changed; inspect the machine before updating its configuration")
		}
		t.MachineID = caps.MachineID
		c.Targets[args[0]] = t
		if err := remote.Save(a.targetsFile, c); err != nil {
			return err
		}
		if a.json {
			return json.NewEncoder(a.stdout).Encode(caps)
		}
		fmt.Fprintf(a.stdout, "Verified %s (%s), machine %s.\n", args[0], t.SSH, t.MachineID)
		return nil
	}}
	cmd.AddCommand(set, list, show, remove, verify)
	return cmd
}

func (a *app) loadTarget(name string) (remote.Target, error) {
	c, err := remote.Load(a.targetsFile)
	if err != nil {
		return remote.Target{}, err
	}
	t, ok := c.Targets[name]
	if !ok {
		return t, fmt.Errorf("unknown target %q; use helios target set", name)
	}
	return t, nil
}
func targetTransport() remote.Transport {
	return remote.Transport{Program: strings.Fields(envOr("BEDROCK_SSH", ""))}
}

type targetCapabilities struct {
	APIVersion      int      `json:"api_version"`
	ManifestVersion int      `json:"manifest_version"`
	StateVersion    int      `json:"state_version"`
	MachineID       string   `json:"machine_id"`
	Capabilities    []string `json:"capabilities"`
}

func (c targetCapabilities) has(name string) bool {
	for _, n := range c.Capabilities {
		if n == name {
			return true
		}
	}
	return false
}
func (a *app) targetCapabilities(ctx context.Context, t remote.Target) (targetCapabilities, error) {
	var out bytes.Buffer
	var c targetCapabilities
	err := targetTransport().Run(ctx, t, append(a.targetStateArgs(), "capabilities", "--json"), nil, &boundedBuffer{Buffer: &out, Max: 1 << 20}, a.stderr)
	if err != nil {
		return c, fmt.Errorf("target capabilities unavailable: %w; install a compatible helios on the target", err)
	}
	if err = json.Unmarshal(out.Bytes(), &c); err != nil {
		return c, fmt.Errorf("target returned invalid capabilities: %w", err)
	}
	if c.APIVersion != 1 || c.ManifestVersion != 1 || c.MachineID == "" {
		return c, errors.New("target API, manifest version or machine identity is incompatible")
	}
	if t.MachineID != "" && t.MachineID != c.MachineID {
		return c, errors.New("target machine identity changed; inspect the machine before updating its configuration")
	}
	return c, nil
}

type boundedBuffer struct {
	Buffer *bytes.Buffer
	Max    int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Buffer.Len()+len(p) > b.Max {
		return 0, errors.New("remote structured response is too large")
	}
	return b.Buffer.Write(p)
}

// remoteArguments reconstructs parsed flags without interpreting their values
// as shell code. Slice flags are expanded through their declared pflag type.
func remoteArguments(cmd *cobra.Command, args []string, omit map[string]bool) []string {
	path := strings.Fields(cmd.CommandPath())
	path = path[1:]
	var flags []string
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if omit[f.Name] || f.Name == "target" || f.Name == "targets-file" {
			return
		}
		if s, ok := f.Value.(pflag.SliceValue); ok {
			for _, v := range s.GetSlice() {
				flags = append(flags, "--"+f.Name+"="+v)
			}
		} else {
			flags = append(flags, "--"+f.Name+"="+f.Value.String())
		}
	})
	path = append(path, flags...)
	dash := cmd.ArgsLenAtDash()
	if dash >= 0 {
		path = append(path, args[:dash]...)
		path = append(path, "--")
		path = append(path, args[dash:]...)
	} else {
		path = append(path, args...)
	}
	return path
}
func (a *app) dispatchTarget(cmd *cobra.Command, args []string) error {
	t, err := a.loadTarget(a.targetName)
	if err != nil {
		return err
	}
	caps, err := a.targetCapabilities(cmd.Context(), t)
	if err != nil {
		return err
	}
	t.MachineID = caps.MachineID
	fmt.Fprintf(a.stderr, "Target %s (%s), machine %s\n", a.targetName, t.SSH, t.MachineID)
	args = append([]string{}, args...)
	omit := map[string]bool{"plan": true, "yes": true, "digest": true, "json": true, "state-dir": true, "socket": true}
	var input io.Reader = os.Stdin
	var replay []byte
	sourceHash := ""
	localSource := ""
	command := strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()+" ")
	input, err = a.targetCredentialInput(cmd.Context(), t, command, args, input)
	if err != nil {
		return err
	}
	if command == "git signers add" && len(args) == 1 {
		// A public key read here goes to the target as an argument: its
		// plan and its apply each run with their own stdin.
		key, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<10))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(key)) == "" {
			return errors.New("give the signer's public key as an argument or on stdin")
		}
		args = append(args, strings.TrimSpace(string(key)))
	}
	planOnly, _ := cmd.Flags().GetBool("plan")
	if !planOnly && (command == "move out" || command == "move rehearse" || command == "move final") {
		a.narrate = a.stderr
	}
	if command == "recover" {
		identityStdin, _ := cmd.Flags().GetBool("identity-stdin")
		identityFile, _ := cmd.Flags().GetString("identity-file")
		if identityStdin && identityFile != "" {
			return errors.New("choose either --identity-file or --identity-stdin")
		}
		if !planOnly && identityStdin && !a.yes && a.digest == "" {
			return errors.New("--identity-stdin needs --yes or an approved --digest because stdin is reserved for the identity")
		}
	}
	if command == "recover" && cmd.Flags().Changed("identity-file") {
		omit["identity-file"] = true
		if !planOnly {
			path, _ := cmd.Flags().GetString("identity-file")
			f, err := openRecoveryIdentityFile(path)
			if err != nil {
				return err
			}
			defer f.Close()
			input = f
		}
	}
	if (command == "git require-signed" || strings.HasPrefix(command, "git signers")) && !caps.has("git.signed.v1") {
		return errors.New("target does not gate deploys on signed commits; upgrade it first")
	}
	if command == "deploy" || command == "check" || command == "move stage" || command == "move test" || command == "rehearse" {
		if !caps.has("remote.source.v1") {
			return errors.New("target does not support source upload; upgrade it first")
		}
		if command == "deploy" && cmd.Flags().Changed("to") {
			return errors.New("use either --target or --to")
		}
		source := "."
		if len(args) > 0 {
			source = args[0]
		}
		localSource = source
		// The target may still use Bedrock's default filename. Bind and forward
		// the client's selection rather than letting the remote choose again.
		if command == "deploy" || command == "check" {
			name, _ := cmd.Flags().GetString("manifest")
			selected, err := manifest.ResolveFileName(source, name)
			if err != nil {
				return err
			}
			if err := cmd.Flags().Set("manifest", selected); err != nil {
				return err
			}
		}
		archive, hash, err := snapshotSource(cmd.Context(), source)
		if err != nil {
			return err
		}
		defer os.Remove(archive.Name())
		defer archive.Close()
		sourceHash = hash
		staged, err := a.uploadArtifact(cmd.Context(), t, archive, hash, "source")
		if err != nil {
			return err
		}
		if len(args) == 0 {
			args = []string{staged}
		} else {
			args[0] = staged
		}
		if command == "move stage" || command == "move test" {
			if cmd.Flags().Changed("source-commit") {
				return errors.New("--source-commit is set by named-target source transport")
			}
			if commit, err := exec.CommandContext(cmd.Context(), "git", "-C", source, "rev-parse", "HEAD").Output(); err == nil {
				omit["source-commit"] = true
				_ = cmd.Flags().Set("source-commit", strings.TrimSpace(string(commit)))
			}
		}
	} else if command == "upgrade" && len(args) == 1 {
		f, hash, err := snapshotFile(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		sourceHash = hash
		args[0], err = a.uploadArtifact(cmd.Context(), t, f, hash, "binary")
		if err != nil {
			return err
		}
	}
	if command == "move in" || command == "move stage" || command == "move test" {
		p, _ := cmd.Flags().GetString("handoff")
		if p != "" && p != "-" {
			f, openErr := os.Open(p)
			if openErr != nil {
				return openErr
			}
			replay, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
			f.Close()
			if err != nil {
				return err
			}
			if len(replay) > 1<<20 {
				return errors.New("handoff is too large")
			}
			omit["handoff"] = true
		} else {
			replay, err = io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+1))
			if err != nil {
				return err
			}
			if len(replay) > 1<<20 {
				return errors.New("handoff is too large")
			}
		}
		input = bytes.NewReader(replay)
		hash := sha256.Sum256(replay)
		sourceHash = combineArtifactHashes(sourceHash, "handoff", hex.EncodeToString(hash[:]))
	}
	var fileFlags []string
	if command == "deploy" {
		for _, flag := range []string{"restore-postgres", "restore-volume"} {
			if !cmd.Flags().Changed(flag) {
				continue
			}
			omit[flag] = true
			var values []string
			if flag == "restore-volume" {
				values, _ = cmd.Flags().GetStringArray(flag)
			} else {
				value, _ := cmd.Flags().GetString(flag)
				values = []string{value}
			}
			for _, value := range values {
				path := value
				prefix := ""
				if flag == "restore-volume" {
					name, p, ok := strings.Cut(value, "=")
					if !ok {
						return errors.New("--restore-volume expects name=file")
					}
					prefix = name + "="
					path = p
				}
				f, hash, err := snapshotBoundedFile(path, gitdeploy.MaxSource)
				if err != nil {
					return err
				}
				staged, uploadErr := a.uploadArtifact(cmd.Context(), t, f, hash, "data")
				f.Close()
				if uploadErr != nil {
					return uploadErr
				}
				sourceHash = combineArtifactHashes(sourceHash, flag+prefix, hash)
				fileFlags = append(fileFlags, "--"+flag+"="+prefix+staged)
			}
		}
	}
	argv := append(a.targetStateArgs(), remoteArguments(cmd, args, omit)...)
	argv = appendRemoteFlags(argv, fileFlags...)
	if command == "move stage" || command == "move test" {
		if commit, _ := cmd.Flags().GetString("source-commit"); commit != "" {
			argv = appendRemoteFlags(argv, "--source-commit="+commit)
		}
	}

	if command == "recover" && cmd.Flags().Changed("identity-file") && !planOnly {
		argv = appendRemoteFlags(argv, "--identity-stdin")
	}
	if command == "move in" || command == "move stage" || command == "move test" {
		argv = append(argv, "--handoff=-")
	}
	hasPlan := cmd.Flags().Lookup("plan") != nil
	if command == "move out" {
		noBackup, _ := cmd.Flags().GetBool("no-backup")
		if noBackup {
			hasPlan = false
			if a.digest != "" {
				return errors.New("move out --no-backup only reads a handoff; there is no operation digest to approve")
			}
		}
	}
	if hasPlan {
		for _, name := range []string{"kernel.plan.v1", "kernel.apply.v1", "kernel.expect.v1"} {
			if !caps.has(name) {
				return fmt.Errorf("target lacks %s; upgrade it first", name)
			}
		}
	}
	scope := remote.Binding{Target: t, SourceHash: sourceHash, StateArgs: a.targetStateArgs()}
	if command == "check" {
		var out bytes.Buffer
		err := targetTransport().Run(cmd.Context(), t, appendRemoteFlags(argv, "--json"), nil, &boundedBuffer{Buffer: &out, Max: 4 << 20}, a.stderr)
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				return remoteExit(err)
			}
		}
		var report sourceCheckReport
		if decodeErr := json.Unmarshal(out.Bytes(), &report); decodeErr != nil || report.SchemaVersion == "" {
			return errors.New("target returned an invalid source check report")
		}
		if report.HostPreflight != nil && report.HostPreflight.Plan != nil {
			report.HostPreflight.Plan.Digest = scope.ScopeDigest(report.HostPreflight.Plan.Digest)
		}
		if source, err := filepath.Abs(localSource); err == nil {
			report.Source = source
		}
		name, _ := cmd.Flags().GetString("manifest")
		if err := a.printCheckReport(report, name); err != nil {
			return err
		}
		return quietError{0}
	}
	if a.digest != "" {
		raw, err := scope.UnscopeDigest(a.digest)
		if err != nil {
			return err
		}
		argv = appendRemoteFlags(argv, "--digest="+raw)
	}
	if hasPlan && (planOnly || (!a.yes && a.digest == "" && cmd.Flags().Lookup("yes") != nil)) {
		var out bytes.Buffer
		planArgs := appendRemoteFlags(argv, "--plan", "--json")
		var planInput io.Reader
		if replay != nil {
			planInput = bytes.NewReader(replay)
		}
		if err := targetTransport().Run(cmd.Context(), t, planArgs, planInput, &boundedBuffer{Buffer: &out, Max: 4 << 20}, a.stderr); err != nil {
			return remoteExit(err)
		}
		if command == "preview prune" && strings.TrimSpace(out.String()) == "[]" {
			if a.json {
				fmt.Fprintln(a.stdout, "[]")
			} else {
				fmt.Fprintln(a.stdout, "No unpinned previews match this cleanup selection.")
			}
			return quietError{0}
		}
		var view kernel.PlanView
		if err := json.Unmarshal(out.Bytes(), &view); err != nil {
			return fmt.Errorf("target plan is not a single supported plan: %w", err)
		}
		if view.Kind == "" || view.Target == "" || view.Digest == "" || len(view.Steps) == 0 {
			return errors.New("target returned an incomplete operation plan")
		}
		raw := view.Digest
		view.Digest = scope.ScopeDigest(raw)
		a.renderer().Plan(&view)
		if planOnly {
			return quietError{0}
		}
		if !a.tty {
			return errors.New("this would change the target; add --yes or apply its target plan with --digest")
		}
		fmt.Fprint(a.narrateTo(), "Apply to "+a.targetName+"? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.ToLower(strings.TrimSpace(answer)); s != "y" && s != "yes" {
			return errors.New("not applied")
		}
		argv = appendRemoteFlags(argv, "--digest="+raw)
		if replay != nil {
			input = bytes.NewReader(replay)
		}
	}
	if a.yes && cmd.Flags().Lookup("yes") != nil {
		argv = appendRemoteFlags(argv, "--yes")
	}
	if planOnly {
		argv = appendRemoteFlags(argv, "--plan")
	}
	if a.json {
		argv = appendRemoteFlags(argv, "--json")
	}
	if err := targetTransport().Run(cmd.Context(), t, argv, input, a.stdout, a.stderr); err != nil {
		return remoteExit(err)
	}
	return quietError{0}
}
func remoteExit(err error) error {
	var ex *exec.ExitError
	if errors.As(err, &ex) {
		return quietError{ex.ExitCode()}
	}
	return err
}

// Flags must precede -- so run/exec command arguments remain untouched.
func appendRemoteFlags(args []string, flags ...string) []string {
	at := len(args)
	for i, arg := range args {
		if arg == "--" {
			at = i
			break
		}
	}
	out := append([]string{}, args[:at]...)
	out = append(out, flags...)
	return append(out, args[at:]...)
}

func combineArtifactHashes(base, name, hash string) string {
	sum := sha256.Sum256([]byte(base + "\x00" + name + "\x00" + hash))
	return hex.EncodeToString(sum[:])
}
