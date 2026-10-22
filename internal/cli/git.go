package cli

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/gitdeploy"
	"github.com/kylebegeman/helios/internal/host"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/remote"
	"github.com/kylebegeman/helios/internal/state"
)

func newGit(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git",
		Short: "Deploy by pushing: which keys may push which apps, remotes, and GitHub webhooks.",
	}
	cmd.AddCommand(newGitAllow(a), newGitDeny(a), newGitKeys(a), newGitSigners(a), newGitRequireSigned(a), newGitRemote(a), newGitBranch(a), newGitWebhook(a), newGitWebhooks(a), newGitServe(a), newGitHook(a))
	return cmd
}

// newGitSigners is helios git signers.
func newGitSigners(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signers",
		Short: "The SSH keys whose signed commits may deploy an app that requires signed commits.",
	}
	cmd.AddCommand(newGitSignersAdd(a), newGitSignersRemove(a), newGitSignersList(a))
	return cmd
}

// newGitSignersAdd is helios git signers add.
func newGitSignersAdd(a *app) *cobra.Command {
	var planOnly bool
	cmd := &cobra.Command{
		Use:   "add <name> [public key]",
		Short: "Allow an SSH key to sign the commits an app that requires signed commits deploys. The key comes from the argument or stdin.",
		Long: `Allow an SSH key to sign the commits an app that requires signed commits deploys.
The key comes from the argument or stdin. The name is one word, such as an
email address, and is what a refusal and a receipt show.

This is a signing key, not a push key: helios git allow says who may push,
and this says whose signature a pushed commit must carry. Give it the
public half of a key a person holds, never one an agent or CI can use.

  helios git signers add kyle@example.com "$(cat ~/.ssh/id_ed25519.pub)"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			text := strings.Join(args[1:], " ")
			if text == "" {
				// stdin holds the key, so it can't also answer the prompt.
				if !planOnly && !a.yes && a.digest == "" {
					return errors.New("a key on stdin needs --yes or an approved --digest, because stdin can't also answer the prompt; or give the key as an argument")
				}
				b, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<10))
				if err != nil {
					return err
				}
				text = string(b)
			}
			return a.operate(cmd.Context(), gitdeploy.SignersAddKind, gitdeploy.SignersAddInput{Principal: args[0], Key: strings.TrimSpace(text), By: requester()}, planOnly)
		},
	}
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

// newGitSignersRemove is helios git signers remove.
func newGitSignersRemove(a *app) *cobra.Command {
	var planOnly bool
	cmd := &cobra.Command{
		Use:   "remove <name, fingerprint or public key>",
		Short: "Stop a signer's commits from deploying; a name removes every key it signs with.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), gitdeploy.SignersRemoveKind, gitdeploy.SignersRemoveInput{Signer: strings.Join(args, " "), By: requester()}, planOnly)
		},
	}
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

// newGitSignersList is helios git signers list.
func newGitSignersList(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the allowed signers, and the apps that deploy only signed commits.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			p, err := gitdeploy.ReadPolicy(gitdeploy.SigningDir)
			if err != nil {
				return err
			}
			if a.json {
				type row struct {
					Principal   string `json:"principal"`
					Type        string `json:"type"`
					Fingerprint string `json:"fingerprint"`
					Options     string `json:"options,omitempty"`
				}
				out := struct {
					Signers       []row    `json:"signers"`
					HandWritten   int      `json:"hand_written,omitempty"`
					RequireSigned []string `json:"require_signed"`
				}{Signers: []row{}, HandWritten: len(p.Others), RequireSigned: append([]string{}, p.RequireSigned...)}
				for _, s := range p.Signers {
					out.Signers = append(out.Signers, row{s.Principal, s.Type, s.Fingerprint(), s.Options})
				}
				return json.NewEncoder(a.stdout).Encode(out)
			}
			if len(p.Signers) == 0 && len(p.Others) == 0 {
				fmt.Fprintln(a.stdout, "no signer is allowed yet; helios git signers add <name> <public key> allows one")
			} else if len(p.Signers) > 0 {
				w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "SIGNER\tKEY\tTYPE")
				for _, s := range p.Signers {
					fmt.Fprintf(w, "%s\t%s\t%s\n", s.Principal, s.Fingerprint(), s.Type)
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
			if len(p.Others) > 0 {
				fmt.Fprintf(a.stdout, "%d hand-written line(s) in %s that helios can't read may allow signers too, and are kept as they are\n", len(p.Others), filepath.Join(gitdeploy.SigningDir, "allowed_signers"))
			}
			if len(p.RequireSigned) == 0 {
				fmt.Fprintln(a.stdout, "no app deploys only signed commits; helios git require-signed <app> makes one")
			} else {
				fmt.Fprintf(a.stdout, "deploys only signed commits: %s\n", strings.Join(p.RequireSigned, ", "))
			}
			return nil
		},
	}
	return cmd
}

// newGitRequireSigned is helios git require-signed.
func newGitRequireSigned(a *app) *cobra.Command {
	var (
		planOnly bool
		off      bool
	)
	cmd := &cobra.Command{
		Use:   "require-signed <app>",
		Short: "Deploy an app only from commits an allowed signer signed, over push and webhook; --off deploys any commit again.",
		Long: `Deploy an app only from commits an allowed signer signed, over push and webhook.

The commit that deploys, the tip of the push or of the branch a webhook
names, must carry an SSH signature by a key helios git signers allows.
An unsigned tip, a key nobody allowed, a GPG signature (GitHub's on the
merges it makes among them) or a key not allowed to sign git commits is
refused, and nothing of it is built. A tree uploaded with helios deploy
--to bedrock@ is refused too, since it has no commit to check; root can
still deploy one, with helios deploy on the machine or --to root@.

To sign, on the machine you commit from:

  git config gpg.format ssh
  git config user.signingkey ~/.ssh/id_ed25519.pub
  git config commit.gpgsign true

Allow the signer first, then require signatures:

  helios git signers add kyle@example.com "$(cat ~/.ssh/id_ed25519.pub)"
  helios git require-signed hello`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), gitdeploy.RequireSignedKind, gitdeploy.RequireSignedInput{App: args[0], Off: off, By: requester()}, planOnly)
		},
	}
	cmd.Flags().BoolVar(&off, "off", false, "deploy the app from any commit again, signed or not")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

// newGitAllow is helios git allow.
func newGitAllow(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allow <app> [public key]",
		Short: "Let an SSH key deploy an app with git push or helios deploy --to. The key comes from the argument or stdin.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appName := args[0]
			if !gitdeploy.ValidApp(appName) {
				return fmt.Errorf("%q isn't an app's name", appName)
			}
			text := strings.Join(args[1:], " ")
			if text == "" {
				b, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<10))
				if err != nil {
					return err
				}
				text = string(b)
			}
			key, err := gitdeploy.ParseKey(text)
			if err != nil {
				return err
			}
			if err := updateKeys(func(kf *gitdeploy.KeyFile) error {
				var err error
				key, err = kf.Allow(key, appName)
				return err
			}); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "%s may deploy %s\n", key.Fingerprint(), strings.Join(key.Apps, ", "))
			fmt.Fprintf(a.stdout, "from its machine: git remote add helios %s && git push helios main\n", remoteFor(cmd.Context(), appName))
			return nil
		},
	}
	return cmd
}

// newGitDeny is helios git deny.
func newGitDeny(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deny <app> <fingerprint or public key>",
		Short: "Stop a key from deploying an app; a key left with no apps is removed.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := updateKeys(func(kf *gitdeploy.KeyFile) error {
				if !kf.Deny(args[0], strings.Join(args[1:], " ")) {
					return fmt.Errorf("no key named %s deploys %s", strings.Join(args[1:], " "), args[0])
				}
				return nil
			}); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "that key no longer deploys %s\n", args[0])
			return nil
		},
	}
	return cmd
}

// newGitKeys is helios git keys.
func newGitKeys(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List the keys that may push, and the apps each deploys.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			kf, err := gitdeploy.ReadKeys(gitdeploy.AuthorizedKeys)
			if err != nil {
				return err
			}
			policy, err := gitdeploy.ReadPolicy(gitdeploy.SigningDir)
			if err != nil {
				return err
			}
			if a.json {
				type row struct {
					Fingerprint string   `json:"fingerprint"`
					Comment     string   `json:"comment,omitempty"`
					Apps        []string `json:"apps"`
					// SignedOnly are the apps among Apps that deploy only
					// signed commits.
					SignedOnly []string `json:"signed_only,omitempty"`
				}
				var rows []row
				for _, k := range kf.Keys {
					var signed []string
					for _, app := range k.Apps {
						if policy.Requires(app) {
							signed = append(signed, app)
						}
					}
					rows = append(rows, row{k.Fingerprint(), k.Comment, k.Apps, signed})
				}
				return json.NewEncoder(a.stdout).Encode(rows)
			}
			if len(kf.Keys) == 0 {
				fmt.Fprintln(a.stdout, "no key may push yet; helios git allow <app> <public key> adds one")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tCOMMENT\tDEPLOYS")
			for _, k := range kf.Keys {
				deploys := make([]string, len(k.Apps))
				for i, app := range k.Apps {
					deploys[i] = app
					if policy.Requires(app) {
						deploys[i] += " (signed commits only)"
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", k.Fingerprint(), orDash(k.Comment), strings.Join(deploys, ", "))
			}
			return w.Flush()
		},
	}
	return cmd
}

// newGitRemote is helios git remote.
func newGitRemote(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote <app>",
		Short: "Print the git remote that deploys an app.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(a.stdout, remoteFor(cmd.Context(), args[0]))
			return nil
		},
	}
	return cmd
}

// newGitBranch is helios git branch.
func newGitBranch(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "branch <app> <branch>",
		Short: "Choose the branch whose pushes deploy an app (main by default).",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			dir, err := gitdeploy.EnsureRepo(args[0])
			if err != nil {
				return err
			}
			if err := gitdeploy.SetBranch(dir, args[1]); err != nil {
				return err
			}
			if err := chownToPushUser(dir); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "pushes to %s deploy %s\n", args[1], args[0])
			return nil
		},
	}
	return cmd
}

// newGitWebhook is helios git webhook.
func newGitWebhook(a *app) *cobra.Command {
	var (
		repo, hookBranch string
		off              bool
	)
	cmd := &cobra.Command{
		Use:   "webhook <app>",
		Short: "Deploy an app when GitHub says its branch moved; prints what to paste into GitHub, once.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			appName := args[0]
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			if off {
				if err := gitdeploy.Disable(ctx, store, a.secretsStore(), appName); errors.Is(err, state.ErrNotFound) {
					return fmt.Errorf("%s has no webhook", appName)
				} else if err != nil {
					return err
				}
				if err := apps.ReloadEdge(ctx, store, a.secretsStore()); err != nil {
					return err
				}
				fmt.Fprintf(a.stdout, "%s no longer deploys on webhooks; remove the webhook on GitHub too\n", appName)
				return nil
			}
			if repo == "" {
				return errors.New("give --repo, the repository GitHub pushes, such as git@github.com:you/app.git")
			}
			rev, err := store.RevisionWithStatus(ctx, appName, state.RevisionActive)
			if err != nil {
				return err
			}
			if rev == nil {
				return fmt.Errorf("deploy %s once first: its webhook arrives through one of its hosts", appName)
			}
			var m manifest.Manifest
			if err := json.Unmarshal(rev.Manifest, &m); err != nil {
				return err
			}
			hosts := m.Hosts()
			if len(hosts) == 0 {
				return fmt.Errorf("%s has no hosts for a webhook to arrive on", appName)
			}
			if err := a.ensureSecretsKey(a.secretsStore()); err != nil {
				return err
			}
			w, err := gitdeploy.Configure(ctx, store, a.secretsStore(), appName, repo, hookBranch, hosts[0])
			if err != nil {
				return err
			}
			if err := apps.ReloadEdge(ctx, store, a.secretsStore()); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "On GitHub, in the repository's Settings, add a webhook:\n  Payload URL   %s\n  Content type  application/json\n  Events        just the push event\n", w.URL)
			fmt.Fprintf(a.stderr, "  Secret        %s\n(shown once, here, and nowhere else)\n", w.Secret)
			if w.DeployKey != "" {
				fmt.Fprintf(a.stdout, "and, under Deploy keys, this key, read-only:\n  %s\n", w.DeployKey)
			}
			fmt.Fprintf(a.stdout, "pushes to %s of %s now deploy %s\n", hookBranch, repo, appName)
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "the repository: git@github.com:you/app.git, https://..., or file:///path for a test")
	cmd.Flags().StringVar(&hookBranch, "branch", gitdeploy.DefaultBranch, "the branch whose pushes deploy")
	cmd.Flags().BoolVar(&off, "off", false, "stop deploying on webhooks and forget the secret and key")
	a.guardSecretMutation(cmd, func([]string) string { return integration.App })
	return cmd
}

// newGitWebhooks is helios git webhooks.
func newGitWebhooks(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhooks",
		Short: "List the webhooks and what their last delivery did.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			hooks, err := store.GitHooks(cmd.Context())
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(hooks)
			}
			if len(hooks) == 0 {
				fmt.Fprintln(a.stdout, "no webhooks")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "APP\tREPOSITORY\tBRANCH\tLAST")
			for _, h := range hooks {
				last := "nothing yet"
				if !h.LastAt.IsZero() {
					last = fmt.Sprintf("%s %s: %s", h.LastAt.Local().Format("2006-01-02 15:04"), h.LastCommit, h.LastResult)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", h.App, h.Repo, h.Branch, last)
			}
			return w.Flush()
		},
	}
	return cmd
}

// newGitServe is helios git serve, what a push key runs.
func newGitServe(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "serve <apps...>",
		Short:  "What a push key runs: git receive-pack, upload-pack or a tarball deploy, for its apps only.",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := gitdeploy.ParseCommand(os.Getenv("SSH_ORIGINAL_COMMAND"))
			if err != nil {
				return err
			}
			if err := req.Allowed(args); err != nil {
				return err
			}
			switch req.Kind {
			case gitdeploy.Receive:
				dir, err := gitdeploy.EnsureRepo(req.App)
				if err != nil {
					return err
				}
				return execGit("receive-pack", dir)
			case gitdeploy.Upload:
				dir := gitdeploy.RepoDir(req.App)
				if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
					return fmt.Errorf("nothing has been pushed to %s yet", req.App)
				}
				return execGit("upload-pack", dir)
			default:
				// A push key can't deploy around the signing policy; root
				// can, through helios receive.
				if err := gitdeploy.CheckTree(gitdeploy.SigningDir, req.App); err != nil {
					return err
				}
				if code := gitdeploy.ReceiveTree(cmd.Context(), req.App, os.Stdin, a.stdout, gitdeploy.ThroughDaemon(a.socket), gitdeploy.BuildsDir); code != 0 {
					return quietError{code}
				}
				return nil
			}
		},
	}
	return cmd
}

// newGitHook is helios git hook, an app repository's pre-receive hook.
func newGitHook(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "hook <app>",
		Short:  "The pre-receive hook of an app's repository.",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if code := gitdeploy.Hook(cmd.Context(), args[0], os.Stdin, a.stdout, gitdeploy.ThroughDaemon(a.socket)); code != 0 {
				return quietError{code}
			}
			return nil
		},
	}
	return cmd
}

// newReceive deploys a source tree sent on stdin, for helios deploy --to
// over a root login; the bedrock user's keys reach the same code through
// git serve.
func newReceive(a *app) *cobra.Command {
	return &cobra.Command{
		Use:    "receive <app>",
		Short:  "Deploy the source tree on stdin (what helios deploy --to sends).",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !gitdeploy.ValidApp(args[0]) {
				return fmt.Errorf("%q isn't an app's name", args[0])
			}
			root := gitdeploy.BuildsDir
			if os.Geteuid() == 0 {
				root = filepath.Join(a.stateDir, "builds")
			} else if err := gitdeploy.CheckTree(gitdeploy.SigningDir, args[0]); err != nil {
				return err
			}
			if code := gitdeploy.ReceiveTree(cmd.Context(), args[0], os.Stdin, a.stdout, gitdeploy.ThroughDaemon(a.socket), root); code != 0 {
				return quietError{code}
			}
			return nil
		},
	}
}

func execGit(sub, dir string) error {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return err
	}
	return syscall.Exec(gitPath, []string{"git", sub, dir}, os.Environ())
}

// updateKeys changes the key file atomically and gives it to the push user.
func updateKeys(change func(*gitdeploy.KeyFile) error) error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return errors.New("changing who may push needs root")
	}
	if err := gitdeploy.UpdateKeys(gitdeploy.AuthorizedKeys, change); err != nil {
		return err
	}
	if err := chownToPushUser(filepath.Dir(gitdeploy.AuthorizedKeys)); err != nil {
		return err
	}
	return chownToPushUser(gitdeploy.AuthorizedKeys)
}

// chownToPushUser gives a path, and everything under it, to the bedrock user.
func chownToPushUser(path string) error {
	u, err := user.Lookup(gitdeploy.User)
	if err != nil {
		return fmt.Errorf("the %s user doesn't exist; run helios host reconcile", gitdeploy.User)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return filepath.WalkDir(path, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// remoteFor names the git remote that deploys an app on this machine.
func remoteFor(ctx context.Context, appName string) string {
	addr := "<this machine>"
	for _, a := range host.Addresses(ctx, host.RealEnv()) {
		if !strings.Contains(a, ":") {
			addr = a
			break
		}
	}
	return fmt.Sprintf("%s@%s:%s.git", gitdeploy.User, addr, appName)
}

// deployTo sends a source tree to a machine over SSH and deploys it
// there, printing the machine's steps as they happen.
func deployTo(ctx context.Context, a *app, dir, appName, target string) error {
	if !gitdeploy.ValidApp(appName) {
		return fmt.Errorf("%q isn't an app's name", appName)
	}
	connection := remote.Target{SSH: target}
	if err := connection.Validate(); err != nil {
		return err
	}
	files, err := sourceFiles(ctx, dir)
	if err != nil {
		return err
	}
	var size int64
	for _, f := range files {
		if info, err := os.Lstat(filepath.Join(dir, f)); err == nil {
			size += info.Size()
		}
	}
	fmt.Fprintf(a.stderr, "sending %d files (%s) of %s to %s\n", len(files), bytesWord(size), appName, target)
	cmd, err := targetTransport().Command(ctx, connection, "bedrock receive "+appName)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = a.stdout, a.stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	writeErr := writeTree(stdin, dir, files)
	stdin.Close()
	waitErr := cmd.Wait()
	if waitErr != nil {
		var exit *exec.ExitError
		if errors.As(waitErr, &exit) {
			return quietError{exit.ExitCode()}
		}
		return waitErr
	}
	return writeErr
}

// sourceFiles lists what to send: in a git checkout, the tracked files and
// the untracked ones git doesn't ignore; elsewhere, everything but .git
// and node_modules.
func sourceFiles(ctx context.Context, dir string) ([]string, error) {
	out, gitErr := exec.CommandContext(ctx, "git", "-C", dir, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if gitErr == nil {
		var files []string
		seen := map[string]bool{}
		for _, f := range strings.Split(string(out), "\x00") {
			if f == "" || seen[f] || isEnvironmentFile(f) {
				continue
			}
			seen[f] = true
			if _, err := os.Lstat(filepath.Join(dir, f)); err == nil {
				files = append(files, f)
			}
		}
		sort.Strings(files)
		return files, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A failed Git query must not turn a checkout into an unfiltered upload.
	// Repositories and worktrees both have .git metadata at their root;
	// source directories may be nested below that root.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	for current := resolved; ; current = filepath.Dir(current) {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return nil, fmt.Errorf("list Git source files: %w", gitErr)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	var files []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && !isEnvironmentFile(p) {
			rel, _ := filepath.Rel(dir, p)
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

// Environment configuration belongs in the sealed secret store. Keep this
// exclusion common to legacy deploys and named-target snapshots.
func isEnvironmentFile(path string) bool {
	name := filepath.Base(path)
	return name == ".env" || strings.HasPrefix(name, ".env.")
}

// writeTree writes files as a gzipped tar stream.
func writeTree(w io.Writer, dir string, files []string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	bw := bufio.NewWriterSize(w, 256<<10)
	gz := gzip.NewWriter(bw)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		info, err := root.Lstat(f)
		if err != nil {
			return err
		}
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = root.Readlink(f); err != nil {
				return err
			}
		} else if !info.Mode().IsRegular() {
			continue
		}
		h, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(f)
		h.Uname, h.Gname, h.Uid, h.Gid = "", "", 0, 0
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			file, err := root.Open(f)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, file)
			file.Close()
			if err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return bw.Flush()
}
