package gitdeploy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/remote"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// ValidRepo checks a repository URL helios can fetch.
func ValidRepo(repo string) error {
	invalid := errors.New("repository must be a URL without embedded credentials (https://, git@host:owner/repo.git, ssh:// or file:///)")
	if strings.ContainsAny(repo, "\x00\r\n\t ") {
		return invalid
	}
	if strings.HasPrefix(repo, "git@") {
		host, path, ok := strings.Cut(strings.TrimPrefix(repo, "git@"), ":")
		if ok && host != "" && path != "" && !strings.HasPrefix(host, "-") && !strings.ContainsAny(host, "/@?#") {
			return nil
		}
		return invalid
	}
	u, err := url.Parse(repo)
	if err != nil || u.Fragment != "" || u.RawQuery != "" || u.Path == "" || u.Path == "/" {
		return invalid
	}
	switch u.Scheme {
	case "file":
		if u.Host != "" || u.User != nil || !filepath.IsAbs(u.Path) {
			return invalid
		}
	case "http", "https", "ssh":
		if u.Hostname() == "" {
			return invalid
		}
		if u.User != nil {
			if _, password := u.User.Password(); u.Scheme != "ssh" || password {
				return invalid
			}
		}
		if port := u.Port(); port != "" {
			number, err := strconv.Atoi(port)
			if err != nil || number < 1 || number > 65535 {
				return invalid
			}
		}
	default:
		return invalid
	}
	return nil
}

var branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// ValidBranch checks a branch name before it goes on a git command line:
// one that starts with a hyphen would be read as a flag, and git refuses
// the rest.
func ValidBranch(branch string) error {
	switch {
	case !branchPattern.MatchString(branch), branch == "HEAD", strings.Contains(branch, ".."), strings.HasSuffix(branch, "/"), strings.HasSuffix(branch, "."):
		return fmt.Errorf("%q isn't a branch name", branch)
	}
	for _, part := range strings.Split(branch, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return fmt.Errorf("%q isn't a branch name", branch)
		}
	}
	return nil
}

func usesSSH(repo string) bool {
	return strings.HasPrefix(repo, "ssh://") || strings.HasPrefix(repo, "git@")
}

// Webhook is what a person needs to set a webhook up on GitHub.
type Webhook struct {
	URL    string
	Secret string
	// DeployKey is the public key to add as a read-only deploy key, for
	// a repository fetched over SSH.
	DeployKey string
}

// Configure sets an app's webhook up: a secret for GitHub to sign with,
// and, for a repository reached over SSH, a deploy key of its own. Both
// live in helios's own secrets; the caller shows them once.
func Configure(ctx context.Context, store *state.Store, sec *secrets.Store, appName, repo, branch, host string) (*Webhook, error) {
	if !ValidApp(appName) {
		return nil, errors.New("invalid webhook app name")
	}
	if err := ValidRepo(repo); err != nil {
		return nil, err
	}
	if err := ValidBranch(branch); err != nil {
		return nil, err
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	w := &Webhook{URL: "https://" + host + edge.HookPath, Secret: hex.EncodeToString(b[:])}
	secret := w.Secret
	changes := map[string]*string{integration.WebhookSecretName(appName): &secret, integration.DeployKeyName(appName): nil}
	if usesSSH(repo) {
		private, public, err := newDeployKey(appName)
		if err != nil {
			return nil, err
		}
		changes[integration.DeployKeyName(appName)] = &private
		w.DeployKey = public
	}
	if _, err := sec.SetAll(integration.App, changes); err != nil {
		return nil, err
	}
	if err := store.SaveGitHook(ctx, state.GitHook{App: appName, Repo: repo, Branch: branch, CreatedAt: time.Now().UTC()}); err != nil {
		return nil, err
	}
	return w, nil
}

// Disable forgets an app's webhook and its secrets.
func Disable(ctx context.Context, store *state.Store, sec *secrets.Store, appName string) error {
	if err := store.RemoveGitHook(ctx, appName); err != nil {
		return err
	}
	_, err := sec.SetAll(integration.App, map[string]*string{integration.WebhookSecretName(appName): nil, integration.DeployKeyName(appName): nil})
	return err
}

// newDeployKey makes an ed25519 key pair with ssh-keygen and returns the
// private key's text and the public key's line.
func newDeployKey(appName string) (string, string, error) {
	dir, err := os.MkdirTemp("", "bedrock-key-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)
	host, _ := os.Hostname()
	path := filepath.Join(dir, "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "helios deploy key for "+appName+" on "+host, "-f", path).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(string(out)))
	}
	private, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	public, err := os.ReadFile(path + ".pub")
	if err != nil {
		return "", "", err
	}
	return string(private), strings.TrimSpace(string(public)), nil
}

// VerifySignature checks GitHub's X-Hub-Signature-256 header against the
// body and the secret.
func VerifySignature(secret string, body []byte, header string) bool {
	given, ok := strings.CutPrefix(header, "sha256=")
	if !ok || secret == "" {
		return false
	}
	want, err := hex.DecodeString(given)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}

// Receiver answers webhooks and deploys what they announce, one deploy per
// app at a time; pushes that arrive meanwhile collapse into the newest.
type Receiver struct {
	// Context owns background fetches and deploys for the daemon lifetime.
	// Request cancellation does not cancel an accepted deployment.
	Context context.Context
	Store   *state.Store
	Secrets *secrets.Store
	Deploy  Deployer
	// Notify tells a person when a deploy from a webhook fails.
	Notify func(ctx context.Context, subject, body string)
	Log    func(format string, args ...any)
	// SourcesDir holds the fetched mirrors; BuildsDir the source trees.
	SourcesDir string
	BuildsDir  string
	// SigningDir holds the signing policy a fetched commit is held to;
	// empty means the machine's, SigningDir.
	SigningDir string

	mu      sync.Mutex
	running map[string]bool
	pending map[string]bool
}

type pushEvent struct {
	Ref     string `json:"ref"`
	After   string `json:"after"`
	Deleted bool   `json:"deleted"`
}

// ServeHTTP implements http.Handler.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || strings.TrimSuffix(req.URL.Path, "/") != edge.HookPath {
		http.NotFound(w, req)
		return
	}
	ctx := req.Context()
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	appName, err := r.appFor(ctx, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hook, err := r.Store.GitHookFor(ctx, appName)
	if err != nil || hook == nil || appName == "" {
		http.NotFound(w, req)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 5<<20))
	if err != nil {
		http.Error(w, "can't read the body", http.StatusBadRequest)
		return
	}
	values, _, err := r.Secrets.LoadCurrent(integration.App)
	if err != nil {
		http.Error(w, "secrets unavailable", http.StatusInternalServerError)
		return
	}
	if !VerifySignature(values[integration.WebhookSecretName(appName)], body, req.Header.Get("X-Hub-Signature-256")) {
		r.log("webhook for %s: bad signature from %s", appName, logSafe(req.Header.Get("X-Forwarded-For")))
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	switch req.Header.Get("X-GitHub-Event") {
	case "ping":
		fmt.Fprintf(w, "helios hears %s's pushes to %s\n", appName, hook.Branch)
		return
	case "push":
	default:
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "ignored: only pushes deploy")
		return
	}
	var ev pushEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad push payload", http.StatusBadRequest)
		return
	}
	if ev.Deleted || ev.Ref != "refs/heads/"+hook.Branch {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "ignored: %s isn't %s\n", ev.Ref, hook.Branch)
		return
	}
	if !r.enqueue(appName) {
		http.Error(w, "webhook receiver is stopping", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, "deploying %s of %s\n", short(ev.After), appName)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// logSafe bounds a value from a request before it goes in the log, so a
// caller can't write lines of their own there.
func logSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return s
}

// appFor finds the app a host belongs to.
func (r *Receiver) appFor(ctx context.Context, host string) (string, error) {
	routes, err := app.Routes(ctx, r.Store)
	if err != nil {
		return "", err
	}
	for _, rt := range routes {
		if rt.Host == host {
			return rt.App, nil
		}
	}
	return "", nil
}

// enqueue starts a deploy for an app, or marks one as wanted after the
// deploy that is running: the branch's newest commit is what it deploys.
func (r *Receiver) enqueue(appName string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx := r.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}
	if r.running == nil {
		r.running, r.pending = map[string]bool{}, map[string]bool{}
	}
	if r.running[appName] {
		r.pending[appName] = true
		return true
	}
	r.running[appName] = true
	go r.work(ctx, appName)
	return true
}

func (r *Receiver) work(ctx context.Context, appName string) {
	cleanupNeeded := true
	defer func() {
		if p := recover(); p != nil {
			r.log("webhook deploy of %s: panic: %v\n%s", appName, p, debug.Stack())
		}
		if cleanupNeeded {
			r.mu.Lock()
			delete(r.running, appName)
			delete(r.pending, appName)
			r.mu.Unlock()
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		r.deployOnce(ctx, appName)
		r.mu.Lock()
		pending := r.pending[appName] && ctx.Err() == nil
		delete(r.pending, appName)
		if !pending {
			delete(r.running, appName)
			cleanupNeeded = false
		}
		r.mu.Unlock()
		if !pending {
			return
		}
	}
}

func (r *Receiver) log(format string, args ...any) {
	if r.Log != nil {
		r.Log(format, args...)
	}
}

// Wait blocks until no webhook deploy is running, for tests and shutdown.
func (r *Receiver) Wait(ctx context.Context) {
	for {
		r.mu.Lock()
		busy := len(r.running) > 0
		r.mu.Unlock()
		if !busy {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (r *Receiver) deployOnce(ctx context.Context, appName string) {
	hook, err := r.Store.GitHookFor(ctx, appName)
	if err != nil || hook == nil {
		return
	}
	commit, signer, dir, err := r.fetch(ctx, *hook)
	var result string
	var refused refusal
	switch {
	case errors.As(err, &refused):
		result = "refused: " + refused.Error()
	case err != nil:
		result = "fetch failed: " + err.Error()
	default:
		var log strings.Builder
		ok, derr := Deploy(ctx, r.Deploy, dir, short(commit), signer, &log)
		switch {
		case derr != nil:
			result = "failed: " + derr.Error()
		case !ok:
			result = "failed: " + lastFailure(log.String())
		default:
			result = "deployed"
		}
		PruneBuilds(r.BuildsDir, appName, 3)
	}
	_ = r.Store.RecordGitHook(ctx, appName, short(commit), result, time.Now().UTC())
	r.log("webhook deploy of %s %s: %s", appName, short(commit), result)
	switch {
	case result == "deployed" || r.Notify == nil || ctx.Err() != nil:
	case refused.error != nil:
		// Nothing was deployed, so helios history has no receipt; the
		// webhook's own record is the one to read.
		r.Notify(ctx, appName+": the deploy from "+hook.Repo+" was refused",
			fmt.Sprintf("A push to %s of %s asked for a deploy, and the machine refused it: %s.\n\nThe running revision stays. helios git webhooks shows the last result, and helios git signers list shows whose signature deploys.\n", hook.Branch, hook.Repo, refused.Error()))
	default:
		r.Notify(ctx, appName+": the deploy from "+hook.Repo+" failed",
			fmt.Sprintf("A push to %s of %s asked for a deploy, and it %s.\n\nThe running revision stays. helios history on the machine has the receipt.\n", hook.Branch, hook.Repo, result))
	}
}

// lastFailure picks the failing step's line out of a rendered deploy.
func lastFailure(log string) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "fail ") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), "fail"))
		}
	}
	return lines[len(lines)-1]
}

// refusal is a fetched commit the signing policy won't deploy.
type refusal struct{ error }

func (r refusal) Unwrap() error { return r.error }

// fetch brings the branch's newest commit into the app's mirror, holds it
// to the signing policy, and writes its tree out. It returns the commit,
// who signed it when the app deploys only signed commits, and the tree.
func (r *Receiver) fetch(ctx context.Context, h state.GitHook) (string, string, string, error) {
	if !ValidApp(h.App) {
		return "", "", "", errors.New("invalid webhook app name")
	}
	if err := ValidRepo(h.Repo); err != nil {
		return "", "", "", err
	}
	if err := ValidBranch(h.Branch); err != nil {
		return "", "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	sourceRoot, err := filepath.Abs(r.SourcesDir)
	if err != nil {
		return "", "", "", err
	}
	mirror := filepath.Join(sourceRoot, h.App+".git")
	if _, err := os.Stat(filepath.Join(mirror, "HEAD")); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(r.SourcesDir, 0o700); err != nil {
			return "", "", "", err
		}
		if out, err := exec.CommandContext(ctx, "git", "init", "--bare", "--quiet", mirror).CombinedOutput(); err != nil {
			return "", "", "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
	}
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if usesSSH(h.Repo) {
		values, _, err := r.Secrets.LoadCurrent(integration.App)
		if err != nil {
			return "", "", "", err
		}
		key := values[integration.DeployKeyName(h.App)]
		if key == "" {
			return "", "", "", errors.New("no deploy key; run helios git webhook again")
		}
		// Made afresh, so the file has the mode asked for and not one an
		// earlier helios left it with.
		keyFile := filepath.Join(sourceRoot, "."+h.App+".key")
		_ = os.Remove(keyFile)
		if err := os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
			return "", "", "", err
		}
		defer os.Remove(keyFile)
		env = append(env, "GIT_SSH_COMMAND=ssh -i "+remote.Quote(keyFile)+" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="+remote.Quote(filepath.Join(sourceRoot, "known_hosts")))
	}
	ref := "refs/heads/" + h.Branch
	fetch := exec.CommandContext(ctx, "git", "-C", mirror, "fetch", "--quiet", "--force", "--depth", "1", h.Repo, ref+":"+ref)
	fetch.Env = env
	if out, err := fetch.CombinedOutput(); err != nil {
		return "", "", "", fmt.Errorf("git fetch %s %s: %s", h.Repo, h.Branch, strings.TrimSpace(string(out)))
	}
	out, err := exec.CommandContext(ctx, "git", "-C", mirror, "rev-parse", ref).Output()
	if err != nil {
		return "", "", "", err
	}
	commit := strings.TrimSpace(string(out))
	// As the push hook does, the commit is checked before its tree is
	// written anywhere.
	policy := r.SigningDir
	if policy == "" {
		policy = SigningDir
	}
	signer, err := CheckTip(ctx, policy, h.App, mirror, commit)
	if err != nil {
		return commit, "", "", refusal{err}
	}
	dir, err := NewBuildDir(r.BuildsDir, h.App, short(commit))
	if err != nil {
		return commit, signer, "", err
	}
	if err := ExportCommit(ctx, mirror, commit, dir); err != nil {
		return commit, signer, "", err
	}
	if _, err := CheckSource(dir, h.App); err != nil {
		return commit, signer, "", err
	}
	return commit, signer, dir, nil
}

// InProcess is a Deployer for the daemon itself, which owns the kernel.
func InProcess(run func(ctx context.Context, kind string, input json.RawMessage, emit func(kernel.Event)) (*kernel.Receipt, error)) Deployer {
	return func(ctx context.Context, in app.DeployInput, emit func(kernel.Event)) (*kernel.Receipt, error) {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		return run(ctx, app.DeployKind, raw, emit)
	}
}
