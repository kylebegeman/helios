package gitdeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// signingKey makes an SSH key for a test and returns its private key file
// and its public key line.
func signingKey(t *testing.T, name string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen isn't installed")
	}
	path := filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name+"@example.test", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %s", out)
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.TrimSpace(string(pub))
}

// signedRepo is repoWith for a commit signed with key, or unsigned when
// key is empty. The person's own git configuration is kept out of it.
func signedRepo(t *testing.T, files map[string]string, key string) (string, string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	work, bare := t.TempDir(), filepath.Join(t.TempDir(), "up.git")
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(work, "init", "-q", "--initial-branch=main")
	for name, text := range files {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(work, name)), 0o755)
		_ = os.WriteFile(filepath.Join(work, name), []byte(text), 0o644)
	}
	git(work, "add", "-A")
	if key == "" {
		git(work, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "first")
	} else {
		git(work, "-c", "gpg.format=ssh", "-c", "user.signingkey="+key, "commit", "-S", "-q", "-m", "first")
	}
	git(t.TempDir(), "init", "-q", "--bare", "--initial-branch=main", bare)
	git(work, "push", "-q", bare, "main")
	return bare, git(work, "rev-parse", "HEAD")
}

// withSignature writes a copy of commit carrying signature as its gpgsig
// header, and returns the copy.
func withSignature(t *testing.T, repo, commit, signature string) string {
	t.Helper()
	raw, err := exec.Command("git", "-C", repo, "cat-file", "commit", commit).Output()
	if err != nil {
		t.Fatal(err)
	}
	header, body, _ := strings.Cut(string(raw), "\n\n")
	sig := "gpgsig " + strings.ReplaceAll(strings.TrimRight(signature, "\n"), "\n", "\n ")
	cmd := exec.Command("git", "-C", repo, "hash-object", "-t", "commit", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(header + "\n" + sig + "\n\n" + body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hash-object: %s", out)
	}
	return strings.TrimSpace(string(out))
}

// payload is a commit as git signs it: the object without its signature.
func payload(t *testing.T, repo, commit string) string {
	t.Helper()
	raw, err := exec.Command("git", "-C", repo, "cat-file", "commit", commit).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// policyWith writes a signing policy in a temp dir, the way root would.
func policyWith(t *testing.T, change func(*Policy) error) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "git")
	if err := UpdatePolicy(dir, change); err != nil {
		t.Fatal(err)
	}
	return dir
}

func allow(principal, pub, options string) func(*Policy) error {
	return func(p *Policy) error {
		k, err := ParseKey(pub)
		if err != nil {
			return err
		}
		p.Signers = append(p.Signers, Signer{Principal: principal, Options: options, Type: k.Type, Blob: k.Blob})
		return nil
	}
}

func both(changes ...func(*Policy) error) func(*Policy) error {
	return func(p *Policy) error {
		for _, c := range changes {
			if err := c(p); err != nil {
				return err
			}
		}
		return nil
	}
}

func requiring(app string) func(*Policy) error {
	return func(p *Policy) error { p.Require(app, false); return nil }
}

func TestOnlyATipSignedByAnAllowedSSHKeyDeploys(t *testing.T) {
	ctx := context.Background()
	key, pub := signingKey(t, "kyle")
	strangerKey, strangerPub := signingKey(t, "stranger")
	files := map[string]string{"helios.yaml": helloYAML}
	signed, signedCommit := signedRepo(t, files, key)
	unsigned, unsignedCommit := signedRepo(t, files, "")
	foreign, foreignCommit := signedRepo(t, files, strangerKey)
	gpg := withSignature(t, unsigned, unsignedCommit, "-----BEGIN PGP SIGNATURE-----\n\niHUEABYKAB0WIQQexample\n=abcd\n-----END PGP SIGNATURE-----")
	x509 := withSignature(t, unsigned, unsignedCommit, "-----BEGIN SIGNED MESSAGE-----\nMIIexample\n-----END SIGNED MESSAGE-----")
	// A signature by an allowed key, made for files and not for git.
	sign := exec.Command("ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", "file")
	sign.Stdin = strings.NewReader(payload(t, unsigned, unsignedCommit))
	fileSig, err := sign.Output()
	if err != nil {
		t.Fatal(err)
	}
	otherNamespace := withSignature(t, unsigned, unsignedCommit, string(fileSig))

	policy := policyWith(t, both(allow("kyle@example.com", pub, gitOnly), requiring("hello")))
	k, _ := ParseKey(pub)
	who, err := CheckTip(ctx, policy, "hello", signed, signedCommit)
	if err != nil || who != "kyle@example.com ("+k.Fingerprint()+")" {
		t.Fatalf("a signed tip: %q %v", who, err)
	}
	stranger, _ := ParseKey(strangerPub)
	for name, c := range map[string]struct{ repo, commit, want string }{
		"unsigned":        {unsigned, unsignedCommit, "isn't signed"},
		"unknown key":     {foreign, foreignCommit, "is signed with ED25519 key " + stranger.Fingerprint() + ", which isn't an allowed signer"},
		"gpg":             {unsigned, gpg, "has a GPG signature, and only SSH signatures count"},
		"x509":            {unsigned, x509, "has an X.509 signature"},
		"other namespace": {unsigned, otherNamespace, "has an SSH signature that doesn't verify"},
	} {
		who, err := CheckTip(ctx, policy, "hello", c.repo, c.commit)
		if err == nil || who != "" {
			t.Errorf("%s: deployed as %q", name, who)
			continue
		}
		for _, want := range []string{"hello deploys only commits signed by kyle@example.com", "commit " + c.commit[:12], c.want} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: want %q in %q", name, want, err)
			}
		}
	}
	// The key is allowed, but not for signing git commits.
	fileOnly := policyWith(t, both(allow("kyle@example.com", pub, `namespaces="file"`), requiring("hello")))
	if _, err := CheckTip(ctx, fileOnly, "hello", signed, signedCommit); err == nil || !strings.Contains(err.Error(), "isn't allowed to sign git commits") {
		t.Fatalf("a key for files only: %v", err)
	}
	// An app the policy doesn't name deploys as it did before.
	if who, err := CheckTip(ctx, policy, "other", unsigned, unsignedCommit); err != nil || who != "" {
		t.Fatalf("an app without the policy: %q %v", who, err)
	}
	if who, err := CheckTip(ctx, filepath.Join(t.TempDir(), "none"), "hello", unsigned, unsignedCommit); err != nil || who != "" {
		t.Fatalf("no policy at all: %q %v", who, err)
	}
	nobody := policyWith(t, requiring("hello"))
	if _, err := CheckTip(ctx, nobody, "hello", signed, signedCommit); err == nil || !strings.Contains(err.Error(), "no signer is allowed yet") {
		t.Fatalf("a policy with no signers: %v", err)
	}
}

func TestASignatureOfAnotherKindAlongsideAnSSHOneIsWhatCounts(t *testing.T) {
	raw := []byte("tree 1\nauthor a\ngpgsig -----BEGIN SSH SIGNATURE-----\n abc\n -----END SSH SIGNATURE-----\ngpgsig-sha256 -----BEGIN PGP SIGNATURE-----\n def\n -----END PGP SIGNATURE-----\n\ngpgsig -----BEGIN SSH SIGNATURE----- in the message\n")
	if got := signatureArmor(raw); got != pgpArmor {
		t.Fatalf("armor %q", got)
	}
	if got := signatureArmor([]byte("tree 1\n\nmessage gpgsig -----BEGIN SSH SIGNATURE-----\n")); got != "" {
		t.Fatalf("a signature in the message isn't one: %q", got)
	}
}

func TestAPolicyNobodyCanReadRefusesInsteadOfAllowing(t *testing.T) {
	dir := policyWith(t, requiring("hello"))
	if err := os.WriteFile(filepath.Join(dir, policyName), []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTip(context.Background(), dir, "other", t.TempDir(), strings.Repeat("a", 40)); err == nil {
		t.Fatal("a policy that can't be read must not let any app deploy")
	}
	if err := CheckTree(dir, "other"); err == nil {
		t.Fatal("nor an uploaded tree")
	}
	if os.Geteuid() == 0 {
		return
	}
	locked := policyWith(t, requiring("hello"))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o750) })
	if _, err := ReadPolicy(locked); err == nil || !strings.Contains(err.Error(), "helios host reconcile") {
		t.Fatalf("a policy the push user can't reach: %v", err)
	}
}

func TestThePolicyFilesAreWrittenWholeAndKeepHandWrittenLines(t *testing.T) {
	_, pub := signingKey(t, "kyle")
	dir := policyWith(t, both(allow("kyle@example.com", pub, gitOnly), requiring("hello"), requiring("api")))
	for _, name := range []string{signersName, policyName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("%s: %v %v", name, err, info.Mode())
		}
	}
	signers, _ := os.ReadFile(filepath.Join(dir, signersName))
	if !strings.Contains(string(signers), "kyle@example.com namespaces=\"git\" ssh-ed25519 ") {
		t.Fatalf("allowed signers:\n%s", signers)
	}
	f, _ := os.OpenFile(filepath.Join(dir, signersName), os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprintln(f, `*@example.com cert-authority ssh-ed25519 AAAAhandwritten`)
	f.Close()
	if err := UpdatePolicy(dir, func(p *Policy) error { p.Require("api", true); return nil }); err != nil {
		t.Fatal(err)
	}
	p, err := ReadPolicy(dir)
	if err != nil || len(p.Signers) != 1 || len(p.Others) != 1 || strings.Join(p.RequireSigned, ",") != "hello" {
		t.Fatalf("%v %+v", err, p)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, policyName))
	var file policyFile
	if err := json.Unmarshal(raw, &file); err != nil || len(file.RequireSigned) != 1 {
		t.Fatalf("%s %v", raw, err)
	}
	// Changes from many processes at once all land.
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			if err := UpdatePolicy(dir, requiring(fmt.Sprintf("app-%d", i))); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if p, err := ReadPolicy(dir); err != nil || len(p.RequireSigned) != 21 {
		t.Fatalf("%v %v", err, p.RequireSigned)
	}
}

func TestTheBedrockGroupMayPassThroughEtcBedrockAndListNothing(t *testing.T) {
	const bedrock, adm = 997, 4
	for name, c := range map[string]struct {
		mode      os.FileMode
		gid       int
		wantGroup int
		wantMode  os.FileMode
	}{
		"a stock 755 root:root":          {0o755, 0, bedrock, 0o715},
		"750 root:root":                  {0o750, 0, bedrock, 0o710},
		"700 root:root":                  {0o700, 0, bedrock, 0o710},
		"715 root:bedrock, as reconcile": {0o715, bedrock, -1, 0o715},
		"755 root:bedrock":               {0o755, bedrock, -1, 0o715},
		"755 of another group":           {0o755, adm, -1, 0o755},
		"750 of another group gains o+x": {0o750, adm, -1, 0o751},
	} {
		group, mode := sharedParent(c.mode, c.gid, bedrock)
		if group != c.wantGroup || mode != c.wantMode {
			t.Errorf("%s: group %d mode %o, want %d %o", name, group, mode, c.wantGroup, c.wantMode)
		}
	}
}

func TestAnUploadedTreeIsRefusedForAnAppThatRequiresSignedCommits(t *testing.T) {
	dir := policyWith(t, requiring("hello"))
	if err := CheckTree(dir, "hello"); err == nil || !strings.Contains(err.Error(), "an uploaded tree has no commit to check") || !strings.Contains(err.Error(), "helios deploy --to root@") {
		t.Fatalf("%v", err)
	}
	if err := CheckTree(dir, "other"); err != nil {
		t.Fatal(err)
	}
}

// hookSigned runs the hook in a bare repository, held to a policy.
func hookSigned(t *testing.T, bare, policy, line string, d Deployer) (int, string, string) {
	t.Helper()
	old, _ := os.Getwd()
	if err := os.Chdir(bare); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	savedBuilds, savedSigning := hookBuildsDir, signingDir
	hookBuildsDir, signingDir = t.TempDir(), policy
	defer func() { hookBuildsDir, signingDir = savedBuilds, savedSigning }()
	builds := hookBuildsDir
	var out bytes.Buffer
	code := Hook(context.Background(), "hello", strings.NewReader(line), &out, d)
	return code, out.String(), builds
}

func TestAPushOfAnUnsignedTipIsRefusedBeforeAnythingIsExported(t *testing.T) {
	key, pub := signingKey(t, "kyle")
	files := map[string]string{"helios.yaml": helloYAML, "main.go": "package main"}
	policy := policyWith(t, both(allow("kyle@example.com", pub, gitOnly), requiring("hello")))
	var seen []app.DeployInput

	bare, commit := signedRepo(t, files, "")
	code, out, builds := hookSigned(t, bare, policy, zeroCommit+" "+commit+" refs/heads/main\n", fakeDeployer(state.Succeeded, &seen))
	if code == 0 || len(seen) != 0 || !strings.Contains(out, "commit "+commit[:12]+" isn't signed; the push is refused") || strings.Contains(out, "deploying") {
		t.Fatalf("code %d, seen %+v, out:\n%s", code, seen, out)
	}
	if entries, _ := os.ReadDir(builds); len(entries) != 0 {
		t.Fatalf("a refused commit was exported: %v", entries)
	}

	bare, commit = signedRepo(t, files, key)
	code, out, _ = hookSigned(t, bare, policy, zeroCommit+" "+commit+" refs/heads/main\n", fakeDeployer(state.Succeeded, &seen))
	k, _ := ParseKey(pub)
	if code != 0 || len(seen) != 1 || seen[0].Signer != "kyle@example.com ("+k.Fingerprint()+")" || !strings.Contains(out, commit[:12]+" is signed by kyle@example.com") {
		t.Fatalf("code %d, seen %+v, out:\n%s", code, seen, out)
	}
}

func TestAWebhookForAnUnsignedTipIsRefusedAndSaysSo(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sec := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "key")}
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	manifestJSON := json.RawMessage(`{"app":"hello","workloads":{"web":{"kind":"web","image":"x","port":8000,"routes":[{"host":"hello.example.com"}]}}}`)
	if err := store.SaveRevision(ctx, state.Revision{App: "hello", ID: "r1", Status: state.RevisionFailed, Manifest: manifestJSON, Images: map[string]string{}, Containers: map[string]string{}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(ctx, "hello", "r1", time.Now()); err != nil {
		t.Fatal(err)
	}
	key, pub := signingKey(t, "kyle")
	files := map[string]string{"helios.yaml": helloYAML, "main.go": "package main"}
	policy := policyWith(t, both(allow("kyle@example.com", pub, gitOnly), requiring("hello")))
	var mu sync.Mutex
	var seen []app.DeployInput
	var notices []string
	r := &Receiver{
		Store: store, Secrets: sec, Log: t.Logf, SigningDir: policy,
		SourcesDir: filepath.Join(dir, "sources"), BuildsDir: filepath.Join(dir, "builds"),
		Deploy: func(_ context.Context, in app.DeployInput, emit func(kernel.Event)) (*kernel.Receipt, error) {
			mu.Lock()
			seen = append(seen, in)
			mu.Unlock()
			return &kernel.Receipt{Status: state.Succeeded}, nil
		},
		Notify: func(_ context.Context, subject, body string) {
			mu.Lock()
			notices = append(notices, subject+"\n"+body)
			mu.Unlock()
		},
	}
	deliver := func(bare, commit string) *state.GitHook {
		t.Helper()
		hook, err := Configure(ctx, store, sec, "hello", "file://"+bare, "main", "hello.example.com")
		if err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"ref":"refs/heads/main","after":"` + commit + `"}`)
		req := httptest.NewRequest(http.MethodPost, "https://hello.example.com/_bedrock/hook", bytes.NewReader(body))
		req.Host = "hello.example.com"
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-Hub-Signature-256", sign(hook.Secret, body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		wait, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		r.Wait(wait)
		got, err := store.GitHookFor(ctx, "hello")
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	bare, commit := signedRepo(t, files, "")
	got := deliver(bare, commit)
	mu.Lock()
	if len(seen) != 0 || !strings.HasPrefix(got.LastResult, "refused: hello deploys only commits signed by kyle@example.com, and commit "+commit[:12]+" isn't signed") {
		t.Fatalf("seen %+v, result %q", seen, got.LastResult)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "the deploy from file://"+bare+" was refused") || !strings.Contains(notices[0], "helios git signers list") || strings.Contains(notices[0], "helios history") {
		t.Fatalf("%q", notices)
	}
	mu.Unlock()
	if entries, _ := os.ReadDir(filepath.Join(dir, "builds")); len(entries) != 0 {
		t.Fatalf("a refused commit was exported: %v", entries)
	}

	bare, commit = signedRepo(t, files, key)
	got = deliver(bare, commit)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || got.LastResult != "deployed" || !strings.HasPrefix(seen[0].Signer, "kyle@example.com (SHA256:") {
		t.Fatalf("seen %+v, result %q", seen, got.LastResult)
	}
}

// planAndApply plans an operation and applies its steps, as the kernel
// would.
func planAndApply(t *testing.T, d kernel.Definition, input any) (*kernel.Plan, string, error) {
	t.Helper()
	raw, _ := json.Marshal(input)
	plan, err := d.Plan(context.Background(), raw)
	if err != nil {
		return nil, "", err
	}
	var out bytes.Buffer
	for _, step := range plan.Steps {
		if err := step.Apply(context.Background(), &out); err != nil {
			return plan, out.String(), err
		}
	}
	return plan, out.String(), nil
}

func TestSignersAndTheAppsThatRequireThemArePlannedChanges(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "git")
	_, pub := signingKey(t, "kyle")
	k, _ := ParseKey(pub)
	require := RequireSigned{Dir: dir}
	if _, _, err := planAndApply(t, require, RequireSignedInput{App: "hello"}); err == nil || !strings.Contains(err.Error(), "no signer is allowed yet") {
		t.Fatalf("requiring signatures before anyone may sign: %v", err)
	}
	if _, _, err := planAndApply(t, SignersAdd{Dir: dir}, SignersAddInput{Principal: "kyle example", Key: pub}); err == nil {
		t.Fatal("a name with a space was accepted")
	}
	plan, out, err := planAndApply(t, SignersAdd{Dir: dir}, SignersAddInput{Principal: "kyle@example.com", Key: pub, By: "kyle"})
	if err != nil || plan.Steps[0].Change != "let kyle@example.com sign deploy commits with ssh-ed25519 key "+k.Fingerprint()+", asked by kyle" || !strings.Contains(out, "may sign") {
		t.Fatalf("%v %+v %s", err, plan, out)
	}
	if plan, _, err := planAndApply(t, SignersAdd{Dir: dir}, SignersAddInput{Principal: "kyle@example.com", Key: pub}); err != nil || !strings.Contains(plan.Steps[0].Note, "already signs with this key, so nothing changes") {
		t.Fatalf("the same signer twice: %v %+v", err, plan)
	}
	if _, _, err := planAndApply(t, SignersAdd{Dir: dir}, SignersAddInput{Principal: "someone@example.com", Key: pub}); err == nil || !strings.Contains(err.Error(), "already signs as kyle@example.com") {
		t.Fatalf("one key for two names: %v", err)
	}
	plan, _, err = planAndApply(t, require, RequireSignedInput{App: "hello"})
	if err != nil || !strings.Contains(plan.Steps[0].Change, "deploy hello only from commits signed by kyle@example.com") {
		t.Fatalf("%v %+v", err, plan)
	}
	if p, _ := ReadPolicy(dir); !p.Requires("hello") {
		t.Fatalf("%+v", p)
	}
	if plan, _, err := planAndApply(t, require, RequireSignedInput{App: "hello"}); err != nil || !strings.Contains(plan.Steps[0].Note, "already deploys only signed commits") {
		t.Fatalf("requiring it twice must say so: %v %+v", err, plan)
	}
	if plan, _, err := planAndApply(t, SignersRemove{Dir: dir}, SignersRemoveInput{Signer: "nobody@example.com"}); err != nil || !strings.Contains(plan.Steps[0].Note, "no allowed signer is nobody@example.com now, so nothing changes") {
		t.Fatalf("removing a signer nobody allowed must say so: %v %+v", err, plan)
	}
	for _, which := range []string{"kyle@example.com", k.Fingerprint(), pub} {
		plan, _, err = planAndApply(t, SignersRemove{Dir: dir}, SignersRemoveInput{Signer: which})
		if err != nil || !strings.Contains(plan.Steps[0].Note, "every push of hello is refused") {
			t.Fatalf("%s: %v %+v", which, err, plan)
		}
		if p, _ := ReadPolicy(dir); len(p.Signers) != 0 {
			t.Fatalf("%s: %+v", which, p)
		}
		if _, _, err := planAndApply(t, SignersAdd{Dir: dir}, SignersAddInput{Principal: "kyle@example.com", Key: pub}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := planAndApply(t, require, RequireSignedInput{App: "hello", Off: true}); err != nil {
		t.Fatal(err)
	}
	if p, _ := ReadPolicy(dir); p.Requires("hello") {
		t.Fatalf("%+v", p)
	}
	if plan, _, err := planAndApply(t, require, RequireSignedInput{App: "hello", Off: true}); err != nil || !strings.Contains(plan.Steps[0].Note, "doesn't require signed commits") {
		t.Fatalf("turning off what isn't on must say so: %v %+v", err, plan)
	}
}

// sameDigest reports whether two plans would have the same digest, which
// is what lets the kernel resume an operation by planning it again.
func sameDigest(a, b *kernel.Plan) bool {
	if a.Target != b.Target || a.Recovery != b.Recovery || len(a.Steps) != len(b.Steps) {
		return false
	}
	for i := range a.Steps {
		if a.Steps[i].Name != b.Steps[i].Name || a.Steps[i].Change != b.Steps[i].Change {
			return false
		}
	}
	return true
}

func TestASignersChangeThatStoppedAfterWritingPlansTheSameAgainAndFinishes(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "git")
	_, pub := signingKey(t, "kyle")
	for _, c := range []struct {
		d     kernel.Definition
		input any
	}{
		{SignersAdd{Dir: dir}, SignersAddInput{Principal: "kyle@example.com", Key: pub}},
		{RequireSigned{Dir: dir}, RequireSignedInput{App: "hello"}},
		{RequireSigned{Dir: dir}, RequireSignedInput{App: "hello", Off: true}},
		{SignersRemove{Dir: dir}, SignersRemoveInput{Signer: "kyle@example.com"}},
	} {
		raw, _ := json.Marshal(c.input)
		before, err := c.d.Plan(ctx, raw)
		if err != nil {
			t.Fatalf("%+v: %v", c.input, err)
		}
		for _, step := range before.Steps {
			if err := step.Apply(ctx, io.Discard); err != nil {
				t.Fatalf("%+v: %v", c.input, err)
			}
		}
		// The daemon stopped here: the policy is written, the receipt isn't.
		again, err := c.d.Plan(ctx, raw)
		if err != nil || !sameDigest(before, again) || !strings.Contains(again.Steps[0].Note, "nothing changes") {
			t.Fatalf("%+v planned again: %v %+v", c.input, err, again)
		}
		for _, step := range again.Steps {
			if err := step.Apply(ctx, io.Discard); err != nil {
				t.Fatalf("%+v resumed: %v", c.input, err)
			}
		}
	}
}

func TestRemovingOneNameKeepsAnotherThatSharesItsKey(t *testing.T) {
	_, pub := signingKey(t, "shared")
	k, _ := ParseKey(pub)
	dir := policyWith(t, both(allow("kyle@example.com", pub, gitOnly), allow("ops@example.com", pub, gitOnly)))
	if _, _, err := planAndApply(t, SignersRemove{Dir: dir}, SignersRemoveInput{Signer: "kyle@example.com"}); err != nil {
		t.Fatal(err)
	}
	p, err := ReadPolicy(dir)
	if err != nil || len(p.Signers) != 1 || p.Signers[0].Principal != "ops@example.com" {
		t.Fatalf("%v %+v", err, p.Signers)
	}
	dir = policyWith(t, both(allow("kyle@example.com", pub, gitOnly), allow("ops@example.com", pub, gitOnly)))
	plan, _, err := planAndApply(t, SignersRemove{Dir: dir}, SignersRemoveInput{Signer: k.Fingerprint()})
	if err != nil || !strings.Contains(plan.Steps[0].Note, "kyle@example.com") || !strings.Contains(plan.Steps[0].Note, "ops@example.com") {
		t.Fatalf("%v %+v", err, plan)
	}
	if p, _ := ReadPolicy(dir); len(p.Signers) != 0 {
		t.Fatalf("removing by key keeps %+v", p.Signers)
	}
}

func TestHandWrittenCommentsSurviveEveryChange(t *testing.T) {
	_, pub := signingKey(t, "kyle")
	_, laptop := signingKey(t, "laptop")
	_, other := signingKey(t, "other")
	dir := policyWith(t, allow("kyle@example.com", pub, gitOnly))
	signers := filepath.Join(dir, signersName)
	k, _ := ParseKey(laptop)
	handWritten := "# kyle's laptop, added by hand\nlaptop@example.com namespaces=\"git\" " + k.Type + " " + k.Blob + " the old laptop\n\n"
	f, _ := os.OpenFile(signers, os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprint(f, handWritten)
	f.Close()
	before, _ := os.ReadFile(signers)
	if _, _, err := planAndApply(t, RequireSigned{Dir: dir}, RequireSignedInput{App: "hello"}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(signers); !bytes.Equal(before, after) {
		t.Fatalf("requiring signatures rewrote the signers:\n%s\nwas\n%s", after, before)
	}
	if _, _, err := planAndApply(t, SignersAdd{Dir: dir}, SignersAddInput{Principal: "ops@example.com", Key: other}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := planAndApply(t, SignersRemove{Dir: dir}, SignersRemoveInput{Signer: "kyle@example.com"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(signers)
	if !strings.Contains(string(after), handWritten) || strings.Contains(string(after), "kyle@example.com") || !strings.Contains(string(after), "ops@example.com") || strings.Count(string(after), signersHeader) != 1 {
		t.Fatalf("allowed signers:\n%s", after)
	}
	if p, err := ReadPolicy(dir); err != nil || p.Holder(k.Blob, "") != "laptop@example.com" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestAKeyOutsideItsValidDatesDoesntSign(t *testing.T) {
	ctx := context.Background()
	key, pub := signingKey(t, "kyle")
	bare, commit := signedRepo(t, map[string]string{"helios.yaml": helloYAML}, key)
	for options, want := range map[string]string{
		gitOnly + `,valid-before="20200101"`: "doesn't allow at the commit's date",
		gitOnly + `,valid-after="29990101"`:  "doesn't allow at the commit's date",
		gitOnly + `,valid-after="20200101"`:  "",
	} {
		policy := policyWith(t, both(allow("kyle@example.com", pub, options), requiring("hello")))
		who, err := CheckTip(ctx, policy, "hello", bare, commit)
		if want == "" {
			if err != nil || who == "" {
				t.Errorf("%s: %q %v", options, who, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %q %v", options, who, err)
		}
	}
}

func TestAReplaceRefCantChangeWhatASignedCommitDeploys(t *testing.T) {
	ctx := context.Background()
	key, pub := signingKey(t, "kyle")
	bare, commit := signedRepo(t, map[string]string{"helios.yaml": helloYAML}, key)
	policy := policyWith(t, both(allow("kyle@example.com", pub, gitOnly), requiring("hello")))
	git := func(stdin string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", bare}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
		return strings.TrimSpace(string(out))
	}
	// Someone who can push swaps the signed commit's tree for another.
	tree := git("", "rev-parse", commit+"^{tree}")
	evil := git("app: evil\n", "hash-object", "-w", "--stdin")
	evilTree := git("100644 blob "+evil+"\thelios.yaml\n", "mktree")
	git("", "replace", tree, evilTree)
	if _, err := CheckTip(ctx, policy, "hello", bare, commit); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := ExportCommit(ctx, bare, commit, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "helios.yaml")); string(got) != helloYAML {
		t.Fatalf("the export followed the replace ref:\n%s", got)
	}

	// A push that would add a replace ref is refused, and deleting one isn't.
	var seen []app.DeployInput
	code, out, _ := hookSigned(t, bare, policy, zeroCommit+" "+evilTree+" refs/replace/"+tree+"\n", fakeDeployer(state.Succeeded, &seen))
	if code == 0 || len(seen) != 0 || !strings.Contains(out, "replace refs aren't kept here, and the push is refused") {
		t.Fatalf("code %d, out:\n%s", code, out)
	}
	if code, out, _ := hookSigned(t, bare, policy, evilTree+" "+zeroCommit+" refs/replace/"+tree+"\n", fakeDeployer(state.Succeeded, &seen)); code != 0 || len(seen) != 0 {
		t.Fatalf("deleting a replace ref: code %d, out:\n%s", code, out)
	}
}
