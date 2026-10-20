package gitdeploy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

// A real ed25519 public key (a throwaway, generated for this test).
const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbl2PAEEDEdOcJbAgHmimw2G6VM5yyT4XHNwMjpm8gV kyle@mac"

func TestKeysAreBoundToTheirApps(t *testing.T) {
	k, err := ParseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if k.Comment != "kyle@mac" || !strings.HasPrefix(k.Fingerprint(), "SHA256:") {
		t.Fatalf("%+v %s", k, k.Fingerprint())
	}
	path := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ssh-rsa AAAAB3Nza someone-else-by-hand\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kf, err := ReadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"begamin", "dragon-writer", "begamin"} {
		if _, err := kf.Allow(k, app); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := kf.Allow(k, "Not An App"); err == nil {
		t.Fatal("a name that isn't an app's went into a forced command")
	}
	if err := kf.Write(); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(path)
	want := `command="/usr/local/bin/bedrock git serve begamin dragon-writer",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbl2PAEEDEdOcJbAgHmimw2G6VM5yyT4XHNwMjpm8gV kyle@mac`
	if !strings.Contains(string(text), want) || !strings.Contains(string(text), "someone-else-by-hand") {
		t.Fatalf("key file:\n%s", text)
	}
	again, err := ReadKeys(path)
	if err != nil || len(again.Keys) != 1 || strings.Join(again.Keys[0].Apps, ",") != "begamin,dragon-writer" || len(again.Others) != 1 {
		t.Fatalf("%+v %v", again, err)
	}
	if !again.Deny("begamin", k.Fingerprint()) || !again.Deny("dragon-writer", pub) {
		t.Fatal("deny didn't find the key")
	}
	if len(again.Keys) != 0 || again.Deny("begamin", k.Fingerprint()) {
		t.Fatalf("a key with no apps must go: %+v", again.Keys)
	}
	for _, bad := range []string{"", "ssh-ed25519", "ssh-dss AAAA", "ssh-ed25519 not-base64!", "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQ"} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestOnlyTheAllowedCommandsRun(t *testing.T) {
	cases := map[string]Request{
		"git-receive-pack 'begamin.git'":      {Receive, "begamin"},
		"git-receive-pack '/begamin.git'":     {Receive, "begamin"},
		"git receive-pack 'begamin'":          {Receive, "begamin"},
		"git-upload-pack 'dragon-writer.git'": {Upload, "dragon-writer"},
		"bedrock receive begamin":             {Tarball, "begamin"},
	}
	for cmd, want := range cases {
		got, err := ParseCommand(cmd)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", cmd, got, err)
		}
	}
	for _, cmd := range []string{"", "bash", "git-receive-pack '../../etc.git'", "git-receive-pack 'Begamin.git'", "helios remove begamin", "git-receive-pack 'a b.git'", "scp -t /tmp"} {
		if _, err := ParseCommand(cmd); err == nil {
			t.Errorf("allowed %q", cmd)
		}
	}
	req, _ := ParseCommand("git-receive-pack 'site.git'")
	if err := req.Allowed([]string{"begamin"}); err == nil || !strings.Contains(err.Error(), "deploys begamin, not site") {
		t.Fatalf("%v", err)
	}
}

func tarOf(t *testing.T, entries ...[3]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		switch e[0] {
		case "file":
			_ = tw.WriteHeader(&tar.Header{Name: e[1], Mode: 0o644, Size: int64(len(e[2])), Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte(e[2]))
		case "link":
			_ = tw.WriteHeader(&tar.Header{Name: e[1], Linkname: e[2], Typeflag: tar.TypeSymlink})
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

func TestExtractKeepsEverythingInside(t *testing.T) {
	dir := t.TempDir()
	err := Extract(bytes.NewReader(tarOf(t,
		[3]string{"file", "helios.yaml", "app: x"},
		[3]string{"file", "src/main.go", "package main"},
		[3]string{"link", "src/current", "main.go"},
		[3]string{"link", "shadow", "/etc/shadow"},
		[3]string{"link", "up", "../../outside"},
	)), dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "src", "current")); string(b) != "package main" {
		t.Fatalf("a link inside the tree should stay: %q", b)
	}
	for _, gone := range []string{"shadow", "up"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); err == nil {
			t.Errorf("%s points out of the tree and must not be written", gone)
		}
	}
	if err := Extract(bytes.NewReader(tarOf(t, [3]string{"file", "../escape", "x"})), t.TempDir()); err == nil {
		t.Fatal("a path outside the tree must be refused")
	}
}

func TestCheckSourceWantsItsOwnManifest(t *testing.T) {
	dir := t.TempDir()
	if _, err := CheckSource(dir, "hello"); err == nil {
		t.Fatal("no manifest")
	}
	yaml := "app: hello\nworkloads:\n  web:\n    kind: worker\n    image: alpine:3.21\n"
	_ = os.WriteFile(filepath.Join(dir, "helios.yaml"), []byte(yaml), 0o644)
	if _, err := CheckSource(dir, "site"); err == nil || !strings.Contains(err.Error(), "says app: hello, but this is site's remote") {
		t.Fatalf("%v", err)
	}
	if _, err := CheckSource(dir, "hello"); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	_ = os.Symlink(filepath.Join(dir, "helios.yaml"), filepath.Join(linked, "helios.yaml"))
	if _, err := CheckSource(linked, "hello"); err == nil {
		t.Fatal("a linked manifest must be refused")
	}
}

func TestSignatures(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/main"}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifySignature("s3cret", body, good) {
		t.Fatal("a good signature was refused")
	}
	for _, bad := range []string{"", "sha1=abc", good[:len(good)-2] + "00", "sha256=zz"} {
		if VerifySignature("s3cret", body, bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if VerifySignature("", body, good) {
		t.Fatal("no secret must mean no deploy")
	}
}

// repoWith makes a bare repository holding one commit of files, and
// returns it with the commit.
func repoWith(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	work, bare := t.TempDir(), filepath.Join(t.TempDir(), "up.git")
	git := func(dir string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
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
	git(work, "commit", "-q", "-m", "first")
	if out, err := exec.Command("git", "init", "-q", "--bare", "--initial-branch=main", bare).CombinedOutput(); err != nil {
		t.Fatalf("%s", out)
	}
	git(work, "push", "-q", bare, "main")
	return bare, git(work, "rev-parse", "HEAD")
}

const helloYAML = "app: hello\nworkloads:\n  web:\n    kind: worker\n    image: alpine:3.21\n"

func fakeDeployer(status state.OperationStatus, seen *[]app.DeployInput) Deployer {
	return func(_ context.Context, in app.DeployInput, emit func(kernel.Event)) (*kernel.Receipt, error) {
		*seen = append(*seen, in)
		emit(kernel.Event{Type: kernel.EventStepFinished, Step: &kernel.StepView{Name: "build-web", Status: state.StepSucceeded}})
		return &kernel.Receipt{Status: status}, nil
	}
}

func TestTheHookDeploysTheBranchAndRefusesAFailure(t *testing.T) {
	bare, commit := repoWith(t, map[string]string{"helios.yaml": helloYAML, "main.go": "package main"})
	old, _ := os.Getwd()
	if err := os.Chdir(bare); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	var seen []app.DeployInput
	var out bytes.Buffer
	line := zeroCommit + " " + commit + " refs/heads/main\n"
	code := hookWithBuilds(t, "hello", line, &out, fakeDeployer(state.Succeeded, &seen))
	if code != 0 || len(seen) != 1 || seen[0].Commit != commit[:12] || !strings.Contains(out.String(), "helios: hello is live") {
		t.Fatalf("code %d, seen %+v, out:\n%s", code, seen, out.String())
	}
	if b, err := os.ReadFile(filepath.Join(seen[0].Source, "main.go")); err != nil || string(b) != "package main" {
		t.Fatalf("the exported tree: %v %q", err, b)
	}
	out.Reset()
	if code := hookWithBuilds(t, "hello", line, &out, fakeDeployer(state.Failed, &seen)); code == 0 || !strings.Contains(out.String(), "the push is refused") {
		t.Fatalf("a failed deploy must refuse the push: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := hookWithBuilds(t, "hello", zeroCommit+" "+commit+" refs/heads/feature\n", &out, fakeDeployer(state.Succeeded, &seen)); code != 0 || !strings.Contains(out.String(), "feature kept; pushes to main deploy") || len(seen) != 2 {
		t.Fatalf("another branch is kept, not deployed: %d %d\n%s", code, len(seen), out.String())
	}
	out.Reset()
	if code := hookWithBuilds(t, "hello", commit+" "+zeroCommit+" refs/heads/main\n", &out, fakeDeployer(state.Succeeded, &seen)); code == 0 {
		t.Fatal("deleting the deploy branch must be refused")
	}
	out.Reset()
	if code := hookWithBuilds(t, "site", line, &out, fakeDeployer(state.Succeeded, &seen)); code == 0 || !strings.Contains(out.String(), "this is site's remote") {
		t.Fatalf("a push of another app's code must be refused: %d\n%s", code, out.String())
	}
}

// hookWithBuilds runs the hook with its build directory in a temp dir,
// and no signing policy.
func hookWithBuilds(t *testing.T, app, stdin string, out *bytes.Buffer, d Deployer) int {
	t.Helper()
	savedBuilds, savedSigning := hookBuildsDir, signingDir
	hookBuildsDir, signingDir = t.TempDir(), filepath.Join(t.TempDir(), "git")
	defer func() { hookBuildsDir, signingDir = savedBuilds, savedSigning }()
	return Hook(context.Background(), app, strings.NewReader(stdin), out, d)
}

func TestBranchNamesThatWouldBeFlagsAreRefused(t *testing.T) {
	for _, bad := range []string{"-x", "--upload-pack=evil", "a..b", "feat/", "", "x.lock", "a b"} {
		if err := ValidBranch(bad); err == nil {
			t.Errorf("%q was accepted as a branch name", bad)
		}
	}
	for _, good := range []string{"main", "feature/new-nav", "v1.2", "release-2026.09", "kyle_wip"} {
		if err := ValidBranch(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

func TestExtractCannotFollowExistingLinkOutside(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(outside, "protected")
	if err := os.WriteFile(protected, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := Extract(bytes.NewReader(tarOf(t, [3]string{"file", "linked/protected", "overwrite"})), dir); err == nil {
		t.Fatal("archive followed an existing link outside the destination")
	}
	got, err := os.ReadFile(protected)
	if err != nil || string(got) != "keep" {
		t.Fatalf("outside file changed: %q %v", got, err)
	}
}
