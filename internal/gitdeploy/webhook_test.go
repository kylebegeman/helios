package gitdeploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestAWebhookFetchesTheBranchAndDeploysIt(t *testing.T) {
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
	bare, commit := repoWith(t, map[string]string{"helios.yaml": helloYAML, "main.go": "package main"})
	hook, err := Configure(ctx, store, sec, "hello", "file://"+bare, "main", "hello.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if hook.URL != "https://hello.example.com/_bedrock/hook" || len(hook.Secret) != 64 || hook.DeployKey != "" {
		t.Fatalf("%+v", hook)
	}
	var mu sync.Mutex
	var seen []app.DeployInput
	r := &Receiver{
		Store: store, Secrets: sec, Log: t.Logf, SigningDir: filepath.Join(dir, "git"),
		SourcesDir: filepath.Join(dir, "sources"), BuildsDir: filepath.Join(dir, "builds"),
		Deploy: func(_ context.Context, in app.DeployInput, emit func(kernel.Event)) (*kernel.Receipt, error) {
			mu.Lock()
			seen = append(seen, in)
			mu.Unlock()
			return &kernel.Receipt{Status: state.Succeeded}, nil
		},
	}
	post := func(event string, body []byte, signature string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://hello.example.com/_bedrock/hook", strings.NewReader(string(body)))
		req.Host = "hello.example.com"
		req.Header.Set("X-GitHub-Event", event)
		req.Header.Set("X-Hub-Signature-256", signature)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	ping := []byte(`{"zen":"hi"}`)
	if w := post("ping", ping, sign(hook.Secret, ping)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hears hello's pushes to main") {
		t.Fatalf("ping: %d %s", w.Code, w.Body)
	}
	push := []byte(`{"ref":"refs/heads/main","after":"` + commit + `"}`)
	if w := post("push", push, sign("wrong", push)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a bad signature must be refused: %d", w.Code)
	}
	other := []byte(`{"ref":"refs/heads/feature","after":"` + commit + `"}`)
	if w := post("push", other, sign(hook.Secret, other)); w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "ignored") {
		t.Fatalf("another branch: %d %s", w.Code, w.Body)
	}
	if w := post("push", push, sign(hook.Secret, push)); w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "deploying "+commit[:12]) {
		t.Fatalf("push: %d %s", w.Code, w.Body)
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r.Wait(wait)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].Commit != commit[:12] {
		t.Fatalf("deploys: %+v", seen)
	}
	if b, err := os.ReadFile(filepath.Join(seen[0].Source, "main.go")); err != nil || string(b) != "package main" {
		t.Fatalf("fetched tree: %v %q", err, b)
	}
	hooks, _ := store.GitHooks(ctx)
	if len(hooks) != 1 || hooks[0].LastResult != "deployed" || hooks[0].LastCommit != commit[:12] {
		t.Fatalf("%+v", hooks)
	}
	// Another app's host, or no webhook at all, is not found.
	req := httptest.NewRequest(http.MethodPost, "https://other.example.com/_bedrock/hook", strings.NewReader("{}"))
	req.Host = "other.example.com"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown host: %d", w.Code)
	}
	if err := Disable(ctx, store, sec, "hello"); err != nil {
		t.Fatal(err)
	}
	if w := post("push", push, sign(hook.Secret, push)); w.Code != http.StatusNotFound {
		t.Fatalf("after disable: %d", w.Code)
	}
}

func TestValuesFromRequestsAreBoundedBeforeTheyAreLogged(t *testing.T) {
	if got := logSafe("203.0.113.9\nfake: line"); got != "203.0.113.9 fake: line" {
		t.Fatalf("got %q", got)
	}
	if got := logSafe(strings.Repeat("x", 100)); len(got) != 83 || !strings.HasSuffix(got, "...") {
		t.Fatalf("got %q", got)
	}
}
