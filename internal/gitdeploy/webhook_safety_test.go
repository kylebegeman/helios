package gitdeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

func webhookSafetyFixture(t *testing.T) (*Receiver, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sec := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "key")}
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	m := json.RawMessage(`{"app":"hello","workloads":{"web":{"kind":"web","image":"x","port":8000,"routes":[{"host":"hello.example.com"}]}}}`)
	if err := store.SaveRevision(ctx, state.Revision{App: "hello", ID: "r1", Status: state.RevisionFailed, Manifest: m, Images: map[string]string{}, Containers: map[string]string{}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(ctx, "hello", "r1", time.Now()); err != nil {
		t.Fatal(err)
	}
	hook, err := Configure(ctx, store, sec, "hello", "https://example.com/hello.git", "main", "hello.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return &Receiver{Store: store, Secrets: sec, SigningDir: filepath.Join(dir, "git"), SourcesDir: filepath.Join(dir, "sources"), BuildsDir: filepath.Join(dir, "builds")}, hook.Secret
}

func TestWebhookRefusesBodiesBeyondTheAuthenticatedLimit(t *testing.T) {
	r, secret := webhookSafetyFixture(t)
	prefix := bytes.Repeat([]byte(" "), 5<<20)
	copy(prefix, []byte(`{"zen":"hello"}`))
	body := append(bytes.Clone(prefix), []byte("unauthenticated suffix")...)
	req := httptest.NewRequest(http.MethodPost, "https://hello.example.com/_bedrock/hook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "ping")
	req.Header.Set("X-Hub-Signature-256", sign(secret, prefix))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("request was authenticated using only a prefix: %d %s", w.Code, w.Body)
	}
	req = httptest.NewRequest(http.MethodPost, "https://hello.example.com/_bedrock/hook", bytes.NewReader(prefix))
	req.Header.Set("X-GitHub-Event", "ping")
	req.Header.Set("X-Hub-Signature-256", sign(secret, prefix))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated request at the size limit was refused: %d %s", w.Code, w.Body)
	}
}

func TestFailedWebhookSourceValidationRemovesItsTemporaryExport(t *testing.T) {
	r, _ := webhookSafetyFixture(t)
	bare, _ := signedRepo(t, map[string]string{"helios.yaml": "app: another\nworkloads:\n  worker: {kind: worker, image: alpine}\n"}, "")
	_, _, _, err := r.fetch(context.Background(), state.GitHook{App: "hello", Repo: "file://" + bare, Branch: "main"})
	if err == nil {
		t.Fatal("webhook accepted another app's source")
	}
	entries, err := os.ReadDir(filepath.Join(r.BuildsDir, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed export leaked source trees: %v", entries)
	}
}
