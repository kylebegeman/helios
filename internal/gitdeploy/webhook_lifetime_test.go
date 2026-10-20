package gitdeploy

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

func TestWebhookWorkersStopAndDiscardPendingOnDaemonCancellation(t *testing.T) {
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
	bare, _ := repoWith(t, map[string]string{"helios.yaml": helloYAML})
	if _, err := Configure(context.Background(), store, sec, "hello", "file://"+bare, "main", "hello.example.com"); err != nil {
		t.Fatal(err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan context.Context, 1)
	var deployments atomic.Int32
	receiver := &Receiver{Context: lifetime, Store: store, Secrets: sec, SigningDir: filepath.Join(dir, "git"), SourcesDir: filepath.Join(dir, "sources"), BuildsDir: filepath.Join(dir, "builds"), Deploy: func(ctx context.Context, _ app.DeployInput, _ func(kernel.Event)) (*kernel.Receipt, error) {
		deployments.Add(1)
		entered <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if !receiver.enqueue("hello") {
		t.Fatal("active worker refused")
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("webhook did not reach deploy")
	}
	if !receiver.enqueue("hello") {
		t.Fatal("pending worker refused")
	}
	cancel()
	wait, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	receiver.Wait(wait)
	if wait.Err() != nil {
		t.Fatal("webhook workers outlived daemon cancellation")
	}
	if receiver.enqueue("hello") {
		t.Fatal("shutdown receiver accepted more work")
	}
	if deployments.Load() != 1 {
		t.Fatalf("pending deployment ran during shutdown: %d", deployments.Load())
	}
}
