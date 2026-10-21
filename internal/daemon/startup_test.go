package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/gitdeploy"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

type startupRecoveryDefinition struct {
	planning, applying       chan struct{}
	releasePlan, releaseStep chan struct{}
}

func (*startupRecoveryDefinition) Kind() string { return "test.startup-recovery" }

func (d *startupRecoveryDefinition) Plan(ctx context.Context, _ json.RawMessage) (*kernel.Plan, error) {
	if d.planning != nil {
		close(d.planning)
		select {
		case <-d.releasePlan:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &kernel.Plan{Target: "startup", Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "recover", Change: "finish interrupted work", Apply: func(ctx context.Context, _ io.Writer) error {
			close(d.applying)
			select {
			case <-d.releaseStep:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}}}, nil
}

func startupRecoveryDaemon(t *testing.T, ctx context.Context) (*daemon, *startupRecoveryDefinition) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	def := &startupRecoveryDefinition{}
	reg := kernel.Registry{}
	reg.Add(def)
	engine := kernel.New(store, reg, "new-daemon")
	view, err := engine.PlanOnly(ctx, def.Kind(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.CreateOperation(ctx, state.NewOperation{ID: "op-startup", Kind: def.Kind(), Target: view.Target,
		Input: json.RawMessage(`null`), Plan: plan, PlanDigest: view.Digest, Recovery: string(kernel.Resume),
		StepNames: []string{"recover"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, "op-startup", "dead-daemon", now, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	def.planning, def.applying = make(chan struct{}), make(chan struct{})
	def.releasePlan, def.releaseStep = make(chan struct{}), make(chan struct{})
	d := &daemon{cfg: Config{Owner: "new-daemon", SweepInterval: time.Hour}, store: store,
		api: &api.Server{Store: store, Engine: engine, Lifetime: ctx}, logf: func(string, ...any) {}}
	d.stopStartup = notifierFromEnv().startup(ctx, startupNotifyInterval, func(ctx context.Context) bool {
		_, err := store.List(ctx, 1)
		return err == nil
	})
	t.Cleanup(d.stopStartup)
	return d, def
}

func awaitNotification(t *testing.T, sd *fakeSystemd, start int, prefix string, limit time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		messages := sd.messages()
		for _, message := range messages[start:] {
			if strings.HasPrefix(message, prefix) {
				return messages
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s notification within %s: %v", prefix, limit, messages)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStartupRecoveryExtendsDeadlineBeforeEventsAndDuringSilentSteps(t *testing.T) {
	sd := newFakeSystemd(t)
	t.Setenv("NOTIFY_SOCKET", sd.path())
	t.Setenv("WATCHDOG_USEC", "100000")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	d, def := startupRecoveryDaemon(t, ctx)
	done := make(chan error, 1)
	go func() { done <- d.recoverOperations(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("startup recovery did not stop")
		}
		d.loops.Wait()
	})
	<-def.planning
	// Planning emits no kernel event. Even here, a responsive recovering
	// daemon must renew its startup deadline without claiming readiness.
	messages := awaitNotification(t, sd, 0, "EXTEND_TIMEOUT_USEC=", 12*time.Second)
	if slices.Contains(messages, "READY=1") || slices.Contains(messages, "WATCHDOG=1") {
		t.Fatalf("not ready while rebuilding the plan: %v", messages)
	}
	close(def.releasePlan)
	<-def.applying
	messages = awaitNotification(t, sd, len(messages), "EXTEND_TIMEOUT_USEC=", 12*time.Second)
	if slices.Contains(messages, "READY=1") || slices.Contains(messages, "WATCHDOG=1") {
		t.Fatalf("not ready while applying recovery: %v", messages)
	}
	close(def.releaseStep)
	err := <-done
	done <- err // leave the result for cleanup
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := d.api.Engine.ReceiptOf(ctx, "op-startup")
	if err != nil || receipt.Status != state.Succeeded || receipt.Interruptions != 1 {
		t.Fatalf("recovery receipt: %+v, %v", receipt, err)
	}

	// Readiness and the ordinary watchdog start only with the API listener.
	d.cfg.Socket = filepath.Join(filepath.Dir(sd.path()), "api.sock")
	serving := make(chan error, 1)
	go func() { serving <- d.serveAPI(ctx, &gitdeploy.Receiver{}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serving:
			if err != nil {
				t.Errorf("serve API: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("API did not stop")
		}
	})
	awaitNotification(t, sd, len(messages), "READY=1", time.Second)
	awaitNotification(t, sd, len(messages), "WATCHDOG=1", time.Second)
	client := api.Dial(d.cfg.Socket)
	defer client.Close()
	if _, err := client.Version(ctx); err != nil {
		t.Fatalf("ready API did not answer: %v", err)
	}
}

func TestCancelDuringStartupRecoveryReturnsWithoutReadiness(t *testing.T) {
	sd := newFakeSystemd(t)
	t.Setenv("NOTIFY_SOCKET", sd.path())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	d, def := startupRecoveryDaemon(t, ctx)
	done := make(chan error, 1)
	go func() { done <- d.recoverOperations(ctx) }()
	<-def.planning
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("recovery cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup recovery did not stop after cancellation")
	}
	d.loops.Wait()
	if messages := sd.messages(); slices.Contains(messages, "READY=1") || slices.Contains(messages, "WATCHDOG=1") {
		t.Fatalf("canceled recovery claimed readiness: %v", messages)
	}
}

func TestStartupFailureReturnsWithoutReadinessOrExtension(t *testing.T) {
	sd := newFakeSystemd(t)
	t.Setenv("NOTIFY_SOCKET", sd.path())
	stateDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(stateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- Run(t.Context(), Config{StateDir: stateDir}, io.Discard) }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("invalid state directory did not fail startup")
		}
		// Run this same test with the lane's -broken build stamp to verify
		// that a bad candidate still exits before starting any recovery loop.
		if strings.Contains(version.Current().Version, "-broken") && !strings.Contains(err.Error(), "deliberately broken") {
			t.Fatalf("broken build did not refuse startup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup failure did not return promptly")
	}
	// A marker notification drains any earlier datagrams before asserting
	// that the failed candidate neither extended startup nor claimed READY.
	newNotifier(sd.path(), "").stopping()
	if messages := awaitNotification(t, sd, 0, "STOPPING=1", time.Second); len(messages) != 1 {
		t.Fatalf("failed candidate sent startup notifications: %v", messages)
	}
}

func TestRunExtendsDeadlineDuringEdgeStartupUntilAPIReadiness(t *testing.T) {
	sd := newFakeSystemd(t)
	t.Setenv("NOTIFY_SOCKET", sd.path())
	t.Setenv("WATCHDOG_USEC", "100000")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	inspecting := make(chan struct{})
	releaseEdge := make(chan struct{})
	var inspectOnce sync.Once
	docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.Header().Set("API-Version", "1.56")
			_, _ = io.WriteString(w, "OK")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/containers/bedrock-edge/json") {
			inspectOnce.Do(func() { close(inspecting) })
			select {
			case <-releaseEdge:
			case <-r.Context().Done():
			}
		}
		http.Error(w, `{"message":"no such container"}`, http.StatusNotFound)
	}))
	t.Cleanup(docker.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(docker.URL, "http://"))
	t.Setenv("DOCKER_API_VERSION", "1.56")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	cfg := Config{StateDir: t.TempDir(), Socket: filepath.Join(filepath.Dir(sd.path()), "api.sock")}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("daemon: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	select {
	case <-inspecting:
	case <-time.After(time.Second):
		t.Fatal("startup did not reach edge reconciliation")
	}
	messages := awaitNotification(t, sd, 0, "EXTEND_TIMEOUT_USEC=", time.Second)
	messages = awaitNotification(t, sd, len(messages), "EXTEND_TIMEOUT_USEC=", 12*time.Second)
	if slices.Contains(messages, "READY=1") || slices.Contains(messages, "WATCHDOG=1") {
		t.Fatalf("edge reconciliation claimed readiness: %v", messages)
	}
	if _, err := os.Stat(cfg.Socket); !os.IsNotExist(err) {
		t.Fatalf("API opened before edge startup completed: %v", err)
	}
	close(releaseEdge)
	awaitNotification(t, sd, len(messages), "READY=1", time.Second)
	awaitNotification(t, sd, len(messages), "WATCHDOG=1", time.Second)
	client := api.Dial(cfg.Socket)
	defer client.Close()
	if _, err := client.Version(ctx); err != nil {
		t.Fatalf("ready API did not answer: %v", err)
	}
}

func TestCancellationAtReadinessHandoffDoesNotSendReady(t *testing.T) {
	sd := newFakeSystemd(t)
	t.Setenv("NOTIFY_SOCKET", sd.path())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	d := &daemon{cfg: Config{Socket: filepath.Join(filepath.Dir(sd.path()), "api.sock")},
		store: store, api: &api.Server{Store: store}, logf: func(string, ...any) {},
		// Cancellation can arrive while joining the last startup health query.
		stopStartup: cancel,
	}
	if err := d.serveAPI(ctx, &gitdeploy.Receiver{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation at readiness handoff: %v", err)
	}
	newNotifier(sd.path(), "").stopping()
	if messages := awaitNotification(t, sd, 0, "STOPPING=1", time.Second); len(messages) != 1 {
		t.Fatalf("canceled startup claimed readiness: %v", messages)
	}
}

func TestAPIListenerFailureStillEndsStartup(t *testing.T) {
	sd := newFakeSystemd(t)
	t.Setenv("NOTIFY_SOCKET", sd.path())
	t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(filepath.Dir(sd.path()), "no-docker.sock"))
	socket := filepath.Join(filepath.Dir(sd.path()), "occupied")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := Run(ctx, Config{StateDir: t.TempDir(), Socket: socket}, io.Discard); err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("late startup failure did not return: %v", err)
	}
	newNotifier(sd.path(), "").stopping()
	messages := awaitNotification(t, sd, 0, "STOPPING=1", time.Second)
	if slices.Contains(messages, "READY=1") || slices.Contains(messages, "WATCHDOG=1") {
		t.Fatalf("failed API listener claimed readiness: %v", messages)
	}
}
