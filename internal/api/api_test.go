package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

func server(t *testing.T) (*Client, *state.Store) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	reg := kernel.Registry{}
	reg.Add(kernel.Exercise{})
	srv := &Server{Engine: kernel.New(store, reg, "test-daemon"), Store: store}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return NewClient(ts.Client(), ts.URL), store
}

func input(t *testing.T, dir string, steps, failAt int) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(kernel.ExerciseInput{Dir: dir, Steps: steps, FailAt: failAt})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRunStreamsEventsAndEndsWithTheReceipt(t *testing.T) {
	ctx := context.Background()
	client, _ := server(t)
	dir := t.TempDir()
	var seen []kernel.EventType
	receipt, err := client.Run(ctx, kernel.ExerciseKind, input(t, dir, 2, 0), func(ev kernel.Event) { seen = append(seen, ev.Type) })
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != state.Succeeded || len(receipt.Steps) != 2 {
		t.Fatalf("receipt: %+v", receipt)
	}
	if seen[0] != kernel.EventPlanned || seen[len(seen)-1] != kernel.EventFinished {
		t.Fatalf("events: %v", seen)
	}
	if _, err := os.Stat(filepath.Join(dir, "step-2")); err != nil {
		t.Fatal("the operation didn't run on the server side")
	}
	rows, err := client.List(ctx, 10)
	if err != nil || len(rows) != 1 || rows[0].ID != receipt.ID || rows[0].Status != state.Succeeded {
		t.Fatalf("list: %v %+v", err, rows)
	}
	again, err := client.Receipt(ctx, receipt.ID)
	if err != nil || again.PlanDigest != receipt.PlanDigest {
		t.Fatalf("receipt by id: %v %+v", err, again)
	}
	info, err := client.Version(ctx)
	if err != nil || info.Version == "" {
		t.Fatalf("version: %v %+v", err, info)
	}
}

func TestPlanOnlyChangesNothing(t *testing.T) {
	ctx := context.Background()
	client, store := server(t)
	dir := t.TempDir()
	view, err := client.Plan(ctx, kernel.ExerciseKind, input(t, dir, 3, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Steps) != 3 || view.Digest == "" {
		t.Fatalf("plan: %+v", view)
	}
	if _, err := os.Stat(filepath.Join(dir, "step-1")); err == nil {
		t.Fatal("planning wrote a marker")
	}
	if ops, _ := store.List(ctx, 10); len(ops) != 0 {
		t.Fatal("planning recorded an operation")
	}
}

func TestErrorsComeBackAsErrors(t *testing.T) {
	ctx := context.Background()
	client, _ := server(t)
	if _, err := client.Plan(ctx, "no.such.kind", json.RawMessage(`{}`)); err == nil || err.Error() != `unknown operation kind "no.such.kind"` {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := client.Receipt(ctx, "op-nope"); err == nil || err.Error() != "not found" {
		t.Fatalf("missing receipt: %v", err)
	}
	if _, err := client.Run(ctx, kernel.ExerciseKind, json.RawMessage(`{"dir":""}`), func(kernel.Event) {}); err == nil {
		t.Fatal("a bad input must fail the run")
	}
}

func TestListenReplacesAStaleSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "q.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", err, info.Mode())
	}
	if _, err := Listen(socket); err == nil {
		t.Fatal("a live socket must not be replaced")
	}
}

func TestOnlyOneLocalOperationRunsAtATime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	unlock, err := LockOperations(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := LockOperations(ctx, path); err == nil || !strings.Contains(err.Error(), "another helios operation is running on this machine") {
		t.Fatalf("a second operation got the lock: %v", err)
	}
	unlock()
	again, err := LockOperations(context.Background(), path)
	if err != nil {
		t.Fatalf("the lock was not let go: %v", err)
	}
	again()
}

func TestHeldOperationLockSaysSinceWhen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if _, held, err := HeldOperationLock(path); err != nil || held {
		t.Fatalf("a machine that never ran an operation holds no lock: %v %v", held, err)
	}
	before := time.Now().UTC().Add(-time.Second)
	unlock, err := LockOperations(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	lock, held, err := HeldOperationLock(path)
	if err != nil || !held || lock.PID != os.Getpid() || lock.AcquiredAt.Before(before) || lock.AcquiredAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("held lock: %+v %v %v", lock, held, err)
	}
	// Looking must not get in the way of whoever takes the lock next.
	unlock()
	if _, held, err := HeldOperationLock(path); err != nil || held {
		t.Fatalf("a released lock still reads as held: %v %v", held, err)
	}
	again, err := LockOperations(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	again()
}

func TestHeldOperationLockFromAnOlderReleaseHasNoTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.MkdirAll(filepath.Join(filepath.Dir(path), "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Releases before 0.7.11 lock the file without writing to it.
	f, err := os.OpenFile(operationLockPath(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	lock, held, err := HeldOperationLock(path)
	if err != nil || !held || !lock.AcquiredAt.IsZero() {
		t.Fatalf("undated lock: %+v %v %v", lock, held, err)
	}
}

type lifecycleDefinition struct {
	started chan struct{}
	stopped chan struct{}
	release chan struct{}
}

func (l lifecycleDefinition) Kind() string { return "test.lifecycle" }
func (l lifecycleDefinition) Plan(context.Context, json.RawMessage) (*kernel.Plan, error) {
	return &kernel.Plan{Steps: []kernel.Step{{Name: "wait", Apply: func(ctx context.Context, _ io.Writer) error {
		close(l.started)
		select {
		case <-ctx.Done():
			close(l.stopped)
			return ctx.Err()
		case <-l.release:
			return nil
		}
	}}}}, nil
}
func TestDaemonLifetimeCancelsDetachedClientOperations(t *testing.T) {
	l := lifecycleDefinition{started: make(chan struct{}), stopped: make(chan struct{})}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reg := kernel.Registry{}
	reg.Add(l)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Engine: kernel.New(store, reg, "test"), Store: store}
	// A server lifetime is independent of the requesting client's lifetime.
	// The daemon supplies it during startup.
	srv.Lifetime = ctx
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := NewClient(ts.Client(), ts.URL)
	done := make(chan error, 1)
	go func() { _, err := client.Run(context.Background(), l.Kind(), nil, func(kernel.Event) {}); done <- err }()
	select {
	case <-l.started:
	case <-time.After(time.Second):
		t.Fatal("operation did not start")
	}
	cancel()
	select {
	case <-l.stopped:
	case <-time.After(time.Second):
		t.Fatal("daemon shutdown left operation running")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("operation stream did not close")
	}
}

func TestRunRequestRejectsTrailingJSON(t *testing.T) {
	client, _ := server(t)
	body := `{"kind":"kernel.exercise","input":{"dir":"/unused","steps":1},"plan_only":true} {"unexpected":true}`
	resp, err := client.http.Post(client.base+"/v1/operations", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("trailing request accepted: %d", resp.StatusCode)
	}
}
func TestClientDisconnectDoesNotCancelDaemonOperation(t *testing.T) {
	l := lifecycleDefinition{started: make(chan struct{}), stopped: make(chan struct{}), release: make(chan struct{})}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reg := kernel.Registry{}
	reg.Add(l)
	daemonCtx, stopDaemon := context.WithCancel(context.Background())
	defer stopDaemon()
	srv := &Server{Engine: kernel.New(store, reg, "test"), Store: store, Lifetime: daemonCtx}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := NewClient(ts.Client(), ts.URL)
	clientCtx, stopClient := context.WithCancel(context.Background())
	defer stopClient()
	done := make(chan error, 1)
	go func() { _, err := client.Run(clientCtx, l.Kind(), nil, func(kernel.Event) {}); done <- err }()
	select {
	case <-l.started:
	case <-time.After(time.Second):
		t.Fatal("operation did not start")
	}
	stopClient()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not disconnect")
	}
	select {
	case <-l.stopped:
		t.Fatal("client disconnect canceled daemon operation")
	default:
	}
	close(l.release)
	deadline := time.Now().Add(time.Second)
	for {
		ops, err := store.List(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(ops) == 1 && ops[0].Status == state.Succeeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation did not finish: %+v", ops)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := srv.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.RunLocked(context.Background(), l.Kind(), nil, func(kernel.Event) {}); err == nil {
		t.Fatal("drained server accepted new work")
	}
}

type lifecyclePlan struct{ started, stopped chan struct{} }

func (l lifecyclePlan) Kind() string { return "test.lifecycle-plan" }
func (l lifecyclePlan) Plan(ctx context.Context, _ json.RawMessage) (*kernel.Plan, error) {
	close(l.started)
	<-ctx.Done()
	close(l.stopped)
	return nil, ctx.Err()
}
func TestDaemonLifetimeTracksAndCancelsPlanRequests(t *testing.T) {
	l := lifecyclePlan{started: make(chan struct{}), stopped: make(chan struct{})}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reg := kernel.Registry{}
	reg.Add(l)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Engine: kernel.New(store, reg, "test"), Store: store, Lifetime: ctx}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := NewClient(ts.Client(), ts.URL)
	done := make(chan error, 1)
	go func() { _, err := client.Plan(context.Background(), l.Kind(), nil); done <- err }()
	select {
	case <-l.started:
	case <-time.After(time.Second):
		t.Fatal("plan did not start")
	}
	cancel()
	select {
	case <-l.stopped:
	case <-time.After(time.Second):
		t.Fatal("daemon shutdown left planning active")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled plan reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("plan stream did not close")
	}
	if err := srv.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestListenPreservesNonSocketPaths(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			socket := filepath.Join(dir, "api.sock")
			const contents = "fixture configuration"
			switch kind {
			case "file":
				if err := os.WriteFile(socket, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.WriteFile(filepath.Join(dir, "config"), []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("config", socket); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(socket, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			listener, err := Listen(socket)
			if listener != nil {
				listener.Close()
			}
			if err == nil {
				t.Fatal("listener replaced a non-socket path")
			}
			info, err := os.Lstat(socket)
			if err != nil {
				t.Fatalf("existing path was removed: %v", err)
			}
			switch kind {
			case "file":
				body, err := os.ReadFile(socket)
				if err != nil || string(body) != contents {
					t.Fatalf("existing contents changed: %q, %v", body, err)
				}
			case "symlink":
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("existing symlink changed")
				}
			case "directory":
				if !info.IsDir() {
					t.Fatal("existing directory changed")
				}
			}
		})
	}
}

func TestSocketGroupPreservesSharedParentPermissions(t *testing.T) {
	for _, tc := range []struct{ mode, want os.FileMode }{
		{0o755, 0o755},
		{os.ModeSticky | 0o777, os.ModeSticky | 0o777},
		{0o700, 0o750},
	} {
		dir := t.TempDir()
		mode := tc.mode
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(dir, "api.sock")
		if err := os.WriteFile(socket, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		setSocketGroup(socket, os.Getgid())
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode() & (os.ModePerm | os.ModeSticky); got != tc.want {
			t.Errorf("parent mode = %v, want %v", got, tc.want)
		}
	}
}
