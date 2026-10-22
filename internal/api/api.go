// Package api is how the CLI talks to a daemon: JSON over a Unix socket,
// with operations streamed as one event per line. Local is the same
// contract without a daemon, for a machine that has none (the Mac).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/kylebegeman/helios/internal/compat"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

// Summary is one operation as history lists it.
type Summary struct {
	ID            string                `json:"id"`
	Kind          string                `json:"kind"`
	Target        string                `json:"target"`
	Status        state.OperationStatus `json:"status"`
	CreatedAt     time.Time             `json:"created_at"`
	FinishedAt    time.Time             `json:"finished_at,omitempty"`
	Interruptions int                   `json:"interruptions"`
	Error         string                `json:"error,omitempty"`
}

func summarize(op state.Operation) Summary {
	return Summary{ID: op.ID, Kind: op.Kind, Target: op.Target, Status: op.Status, CreatedAt: op.CreatedAt, FinishedAt: op.FinishedAt, Interruptions: op.Interruptions, Error: op.Error}
}

// Runner is what the CLI needs, whether a daemon or the local kernel serves it.
type Runner interface {
	Version(ctx context.Context) (version.Info, error)
	Plan(ctx context.Context, kind string, input json.RawMessage) (*kernel.PlanView, error)
	Run(ctx context.Context, kind string, input json.RawMessage, emit func(kernel.Event)) (*kernel.Receipt, error)
	RunExpecting(ctx context.Context, kind string, input json.RawMessage, expect string, emit func(kernel.Event)) (*kernel.Receipt, error)
	List(ctx context.Context, limit int) ([]Summary, error)
	ListFiltered(ctx context.Context, filter state.OperationFilter) ([]Summary, error)
	Receipt(ctx context.Context, id string) (*kernel.Receipt, error)
	Output(ctx context.Context, id, step string) (*kernel.OperationOutput, error)
	Close() error
}

// RunRequest is the body of POST /v1/operations.
type RunRequest struct {
	Kind     string          `json:"kind"`
	Input    json.RawMessage `json:"input"`
	PlanOnly bool            `json:"plan_only,omitempty"`
	// Expect is the digest of the plan the caller means to apply. When it
	// is set and the plan built now differs, nothing runs.
	Expect string `json:"expect,omitempty"`
}

// Server serves the API for one engine. Operations run one at a time: the
// daemon is the single authority on its machine.
type Server struct {
	Engine *kernel.Engine
	Store  *state.Store
	// Lifetime bounds work to the daemon rather than an individual client.
	// Nil retains the standalone server's caller-controlled lifetime.
	Lifetime context.Context
	mu       sync.Mutex
	workMu   sync.Mutex
	work     sync.WaitGroup
	stopping bool
}

// begin binds accepted work to the daemon's lifetime and tracks it for drain.
func (s *Server) begin(ctx context.Context) (context.Context, func(), error) {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.stopping {
		return nil, nil, context.Canceled
	}
	if s.Lifetime != nil {
		if err := s.Lifetime.Err(); err != nil {
			return nil, nil, err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := func() bool { return false }
	if s.Lifetime != nil {
		stop = context.AfterFunc(s.Lifetime, cancel)
	}
	s.work.Add(1)
	return ctx, func() { stop(); cancel(); s.work.Done() }, nil
}

// Drain stops accepting operations and waits for accepted work to leave the
// engine. The daemon cancels Lifetime before draining, so leases and subprocesses
// stop before the state store closes.
func (s *Server) Drain(ctx context.Context) error {
	s.workMu.Lock()
	s.stopping = true
	s.workMu.Unlock()
	done := make(chan struct{})
	go func() { s.work.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) lock(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.mu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Recover finishes operations left behind by a daemon that died, one at a
// time with everything else the server runs. The daemon calls it at start
// and then keeps sweeping, because a dead daemon's lease can outlive its
// restart.
func (s *Server) Recover(ctx context.Context, emit func(kernel.Event)) (int, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer done()
	if err := s.lock(ctx); err != nil {
		return 0, err
	}
	defer s.mu.Unlock()
	unlock, err := s.lockMachine(ctx)
	if err != nil {
		return 0, err
	}
	defer unlock()
	return s.Engine.Recover(ctx, emit)
}

// RunLocked runs an operation the daemon starts on its own clock, such as
// a scheduled backup, one at a time with everything else the server runs.
func (s *Server) RunLocked(ctx context.Context, kind string, input json.RawMessage, emit func(kernel.Event)) (*kernel.Receipt, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	unlock, err := s.lockMachine(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.Engine.Run(ctx, kind, input, emit)
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, version.Current())
	})
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		keyPath := ""
		if s.Store != nil {
			keyPath = secrets.DefaultStore(filepath.Dir(s.Store.Path())).KeyPath
		}
		info, err := compat.Current(keyPath)
		if err == nil && s.Store != nil {
			var v int
			v, err = s.Store.Version(r.Context())
			info.PersistedStateVersion = &v
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, info)
	})
	mux.HandleFunc("GET /v1/operations", s.listOperations)
	// A distinct route lets filtered clients fail on an older daemon rather
	// than have unknown query parameters silently ignored.
	mux.HandleFunc("GET /v1/operations/history", s.listOperations)
	mux.HandleFunc("GET /v1/operations/{id}/output", func(w http.ResponseWriter, r *http.Request) {
		output, err := s.Engine.OutputOf(r.Context(), r.PathValue("id"), r.URL.Query().Get("step"))
		switch {
		case errors.Is(err, state.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, kernel.ErrUnknownStep):
			writeError(w, http.StatusBadRequest, err)
		case err != nil:
			writeError(w, http.StatusInternalServerError, err)
		default:
			writeJSON(w, http.StatusOK, output)
		}
	})
	mux.HandleFunc("GET /v1/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		receipt, err := s.Engine.ReceiptOf(r.Context(), r.PathValue("id"))
		if errors.Is(err, state.ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, receipt)
	})
	mux.HandleFunc("POST /v1/operations", s.runOperation)
	return mux
}

func (s *Server) listOperations(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := state.OperationFilter{Target: query.Get("app"), Kind: query.Get("kind")}
	var err error
	if value := query.Get("limit"); value != "" {
		filter.Limit, err = strconv.Atoi(value)
		if err != nil || filter.Limit < 0 {
			writeError(w, http.StatusBadRequest, errors.New("limit must be zero or a positive integer"))
			return
		}
	}
	if value := query.Get("failed"); value != "" {
		filter.Failed, err = strconv.ParseBool(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("failed must be true or false"))
			return
		}
	}
	if value := query.Get("since"); value != "" {
		filter.Since, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("since must be an RFC3339 timestamp"))
			return
		}
	}
	ops, err := s.Store.ListFiltered(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	rows := make([]Summary, 0, len(ops))
	for _, op := range ops {
		rows = append(rows, summarize(op))
	}
	writeJSON(w, http.StatusOK, rows)
}

const operationStreamWriteTimeout = 5 * time.Second

func (s *Server) runOperation(w http.ResponseWriter, r *http.Request) {
	var req RunRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad request: %w", err))
		return
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errors.New("bad request: expected one JSON object"))
		return
	}
	if req.PlanOnly {
		ctx, done, err := s.begin(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		defer done()
		view, err := s.Engine.PlanOnly(ctx, req.Kind, req.Input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		_ = json.NewEncoder(w).Encode(kernel.Event{Type: kernel.EventPlanned, At: time.Now().UTC(), Plan: view})
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	controller := http.NewResponseController(w)
	var outputMu sync.Mutex
	disconnected := false
	send := func(value any) {
		outputMu.Lock()
		defer outputMu.Unlock()
		if disconnected {
			return
		}
		// A slow event reader cannot hold the machine's mutation queue.
		// Stop streaming on failure while the journaled operation continues.
		_ = controller.SetWriteDeadline(time.Now().Add(operationStreamWriteTimeout))
		if err := enc.Encode(value); err != nil {
			disconnected = true
			return
		}
		if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			disconnected = true
			return
		}
		_ = controller.SetWriteDeadline(time.Time{})
	}
	emit := func(ev kernel.Event) { send(ev) }
	// The client going away must not stop the operation: it is journaled
	// and finishes on the daemon's own clock.
	ctx, done, err := s.begin(context.WithoutCancel(r.Context()))
	if err != nil {
		emit(kernel.Event{Type: kernel.EventError, At: time.Now().UTC(), Message: err.Error()})
		return
	}
	defer done()
	if err := s.lock(ctx); err != nil {
		emit(kernel.Event{Type: kernel.EventError, At: time.Now().UTC(), Message: err.Error()})
		return
	}
	defer s.mu.Unlock()
	unlock, err := s.lockMachine(ctx)
	if err != nil {
		emit(kernel.Event{Type: kernel.EventError, At: time.Now().UTC(), Message: err.Error()})
		return
	}
	defer unlock()
	if _, err := s.Engine.RunExpecting(ctx, req.Kind, req.Input, req.Expect, emit); err != nil {
		problem := problemFor(http.StatusBadRequest, err)
		// Preserve the event shape used by older clients, adding problem fields.
		send(struct {
			kernel.Event
			Code       string `json:"code"`
			Retryable  bool   `json:"retryable"`
			APIVersion int    `json:"api_version"`
		}{kernel.Event{Type: kernel.EventError, At: time.Now().UTC(), Message: err.Error()}, problem.Code, problem.Retryable, compat.APIVersion})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, problemFor(status, err))
}

// Listen opens the daemon's Unix socket, replacing a stale one, readable
// and writable by its owner and group only.
func Listen(socket string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %s", socket)
		}
		conn, err := net.DialTimeout("unix", socket, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil, fmt.Errorf("another daemon is listening on %s", socket)
		}
		// Only a refused connection establishes that this socket is stale.
		// Permissions, timeouts and other failures must preserve its owner.
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("checking existing socket %s: %w", socket, err)
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	// The bedrock user, who receives pushes, asks the daemon to deploy them
	// through the socket: its group may use it.
	if g, err := user.LookupGroup(SocketGroup); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			setSocketGroup(socket, gid)
		}
	}
	return l, nil
}

func setSocketGroup(socket string, gid int) {
	_ = os.Chown(socket, 0, gid)
	dir := filepath.Dir(socket)
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm()&0o001 != 0 {
		// An existing shared directory already permits traversal. In
		// particular, a socket under /tmp or /run must not restrict it.
		return
	}
	_ = os.Chown(dir, 0, gid)
	_ = os.Chmod(dir, info.Mode().Perm()|0o050)
}

// SocketGroup may use the daemon's socket.
const SocketGroup = "bedrock"

// Local serves the Runner contract from an in-process kernel.
type Local struct {
	Engine *kernel.Engine
	Store  *state.Store
}

// Version implements Runner.
func (l *Local) Version(context.Context) (version.Info, error) { return version.Current(), nil }

// Plan implements Runner.
func (l *Local) Plan(ctx context.Context, kind string, input json.RawMessage) (*kernel.PlanView, error) {
	return l.Engine.PlanOnly(ctx, kind, input)
}

// Run implements Runner.
func (l *Local) Run(ctx context.Context, kind string, input json.RawMessage, emit func(kernel.Event)) (*kernel.Receipt, error) {
	return l.RunExpecting(ctx, kind, input, "", emit)
}

// RunExpecting implements Runner. Operations run one at a time on a
// machine; with no daemon to hold them in line, a lock beside the store
// does, so two commands run by hand can't interleave their steps.
func (l *Local) RunExpecting(ctx context.Context, kind string, input json.RawMessage, expect string, emit func(kernel.Event)) (*kernel.Receipt, error) {
	unlock, err := LockOperations(ctx, l.Store.Path())
	if err != nil {
		return nil, err
	}
	defer unlock()
	return l.Engine.RunExpecting(ctx, kind, input, expect, emit)
}

// LockOperations takes the machine's operation lock, kept beside the state
// store, waiting for whoever holds it until ctx ends. The holder writes when
// it took the lock into the lock file, so HeldOperationLock can tell how long
// the machine's operations have been waiting on it.
func LockOperations(ctx context.Context, statePath string) (func(), error) {
	dir := filepath.Join(filepath.Dir(statePath), "locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(operationLockPath(statePath), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			// The record is advisory: a lock without one still locks, it just
			// can't say since when.
			if body, err := json.Marshal(OperationLock{PID: os.Getpid(), AcquiredAt: time.Now().UTC()}); err == nil {
				if f.Truncate(0) == nil {
					_, _ = f.WriteAt(body, 0)
				}
			}
			return func() {
				_ = f.Truncate(0)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("another helios operation is running on this machine: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func operationLockPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "locks", "operations.lock")
}

// OperationLock describes who holds the machine's operation lock.
type OperationLock struct {
	PID        int       `json:"pid"`
	AcquiredAt time.Time `json:"acquired_at"`
}

// HeldOperationLock reports whether some process holds the machine's
// operation lock, and since when if the holder recorded it. A holder from a
// release before 0.7.11 records nothing, so it reads as held with a zero
// AcquiredAt. Looking takes a shared lock for an instant, which a process
// waiting to take the lock simply retries past.
func HeldOperationLock(statePath string) (OperationLock, bool, error) {
	f, err := os.Open(operationLockPath(statePath))
	if errors.Is(err, os.ErrNotExist) {
		return OperationLock{}, false, nil
	}
	if err != nil {
		return OperationLock{}, false, err
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return OperationLock{}, false, nil
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		return OperationLock{}, false, err
	}
	var held OperationLock
	if body, err := io.ReadAll(io.LimitReader(f, 4096)); err == nil && len(body) > 0 {
		if json.Unmarshal(body, &held) != nil {
			held = OperationLock{}
		}
	}
	return held, true, nil
}

// List implements Runner.
func (l *Local) List(ctx context.Context, limit int) ([]Summary, error) {
	return l.ListFiltered(ctx, state.OperationFilter{Limit: limit})
}

// ListFiltered implements Runner.
func (l *Local) ListFiltered(ctx context.Context, filter state.OperationFilter) ([]Summary, error) {
	ops, err := l.Store.ListFiltered(ctx, filter)
	if err != nil {
		return nil, err
	}
	rows := make([]Summary, 0, len(ops))
	for _, op := range ops {
		rows = append(rows, summarize(op))
	}
	return rows, nil
}

// Receipt implements Runner.
func (l *Local) Receipt(ctx context.Context, id string) (*kernel.Receipt, error) {
	return l.Engine.ReceiptOf(ctx, id)
}

// Output implements Runner.
func (l *Local) Output(ctx context.Context, id, step string) (*kernel.OperationOutput, error) {
	return l.Engine.OutputOf(ctx, id, step)
}

// Close implements Runner.
func (l *Local) Close() error { return l.Store.Close() }

// lockMachine shares the local fallback's operation lock, so forcing a separate
// socket cannot run a second authority alongside the daemon on the same state.
func (s *Server) lockMachine(ctx context.Context) (func(), error) {
	if s.Store == nil {
		return func() {}, nil
	}
	return LockOperations(ctx, s.Store.Path())
}

// Recover resumes a client's dedicated journal under the same execution lock.
func (l *Local) Recover(ctx context.Context, emit func(kernel.Event)) (int, error) {
	unlock, err := LockOperations(ctx, l.Store.Path())
	if err != nil {
		return 0, err
	}
	defer unlock()
	return l.Engine.Recover(ctx, emit)
}
