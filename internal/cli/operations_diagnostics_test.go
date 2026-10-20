package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/version"
)

func TestFailedOperationOffersSavedDiagnosticsFromTheSameState(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state with space's")
	out, errOut, code := run(t, stateDir, "--json", "kernel", "exercise", "--dir", t.TempDir(), "--steps", "2", "--fail-at", "2", "--yes")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var last kernel.Event
	if json.Unmarshal([]byte(lines[len(lines)-1]), &last) != nil || last.Receipt == nil {
		t.Fatalf("missing failure receipt: %q", out)
	}
	if code != 1 || !strings.Contains(errOut, "helios history "+last.Receipt.ID+" --output") || !strings.Contains(errOut, "--state-dir '") || !strings.Contains(errOut, "'\"'\"'") {
		t.Fatalf("missing correctly quoted recovery command: code %d, stderr %q", code, errOut)
	}
	// The follow-up is read-only and shows the completed step's diagnostic.
	out, errOut, code = run(t, stateDir, "history", last.Receipt.ID, "--output", "--step", "step-1")
	if code != 0 || !strings.Contains(out, "wrote ") {
		t.Fatalf("failure output unavailable: %d %q %q", code, out, errOut)
	}
}

func TestDisconnectedOperationOffersSavedDiagnosticsOnTheSameSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "bd-history-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "daemon.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	shortenFollowing(t, 20*time.Millisecond)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoder := json.NewEncoder(w)
		if r.URL.Path == "/v1/version" {
			_ = encoder.Encode(version.Current())
			return
		}
		if r.Method == http.MethodGet {
			// The daemon never comes back to say how the operation ended.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var req api.RunRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid operation request")
			return
		}
		if req.PlanOnly {
			_ = encoder.Encode(kernel.Event{Type: kernel.EventPlanned, Plan: &kernel.PlanView{Kind: kernel.ExerciseKind, Target: "fixture"}})
			return
		}
		_ = encoder.Encode(kernel.Event{Type: kernel.EventPlanned, Operation: "op-disconnected"})
		// End the stream before the receipt, as a lost connection would.
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	var stdout, stderr bytes.Buffer
	a := &app{stdout: &stdout, stderr: &stderr, stateDir: filepath.Join(dir, "state"), socket: socket, yes: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = a.operate(ctx, kernel.ExerciseKind, kernel.ExerciseInput{Dir: "fixture", Steps: 1}, false)
	if !errors.Is(err, api.ErrDisconnected) || !strings.Contains(err.Error(), "helios history op-disconnected --output") || !strings.Contains(err.Error(), "--socket "+socket) || !strings.Contains(err.Error(), "--state-dir "+a.stateDir) {
		t.Fatalf("disconnection lost operation or connection context: %v", err)
	}
}
