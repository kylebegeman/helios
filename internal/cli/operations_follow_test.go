package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/host"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

// shortenFollowing makes a followed operation's receipt reads quick and the
// daemon's allowed absence patience, for one test.
func shortenFollowing(t *testing.T, patience time.Duration) {
	every, waited := followEvery, followPatience
	t.Cleanup(func() { followEvery, followPatience = every, waited })
	followEvery, followPatience = time.Millisecond, patience
}

// restartingDaemon streams an upgrade that it breaks off at the restart
// step, as a daemon systemd stops does, then answers the receipt reads that
// follow from a script whose last answer repeats.
type restartingDaemon struct {
	id       string // the operation the stream names; empty names none
	canceled bool   // end with the stopping daemon's canceled error, not EOF
	answers  []func(http.ResponseWriter)
	reads    atomic.Int32
	onRead   func(n int)
}

func (d *restartingDaemon) serve(t *testing.T) api.Runner {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			n := int(d.reads.Add(1))
			if d.id == "" || r.URL.Path != "/v1/operations/"+d.id {
				t.Errorf("read %s, but the run named no such operation", r.URL.Path)
				return
			}
			if d.onRead != nil {
				d.onRead(n)
			}
			d.answers[min(n, len(d.answers))-1](w)
			return
		}
		var req api.RunRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid operation request")
			return
		}
		encoder := json.NewEncoder(w)
		if req.PlanOnly {
			_ = encoder.Encode(kernel.Event{Type: kernel.EventPlanned, Plan: &kernel.PlanView{Kind: host.UpgradeKind, Target: host.BinaryPath, Digest: "fixture"}})
			return
		}
		_ = encoder.Encode(kernel.Event{Type: kernel.EventStepStarted, Operation: d.id, Step: &kernel.StepView{Index: 2, Name: "restart", Status: state.StepRunning}})
		if d.canceled {
			_ = encoder.Encode(struct {
				kernel.Event
				Code string `json:"code"`
			}{kernel.Event{Type: kernel.EventError, Message: context.Canceled.Error()}, "canceled"})
		}
	}))
	t.Cleanup(server.Close)
	return api.NewClient(server.Client(), server.URL)
}

// upgrade applies the upgrade against the daemon and returns what the
// command printed and how it ended.
func (d *restartingDaemon) upgrade(t *testing.T, ctx context.Context, jsonMode bool) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	a := &app{stdout: &stdout, stderr: &stderr, json: jsonMode, yes: true}
	err := a.operateRaw(ctx, d.serve(t), host.UpgradeKind, json.RawMessage(`{"path":"/fixture/helios"}`), false)
	return stdout.String(), stderr.String(), err
}

func receiptAnswer(id string, status state.OperationStatus, opErr string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(kernel.Receipt{ID: id, Kind: host.UpgradeKind, Target: host.BinaryPath, Status: status, Error: opErr, Interruptions: 1})
	}
}

// unavailable is a daemon answering while it stops, or one in front of it.
func unavailable(w http.ResponseWriter) {
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "the daemon is stopping", "code": "unavailable", "retryable": true})
}

// dropped is a daemon gone mid-read.
func dropped(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}

func withDeadline(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestAnUpgradeTheDaemonRestartsUnderIsFollowedToItsOutcome(t *testing.T) {
	shortenFollowing(t, time.Minute)
	d := &restartingDaemon{id: "op-restarted", canceled: true, answers: []func(http.ResponseWriter){
		dropped, unavailable, receiptAnswer("op-restarted", state.Applying, ""), receiptAnswer("op-restarted", state.Succeeded, ""),
	}}
	stdout, stderr, err := d.upgrade(t, withDeadline(t), false)
	if err != nil {
		t.Fatalf("an upgrade that succeeded failed: %v\nstdout:\n%s", err, stdout)
	}
	if strings.Count(stdout, "the daemon restarted; following op-restarted until it ends\n") != 1 {
		t.Errorf("the command didn't say once that it follows the operation:\n%s", stdout)
	}
	if !strings.Contains(stdout, "op-restarted  host.upgrade on "+host.BinaryPath+"\nsucceeded") {
		t.Errorf("the outcome wasn't shown:\n%s", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestUnderJSONAFollowedOperationEndsWithTheEventARunEndsWith(t *testing.T) {
	shortenFollowing(t, time.Minute)
	for _, c := range []struct {
		name   string
		status state.OperationStatus
		reason string
	}{
		{"succeeded", state.Succeeded, ""},
		// The kernel's finished event carries the reason as its message.
		{"failed", state.Failed, "restart: the new build didn't start"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &restartingDaemon{id: "op-restarted", canceled: true, answers: []func(http.ResponseWriter){
				unavailable, receiptAnswer("op-restarted", c.status, c.reason),
			}}
			stdout, stderr, err := d.upgrade(t, withDeadline(t), true)
			if (err != nil) != (c.status != state.Succeeded) {
				t.Fatalf("an upgrade that %s ended with %v", c.status, err)
			}
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			for _, line := range lines {
				if !json.Valid([]byte(line)) {
					t.Fatalf("stdout carries more than JSON: %q", line)
				}
			}
			var last kernel.Event
			if json.Unmarshal([]byte(lines[len(lines)-1]), &last) != nil || last.Type != kernel.EventFinished || last.Receipt == nil || last.Receipt.Status != c.status {
				t.Fatalf("the last line isn't the finished event: %q", lines[len(lines)-1])
			}
			if last.Message != last.Receipt.Error || last.Message != c.reason {
				t.Errorf("the finished event's message is %q, want the receipt's error %q", last.Message, c.reason)
			}
			if !strings.Contains(stderr, "following op-restarted") {
				t.Errorf("the note isn't on stderr: %q", stderr)
			}
		})
	}
}

func TestAFollowedOperationThatFailsNamesItsSavedOutput(t *testing.T) {
	shortenFollowing(t, time.Minute)
	d := &restartingDaemon{id: "op-rolled-back", canceled: true, answers: []func(http.ResponseWriter){
		receiptAnswer("op-rolled-back", state.Applying, ""), receiptAnswer("op-rolled-back", state.Failed, "restart: the new build didn't start"),
	}}
	stdout, _, err := d.upgrade(t, withDeadline(t), false)
	if err == nil || !strings.Contains(err.Error(), "failed: restart: the new build didn't start; inspect saved output: helios history op-rolled-back --output") {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(stdout, "op-rolled-back  host.upgrade") {
		t.Errorf("the failed receipt wasn't shown:\n%s", stdout)
	}
}

// Each answer showing the operation under way starts the patience again, so
// an operation that applies for longer than it is still followed.
func TestAnOperationStillApplyingIsFollowedPastThePatience(t *testing.T) {
	const patience, every, applyingReads = 30 * time.Millisecond, 3 * time.Millisecond, 40
	shortenFollowing(t, patience)
	followEvery = every
	answers := []func(http.ResponseWriter){}
	for range applyingReads {
		answers = append(answers, receiptAnswer("op-slow", state.Applying, ""))
	}
	d := &restartingDaemon{id: "op-slow", canceled: true, answers: append(answers, receiptAnswer("op-slow", state.Succeeded, ""))}
	start := time.Now()
	if _, _, err := d.upgrade(t, withDeadline(t), false); err != nil {
		t.Fatalf("an upgrade still applying past the patience, then succeeding, failed after %s: %v", time.Since(start), err)
	}
	if took := time.Since(start); took <= patience {
		t.Fatalf("the operation applied for only %s, within the patience", took)
	}
}

func TestADaemonThatNeverComesBackIsWaitedForOnlySoLong(t *testing.T) {
	shortenFollowing(t, 50*time.Millisecond)
	d := &restartingDaemon{id: "op-stranded", canceled: true, answers: []func(http.ResponseWriter){unavailable, dropped}}
	ctx := withDeadline(t)
	_, _, err := d.upgrade(t, ctx, false)
	if ctx.Err() != nil {
		t.Fatal("the command waited out the test's deadline")
	}
	if !errors.Is(err, api.ErrDisconnected) || !strings.Contains(err.Error(), "hasn't come back in 50ms; the daemon finishes or undoes op-stranded on its own; inspect saved output: helios history op-stranded --output") {
		t.Fatalf("got %v", err)
	}
	if d.reads.Load() < 2 {
		t.Errorf("the receipt was read %d times; the daemon was given no time to come back", d.reads.Load())
	}
}

func TestAStreamThatJustEndsIsFollowedToo(t *testing.T) {
	shortenFollowing(t, time.Minute)
	d := &restartingDaemon{id: "op-dropped", answers: []func(http.ResponseWriter){
		receiptAnswer("op-dropped", state.Applying, ""), receiptAnswer("op-dropped", state.Succeeded, ""),
	}}
	if _, _, err := d.upgrade(t, withDeadline(t), false); err != nil {
		t.Fatalf("an upgrade that succeeded failed: %v", err)
	}
}

func TestARunBrokenOffBeforeItNamedAnOperationFailsAsBefore(t *testing.T) {
	shortenFollowing(t, time.Minute)
	t.Run("canceled", func(t *testing.T) {
		d := &restartingDaemon{canceled: true}
		stdout, _, err := d.upgrade(t, withDeadline(t), false)
		var problem *api.Error
		if !errors.As(err, &problem) || problem.Code != "canceled" || strings.Contains(stdout, "following") {
			t.Fatalf("got %v, stdout %q", err, stdout)
		}
	})
	t.Run("dropped", func(t *testing.T) {
		d := &restartingDaemon{}
		if _, _, err := d.upgrade(t, withDeadline(t), false); err != api.ErrDisconnected {
			t.Fatalf("got %v", err)
		}
	})
}

func TestStoppingTheFollowLeavesTheOperationToTheDaemon(t *testing.T) {
	shortenFollowing(t, time.Minute)
	ctx, stop := context.WithCancel(withDeadline(t))
	d := &restartingDaemon{id: "op-long", canceled: true, answers: []func(http.ResponseWriter){receiptAnswer("op-long", state.Applying, "")},
		onRead: func(n int) {
			if n == 3 {
				stop() // as Ctrl-C does
			}
		}}
	_, _, err := d.upgrade(t, ctx, false)
	if err == nil || !strings.Contains(err.Error(), "stopped following op-long; the daemon carries on with it; inspect saved output: helios history op-long --output") {
		t.Fatalf("got %v", err)
	}
}

func TestAnOperationThatNeverStartedIsNotWaitedOnForever(t *testing.T) {
	shortenFollowing(t, 50*time.Millisecond)
	d := &restartingDaemon{id: "op-planned", canceled: true, answers: []func(http.ResponseWriter){receiptAnswer("op-planned", state.Planned, "")}}
	ctx := withDeadline(t)
	_, _, err := d.upgrade(t, ctx, false)
	if ctx.Err() != nil || err == nil || !strings.Contains(err.Error(), "op-planned never started, so nothing was applied") {
		t.Fatalf("got %v", err)
	}
}
