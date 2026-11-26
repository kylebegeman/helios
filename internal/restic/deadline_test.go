package restic

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
)

// A helper that never exits stands in for a repository that stops
// answering: restic waits on it until something stops the container.
func hangingRestic(t *testing.T) (*dockertest.Server, *[][]string) {
	t.Helper()
	fake := dockertest.New(t)
	var commands [][]string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, append([]string(nil), c.Cmd...))
		fake.Update(c.Name, func(c *dockertest.Container) { c.Logs = `{"message_type":"status"}` })
	}
	return fake, &commands
}

// safetyContext ends a test whose call ignores its own deadline with a
// plain context error, which the assertions then reject, instead of
// letting the call hang until go test's own timeout.
func safetyContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestRepositoryCallsAreStoppedAtTheirDeadline(t *testing.T) {
	const limit = 50 * time.Millisecond
	for _, tc := range []struct {
		action string
		call   func(context.Context, Runner) error
	}{
		{"init", func(ctx context.Context, r Runner) error { _, err := r.Ensure(ctx); return err }},
		{"unlock", func(ctx context.Context, r Runner) error { return r.Unlock(ctx) }},
		{"backup", func(ctx context.Context, r Runner) error {
			_, err := r.Backup(ctx, "site", nil, DataRoot)
			return err
		}},
		{"forget", func(ctx context.Context, r Runner) error {
			_, err := r.Forget(ctx, "site", Keep{Daily: 7}, nil)
			return err
		}},
		{"prune", func(ctx context.Context, r Runner) error { return r.Prune(ctx, false) }},
		{"restore", func(ctx context.Context, r Runner) error {
			_, err := r.Restore(ctx, "latest", "site", nil)
			return err
		}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			fake, commands := hangingRestic(t)
			r := runner(t)
			r.Deadlines = Deadlines{Ensure: limit, Unlock: limit, Backup: limit, Forget: limit, Prune: limit, Restore: limit}
			err := tc.call(safetyContext(t), r)
			var deadline *DeadlineError
			if !errors.As(err, &deadline) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("a stopped call must say it ran out of time: %v", err)
			}
			if deadline.Action != tc.action || deadline.Limit != limit || !strings.Contains(err.Error(), "restic "+tc.action+" did not finish within 50ms") {
				t.Fatalf("unclear deadline error: %v", err)
			}
			if len(*commands) != 1 || (*commands)[0][0] != tc.action {
				t.Fatalf("unexpected restic runs: %v", *commands)
			}
			// The helper is stopped, so restic gets to release its lock, and removed.
			if fake.Last(func(c string) bool { return strings.HasSuffix(c, "/stop") }) < 0 {
				t.Fatalf("the helper was not stopped: %v", fake.Calls())
			}
			if fake.Last(func(c string) bool { return strings.HasPrefix(c, "DELETE ") }) < 0 {
				t.Fatalf("the helper was not removed: %v", fake.Calls())
			}
		})
	}
}

func TestPruneIsCappedUnlessFullAndHasItsOwnDeadline(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(map[bool]string{false: "after a backup", true: "the weekly full prune"}[full], func(t *testing.T) {
			_, commands := hangingRestic(t)
			r := runner(t)
			r.Deadlines = Deadlines{Forget: time.Hour, Prune: 50 * time.Millisecond}
			err := r.Prune(safetyContext(t), full)
			var deadline *DeadlineError
			if !errors.As(err, &deadline) || deadline.Action != "prune" {
				t.Fatalf("a prune out of time must say so: %v", err)
			}
			want := []string{"prune", "--max-repack-size", PruneMaxRepack}
			if full {
				// No cap, and nothing that forces a lock: a full prune stopped
				// here leaves a stale lock for the next backup's unlock.
				want = []string{"prune"}
			}
			if len(*commands) != 1 || !slices.Equal((*commands)[0], want) {
				t.Fatalf("unexpected restic runs: %v", *commands)
			}
		})
	}
}

func TestTheCallersCancellationIsNotReportedAsADeadline(t *testing.T) {
	fake := dockertest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The caller goes away while the helper is being started, as a daemon
	// shutdown would cancel it.
	fake.OnCreate = func(dockertest.Container) { cancel() }
	r := runner(t)
	r.Deadlines.Forget = time.Hour
	_, err := r.Forget(ctx, "site", Keep{Daily: 7}, nil)
	var deadline *DeadlineError
	if !errors.Is(err, context.Canceled) || errors.As(err, &deadline) {
		t.Fatalf("cancellation must stay cancellation: %v", err)
	}
}

func TestTheCallersDeadlineIsNotReportedAsTheCallsOwn(t *testing.T) {
	hangingRestic(t)
	// An app capture runs inside its maintenance window: when that window
	// ends first, the upload did not run out of its own two hours.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r := runner(t)
	r.Deadlines.Backup = time.Hour
	_, err := r.Backup(ctx, "site", nil, DataRoot)
	var deadline *DeadlineError
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &deadline) {
		t.Fatalf("the caller's deadline must not read as the call's own: %v", err)
	}
}

func TestOnlyACallsOwnDeadlineGetsTheLongStopGrace(t *testing.T) {
	own, cancelOwn := context.WithTimeoutCause(context.Background(), time.Nanosecond, errCallDeadline)
	defer cancelOwn()
	<-own.Done()
	if got := graceFor(own); got != stopGrace {
		t.Fatalf("a call out of its own time must let restic release its lock: %s", got)
	}
	parent, cancelParent := context.WithCancel(context.Background())
	call, cancelCall := context.WithTimeoutCause(parent, time.Hour, errCallDeadline)
	defer cancelCall()
	cancelParent()
	if got := graceFor(call); got != shutdownStopGrace {
		t.Fatalf("a daemon stopping must fit its stop budget: %s", got)
	}
}

func TestUnlockOnlyRemovesStaleLocks(t *testing.T) {
	fake := dockertest.New(t)
	var command []string
	fake.OnCreate = func(c dockertest.Container) {
		command = c.Cmd
		fake.Update(c.Name, func(c *dockertest.Container) { c.ExitAfter = 1 })
	}
	if err := runner(t).Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(command, []string{"unlock"}) {
		t.Fatalf("unlock must never force removal of live locks: %v", command)
	}
}
