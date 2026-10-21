package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/daemon"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/ui"
)

// operate is what every mutating command does: show the plan, stop there
// with --plan, ask unless --yes (or refuse without a terminal), then run it
// and render the events.
func (a *app) operate(ctx context.Context, kind string, input any, planOnly bool) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	runner, err := a.runner(ctx, fmt.Sprintf("cli-%d", os.Getpid()))
	if err != nil {
		return err
	}
	return a.operateRaw(ctx, runner, kind, raw, planOnly)
}

func (a *app) operateRaw(ctx context.Context, runner api.Runner, kind string, raw json.RawMessage, planOnly bool) error {
	defer runner.Close()
	r := a.renderer()
	view, err := runner.Plan(ctx, kind, raw)
	if err != nil {
		return err
	}
	if planOnly {
		r.Plan(view)
		return nil
	}
	// Naming the exact plan is the approval: an agent reads a plan, shows it,
	// and applies that one. Asking again for a yes would be asking about a
	// plan the person has already seen and named.
	expect := a.digest
	if !a.yes && expect == "" {
		if !a.tty {
			r.Plan(view)
			return errors.New("this would change the machine; add --yes to apply it without a prompt, or --plan to only look")
		}
		r.Plan(view)
		fmt.Fprint(a.narrateTo(), "Apply? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.ToLower(strings.TrimSpace(answer)); s != "y" && s != "yes" {
			return errors.New("not applied")
		}
		expect = view.Digest
	}
	var lastID string
	receipt, err := runner.RunExpecting(ctx, kind, raw, expect, func(ev kernel.Event) {
		if ev.Operation != "" {
			lastID = ev.Operation
		}
		r.Event(ev)
	})
	// A daemon that restarts mid-way, as an upgrade's does, ends the stream
	// before the outcome while the journaled operation goes on.
	if lastID != "" && ctx.Err() == nil && brokenOff(err) {
		receipt, err = a.follow(ctx, runner, r, lastID)
	}
	if errors.Is(err, api.ErrDisconnected) {
		if lastID != "" {
			return fmt.Errorf("%w; the daemon finishes or undoes %s on its own; inspect saved output: %s", err, lastID, a.historyOutputCommand(lastID))
		}
		return err
	}
	if err != nil {
		if lastID != "" {
			return fmt.Errorf("%w; inspect saved output: %s", err, a.historyOutputCommand(lastID))
		}
		return err
	}
	if receipt.Status != "succeeded" {
		return fmt.Errorf("%s: %s; inspect saved output: %s", receipt.Status, receipt.Error, a.historyOutputCommand(receipt.ID))
	}
	return nil
}

// restartPatience is how long a command following an operation waits for a
// daemon that doesn't answer. It covers what bedrock.service gives systemd:
// stopping the old daemon (TimeoutStopSec=60), a new build that won't start
// using up its three tries within StartLimitIntervalSec=60, and the rollback
// unit starting the previous build in its place.
const restartPatience = 3 * time.Minute

// How often a followed operation's receipt is read, and how long its daemon
// may stay away. Tests shorten both.
var (
	followEvery    = time.Second
	followPatience = restartPatience
)

// brokenOff reports whether a run's stream ended without its outcome because
// the daemon went away: the connection dropped, or the daemon, stopping,
// canceled the run it was streaming.
func brokenOff(err error) bool {
	var problem *api.Error
	return errors.Is(err, api.ErrDisconnected) || errors.As(err, &problem) && problem.Code == "canceled"
}

// follow reads an operation's receipt until the operation ends, through the
// daemon going away and coming back, and shows the outcome.
func (a *app) follow(ctx context.Context, runner api.Runner, r *ui.Renderer, id string) (*kernel.Receipt, error) {
	note := fmt.Sprintf("the daemon restarted; following %s until it ends", id)
	if a.json {
		fmt.Fprintln(a.stderr, note)
	} else {
		r.Note(note)
	}
	// heard is when the daemon last showed the operation under way. A
	// planned one isn't: once its run is broken off, nothing starts it.
	heard := time.Now()
	for {
		// A daemon may accept the connection without answering. Bound each
		// read too, so it cannot bypass the promised absence deadline.
		readCtx, cancel := context.WithTimeout(ctx, min(2*time.Second, followPatience))
		receipt, err := runner.Receipt(readCtx, id)
		cancel()
		switch {
		case ctx.Err() != nil:
			return nil, fmt.Errorf("stopped following %s; the daemon carries on with it", id)
		case err == nil && receipt.Status.Final():
			// The events since the restart went unseen: show the whole
			// receipt, or under --json the event a run streamed to its end
			// finishes with, its message the reason the kernel gave.
			if a.json {
				r.Event(kernel.Event{Type: kernel.EventFinished, Operation: id, At: receipt.FinishedAt, Receipt: receipt, Message: receipt.Error})
			} else {
				r.Receipt(receipt)
			}
			return receipt, nil
		case err == nil && receipt.Status != state.Planned:
			heard = time.Now()
		case time.Since(heard) < followPatience:
			// away, or not started yet: keep asking
		case err == nil:
			return nil, fmt.Errorf("%s never started, so nothing was applied, and the daemon won't start it now", id)
		default:
			return nil, fmt.Errorf("%w and it hasn't come back in %s", api.ErrDisconnected, ui.Duration(followPatience))
		}
		select {
		case <-ctx.Done(): // the next read says so
		case <-time.After(followEvery):
		}
	}
}

// historyOutputCommand keeps a diagnostic follow-up on the same state and
// socket when the operator uses a nondefault installation.
func (a *app) historyOutputCommand(id string) string {
	command := "helios history " + shellArgument(id) + " --output"
	if a.targetName != "" {
		command += " --target " + shellArgument(a.targetName)
		if a.targetsFile != defaultTargetsFile() {
			command += " --targets-file " + shellArgument(a.targetsFile)
		}
	}
	if a.stateDir != "" && a.stateDir != defaultStateDir() {
		command += " --state-dir " + shellArgument(a.stateDir)
	}
	if a.socket != "" && a.socket != daemon.DefaultSocket {
		command += " --socket " + shellArgument(a.socket)
	}
	return command
}

func shellArgument(value string) string {
	if value != "" && strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._/:@", r))
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// mutatingFlags adds --plan, --yes and --digest to a command that changes
// the machine.
func (a *app) mutatingFlags(cmd *cobra.Command, planOnly *bool) {
	cmd.Flags().BoolVar(planOnly, "plan", false, "show the plan and change nothing")
	cmd.Flags().BoolVar(&a.yes, "yes", false, "apply without asking")
	cmd.Flags().StringVar(&a.digest, "digest", "", "apply only if the plan is still the one with this digest; implies --yes")
}

func newHistory(a *app) *cobra.Command {
	var (
		filter state.OperationFilter
		since  string
		output bool
		step   string
	)
	cmd := &cobra.Command{
		Use:   "history [operation-id]",
		Short: "List recent operations, show a receipt, or retrieve saved diagnostic output.",
		Long: `List recent operations, show a receipt, or retrieve saved diagnostic output.

List filters are combined and applied before --limit. --failed includes
failed and compensated operations. --since accepts a positive duration
such as 24h, or an RFC3339 timestamp such as 2026-10-10T12:00:00Z.

  helios history --app api --kind app.deploy --failed --since 24h
  helios history <operation-id> --output
  helios history <operation-id> --output --step build-web

Output is opt-in and contains saved tails, not a complete log. Each step
execution keeps up to 40 lines; a running execution's output is saved when
it finishes. --step selects an exact name or a one-based step position.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if filter.Limit < 1 {
				return errors.New("--limit must be a positive integer")
			}
			if cmd.Flags().Changed("step") && (!output || step == "") {
				return errors.New("--step needs --output and a step name or one-based position")
			}
			if output && len(args) == 0 {
				return errors.New("--output needs an operation ID: helios history <operation-id> --output")
			}
			if len(args) == 1 {
				for _, name := range []string{"app", "kind", "failed", "since"} {
					if cmd.Flags().Changed(name) {
						return fmt.Errorf("--%s filters the operation list; omit the operation ID to use it", name)
					}
				}
			}
			if cmd.Flags().Changed("since") {
				var err error
				filter.Since, err = historySince(since, time.Now())
				if err != nil {
					return err
				}
			}
			ctx := cmd.Context()
			runner, err := a.runner(ctx, fmt.Sprintf("cli-%d", os.Getpid()))
			if err != nil {
				return err
			}
			defer runner.Close()
			r := a.renderer()
			if len(args) == 1 {
				if output {
					saved, err := runner.Output(ctx, args[0], step)
					if err != nil {
						return err
					}
					r.Output(saved)
					return nil
				}
				receipt, err := runner.Receipt(ctx, args[0])
				if err != nil {
					return err
				}
				r.Receipt(receipt)
				return nil
			}
			rows, err := runner.ListFiltered(ctx, filter)
			if err != nil {
				return err
			}
			summaries := make([]ui.Summary, 0, len(rows))
			for _, row := range rows {
				summaries = append(summaries, ui.Summary{ID: row.ID, Kind: row.Kind, Target: row.Target, Status: row.Status, CreatedAt: row.CreatedAt, Interruptions: row.Interruptions, Error: row.Error})
			}
			r.History(summaries)
			return nil
		},
	}
	cmd.Flags().IntVar(&filter.Limit, "limit", 20, "how many matching operations to list")
	cmd.Flags().StringVar(&filter.Target, "app", "", "only operations targeting this app")
	cmd.Flags().StringVar(&filter.Kind, "kind", "", "only this operation kind, such as app.deploy")
	cmd.Flags().BoolVar(&filter.Failed, "failed", false, "only failed or compensated operations")
	cmd.Flags().StringVar(&since, "since", "", "operations created since a duration ago or an RFC3339 timestamp")
	cmd.Flags().BoolVar(&output, "output", false, "show the operation's saved step-output tails instead of its receipt")
	cmd.Flags().StringVar(&step, "step", "", "with --output, select a step by name or one-based position")
	return cmd
}

func historySince(value string, now time.Time) (time.Time, error) {
	if duration, err := time.ParseDuration(value); err == nil {
		if duration <= 0 {
			return time.Time{}, errors.New("--since needs a positive duration, such as 24h")
		}
		return now.Add(-duration).UTC(), nil
	}
	if since, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return since.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("--since %q must be a positive duration such as 24h or an RFC3339 timestamp", value)
}

func newKernel(a *app) *cobra.Command {
	kernelCmd := &cobra.Command{
		Use:    "kernel",
		Short:  "Exercise the kernel itself.",
		Hidden: true, // a fixture for the lane, not a command for a person
	}
	var (
		in       kernel.ExerciseInput
		planOnly bool
		recovery string
	)
	exercise := &cobra.Command{
		Use:   "exercise",
		Short: "Run a fixture operation that writes marker files, to prove journaling and recovery.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			in.Recovery = kernel.Recovery(recovery)
			return a.operate(cmd.Context(), kernel.ExerciseKind, in, planOnly)
		},
	}
	exercise.Flags().StringVar(&in.Dir, "dir", "", "where the marker files go (required)")
	exercise.Flags().IntVar(&in.Steps, "steps", 4, "how many steps")
	exercise.Flags().StringVar(&in.StepDuration, "step-duration", "0s", "how long each step takes")
	exercise.Flags().IntVar(&in.FailAt, "fail-at", 0, "make this step fail (1-based)")
	exercise.Flags().StringVar(&recovery, "recovery", "resume", "resume or compensate after an interruption")
	a.mutatingFlags(exercise, &planOnly)
	_ = exercise.MarkFlagRequired("dir")
	kernelCmd.AddCommand(exercise)
	return kernelCmd
}
