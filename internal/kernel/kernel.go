// Package kernel runs operations. An operation is planned as steps,
// journaled in the state store under a lease while it applies, and finished
// with a receipt. When the daemon dies mid-way, the next daemon resumes the
// remaining steps or undoes the completed ones, as the plan says.
package kernel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

// Step is one unit of work in a plan.
type Step struct {
	// Name identifies the step within its operation. It must be the same
	// each time the same input is planned, because recovery matches by name.
	Name string
	// Change says what the step does, for plans and receipts.
	Change string
	// Note says what the planner saw, such as "already installed". It is
	// shown in plans and left out of the plan digest, because the world can
	// change between planning and a resume without changing the plan.
	Note string
	// Apply does the work. After a crash it may run again, so it must be
	// safe to repeat.
	Apply func(ctx context.Context, out io.Writer) error
	// Undo reverses a step that succeeded. Nil when there is nothing to undo.
	Undo func(ctx context.Context, out io.Writer) error
}

// Recovery says what to do with an operation whose daemon died mid-way.
type Recovery string

const (
	// Resume runs the steps that haven't succeeded yet.
	Resume Recovery = "resume"
	// Compensate undoes the steps that succeeded, in reverse, and marks the
	// operation compensated.
	Compensate Recovery = "compensate"
)

// Plan is what a Definition produces for an input.
type Plan struct {
	Target   string
	Steps    []Step
	Recovery Recovery
}

// Definition is an operation kind: how to plan it from its input.
type Definition interface {
	Kind() string
	// Plan builds the steps for input. It reads the world and changes
	// nothing. For the same input and world it yields the same step names.
	Plan(ctx context.Context, input json.RawMessage) (*Plan, error)
}

// An Abandoner is told when Recover ends one of its operations without
// applying it again, because its plan can't be rebuilt or has changed since
// it started, so it can close what the operation left open for a resumed
// attempt that now never comes. It is told before the operation finishes,
// so a daemon killed in between tells it again, and nothing it does changes
// how the operation ends. A definition that wraps another passes it on.
type Abandoner interface {
	Abandon(ctx context.Context, operation, reason string)
}

// Registry maps kinds to definitions.
type Registry map[string]Definition

// Add registers a definition under its kind.
func (r Registry) Add(d Definition) { r[d.Kind()] = d }

// EventType names what happened.
type EventType string

const (
	EventPlanned      EventType = "planned"
	EventResumed      EventType = "resumed"
	EventStepStarted  EventType = "step-started"
	EventStepOutput   EventType = "step-output"
	EventStepFinished EventType = "step-finished"
	EventFinished     EventType = "finished"
	// EventError is sent by the API when a run could not start or continue.
	EventError EventType = "error"
)

// Event is one thing the kernel reports while an operation runs.
type Event struct {
	Type      EventType `json:"type"`
	Operation string    `json:"operation"`
	At        time.Time `json:"at"`
	Plan      *PlanView `json:"plan,omitempty"`
	Step      *StepView `json:"step,omitempty"`
	Line      string    `json:"line,omitempty"`
	Message   string    `json:"message,omitempty"`
	Receipt   *Receipt  `json:"receipt,omitempty"`
}

// PlanView is a plan as shown to people and recorded in the journal.
type PlanView struct {
	Kind     string         `json:"kind"`
	Target   string         `json:"target"`
	Recovery Recovery       `json:"recovery"`
	Steps    []PlanStepView `json:"steps"`
	Digest   string         `json:"digest"`
}

// PlanStepView is one step of a PlanView.
type PlanStepView struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Change string `json:"change"`
	Note   string `json:"note,omitempty"`
}

// StepView is a step's state as reported in events and receipts.
type StepView struct {
	Index    int              `json:"index"`
	Name     string           `json:"name"`
	Change   string           `json:"change,omitempty"`
	Note     string           `json:"note,omitempty"`
	Status   state.StepStatus `json:"status"`
	Attempts int              `json:"attempts,omitempty"`
	Error    string           `json:"error,omitempty"`
	Duration time.Duration    `json:"duration,omitempty"`
	Undoing  bool             `json:"undoing,omitempty"`
}

// Receipt is the record an operation leaves behind.
type Receipt struct {
	ID            string                `json:"id"`
	Kind          string                `json:"kind"`
	Target        string                `json:"target"`
	Status        state.OperationStatus `json:"status"`
	Error         string                `json:"error,omitempty"`
	Owner         string                `json:"owner"`
	Interruptions int                   `json:"interruptions"`
	StartedAt     time.Time             `json:"started_at"`
	FinishedAt    time.Time             `json:"finished_at"`
	Duration      time.Duration         `json:"duration"`
	InputDigest   string                `json:"input_digest"`
	PlanDigest    string                `json:"plan_digest"`
	Steps         []StepView            `json:"steps"`
	Version       string                `json:"bedrock"`
}

// StepOutput is a journaled step's saved diagnostic tail. Output is saved
// when an execution finishes, so running steps may not have output yet.
type StepOutput struct {
	Index      int              `json:"index"`
	Name       string           `json:"name"`
	Status     state.StepStatus `json:"status"`
	Error      string           `json:"error,omitempty"`
	Output     string           `json:"output"`
	FinishedAt time.Time        `json:"finished_at,omitempty"`
}

// OperationOutput is explicitly requested diagnostic output, separate from
// ordinary receipts. Tails can contain both apply and compensation output;
// each execution retains at most TailLinesPerExecution lines.
type OperationOutput struct {
	ID                    string       `json:"id"`
	TailLinesPerExecution int          `json:"tail_lines_per_execution"`
	Steps                 []StepOutput `json:"steps"`
}

// ErrUnknownStep means an output selector did not name a journaled step.
var ErrUnknownStep = errors.New("unknown operation step")

// Engine plans and applies operations against one store.
type Engine struct {
	store    *state.Store
	registry Registry
	owner    string
	leaseTTL time.Duration
	now      func() time.Time
	// crashAfterStep is a test hook. When it returns true the run stops as
	// a killed process would: the lease stays, nothing is finished.
	crashAfterStep func(index int) bool
}

// Option configures an Engine.
type Option func(*Engine)

// WithLeaseTTL sets how long a lease lasts without renewal.
func WithLeaseTTL(d time.Duration) Option { return func(e *Engine) { e.leaseTTL = d } }

// WithClock sets the engine's clock.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// DefaultLeaseTTL is how long a lease lasts without renewal. The engine
// renews every third of it, so a dead daemon is noticed within this long.
const DefaultLeaseTTL = 15 * time.Second

// New returns an engine owned by owner, which names the process holding
// leases.
func New(store *state.Store, registry Registry, owner string, opts ...Option) *Engine {
	e := &Engine{store: store, registry: registry, owner: owner, leaseTTL: DefaultLeaseTTL, now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// PlanOnly builds and shows a plan without recording or applying anything.
func (e *Engine) PlanOnly(ctx context.Context, kind string, input json.RawMessage) (*PlanView, error) {
	_, view, err := e.plan(ctx, kind, input)
	return view, err
}

func (e *Engine) plan(ctx context.Context, kind string, input json.RawMessage) (*Plan, *PlanView, error) {
	def, ok := e.registry[kind]
	if !ok {
		return nil, nil, fmt.Errorf("unknown operation kind %q", kind)
	}
	plan, err := def.Plan(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("plan %s: %w", kind, err)
	}
	if len(plan.Steps) == 0 {
		return nil, nil, fmt.Errorf("plan %s: no steps", kind)
	}
	if plan.Recovery == "" {
		plan.Recovery = Resume
	}
	seen := map[string]bool{}
	view := &PlanView{Kind: kind, Target: plan.Target, Recovery: plan.Recovery}
	for i, st := range plan.Steps {
		if st.Name == "" || st.Apply == nil {
			return nil, nil, fmt.Errorf("plan %s: step %d needs a name and an Apply", kind, i)
		}
		if seen[st.Name] {
			return nil, nil, fmt.Errorf("plan %s: step name %q repeats", kind, st.Name)
		}
		seen[st.Name] = true
		view.Steps = append(view.Steps, PlanStepView{Index: i, Name: st.Name, Change: st.Change, Note: st.Note})
	}
	view.Digest = digestPlan(view)
	return plan, view, nil
}

// Run plans, records and applies an operation, reporting events as it
// goes, and returns the receipt. The receipt's Status says how it ended;
// the error is set only when the operation didn't reach a final status.
func (e *Engine) Run(ctx context.Context, kind string, input json.RawMessage, emit func(Event)) (*Receipt, error) {
	return e.RunExpecting(ctx, kind, input, "", emit)
}

// ErrPlanChanged is returned when a caller named the plan it meant to apply
// and the plan built now is a different one.
var ErrPlanChanged = errors.New("the plan changed since it was read")

// RunExpecting is Run, refusing unless the plan it builds has the digest the
// caller names. An empty digest applies whatever the plan turns out to be.
//
// This is what makes it safe to read a plan, show it to someone, and apply
// it as a separate act: between those two moments the manifest, the machine
// or another operation can move, and the plan that would run is then not the
// plan that was approved. The digest is checked here rather than in the
// caller so that it holds for the daemon's API too, not only the CLI.
func (e *Engine) RunExpecting(ctx context.Context, kind string, input json.RawMessage, expect string, emit func(Event)) (*Receipt, error) {
	plan, view, err := e.plan(ctx, kind, input)
	if err != nil {
		return nil, err
	}
	if expect != "" && view.Digest != expect {
		return nil, fmt.Errorf("%w: it is now %s, not %s; read it again", ErrPlanChanged, view.Digest, expect)
	}
	planJSON, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	now := e.now()
	id := NewID(now)
	names := make([]string, len(plan.Steps))
	for i, st := range plan.Steps {
		names[i] = st.Name
	}
	if input == nil {
		input = json.RawMessage(`null`)
	}
	err = e.store.CreateOperation(ctx, state.NewOperation{
		ID: id, Kind: kind, Target: plan.Target, Input: input, Plan: planJSON, PlanDigest: view.Digest,
		Recovery: string(plan.Recovery), StepNames: names, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	emit(Event{Type: EventPlanned, Operation: id, At: now, Plan: view})
	op, err := e.store.Claim(ctx, id, e.owner, now, now.Add(e.leaseTTL))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRenewing := e.keepLease(ctx, op.ID, cancel)
	defer stopRenewing()
	return e.apply(ctx, op, plan, view, emit)
}

// Recover finds operations left applying by a daemon that died and finishes
// them as their plan asks. It returns how many it handled; one another
// owner claimed first is left to that owner and not counted.
func (e *Engine) Recover(ctx context.Context, emit func(Event)) (int, error) {
	orphans, err := e.store.Orphaned(ctx, e.now())
	if err != nil {
		return 0, err
	}
	handled := 0
	for _, orphan := range orphans {
		now := e.now()
		op, err := e.store.Claim(ctx, orphan.ID, e.owner, now, now.Add(e.leaseTTL))
		if errors.Is(err, state.ErrLeased) {
			continue // someone else got there first
		}
		if err != nil {
			return 0, err
		}
		handled++
		if err := e.recoverOperation(ctx, op, emit); err != nil && !errors.Is(err, errCrashed) {
			return handled, err
		}
	}
	return handled, nil
}

// Recovery owns the lease while rebuilding the plan as well as executing it:
// planning and compensation can both take longer than the initial lease.
func (e *Engine) recoverOperation(ctx context.Context, op *state.Operation, emit func(Event)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRenewing := e.keepLease(ctx, op.ID, cancel)
	defer stopRenewing()
	plan, view, planErr := e.plan(withOperationID(ctx, op.ID), op.Kind, op.Input)
	switch {
	case planErr != nil:
		return e.abandon(ctx, op, "interrupted, and the plan can't be rebuilt: "+planErr.Error(), emit)
	case !recordedPlanMatches(op, view):
		return e.abandon(ctx, op, "interrupted, and the plan changed since it started", emit)
	}
	emit(Event{Type: EventResumed, Operation: op.ID, At: e.now(), Plan: view,
		Message: fmt.Sprintf("interrupted %d time(s); %s", op.Interruptions, describeRecovery(plan.Recovery))})
	if plan.Recovery == Compensate {
		_, err := e.compensate(ctx, op, plan, "interrupted before it finished", emit)
		return err
	}
	_, err := e.apply(ctx, op, plan, view, emit)
	return err
}

// recordedPlanMatches compares the semantic fields as well as the digest.
// Legacy separator hashes can collide, so their equality alone never permits
// recovery. Unchanged legacy plans retain their original journal and receipt
// digest even when the current encoding gives them a different one.
func recordedPlanMatches(op *state.Operation, fresh *PlanView) bool {
	var saved PlanView
	if json.Unmarshal(op.Plan, &saved) != nil || saved.Kind != fresh.Kind || saved.Target != fresh.Target || saved.Recovery != fresh.Recovery || len(saved.Steps) != len(fresh.Steps) {
		return false
	}
	for i, st := range saved.Steps {
		current := fresh.Steps[i]
		if st.Index != current.Index || st.Name != current.Name || st.Change != current.Change {
			return false
		}
	}
	return op.PlanDigest == digestPlan(&saved) || op.PlanDigest == legacyPlanDigest(&saved)
}

// abandon ends a recovered operation as failed without applying it again,
// telling its definition first when it is an Abandoner.
func (e *Engine) abandon(ctx context.Context, op *state.Operation, reason string, emit func(Event)) error {
	if a, ok := e.registry[op.Kind].(Abandoner); ok {
		a.Abandon(ctx, op.ID, reason)
	}
	return e.finish(ctx, op.ID, state.Failed, reason, emit)
}

func describeRecovery(r Recovery) string {
	if r == Compensate {
		return "undoing the completed steps"
	}
	return "resuming the remaining steps"
}

// errCrashed is what the test hook makes apply return.
var errCrashed = errors.New("simulated crash")

type attemptKey struct{}

// Attempt is which attempt of its step the calling Apply is: 1 the first
// time, 2 when a resumed operation runs the step again. Zero outside a
// step.
func Attempt(ctx context.Context) int {
	n, _ := ctx.Value(attemptKey{}).(int)
	return n
}

// apply runs the steps that haven't succeeded, under a lease it keeps renewing.
func (e *Engine) apply(ctx context.Context, op *state.Operation, plan *Plan, view *PlanView, emit func(Event)) (*Receipt, error) {
	steps, err := e.store.Steps(ctx, op.ID)
	if err != nil {
		return nil, err
	}
	if reason := journalFits(op.ID, steps, plan); reason != "" {
		return e.finishWithReceipt(ctx, op.ID, state.Failed, reason, emit)
	}
	for i, st := range plan.Steps {
		if steps[i].Status == state.StepSucceeded {
			continue
		}
		started := e.now()
		if err := e.store.StepStarted(ctx, op.ID, i, started); err != nil {
			return nil, err
		}
		emit(Event{Type: EventStepStarted, Operation: op.ID, At: started, Step: &StepView{Index: i, Name: st.Name, Change: st.Change, Status: state.StepRunning}})
		out := newLineWriter(func(line string) {
			emit(Event{Type: EventStepOutput, Operation: op.ID, At: e.now(), Step: &StepView{Index: i, Name: st.Name}, Line: line})
		})
		stepErr := st.Apply(context.WithValue(withOperationID(ctx, op.ID), attemptKey{}, steps[i].Attempts+1), out)
		out.Flush()
		finished := e.now()
		status, errText := state.StepSucceeded, ""
		if stepErr != nil {
			status, errText = state.StepFailed, stepErr.Error()
		}
		if err := e.store.StepFinished(ctx, op.ID, i, status, errText, out.Tail(), finished); err != nil {
			return nil, err
		}
		emit(Event{Type: EventStepFinished, Operation: op.ID, At: finished, Step: &StepView{Index: i, Name: st.Name, Change: st.Change, Status: status, Error: errText, Duration: finished.Sub(started)}})
		if stepErr != nil {
			if plan.Recovery == Compensate {
				return e.compensate(ctx, op, plan, fmt.Sprintf("%s: %s", st.Name, stepErr), emit)
			}
			return e.finishWithReceipt(ctx, op.ID, state.Failed, fmt.Sprintf("%s: %s", st.Name, stepErr), emit)
		}
		if e.crashAfterStep != nil && e.crashAfterStep(i) {
			return nil, errCrashed
		}
	}
	return e.finishWithReceipt(ctx, op.ID, state.Succeeded, "", emit)
}

// compensate undoes the succeeded steps in reverse and marks the operation
// compensated with reason.
func (e *Engine) compensate(ctx context.Context, op *state.Operation, plan *Plan, reason string, emit func(Event)) (*Receipt, error) {
	steps, err := e.store.Steps(ctx, op.ID)
	if err != nil {
		return nil, err
	}
	if reason := journalFits(op.ID, steps, plan); reason != "" {
		return e.finishWithReceipt(ctx, op.ID, state.Failed, reason, emit)
	}
	for i := len(plan.Steps) - 1; i >= 0; i-- {
		if steps[i].Status != state.StepSucceeded || plan.Steps[i].Undo == nil {
			continue
		}
		st := plan.Steps[i]
		started := e.now()
		emit(Event{Type: EventStepStarted, Operation: op.ID, At: started, Step: &StepView{Index: i, Name: st.Name, Change: st.Change, Status: state.StepRunning, Undoing: true}})
		out := newLineWriter(func(line string) {
			emit(Event{Type: EventStepOutput, Operation: op.ID, At: e.now(), Step: &StepView{Index: i, Name: st.Name, Undoing: true}, Line: line})
		})
		undoErr := st.Undo(withOperationID(ctx, op.ID), out)
		out.Flush()
		finished := e.now()
		status, errText := state.StepUndone, ""
		if undoErr != nil {
			status, errText = state.StepFailed, "undo: "+undoErr.Error()
		}
		if err := e.store.StepFinished(ctx, op.ID, i, status, errText, steps[i].Output+out.Tail(), finished); err != nil {
			return nil, err
		}
		emit(Event{Type: EventStepFinished, Operation: op.ID, At: finished, Step: &StepView{Index: i, Name: st.Name, Change: st.Change, Status: status, Error: errText, Duration: finished.Sub(started), Undoing: true}})
		if undoErr != nil {
			return e.finishWithReceipt(ctx, op.ID, state.Failed, fmt.Sprintf("%s; then undoing %s failed: %s", reason, st.Name, undoErr), emit)
		}
	}
	return e.finishWithReceipt(ctx, op.ID, state.Compensated, reason, emit)
}

// journalFits says why an operation's journal can't be applied against a
// plan, or "" when the two describe the same steps. A recovered plan is
// checked by digest before it gets here, so a mismatch means the journal
// itself lost or gained rows; the operation ends rather than the daemon.
func journalFits(id string, steps []state.Step, plan *Plan) string {
	if len(steps) != len(plan.Steps) {
		return fmt.Sprintf("the journal of %s holds %d step(s) for a plan of %d; it can't be applied", id, len(steps), len(plan.Steps))
	}
	for i, st := range steps {
		if st.Index != i {
			return fmt.Sprintf("the journal of %s records step %d at index %d; it can't be applied", id, i+1, st.Index)
		}
		if st.Name != plan.Steps[i].Name {
			return fmt.Sprintf("the journal of %s names step %d %q where the plan says %q; it can't be applied", id, i+1, st.Name, plan.Steps[i].Name)
		}
	}
	return ""
}

func (e *Engine) finish(ctx context.Context, id string, status state.OperationStatus, reason string, emit func(Event)) error {
	_, err := e.finishWithReceipt(ctx, id, status, reason, emit)
	return err
}

func (e *Engine) finishWithReceipt(ctx context.Context, id string, status state.OperationStatus, reason string, emit func(Event)) (*Receipt, error) {
	now := e.now()
	// Write the receipt from the journal, then store it with the outcome.
	op, steps, err := e.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	op.Status, op.Error, op.FinishedAt = status, reason, now
	receipt := buildReceipt(op, steps)
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	if err := e.store.Finish(ctx, id, status, reason, raw, now); err != nil {
		return nil, err
	}
	emit(Event{Type: EventFinished, Operation: id, At: now, Receipt: receipt, Message: reason})
	return receipt, nil
}

// keepLease renews the operation's lease until stop is called. Losing the
// lease cancels the run: another owner has taken the operation.
func (e *Engine) keepLease(ctx context.Context, id string, lost context.CancelFunc) (stop func()) {
	interval := e.leaseTTL / 3
	if interval <= 0 {
		interval = time.Second
	}
	done := make(chan struct{})
	exited := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(exited)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := e.store.Renew(ctx, id, e.owner, e.now().Add(e.leaseTTL)); err != nil {
					lost()
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }); <-exited }
}

// ReceiptOf builds the receipt for a recorded operation, finished or not.
func (e *Engine) ReceiptOf(ctx context.Context, id string) (*Receipt, error) {
	return ReceiptFromStore(ctx, e.store, id)
}

// ReceiptFromStore is ReceiptOf for a caller that holds only the store,
// such as one reading an incident's last deploy. A finished operation's
// receipt is the one it saved; state.ErrNotFound when there is no such
// operation.
func ReceiptFromStore(ctx context.Context, store *state.Store, id string) (*Receipt, error) {
	op, steps, err := store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if op.Receipt != nil {
		var r Receipt
		if err := json.Unmarshal(op.Receipt, &r); err == nil {
			return &r, nil
		}
	}
	return buildReceipt(op, steps), nil
}

// OutputOf returns saved tails for an operation, optionally selecting one
// step by name or its one-based position. ReceiptOf intentionally omits them.
func (e *Engine) OutputOf(ctx context.Context, id, selected string) (*OperationOutput, error) {
	op, steps, err := e.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &OperationOutput{ID: op.ID, TailLinesPerExecution: tailLines, Steps: make([]StepOutput, 0, len(steps))}
	position, _ := strconv.Atoi(selected)
	// Prefer an exact name when a step's name happens to be a number.
	named := false
	for _, st := range steps {
		if st.Name == selected {
			named = true
			break
		}
	}
	var names []string
	for _, st := range steps {
		names = append(names, st.Name)
		if selected != "" && st.Name != selected && (named || position != st.Index+1) {
			continue
		}
		out.Steps = append(out.Steps, StepOutput{Index: st.Index, Name: st.Name, Status: st.Status, Error: st.Error, Output: st.Output, FinishedAt: st.FinishedAt})
	}
	if selected != "" && len(out.Steps) == 0 {
		return nil, fmt.Errorf("%w %q; choose a name or a one-based position: %s", ErrUnknownStep, selected, strings.Join(names, ", "))
	}
	return out, nil
}

func buildReceipt(op *state.Operation, steps []state.Step) *Receipt {
	var view PlanView
	_ = json.Unmarshal(op.Plan, &view)
	r := &Receipt{
		ID: op.ID, Kind: op.Kind, Target: op.Target, Status: op.Status, Error: op.Error, Owner: op.LeaseOwner,
		Interruptions: op.Interruptions, StartedAt: op.StartedAt, FinishedAt: op.FinishedAt,
		InputDigest: digestBytes(op.Input), PlanDigest: op.PlanDigest, Version: version.Current().Version,
	}
	if !op.StartedAt.IsZero() && !op.FinishedAt.IsZero() {
		r.Duration = op.FinishedAt.Sub(op.StartedAt)
	}
	for _, st := range steps {
		sv := StepView{Index: st.Index, Name: st.Name, Status: st.Status, Attempts: st.Attempts, Error: st.Error}
		if st.Index >= 0 && st.Index < len(view.Steps) {
			sv.Change, sv.Note = view.Steps[st.Index].Change, view.Steps[st.Index].Note
		}
		if !st.StartedAt.IsZero() && !st.FinishedAt.IsZero() {
			sv.Duration = st.FinishedAt.Sub(st.StartedAt)
		}
		r.Steps = append(r.Steps, sv)
	}
	return r
}

// NewID makes an operation ID that sorts by time and can't be guessed.
func NewID(now time.Time) string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var tail strings.Builder
	for _, c := range b {
		tail.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return "op-" + now.UTC().Format("20060102-150405") + "-" + tail.String()
}

// Escape field separators and their escape character so descriptions cannot
// impersonate another field or step. Ordinary plans retain their existing
// digests, including during upgrade recovery.
var planDigestEscaper = strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\t", "\\t")

func digestPlan(view *PlanView) string {
	h := sha256.New()
	escaped := strings.ContainsAny(view.Kind, "\\\n\t") || strings.ContainsAny(view.Target, "\\\n\t") || strings.ContainsAny(string(view.Recovery), "\\\n\t")
	for _, st := range view.Steps {
		escaped = escaped || strings.ContainsAny(st.Name, "\\\n\t") || strings.ContainsAny(st.Change, "\\\n\t")
	}
	if escaped {
		// The NUL prefix cannot be the start of a registered legacy kind.
		// Keep escaped digests separate from every legacy literal-escape hash.
		io.WriteString(h, "\x00helios-plan-escaped-v1\n")
	}
	fmt.Fprintf(h, "%s\n%s\n%s\n", planDigestEscaper.Replace(view.Kind), planDigestEscaper.Replace(view.Target), planDigestEscaper.Replace(string(view.Recovery)))
	for _, st := range view.Steps {
		fmt.Fprintf(h, "%d\t%s\t%s\n", st.Index, planDigestEscaper.Replace(st.Name), planDigestEscaper.Replace(st.Change))
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// legacyPlanDigest is used only to validate a persisted plan during recovery,
// after its semantic fields have been compared with the freshly built plan.
func legacyPlanDigest(view *PlanView) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", view.Kind, view.Target, view.Recovery)
	for _, st := range view.Steps {
		fmt.Fprintf(h, "%d\t%s\t%s\n", st.Index, st.Name, st.Change)
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:24]
}

// lineWriter turns a step's output into lines and keeps a bounded tail.
type lineWriter struct {
	mu        sync.Mutex
	emit      func(string)
	partial   strings.Builder
	truncated bool
	tail      []string
}

const (
	tailLines    = 40
	maxLineBytes = 64 << 10
)

func newLineWriter(emit func(string)) *lineWriter { return &lineWriter{emit: emit} }

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range p {
		if c == '\n' {
			w.flushLine()
			continue
		}
		if w.partial.Len() < maxLineBytes {
			w.partial.WriteByte(c)
		} else {
			w.truncated = true
		}
	}
	return len(p), nil
}

func (w *lineWriter) flushLine() {
	line := w.partial.String()
	if w.truncated {
		line += " [line truncated]"
	}
	w.line(line)
	w.partial.Reset()
	w.truncated = false
}

func (w *lineWriter) line(s string) {
	s = strings.TrimRight(s, "\r")
	w.tail = append(w.tail, s)
	if len(w.tail) > tailLines {
		w.tail = w.tail[len(w.tail)-tailLines:]
	}
	w.emit(s)
}

// Flush emits a final line that had no newline.
func (w *lineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.partial.Len() > 0 {
		w.flushLine()
	}
}

// Tail returns the last lines of output, newline-terminated.
func (w *lineWriter) Tail() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.tail) == 0 {
		return ""
	}
	return strings.Join(w.tail, "\n") + "\n"
}
