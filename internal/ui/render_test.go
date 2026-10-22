package ui

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

func events() []kernel.Event {
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	return []kernel.Event{
		{Type: kernel.EventPlanned, Operation: "op-1", At: t0, Plan: &kernel.PlanView{Kind: "kernel.exercise", Target: "/tmp/x", Steps: []kernel.PlanStepView{{Name: "step-1"}, {Name: "step-2"}}}},
		{Type: kernel.EventStepStarted, Operation: "op-1", Step: &kernel.StepView{Index: 0, Name: "step-1", Status: state.StepRunning}},
		{Type: kernel.EventStepOutput, Operation: "op-1", Step: &kernel.StepView{Index: 0, Name: "step-1"}, Line: "wrote /tmp/x/step-1"},
		{Type: kernel.EventStepFinished, Operation: "op-1", Step: &kernel.StepView{Index: 0, Name: "step-1", Status: state.StepSucceeded, Duration: 1200 * time.Millisecond}},
		{Type: kernel.EventStepStarted, Operation: "op-1", Step: &kernel.StepView{Index: 1, Name: "step-2", Status: state.StepRunning}},
		{Type: kernel.EventStepFinished, Operation: "op-1", Step: &kernel.StepView{Index: 1, Name: "step-2", Status: state.StepFailed, Error: "asked to fail", Duration: 300 * time.Millisecond}},
		{Type: kernel.EventFinished, Operation: "op-1", Receipt: &kernel.Receipt{ID: "op-1", Status: state.Failed, Error: "step-2: asked to fail", Duration: 1500 * time.Millisecond, Interruptions: 1}},
	}
}

func TestPlainOutputIsOneLinePerEvent(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, false, false)
	for _, ev := range events() {
		r.Event(ev)
	}
	want := strings.Join([]string{
		"kernel.exercise on /tmp/x (2 steps) op-1",
		"  ...  step-1",
		"       | wrote /tmp/x/step-1",
		"  ok   step-1 (1.2s)",
		"  ...  step-2",
		"  fail step-2 (300ms): asked to fail",
		"failed in 1.5s, interrupted once: step-2: asked to fail",
		"receipt op-1",
		"",
	}, "\n")
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestTerminalOutputRewritesTheRunningLine(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, true, false)
	for _, ev := range events() {
		r.Event(ev)
	}
	s := out.String()
	if !strings.Contains(s, "\r\033[K  ...  step-1: wrote /tmp/x/step-1") {
		t.Fatalf("running line not rewritten in place:\n%q", s)
	}
	// The plan line, two finished steps, the outcome and the receipt line.
	if strings.Count(s, "\n") != 5 {
		t.Fatalf("want 5 lines, got %d:\n%q", strings.Count(s, "\n"), s)
	}
	if !strings.HasSuffix(s, "receipt op-1\n") {
		t.Fatalf("unexpected ending:\n%q", s)
	}
}

func TestJSONOutputIsOneObjectPerEvent(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, true, true)
	for _, ev := range events() {
		r.Event(ev)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(events()) {
		t.Fatalf("want %d lines, got %d", len(events()), len(lines))
	}
	var back kernel.Event
	if err := json.Unmarshal([]byte(lines[0]), &back); err != nil || back.Type != kernel.EventPlanned || back.Plan == nil {
		t.Fatalf("first line: %v %+v", err, back)
	}
}

func TestANoteAfterARunningStepStartsOnALineOfItsOwnAndJSONLeavesItOut(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, true, false)
	r.Event(events()[1])
	r.Note("following op-1")
	if got := out.String(); got != "\r\033[K  ...  step-1\r\033[Kfollowing op-1\n" {
		t.Fatalf("note shares the running line: %q", got)
	}
	out.Reset()
	New(&out, true, true).Note("following op-1")
	if out.Len() != 0 {
		t.Fatalf("JSON output carries a note: %q", out.String())
	}
}

func TestPlanAndReceiptRender(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, false, false)
	r.Plan(&kernel.PlanView{Kind: "kernel.exercise", Target: "/tmp/x", Recovery: kernel.Compensate, Digest: "abc", Steps: []kernel.PlanStepView{{Index: 0, Name: "step-1", Change: "write /tmp/x/step-1"}}})
	if got := out.String(); got != "kernel.exercise on /tmp/x: 1 steps, undo on interruption\n   1. write /tmp/x/step-1\nplan digest abc\n" {
		t.Fatalf("plan:\n%q", got)
	}
	out.Reset()
	r.Receipt(&kernel.Receipt{ID: "op-1", Kind: "kernel.exercise", Target: "/tmp/x", Status: state.Succeeded, Duration: 2 * time.Second, StartedAt: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC),
		Steps: []kernel.StepView{{Name: "step-1", Note: "revision r1", Status: state.StepSucceeded, Duration: time.Second, Attempts: 2}}})
	if got := out.String(); !strings.Contains(got, "succeeded, 1 steps, 2.0s") || !strings.Contains(got, "  ok   step-1 (revision r1) (1.0s), 2 attempts") {
		t.Fatalf("receipt:\n%q", got)
	}
}

func TestDuration(t *testing.T) {
	cases := map[time.Duration]string{0: "0s", 250 * time.Millisecond: "250ms", 1500 * time.Millisecond: "1.5s", 90 * time.Second: "1m30s"}
	for d, want := range cases {
		if got := Duration(d); got != want {
			t.Errorf("%v: got %q want %q", d, got, want)
		}
	}
}

func TestRenderedWorkloadOutputCannotControlTheTerminal(t *testing.T) {
	for _, tty := range []bool{false, true} {
		var out bytes.Buffer
		r := New(&out, tty, false)
		r.Event(kernel.Event{Type: kernel.EventStepOutput, Step: &kernel.StepView{Name: "build"}, Line: "hello\x1b]52;c;clipboard\x07\rforged"})
		wantEscapes := 0
		if tty {
			wantEscapes = 1 // The renderer's own clear-line sequence.
		}
		if strings.Count(out.String(), "\x1b") != wantEscapes || strings.Contains(out.String(), "\x07") || !strings.Contains(out.String(), `hello\x1b]52;c;clipboard\x07\x0dforged`) {
			t.Fatalf("untrusted terminal controls were rendered: %q", out.String())
		}
	}
}

func TestHumanOutputEscapesUnicodeControlsButJSONKeepsOriginal(t *testing.T) {
	ev := kernel.Event{Type: kernel.EventError, Message: "hello\u009b31m\nnext\tcolumn"}
	var human, machine bytes.Buffer
	New(&human, false, false).Event(ev)
	if got := human.String(); got != "error: hello\\x9b31m\nnext\tcolumn\n" {
		t.Fatalf("human output: %q", got)
	}
	New(&machine, false, true).Event(ev)
	var decoded kernel.Event
	if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil || decoded.Message != ev.Message {
		t.Fatalf("JSON changed untrusted value: %+v, %v", decoded, err)
	}
}

func TestHistoryEscapesTerminalControlsAndKeepsEachOperationOnOneRow(t *testing.T) {
	row := Summary{
		ID: "op-1\x1b]52;c;clipboard\x07", Kind: "app.deploy\u009b31m",
		Target: "site\tforged\nrow", Status: state.Failed, Error: "failed\rhidden\nnext\tcolumn",
	}
	var human, machine bytes.Buffer
	New(&human, false, false).History([]Summary{row})
	got := human.String()
	if strings.ContainsAny(got, "\x1b\x07\r\u009b") || strings.Count(got, "\n") != 2 {
		t.Fatalf("history let a field control the terminal or create a row: %q", got)
	}
	for _, want := range []string{`op-1\x1b]52;c;clipboard\x07`, `app.deploy\x9b31m`, `site\tforged\nrow`, `failed\x0dhidden\nnext\tcolumn`} {
		if !strings.Contains(got, want) {
			t.Errorf("history lost the visible field %q: %q", want, got)
		}
	}
	New(&machine, true, true).History([]Summary{row})
	var decoded []Summary
	if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil || len(decoded) != 1 || decoded[0] != row {
		t.Fatalf("JSON history changed the original fields: %+v, %v", decoded, err)
	}
}

func TestHistoryClearsTheRunningLineBeforeItsTable(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, true, false)
	r.Event(events()[1])
	r.History([]Summary{{ID: "op-1", Kind: "app.deploy", Target: "site", Status: state.Applying}})
	if !strings.HasPrefix(out.String(), "\r\033[K  ...  step-1\r\033[KID") {
		t.Fatalf("history shared the running line: %q", out.String())
	}
}

func TestRunningOutputKeepsTabsAndNewlinesOnOneTerminalLine(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, true, false)
	r.Event(kernel.Event{Type: kernel.EventStepOutput, Step: &kernel.StepView{Name: "build"}, Line: "one\ttwo\nthree"})
	if got, want := out.String(), "\r\033[K  ...  build: one\\ttwo\\nthree"; got != want {
		t.Fatalf("running output escaped its terminal line: got %q, want %q", got, want)
	}
}
