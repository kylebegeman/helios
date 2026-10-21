package incident

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// full is evidence with something for every step of Fit to trim: two
// containers of 400 lines, steps with notes, ten earlier incidents and
// fifty signals.
func full() *Evidence {
	e := &Evidence{
		Schema: Schema, Host: "web.example.test",
		Incident:  Incident{ID: 42, Key: "app:web", Subject: "web is failing", Severity: "critical", Message: "GET / answered 502", OpenedAt: opened},
		Window:    Window{Since: opened.Add(-window), Until: opened},
		Redaction: Redaction{Status: RedactionApplied},
		LastChange: &Change{Operation: "op-web-3", Kind: "app.deploy", App: "web", Revision: "r7", StartedAt: opened.Add(-5 * time.Minute), Outcome: "succeeded", Steps: []Step{
			{Name: "build", Status: "succeeded", TookMS: 812, Note: strings.Repeat("n", 900)},
			{Name: "start", Status: "succeeded", TookMS: 90, Note: strings.Repeat("n", 900)},
		}},
		History:   &History{},
		Upstream:  []Upstream{{Name: "status.example.test", Indicator: "none", FetchedAt: opened}},
		Truncated: []string{"logs: the 12 containers that wrote last"},
		Errors:    []SourceError{},
	}
	for c := range 2 {
		log := Log{Container: fmt.Sprintf("web-%d", c+1), Source: sourceJournal, LinesTotal: 400, LinesKept: 400}
		for i := range 400 {
			log.Lines = append(log.Lines, Line{T: opened.Add(time.Duration(i-400) * time.Second), Stream: "stdout", Text: fmt.Sprintf("line %d", i)})
		}
		e.Logs = append(e.Logs, log)
	}
	for i := range 10 {
		e.History.Incidents = append(e.History.Incidents, PriorIncident{ID: int64(41 - i), Severity: "warning", OpenedAt: opened.Add(-time.Duration(i+1) * time.Hour), Message: strings.Repeat("m", 200)})
	}
	for i := range 50 {
		e.History.Signals = append(e.History.Signals, Signal{At: opened.Add(-time.Duration(i) * time.Hour), Kind: "requests", Detail: strings.Repeat("d", 100)})
	}
	return e
}

func TestFitTrimsInItsOrderAndStopsOnceItFits(t *testing.T) {
	e := full()
	size := Size(e)

	if notes := Fit(e.Clone(), size); notes != nil {
		t.Fatalf("evidence that fits was trimmed: %q", notes)
	}

	one := e.Clone()
	if notes := Fit(one, size-1); !slices.Equal(notes, []string{"logs: newest 200 lines per container"}) {
		t.Fatalf("one byte over took %q", notes)
	}
	if l := one.Logs[1]; len(l.Lines) != 200 || l.LinesKept != 200 || l.LinesTotal != 400 || l.Lines[0].Text != "line 200" {
		t.Fatalf("kept %d of %d lines from %q", l.LinesKept, l.LinesTotal, l.Lines[0].Text)
	}

	all := e.Clone()
	notes := Fit(all, 1)
	want := []string{
		"logs: newest 20 lines per container",
		"last_change: step notes dropped",
		"history: newest 3 incidents",
		"history: newest 10 signals",
		"logs: lines dropped, containers and counts kept",
		"envelope only: incident, window and last change",
	}
	if !slices.Equal(notes, want) || !slices.Equal(all.Truncated, append([]string{"logs: the 12 containers that wrote last"}, want...)) {
		t.Fatalf("fit took %q, truncated %q", notes, all.Truncated)
	}
	if all.Logs != nil || all.History != nil || all.Upstream != nil || all.LastChange == nil || all.LastChange.Steps != nil || all.LastChange.Revision != "r7" {
		t.Fatalf("envelope %+v", all)
	}

	// Lines go down to 20 a container before step notes go, and fitting
	// to what those two steps leave stops there.
	two := e.Clone()
	for i := range two.Logs {
		two.Logs[i].Lines, two.Logs[i].LinesKept = two.Logs[i].Lines[380:], 20
	}
	for i := range two.LastChange.Steps {
		two.LastChange.Steps[i].Note = ""
	}
	two.Truncated = append(two.Truncated, want[:2]...)
	if notes := Fit(e.Clone(), Size(two)); !slices.Equal(notes, want[:2]) {
		t.Fatalf("fit to %d took %q", Size(two), notes)
	}

	if Size(e) != size {
		t.Fatal("fitting a clone changed the evidence")
	}
}

func TestFitGivesTheSameResultEveryTime(t *testing.T) {
	e := full()
	for _, limit := range []int{FileMax, 40_000, 12_000, 3_000, 1} {
		a, b := e.Clone(), e.Clone()
		notesA, notesB := Fit(a, limit), Fit(b, limit)
		ja, err := json.MarshalIndent(a, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		jb, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if string(ja) != string(jb) || !slices.Equal(notesA, notesB) {
			t.Fatalf("fit to %d gave %q and %q", limit, notesA, notesB)
		}
		if limit >= Size(e) {
			continue
		}
		if len(ja) > limit && notesA[len(notesA)-1] != "envelope only: incident, window and last change" {
			t.Fatalf("fit to %d left %d bytes", limit, len(ja))
		}
	}
}
