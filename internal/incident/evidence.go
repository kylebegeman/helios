// Package incident gathers what someone looking into an incident needs
// first: the change made before it, what the app's containers wrote
// around it, the key's history and the status of the services the host
// leans on. Secrets and private addresses are redacted as each part is
// collected, and the whole is fit to a size before it is kept or sent.
package incident

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"time"
)

// Schema is the version of the evidence's shape.
const Schema = 1

// Caps on evidence. Sizes are of the JSON indented by two spaces.
const (
	// FileMax is the most evidence.json holds.
	FileMax = 256 << 10
	// LoomEvidenceMax is the most of the evidence a Loom body carries.
	LoomEvidenceMax = 90_000
	// CollectBudget is how long Collect may take; a source still going
	// then records its error.
	CollectBudget = 20 * time.Second

	// window is how far back from the incident's opening logs are read.
	window = 10 * time.Minute
	// lineMax is the longest log line kept; the rest is counted.
	lineMax = 2 << 10
	// linesPerContainer are the newest lines kept from each container,
	// and minLinesPerContainer the fewest Fit leaves.
	linesPerContainer    = 400
	minLinesPerContainer = 20
	// maxContainers are the containers kept, those that wrote last first.
	maxContainers = 12
	// messageMax caps an incident's key, subject and message.
	messageMax = 4 << 10
	// noteMax caps a step's note or error, an operation's error and each
	// error a source records.
	noteMax  = 1 << 10
	maxSteps = 50
	// maxIncidents are the key's earlier incidents kept, newest first.
	maxIncidents = 10
	// signalWindow and maxSignals bound the app's hourly signals.
	signalWindow = 6 * time.Hour
	maxSignals   = 50
	// maxSuppressed are journald's newest notes of dropped output kept.
	maxSuppressed = 50
	// changeScan is how many of an app's deploys, and of its rollbacks,
	// are looked through for the last change before the incident.
	changeScan = 50
	// recentWindow and maxRecent bound the deploys a host incident lists.
	recentWindow = time.Hour
	maxRecent    = 5
	// fitIncidents and fitSignals are what Fit's third step leaves.
	fitIncidents = 3
	fitSignals   = 10
)

// Redaction statuses.
const (
	// RedactionApplied means every secret helios holds for the app was
	// known and replaced.
	RedactionApplied = "applied"
	// RedactionLogsOmitted means a secret set couldn't be read or a value
	// survived redaction, so logs and step notes were left out.
	RedactionLogsOmitted = "logs_omitted"
)

// Evidence is what is known about an incident. evidence.json and a Loom
// body's evidence have this shape.
type Evidence struct {
	Schema      int       `json:"schema"`
	Host        string    `json:"host"`
	Incident    Incident  `json:"incident"`
	Window      Window    `json:"window"`
	CollectedAt time.Time `json:"collected_at"`
	// CollectedBy is who collected it, such as the daemon or the CLI.
	CollectedBy string `json:"collected_by"`
	// Late is set when it was collected after the incident's alerts went
	// out; it still covers the same window.
	Late       bool      `json:"late"`
	Redaction  Redaction `json:"redaction"`
	LastChange *Change   `json:"last_change,omitempty"`
	// RecentDeploys are deploys and rollbacks across apps in the hour
	// before a host incident.
	RecentDeploys     []Change     `json:"recent_deploys,omitempty"`
	Logs              []Log        `json:"logs,omitempty"`
	JournalSuppressed []Suppressed `json:"journal_suppressed,omitempty"`
	History           *History     `json:"history,omitempty"`
	Upstream          []Upstream   `json:"upstream,omitempty"`
	// Truncated says what was left out to fit.
	Truncated []string      `json:"truncated"`
	Errors    []SourceError `json:"errors"`
}

// Incident is the incident the evidence is about.
type Incident struct {
	ID         int64      `json:"id"`
	Key        string     `json:"key"`
	Subject    string     `json:"subject"`
	Severity   string     `json:"severity"`
	Message    string     `json:"message"`
	OpenedAt   time.Time  `json:"opened_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

// Window is the stretch of time logs were read from.
type Window struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// Redaction says how far the evidence could be redacted.
type Redaction struct {
	Status string `json:"status"`
}

// Change is a deploy or rollback.
type Change struct {
	Operation  string    `json:"operation"`
	Kind       string    `json:"kind"`
	App        string    `json:"app"`
	Revision   string    `json:"revision,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Signer     string    `json:"signer,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error,omitempty"`
	Steps      []Step    `json:"steps,omitempty"`
}

// Step is one step of a change.
type Step struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	TookMS int64  `json:"took_ms"`
	Note   string `json:"note,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Log is what one container wrote in the window, newest lines kept.
type Log struct {
	Container string `json:"container"`
	Workload  string `json:"workload,omitempty"`
	Revision  string `json:"revision,omitempty"`
	// Source is journal, or engine for a container Docker logged to its
	// own files.
	Source     string `json:"source"`
	LinesTotal int    `json:"lines_total"`
	LinesKept  int    `json:"lines_kept"`
	Lines      []Line `json:"lines,omitempty"`
}

// Line is one log line. Lines read from the engine have no time or
// stream.
type Line struct {
	T      time.Time `json:"t,omitzero"`
	Stream string    `json:"stream,omitempty"`
	Text   string    `json:"text"`
}

// Suppressed is journald's note that it dropped Count of Docker's lines.
type Suppressed struct {
	At    time.Time `json:"at"`
	Count int       `json:"count"`
}

// History is what happened to the key before.
type History struct {
	Incidents []PriorIncident `json:"incidents"`
	Signals   []Signal        `json:"signals,omitempty"`
}

// PriorIncident is an earlier incident of the same key.
type PriorIncident struct {
	ID           int64      `json:"id"`
	Severity     string     `json:"severity"`
	OpenedAt     time.Time  `json:"opened_at"`
	ResolvedAt   *time.Time `json:"resolved_at"`
	Observations int        `json:"observations"`
	Message      string     `json:"message"`
}

// Signal is one hourly rollup of the app's numbers.
type Signal struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

// Upstream is a vendor's status page as it read when collected.
type Upstream struct {
	Name        string    `json:"name"`
	Indicator   string    `json:"indicator"`
	Description string    `json:"description"`
	FetchedAt   time.Time `json:"fetched_at"`
	Error       string    `json:"error"`
}

// SourceError is a source that couldn't be read.
type SourceError struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

// Size is the length of e's JSON indented by two spaces, which is never
// shorter than Loom's JSON.stringify(v, null, 2) of the same value.
func Size(e *Evidence) int {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return math.MaxInt
	}
	return len(b)
}

// Fit trims e until Size(e) is at most limit, in steps that each give up
// more than the one before, and stops as soon as it fits:
//
//  1. halve each container's lines, newest kept, down to 20;
//  2. drop step notes;
//  3. keep the 3 newest earlier incidents, then the 10 newest signals;
//  4. drop log lines, keeping each container and its counts;
//  5. keep only the envelope: the incident, its window, the last change
//     without its steps, and what was truncated and failed.
//
// Each step that changes something is noted in e.Truncated, and the
// notes are returned. The same evidence and limit always give the same
// result. The envelope can still be over a limit that is too small.
func Fit(e *Evidence, limit int) []string {
	start := len(e.Truncated)
	fitted := func() []string { return slices.Clone(e.Truncated[start:]) }
	if Size(e) <= limit {
		return nil
	}
	note := -1
	for allowance := linesPerContainer; allowance > minLinesPerContainer; {
		allowance = max(allowance/2, minLinesPerContainer)
		if !keepNewestLines(e, allowance) {
			continue
		}
		text := fmt.Sprintf("logs: newest %d lines per container", allowance)
		if note < 0 {
			note = len(e.Truncated)
			e.Truncated = append(e.Truncated, text)
		} else {
			e.Truncated[note] = text
		}
		if Size(e) <= limit {
			return fitted()
		}
	}
	if dropStepNotes(e) {
		e.Truncated = append(e.Truncated, "last_change: step notes dropped")
		if Size(e) <= limit {
			return fitted()
		}
	}
	if h := e.History; h != nil && len(h.Incidents) > fitIncidents {
		h.Incidents = h.Incidents[:fitIncidents]
		e.Truncated = append(e.Truncated, fmt.Sprintf("history: newest %d incidents", fitIncidents))
		if Size(e) <= limit {
			return fitted()
		}
	}
	if h := e.History; h != nil && len(h.Signals) > fitSignals {
		h.Signals = h.Signals[:fitSignals]
		e.Truncated = append(e.Truncated, fmt.Sprintf("history: newest %d signals", fitSignals))
		if Size(e) <= limit {
			return fitted()
		}
	}
	if dropLogLines(e) {
		e.Truncated = append(e.Truncated, "logs: lines dropped, containers and counts kept")
		if Size(e) <= limit {
			return fitted()
		}
	}
	e.RecentDeploys, e.Logs, e.JournalSuppressed, e.History, e.Upstream = nil, nil, nil, nil, nil
	if e.LastChange != nil {
		e.LastChange.Steps = nil
	}
	e.Truncated = append(e.Truncated, "envelope only: incident, window and last change")
	return fitted()
}

// keepNewestLines cuts each container to its newest n lines and reports
// whether any had more.
func keepNewestLines(e *Evidence, n int) bool {
	cut := false
	for i := range e.Logs {
		l := &e.Logs[i]
		if len(l.Lines) > n {
			l.Lines = l.Lines[len(l.Lines)-n:]
			l.LinesKept = n
			cut = true
		}
	}
	return cut
}

func dropStepNotes(e *Evidence) bool {
	if e.LastChange == nil {
		return false
	}
	dropped := false
	for i := range e.LastChange.Steps {
		if e.LastChange.Steps[i].Note != "" {
			e.LastChange.Steps[i].Note = ""
			dropped = true
		}
	}
	return dropped
}

func dropLogLines(e *Evidence) bool {
	dropped := false
	for i := range e.Logs {
		if len(e.Logs[i].Lines) > 0 {
			e.Logs[i].Lines, e.Logs[i].LinesKept = nil, 0
			dropped = true
		}
	}
	return dropped
}

// Clone copies e so one copy can be fit without changing the other.
// Times are shared; nothing changes them.
func (e *Evidence) Clone() *Evidence {
	c := *e
	if e.LastChange != nil {
		change := *e.LastChange
		change.Steps = slices.Clone(change.Steps)
		c.LastChange = &change
	}
	c.RecentDeploys = slices.Clone(e.RecentDeploys)
	c.Logs = slices.Clone(e.Logs)
	for i := range c.Logs {
		c.Logs[i].Lines = slices.Clone(c.Logs[i].Lines)
	}
	c.JournalSuppressed = slices.Clone(e.JournalSuppressed)
	if e.History != nil {
		h := History{Incidents: slices.Clone(e.History.Incidents), Signals: slices.Clone(e.History.Signals)}
		c.History = &h
	}
	c.Upstream = slices.Clone(e.Upstream)
	c.Truncated = slices.Clone(e.Truncated)
	c.Errors = slices.Clone(e.Errors)
	return &c
}
