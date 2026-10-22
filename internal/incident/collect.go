package incident

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// Secrets reads an app's sealed secrets; *secrets.Store is one.
type Secrets interface {
	LoadCurrent(app string) (map[string]string, int, error)
	Versions(app string) ([]secrets.VersionInfo, error)
	Load(app string, version int) (map[string]string, error)
}

// Engine reads a container's stdout and stderr from Docker;
// *docker.Engine is one.
type Engine interface {
	LogStreams(ctx context.Context, name string, opts docker.LogOptions, stdout, stderr io.Writer) error
}

// Journal reads containers' output from the system journal;
// docker.Journal is one.
type Journal interface {
	Read(ctx context.Context, q docker.JournalQuery) ([]docker.JournalContainer, error)
	Suppressed(ctx context.Context, since, until time.Time) ([]docker.JournalSuppressed, error)
}

// Sources are what Collect reads. A nil Journal or Engine, or no
// Upstream, leaves out what it would give. Without Secrets nothing is
// known to be redacted, so logs, step notes and messages are left out.
type Sources struct {
	Store    *state.Store
	Secrets  Secrets
	Engine   Engine
	Journal  Journal
	Upstream []Statuspage
	// Host is the machine's name as alerts give it.
	Host        string
	CollectedBy string
	// Late marks a collection made after the incident's alerts went out.
	Late bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Log sources.
const (
	sourceJournal = "journal"
	sourceEngine  = "engine"
)

// Collect gathers inc's evidence: for an app the change before it, the
// logs of the ten minutes before it opened and the app's signals; for
// the host the deploys of the hour before; for every key its earlier
// incidents and the upstream status pages. A source that fails records
// its error and the rest go on, within CollectBudget. The evidence is
// redacted and fit to FileMax, and an error is returned only when it
// can't be shown to be free of secrets.
func Collect(ctx context.Context, inc state.Incident, src Sources) (*Evidence, error) {
	if src.Store == nil {
		return nil, errors.New("collecting evidence needs the state store")
	}
	ctx, cancel := context.WithTimeout(ctx, CollectBudget)
	defer cancel()
	if src.Now == nil {
		src.Now = time.Now
	}
	at := inc.OpenedAt.UTC()
	c := &collection{src: src, at: at, e: &Evidence{
		Schema: Schema,
		Host:   src.Host,
		Incident: Incident{
			ID: inc.ID, Key: inc.Key, Subject: inc.Subject, Severity: inc.Severity, Message: inc.Message,
			OpenedAt: at, ResolvedAt: timeOrNil(inc.ResolvedAt),
		},
		Window:      Window{Since: at.Add(-window), Until: at},
		CollectedAt: src.Now().UTC(),
		CollectedBy: src.CollectedBy,
		Late:        src.Late,
		Redaction:   Redaction{Status: RedactionApplied},
		Truncated:   []string{},
		Errors:      []SourceError{},
	}}
	app, isApp := strings.CutPrefix(inc.Key, "app:")
	isApp = isApp && app != ""
	if !isApp {
		app = ""
	}
	c.loadRedactor(ctx, app)
	switch {
	case isApp:
		c.lastChange(ctx, app)
		if !c.omit {
			c.logs(ctx, app)
		}
		c.history(ctx, inc.Key)
		c.signals(ctx, app)
	case strings.HasPrefix(inc.Key, "host:"):
		c.recentDeploys(ctx)
		c.history(ctx, inc.Key)
	default:
		c.history(ctx, inc.Key)
	}
	c.upstream(ctx)
	return c.finish()
}

// collection is one Collect under way.
type collection struct {
	src Sources
	// at is when the incident opened, the end of the window.
	at time.Time
	e  *Evidence
	// redact knows every value to redact; omit is set when it might not.
	redact    *redactor
	omit      bool
	revisions []state.Revision
}

func (c *collection) fail(source string, err error) {
	c.e.Errors = append(c.e.Errors, SourceError{Source: source, Error: err.Error()})
}

// loadRedactor learns the values to redact: the reserved app's current
// secrets and, for an app, every secrets version it has kept, which
// covers the versions its revisions pinned even after gc removed them,
// and the env values of the revisions it still has. A set that can't be
// read leaves logs, step notes and messages out.
func (c *collection) loadRedactor(ctx context.Context, app string) {
	c.redact = &redactor{}
	unreadable := func(source string, err error) {
		c.omit = true
		if !slices.Contains(c.e.Errors, SourceError{Source: source, Error: err.Error()}) {
			c.fail(source, err)
		}
	}
	if c.src.Secrets == nil {
		unreadable("secrets", errors.New("no secret store to redact with"))
	} else {
		values, _, err := c.src.Secrets.LoadCurrent(manifest.ReservedApp)
		if err != nil {
			unreadable("secrets", err)
		}
		c.addSecrets(values)
		if app != "" && app != manifest.ReservedApp {
			c.loadAppSecrets(app, unreadable)
		}
	}
	if app == "" {
		return
	}
	revisions, err := c.src.Store.Revisions(ctx, app)
	if err != nil {
		unreadable("revisions", err)
		return
	}
	c.revisions = revisions
	for _, rev := range revisions {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			unreadable("revisions", fmt.Errorf("the manifest of revision %s can't be read: %w", rev.ID, err))
			continue
		}
		for _, w := range m.Workloads {
			c.addEnv(w.Env)
		}
		if m.Data != nil && m.Data.Postgres != nil {
			c.addEnv(m.Data.Postgres.Env)
		}
	}
}

func (c *collection) loadAppSecrets(app string, unreadable func(string, error)) {
	values, current, err := c.src.Secrets.LoadCurrent(app)
	if err != nil {
		unreadable("secrets", err)
	}
	c.addSecrets(values)
	versions, err := c.src.Secrets.Versions(app)
	if err != nil {
		unreadable("secrets", err)
		return
	}
	for _, v := range versions {
		if v.Version == current {
			continue
		}
		values, err := c.src.Secrets.Load(app, v.Version)
		if err != nil {
			unreadable("secrets", err)
			continue
		}
		c.addSecrets(values)
	}
}

func (c *collection) addSecrets(values map[string]string) {
	for _, name := range slices.Sorted(maps.Keys(values)) {
		c.redact.add(name, values[name], minSecretValue)
	}
}

func (c *collection) addEnv(env map[string]string) {
	for _, name := range slices.Sorted(maps.Keys(env)) {
		c.redact.add(name, env[name], minEnvValue)
	}
}

// lastChange is the app's newest deploy or rollback that started by the
// time the incident opened, with its steps.
func (c *collection) lastChange(ctx context.Context, app string) {
	var last *state.Operation
	for _, kind := range []string{apps.DeployKind, apps.RollbackKind} {
		ops, err := c.src.Store.ListFiltered(ctx, state.OperationFilter{Target: app, Kind: kind, Until: c.at, Limit: changeScan})
		if err != nil {
			c.fail("operations", err)
			return
		}
		for i := range ops {
			op := &ops[i]
			if op.StartedAt.IsZero() || op.StartedAt.After(c.at) {
				continue
			}
			if last == nil || op.StartedAt.After(last.StartedAt) || (op.StartedAt.Equal(last.StartedAt) && op.ID > last.ID) {
				last = op
			}
		}
	}
	if last == nil {
		return
	}
	change := changeOf(*last)
	receipt, err := kernel.ReceiptFromStore(ctx, c.src.Store, last.ID)
	if err != nil {
		c.fail("receipt", err)
	} else {
		for i, s := range receipt.Steps {
			if i == maxSteps {
				c.e.Truncated = append(c.e.Truncated, fmt.Sprintf("last_change: first %d of %d steps", maxSteps, len(receipt.Steps)))
				break
			}
			change.Steps = append(change.Steps, Step{Name: s.Name, Status: string(s.Status), TookMS: s.Duration.Milliseconds(), Note: s.Note, Error: s.Error})
		}
	}
	c.e.LastChange = &change
}

// recentDeploys are the deploys and rollbacks of any app that started in
// the hour before the incident, without their errors or steps, which
// would need every app's secrets to redact.
func (c *collection) recentDeploys(ctx context.Context) {
	since := c.at.Add(-recentWindow)
	var changes []Change
	for _, kind := range []string{apps.DeployKind, apps.RollbackKind} {
		ops, err := c.src.Store.ListFiltered(ctx, state.OperationFilter{Kind: kind, Since: since, Until: c.at, Limit: changeScan})
		if err != nil {
			c.fail("operations", err)
			return
		}
		for _, op := range ops {
			if op.StartedAt.IsZero() || op.StartedAt.Before(since) || op.StartedAt.After(c.at) {
				continue
			}
			change := changeOf(op)
			change.Error = ""
			changes = append(changes, change)
		}
	}
	slices.SortFunc(changes, func(a, b Change) int {
		if n := b.StartedAt.Compare(a.StartedAt); n != 0 {
			return n
		}
		return strings.Compare(b.Operation, a.Operation)
	})
	c.e.RecentDeploys = changes[:min(len(changes), maxRecent)]
}

// changeOf reads a deploy's or rollback's revision, commit and signer
// from what it was asked to do.
func changeOf(op state.Operation) Change {
	change := Change{
		Operation: op.ID, Kind: op.Kind, App: op.Target,
		StartedAt: op.StartedAt.UTC(), FinishedAt: op.FinishedAt.UTC(),
		Outcome: string(op.Status), Error: op.Error,
	}
	switch op.Kind {
	case apps.DeployKind:
		var in apps.DeployInput
		if json.Unmarshal(op.Input, &in) == nil {
			change.Revision, change.Commit, change.Signer = in.Revision, in.Commit, in.Signer
		}
	case apps.RollbackKind:
		var in apps.RollbackInput
		if json.Unmarshal(op.Input, &in) == nil {
			change.Revision = in.Revision
		}
	}
	return change
}

// logs reads what the app's containers wrote in the window: from the
// journal, which keeps removed containers and jobs, and from the engine
// for the active revision's containers the journal doesn't have, which
// Docker logged to its own files. The journal gives its newest lines
// across the app, so a noisy container can crowd out the others.
func (c *collection) logs(ctx context.Context, app string) {
	since, until := c.e.Window.Since, c.e.Window.Until
	var logs []Log
	seen := map[string]bool{}
	if c.src.Journal != nil {
		containers, err := c.src.Journal.Read(ctx, docker.JournalQuery{App: app, Since: since, Until: until, Lines: maxContainers * linesPerContainer})
		switch {
		case errors.Is(err, docker.ErrJournalLimit):
			c.e.Truncated = append(c.e.Truncated, "logs: the journal read stopped at 8 MiB")
		case err != nil:
			c.fail(sourceJournal, err)
		}
		for _, jc := range containers {
			name := jc.Name
			if name == "" {
				name = jc.ID[:min(len(jc.ID), 12)]
			}
			log := Log{Container: name, Workload: jc.Workload, Revision: jc.Revision, Source: sourceJournal}
			for _, l := range jc.Lines {
				// journalctl widens the query to whole seconds. Keep only
				// output in the incident's exact window.
				if l.At.Before(since) || l.At.After(until) {
					continue
				}
				log.Lines = append(log.Lines, Line{T: l.At.UTC(), Stream: l.Stream, Text: clean(l.Text)})
			}
			log.LinesTotal = len(log.Lines)
			if log.LinesTotal == 0 {
				continue
			}
			seen[name] = true
			log.Lines = log.Lines[max(0, len(log.Lines)-linesPerContainer):]
			log.LinesKept = len(log.Lines)
			logs = append(logs, log)
		}
		if err == nil || errors.Is(err, docker.ErrJournalLimit) {
			c.suppressed(ctx)
		}
	}
	logs = append(logs, c.engineLogs(ctx, seen)...)
	last := func(l Log) time.Time {
		if len(l.Lines) == 0 || l.Lines[len(l.Lines)-1].T.IsZero() {
			return until
		}
		return l.Lines[len(l.Lines)-1].T
	}
	slices.SortStableFunc(logs, func(a, b Log) int {
		if n := last(b).Compare(last(a)); n != 0 {
			return n
		}
		return strings.Compare(a.Container, b.Container)
	})
	if len(logs) > maxContainers {
		logs = logs[:maxContainers]
		c.e.Truncated = append(c.e.Truncated, fmt.Sprintf("logs: the %d containers that wrote last", maxContainers))
	}
	c.e.Logs = logs
}

// suppressed is when journald dropped Docker's output in the window.
func (c *collection) suppressed(ctx context.Context) {
	notes, err := c.src.Journal.Suppressed(ctx, c.e.Window.Since, c.e.Window.Until)
	if err != nil {
		c.fail(sourceJournal, err)
		return
	}
	for _, n := range notes {
		if n.At.Before(c.e.Window.Since) || n.At.After(c.e.Window.Until) {
			continue
		}
		c.e.JournalSuppressed = append(c.e.JournalSuppressed, Suppressed{At: n.At.UTC(), Count: n.Count})
	}
	c.e.JournalSuppressed = c.e.JournalSuppressed[max(0, len(c.e.JournalSuppressed)-maxSuppressed):]
}

// engineLogs reads the active revision's containers the journal didn't
// have. The engine gives no times, and its lines keep no stream: stdout
// and stderr are read apart only to tell a line's chunks from the other
// stream's lines.
func (c *collection) engineLogs(ctx context.Context, seen map[string]bool) []Log {
	if c.src.Engine == nil {
		return nil
	}
	var active *state.Revision
	for i := range c.revisions {
		if c.revisions[i].Status == state.RevisionActive {
			active = &c.revisions[i]
			break
		}
	}
	if active == nil {
		return nil
	}
	var logs []Log
	for _, workload := range slices.Sorted(maps.Keys(active.Containers)) {
		name := active.Containers[workload]
		if seen[name] {
			continue
		}
		out := newEngineOutput(docker.JournalReadLimit)
		opts := docker.LogOptions{Tail: strconv.Itoa(engineTail), Since: c.e.Window.Since, Until: c.e.Window.Until}
		err := c.src.Engine.LogStreams(ctx, name, opts, &out.stdout, &out.stderr)
		if docker.IsNotFound(err) {
			continue
		}
		if err != nil {
			c.fail(sourceEngine, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if out.cut {
			c.e.Truncated = append(c.e.Truncated, "logs: the engine read of "+c.redact.String(name)+" stopped at 8 MiB")
		}
		lines := out.wholeLines()
		if len(lines) == 0 {
			continue
		}
		log := Log{Container: name, Workload: workload, Revision: active.ID, Source: sourceEngine, LinesTotal: len(lines)}
		for _, l := range lines[max(0, len(lines)-linesPerContainer):] {
			log.Lines = append(log.Lines, Line{Text: clean(l)})
		}
		log.LinesKept = len(log.Lines)
		logs = append(logs, log)
	}
	return logs
}

// Docker logs a line longer than dockerChunk in chunks of that size, and
// the engine's tail counts chunks, not lines. engineTail asks for one
// more than is kept, so a first line the tail cut into can go.
const (
	dockerChunk = 16 << 10
	engineTail  = linesPerContainer + 1
)

// engineOutput splits a container's stdout and stderr into lines, in the
// order each ends, keeping the first max bytes of the two.
type engineOutput struct {
	stdout, stderr engineStream
	max, size      int
	// cut is whether there were more than max bytes.
	cut   bool
	lines []engineLine
}

// engineStream is one of the streams an engineOutput reads. Docker logs
// each in chunks of its own, so a line's chunks follow one another in
// it, but the other stream can write any number of lines between them.
type engineStream struct {
	out   *engineOutput
	other *engineStream
	// line is the line it is writing, up to its last chunk.
	line []byte
	// ended is whether it has ended a line, and broken whether the other
	// stream wrote between two chunks of this one.
	ended, broken bool
}

// engineLine is a line an engineStream wrote.
type engineLine struct {
	text string
	// first is its stream's first line, which can be the rest of one
	// whose first chunks the tail left behind.
	first bool
	// broken is whether the other stream wrote between its chunks, or the
	// read stopped inside it.
	broken bool
}

func newEngineOutput(max int) *engineOutput {
	o := &engineOutput{max: max}
	o.stdout = engineStream{out: o, other: &o.stderr}
	o.stderr = engineStream{out: o, other: &o.stdout}
	return o
}

func (s *engineStream) Write(p []byte) (int, error) {
	n, o := len(p), s.out
	room := max(o.max-o.size, 0)
	o.cut = o.cut || n > room
	p = p[:min(n, room)]
	o.size += len(p)
	if len(p) > 0 && len(s.other.line) > 0 {
		s.other.broken = true
	}
	for {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.line = append(s.line, p...)
			return n, nil
		}
		s.line = append(s.line, p[:i]...)
		o.lines = append(o.lines, s.current())
		s.line, s.ended, s.broken = s.line[:0], true, false
		p = p[i+1:]
	}
}

// current is the line s is writing as it stands.
func (s *engineStream) current() engineLine {
	return engineLine{text: string(s.line), first: !s.ended, broken: s.broken}
}

// wholeLines is the output's lines less those that could start or end
// partway through another, where a secret could be cut: the first of
// each stream, unless there are too few chunks for the tail to have cut
// anything, and one the read stopped inside. A line the other stream
// wrote between the chunks of is left out too, however many lines that
// was, rather than trusted to have been put back together whole.
func (o *engineOutput) wholeLines() []string {
	all := slices.Clone(o.lines)
	for _, s := range []*engineStream{&o.stdout, &o.stderr} {
		if len(s.line) > 0 {
			l := s.current()
			l.broken = l.broken || o.cut
			all = append(all, l)
		}
	}
	chunks := 0
	for _, l := range all {
		chunks += len(l.text)/dockerChunk + 1
	}
	var out []string
	for _, l := range all {
		if l.broken || l.first && chunks >= engineTail {
			continue
		}
		out = append(out, l.text)
	}
	return out
}

// history is the key's earlier incidents, newest first.
func (c *collection) history(ctx context.Context, key string) {
	c.e.History = &History{Incidents: []PriorIncident{}}
	prior, err := c.src.Store.IncidentsByKey(ctx, key, c.at, maxIncidents)
	if err != nil {
		c.fail("incidents", err)
		return
	}
	for _, p := range prior {
		c.e.History.Incidents = append(c.e.History.Incidents, PriorIncident{
			ID: p.ID, Severity: p.Severity, OpenedAt: p.OpenedAt.UTC(), ResolvedAt: timeOrNil(p.ResolvedAt),
			Observations: p.Observations, Message: p.Message,
		})
	}
}

// signals are the app's hourly rollups from the six hours up to the
// incident, newest first, without the latency buckets.
func (c *collection) signals(ctx context.Context, app string) {
	rows, err := c.src.Store.Signals(ctx, app, c.at.Add(-signalWindow))
	if err != nil {
		c.fail("signals", err)
		return
	}
	rows = slices.DeleteFunc(rows, func(r state.Signal) bool {
		return r.Hour.After(c.at) || strings.HasPrefix(r.Metric, state.SignalBucketPrefix)
	})
	slices.SortFunc(rows, func(a, b state.Signal) int {
		if n := b.Hour.Compare(a.Hour); n != 0 {
			return n
		}
		return cmp.Or(strings.Compare(a.Key, b.Key), strings.Compare(a.Metric, b.Metric))
	})
	for _, r := range rows[:min(len(rows), maxSignals)] {
		detail := strconv.FormatFloat(r.Value, 'f', -1, 64) + ", " + strconv.Itoa(r.Samples) + " samples"
		if r.Key != "" {
			detail = r.Key + ": " + detail
		}
		c.e.History.Signals = append(c.e.History.Signals, Signal{At: r.Hour.UTC(), Kind: r.Metric, Detail: detail})
	}
}

// upstream reads every status page at once.
func (c *collection) upstream(ctx context.Context) {
	if len(c.src.Upstream) == 0 {
		return
	}
	out := make([]Upstream, len(c.src.Upstream))
	var wg sync.WaitGroup
	for i, page := range c.src.Upstream {
		wg.Go(func() {
			indicator, description, err := page.Fetch(ctx)
			out[i] = Upstream{Name: page.Name, Indicator: indicator, Description: description, FetchedAt: c.src.Now().UTC()}
			if err != nil {
				out[i].Error = err.Error()
			}
		})
	}
	wg.Wait()
	c.e.Upstream = out
}

// finish redacts the evidence, caps its strings and fits it to FileMax.
// Should a secret value still be found, logs, step notes and messages go
// and it is fit again; should one survive that, there is no evidence.
// The note of what went, like what fitting adds, is helios's own words
// and names, so it is added once the evidence is known to be clean.
func (c *collection) finish() (*Evidence, error) {
	e := c.e
	c.redact.evidence(e)
	capStrings(e)
	if c.omit {
		omitLogs(e)
	}
	Fit(e, FileMax)
	if leaked := c.redact.leaks(e); len(leaked) > 0 {
		omitLogs(e)
		if len(c.redact.leaks(e)) > 0 {
			return nil, errors.New("a secret value survived redaction, so there is no evidence")
		}
		e.Errors = append(e.Errors, SourceError{Source: "redaction", Error: "a value of " + strings.Join(leaked, ", ") + " survived redaction, so logs, step notes and messages were left out"})
		Fit(e, FileMax)
	}
	return e, nil
}

// messageOmitted stands in for an incident's message omitLogs leaves out.
const messageOmitted = "[left out with the logs]"

// omitLogs leaves out what can carry an app's secrets unnoticed: logs,
// the notes and errors of the last change and its steps, and the
// messages of the incident and its key's earlier ones, which can end with
// a container's own output.
func omitLogs(e *Evidence) {
	e.Redaction.Status = RedactionLogsOmitted
	e.Logs = nil
	e.Incident.Message = messageOmitted
	if h := e.History; h != nil {
		for i := range h.Incidents {
			h.Incidents[i].Message = messageOmitted
		}
	}
	if lc := e.LastChange; lc != nil {
		lc.Error = ""
		for i := range lc.Steps {
			lc.Steps[i].Note, lc.Steps[i].Error = "", ""
		}
	}
}

// capStrings cuts each string to its cap once it is redacted, so a cut
// can't leave part of a secret behind.
func capStrings(e *Evidence) {
	e.Host = cut(e.Host, messageMax)
	e.Incident.Key, e.Incident.Subject, e.Incident.Message = cut(e.Incident.Key, messageMax), cut(e.Incident.Subject, messageMax), cut(e.Incident.Message, messageMax)
	if lc := e.LastChange; lc != nil {
		lc.Error = cut(lc.Error, noteMax)
		for i := range lc.Steps {
			lc.Steps[i].Note, lc.Steps[i].Error = cut(lc.Steps[i].Note, noteMax), cut(lc.Steps[i].Error, noteMax)
		}
	}
	for i := range e.Logs {
		for j := range e.Logs[i].Lines {
			e.Logs[i].Lines[j].Text = cut(e.Logs[i].Lines[j].Text, lineMax)
		}
	}
	if h := e.History; h != nil {
		for i := range h.Incidents {
			h.Incidents[i].Message = cut(h.Incidents[i].Message, messageMax)
		}
	}
	for i := range e.Upstream {
		u := &e.Upstream[i]
		u.Indicator, u.Description, u.Error = cut(u.Indicator, noteMax), cut(u.Description, noteMax), cut(u.Error, noteMax)
	}
	for i := range e.Errors {
		e.Errors[i].Error = cut(e.Errors[i].Error, noteMax)
	}
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}
