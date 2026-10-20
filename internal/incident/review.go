package incident

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/state"
)

// reviewSource is the blameless review an incident gets. Rendered blank,
// it is docs/operations/incident-review.md.
//
//go:embed review.md.tmpl
var reviewSource string

var reviewTemplate = template.Must(template.New("review").Parse(reviewSource))

// Caps on a review's timeline.
const (
	// reviewPrior are the key's earlier incidents it lists, newest kept.
	reviewPrior = 3
	// reviewOperations are the operations it lists from the window
	// before the incident, and again from while it was open, latest kept.
	reviewOperations = 10
	// reviewMessageMax caps an earlier incident's message in it.
	reviewMessageMax = 200
	// commitShown is how much of a commit it shows.
	commitShown = 12
)

// Review is what an incident's blameless review is written from.
type Review struct {
	Incident state.Incident
	// Host is the machine's name, for when there is no evidence to say.
	Host string
	// Evidence is the incident's, or nil when there is none. Its key,
	// subject and message are redacted, so they are used when it is there.
	Evidence *Evidence
	// Loom is the incident's send to Loom, or nil when there was none.
	Loom *LoomMarker
	// Operations are those around the incident, as OperationsAround reads
	// them.
	Operations []state.Operation
}

// Event is one line of a review's timeline.
type Event struct {
	At   time.Time
	What string
}

// OperationsAround reads the operations created in the window before inc
// opened and those created while it was open, up to now for one still
// open: up to reviewOperations of each, the latest kept.
func OperationsAround(ctx context.Context, store *state.Store, inc state.Incident, now time.Time) ([]state.Operation, error) {
	end := inc.ResolvedAt
	if end.IsZero() {
		end = now
	}
	before, err := store.ListFiltered(ctx, state.OperationFilter{Since: inc.OpenedAt.Add(-window), Until: inc.OpenedAt, Limit: reviewOperations})
	if err != nil {
		return nil, err
	}
	during, err := store.ListFiltered(ctx, state.OperationFilter{Since: inc.OpenedAt, Until: end, Limit: reviewOperations})
	if err != nil {
		return nil, err
	}
	return append(during, before...), nil
}

// Timeline is what happened around the incident, oldest first, in UTC:
// the key's latest earlier incidents, the change before it, the
// operations around it, its opening, the last alert about it, its send to
// Loom and its resolution. An operation is listed once however many
// sources hold it, as the store has it now when it still does: the
// evidence may have caught it before it finished. Step notes, errors and
// log lines are left out.
func (r *Review) Timeline() []Event {
	var events []Event
	add := func(at time.Time, what string) {
		if !at.IsZero() {
			events = append(events, Event{At: at.UTC(), What: what})
		}
	}
	listed := map[string]bool{}
	change := func(c Change) {
		if listed[c.Operation] {
			return
		}
		listed[c.Operation] = true
		var about []string
		if c.Revision != "" {
			about = append(about, "revision "+c.Revision)
		}
		if c.Commit != "" {
			about = append(about, "commit "+c.Commit[:min(len(c.Commit), commitShown)])
		}
		if c.Signer != "" {
			about = append(about, "signed by "+c.Signer)
		}
		started := operationName(c.Kind, c.App) + " started"
		if len(about) > 0 {
			started += ": " + strings.Join(about, ", ")
		}
		add(c.StartedAt, started+" ("+c.Operation+")")
		add(c.FinishedAt, fmt.Sprintf("%s finished: %s (%s)", operationName(c.Kind, c.App), c.Outcome, c.Operation))
	}
	for _, op := range r.Operations {
		if op.Kind == apps.DeployKind || op.Kind == apps.RollbackKind {
			change(changeOf(op))
			continue
		}
		// One created as the incident opened is read from both sides of it.
		if listed[op.ID] {
			continue
		}
		listed[op.ID] = true
		add(op.StartedAt, fmt.Sprintf("%s started (%s)", operationName(op.Kind, op.Target), op.ID))
		add(op.FinishedAt, fmt.Sprintf("%s finished: %s (%s)", operationName(op.Kind, op.Target), op.Status, op.ID))
	}
	inc := r.Incident
	subject := inc.Subject
	if e := r.Evidence; e != nil {
		subject = e.Incident.Subject
		if e.LastChange != nil {
			change(*e.LastChange)
		}
		for _, c := range e.RecentDeploys {
			change(c)
		}
		if e.History != nil {
			for _, p := range e.History.Incidents[:min(len(e.History.Incidents), reviewPrior)] {
				what := fmt.Sprintf("earlier incident %d, %s", p.ID, p.Severity)
				if p.ResolvedAt != nil {
					what += ", lasted " + p.ResolvedAt.Sub(p.OpenedAt).Round(time.Second).String()
				}
				add(p.OpenedAt, what+": "+cut(p.Message, reviewMessageMax))
			}
		}
	}
	// Added in the order they happen, which the sort keeps for those at
	// the same time: the alert about a resolution goes out as it's seen.
	add(inc.OpenedAt, fmt.Sprintf("incident %d opened: %s went %s", inc.ID, subject, inc.Severity))
	if !inc.ResolvedAt.IsZero() {
		add(inc.ResolvedAt, fmt.Sprintf("incident %d resolved after %s", inc.ID, inc.ResolvedAt.Sub(inc.OpenedAt).Round(time.Second)))
	}
	add(inc.NotifiedAt, "the last alert about it went out")
	if r.Loom != nil {
		add(r.Loom.At, "Loom delivery: "+r.Loom.Outcome())
	}
	slices.SortStableFunc(events, func(a, b Event) int { return a.At.Compare(b.At) })
	return events
}

// operationName is how a timeline names an operation, such as
// "app.deploy of api".
func operationName(kind, target string) string {
	if target == "" {
		return kind
	}
	return kind + " of " + target
}

// reviewPage is what the template fills in.
type reviewPage struct {
	// Blank is set for the skeleton, which has a placeholder in each
	// part an incident fills in.
	Blank                                                       bool
	ID, Subject, Key, Severity, Host, Opened, Resolved, Message string
	Timeline                                                    []reviewRow
}

type reviewRow struct{ At, What string }

// Write prints r's review in Markdown.
func (r *Review) Write(w io.Writer) error {
	inc := r.Incident
	p := reviewPage{
		ID: strconv.FormatInt(inc.ID, 10), Subject: inc.Subject, Key: inc.Key, Severity: inc.Severity,
		Host: r.Host, Opened: reviewTime(inc.OpenedAt), Message: inc.Message,
	}
	if e := r.Evidence; e != nil {
		p.Subject, p.Key, p.Message = e.Incident.Subject, e.Incident.Key, e.Incident.Message
		if e.Host != "" {
			p.Host = e.Host
		}
	}
	if !inc.ResolvedAt.IsZero() {
		p.Resolved = reviewTime(inc.ResolvedAt)
	}
	p.Subject, p.Key, p.Severity, p.Host, p.Message = oneLine(p.Subject), oneLine(p.Key), oneLine(p.Severity), oneLine(p.Host), oneLine(p.Message)
	for _, e := range r.Timeline() {
		p.Timeline = append(p.Timeline, reviewRow{At: e.At.Format(time.DateTime), What: cell(e.What)})
	}
	return reviewTemplate.Execute(w, p)
}

// WriteBlankReview prints the review's skeleton.
func WriteBlankReview(w io.Writer) error {
	return reviewTemplate.Execute(w, reviewPage{
		Blank: true, ID: "[id]", Subject: "[subject]", Key: "[key]", Severity: "[severity]", Host: "[host]",
		Opened: "[time]", Resolved: "[time]", Message: "[what the watcher saw]",
		Timeline: []reviewRow{{At: "[time]", What: "[event]"}},
	})
}

func reviewTime(t time.Time) string { return t.UTC().Format(time.DateTime) + " UTC" }

// oneLine keeps s to one line, so it can't break the Markdown around it.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// cell keeps s to one table cell.
func cell(s string) string { return strings.ReplaceAll(oneLine(s), "|", `\|`) }
