package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/incident"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/peer"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/ui"
	"github.com/kylebegeman/helios/internal/watch"
)

func newAlerts(a *app) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "What is wrong right now, and what was recently.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			all, err := store.IncidentHistory(ctx, limit)
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(all)
			}
			var open, past []state.Incident
			for _, inc := range all {
				if inc.Open() {
					open = append(open, inc)
				} else {
					past = append(past, inc)
				}
			}
			if len(open) == 0 {
				fmt.Fprintln(a.stdout, "nothing wrong right now")
			}
			// Who sent a peer notice is in peer watch's sidecar; without
			// one, every notice reads as this machine's own.
			sidecar, _ := peer.ReadSidecar(store)
			for _, inc := range open {
				fmt.Fprintf(a.stdout, "OPEN  #%d %s (%s) since %s: %s\n", inc.ID, inc.Subject, inc.Severity, inc.OpenedAt.Local().Format("2006-01-02 15:04"), inc.Message)
				// Some legs can have told you while another missed it.
				if by, at, ok := sidecar.SentBy(inc); ok {
					fmt.Fprintf(a.stdout, "      sent by %s at %s\n", by, at.Local().Format("15:04"))
				} else if !inc.NotifiedAt.IsZero() {
					fmt.Fprintf(a.stdout, "      told you at %s\n", inc.NotifiedAt.Local().Format("15:04"))
				}
				if to, since, ok := sidecar.WaitingOn(inc); ok {
					fmt.Fprintf(a.stdout, "      %s is to send this%s\n", to, waitingSince(since))
				} else if inc.NotifyError != "" {
					fmt.Fprintf(a.stdout, "      NOT DELIVERED: %s\n", inc.NotifyError)
				}
			}
			for _, inc := range past {
				fmt.Fprintf(a.stdout, "past  #%d %s: %s, from %s for %s\n", inc.ID, inc.Subject, inc.Message, inc.OpenedAt.Local().Format("2006-01-02 15:04"), inc.ResolvedAt.Sub(inc.OpenedAt).Round(time.Minute))
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "how many resolved incidents to list; every open incident is included")
	var leg string
	test := &cobra.Command{
		Use:   "test",
		Short: "Send a test alert through each way alerts go out, and say how each did.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			hostname, _ := os.Hostname()
			results, err := watch.SendTestAlerts(cmd.Context(), a.secretsStore(), store, hostname, leg, time.Now().UTC())
			if a.json && results != nil {
				if err := json.NewEncoder(a.stdout).Encode(results); err != nil {
					return err
				}
			}
			for _, r := range results {
				if a.json {
					break
				}
				switch {
				case r.Error != "":
					fmt.Fprintf(a.stdout, "%s: FAILED: %s\n", r.Leg, r.Error)
				case r.Held:
					fmt.Fprintf(a.stdout, "%s: the relay held it for Loom, which is offline, so it shows nothing; test again once Loom is back\n", r.Leg)
				case r.Probe:
					fmt.Fprintf(a.stdout, "%s: probe reached %s, which turned it away as it should\n", r.Leg, r.To)
				default:
					fmt.Fprintf(a.stdout, "%s: test alert sent to %s\n", r.Leg, r.To)
				}
			}
			if err != nil {
				return err
			}
			failed := 0
			for _, r := range results {
				if r.Error != "" {
					failed++
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d failed; fix it, then run helios alerts test again", failed, len(results))
			}
			return nil
		},
	}
	test.Flags().StringVar(&leg, "leg", "", "test only this one: email, email2, pushover, ntfy or loom_webhook, which opens a Loom thread")
	cmd.AddCommand(test, newAlertsShow(a), newAlertsReview(a))
	return cmd
}

// evidenceSources points src at this machine's Docker, journal and
// upstream status pages, and returns what releases them. Tests replace
// it.
var evidenceSources = incident.Local

func newAlertsShow(a *app) *cobra.Command {
	var withEvidence bool
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one incident and how its alerts went out, and with --evidence what was known about it.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			inc, err := findIncident(ctx, store, args[0])
			if err != nil {
				return err
			}
			var e *incident.Evidence
			if withEvidence {
				if e, err = a.incidentEvidence(ctx, store, *inc); err != nil {
					return err
				}
			}
			marker, markerErr := incident.LoomMarkerOf(a.stateDir, *inc)
			if a.json {
				if markerErr != nil {
					fmt.Fprintln(a.stderr, markerErr)
				}
				return json.NewEncoder(a.stdout).Encode(struct {
					Incident state.Incident       `json:"incident"`
					Loom     *incident.LoomMarker `json:"loom"`
					Evidence *incident.Evidence   `json:"evidence"`
				}{*inc, marker, e})
			}
			w := a.stdout
			field := func(label, value string) { fmt.Fprintf(w, "%-13s  %s\n", label, value) }
			fmt.Fprintf(w, "Incident %d: %s\n", inc.ID, inc.Subject)
			field("key", inc.Key)
			field("severity", inc.Severity)
			field("opened", utcTime(inc.OpenedAt))
			if inc.Open() {
				field("resolved", "still open")
			} else {
				field("resolved", fmt.Sprintf("%s, after %s", utcTime(inc.ResolvedAt), inc.ResolvedAt.Sub(inc.OpenedAt).Round(time.Second)))
			}
			if !inc.NotifiedAt.IsZero() {
				field("told you at", utcTime(inc.NotifiedAt))
			}
			if inc.NotifyError != "" {
				field("NOT DELIVERED", inc.NotifyError)
			}
			field("Loom", a.loomDelivery(*inc, marker, markerErr))
			if marker != nil && marker.Error != "" {
				field("Loom notes", marker.Error)
			}
			field("message", inc.Message)
			if e != nil {
				writeEvidence(w, e)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&withEvidence, "evidence", false, "also show the change before it, its logs, history and upstream status, collected now if they weren't then")
	return cmd
}

func newAlertsReview(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "review <id>",
		Short: "Print a blameless review of an incident, its timeline filled in, for you to finish.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			inc, err := findIncident(ctx, store, args[0])
			if err != nil {
				return err
			}
			r := incident.Review{Incident: *inc}
			r.Host, _ = os.Hostname()
			if r.Evidence, err = a.incidentEvidence(ctx, store, *inc); err != nil {
				fmt.Fprintf(a.stderr, "written without evidence: %v\n", err)
			}
			if r.Loom, err = incident.LoomMarkerOf(a.stateDir, *inc); err != nil {
				fmt.Fprintf(a.stderr, "written without its send to Loom: %v\n", err)
			}
			if r.Operations, err = incident.OperationsAround(ctx, store, *inc, time.Now().UTC()); err != nil {
				return err
			}
			return r.Write(a.stdout)
		},
	}
}

// findIncident reads the incident numbered arg.
func findIncident(ctx context.Context, store *state.Store, arg string) (*state.Incident, error) {
	id, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("incidents are numbered; helios alerts lists them")
	}
	inc, err := store.Incident(ctx, id)
	if errors.Is(err, state.ErrNotFound) {
		return nil, fmt.Errorf("no incident %d; helios alerts lists them", id)
	}
	return inc, err
}

// incidentEvidence reads inc's saved evidence. When none was saved, as
// for an incident that never went to Loom, it is collected now over the
// same window and saved for next time; the journal may no longer have
// the logs.
func (a *app) incidentEvidence(ctx context.Context, store *state.Store, inc state.Incident) (*incident.Evidence, error) {
	e, err := incident.Load(a.stateDir, inc)
	switch {
	case err == nil:
		return e, nil
	case !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, incident.ErrStale):
		return nil, err
	}
	src := incident.Sources{Store: store, Secrets: a.secretsStore(), CollectedBy: "cli", Late: true}
	src.Host, _ = os.Hostname()
	release := evidenceSources(&src)
	e, err = incident.Collect(ctx, inc, src)
	release()
	if err != nil {
		return nil, err
	}
	if err := incident.Save(a.stateDir, e); err != nil {
		fmt.Fprintf(a.stderr, "the evidence can't be saved: %v\n", err)
	}
	if strings.HasPrefix(inc.Key, "app:") && e.Redaction.Status == incident.RedactionApplied && !slices.ContainsFunc(e.Logs, func(l incident.Log) bool { return len(l.Lines) > 0 }) {
		fmt.Fprintln(a.stderr, "collected now; logs older than the journal's retention are gone")
	}
	return e, nil
}

// loomDelivery says how inc's send to Loom went, or why there was none.
func (a *app) loomDelivery(inc state.Incident, m *incident.LoomMarker, err error) string {
	switch {
	case err != nil:
		return "can't tell: " + err.Error()
	case m != nil && m.DeliveryID != "":
		return m.Outcome() + ", delivery " + m.DeliveryID
	case m != nil:
		return m.Outcome()
	}
	if _, err := integration.LoadLoomWebhook(a.secretsStore()); errors.Is(err, integration.ErrNotSet) {
		return "not configured"
	}
	if inc.Severity != state.SeverityCritical {
		return "not sent; only a critical incident opens a Loom thread"
	}
	return "not sent"
}

func utcTime(t time.Time) string { return t.UTC().Format(time.DateTime) + " UTC" }

// writeEvidence prints what was known about an incident, section by
// section, leaving out those it has nothing for.
func writeEvidence(w io.Writer, e *incident.Evidence) {
	by := e.CollectedBy
	if e.Late {
		by += ", late"
	}
	fmt.Fprintf(w, "\nEvidence collected %s by %s; redaction %s\n", utcTime(e.CollectedAt), by, strings.ReplaceAll(e.Redaction.Status, "_", " "))
	fmt.Fprintf(w, "logs read from %s to %s\n", utcTime(e.Window.Since), utcTime(e.Window.Until))
	change := func(c incident.Change) string {
		s := c.Kind + " of " + c.App + ", " + c.Outcome
		for _, part := range [][2]string{{"revision", c.Revision}, {"commit", c.Commit}, {"signed by", c.Signer}} {
			if part[1] != "" {
				s += ", " + part[0] + " " + part[1]
			}
		}
		return s + " (" + c.Operation + ")"
	}
	if c := e.LastChange; c != nil {
		fmt.Fprintf(w, "\nLast change: %s\n", change(*c))
		fmt.Fprintf(w, "  started %s", utcTime(c.StartedAt))
		if !c.FinishedAt.IsZero() {
			fmt.Fprintf(w, ", finished %s", utcTime(c.FinishedAt))
		}
		fmt.Fprintln(w)
		if c.Error != "" {
			fmt.Fprintf(w, "  %s\n", c.Error)
		}
		for _, st := range c.Steps {
			word := map[string]string{string(state.StepPending): "-", string(state.StepRunning): "...", string(state.StepSucceeded): "ok", string(state.StepFailed): "fail", string(state.StepUndone): "undid"}[st.Status]
			line := fmt.Sprintf("  %-4s %s (%s)", word, st.Name, ui.Duration(time.Duration(st.TookMS)*time.Millisecond))
			if st.Note != "" {
				line += " " + st.Note
			}
			if st.Error != "" {
				line += ": " + st.Error
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(e.RecentDeploys) > 0 {
		fmt.Fprintln(w, "\nDeploys in the hour before:")
		for _, c := range e.RecentDeploys {
			fmt.Fprintf(w, "  %s  %s\n", utcTime(c.StartedAt), change(c))
		}
	}
	if len(e.Logs) > 0 {
		fmt.Fprintln(w, "\nLogs:")
		for _, l := range e.Logs {
			var about []string
			if l.Workload != "" {
				about = append(about, l.Workload)
			}
			if l.Revision != "" {
				about = append(about, "revision "+l.Revision)
			}
			about = append(about, "from the "+l.Source)
			fmt.Fprintf(w, "  %s (%s): %d of %d lines\n", l.Container, strings.Join(about, ", "), l.LinesKept, l.LinesTotal)
			for _, line := range l.Lines {
				prefix := ""
				if !line.T.IsZero() {
					prefix = line.T.UTC().Format(time.DateTime) + " "
				}
				if line.Stream != "" {
					prefix += line.Stream + " "
				}
				fmt.Fprintf(w, "    %s%s\n", prefix, line.Text)
			}
		}
	}
	if len(e.JournalSuppressed) > 0 {
		fmt.Fprintln(w, "\nLines the journal dropped:")
		for _, s := range e.JournalSuppressed {
			fmt.Fprintf(w, "  %s  %d\n", utcTime(s.At), s.Count)
		}
	}
	if h := e.History; h != nil && len(h.Incidents) > 0 {
		fmt.Fprintln(w, "\nEarlier incidents:")
		for _, p := range h.Incidents {
			lasted := "still open"
			if p.ResolvedAt != nil {
				lasted = "lasted " + p.ResolvedAt.Sub(p.OpenedAt).Round(time.Second).String()
			}
			fmt.Fprintf(w, "  #%d %s, opened %s, %s, %d rounds: %s\n", p.ID, p.Severity, utcTime(p.OpenedAt), lasted, p.Observations, p.Message)
		}
	}
	if h := e.History; h != nil && len(h.Signals) > 0 {
		fmt.Fprintln(w, "\nSignals:")
		for _, s := range h.Signals {
			fmt.Fprintf(w, "  %s  %s  %s\n", utcTime(s.At), s.Kind, s.Detail)
		}
	}
	if len(e.Upstream) > 0 {
		fmt.Fprintln(w, "\nUpstream:")
		for _, u := range e.Upstream {
			if u.Error != "" {
				fmt.Fprintf(w, "  %s: FAILED: %s\n", u.Name, u.Error)
			} else {
				fmt.Fprintf(w, "  %s: %s, %s\n", u.Name, u.Indicator, u.Description)
			}
		}
	}
	for _, list := range []struct {
		title string
		items []string
	}{{"Left out to fit", e.Truncated}, {"Couldn't read", sourceErrors(e.Errors)}} {
		if len(list.items) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s:\n", list.title)
		for _, item := range list.items {
			fmt.Fprintf(w, "  %s\n", item)
		}
	}
}

func sourceErrors(errs []incident.SourceError) []string {
	var out []string
	for _, e := range errs {
		out = append(out, e.Source+": "+e.Error)
	}
	return out
}

func newWatch(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Public URLs this machine checks from the outside, such as the other machine's sites.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			ws, err := store.Watches(cmd.Context())
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(ws)
			}
			if len(ws) == 0 {
				fmt.Fprintln(a.stdout, "watching nothing; add a URL with helios watch add https://...")
			}
			for _, w := range ws {
				fmt.Fprintf(a.stdout, "%s (since %s)\n", w.URL, w.AddedAt.Local().Format("2006-01-02"))
			}
			return nil
		},
	}
	add := &cobra.Command{
		Use:   "add <url>",
		Short: "Check a URL every minute and alert when it stops answering 200.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			url := args[0]
			if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
				return errors.New("the URL must start with https:// or http://")
			}
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.AddWatch(cmd.Context(), url, time.Now().UTC()); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "watching %s\n", url)
			return nil
		},
	}
	remove := &cobra.Command{
		Use:   "remove <url>",
		Short: "Stop checking a URL.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.RemoveWatch(cmd.Context(), args[0]); errors.Is(err, state.ErrNotFound) {
				return fmt.Errorf("%s wasn't being watched", args[0])
			} else if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "no longer watching %s\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(add, remove)
	return cmd
}

// waitingSince says since when this machine has held a notice for the
// observer that is to send it, where peer watch's sidecar says.
func waitingSince(since time.Time) string {
	if since.IsZero() {
		return ""
	}
	return " (waiting since " + since.Local().Format("15:04") + ")"
}
