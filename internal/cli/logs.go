package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/state"
)

// pastLogs reads a revision's or a job run's output: from the Engine while
// its container is there, and from the journal once it is gone.
type pastLogs struct {
	a                 *app
	appName, workload string
	revision, job     string
	follow            bool
	tail              string
	// journalLines is tail as journalctl's --lines.
	journalLines int
	engine       *docker.Engine
	store        *state.Store
	journal      docker.Journal
}

func (a *app) pastLogs(ctx context.Context, p pastLogs) error {
	lines, err := journalLines(p.tail)
	if err != nil {
		return err
	}
	p.a, p.journalLines = a, lines
	store, err := a.openState()
	if err != nil {
		return err
	}
	defer store.Close()
	p.store = store
	if p.job != "" {
		return p.ofJob(ctx)
	}
	engine, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer engine.Close()
	p.engine = engine
	return p.ofRevision(ctx)
}

// journalLines maps --tail onto journalctl's --lines, where 0 is all, so
// no lines at all can't be asked of what is past.
func journalLines(tail string) (int, error) {
	if tail == "all" {
		return 0, nil
	}
	n, err := strconv.Atoi(tail)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("--tail takes a number of lines or all, not %q", tail)
	}
	return n, nil
}

func (p pastLogs) ofRevision(ctx context.Context) error {
	rev, err := p.store.GetRevision(ctx, p.appName, p.revision)
	if errors.Is(err, state.ErrNotFound) {
		return p.ofForgottenRevision(ctx)
	}
	if err != nil {
		return err
	}
	workloads := make([]string, 0, len(rev.Containers))
	for w := range rev.Containers {
		if p.workload == "" || w == p.workload {
			workloads = append(workloads, w)
		}
	}
	slices.Sort(workloads)
	if len(workloads) == 0 && p.workload != "" {
		return fmt.Errorf("revision %s of %s runs no workload named %s; a job's output is under --job", p.revision, p.appName, p.workload)
	}
	if len(workloads) == 0 {
		return fmt.Errorf("revision %s of %s runs no workloads; a job's output is under --job", p.revision, p.appName)
	}
	if p.follow && len(workloads) > 1 {
		return fmt.Errorf("--follow follows one workload; name one of %v", workloads)
	}
	for _, w := range workloads {
		prefix := ""
		if len(workloads) > 1 {
			prefix = w + " | "
		}
		if err := p.ofContainer(ctx, rev.Containers[w], prefix); err != nil {
			return err
		}
	}
	return nil
}

// ofForgottenRevision reads a revision gc has dropped from the state: its
// containers' names went with it, but their labels are in the journal.
func (p pastLogs) ofForgottenRevision(ctx context.Context) error {
	fmt.Fprintln(p.a.stderr, "revision no longer recorded; showing every container labelled with it, jobs included")
	q := docker.JournalQuery{App: p.appName, Workload: p.workload, Revision: p.revision, Lines: p.journalLines}
	var prefix func(docker.JournalLine) string
	if p.workload == "" {
		prefix = func(l docker.JournalLine) string { return l.Workload + " | " }
	}
	n, err := p.fromJournal(ctx, q, prefix)
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Fprintf(p.a.stderr, "journal has nothing for revision %s of %s\n", p.revision, p.appName)
	}
	return nil
}

// ofContainer prints one container's output, putting prefix before each
// line. A removed container writes nothing more, so only a live one is
// followed.
func (p pastLogs) ofContainer(ctx context.Context, name, prefix string) error {
	live, err := p.exists(ctx, name)
	if err != nil {
		return err
	}
	if live {
		w := &prefixLines{w: p.a.stdout, prefix: prefix}
		err := p.engine.Logs(ctx, name, docker.LogOptions{Follow: p.follow, Tail: p.tail}, w)
		w.end()
		return err
	}
	n, err := p.fromJournal(ctx, docker.JournalQuery{Names: []string{name}, Lines: p.journalLines}, func(docker.JournalLine) string { return prefix })
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Fprintf(p.a.stderr, "journal has nothing for %s; a container removed before helios logged to the journal took its output with it\n", name)
	}
	return nil
}

func (p pastLogs) ofJob(ctx context.Context) error {
	id, err := strconv.ParseInt(p.job, 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("job runs are numbered; helios jobs %s lists them", p.appName)
	}
	run, err := p.store.JobRun(ctx, id)
	if errors.Is(err, state.ErrNotFound) {
		return fmt.Errorf("no job run %d; helios jobs %s lists them", id, p.appName)
	}
	if err != nil {
		return err
	}
	if run.App != p.appName {
		return fmt.Errorf("job %d is not one of %s's", id, p.appName)
	}
	if p.workload != "" && run.Workload != p.workload {
		return fmt.Errorf("job %d ran %s, not %s", id, run.Workload, p.workload)
	}
	if run.Kind == state.JobHold {
		return fmt.Errorf("job %d is a hold on %s, not a run; it has no output", id, run.Workload)
	}
	note := "journal has nothing for this job; showing the last 40 lines kept with the run"
	if run.Container != "" {
		if p.engine == nil {
			engine, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer engine.Close()
			p.engine = engine
		}
		live, err := p.exists(ctx, run.Container)
		if err != nil {
			return err
		}
		if live {
			return p.engine.Logs(ctx, run.Container, docker.LogOptions{Follow: p.follow, Tail: p.tail}, p.a.stdout)
		}
		n, err := p.fromJournal(ctx, docker.JournalQuery{Names: []string{run.Container}, Lines: p.journalLines}, nil)
		if err != nil {
			note = err.Error() + "; showing the last 40 lines kept with the run"
		} else if n > 0 {
			return nil
		}
	}
	fmt.Fprintln(p.a.stderr, note)
	_, err = io.WriteString(p.a.stdout, run.Output)
	return err
}

func (p pastLogs) exists(ctx context.Context, name string) (bool, error) {
	_, err := p.engine.Inspect(ctx, name)
	if docker.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// fromJournal prints the query's lines, each after its prefix when there
// is one, and counts them.
func (p pastLogs) fromJournal(ctx context.Context, q docker.JournalQuery, prefix func(docker.JournalLine) string) (int, error) {
	n := 0
	err := p.journal.Stream(ctx, q, func(l docker.JournalLine) error {
		n++
		text := l.Text
		if prefix != nil {
			text = prefix(l) + text
		}
		_, err := fmt.Fprintln(p.a.stdout, text)
		return err
	})
	return n, err
}

// prefixLines puts prefix before every line written through it.
type prefixLines struct {
	w      io.Writer
	prefix string
	// inLine is set while a line has started but not ended.
	inLine bool
}

func (p *prefixLines) Write(b []byte) (int, error) {
	if p.prefix == "" {
		return p.w.Write(b)
	}
	n := len(b)
	for len(b) > 0 {
		if !p.inLine {
			if _, err := io.WriteString(p.w, p.prefix); err != nil {
				return 0, err
			}
		}
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			p.inLine = true
			_, err := p.w.Write(b)
			return n, err
		}
		if _, err := p.w.Write(b[:i+1]); err != nil {
			return 0, err
		}
		p.inLine = false
		b = b[i+1:]
	}
	return n, nil
}

// end finishes a line left open, so the next container starts its own.
func (p *prefixLines) end() {
	if p.inLine {
		io.WriteString(p.w, "\n")
		p.inLine = false
	}
}
