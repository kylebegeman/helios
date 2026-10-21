package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// JournalReadLimit caps how much of journalctl's output one Read takes
// in, so a noisy container can't fill memory.
const JournalReadLimit = 8 << 20

// ErrJournalLimit means a Read stopped at JournalReadLimit; what it read
// before then is still returned.
var ErrJournalLimit = errors.New("journal read stopped at 8 MiB")

// JournalQuery picks container output out of the system journal: lines
// from any of Names that carry every label given, between Since and
// Until. Zero values leave that part open.
type JournalQuery struct {
	Names                   []string
	App, Workload, Revision string
	Since, Until            time.Time
	// Lines keeps only the newest n lines; 0 keeps them all.
	Lines  int
	Follow bool
}

// journalFields are what a read asks journalctl to print. It prints
// __REALTIME_TIMESTAMP whatever is asked.
var journalFields = []string{
	"MESSAGE", "PRIORITY", "CONTAINER_NAME", "CONTAINER_ID_FULL",
	"CONTAINER_PARTIAL_MESSAGE", "CONTAINER_PARTIAL_ID", "CONTAINER_PARTIAL_ORDINAL", "CONTAINER_PARTIAL_LAST",
	"BEDROCK_APP", "BEDROCK_WORKLOAD", "BEDROCK_REVISION", "SYSLOG_IDENTIFIER",
}

// Args are journalctl's arguments for the query. Matches on the same
// field are alternatives and matches on different fields all have to
// hold.
func (q JournalQuery) Args() []string {
	args := []string{"--no-pager", "--all", "--output=json", "--output-fields=" + strings.Join(journalFields, ",")}
	args = append(args, journalWindow(q.Since, q.Until)...)
	if q.Lines > 0 {
		args = append(args, "--lines="+strconv.Itoa(q.Lines))
	}
	if q.Follow {
		args = append(args, "--follow")
	}
	for _, name := range q.Names {
		args = append(args, "CONTAINER_NAME="+name)
	}
	for _, m := range [][2]string{{"BEDROCK_APP", q.App}, {"BEDROCK_WORKLOAD", q.Workload}, {"BEDROCK_REVISION", q.Revision}} {
		if m[1] != "" {
			args = append(args, m[0]+"="+m[1])
		}
	}
	return args
}

// journalWindow bounds a read in whole seconds, which is what journalctl
// takes, widened so no line inside the window is lost.
func journalWindow(since, until time.Time) []string {
	var args []string
	if !since.IsZero() {
		args = append(args, "--since=@"+strconv.FormatInt(since.Unix(), 10))
	}
	if !until.IsZero() {
		end := until.Unix()
		if until.Nanosecond() > 0 {
			end++
		}
		args = append(args, "--until=@"+strconv.FormatInt(end, 10))
	}
	return args
}

// JournalLine is one line a container wrote, put back together when
// Docker split it into chunks.
type JournalLine struct {
	At time.Time
	// Stream is stdout or stderr.
	Stream string
	Text   string
	// Container is the container's full ID; Name is its name when it
	// started.
	Container, Name         string
	App, Workload, Revision string
}

// JournalContainer is one container's lines in the journal's order.
type JournalContainer struct {
	ID, Name                string
	App, Workload, Revision string
	Lines                   []JournalLine
}

// JournalSuppressed is journald's own note that it dropped Count of
// Docker's messages under its rate limit.
type JournalSuppressed struct {
	At    time.Time
	Count int
}

// journalExec starts journalctl with args and returns its output and a
// func that waits for it to exit.
type journalExec func(ctx context.Context, args []string) (io.ReadCloser, func() error, error)

// Journal reads what containers wrote to the system journal. Its zero
// value runs journalctl.
type Journal struct {
	exec journalExec
}

func (j Journal) start(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
	if j.exec != nil {
		return j.exec(ctx, args)
	}
	return journalctl(ctx, args)
}

// Stream calls each with every line the query picks, in the journal's
// order, until the output ends, each fails or, when following, ctx ends.
// Nothing caps the total, so it is for a person watching. Like docker
// logs, it gives a line whose first chunks it didn't read as it is.
func (j Journal) Stream(ctx context.Context, q JournalQuery, each func(JournalLine) error) error {
	_, err := j.read(ctx, q, 0, true, each)
	return err
}

// Read takes in at most JournalReadLimit of the query's lines and groups
// them by container, in the order their first lines come. Past the limit
// it returns what it read with ErrJournalLimit. It leaves out a line
// whose first chunks it didn't read, which could start partway through a
// secret.
func (j Journal) Read(ctx context.Context, q JournalQuery) ([]JournalContainer, error) {
	q.Follow = false
	var out []JournalContainer
	index := map[string]int{}
	limited, err := j.read(ctx, q, JournalReadLimit, false, func(l JournalLine) error {
		i, ok := index[l.Container]
		if !ok {
			i = len(out)
			index[l.Container] = i
			out = append(out, JournalContainer{ID: l.Container, Name: l.Name, App: l.App, Workload: l.Workload, Revision: l.Revision})
		}
		out[i].Lines = append(out[i].Lines, l)
		return nil
	})
	if err == nil && limited {
		err = ErrJournalLimit
	}
	return out, err
}

// suppressedMessage is journald's note when its rate limit drops a
// unit's messages; the unit is a name or a cgroup path.
var suppressedMessage = regexp.MustCompile(`^Suppressed (\d+) messages from (\S+)$`)

// Suppressed lists the times journald dropped Docker's messages between
// since and until, which is where container output goes missing.
func (j Journal) Suppressed(ctx context.Context, since, until time.Time) ([]JournalSuppressed, error) {
	args := append([]string{"--no-pager", "--all", "--output=json", "--output-fields=MESSAGE"}, journalWindow(since, until)...)
	args = append(args, "_SYSTEMD_UNIT=systemd-journald.service")
	var out []JournalSuppressed
	_, err := j.run(ctx, args, JournalReadLimit, func(e journalEntry) error {
		m := suppressedMessage.FindStringSubmatch(e.field("MESSAGE"))
		if m == nil || !strings.HasSuffix(m[2], "docker.service") {
			return nil
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return nil
		}
		out = append(out, JournalSuppressed{At: e.at(), Count: n})
		return nil
	})
	return out, err
}

// read runs the query and hands each a whole line: Docker numbers the
// chunks of a long line and marks every one but the last as partial, and
// the chunks join with nothing between them. Older Docker numbers none,
// so its chunks join in the order they come. A line still waiting for
// its last chunk when the output ends, when another line starts or when
// it grows past JournalReadLimit is handed over as it is. A line whose
// first chunks didn't come, because the window or --lines cut them off
// or journald dropped them, is handed over only when headless is set.
func (j Journal) read(ctx context.Context, q JournalQuery, limit int64, headless bool, each func(JournalLine) error) (bool, error) {
	if len(q.Names) == 0 && q.App == "" && q.Revision == "" {
		return false, errors.New("a journal query needs a container name, an app or a revision")
	}
	type key struct{ container, stream string }
	// chunked is a line put together so far: id and next are the
	// partial ID and the ordinal its next chunk carries, both zero when
	// Docker numbers none.
	type chunked struct {
		line     JournalLine
		id       string
		next     int
		headless bool
	}
	pending := map[key]*chunked{}
	var waiting []key
	hand := func(c *chunked) error {
		if c.headless && !headless {
			return nil
		}
		return each(c.line)
	}
	done := func(k key) error {
		c := pending[k]
		delete(pending, k)
		waiting = slices.DeleteFunc(waiting, func(w key) bool { return w == k })
		return hand(c)
	}
	limited, err := j.run(ctx, q.Args(), limit, func(e journalEntry) error {
		l := e.line()
		k := key{l.Container, l.Stream}
		partial := e.field("CONTAINER_PARTIAL_MESSAGE") == "true"
		id := e.field("CONTAINER_PARTIAL_ID")
		ordinal, _ := strconv.Atoi(e.field("CONTAINER_PARTIAL_ORDINAL"))
		next := 0
		if ordinal > 0 {
			next = ordinal + 1
		}
		p := pending[k]
		if p != nil && (p.id != id || p.next != ordinal) {
			if err := done(k); err != nil {
				return err
			}
			p = nil
		}
		if p == nil {
			c := &chunked{line: l, id: id, next: next, headless: ordinal > 1}
			if !partial {
				return hand(c)
			}
			pending[k] = c
			waiting = append(waiting, k)
			return nil
		}
		p.line.Text += l.Text
		p.next = next
		if partial && len(p.line.Text) < JournalReadLimit {
			return nil
		}
		return done(k)
	})
	if err != nil {
		return limited, err
	}
	for _, k := range waiting {
		if err := hand(pending[k]); err != nil {
			return limited, err
		}
	}
	return limited, nil
}

// run starts journalctl and hands each entry it prints to each, reading
// at most limit bytes when limit is above 0, and reports whether it
// stopped there. Lines that aren't JSON, such as "-- No entries --", are
// skipped, as is one cut short by the limit. When journalctl prints no
// entry, run asks it whether it was kept from the system journal.
func (j Journal) run(ctx context.Context, args []string, limit int64, each func(journalEntry) error) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out, wait, err := j.start(ctx, args)
	if err != nil {
		return false, err
	}
	defer out.Close()
	var src io.Reader = out
	var lr *io.LimitedReader
	if limit > 0 {
		lr = &io.LimitedReader{R: out, N: limit + 1}
		src = lr
	}
	r := bufio.NewReader(src)
	var eachErr error
	printed := false
	for {
		b, readErr := r.ReadBytes('\n')
		cut := readErr != nil && lr != nil && lr.N == 0
		if e, ok := parseJournalEntry(b); ok && !cut {
			printed = true
			if eachErr = each(e); eachErr != nil {
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	limited := lr != nil && lr.N == 0
	if limited || eachErr != nil {
		// Stop journalctl rather than read the rest of what it has.
		cancel()
		wait()
		return limited, eachErr
	}
	err = wait()
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.Canceled) {
			return false, nil
		}
		return false, ctxErr
	}
	if err == nil && !printed && j.denied(ctx) {
		return false, errJournalPermission
	}
	return false, err
}

// denied reports whether journalctl says it can't read the system
// journal. Printing JSON makes it as quiet as --quiet: able to open
// the user's own journal but not the system's, it prints nothing and
// exits 0. Asked for no lines of its plain output, it gives its hint.
func (j Journal) denied(ctx context.Context) bool {
	out, wait, err := j.start(ctx, []string{"--no-pager", "--output=short", "--lines=0"})
	if err != nil {
		return false
	}
	defer out.Close()
	_, _ = io.Copy(io.Discard, out)
	return errors.Is(wait(), errJournalPermission)
}

// journalEntry is one record as journalctl prints it in JSON: each value
// is a string, an array of bytes when it isn't text, null when journalctl
// left it out, or an array of those when the field was set more than once.
type journalEntry map[string]json.RawMessage

func parseJournalEntry(b []byte) (journalEntry, bool) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return nil, false
	}
	var e journalEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, false
	}
	return e, true
}

func (e journalEntry) field(name string) string { return journalValue(e[name]) }

// journalValue decodes one value; a field set more than once is read as
// its last value.
func journalValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || len(items) == 0 {
		return ""
	}
	b := make([]byte, 0, len(items))
	for _, item := range items {
		n, err := strconv.Atoi(string(item))
		if err != nil || n < 0 || n > 255 {
			return journalValue(items[len(items)-1])
		}
		b = append(b, byte(n))
	}
	return string(b)
}

// at is when journald received the entry.
func (e journalEntry) at() time.Time {
	us, err := strconv.ParseInt(e.field("__REALTIME_TIMESTAMP"), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMicro(us).UTC()
}

// line reads a container's entry. Docker logs stderr at priority 3 and
// stdout at 6.
func (e journalEntry) line() JournalLine {
	stream := "stdout"
	if e.field("PRIORITY") == "3" {
		stream = "stderr"
	}
	return JournalLine{
		At: e.at(), Stream: stream, Text: e.field("MESSAGE"),
		Container: e.field("CONTAINER_ID_FULL"), Name: e.field("CONTAINER_NAME"),
		App: e.field("BEDROCK_APP"), Workload: e.field("BEDROCK_WORKLOAD"), Revision: e.field("BEDROCK_REVISION"),
	}
}

// journalPermission is journalctl's stderr when it can't read the system
// journal: that it opened nothing, or, unless it prints JSON, the hint
// that it opened only the user's own journal.
var journalPermission = []string{"insufficient permissions", "not seeing messages from other users"}

// errJournalPermission is what a read kept from the system journal
// returns.
var errJournalPermission = errors.New("journalctl cannot read the system journal; run as root or join systemd-journal")

// journalctl runs the machine's journalctl.
func journalctl(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stderr := &boundedBuffer{max: 64 << 10}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, nil, errors.New("journalctl is not installed")
		}
		return nil, nil, fmt.Errorf("journalctl: %w", err)
	}
	wait := func() error {
		err := cmd.Wait()
		text := strings.TrimSpace(stderr.String())
		for _, hint := range journalPermission {
			if strings.Contains(text, hint) {
				return errJournalPermission
			}
		}
		if err == nil {
			return nil
		}
		if text != "" {
			lines := strings.Split(text, "\n")
			return fmt.Errorf("journalctl: %s", lines[len(lines)-1])
		}
		return fmt.Errorf("journalctl: %w", err)
	}
	return out, wait, nil
}

// boundedBuffer keeps the first max bytes written to it. It has no
// ReadFrom, so the copy exec makes from journalctl's stderr comes through
// Write.
type boundedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string { return b.buf.String() }
