package docker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
)

// fakeJournal is a journal whose journalctl prints out and records what
// it was asked and whether it was stopped.
type fakeJournal struct {
	out     string
	args    []string
	stopped bool
}

func (f *fakeJournal) journal() Journal {
	return Journal{exec: func(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
		f.args = args
		return io.NopCloser(strings.NewReader(f.out)), func() error {
			f.stopped = ctx.Err() != nil
			return nil
		}, nil
	}}
}

// at is a journal timestamp, in microseconds, some seconds into the
// fixtures' window.
func at(seconds int) string { return fmt.Sprint(time.Unix(1792487040+int64(seconds), 0).UnixMicro()) }

func TestAJournalQueryAsksForItsContainersInItsWindow(t *testing.T) {
	q := JournalQuery{
		Names: []string{"bedrock-hello-web-r1", "bedrock-hello-worker-r1"}, App: "hello", Workload: "web", Revision: "r1",
		Since: time.Date(2026, 10, 20, 9, 4, 0, 500_000_000, time.UTC), Until: time.Date(2026, 10, 20, 9, 14, 0, 250_000_000, time.UTC),
		Lines: 40, Follow: true,
	}
	head := []string{"--no-pager", "--all", "--output=json",
		"--output-fields=MESSAGE,PRIORITY,CONTAINER_NAME,CONTAINER_ID_FULL,CONTAINER_PARTIAL_MESSAGE,CONTAINER_PARTIAL_ID,CONTAINER_PARTIAL_ORDINAL,CONTAINER_PARTIAL_LAST,BEDROCK_APP,BEDROCK_WORKLOAD,BEDROCK_REVISION,SYSLOG_IDENTIFIER"}
	want := append(slices.Clone(head),
		"--since=@1792487040", "--until=@1792487641", "--lines=40", "--follow",
		"CONTAINER_NAME=bedrock-hello-web-r1", "CONTAINER_NAME=bedrock-hello-worker-r1",
		"BEDROCK_APP=hello", "BEDROCK_WORKLOAD=web", "BEDROCK_REVISION=r1")
	if got := q.Args(); !slices.Equal(got, want) {
		t.Fatalf("args\n got %q\nwant %q", got, want)
	}
	if got, want := (JournalQuery{Names: []string{"bedrock-hello-job-x"}}).Args(), append(slices.Clone(head), "CONTAINER_NAME=bedrock-hello-job-x"); !slices.Equal(got, want) {
		t.Fatalf("an open query adds %q", got[len(head):])
	}
}

func TestAJournalQueryForNothingIsNotRun(t *testing.T) {
	fake := &fakeJournal{}
	if _, err := fake.journal().Read(context.Background(), JournalQuery{Lines: 10}); err == nil || fake.args != nil {
		t.Fatalf("ran journalctl %q for the whole journal (err %v)", fake.args, err)
	}
}

// journalctl prints a value as a string, as its bytes when it isn't
// text, as null when it left it out, and as a list when the field was set
// more than once.
func TestJournalLinesReadEveryShapeOfMessage(t *testing.T) {
	web := `"CONTAINER_NAME":"bedrock-hello-web-r1","CONTAINER_ID_FULL":"aaa","BEDROCK_APP":"hello","BEDROCK_WORKLOAD":"web","BEDROCK_REVISION":"r1"`
	fake := &fakeJournal{out: strings.Join([]string{
		`-- No entries --`,
		`{"__REALTIME_TIMESTAMP":"` + at(1) + `","PRIORITY":"6","MESSAGE":"listening on :8080",` + web + `}`,
		`{"__REALTIME_TIMESTAMP":"` + at(2) + `","PRIORITY":"3","MESSAGE":[104,105,255],` + web + `}`,
		`{"__REALTIME_TIMESTAMP":"` + at(3) + `","PRIORITY":"6","MESSAGE":null,` + web + `}`,
		`{"__REALTIME_TIMESTAMP":"` + at(4) + `","PRIORITY":["3","6"],"MESSAGE":["first","second"],` + web + `}`,
		`{"__REALTIME_TIMESTAMP":"` + at(5) + `","PRIORITY":"6","MESSAGE":[[111,107],[110,111]],` + web + `}`,
	}, "\n")}
	got, err := fake.journal().Read(context.Background(), JournalQuery{Names: []string{"bedrock-hello-web-r1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("containers %+v", got)
	}
	c := got[0]
	if c.ID != "aaa" || c.Name != "bedrock-hello-web-r1" || c.App != "hello" || c.Workload != "web" || c.Revision != "r1" {
		t.Fatalf("container %+v", c)
	}
	var lines []string
	for _, l := range c.Lines {
		lines = append(lines, fmt.Sprintf("%s %s %q", l.At.Format(time.TimeOnly), l.Stream, l.Text))
	}
	want := []string{
		`09:04:01 stdout "listening on :8080"`,
		`09:04:02 stderr "hi\xff"`,
		`09:04:03 stdout ""`,
		`09:04:04 stdout "second"`,
		`09:04:05 stdout "no"`,
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("lines\n got %q\nwant %q", lines, want)
	}
}

// Docker splits a long line into chunks marked partial but the last; the
// chunks of one stream of one container join with nothing between them,
// whatever else comes in between.
func TestJournalLinesSplitByDockerComeBackWhole(t *testing.T) {
	entry := func(seconds int, container, priority, message, extra string) string {
		return fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%s","CONTAINER_ID_FULL":"%s","PRIORITY":"%s","MESSAGE":"%s"%s}`, at(seconds), container, priority, message, extra)
	}
	partial := `,"CONTAINER_PARTIAL_MESSAGE":"true"`
	fake := &fakeJournal{out: strings.Join([]string{
		entry(1, "aaa", "6", "aaaa", partial),
		entry(2, "bbb", "6", "worker up", ""),
		entry(3, "aaa", "3", "oops", ""),
		entry(4, "aaa", "6", "bbbb", partial),
		entry(5, "aaa", "6", "cc", `,"CONTAINER_PARTIAL_LAST":"true"`),
		entry(6, "ccc", "6", "cut off", partial),
	}, "\n") + "\n"}
	got, err := fake.journal().Read(context.Background(), JournalQuery{App: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, c := range got {
		for _, l := range c.Lines {
			lines = append(lines, fmt.Sprintf("%s %s %s %s", c.ID, l.At.Format(time.TimeOnly), l.Stream, l.Text))
		}
	}
	want := []string{
		"bbb 09:04:02 stdout worker up",
		"aaa 09:04:03 stderr oops",
		"aaa 09:04:01 stdout aaaabbbbcc",
		"ccc 09:04:06 stdout cut off",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("lines\n got %q\nwant %q", lines, want)
	}
}

// Docker numbers a long line's chunks. A line whose first chunks fell
// outside the window, or that journald dropped, can start partway
// through a secret, so a Read leaves it out; Stream gives it as it is,
// as docker logs does.
func TestAJournalLineThatLostItsFirstChunksIsLeftOutOfARead(t *testing.T) {
	chunk := func(seconds int, container, id string, ordinal int, last bool, message string) string {
		extra := fmt.Sprintf(`,"CONTAINER_PARTIAL_ID":"%s","CONTAINER_PARTIAL_ORDINAL":"%d","CONTAINER_PARTIAL_LAST":"%t"`, id, ordinal, last)
		if !last {
			extra += `,"CONTAINER_PARTIAL_MESSAGE":"true"`
		}
		return fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%s","CONTAINER_ID_FULL":"%s","PRIORITY":"6","MESSAGE":"%s"%s}`, at(seconds), container, message, extra)
	}
	fake := &fakeJournal{out: strings.Join([]string{
		chunk(1, "aaa", "p1", 2, false, "456789 from the middle"),
		chunk(2, "aaa", "p1", 3, true, " to the end"),
		chunk(3, "bbb", "p2", 2, true, "456789 at the end"),
		chunk(4, "ccc", "p3", 1, false, "a start "),
		chunk(5, "ccc", "p3", 3, true, "456789 after a gap"),
		chunk(6, "ddd", "p4", 1, false, "one "),
		chunk(7, "ddd", "p4", 2, false, "two "),
		chunk(8, "ddd", "p4", 3, true, "three"),
		chunk(9, "eee", "p5", 1, false, "never finished "),
		chunk(10, "eee", "p6", 1, false, "the next "),
		chunk(11, "eee", "p6", 2, true, "line"),
	}, "\n") + "\n"}
	q := JournalQuery{App: "hello"}
	got, err := fake.journal().Read(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var read []string
	for _, c := range got {
		for _, l := range c.Lines {
			read = append(read, fmt.Sprintf("%s %s %s", c.ID, l.At.Format(time.TimeOnly), l.Text))
		}
	}
	want := []string{
		"ccc 09:04:04 a start ",
		"ddd 09:04:06 one two three",
		"eee 09:04:09 never finished ",
		"eee 09:04:10 the next line",
	}
	if !slices.Equal(read, want) {
		t.Fatalf("read\n got %q\nwant %q", read, want)
	}
	var streamed []string
	if err := fake.journal().Stream(context.Background(), q, func(l JournalLine) error {
		streamed = append(streamed, l.Container+" "+l.Text)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"aaa 456789 from the middle to the end",
		"bbb 456789 at the end",
		"ccc a start ",
		"ccc 456789 after a gap",
		"ddd one two three",
		"eee never finished ",
		"eee the next line",
	}
	if !slices.Equal(streamed, want) {
		t.Fatalf("streamed\n got %q\nwant %q", streamed, want)
	}
}

func TestAJournalReadStopsAt8MiBAndKeepsWhatItRead(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"` + at(1) + `","CONTAINER_ID_FULL":"aaa","PRIORITY":"6","MESSAGE":"` + strings.Repeat("x", 1000) + `"}` + "\n"
	fake := &fakeJournal{out: strings.Repeat(line, 9<<20/len(line))}
	got, err := fake.journal().Read(context.Background(), JournalQuery{App: "hello"})
	if !errors.Is(err, ErrJournalLimit) {
		t.Fatalf("err %v", err)
	}
	if len(got) != 1 || len(got[0].Lines) == 0 || len(got[0].Lines)*len(line) > JournalReadLimit {
		t.Fatalf("kept %+v", got)
	}
	if !fake.stopped {
		t.Fatal("journalctl was left running")
	}
}

func TestJournaldsDroppedDockerMessagesAreCounted(t *testing.T) {
	fake := &fakeJournal{out: strings.Join([]string{
		`{"__REALTIME_TIMESTAMP":"` + at(10) + `","MESSAGE":"Suppressed 1200 messages from docker.service"}`,
		`{"__REALTIME_TIMESTAMP":"` + at(20) + `","MESSAGE":"Suppressed 3 messages from ssh.service"}`,
		`{"__REALTIME_TIMESTAMP":"` + at(30) + `","MESSAGE":"Journal started"}`,
		`{"__REALTIME_TIMESTAMP":"` + at(40) + `","MESSAGE":"Suppressed 7 messages from /system.slice/docker.service"}`,
	}, "\n")}
	since, until := time.Unix(1792487040, 0), time.Unix(1792487640, 0)
	got, err := fake.journal().Suppressed(context.Background(), since, until)
	if err != nil {
		t.Fatal(err)
	}
	want := []JournalSuppressed{{At: time.Unix(1792487050, 0).UTC(), Count: 1200}, {At: time.Unix(1792487080, 0).UTC(), Count: 7}}
	if !slices.Equal(got, want) {
		t.Fatalf("suppressed %+v", got)
	}
	if !slices.Contains(fake.args, "_SYSTEMD_UNIT=systemd-journald.service") || !slices.Contains(fake.args, "--since=@1792487040") || !slices.Contains(fake.args, "--until=@1792487640") {
		t.Fatalf("asked %q", fake.args)
	}
}

// fakeJournalctl puts a journalctl that runs script first on PATH.
func fakeJournalctl(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

// journalctl printing JSON is as quiet as with --quiet. Kept from the
// system journal but able to open the user's own, it prints nothing and
// exits 0; only printing for a person does it give its hint.
func TestAJournalThatCantBeReadSaysWhatToDo(t *testing.T) {
	q := JournalQuery{Names: []string{"bedrock-hello-web-r1"}}
	permission := "journalctl cannot read the system journal; run as root or join systemd-journal"
	empty := "case \"$*\" in\n*--output=json*) ;;\n*) echo '-- No entries --'; %s ;;\nesac\n"
	hint := `printf '%s\n' "Hint: You are currently not seeing messages from other users and the system." "      Users in groups 'adm', 'systemd-journal' can see all messages." "      Pass -q to turn off this notice." >&2`
	for _, c := range []struct{ name, script, want string }{
		{"not installed", "", "journalctl is not installed"},
		{"no journal files", "echo 'No journal files were opened due to insufficient permissions.' >&2\nexit 1\n", permission},
		{"only the user's own", fmt.Sprintf(empty, hint), permission},
		{"nothing in it", fmt.Sprintf(empty, "true"), ""},
		{"failed", "echo 'Failed to parse timestamp: @x' >&2\nexit 1\n", "journalctl: Failed to parse timestamp: @x"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.script == "" {
				t.Setenv("PATH", t.TempDir())
			} else {
				fakeJournalctl(t, c.script)
			}
			got := ""
			if _, err := (Journal{}).Read(context.Background(), q); err != nil {
				got = err.Error()
			}
			if got != c.want {
				t.Fatalf("err %q, want %q", got, c.want)
			}
		})
	}
}

// Asked why a read found nothing, journalctl must print none of the
// journal, which for root is all of it.
func TestAskingWhyAReadFoundNothingReadsNoneOfTheJournal(t *testing.T) {
	fake := &fakeJournal{}
	if _, err := fake.journal().Read(context.Background(), JournalQuery{Names: []string{"bedrock-hello-web-r1"}}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"--no-pager", "--output=short", "--lines=0"}; !slices.Equal(fake.args, want) {
		t.Fatalf("asked %q, want %q", fake.args, want)
	}
}

func TestJournalctlKeepsNoMoreThan64KiBOfWhatItSaysOnStderr(t *testing.T) {
	fakeJournalctl(t, "s=x; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do s=$s$s; done\nprintf %s \"$s\" >&2\nexit 1\n")
	_, err := Journal{}.Read(context.Background(), JournalQuery{Names: []string{"bedrock-hello-web-r1"}})
	if err == nil || len(err.Error()) > len("journalctl: ")+64<<10 {
		t.Fatalf("an error of %d bytes", len(fmt.Sprint(err)))
	}
}

// Following the journal ends when the person watching stops it, and that
// is not a failure.
func TestFollowingTheJournalEndsQuietlyWhenStopped(t *testing.T) {
	fakeJournalctl(t, `echo '{"__REALTIME_TIMESTAMP":"`+at(1)+`","CONTAINER_ID_FULL":"aaa","MESSAGE":"up"}'`+"\nexec /bin/sleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got []string
	err := Journal{}.Stream(ctx, JournalQuery{Names: []string{"bedrock-hello-web-r1"}, Follow: true}, func(l JournalLine) error {
		got = append(got, l.Text)
		cancel()
		return nil
	})
	if err != nil || !slices.Equal(got, []string{"up"}) {
		t.Fatalf("lines %q, err %v", got, err)
	}
}

// Docker logs a long line in chunks, and the other stream can write
// between two of them.
func TestLogStreamsKeepsStdoutAndStderrApart(t *testing.T) {
	e, _ := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/containers/web/logs") {
			return false
		}
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		for _, f := range []struct {
			stream byte
			text   string
		}{{1, "a long line's first chunk, "}, {2, "oops\n"}, {1, "and its rest\n"}} {
			frame := make([]byte, 8)
			frame[0] = f.stream
			binary.BigEndian.PutUint32(frame[4:], uint32(len(f.text)))
			_, _ = w.Write(append(frame, f.text...))
		}
		return true
	})
	var stdout, stderr, both strings.Builder
	if err := e.LogStreams(context.Background(), "web", LogOptions{}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := e.Logs(context.Background(), "web", LogOptions{}, &both); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "a long line's first chunk, and its rest\n" || stderr.String() != "oops\n" || both.String() != "a long line's first chunk, oops\nand its rest\n" {
		t.Fatalf("stdout %q, stderr %q, both %q", stdout.String(), stderr.String(), both.String())
	}
}

func TestLogsAsksTheEngineForATimeWindow(t *testing.T) {
	var queries []string
	e, fake := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/containers/web/logs") {
			q := r.URL.Query()
			queries = append(queries, fmt.Sprintf("since=%s until=%s follow=%s tail=%s", q.Get("since"), q.Get("until"), q.Get("follow"), q.Get("tail")))
		}
		return false
	})
	fake.Add(dockertest.Container{Name: "web", Logs: "up\n"})
	since := time.Date(2026, 10, 20, 9, 4, 0, 0, time.UTC)
	var out strings.Builder
	if err := e.Logs(context.Background(), "web", LogOptions{Since: since, Until: since.Add(10 * time.Minute)}, &out); err != nil {
		t.Fatal(err)
	}
	if err := e.Logs(context.Background(), "web", LogOptions{Follow: true, Tail: "100"}, &out); err != nil {
		t.Fatal(err)
	}
	want := []string{"since=1792487040.000000000 until=1792487640.000000000 follow= tail=", "since= until= follow=1 tail=100"}
	if !slices.Equal(queries, want) || out.String() != "up\nup\n" {
		t.Fatalf("asked %q, read %q", queries, out.String())
	}
}
