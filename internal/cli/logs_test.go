package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/state"
)

// logsFixture is hello with revision r1 retired (web and worker gone),
// r2 active (web running), and r0 forgotten; job runs whose containers
// are running, gone into the journal, or gone with nothing kept there;
// a run of another app and a hold. journalctl answers from a fixed
// journal and writes each command line it was given to the returned
// file.
type logsFixture struct {
	dir, asked                          string
	jobLive, jobGone, jobLost, jobOther int64
	hold                                int64
}

func newLogsFixture(t *testing.T) logsFixture {
	t.Helper()
	ctx := context.Background()
	f := logsFixture{dir: t.TempDir()}
	f.asked = filepath.Join(f.dir, "journalctl-asked")
	store, err := state.Open(filepath.Join(f.dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for _, rev := range []state.Revision{
		{App: "hello", ID: "r1", Status: state.RevisionRetired, Manifest: []byte("{}"), CreatedAt: t0,
			Containers: map[string]string{"web": "bedrock-hello-web-r1", "worker": "bedrock-hello-worker-r1"}},
		{App: "hello", ID: "r2", Status: state.RevisionActive, Manifest: []byte("{}"), CreatedAt: t0.Add(time.Minute),
			Containers: map[string]string{"web": "bedrock-hello-web-r2"}},
	} {
		if err := store.SaveRevision(ctx, rev); err != nil {
			t.Fatal(err)
		}
	}
	job := func(app, revision, container, output string) int64 {
		t.Helper()
		id, err := store.StartJobRun(ctx, state.JobRun{App: app, Workload: "migrate", Revision: revision, Kind: "run", StartedAt: t0, Container: container})
		if err != nil {
			t.Fatal(err)
		}
		if output != "" {
			if err := store.FinishJobRun(ctx, id, 0, "", output, t0.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	f.jobLive = job("hello", "r2", "bedrock-hello-migrate-job-live", "")
	f.jobGone = job("hello", "r1", "bedrock-hello-migrate-job-gone", "migrated (kept)\n")
	f.jobLost = job("hello", "r1", "bedrock-hello-migrate-job-lost", "migrated (kept)\n")
	f.jobOther = job("other", "r1", "bedrock-other-migrate-job-x", "other's\n")
	if f.hold, err = store.HoldJob(ctx, "hello", "migrate", "r2", t0, t0.Add(time.Hour), "the volume is being moved"); err != nil {
		t.Fatal(err)
	}

	fake := dockertest.New(t)
	fake.Add(dockertest.Container{Name: "bedrock-hello-web-r2", Running: true, Logs: "web r2 up\n"})
	fake.Add(dockertest.Container{Name: "bedrock-hello-migrate-job-live", Running: true, Logs: "migrating\n"})

	entry := func(workload, name, message string) string {
		return fmt.Sprintf(`echo '{"__REALTIME_TIMESTAMP":"%d","CONTAINER_ID_FULL":"id-%s","CONTAINER_NAME":"%s","BEDROCK_WORKLOAD":"%s","MESSAGE":"%s"}'`, t0.UnixMicro(), name, name, workload, message)
	}
	script := "echo \"$*\" >> " + f.asked + "\ncase \"$*\" in\n" +
		"*CONTAINER_NAME=bedrock-hello-web-r1*) " + entry("web", "bedrock-hello-web-r1", "web r1 up") + " ;;\n" +
		"*CONTAINER_NAME=bedrock-hello-worker-r1*) " + entry("worker", "bedrock-hello-worker-r1", "worker r1 up") + " ;;\n" +
		"*CONTAINER_NAME=bedrock-hello-migrate-job-gone*) " + entry("migrate", "bedrock-hello-migrate-job-gone", "migrated 3 tables") + " ;;\n" +
		"*BEDROCK_REVISION=r0*) " + entry("web", "bedrock-hello-web-r0", "web r0 up") + "; " + entry("migrate", "bedrock-hello-migrate-job-old", "r0 migrated") + " ;;\n" +
		"esac\n"
	bin := filepath.Join(f.dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "journalctl"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return f
}

// asked is every journalctl command line, or nil when it never ran.
func (f logsFixture) journalAsked(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(f.asked)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func TestARetiredRevisionsLogsComeFromTheJournal(t *testing.T) {
	f := newLogsFixture(t)
	out, errOut, code := run(t, f.dir, "logs", "hello", "--revision", "r1")
	if code != 0 || out != "web | web r1 up\nworker | worker r1 up\n" {
		t.Fatalf("exit %d, stderr %q, output:\n%s", code, errOut, out)
	}
	asked := f.journalAsked(t)
	if len(asked) != 2 || !strings.Contains(asked[0], "--lines=100") || strings.Contains(strings.Join(asked, " "), "--follow") {
		t.Fatalf("journalctl asked %q", asked)
	}
	out, errOut, code = run(t, f.dir, "logs", "hello", "worker", "--revision", "r1", "--tail", "all")
	if code != 0 || out != "worker r1 up\n" {
		t.Fatalf("one workload: exit %d, stderr %q, output:\n%s", code, errOut, out)
	}
	if last := f.journalAsked(t)[2]; strings.Contains(last, "--lines") || !strings.HasSuffix(last, " CONTAINER_NAME=bedrock-hello-worker-r1") {
		t.Fatalf("journalctl asked %q", last)
	}
}

func TestARunningRevisionsLogsComeFromDocker(t *testing.T) {
	f := newLogsFixture(t)
	out, errOut, code := run(t, f.dir, "logs", "hello", "--revision", "r2", "--follow")
	if code != 0 || out != "web r2 up\n" || f.journalAsked(t) != nil {
		t.Fatalf("exit %d, stderr %q, journal asked %q, output:\n%s", code, errOut, f.journalAsked(t), out)
	}
}

// gc forgets a revision's record, and the container names with it, but
// the journal still has its lines under its labels.
func TestAForgottenRevisionsLogsAreFoundByItsLabels(t *testing.T) {
	f := newLogsFixture(t)
	out, errOut, code := run(t, f.dir, "logs", "hello", "--revision", "r0", "--tail", "all")
	if code != 0 || out != "web | web r0 up\nmigrate | r0 migrated\n" || !strings.Contains(errOut, "revision no longer recorded; showing every container labelled with it, jobs included") {
		t.Fatalf("exit %d, stderr %q, output:\n%s", code, errOut, out)
	}
	if asked := f.journalAsked(t); len(asked) != 1 || !strings.HasSuffix(asked[0], " BEDROCK_APP=hello BEDROCK_REVISION=r0") || strings.Contains(asked[0], " CONTAINER_NAME=") {
		t.Fatalf("journalctl asked %q", asked)
	}
	out, errOut, code = run(t, f.dir, "logs", "hello", "--revision", "r9")
	if code != 0 || out != "" || !strings.Contains(errOut, "journal has nothing for revision r9 of hello") {
		t.Fatalf("an unknown revision: exit %d, stderr %q, output:\n%s", code, errOut, out)
	}
}

func TestAJobRunsLogsComeFromWhereverTheyStillAre(t *testing.T) {
	f := newLogsFixture(t)
	kept := "journal has nothing for this job; showing the last 40 lines kept with the run"
	for _, c := range []struct {
		name     string
		job      int64
		out, err string
	}{
		{"running", f.jobLive, "migrating\n", ""},
		{"in the journal", f.jobGone, "migrated 3 tables\n", ""},
		{"gone from the journal too", f.jobLost, "migrated (kept)\n", kept},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, errOut, code := run(t, f.dir, "logs", "hello", "migrate", "--job", fmt.Sprint(c.job))
			if code != 0 || out != c.out || strings.TrimSpace(errOut) != c.err {
				t.Fatalf("exit %d, stderr %q, output:\n%s", code, errOut, out)
			}
		})
	}
	t.Setenv("PATH", t.TempDir())
	out, errOut, code := run(t, f.dir, "logs", "hello", "--job", fmt.Sprint(f.jobGone))
	if code != 0 || out != "migrated (kept)\n" || strings.TrimSpace(errOut) != "journalctl is not installed; showing the last 40 lines kept with the run" {
		t.Fatalf("without journalctl: exit %d, stderr %q, output:\n%s", code, errOut, out)
	}
}

func TestLogsRefusesWhatItCannotShow(t *testing.T) {
	f := newLogsFixture(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"hello", "--revision", "r1", "--job", "1"}, "use either --revision or --job"},
		{[]string{"hello", "--revision", "r1", "--follow"}, "--follow follows one workload; name one of [web worker]"},
		{[]string{"hello", "cron", "--revision", "r1"}, "revision r1 of hello runs no workload named cron; a job's output is under --job"},
		{[]string{"hello", "--revision", "r1", "--tail", "lots"}, `--tail takes a number of lines or all, not "lots"`},
		{[]string{"hello", "--job", "1", "--tail", "0"}, `--tail takes a number of lines or all, not "0"`},
		{[]string{"hello", "--job", "first"}, "job runs are numbered; helios jobs hello lists them"},
		{[]string{"hello", "--job", "999"}, "no job run 999; helios jobs hello lists them"},
		{[]string{"hello", "--job", fmt.Sprint(f.jobOther)}, fmt.Sprintf("job %d is not one of hello's", f.jobOther)},
		{[]string{"hello", "web", "--job", fmt.Sprint(f.jobGone)}, fmt.Sprintf("job %d ran migrate, not web", f.jobGone)},
		{[]string{"hello", "--job", fmt.Sprint(f.hold)}, fmt.Sprintf("job %d is a hold on migrate, not a run; it has no output", f.hold)},
	} {
		out, errOut, code := run(t, f.dir, append([]string{"logs"}, c.args...)...)
		if code == 0 || out != "" || strings.TrimSpace(errOut) != "helios: "+c.want {
			t.Errorf("%v: exit %d, stderr %q, output %q", c.args, code, errOut, out)
		}
	}
	if asked := f.journalAsked(t); asked != nil {
		t.Fatalf("journalctl asked %q", asked)
	}
}

// An older target has no journal reader and doesn't know the flags, so it
// is told to upgrade rather than asked; plain logs still go to it.
func TestATargetWithoutTheJournalIsNotAskedForPastLogs(t *testing.T) {
	config, record := targetFixture(t)
	for _, args := range [][]string{
		{"logs", "hello", "--revision", "r1"},
		{"logs", "hello", "migrate", "--job", "3"},
		{"alerts", "show", "1", "--evidence"},
		{"alerts", "review", "1"},
	} {
		if _, stderr, code := targetRun(t, config, args...); code == 0 || !strings.Contains(stderr, "target does not keep incident evidence or retired logs; upgrade it first") {
			t.Fatalf("%v: %d %s", args, code, stderr)
		}
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("the target was asked")
	}
	if _, stderr, code := targetRun(t, config, "logs", "hello", "--tail", "5"); code != 0 {
		t.Fatalf("plain logs: %d %s", code, stderr)
	}
	if b, err := os.ReadFile(record); err != nil || !strings.Contains(string(b), "--tail=5") {
		t.Fatalf("plain logs sent %q (%v)", b, err)
	}
}
