package incident

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// opened is when the incidents in these tests open.
var opened = time.Unix(1792487640, 0).UTC()

// Fake secret values the noisy journal leaks.
const (
	apiToken      = "tok_fake_0123456789abcdef"
	oldToken      = "tok_old_fake_aaaaaaaa"
	sessionSecret = "s3cr3t/fake+value&more"
	backupKey     = "bk_fake_password_1234"
	databaseURL   = "postgres://web:pg_fake_env_pass@db.example.test:5432/web"
	tlsKey        = "-----BEGIN FAKE KEY-----\nZmFrZWtleWxpbmVvbmU=\n-----END FAKE KEY-----"
)

func TestNoisyLogFitsBody(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	saveRevision(t, store, "web", "r7", map[string]string{"DATABASE_URL": databaseURL, "LOG_LEVEL": "info"}, nil)
	saveChange(t, store, "op-deploy", apps.DeployKind, "web", apps.DeployInput{Revision: "r7"}, opened.Add(-5*time.Minute), "migrated with "+apiToken)
	inc := openIncident(t, store, "app:web", "web answers 502 through 10.0.0.1 "+strings.Repeat("z", 6000), opened)
	noisyJournal(t)
	sealed := fakeSecrets{versions: map[string]map[int]map[string]string{
		manifest.ReservedApp: {1: {"BACKUP_PASSWORD": backupKey}},
		"web": {
			1: {"API_TOKEN": oldToken},
			2: {"API_TOKEN": apiToken, "SESSION_SECRET": sessionSecret, "TLS_KEY": tlsKey},
		},
	}}
	src := Sources{Store: store, Secrets: sealed, Journal: docker.Journal{}, Host: "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened.Add(time.Second) }}

	e, err := Collect(ctx, inc, src)
	if err != nil {
		t.Fatal(err)
	}
	if e.Redaction.Status != RedactionApplied {
		t.Fatalf("redaction %q, errors %+v", e.Redaction.Status, e.Errors)
	}
	stateDir := t.TempDir()
	if err := Save(stateDir, e); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filepath.Join(Dir(stateDir, inc.ID), EvidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(file) > FileMax {
		t.Fatalf("evidence.json is %d bytes", len(file))
	}
	loom := e.Clone()
	Fit(loom, LoomEvidenceMax)
	if size := Size(loom); size > LoomEvidenceMax {
		t.Fatalf("the body's evidence is %d bytes", size)
	}
	body, err := json.Marshal(map[string]any{
		"event_id": "web.example.test:" + strconv.FormatInt(inc.ID, 10) + ":open", "incident_id": inc.ID, "transition": "open",
		"host": e.Host, "key": e.Incident.Key, "severity": e.Incident.Severity, "message": e.Incident.Message,
		"opened_at": e.Incident.OpenedAt, "evidence": loom,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) >= 1<<20 {
		t.Fatalf("the body is %d bytes", len(body))
	}
	if len(e.Truncated) == 0 || len(loom.Truncated) <= len(e.Truncated) {
		t.Fatalf("truncated %q, then %q", e.Truncated, loom.Truncated)
	}
	if !slices.Contains(e.Truncated, "logs: the 12 containers that wrote last") || len(e.Logs) != maxContainers || e.Logs[0].Container != "web-01" {
		t.Fatalf("truncated %q with %d containers", e.Truncated, len(e.Logs))
	}
	if len(e.JournalSuppressed) != 1 || e.JournalSuppressed[0].Count != 1200 {
		t.Fatalf("suppressed %+v", e.JournalSuppressed)
	}
	assertNoSecrets(t, "evidence.json", file)
	assertNoSecrets(t, "the body", body)

	// What was left in shows each line was put together, redacted, then cut.
	saved, err := Load(stateDir, inc)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range saved.Logs[0].Lines {
		lines = append(lines, l.Text)
	}
	for _, want := range []string{
		"auth ok for [redacted API_TOKEN] in 3ms",
		"retrying with [redacted API_TOKEN]",
		"cookie [redacted SESSION_SECRET] set",
		"GET /callback?next=[redacted SESSION_SECRET]",
		"restic opened with [redacted BACKUP_PASSWORD]",
		"connecting to [redacted DATABASE_URL]",
		"loaded key [redacted TLS_KEY]",
		"cache at redis://[redacted]@cache.example.test:6379",
		"GET /hook?api_key=[redacted]&page=2",
		"Authorization: [redacted]",
		"peer [mesh] via [mesh] at [mesh], upstream [private], lan [private]",
		"hi �\t!",
		strings.Repeat("x", 2040) + "[redacte[+12 bytes]",
		strings.Repeat("y", lineMax) + "[+" + strconv.Itoa(1<<20-lineMax) + " bytes]",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("no line %.80q in %.300q", want, lines)
		}
	}
	if note := saved.LastChange.Steps[0].Note; note != "migrated with [redacted API_TOKEN]" {
		t.Errorf("step note %q", note)
	}
	if !strings.HasPrefix(saved.Incident.Message, "web answers 502 through [private] zzz") || !strings.HasSuffix(saved.Incident.Message, " bytes]") {
		t.Errorf("message %.80q", saved.Incident.Message)
	}

	// An unreadable secret store leaves the logs and step notes out.
	src.Secrets = fakeSecrets{err: errors.New("the sealed secrets can't be opened")}
	omitted, err := Collect(ctx, inc, src)
	if err != nil {
		t.Fatal(err)
	}
	if omitted.Redaction.Status != RedactionLogsOmitted || omitted.Logs != nil || omitted.LastChange.Steps[0].Note != "" {
		t.Fatalf("redaction %q with %d logs and note %q", omitted.Redaction.Status, len(omitted.Logs), omitted.LastChange.Steps[0].Note)
	}
	if !slices.Contains(omitted.Errors, SourceError{Source: "secrets", Error: "the sealed secrets can't be opened"}) {
		t.Fatalf("errors %+v", omitted.Errors)
	}
	b, err := json.Marshal(omitted)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "evidence without logs", b)
}

// An incident's message can end with the container's own output, such as
// a health command's last words, where no pattern finds a secret. Without
// the values to redact it with, it is left out like the logs.
func TestMessagesAreLeftOutWhenTheSecretsCantBeRead(t *testing.T) {
	store := openStore(t)
	saveRevision(t, store, "web", "r7", nil, map[string]string{"web": "bedrock-web-web-r7"})
	openIncident(t, store, "app:web", "web: the health command failed: password: sk_fake_earlier_value", opened.Add(-24*time.Hour))
	inc := openIncident(t, store, "app:web", "web: the health command failed: settings invalid {'api_key': 'sk_fake_current_value'}", opened)
	e, err := Collect(context.Background(), inc, Sources{
		Store: store, Secrets: fakeSecrets{err: errors.New("the sealed secrets can't be opened")},
		Host: "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened },
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if e.Redaction.Status != RedactionLogsOmitted || strings.Contains(string(b), "sk_fake_") {
		t.Fatalf("redaction %q with %s", e.Redaction.Status, b)
	}
	if len(e.History.Incidents) != 1 || e.Incident.Message != messageOmitted || e.History.Incidents[0].Message != messageOmitted {
		t.Fatalf("message %q, history %+v", e.Incident.Message, e.History.Incidents)
	}
}

// An env value can be one of the words helios writes itself, such as a
// status page's name, a severity, a signal's kind or a container's name.
// It is redacted where an app or a name it chose holds it, and finding it
// in helios's own words is no leak, so the evidence keeps its logs.
func TestAnEnvValueThatIsOneOfHeliosOwnWordsIsNoLeak(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	env := map[string]string{"DNS_PROVIDER": "cloudflare", "ALERT_LEVEL": "critical", "METRIC": "requests", "WORKER_HOST": "bedrock-web-worker-r7"}
	saveRevision(t, store, "web", "r7", env, map[string]string{"web": "bedrock-web-web-r7", "worker": "bedrock-web-worker-r7"})
	if err := store.AddSignal(ctx, state.Signal{Hour: opened.Add(-time.Hour), App: "web", Metric: "requests", Value: 120, Samples: 60}); err != nil {
		t.Fatal(err)
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":{"indicator":"none","description":"All Systems Operational"}}`)
	}))
	defer page.Close()
	inc := openIncident(t, store, "app:web", "web answers 502", opened)
	journal := &recordingJournal{containers: []docker.JournalContainer{{ID: "c1", Name: "bedrock-web-web-r7", Workload: "web", Revision: "r7", Lines: []docker.JournalLine{{At: opened.Add(-time.Minute), Stream: "stderr", Text: "lookup through cloudflare timed out"}}}}}
	engine := &fakeEngine{logs: map[string][]string{"bedrock-web-worker-r7": {strings.Repeat("c", docker.JournalReadLimit-25) + "\n", "short\n", "working\n", strings.Repeat("w", 25) + "\n"}}}

	e, err := Collect(ctx, inc, Sources{
		Store: store, Secrets: fakeSecrets{}, Engine: engine, Journal: journal,
		Upstream: []Statuspage{{Name: "cloudflare", Base: page.URL}},
		Host:     "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened },
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Redaction.Status != RedactionApplied || len(e.Errors) != 0 {
		t.Fatalf("redaction %q, errors %+v", e.Redaction.Status, e.Errors)
	}
	if e.Incident.Severity != "critical" || len(e.Upstream) != 1 || e.Upstream[0].Name != "cloudflare" || len(e.History.Signals) != 1 || e.History.Signals[0].Kind != "requests" {
		t.Fatalf("severity %q, upstream %+v, signals %+v", e.Incident.Severity, e.Upstream, e.History.Signals)
	}
	var logs []string
	for _, l := range e.Logs {
		for _, line := range l.Lines {
			logs = append(logs, l.Container+": "+line.Text)
		}
	}
	want := []string{"[redacted WORKER_HOST]: working", "bedrock-web-web-r7: lookup through [redacted DNS_PROVIDER] timed out"}
	if !slices.Equal(logs, want) {
		t.Fatalf("logs %q", logs)
	}
	if !slices.Equal(e.Truncated, []string{"logs: the engine read of [redacted WORKER_HOST] stopped at 8 MiB"}) {
		t.Fatalf("truncated %q", e.Truncated)
	}
}

// Redaction's own words can let a value survive it, as here, where a
// secret reads like the stand-in for a private address. Found in a log
// line, the logs, step notes and messages are left out, and the note
// saying so is helios's own words too, which an env value can match.
// Found where nothing is left out, there is no evidence.
func TestAValueThatSurvivesRedactionLeavesTheLogsOutOrTheEvidence(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	saveRevision(t, store, "web", "r7", map[string]string{"QUEUE_NAME": "messages"}, map[string]string{"web": "bedrock-web-web-r7"})
	saveChange(t, store, "op-web-1", apps.DeployKind, "web", apps.DeployInput{Revision: "r7"}, opened.Add(-5*time.Minute), "migrated")
	inc := openIncident(t, store, "app:web", "web answers 502", opened)
	journal := &recordingJournal{containers: []docker.JournalContainer{{ID: "c1", Name: "bedrock-web-web-r7", Workload: "web", Revision: "r7", Lines: []docker.JournalLine{{At: opened.Add(-time.Minute), Stream: "stderr", Text: "upstream 10.0.0.1 refused"}}}}}
	sealed := fakeSecrets{versions: map[string]map[int]map[string]string{"web": {2: {"PROXY_LABEL": "[private]"}}}}
	src := Sources{Store: store, Secrets: sealed, Journal: journal, Host: "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened }}

	e, err := Collect(ctx, inc, src)
	if err != nil {
		t.Fatal(err)
	}
	survived := SourceError{Source: "redaction", Error: "a value of PROXY_LABEL survived redaction, so logs, step notes and messages were left out"}
	if e.Redaction.Status != RedactionLogsOmitted || e.Logs != nil || e.Incident.Message != messageOmitted || e.LastChange.Steps[0].Note != "" || !slices.Equal(e.Errors, []SourceError{survived}) {
		t.Fatalf("redaction %q with %d logs, message %q, note %q, errors %+v", e.Redaction.Status, len(e.Logs), e.Incident.Message, e.LastChange.Steps[0].Note, e.Errors)
	}

	src.Host = "10.0.0.5"
	if e, err := Collect(ctx, inc, src); e != nil || err == nil || err.Error() != "a secret value survived redaction, so there is no evidence" {
		t.Fatalf("evidence %t, error %v", e != nil, err)
	}
}

// assertNoSecrets fails when out holds any secret value or private
// address, as written or as JSON escapes it.
func assertNoSecrets(t *testing.T, what string, out []byte) {
	t.Helper()
	for _, s := range []string{
		apiToken, "tok_fa", oldToken, sessionSecret, url.QueryEscape(sessionSecret), backupKey, "pg_fake_env_pass", "ZmFrZWtleWxpbmVvbmU",
		"redis_fake_pw", "k_fake_query_value", "bearer_fake_value", "100.64.0.1", "fd00::1", "ts.net", "10.0.0.1", "192.168.0.1",
	} {
		escaped, _ := json.Marshal(s)
		for _, form := range []string{s, string(escaped[1 : len(escaped)-1])} {
			if strings.Contains(string(out), form) {
				t.Errorf("%s holds %q", what, form)
			}
		}
	}
}

// noisyJournal puts a journalctl on PATH whose journal has 200,000 lines
// from 16 of web's containers, then, from web-01, the lines that leak
// secrets and addresses or test the caps, and a note that journald
// dropped 1,200 of Docker's lines.
func noisyJournal(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	journal, suppressed := filepath.Join(dir, "journal.json"), filepath.Join(dir, "suppressed.json")
	f, err := os.Create(journal)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	since := opened.Add(-window)
	for i := range 200_000 {
		at := since.Add(time.Duration(i) * 2900 * time.Microsecond)
		fmt.Fprintf(w, `{"__REALTIME_TIMESTAMP":"%d","MESSAGE":"GET /items/%d 200","CONTAINER_NAME":"web-%02d","CONTAINER_ID_FULL":"c%02d","BEDROCK_APP":"web"}`+"\n", at.UnixMicro(), i, i%16+1, i%16+1)
	}
	at := since.Add(590 * time.Second)
	write := func(message any, partial bool) {
		entry := map[string]any{"__REALTIME_TIMESTAMP": strconv.FormatInt(at.UnixMicro(), 10), "MESSAGE": message, "CONTAINER_NAME": "web-01", "CONTAINER_ID_FULL": "c01", "BEDROCK_APP": "web"}
		if partial {
			entry["CONTAINER_PARTIAL_MESSAGE"] = "true"
		}
		b, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(append(b, '\n'))
		at = at.Add(time.Millisecond)
	}
	// A 1 MiB line in Docker's 16 KiB chunks, and a secret split by one.
	for i := range 64 {
		write(strings.Repeat("y", 16<<10), i < 63)
	}
	write("auth ok for "+apiToken[:9], true)
	write(apiToken[9:]+" in 3ms", false)
	for _, line := range []string{
		strings.Repeat("x", 2040) + apiToken,
		"retrying with " + oldToken,
		"cookie " + sessionSecret + " set",
		"GET /callback?next=" + url.QueryEscape(sessionSecret),
		"restic opened with " + backupKey,
		"connecting to " + databaseURL,
		"loaded key ZmFrZWtleWxpbmVvbmU=",
		"cache at redis://default:redis_fake_pw@cache.example.test:6379",
		"GET /hook?api_key=k_fake_query_value&page=2",
		"Authorization: Bearer bearer_fake_value_xyz",
		"peer 100.64.0.1 via fd00::1 at web.example.ts.net, upstream 10.0.0.1, lan 192.168.0.1",
	} {
		write(line, false)
	}
	// journalctl gives a message that isn't UTF-8 as its bytes.
	write([]int{'h', 'i', ' ', 0xff, 0xfe, '\a', '\t', '!'}, false)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	note := fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","MESSAGE":"Suppressed 1200 messages from docker.service"}`+"\n", since.Add(time.Minute).UnixMicro())
	if err := os.WriteFile(suppressed, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	journalctlOnPath(t, journal, suppressed)
}

// journalctlOnPath puts a journalctl on PATH that prints the entries in
// journal, only the newest when asked for --lines as the real one does,
// and those in suppressed when asked for journald's own.
func journalctlOnPath(t *testing.T, journal, suppressed string) {
	t.Helper()
	script := strings.NewReplacer("JOURNAL", journal, "SUPPRESSED", suppressed).Replace(`#!/bin/sh
lines=0
for arg in "$@"; do
	case "$arg" in
	--lines=*) lines=${arg#--lines=} ;;
	_SYSTEMD_UNIT=*) exec cat 'SUPPRESSED' ;;
	esac
done
if [ "$lines" -gt 0 ]; then
	exec tail -n "$lines" 'JOURNAL'
fi
exec cat 'JOURNAL'
`)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// tokenTail is what follows API_TOKEN's first nine bytes, which on its
// own no redaction can know for part of a secret.
var tokenTail = strings.TrimPrefix(apiToken, "tok_fake_")

// A long line whose first chunk fell outside the journal's newest 4,800
// entries starts partway through a secret, so it is left out.
func TestALogLineThatLostItsFirstChunkIsLeftOut(t *testing.T) {
	store := openStore(t)
	saveRevision(t, store, "web", "r7", nil, nil)
	inc := openIncident(t, store, "app:web", "web answers 502", opened)
	dir := t.TempDir()
	journal := filepath.Join(dir, "journal.json")
	var entries []string
	at := opened.Add(-time.Minute)
	write := func(container, message string, chunk map[string]string) {
		entry := map[string]string{"__REALTIME_TIMESTAMP": strconv.FormatInt(at.UnixMicro(), 10), "MESSAGE": message, "CONTAINER_NAME": container, "CONTAINER_ID_FULL": container, "BEDROCK_APP": "web"}
		maps.Copy(entry, chunk)
		b, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, string(b))
		at = at.Add(time.Millisecond)
	}
	chunk := func(ordinal int, last bool) map[string]string {
		c := map[string]string{"CONTAINER_PARTIAL_ID": "p1", "CONTAINER_PARTIAL_ORDINAL": strconv.Itoa(ordinal), "CONTAINER_PARTIAL_LAST": strconv.FormatBool(last)}
		if !last {
			c["CONTAINER_PARTIAL_MESSAGE"] = "true"
		}
		return c
	}
	// web-01 dumps its settings with API_TOKEN across its first two
	// chunks, then web-02 writes enough to push the first chunk out.
	write("web-01", strings.Repeat("x", 16<<10-len("API_TOKEN=tok_fake_"))+"API_TOKEN=tok_fake_", chunk(1, false))
	write("web-01", tokenTail+strings.Repeat("y", 16<<10-len(tokenTail)), chunk(2, false))
	write("web-01", " and the rest", chunk(3, true))
	for i := range maxContainers*linesPerContainer - 2 {
		write("web-02", fmt.Sprintf("GET /items/%d 200", i), nil)
	}
	if err := os.WriteFile(journal, []byte(strings.Join(entries, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	suppressed := filepath.Join(dir, "suppressed.json")
	if err := os.WriteFile(suppressed, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	journalctlOnPath(t, journal, suppressed)
	sealed := fakeSecrets{versions: map[string]map[int]map[string]string{"web": {2: {"API_TOKEN": apiToken}}}}

	e, err := Collect(context.Background(), inc, Sources{Store: store, Secrets: sealed, Journal: docker.Journal{}, Host: "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened }})
	if err != nil {
		t.Fatal(err)
	}
	if e.Redaction.Status != RedactionApplied || len(e.Errors) != 0 {
		t.Fatalf("redaction %q, errors %+v", e.Redaction.Status, e.Errors)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), tokenTail) {
		t.Fatal("the evidence holds the end of API_TOKEN")
	}
	if len(e.Logs) != 1 || e.Logs[0].Container != "web-02" || e.Logs[0].LinesKept != linesPerContainer {
		t.Fatalf("logs %+v", e.Logs)
	}
}

// The engine's tail counts Docker's 16 KiB chunks rather than lines,
// stdout and stderr share its output, and its read stops at 8 MiB, so a
// line can start or end partway through a secret; such lines are left
// out.
func TestEngineLinesThatMayBePartOfAnotherAreLeftOut(t *testing.T) {
	store := openStore(t)
	saveRevision(t, store, "web", "r7", nil, map[string]string{"web": "bedrock-web-web-r7"})
	inc := openIncident(t, store, "app:web", "web answers 502", opened)
	sealed := fakeSecrets{versions: map[string]map[int]map[string]string{"web": {2: {"API_TOKEN": apiToken}}}}
	// chunk is one of Docker's 16 KiB chunks.
	chunk := func(start, fill, end string) string {
		return start + strings.Repeat(fill, 16<<10-len(start)-len(end)) + end
	}
	cut := "API_TOKEN=tok_fake_"
	gets := func(n int) []string {
		var lines []string
		for i := range n {
			lines = append(lines, fmt.Sprintf("GET /items/%d 200\n", i))
		}
		return lines
	}
	for _, c := range []struct {
		name      string
		output    []string
		total     int
		first     string
		truncated string
	}{
		{
			name:   "a tail of whole lines is kept",
			output: gets(400),
			total:  400, first: "GET /items/0 200",
		},
		{
			// The line after the long one goes too: from the other
			// stream it could have been the long one's rest.
			name:   "the tail starts inside a line",
			output: append([]string{chunk("", "x", cut), chunk(tokenTail, "y", cut), tokenTail + " and the rest\n"}, gets(399)...),
			total:  398, first: "GET /items/1 200",
		},
		{
			name:   "a stderr line comes between a stdout line's chunks",
			output: []string{"starting\n", chunk("", "x", cut), "oops\n", tokenTail + " and the rest\n", "done\n"},
			total:  3, first: "starting",
		},
		{
			// Only a driver whose chunks are larger than the usual
			// 16 KiB fills 8 MiB within the tail.
			name:   "the read stops at 8 MiB inside a line",
			output: []string{strings.Repeat("c", docker.JournalReadLimit-25) + "\n", "short\n", "kept\n", apiToken + "\n", "later\n"},
			total:  1, first: "kept", truncated: "logs: the engine read of bedrock-web-web-r7 stopped at 8 MiB",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			engine := &fakeEngine{logs: map[string][]string{"bedrock-web-web-r7": c.output}}
			e, err := Collect(context.Background(), inc, Sources{Store: store, Secrets: sealed, Engine: engine, Host: "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened }})
			if err != nil {
				t.Fatal(err)
			}
			if e.Redaction.Status != RedactionApplied || len(e.Errors) != 0 {
				t.Fatalf("redaction %q, errors %+v", e.Redaction.Status, e.Errors)
			}
			b, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range []string{"tok_fa", tokenTail} {
				if strings.Contains(string(b), part) {
					t.Fatalf("the evidence holds %q", part)
				}
			}
			if len(e.Logs) != 1 || len(e.Logs[0].Lines) == 0 {
				t.Fatalf("%d logs", len(e.Logs))
			}
			if e.Logs[0].LinesTotal != c.total {
				t.Fatalf("%d lines, want %d", e.Logs[0].LinesTotal, c.total)
			}
			if first := e.Logs[0].Lines[0].Text; first != c.first {
				t.Fatalf("first line %.80q", first)
			}
			if c.truncated != "" && !slices.Contains(e.Truncated, c.truncated) {
				t.Fatalf("truncated %q", e.Truncated)
			}
		})
	}
}

func TestEachKindOfKeyReadsItsOwnSources(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	saveRevision(t, store, "web", "r7", nil, map[string]string{"web": "bedrock-web-web-r7", "worker": "bedrock-web-worker-r7", "cron": "bedrock-web-cron-r7"})
	saveChange(t, store, "op-web-1", apps.DeployKind, "web", apps.DeployInput{Revision: "r5"}, opened.Add(-30*time.Minute))
	saveChange(t, store, "op-web-2", apps.RollbackKind, "web", apps.RollbackInput{App: "web", Revision: "r5"}, opened.Add(-20*time.Minute))
	saveChange(t, store, "op-web-3", apps.DeployKind, "web", apps.DeployInput{Revision: "r7", Commit: "abc1234", Signer: "kyle@example.test"}, opened.Add(-5*time.Minute))
	saveChange(t, store, "op-web-4", apps.DeployKind, "web", apps.DeployInput{Revision: "r8"}, opened.Add(time.Minute))
	saveChange(t, store, "op-api-1", apps.DeployKind, "api", apps.DeployInput{Revision: "r2"}, opened.Add(-50*time.Minute))
	saveChange(t, store, "op-api-0", apps.DeployKind, "api", apps.DeployInput{Revision: "r1"}, opened.Add(-2*time.Hour))
	prior := map[string]int64{}
	for _, key := range []string{"app:web", "host:disk", "watch:backup", "skip:web", "hold:web"} {
		prior[key] = openIncident(t, store, key, "earlier", opened.Add(-24*time.Hour)).ID
	}
	for _, sig := range []state.Signal{
		{Hour: opened.Add(-time.Hour), App: "web", Metric: "requests", Value: 120, Samples: 60},
		{Hour: opened.Add(-time.Hour), App: "web", Metric: state.SignalBucketPrefix + "0.25", Value: 100, Samples: 60},
		{Hour: opened.Add(-time.Hour), App: "api", Metric: "requests", Value: 9, Samples: 60},
		// An hour after the opening, which a later collection leaves out.
		{Hour: opened.Add(time.Hour), App: "web", Metric: "requests", Value: 999, Samples: 60},
	} {
		if err := store.AddSignal(ctx, sig); err != nil {
			t.Fatal(err)
		}
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":{"indicator":"none","description":"All Systems Operational"}}`)
	}))
	defer page.Close()

	type sources struct {
		lastChange string
		journal    []docker.JournalQuery
		engine     []string
		logs       []string
		recent     []string
		history    []int64
		signals    []string
		upstream   string
	}
	appWeb := sources{
		lastChange: "op-web-3 r7 abc1234 kyle@example.test",
		journal:    []docker.JournalQuery{{App: "web", Since: opened.Add(-10 * time.Minute), Until: opened, Lines: 4800}},
		engine:     []string{"bedrock-web-cron-r7", "bedrock-web-worker-r7"},
		logs:       []string{"bedrock-web-worker-r7 engine 2", "bedrock-web-web-r7 journal 1"},
		history:    []int64{prior["app:web"]},
		signals:    []string{"requests 120, 60 samples"},
		upstream:   "status.example.test none",
	}
	only := func(key string) sources {
		return sources{history: []int64{prior[key]}, upstream: "status.example.test none"}
	}
	host := only("host:disk")
	host.recent = []string{"op-web-3", "op-web-2", "op-web-1", "op-api-1"}
	for _, c := range []struct {
		key  string
		want sources
	}{
		{"app:web", appWeb},
		{"host:disk", host},
		{"watch:backup", only("watch:backup")},
		{"skip:web", only("skip:web")},
		{"hold:web", only("hold:web")},
	} {
		t.Run(c.key, func(t *testing.T) {
			inc := openIncident(t, store, c.key, "now", opened)
			journal := &recordingJournal{containers: []docker.JournalContainer{{ID: "c1", Name: "bedrock-web-web-r7", Workload: "web", Revision: "r7", Lines: []docker.JournalLine{{At: opened.Add(-time.Minute), Stream: "stderr", Text: "panic"}}}}}
			engine := &fakeEngine{logs: map[string][]string{"bedrock-web-web-r7": {"from the engine\n"}, "bedrock-web-worker-r7": {"started\n", "working\n"}}}
			e, err := Collect(ctx, inc, Sources{
				Store: store, Secrets: fakeSecrets{}, Engine: engine, Journal: journal,
				Upstream: []Statuspage{{Name: "status.example.test", Base: page.URL}},
				Host:     "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened },
			})
			if err != nil {
				t.Fatal(err)
			}
			var got sources
			if lc := e.LastChange; lc != nil {
				got.lastChange = strings.Join([]string{lc.Operation, lc.Revision, lc.Commit, lc.Signer}, " ")
			}
			got.journal, got.engine = journal.queries, engine.asked
			for _, l := range e.Logs {
				got.logs = append(got.logs, fmt.Sprintf("%s %s %d", l.Container, l.Source, l.LinesKept))
			}
			for _, d := range e.RecentDeploys {
				got.recent = append(got.recent, d.Operation)
			}
			for _, p := range e.History.Incidents {
				got.history = append(got.history, p.ID)
			}
			for _, s := range e.History.Signals {
				got.signals = append(got.signals, s.Kind+" "+s.Detail)
			}
			for _, u := range e.Upstream {
				got.upstream = u.Name + " " + u.Indicator + u.Error
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("got  %+v\nwant %+v", got, c.want)
			}
			if len(e.Errors) != 0 || e.Redaction.Status != RedactionApplied {
				t.Fatalf("redaction %q, errors %+v", e.Redaction.Status, e.Errors)
			}
			since := opened.Add(-10 * time.Minute)
			for _, w := range engine.windows {
				if !w.Since.Equal(since) || !w.Until.Equal(opened) || !e.Window.Since.Equal(since) || !e.Window.Until.Equal(opened) {
					t.Fatalf("the engine was read from %s to %s, the window is %s to %s", w.Since, w.Until, e.Window.Since, e.Window.Until)
				}
			}
		})
	}
}

// A host incident lists the deploys of every app in the hour before it,
// without their errors or steps: those can hold another app's secrets,
// which a host incident's redaction doesn't know.
func TestAHostIncidentListsOtherAppsDeploysWithoutTheirErrors(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	const token = "tok_fake_api_registry_0000"
	started := opened.Add(-10 * time.Minute)
	in, err := json.Marshal(apps.DeployInput{Revision: "r2"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(kernel.PlanView{Kind: apps.DeployKind, Target: "api", Steps: []kernel.PlanStepView{{Index: 0, Name: "pull", Change: "update"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateOperation(ctx, state.NewOperation{ID: "op-api-1", Kind: apps.DeployKind, Target: "api", Input: in, Plan: plan, StepNames: []string{"pull"}, CreatedAt: started}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, "op-api-1", "test", started, started.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.StepStarted(ctx, "op-api-1", 0, started); err != nil {
		t.Fatal(err)
	}
	if err := store.StepFinished(ctx, "op-api-1", 0, state.StepFailed, "the registry refused "+token, "", started.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(ctx, "op-api-1", state.Failed, "pull: the registry refused "+token, nil, started.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	inc := openIncident(t, store, "host:disk", "the disk is 95% full", opened)

	e, err := Collect(ctx, inc, Sources{Store: store, Secrets: fakeSecrets{}, Host: "web.example.test", CollectedBy: "test", Now: func() time.Time { return opened }})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.RecentDeploys) != 1 {
		t.Fatalf("recent deploys %+v", e.RecentDeploys)
	}
	if d := e.RecentDeploys[0]; d.Operation != "op-api-1" || d.App != "api" || d.Revision != "r2" || d.Outcome != "failed" || d.Error != "" || d.Steps != nil {
		t.Fatalf("recent deploy %+v", d)
	}
	stateDir := t.TempDir()
	if err := Save(stateDir, e); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filepath.Join(Dir(stateDir, inc.ID), EvidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(file), token) {
		t.Fatal("evidence.json holds api's token")
	}
}

// fakeSecrets holds each app's secrets by version, the highest current,
// or fails every read with err.
type fakeSecrets struct {
	versions map[string]map[int]map[string]string
	err      error
}

func (f fakeSecrets) LoadCurrent(app string) (map[string]string, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	current := 0
	for v := range f.versions[app] {
		current = max(current, v)
	}
	return f.versions[app][current], current, nil
}

func (f fakeSecrets) Versions(app string) ([]secrets.VersionInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []secrets.VersionInfo
	for _, v := range slices.Sorted(maps.Keys(f.versions[app])) {
		out = append(out, secrets.VersionInfo{Version: v, Names: slices.Sorted(maps.Keys(f.versions[app][v]))})
	}
	return out, nil
}

func (f fakeSecrets) Load(app string, version int) (map[string]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	values, ok := f.versions[app][version]
	if !ok {
		return nil, fmt.Errorf("%s has no secrets version %d", app, version)
	}
	return values, nil
}

// recordingJournal gives the same containers to every read and records
// what it was asked.
type recordingJournal struct {
	containers []docker.JournalContainer
	queries    []docker.JournalQuery
}

func (j *recordingJournal) Read(ctx context.Context, q docker.JournalQuery) ([]docker.JournalContainer, error) {
	j.queries = append(j.queries, q)
	return j.containers, nil
}

func (j *recordingJournal) Suppressed(ctx context.Context, since, until time.Time) ([]docker.JournalSuppressed, error) {
	return nil, nil
}

// fakeEngine has the output of the containers in logs, each entry as
// Docker logged it, and no others. Its tail counts entries, as Docker's
// does.
type fakeEngine struct {
	logs  map[string][]string
	asked []string
	// windows are the times each read was bounded to.
	windows []Window
}

func (f *fakeEngine) Logs(ctx context.Context, name string, opts docker.LogOptions, w io.Writer) error {
	f.asked = append(f.asked, name)
	f.windows = append(f.windows, Window{Since: opts.Since, Until: opts.Until})
	entries, ok := f.logs[name]
	if !ok {
		return errdefs.ErrNotFound
	}
	if n, err := strconv.Atoi(opts.Tail); err == nil {
		entries = entries[max(0, len(entries)-n):]
	}
	_, err := io.WriteString(w, strings.Join(entries, ""))
	return err
}

func openStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// saveRevision records app's active revision, whose web workload has env.
func saveRevision(t *testing.T, store *state.Store, app, id string, env, containers map[string]string) {
	t.Helper()
	m, err := json.Marshal(manifest.Manifest{App: app, Workloads: map[string]manifest.Workload{"web": {Env: env}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRevision(context.Background(), state.Revision{App: app, ID: id, Status: state.RevisionActive, Manifest: m, Containers: containers, SecretsVersion: 2, CreatedAt: opened.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

// saveChange records a deploy or rollback that started at started and
// succeeded, with a step for each note.
func saveChange(t *testing.T, store *state.Store, id, kind, app string, input any, started time.Time, notes ...string) {
	t.Helper()
	ctx := context.Background()
	in, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	view := kernel.PlanView{Kind: kind, Target: app}
	var names []string
	for i, note := range notes {
		names = append(names, "step-"+strconv.Itoa(i+1))
		view.Steps = append(view.Steps, kernel.PlanStepView{Index: i, Name: names[i], Change: "update", Note: note})
	}
	plan, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateOperation(ctx, state.NewOperation{ID: id, Kind: kind, Target: app, Input: in, Plan: plan, StepNames: names, CreatedAt: started}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, id, "test", started, started.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for i := range notes {
		if err := store.StepStarted(ctx, id, i, started); err != nil {
			t.Fatal(err)
		}
		if err := store.StepFinished(ctx, id, i, state.StepSucceeded, "", "", started.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Finish(ctx, id, state.Succeeded, "", nil, started.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func openIncident(t *testing.T, store *state.Store, key, message string, at time.Time) state.Incident {
	t.Helper()
	inc := state.Incident{Key: key, Subject: key + " is failing", Severity: state.SeverityCritical, Message: message, OpenedAt: at, Observations: 1}
	id, err := store.OpenIncident(context.Background(), inc)
	if err != nil {
		t.Fatal(err)
	}
	inc.ID = id
	return inc
}
