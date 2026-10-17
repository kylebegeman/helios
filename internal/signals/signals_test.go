package signals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/state"
)

const scrape1 = `# HELP caddy_http_requests_total Counter of HTTP(S) requests made.
# TYPE caddy_http_requests_total counter
caddy_http_requests_total{handler="subroute",host="hello.lane.begam.in",server="helios"} 10
caddy_http_request_duration_seconds_count{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 8
caddy_http_request_duration_seconds_count{code="502",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 2
caddy_http_request_duration_seconds_sum{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 0.4
caddy_http_request_duration_seconds_bucket{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios",le="0.05"} 6
caddy_http_request_duration_seconds_bucket{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios",le="0.25"} 8
caddy_http_request_duration_seconds_bucket{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios",le="+Inf"} 8
caddy_http_response_size_bytes_sum{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 800
caddy_http_requests_total{handler="subroute",host="nobody.example",server="helios"} 99
caddy_http_requests_total{handler="reverse_proxy",host="hello.lane.begam.in",server="helios"} 1000
`

const scrape2 = `caddy_http_requests_total{handler="subroute",host="hello.lane.begam.in",server="helios"} 25
caddy_http_request_duration_seconds_count{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 22
caddy_http_request_duration_seconds_count{code="502",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 3
caddy_http_request_duration_seconds_count{code="503",handler="subroute",host="hello.lane.begam.in",method="POST",server="helios"} 2
caddy_http_request_duration_seconds_sum{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 1.9
caddy_http_request_duration_seconds_bucket{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios",le="0.05"} 16
caddy_http_request_duration_seconds_bucket{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios",le="0.25"} 22
caddy_http_request_duration_seconds_bucket{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios",le="+Inf"} 22
caddy_http_response_size_bytes_sum{code="200",handler="subroute",host="hello.lane.begam.in",method="GET",server="helios"} 2000
`

func TestParsesPrometheusText(t *testing.T) {
	series := ParseMetrics(scrape1)
	if len(series) != 10 {
		t.Fatalf("parsed %d series", len(series))
	}
	first := series[0]
	if first.Name != "caddy_http_requests_total" || first.Labels["host"] != "hello.lane.begam.in" || first.Value != 10 {
		t.Fatalf("%+v", first)
	}
	if series[4].Labels["le"] != "0.05" || series[4].Value != 6 {
		t.Fatalf("%+v", series[4])
	}
}

func TestTrafficRollsUpDeltasAfterPriming(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 9, 19, 16, 30, 0, 0, time.UTC)
	s := &Sampler{Store: store, Log: func(string, ...any) {}}
	hosts := map[string]string{"hello.lane.begam.in": "hello"}
	if err := s.traffic(ctx, now, ParseMetrics(scrape1), hosts); err != nil {
		t.Fatal(err)
	}
	if rows, _ := store.Signals(ctx, "hello", now.Add(-time.Hour)); len(rows) != 0 {
		t.Fatalf("the first round must only prime: %+v", rows)
	}
	if err := s.traffic(ctx, now.Add(time.Minute), ParseMetrics(scrape2), hosts); err != nil {
		t.Fatal(err)
	}
	rows, _ := store.Signals(ctx, "hello", now.Add(-time.Hour))
	sum := Summarize(rows)
	// The 503 series appeared after priming, so it counts in full.
	if sum.Requests != 15 || sum.Errors != 3 || sum.Bytes != 1200 || sum.Hours != 1 {
		t.Fatalf("%+v", sum)
	}
	// 1.5 s over the 17 responses the histogram saw; 14 finished within
	// 0.25 s, 10 within 0.05 s, so the 95th percentile falls to the last bucket.
	if math.Abs(sum.AvgMS-1500.0/17) > 0.01 || sum.P95MS != 250 {
		t.Fatalf("latency: %+v", sum)
	}
	// The edge restarts: counters fall back to small numbers and count from zero.
	if err := s.traffic(ctx, now.Add(2*time.Minute), ParseMetrics(scrape1), hosts); err != nil {
		t.Fatal(err)
	}
	rows, _ = store.Signals(ctx, "hello", now.Add(-time.Hour))
	if sum := Summarize(rows); sum.Requests != 25 {
		t.Fatalf("after a reset: %+v", sum)
	}
	if rows, _ := store.Signals(ctx, "nobody", now.Add(-time.Hour)); len(rows) != 0 {
		t.Fatal("an unknown host was rolled up")
	}
}

func TestSummarizeAveragesResourcesPerWorkload(t *testing.T) {
	hour := time.Date(2026, 9, 19, 16, 0, 0, 0, time.UTC)
	rows := []state.Signal{
		{Hour: hour, App: "a", Key: "web", Metric: state.SignalCPUPercent, Value: 30, Samples: 3},
		{Hour: hour, App: "a", Key: "worker", Metric: state.SignalCPUPercent, Value: 5, Samples: 1},
		{Hour: hour, App: "a", Key: "web", Metric: state.SignalMemoryBytes, Value: 300, Samples: 3},
		{Hour: hour, App: "a", Key: "web", Metric: state.SignalMemoryMax, Value: 150},
		{Hour: hour.Add(-time.Hour), App: "a", Key: "", Metric: state.SignalDiskBytes, Value: 5000},
		{Hour: hour, App: "a", Key: "", Metric: state.SignalDiskBytes, Value: 7000},
	}
	sum := Summarize(rows)
	if sum.CPUPercent != 15 || sum.MemoryBytes != 100 || sum.MemoryMax != 150 || sum.DiskBytes != 7000 || sum.Hours != 2 {
		t.Fatalf("%+v", sum)
	}
}

func TestMetricsRejectNonFiniteSamplesAndDecodeEscapedLabels(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "-Inf", "Inf"} {
		if got := ParseMetrics("metric " + value); len(got) != 0 {
			t.Fatalf("nonfinite sample accepted: %+v", got)
		}
	}
	got := ParseMetrics(`metric{label="one\",two\\three\nfour",other="value"} 2`)
	if len(got) != 1 || got[0].Labels["label"] != "one\",two\\three\nfour" || got[0].Labels["other"] != "value" {
		t.Fatalf("escaped labels changed series identity: %+v", got)
	}
	for _, input := range []string{`metric{a="unterminated} 1`, `metric{a="one",a="two"} 1`} {
		if got := ParseMetrics(input); len(got) != 0 {
			t.Fatalf("malformed label set accepted: %+v", got)
		}
	}
}

func TestMetricSeriesKeysCannotCollideOnLabelDelimiters(t *testing.T) {
	a := Series{Name: "metric", Labels: map[string]string{"a": "b,c=d"}}
	b := Series{Name: "metric", Labels: map[string]string{"a": "b", "c": "d"}}
	if a.key() == b.key() {
		t.Fatal("different label sets share a counter identity")
	}
}

func TestSampleMeasuresDataWithoutWorkloadContainers(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manifest := json.RawMessage(`{"app":"data","data":{"volumes":{"uploads":{}},"postgres":{"version":"17"},"objects":{}},"workloads":{"cron":{"kind":"cron","image":"x","schedule":"0 * * * *"}}}`)
	if err := store.SaveRevision(ctx, state.Revision{App: "data", ID: "r1", Status: state.RevisionActive, Manifest: manifest, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		path := strings.TrimPrefix(request.URL.Path, "/v1.44")
		if path == "/_ping" {
			w.Header().Set("API-Version", "1.44")
			_, _ = w.Write([]byte("OK"))
			return
		}
		if name, found := strings.CutPrefix(path, "/volumes/"); found {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"Name": name, "Mountpoint": "/data/" + name})
			return
		}
		http.NotFound(w, request)
	}))
	defer server.Close()
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(server.URL, "http"))
	t.Setenv("DOCKER_API_VERSION", "1.44")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	paths := map[string]bool{}
	failObjects := false
	now := time.Now().UTC()
	s := &Sampler{Store: store, Now: func() time.Time { return now }, Log: func(string, ...any) {}, Connect: docker.Connect,
		DiskUsage: func(_ context.Context, path string) (int64, error) {
			paths[path] = true
			if failObjects && strings.HasSuffix(path, "bedrock-data-objects") {
				return 0, errors.New("object volume unavailable")
			}
			return 100, nil
		}}
	if err := s.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := store.Signals(ctx, "data", now.Add(-time.Hour))
	if err != nil || len(rows) != 1 || rows[0].Metric != state.SignalDiskBytes || rows[0].Value != 300 || len(paths) != 3 {
		t.Fatalf("data-only app did not measure database, objects and volume: rows=%+v, paths=%v, err=%v", rows, paths, err)
	}
	// A failed volume measurement cannot be reported as the whole app's
	// disk total. Keep the previous honest sample until a complete scan.
	failObjects = true
	now = now.Add(time.Hour)
	if err := s.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = store.Signals(ctx, "data", now.Truncate(time.Hour))
	if err != nil || len(rows) != 0 {
		t.Fatalf("partial volume sizes became a misleading app total: %+v, %v", rows, err)
	}
}

func TestSampleDoesNotAttributeSharedHostTrafficToOneApp(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, name := range []string{"first", "second"} {
		body := json.RawMessage(`{"app":"` + name + `","workloads":{"web":{"kind":"web","image":"x","routes":[{"host":"shared.example","path":"/` + name + `"}]}}}`)
		if err := store.SaveRevision(ctx, state.Revision{App: name, ID: "r1", Status: state.RevisionActive, Manifest: body, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	metrics := `caddy_http_requests_total{handler="subroute",host="shared.example"} 10`
	s := &Sampler{Store: store, Now: func() time.Time { return now }, Log: func(string, ...any) {}, Metrics: func(context.Context) ([]byte, error) { return []byte(metrics), nil }}
	if err := s.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	metrics = strings.Replace(metrics, "10", "20", 1)
	if err := s.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := store.Signals(ctx, "", now.Add(-time.Hour))
	if err != nil || len(rows) != 0 {
		t.Fatalf("shared traffic was assigned to one app: %+v, %v", rows, err)
	}
}

func TestMetricsPreserveLabelsAndIgnoreSampleTimestamps(t *testing.T) {
	input := " \t# a comment\n\n" +
		" plain_metric\u2003-1.25e+2\t1790812800000 \n" +
		`labeled_metric{ host = "app.example.com",path="/api/a,b?next=\"value\"",note="slash\\and\nline",}` + "\t2.5 1790812800000\n" +
		"empty_labels{} 3\n" +
		"missing_value\n"
	got := ParseMetrics(input)
	if len(got) != 3 {
		t.Fatalf("got %d samples, want 3: %+v", len(got), got)
	}
	if got[0].Name != "plain_metric" || got[0].Value != -125 || got[0].Labels == nil || len(got[0].Labels) != 0 {
		t.Fatalf("plain sample with Unicode whitespace: %+v", got[0])
	}
	if got[1].Name != "labeled_metric" || got[1].Value != 2.5 || len(got[1].Labels) != 3 ||
		got[1].Labels["host"] != "app.example.com" || got[1].Labels["path"] != "/api/a,b?next=\"value\"" || got[1].Labels["note"] != "slash\\and\nline" {
		t.Fatalf("escaped sample with a timestamp: %+v", got[1])
	}
	if got[2].Name != "empty_labels" || got[2].Value != 3 || got[2].Labels == nil || len(got[2].Labels) != 0 {
		t.Fatalf("empty label set: %+v", got[2])
	}
}

func TestMetricsRejectMalformedLabelsWithoutDroppingLaterSamples(t *testing.T) {
	for _, input := range []string{
		`metric{label="unfinished} 1`,
		`metric{label="escaped\"} 1`,
		`metric{label="bad\qescape"} 1`,
		`metric{label="one"label="two"} 1`,
		`metric{label="one", label = "two"} 1`,
		`metric{= "value"} 1`,
		`metric{label} 1`,
		`metric{,label="value"} 1`,
		`metric{label="value",,other="value"} 1`,
		`metric{label="value" 1`,
		`metric{label="value"}`,
	} {
		t.Run(input, func(t *testing.T) {
			got := ParseMetrics(input + "\nafter 7\n")
			if len(got) != 1 || got[0].Name != "after" || got[0].Value != 7 {
				t.Fatalf("malformed sample affected later samples: %+v", got)
			}
		})
	}
}

func TestMetricsAcceptLongLinesWithinTheExistingLimit(t *testing.T) {
	value := strings.Repeat("x", 128<<10)
	input := "long_metric{label=\"" + value + "\"} 42\nafter 7\n"
	got := ParseMetrics(input)
	if len(got) != 2 || got[0].Name != "long_metric" || got[0].Value != 42 || got[0].Labels["label"] != value || got[1].Name != "after" {
		t.Fatalf("valid long line was truncated or skipped: %d samples", len(got))
	}
}

func TestMetricsStopAtOversizedLines(t *testing.T) {
	input := "before 1\nlong_metric{label=\"" + strings.Repeat("x", 1<<20) + "\"} 42\nafter 7\n"
	got := ParseMetrics(input)
	if len(got) != 1 || got[0].Name != "before" || got[0].Value != 1 {
		t.Fatalf("oversized line changed the existing scrape limit: %d samples", len(got))
	}
}

func TestMetricSeriesKeysPreserveAllLabelsIndependentlyOfMapOrder(t *testing.T) {
	first := Series{Name: "metric", Labels: map[string]string{
		"host": "app.example.com", "handler": "subroute", "extra": "one\x00,two=three\"four\\five",
	}}
	second := Series{Name: "metric", Labels: map[string]string{}}
	for _, key := range []string{"extra", "handler", "host"} {
		second.Labels[key] = first.Labels[key]
	}
	want := first.key()
	for range 100 {
		if got := second.key(); got != want {
			t.Fatal("the same labels in a different map order changed series identity")
		}
	}
	second.Labels["extra"] += "different"
	if second.key() == want {
		t.Fatal("an extra label was omitted from series identity")
	}
	// More labels than the usual Caddy set must still all participate.
	for i := range 20 {
		first.Labels[fmt.Sprintf("extra_%d", i)] = fmt.Sprint(i)
	}
	second.Labels = make(map[string]string, len(first.Labels))
	for key, value := range first.Labels {
		second.Labels[key] = value
	}
	if first.key() != second.key() {
		t.Fatal("a large label set changed identity with map order")
	}
	second.Labels["extra_19"] = "changed"
	if first.key() == second.key() {
		t.Fatal("a label outside the usual Caddy set was omitted")
	}
}

func TestMetricSeriesKeysCannotCollideOnNamesOrArbitraryLabelBytes(t *testing.T) {
	for _, pair := range [][2]Series{
		{{Name: "metric", Labels: nil}, {Name: "metric", Labels: map[string]string{}}},
		{{Name: "a", Labels: map[string]string{"bc": "d"}}, {Name: "ab", Labels: map[string]string{"c": "d"}}},
		{{Name: "metric\x00a", Labels: map[string]string{"b": "c"}}, {Name: "metric", Labels: map[string]string{"a\x00b": "c"}}},
		{{Name: "metric", Labels: map[string]string{"key\x00value": ""}}, {Name: "metric", Labels: map[string]string{"key": "value\x00"}}},
		{{Name: "metric", Labels: map[string]string{"key": "value,other=label"}}, {Name: "metric", Labels: map[string]string{"key": "value", "other": "label"}}},
		{{Name: "metric{\"key\":\"value\"}", Labels: map[string]string{}}, {Name: "metric", Labels: map[string]string{"key": "value{}"}}},
		{{Name: strings.Repeat("name", 40), Labels: map[string]string{strings.Repeat("key", 50): strings.Repeat("value", 4000)}}, {Name: strings.Repeat("name", 40), Labels: map[string]string{strings.Repeat("key", 50): strings.Repeat("value", 4000) + "x"}}},
		{{Name: "metric", Labels: map[string]string{"key": "\xfe"}}, {Name: "metric", Labels: map[string]string{"key": "\xff"}}},
	} {
		if pair[0].key() == pair[1].key() {
			t.Fatalf("distinct metric identities collided: %#v and %#v", pair[0], pair[1])
		}
	}
}

func TestTrafficSkipsMetricsThatDoNotProduceRollups(t *testing.T) {
	labels := func() map[string]string {
		return map[string]string{"host": "app.example.com", "handler": "subroute"}
	}
	series := []Series{{Name: "caddy_http_requests_total", Labels: labels(), Value: 10}}
	for _, name := range []string{
		"caddy_http_response_size_bytes_count", "caddy_http_response_size_bytes_bucket",
		"caddy_http_requests_in_flight", "caddy_http_unknown_total", "go_goroutines",
	} {
		series = append(series, Series{Name: name, Labels: labels(), Value: 10})
	}
	for _, bound := range []string{"", "+Inf", "NaN", "-1", "invalid"} {
		m := labels()
		m["le"] = bound
		series = append(series, Series{Name: "caddy_http_request_duration_seconds_bucket", Labels: m, Value: 10})
	}
	validBucket := labels()
	validBucket["le"] = "0.25"
	series = append(series, Series{Name: "caddy_http_request_duration_seconds_bucket", Labels: validBucket, Value: 10})
	sampler := &Sampler{}
	hostApps := map[string]string{"app.example.com": "app"}
	if err := sampler.traffic(context.Background(), time.Now(), series, hostApps); err != nil {
		t.Fatal(err)
	}
	if len(sampler.counters) != 2 {
		t.Fatalf("retained %d counters, want only the request counter and finite duration bucket", len(sampler.counters))
	}
	// Unsupported metrics may change freely without producing a write. The
	// request and valid duration bucket remain unchanged, so no Store is used.
	for i := 1; i < len(series)-1; i++ {
		series[i].Value++
	}
	if err := sampler.traffic(context.Background(), time.Now(), series, hostApps); err != nil {
		t.Fatal(err)
	}
}

func TestTrafficTracksExtraLabelsResetsAndEviction(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sampler := &Sampler{Store: store}
	hosts := map[string]string{"app.example.com": "app"}
	sample := func(source string, value float64) Series {
		return Series{Name: "caddy_http_requests_total", Labels: map[string]string{
			"host": "app.example.com", "handler": "subroute", "extra_source": source,
		}, Value: value}
	}
	for i, round := range [][]Series{
		{sample("one\x00,=", 10), sample("two", 20)}, // Prime both identities.
		{sample("two", 25), sample("one\x00,=", 15)}, // Each increases by five.
		{sample("one\x00,=", 3), sample("three", 7)}, // Reset, new series, evict two.
		{sample("two", 4), sample("one\x00,=", 5)},   // Reappearing two counts in full.
	} {
		if err := sampler.traffic(ctx, now.Add(time.Duration(i)*time.Minute), round, hosts); err != nil {
			t.Fatal(err)
		}
		if len(sampler.counters) != 2 {
			t.Fatalf("round %d retained %d counters, want 2 present series", i, len(sampler.counters))
		}
	}
	rows, err := store.Signals(ctx, "app", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Metric != state.SignalRequests || rows[0].Value != 26 || rows[0].Samples != 3 {
		t.Fatalf("extra labels, resets or eviction changed deltas: %+v", rows)
	}
}
