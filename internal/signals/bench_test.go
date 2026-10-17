package signals

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

var benchmarkSeries []Series
var benchmarkSummary Summary

// These workloads retain the unrelated runtime metrics and handler/response-size
// series present in a Caddy scrape. Hosts have two methods, three status codes,
// eight duration buckets and five response-size buckets. Application metrics
// add escaped path labels, which ParseMetrics must also preserve.
func BenchmarkParseMetrics(b *testing.B) {
	for _, hosts := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("Hosts%d", hosts), func(b *testing.B) {
			fixture := benchmarkMetrics(hosts, 10)
			fixture.check(b)
			b.ReportAllocs()
			b.SetBytes(int64(len(fixture.text)))
			for b.Loop() {
				benchmarkSeries = ParseMetrics(fixture.text)
			}
			b.ReportMetric(float64(len(fixture.series)), "series/op")
		})
	}
}

// An unchanged scrape is common for idle applications. This isolates series
// identity, filtering and counter retention from SQLite and metrics parsing.
func BenchmarkTrafficUnchanged(b *testing.B) {
	for _, hosts := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("Hosts%d", hosts), func(b *testing.B) {
			fixture := benchmarkMetrics(hosts, 10)
			series := fixture.check(b)
			sampler := &Sampler{}
			ctx := context.Background()
			if err := sampler.traffic(ctx, benchmarkHour, series, fixture.hostApps); err != nil {
				b.Fatal(err)
			}
			// No Store is needed: a repeated snapshot must produce no writes.
			if err := sampler.traffic(ctx, benchmarkHour, series, fixture.hostApps); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := sampler.traffic(ctx, benchmarkHour, series, fixture.hostApps); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(series)), "series/op")
		})
	}
}

// TrafficRollups measures a complete minute's counter processing and durable
// hourly upserts on a temporary, file-backed SQLite store. Advancing the input
// counters is included; scrape generation and parsing are outside the timer.
func BenchmarkTrafficRollups(b *testing.B) {
	for _, hosts := range []int{1, 10} {
		b.Run(fmt.Sprintf("Hosts%d", hosts), func(b *testing.B) {
			fixture := benchmarkMetrics(hosts, 10)
			series := fixture.check(b)
			increments := make([]float64, len(series))
			for i := range series {
				increments[i] = series[i].Value / 10
			}
			store, err := state.Open(filepath.Join(b.TempDir(), "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = store.Close() })
			sampler := &Sampler{Store: store}
			ctx := context.Background()
			if err := sampler.traffic(ctx, benchmarkHour, series, fixture.hostApps); err != nil {
				b.Fatal(err)
			}
			advance := func() {
				for i := range series {
					series[i].Value += increments[i]
				}
			}
			advance()
			if err := sampler.traffic(ctx, benchmarkHour, series, fixture.hostApps); err != nil {
				b.Fatal(err)
			}
			checkTrafficBenchmark(b, store, hosts, 1)
			b.ReportAllocs()
			for b.Loop() {
				advance()
				if err := sampler.traffic(ctx, benchmarkHour, series, fixture.hostApps); err != nil {
					b.Fatal(err)
				}
			}
			checkTrafficBenchmark(b, store, hosts, b.N+1)
			b.ReportMetric(float64(len(series)), "series/op")
			b.ReportMetric(float64(hosts*12), "rollups/op")
		})
	}
}

func BenchmarkSummarize(b *testing.B) {
	for _, hours := range []int{24, 7 * 24, 90 * 24} {
		b.Run(fmt.Sprintf("Hours%d", hours), func(b *testing.B) {
			rows, want := benchmarkSignalRows(hours)
			if got := Summarize(rows); got != want {
				b.Fatalf("summary = %+v, want %+v", got, want)
			}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkSummary = Summarize(rows)
			}
			b.ReportMetric(float64(len(rows)), "rows/op")
		})
	}
}

var benchmarkHour = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

type metricsBenchmarkFixture struct {
	text     string
	series   []Series
	hostApps map[string]string
}

func (fixture metricsBenchmarkFixture) check(tb testing.TB) []Series {
	tb.Helper()
	got := ParseMetrics(fixture.text)
	if !reflect.DeepEqual(got, fixture.series) {
		tb.Fatalf("parsed scrape differs from generated values and labels: got %d series, want %d", len(got), len(fixture.series))
	}
	return got
}

func benchmarkMetrics(hosts, tick int) metricsBenchmarkFixture {
	fixture := metricsBenchmarkFixture{hostApps: make(map[string]string, hosts)}
	var text strings.Builder
	emit := func(name string, labels map[string]string, value float64) {
		// A fixed label order makes the textual fixture deterministic, while
		// expected values are independent of the parser's implementation.
		fmt.Fprint(&text, name)
		if len(labels) > 0 {
			text.WriteByte('{')
			first := true
			for _, key := range []string{"code", "handler", "host", "method", "path", "server", "le", "quantile", "version"} {
				if value, ok := labels[key]; ok {
					if !first {
						text.WriteByte(',')
					}
					first = false
					fmt.Fprintf(&text, "%s=%s", key, strconv.Quote(value))
				}
			}
			text.WriteByte('}')
		}
		fmt.Fprintf(&text, " %s\n", strconv.FormatFloat(value, 'g', -1, 64))
		if labels == nil {
			labels = map[string]string{}
		}
		fixture.series = append(fixture.series, Series{Name: name, Labels: labels, Value: value})
	}
	text.WriteString("# HELP go_goroutines Number of goroutines that currently exist.\n# TYPE go_goroutines gauge\n")
	for _, name := range []string{
		"go_goroutines", "go_threads", "go_memstats_alloc_bytes", "go_memstats_alloc_bytes_total",
		"go_memstats_buck_hash_sys_bytes", "go_memstats_frees_total", "go_memstats_gc_sys_bytes",
		"go_memstats_heap_alloc_bytes", "go_memstats_heap_idle_bytes", "go_memstats_heap_inuse_bytes",
		"go_memstats_heap_objects", "go_memstats_heap_released_bytes", "go_memstats_heap_sys_bytes",
		"go_memstats_last_gc_time_seconds", "go_memstats_mallocs_total", "go_memstats_mcache_inuse_bytes",
		"go_memstats_mcache_sys_bytes", "go_memstats_mspan_inuse_bytes", "go_memstats_mspan_sys_bytes",
		"go_memstats_next_gc_bytes", "go_memstats_other_sys_bytes", "go_memstats_stack_inuse_bytes",
		"go_memstats_stack_sys_bytes", "go_memstats_sys_bytes", "process_cpu_seconds_total",
		"process_open_fds", "process_resident_memory_bytes", "process_start_time_seconds",
	} {
		emit(name, nil, 100000*float64(tick))
	}
	emit("go_info", map[string]string{"version": "go1.26.0"}, 1)
	for _, quantile := range []string{"0", "0.25", "0.5", "0.75", "1"} {
		emit("go_gc_duration_seconds", map[string]string{"quantile": quantile}, 0.0001)
	}
	for host := range hosts {
		hostname := fmt.Sprintf("app-%03d.example.com", host)
		fixture.hostApps[hostname] = fmt.Sprintf("app-%03d", host)
		labels := func(code, method, handler string) map[string]string {
			m := map[string]string{"handler": handler, "host": hostname, "server": "helios"}
			if code != "" {
				m["code"], m["method"] = code, method
			}
			return m
		}
		emit("caddy_http_requests_total", labels("", "", "subroute"), 21200*float64(tick))
		emit("caddy_http_requests_total", labels("", "", "reverse_proxy"), 21200*float64(tick))
		for codeIndex, code := range []string{"200", "404", "502"} {
			count := []int{10000, 500, 100}[codeIndex]
			for _, method := range []string{"GET", "POST"} {
				value := float64(count * tick)
				emit("caddy_http_request_duration_seconds_count", labels(code, method, "subroute"), value)
				emit("caddy_http_request_duration_seconds_sum", labels(code, method, "subroute"), value*0.05)
				emit("caddy_http_response_size_bytes_count", labels(code, method, "subroute"), value)
				emit("caddy_http_response_size_bytes_sum", labels(code, method, "subroute"), value*1024)
				for bucket, bound := range []string{"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "1", "+Inf"} {
					m := labels(code, method, "subroute")
					m["le"] = bound
					fraction := []int{5, 20, 50, 80, 90, 99, 100, 100}[bucket]
					emit("caddy_http_request_duration_seconds_bucket", m, value*float64(fraction)/100)
				}
				for bucket, bound := range []string{"256", "1024", "4096", "16384", "+Inf"} {
					m := labels(code, method, "subroute")
					m["le"] = bound
					fraction := []int{20, 80, 99, 100, 100}[bucket]
					emit("caddy_http_response_size_bytes_bucket", m, value*float64(fraction)/100)
				}
			}
		}
		for _, path := range []string{"/api/items", "/api/search?filter=\"active\",next=\\page\n"} {
			emit("app_http_requests_total", map[string]string{"host": hostname, "path": path}, 100*float64(tick))
		}
	}
	emit("caddy_http_requests_total", map[string]string{"handler": "subroute", "host": "unknown.example.com", "server": "helios"}, 100*float64(tick))
	fixture.text = text.String()
	return fixture
}

func checkTrafficBenchmark(tb testing.TB, store *state.Store, hosts, rounds int) {
	tb.Helper()
	rows, err := store.Signals(context.Background(), "", benchmarkHour)
	if err != nil {
		tb.Fatal(err)
	}
	if len(rows) != hosts*12 {
		tb.Fatalf("got %d hourly rollups, want %d", len(rows), hosts*12)
	}
	for host := range hosts {
		app := fmt.Sprintf("app-%03d", host)
		var appRows []state.Signal
		for _, row := range rows {
			if row.App == app {
				appRows = append(appRows, row)
			}
		}
		want := Summary{Requests: int64(21200 * rounds), Errors: int64(200 * rounds), AvgMS: 50, P95MS: 250, Bytes: int64(21200 * 1024 * rounds), Hours: 1}
		if got := Summarize(appRows); got != want {
			tb.Fatalf("%s summary = %+v, want %+v", app, got, want)
		}
	}
}

func benchmarkSignalRows(hours int) ([]state.Signal, Summary) {
	const mebibyte = 1 << 20
	rows := make([]state.Signal, 0, hours*34)
	for hour := range hours {
		at := benchmarkHour.Add(time.Duration(hour) * time.Hour)
		add := func(key, metric string, value float64, samples int) {
			rows = append(rows, state.Signal{Hour: at, App: "app", Key: key, Metric: metric, Value: value, Samples: samples})
		}
		for _, host := range []string{"app.example.com", "www.app.example.com"} {
			add(host, state.SignalRequests, 1000, 60)
			add(host, state.SignalErrors, 10, 60)
			add(host, state.SignalObserved, 1000, 60)
			add(host, state.SignalDurationMS, 50000, 60)
			add(host, state.SignalBytes, 1024000, 60)
			for i, bound := range []string{"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "1"} {
				count := []float64{50, 200, 500, 800, 900, 990, 1000}[i]
				add(host, state.SignalBucketPrefix+bound, count, 60)
			}
		}
		for workload, name := range []string{"web", "worker", "scheduler"} {
			add(name, state.SignalCPUPercent, float64((workload+1)*10*60), 60)
			add(name, state.SignalMemoryBytes, float64((workload+1)*64*mebibyte*60), 60)
			add(name, state.SignalMemoryMax, float64(((workload+1)*64+1)*mebibyte), 1)
		}
		add("", state.SignalDiskBytes, float64((10240+hour)*mebibyte), 1)
	}
	return rows, Summary{
		Requests: int64(hours * 2000), Errors: int64(hours * 20), AvgMS: 50, P95MS: 250,
		Bytes: int64(hours * 2048000), CPUPercent: 60, MemoryBytes: 384 * mebibyte,
		MemoryMax: 193 * mebibyte, DiskBytes: int64((10240 + hours - 1) * mebibyte), Hours: hours,
	}
}
