// Package signals keeps the numbers beside every app: requests, errors
// and latency from the edge's per-host metrics, CPU and memory from the
// containers, disk from the volumes and the machine's root filesystem.
// The daemon samples every minute and keeps hourly rollups for 90 days.
package signals

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// Retention is how long rollups are kept.
const Retention = 90 * 24 * time.Hour

// Series is one line of Prometheus text.
type Series struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// ParseMetrics reads Prometheus text format, samples only.
func ParseMetrics(text string) []Series {
	var out []Series
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 4<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, ok := parseLine(line)
		if ok {
			out = append(out, s)
		}
	}
	return out
}

func parseLine(line string) (Series, bool) {
	s := Series{Labels: map[string]string{}}
	rest := line
	if i := strings.IndexByte(line, '{'); i >= 0 {
		s.Name = line[:i]
		end := strings.LastIndexByte(line, '}')
		if end < i {
			return s, false
		}
		for labels := line[i+1 : end]; labels != ""; {
			var pair string
			pair, labels = cutLabel(labels)
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				return s, false
			}
			k = strings.TrimSpace(k)
			decoded, err := strconv.Unquote(strings.TrimSpace(v))
			if err != nil || k == "" {
				return s, false
			}
			if _, duplicate := s.Labels[k]; duplicate {
				return s, false
			}
			s.Labels[k] = decoded
		}
		rest = line[end+1:]
	} else {
		s.Name, rest = cutMetricField(line)
	}
	value, _ := cutMetricField(rest)
	v, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return s, false
	}
	s.Value = v
	return s, true
}

// cutMetricField reads one whitespace-delimited field without allocating a
// slice for the remaining fields, including an optional sample timestamp.
func cutMetricField(text string) (string, string) {
	text = strings.TrimSpace(text)
	for field := range strings.FieldsSeq(text) {
		return field, text[len(field):]
	}
	return "", ""
}

// cutLabel splits at the first comma outside quotes. Both results refer to
// the sample line; escaped quotes and commas stay intact for strconv.Unquote.
func cutLabel(text string) (string, string) {
	quoted, escaped := false, false
	for i := range len(text) {
		switch c := text[i]; {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case c == ',' && !quoted:
			return text[:i], text[i+1:]
		}
	}
	return text, ""
}

func (s Series) key() string {
	// The usual Caddy labels fit on the stack. Larger arbitrary label sets
	// still include every key and value in the identity.
	var localKeys [8]string
	keys := localKeys[:0]
	if len(s.Labels) > cap(keys) {
		keys = make([]string, 0, len(s.Labels))
	}
	size := metricKeyFieldSize(s.Name) + 1
	for k, v := range s.Labels {
		keys = append(keys, k)
		size += metricKeyFieldSize(k) + metricKeyFieldSize(v)
	}
	sort.Strings(keys)
	var key strings.Builder
	key.Grow(size)
	writeMetricKeyField(&key, s.Name)
	if s.Labels == nil {
		key.WriteByte(0)
	} else {
		key.WriteByte(1)
	}
	for _, k := range keys {
		writeMetricKeyField(&key, k)
		writeMetricKeyField(&key, s.Labels[k])
	}
	return key.String()
}

// Length prefixes keep names, keys and values unambiguous even when they
// contain delimiters or NUL bytes, without JSON's temporary encoding buffers.
func writeMetricKeyField(key *strings.Builder, value string) {
	var length [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(length[:], uint64(len(value)))
	key.Write(length[:n])
	key.WriteString(value)
}

func metricKeyFieldSize(value string) int {
	n := len(value)
	size := n + 1
	for n >= 128 {
		size++
		n >>= 7
	}
	return size
}

// Sampler takes one sample per call and rolls it up.
type Sampler struct {
	Store *state.Store
	// Metrics fetches the edge's metrics text.
	Metrics func(ctx context.Context) ([]byte, error)
	Now     func() time.Time
	Log     func(format string, args ...any)
	// Connect opens Docker; nil skips container stats.
	Connect func(ctx context.Context) (*docker.Engine, error)
	// DiskUsage measures a directory in bytes; nil skips disk.
	DiskUsage func(ctx context.Context, path string) (int64, error)
	// HostDisk reads the free and total bytes of the machine's root
	// filesystem; nil skips it.
	HostDisk func() (free, total uint64, ok bool)

	mu          sync.Mutex
	counters    map[string]float64
	primed      bool
	lastDisk    time.Time
	lastGC      time.Time
	sharedHosts string
}

// NewSampler returns a sampler for this machine.
func NewSampler(store *state.Store) *Sampler {
	return &Sampler{
		Store:     store,
		Metrics:   edge.NewAdmin().Metrics,
		Now:       func() time.Time { return time.Now().UTC() },
		Log:       func(string, ...any) {},
		Connect:   docker.Connect,
		DiskUsage: du,
	}
}

// Sample takes one round of measurements. A round still going when the
// next is due is left to finish, and the next is skipped: the rollups are
// hourly, and a queue of late rounds would only pile onto the machine.
func (s *Sampler) Sample(ctx context.Context) error {
	if !s.mu.TryLock() {
		s.Log("signals: the last round is still going; skipping this one")
		return nil
	}
	defer s.mu.Unlock()
	now := s.Now()
	if s.HostDisk != nil {
		if free, total, ok := s.HostDisk(); ok && free <= total {
			_ = s.Store.MaxSignal(ctx, state.Signal{Hour: now, App: manifest.ReservedApp, Key: state.SignalHostDiskRoot, Metric: state.SignalHostDiskUsed, Value: float64(total - free)})
		}
	}
	active, err := s.Store.ActiveRevisions(ctx)
	if err != nil {
		return err
	}
	hostApp := map[string]string{}
	shared := map[string]bool{}
	type workload struct {
		app, name, container string
	}
	var containers []workload
	volumes := map[string][]string{}
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			continue
		}
		for _, h := range m.Hosts() {
			if owner, exists := hostApp[h]; exists && owner != rev.App {
				shared[h] = true
			}
			hostApp[h] = rev.App
		}
		for _, name := range m.WorkloadNames() {
			if c := rev.Containers[name]; c != "" {
				containers = append(containers, workload{rev.App, name, c})
			}
		}
		if m.Data != nil {
			for _, v := range m.DataVolumes() {
				volumes[rev.App] = append(volumes[rev.App], docker.VolumeName(rev.App, v))
			}
			if m.PostgresVersion() != "" {
				volumes[rev.App] = append(volumes[rev.App], docker.VolumeName(rev.App, "postgres"))
			}
		}
	}

	sharedNames := make([]string, 0, len(shared))
	for host := range shared {
		delete(hostApp, host)
		sharedNames = append(sharedNames, host)
	}
	sort.Strings(sharedNames)
	sharedKey := strings.Join(sharedNames, ",")
	if sharedKey != s.sharedHosts {
		s.sharedHosts = sharedKey
		if len(sharedNames) > 0 {
			s.Log("signals: per-host counters cannot attribute traffic for %d shared hosts to individual apps; first host: %s", len(sharedNames), sharedNames[0])
		}
	}

	if text, err := s.scrape(ctx); err != nil {
		s.Log("signals: edge metrics: %v", err)
	} else if err := s.traffic(ctx, now, ParseMetrics(text), hostApp); err != nil {
		s.Log("signals: traffic: %v", err)
	}

	diskDue := s.DiskUsage != nil && len(volumes) > 0 && now.Sub(s.lastDisk) >= time.Hour
	if s.Connect != nil && (len(containers) > 0 || diskDue) {
		e, err := s.Connect(ctx)
		if err != nil {
			s.Log("signals: %v", err)
		} else {
			defer e.Close()
			var wg sync.WaitGroup
			type usage struct {
				workload
				docker.Usage
				err error
			}
			results := make([]usage, len(containers))
			for i, w := range containers {
				wg.Add(1)
				go func(i int, w workload) {
					defer wg.Done()
					u, err := e.Stats(ctx, w.container)
					results[i] = usage{w, u, err}
				}(i, w)
			}
			wg.Wait()
			for _, r := range results {
				if r.err != nil {
					continue
				}
				_ = s.Store.AddSignal(ctx, state.Signal{Hour: now, App: r.app, Key: r.name, Metric: state.SignalCPUPercent, Value: r.CPUPercent, Samples: 1})
				_ = s.Store.AddSignal(ctx, state.Signal{Hour: now, App: r.app, Key: r.name, Metric: state.SignalMemoryBytes, Value: float64(r.MemoryBytes), Samples: 1})
				_ = s.Store.MaxSignal(ctx, state.Signal{Hour: now, App: r.app, Key: r.name, Metric: state.SignalMemoryMax, Value: float64(r.MemoryBytes)})
			}
			if diskDue {
				s.lastDisk = now
				for app, vols := range volumes {
					var total int64
					complete := true
					for _, v := range vols {
						mp, err := e.VolumeMountpoint(ctx, v)
						if err != nil {
							s.Log("signals: disk for %s volume %s: %v", app, v, err)
							complete = false
							continue
						}
						n, err := s.DiskUsage(ctx, mp)
						if err != nil || n < 0 {
							s.Log("signals: disk for %s volume %s could not be measured", app, v)
							complete = false
							continue
						}
						total += n
					}
					if complete {
						_ = s.Store.MaxSignal(ctx, state.Signal{Hour: now, App: app, Key: "", Metric: state.SignalDiskBytes, Value: float64(total)})
					}
				}
			}
		}
	}

	if now.Sub(s.lastGC) >= 24*time.Hour {
		s.lastGC = now
		if n, err := s.Store.PruneSignals(ctx, now.Add(-Retention)); err == nil && n > 0 {
			s.Log("signals: dropped %d rollups older than 90 days", n)
		}
	}
	return nil
}

func (s *Sampler) scrape(ctx context.Context) (string, error) {
	if s.Metrics == nil {
		return "", fmt.Errorf("no metrics source")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := s.Metrics(ctx)
	return string(b), err
}

// traffic turns counter deltas since the last round into rollups. The
// first round only primes the counters. After that a series seen for the
// first time counts in full (the edge makes a series at its first
// request), and a counter that went backwards (the edge restarted)
// counts from zero.
func (s *Sampler) traffic(ctx context.Context, now time.Time, series []Series, hostApp map[string]string) error {
	if s.counters == nil {
		s.counters = map[string]float64{}
	}
	deltas := map[string]map[string]float64{} // app -> host -> metric -> delta, flattened as host|metric
	add := func(app, host, metric string, v float64) {
		if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return
		}
		if deltas[app] == nil {
			deltas[app] = map[string]float64{}
		}
		deltas[app][host+"|"+metric] += v
	}
	seen := map[string]bool{}
	for _, sr := range series {
		switch sr.Name {
		case "caddy_http_requests_total", "caddy_http_request_duration_seconds_count",
			"caddy_http_request_duration_seconds_sum", "caddy_http_request_duration_seconds_bucket",
			"caddy_http_response_size_bytes_sum":
		default:
			continue
		}
		if sr.Value < 0 || math.IsNaN(sr.Value) || math.IsInf(sr.Value, 0) {
			continue
		}
		host := sr.Labels["host"]
		app, known := hostApp[host]
		if !known || sr.Labels["handler"] != "subroute" {
			continue
		}
		if sr.Name == "caddy_http_request_duration_seconds_bucket" {
			bound, err := strconv.ParseFloat(sr.Labels["le"], 64)
			if err != nil || bound < 0 || math.IsNaN(bound) || math.IsInf(bound, 0) {
				continue
			}
		}
		k := sr.key()
		seen[k] = true
		last, had := s.counters[k]
		s.counters[k] = sr.Value
		if !s.primed {
			continue
		}
		delta := sr.Value
		if had {
			delta = sr.Value - last
			if delta < 0 {
				delta = sr.Value
			}
		}
		switch sr.Name {
		case "caddy_http_requests_total":
			add(app, host, state.SignalRequests, delta)
		case "caddy_http_request_duration_seconds_count":
			add(app, host, state.SignalObserved, delta)
			if strings.HasPrefix(sr.Labels["code"], "5") {
				add(app, host, state.SignalErrors, delta)
			}
		case "caddy_http_request_duration_seconds_sum":
			add(app, host, state.SignalDurationMS, delta*1000)
		case "caddy_http_request_duration_seconds_bucket":
			add(app, host, state.SignalBucketPrefix+sr.Labels["le"], delta)
		case "caddy_http_response_size_bytes_sum":
			add(app, host, state.SignalBytes, delta)
		}
	}
	for k := range s.counters {
		if !seen[k] {
			delete(s.counters, k)
		}
	}
	s.primed = true
	for app, m := range deltas {
		for hm, v := range m {
			host, metric, _ := strings.Cut(hm, "|")
			if err := s.Store.AddSignal(ctx, state.Signal{Hour: now, App: app, Key: host, Metric: metric, Value: v, Samples: 1}); err != nil {
				return err
			}
		}
	}
	return nil
}

func du(ctx context.Context, path string) (int64, error) {
	out, err := exec.CommandContext(ctx, "du", "-sb", path).Output()
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0, fmt.Errorf("du: no output")
	}
	return strconv.ParseInt(fields[0], 10, 64)
}

// Summary is an app's signals over a window, in the words helios status
// uses.
type Summary struct {
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
	// AvgMS is the mean response time; P95MS the bound 95% of requests
	// finished within, from the histogram buckets. Both are zero when
	// nothing was observed.
	AvgMS float64 `json:"avg_ms"`
	P95MS float64 `json:"p95_ms"`
	Bytes int64   `json:"bytes"`
	// CPUPercent is the average across the app's workloads, summed.
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes int64   `json:"memory_bytes"`
	MemoryMax   int64   `json:"memory_max"`
	DiskBytes   int64   `json:"disk_bytes"`
	// Hours is how many hours of samples the window holds.
	Hours int `json:"hours"`
}

// Summarize rolls an app's rows up over the window they cover.
func Summarize(rows []state.Signal) Summary {
	var sum Summary
	var durationMS, observed float64
	buckets := map[float64]float64{}
	perWorkload := map[string]*struct {
		cpu, cpuSamples, mem, memSamples float64
	}{}
	hours := map[int64]bool{}
	var latestDisk time.Time
	for _, r := range rows {
		if math.IsNaN(r.Value) || math.IsInf(r.Value, 0) {
			continue
		}
		hours[r.Hour.Unix()] = true
		switch {
		case r.Metric == state.SignalRequests:
			sum.Requests += int64(r.Value)
		case r.Metric == state.SignalErrors:
			sum.Errors += int64(r.Value)
		case r.Metric == state.SignalObserved:
			observed += r.Value
		case r.Metric == state.SignalDurationMS:
			durationMS += r.Value
		case r.Metric == state.SignalBytes:
			sum.Bytes += int64(r.Value)
		case strings.HasPrefix(r.Metric, state.SignalBucketPrefix):
			if le, err := strconv.ParseFloat(strings.TrimPrefix(r.Metric, state.SignalBucketPrefix), 64); err == nil && le >= 0 && !math.IsNaN(le) && !math.IsInf(le, 0) {
				buckets[le] += r.Value
			}
		case r.Metric == state.SignalCPUPercent || r.Metric == state.SignalMemoryBytes:
			w := perWorkload[r.Key]
			if w == nil {
				w = &struct{ cpu, cpuSamples, mem, memSamples float64 }{}
				perWorkload[r.Key] = w
			}
			if r.Metric == state.SignalCPUPercent {
				w.cpu += r.Value
				w.cpuSamples += float64(r.Samples)
			} else {
				w.mem += r.Value
				w.memSamples += float64(r.Samples)
			}
		case r.Metric == state.SignalMemoryMax:
			// The largest hourly maximum, summed per workload, would
			// overstate; keep the largest single workload hour instead.
			if int64(r.Value) > sum.MemoryMax {
				sum.MemoryMax = int64(r.Value)
			}
		case r.Metric == state.SignalDiskBytes:
			if r.Hour.After(latestDisk) || r.Hour.Equal(latestDisk) {
				latestDisk = r.Hour
				sum.DiskBytes = int64(r.Value)
			}
		}
	}
	sum.Hours = len(hours)
	if observed > 0 {
		sum.AvgMS = durationMS / observed
	}
	if len(buckets) > 0 && observed > 0 {
		les := make([]float64, 0, len(buckets))
		for le := range buckets {
			les = append(les, le)
		}
		sort.Float64s(les)
		target := 0.95 * observed
		sum.P95MS = les[len(les)-1] * 1000
		for _, le := range les {
			if buckets[le] >= target {
				sum.P95MS = le * 1000
				break
			}
		}
	}
	for _, w := range perWorkload {
		if w.cpuSamples > 0 {
			sum.CPUPercent += w.cpu / w.cpuSamples
		}
		if w.memSamples > 0 {
			sum.MemoryBytes += int64(w.mem / w.memSamples)
		}
	}
	return sum
}

// AppSummaries returns every app's summary since a time.
func AppSummaries(ctx context.Context, store *state.Store, since time.Time) (map[string]Summary, error) {
	rows, err := store.Signals(ctx, "", since)
	if err != nil {
		return nil, err
	}
	byApp := map[string][]state.Signal{}
	for _, r := range rows {
		byApp[r.App] = append(byApp[r.App], r)
	}
	out := map[string]Summary{}
	for app, rs := range byApp {
		out[app] = Summarize(rs)
	}
	return out, nil
}
