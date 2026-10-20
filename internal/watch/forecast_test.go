package watch

import (
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

const gib = float64(1 << 30)

var forecastNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// series makes n points step apart, the last at forecastNow, with the
// bytes in use given by how long after the first point each one is.
func series(n int, step time.Duration, used func(since time.Duration) float64) []Point {
	points := make([]Point, n)
	for i := range points {
		since := time.Duration(i) * step
		points[i] = Point{At: forecastNow.Add(-time.Duration(n-1-i) * step), Used: used(since)}
	}
	return points
}

// growing grows by perDay from base.
func growing(base, perDay float64) func(time.Duration) float64 {
	return func(since time.Duration) float64 { return base + perDay*since.Hours()/24 }
}

func flat(used float64) func(time.Duration) float64 {
	return func(time.Duration) float64 { return used }
}

func near(got, want, within float64) bool { return math.Abs(got-want) <= within }

func TestTheilSenFitsALineAndShrugsOffOddSamples(t *testing.T) {
	line := series(10, time.Hour, growing(50*gib, 24*gib))
	slope, intercept, ok := TheilSen(line)
	if !ok || !near(slope, gib/3600, 1e-6) || !near(intercept, 50*gib, 1) {
		t.Fatalf("a straight line: slope %v, intercept %v, %v", slope, intercept, ok)
	}
	// A temporary file in two of the samples moves neither.
	line[3].Used += 40 * gib
	line[7].Used -= 30 * gib
	if odd, oddIntercept, _ := TheilSen(line); !near(odd, slope, 1e-6) || !near(oddIntercept, intercept, 1) {
		t.Fatalf("two odd samples swung the fit: slope %v, intercept %v", odd, oddIntercept)
	}
	for _, few := range [][]Point{nil, line[:1], {{At: forecastNow, Used: 1}, {At: forecastNow, Used: 2}}} {
		if _, _, ok := TheilSen(few); ok {
			t.Fatalf("fitted %d points without two times", len(few))
		}
	}
}

func TestForecastSaysWhenTheFreeSpaceRunsOut(t *testing.T) {
	cases := []struct {
		name   string
		points []Point
		min    int
		free   float64
		ok     bool
		full   time.Duration
		perDay float64
	}{
		{"steady growth", series(168, time.Hour, growing(40*gib, 2*gib)), ForecastLongPoints, 10 * gib, true, 5 * 24 * time.Hour, 2 * gib},
		// The cleanup half a day ago drops 30 GiB. The trend stays the
		// growth around it, and the free space counts from now.
		{"a cleanup drop", series(168, time.Hour, func(since time.Duration) float64 {
			used := growing(40*gib, 2*gib)(since)
			if since > 155*time.Hour {
				used -= 30 * gib
			}
			return used
		}), ForecastLongPoints, 40 * gib, true, 20 * 24 * time.Hour, 2 * gib},
		// A log growing 3 GiB an hour for the last three of six hours.
		{"a runaway log", series(360, time.Minute, func(since time.Duration) float64 {
			return 60*gib + 3*gib*max(0, since.Hours()-3)
		}), ForecastShortPoints, 5 * gib, true, 0, 0},
		{"flat usage", series(168, time.Hour, flat(90*gib)), ForecastLongPoints, 10 * gib, false, 0, 0},
		{"shrinking usage", series(168, time.Hour, growing(90*gib, -gib)), ForecastLongPoints, 10 * gib, false, 0, 0},
		{"too few hours", series(ForecastLongPoints-1, time.Hour, growing(40*gib, 20*gib)), ForecastLongPoints, 10 * gib, false, 0, 0},
		{"just enough hours", series(ForecastLongPoints, time.Hour, growing(40*gib, 20*gib)), ForecastLongPoints, 10 * gib, true, 12 * time.Hour, 20 * gib},
		{"a restart with an empty ring", nil, ForecastShortPoints, 10 * gib, false, 0, 0},
		{"too few minutes", series(ForecastShortPoints-1, time.Minute, growing(40*gib, 240*gib)), ForecastShortPoints, 10 * gib, false, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trend, ok := Forecast(c.points, c.min, uint64(c.free))
			if ok != c.ok {
				t.Fatalf("ok %v, want %v: %+v", ok, c.ok, trend)
			}
			if !ok {
				return
			}
			if c.full == 0 {
				// The runaway: the robust trend lags the log's 3 GiB an
				// hour, but it is already over 1 GiB an hour and pages.
				if trend.PerSecond*3600 < gib || trend.Full > DiskFullFast {
					t.Fatalf("the runaway log isn't fast: %.2f GB an hour, full in %s", trend.PerSecond*3600/gib, trend.Full)
				}
				return
			}
			if !near(trend.PerSecond*86400, c.perDay, gib/100) || !near(trend.Full.Hours(), c.full.Hours(), 0.1) {
				t.Fatalf("%.3f GB a day, full in %s; want %.3f and %s", trend.PerSecond*86400/gib, trend.Full, c.perDay/gib, c.full)
			}
		})
	}
	// A trend too slow to measure in a duration lasts as long as one can.
	slow := series(ForecastLongPoints, time.Hour, func(since time.Duration) float64 { return since.Hours() * 1e-9 })
	if trend, ok := Forecast(slow, ForecastLongPoints, math.MaxUint64); !ok || trend.Full != time.Duration(math.MaxInt64) {
		t.Fatalf("an almost flat trend: %+v, %v", trend, ok)
	}
}

func TestDiskConditionsFollowTheTrend(t *testing.T) {
	const total = 100 * gib
	runaway := series(360, time.Minute, func(since time.Duration) float64 {
		return 60*gib + 3*gib*max(0, since.Hours()-3)
	})
	type want struct{ severity, message string }
	cases := []struct {
		name            string
		free            float64
		hourly, minutes []Point
		disk, forecast  want
	}{
		{name: "steady growth with room is a warning about the trend", free: 20 * gib,
			hourly:   series(168, time.Hour, growing(66*gib, 2*gib)),
			forecast: want{state.SeverityWarning, "fills in about 10 days at 2.0 GB a day (7 day trend), 20.0 GB free"}},
		// The 10% rule stays critical, and the forecast warns.
		{name: "filling in 3 days under 10% free", free: 7.8 * gib,
			hourly:   series(168, time.Hour, growing(74.0*gib, 2.6*gib)),
			disk:     want{state.SeverityCritical, "only 7.8 GB free of 100.0 GB (8%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 3 days at 2.6 GB a day (7 day trend), 7.8 GB free"}},
		{name: "filling within 48 hours is critical", free: 30 * gib,
			hourly:   series(168, time.Hour, growing(0, 20*gib)),
			forecast: want{state.SeverityCritical, "fills in about 36 hours at 20.0 GB a day (7 day trend), 30.0 GB free"}},
		{name: "flat usage at 92% is a warning only", free: 8 * gib,
			hourly: series(168, time.Hour, flat(92*gib)),
			disk:   want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"}},
		{name: "slow growth under 10% free is a warning", free: 8 * gib,
			hourly: series(168, time.Hour, growing(91*gib, 0.2*gib)),
			disk:   want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, which lasts about 40 days at 204.8 MB a day (7 day trend)"}},
		{name: "under 10% free without enough hours stays critical", free: 8 * gib,
			hourly: series(ForecastLongPoints-1, time.Hour, flat(92*gib)),
			disk:   want{state.SeverityCritical, "only 8.0 GB free of 100.0 GB (8%) on /"}},
		{name: "the 5 GB floor stays critical however flat", free: 4 * gib,
			hourly: series(168, time.Hour, flat(96*gib)),
			disk:   want{state.SeverityCritical, "only 4.0 GB free of 100.0 GB (4%) on /"}},
		{name: "a cleanup drop counts at once", free: 45 * gib,
			hourly: series(168, time.Hour, func(since time.Duration) float64 {
				used := growing(40*gib, 2*gib)(since)
				if since > 155*time.Hour {
					used -= 30 * gib
				}
				return used
			})},
		{name: "a runaway log pages on the short trend", free: 8 * gib,
			hourly:   series(168, time.Hour, flat(60*gib)),
			minutes:  runaway,
			disk:     want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"},
			forecast: want{state.SeverityCritical, "(6 hour trend), 8.0 GB free"}},
		{name: "a restart with an empty ring waits for the long trend", free: 8 * gib,
			hourly: series(168, time.Hour, flat(60*gib)),
			disk:   want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"}},
		{name: "nothing fires below the point counts", free: 30 * gib,
			hourly:  series(ForecastLongPoints-1, time.Hour, growing(0, 40*gib)),
			minutes: series(ForecastShortPoints-1, time.Minute, growing(0, 1000*gib))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			disk, forecast := diskConditions("/", uint64(c.free), uint64(total), c.hourly, c.minutes)
			check := func(what, key string, got *Condition, want want) {
				t.Helper()
				if want.severity == "" {
					if got != nil {
						t.Fatalf("%s: unexpected %+v", what, *got)
					}
					return
				}
				if got == nil || got.Key != key || got.Severity != want.severity || !strings.Contains(got.Message, want.message) {
					t.Fatalf("%s: got %+v, want %s containing %q", what, got, want.severity, want.message)
				}
			}
			check("disk", "host:disk", disk, c.disk)
			check("forecast", "host:disk-forecast", forecast, c.forecast)
		})
	}
}

// After a restart the minute ring is empty, but the hourly samples the
// sampler kept still forecast, the alert names the deployed app that
// grew most, and the ring fills from the rounds that follow.
func TestTheProberForecastsFromKeptSamplesAfterARestart(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, name := range []string{"packrat", "quiet"} {
		m := json.RawMessage(`{"app":"` + name + `","workloads":{"web":{"kind":"worker","image":"x"}}}`)
		if err := store.SaveRevision(ctx, state.Revision{App: name, ID: "r1", Status: state.RevisionActive, Manifest: m, CreatedAt: forecastNow}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range series(168, time.Hour, growing(0, 10*gib)) {
		rows := []state.Signal{
			{Hour: p.At, App: manifest.ReservedApp, Key: state.SignalHostDiskRoot, Metric: state.SignalHostDiskUsed, Value: p.Used},
			// Noise the forecast must not read: another key and metric.
			{Hour: p.At, App: manifest.ReservedApp, Key: "other", Metric: state.SignalHostDiskUsed, Value: 1},
			{Hour: p.At, App: "packrat", Metric: state.SignalDiskBytes, Value: p.Used / 10},
			{Hour: p.At, App: "quiet", Metric: state.SignalDiskBytes, Value: gib},
			// A removed app that grew more isn't named.
			{Hour: p.At, App: "removed", Metric: state.SignalDiskBytes, Value: p.Used},
		}
		for _, r := range rows {
			if err := store.MaxSignal(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := forecastNow
	p := NewProber(store)
	p.Now = func() time.Time { return now }
	p.Disk = func(string) (uint64, uint64, bool) { return uint64(15 * gib), uint64(100 * gib), true }
	forecast := func() *Condition {
		t.Helper()
		for _, c := range p.host(ctx) {
			if c.Key == "host:disk-forecast" {
				return &c
			}
		}
		return nil
	}
	got := forecast()
	if got == nil || got.Severity != state.SeverityCritical ||
		got.Message != "fills in about 36 hours at 10.0 GB a day (7 day trend), 15.0 GB free; of the apps, packrat grew most, by 7.0 GB in 6 days" {
		t.Fatalf("after a restart: %+v", got)
	}
	if len(p.minutes) != 1 {
		t.Fatalf("the ring holds %d samples after one round", len(p.minutes))
	}
	for range 400 {
		now = now.Add(time.Minute)
		forecast()
	}
	if n := len(p.minutes); n != 360 || p.minutes[0].At != now.Add(-ForecastShortWindow+time.Minute) {
		t.Fatalf("the ring keeps %d samples from %s, not the last six hours", n, p.minutes[0].At)
	}
}
