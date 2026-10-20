package watch

import (
	"context"
	"encoding/json"
	"fmt"
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

// stepped moves used by size from ago before the newest of n samples
// step apart, as a download does, or a cleanup with a negative size.
func stepped(n int, step, ago time.Duration, size float64, used func(time.Duration) float64) func(time.Duration) float64 {
	at := time.Duration(n-1)*step - ago
	return func(since time.Duration) float64 {
		if since >= at {
			return used(since) + size
		}
		return used(since)
	}
}

// bump adds size to used from ago before the newest of n samples step
// apart, for lasting, as a temp file does.
func bump(n int, step, ago, lasting time.Duration, size float64, used func(time.Duration) float64) func(time.Duration) float64 {
	return stepped(n, step, ago, size, stepped(n, step, ago-lasting, -size, used))
}

// download lands size bytes on used at perSecond, give or take jitter as
// a share of it in each step, finishing ended before the newest of n
// samples step apart.
func download(n int, step, ended time.Duration, size, perSecond, jitter float64, used func(time.Duration) float64) func(time.Duration) float64 {
	// landed holds what has landed by each sample, counted back from the
	// one the download finishes at.
	landed := []float64{size}
	for k := uint64(0); landed[len(landed)-1] > 0; k++ {
		// Away from the noise's part of the sequence.
		landed = append(landed, landed[len(landed)-1]-perSecond*step.Seconds()*(1+jitter*wobble(1<<32+k)))
	}
	end := time.Duration(n-1)*step - ended
	return func(since time.Duration) float64 {
		if since >= end {
			return used(since) + size
		}
		if k := int((end - since) / step); k < len(landed) {
			return used(since) + max(0, landed[k])
		}
		return used(since)
	}
}

// noisy adds up to amp either way to each of used's samples, step apart.
// The noise is a fixed pseudo-random sequence, so a fixture reads the
// same on every run.
func noisy(step time.Duration, amp float64, used func(time.Duration) float64) func(time.Duration) float64 {
	return func(since time.Duration) float64 {
		return used(since) + amp*wobble(uint64(since/step+1))
	}
}

// wobble is the kth of a fixed pseudo-random sequence in [-1, 1).
func wobble(k uint64) float64 {
	x := k * 0x9E3779B97F4A7C15
	x ^= x >> 29
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 32
	return float64(x>>11)/(1<<53)*2 - 1
}

func near(got, want, within float64) bool { return math.Abs(got-want) <= within }

// wantCondition is the severity of a condition and part of its message;
// no severity means no condition.
type wantCondition struct{ severity, message string }

// checkDisk compares the conditions diskConditions gave with the ones
// wanted.
func checkDisk(t *testing.T, disk, forecast *Condition, wantDisk, wantForecast wantCondition) {
	t.Helper()
	check := func(what, key, subject string, got *Condition, want wantCondition) {
		t.Helper()
		if want.severity == "" {
			if got != nil {
				t.Fatalf("%s: unexpected %+v", what, *got)
			}
			return
		}
		if got == nil || got.Key != key || got.Subject != subject || got.Severity != want.severity || !strings.Contains(got.Message, want.message) {
			t.Fatalf("%s: got %+v, want %s containing %q", what, got, want.severity, want.message)
		}
	}
	check("disk", "host:disk", "disk", disk, wantDisk)
	// The watcher says the subject "is down", "has a problem" or
	// "recovered".
	check("forecast", "host:disk-forecast", "free disk space", forecast, wantForecast)
}

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

func TestTheForecastTakesOutOnlyALoneStepInUsage(t *testing.T) {
	const n = 100
	hours := func(k int) time.Duration { return time.Duration(k) * time.Hour }
	line := growing(50*gib, 24*gib)
	// climb is a flat disk that rises by each, a sudden change, into each
	// sample from first to last, counted back from the newest.
	climb := func(first, last int, each float64) func(time.Duration) float64 {
		return func(since time.Duration) float64 {
			ago := n - 1 - int(since/time.Hour)
			return 50*gib + each*float64(min(first-last+1, max(0, first-ago+1)))
		}
	}
	cases := []struct {
		name       string
		used, want func(time.Duration) float64
		// within is how far the result may be from want: the noise
		// either side of a step stays in its size.
		within float64
	}{
		{"a lone cleanup", stepped(n, time.Hour, hours(50), -30*gib, line), line, 1},
		{"a lone download", stepped(n, time.Hour, hours(50), 30*gib, flat(50*gib)), flat(50 * gib), 1},
		{"a download over three samples",
			stepped(n, time.Hour, hours(48), 10*gib, stepped(n, time.Hour, hours(49), 10*gib, stepped(n, time.Hour, hours(50), 10*gib, flat(50*gib)))),
			flat(50 * gib), 1},
		{"a cleanup in noise louder than the floor",
			stepped(n, time.Hour, hours(50), -30*gib, noisy(time.Hour, 2*gib, line)), noisy(time.Hour, 2*gib, line), 6 * gib},
		// One rise and one fall are a lone step each way.
		{"a plateau", stepped(n, time.Hour, hours(40), -30*gib, stepped(n, time.Hour, hours(60), 30*gib, flat(50*gib))), flat(50 * gib), 1},
		{"a climb of ShiftMaxSamples is a step", climb(30+ShiftMaxSamples-1, 30, 3*gib), flat(50 * gib), 1},
		// Each change is under the floor, but together they pass it.
		{"a small step spread over ShiftMaxSamples samples", climb(30+ShiftMaxSamples-1, 30, 0.15*gib), flat(50 * gib), 1},
		// A rise and the fall back are one passing bump, whatever else the
		// window holds: taking out one half would invent a step.
		{"a spike is smoothed, not shifted", bump(n, time.Hour, hours(30), time.Hour, 30*gib, line), line, 1},
		{"a spike and a cleanup take out only the cleanup",
			stepped(n, time.Hour, hours(70), -30*gib, bump(n, time.Hour, hours(30), time.Hour, 20*gib, line)), line, 1},
		{"a download in two parts a short gap apart is one step",
			stepped(n, time.Hour, hours(47), 15*gib, stepped(n, time.Hour, hours(50), 15*gib, flat(50*gib))), flat(50 * gib), 1},
		{"two downloads a longer gap apart are two steps",
			stepped(n, time.Hour, hours(46), 15*gib, stepped(n, time.Hour, hours(50), 15*gib, flat(50*gib))),
			stepped(n, time.Hour, hours(46), 15*gib, stepped(n, time.Hour, hours(50), 15*gib, flat(50*gib))), 0},
		// A bump still under way at the newest sample may be the start of
		// something.
		{"a spike that ends at the newest sample is left alone",
			bump(n, time.Hour, hours(1), time.Hour, 30*gib, line), bump(n, time.Hour, hours(1), time.Hour, 30*gib, line), 0},
		// On a quiet disk a change can stand out from the noise and still
		// be too small to matter.
		{"a step under the floor",
			stepped(n, time.Hour, hours(50), gib/10, noisy(time.Hour, gib/1000, flat(50*gib))),
			stepped(n, time.Hour, hours(50), gib/10, noisy(time.Hour, gib/1000, flat(50*gib))), 0},
		// More than one fall, or rise, is the series' rhythm.
		{"a daily log rotation", sawtooth, sawtooth, 0},
		{"a daily staircase", staircase, staircase, 0},
		// A climb that reaches the newest sample may be a runaway.
		{"a climb still going", climb(5, 0, 3*gib), climb(5, 0, 3*gib), 0},
		{"a longer climb is growth", climb(30+ShiftMaxSamples, 30, 3*gib), climb(30+ShiftMaxSamples, 30, 3*gib), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			points, given := series(n, time.Hour, c.used), series(n, time.Hour, c.used)
			got := WithoutShifts(points, gib)
			want := series(n, time.Hour, c.want)
			for i := range got {
				if got[i].At != want[i].At || !near(got[i].Used, want[i].Used, c.within) {
					t.Fatalf("sample %d, %d hours back: %.3f GB, want %.3f", i, n-1-i, got[i].Used/gib, want[i].Used/gib)
				}
				if points[i] != given[i] {
					t.Fatalf("changed the points it was given at sample %d", i)
				}
			}
		})
	}
	// Steady growth across a gap in the samples, such as while the
	// daemon was down, isn't a step.
	gap := series(n, time.Hour, line)
	gap = append(gap[:40:40], gap[52:]...)
	for i, p := range WithoutShifts(gap, gib) {
		if p != gap[i] {
			t.Fatalf("a gap read as a step at sample %d: %.3f GB, want %.3f", i, p.Used/gib, gap[i].Used/gib)
		}
	}
}

// sawtooth is a log that grows 1 GB an hour and is rotated away daily.
func sawtooth(since time.Duration) float64 {
	return 50*gib + gib*float64(int(since.Hours())%24)
}

// staircase is a flat disk that a daily import adds 5 GB to for good.
func staircase(since time.Duration) float64 {
	return 25*gib + 5*gib*float64(int(since.Hours()+5)/24)
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
	type want = wantCondition
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
		// The growth before the cleanup half a day ago leaves 16 GB free
		// on its fitted line, which fills in 8 days. Counted from the 46 GB
		// free now, with the 30 GB the cleanup gave back, it lasts 23 days.
		{name: "a cleanup drop counts at once", free: 46 * gib,
			hourly: series(168, time.Hour, stepped(168, time.Hour, 12*time.Hour, -30*gib, growing(70*gib, 2*gib)))},
		{name: "the same growth without the cleanup warns", free: 16 * gib,
			hourly:   series(168, time.Hour, growing(70*gib, 2*gib)),
			forecast: want{state.SeverityWarning, "fills in about 8 days at 2.0 GB a day (7 day trend), 16.0 GB free"}},
		{name: "a runaway log pages on the short trend", free: 8 * gib,
			hourly:   series(168, time.Hour, flat(60*gib)),
			minutes:  runaway,
			disk:     want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"},
			forecast: want{state.SeverityCritical, "(6 hour trend), 8.0 GB free"}},
		// Only a short trend filling within DiskFullFast pages; a slower
		// one waits for the long trend to have enough hours.
		{name: "a short trend filling in 12 hours waits for the long one", free: 20 * gib,
			minutes: series(360, time.Minute, growing(70*gib, 40*gib))},
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
			checkDisk(t, disk, forecast, c.disk, c.forecast)
		})
	}
}

// A step in usage near the middle of a window, such as a cleanup or a
// download, would swing the fit on its own: a disk still filling would read
// as not growing, and a one-off write as growth. How long each forecast
// gives, at the free space given, says the rate it read.
func TestTheForecastSetsAsideALoneStepInUsage(t *testing.T) {
	const week = 168
	h := time.Hour
	cleanup := func(ago time.Duration) []Point {
		return series(week, time.Hour, stepped(week, time.Hour, ago, -10*gib, noisy(time.Hour, 0.2*gib, growing(96*gib, gib))))
	}
	// nightly adds a backup's 1.5 GB dump to the sample at 03:00 UTC, the
	// hour's largest use while the dump sits on the disk.
	nightly := func(used func(time.Duration) float64) func(time.Duration) float64 {
		first := forecastNow.Add(-(week - 1) * time.Hour)
		return func(since time.Duration) float64 {
			if first.Add(since).Hour() == 3 {
				return used(since) + 1.5*gib
			}
			return used(since)
		}
	}
	type want = wantCondition
	cases := []struct {
		name            string
		free, total     float64
		hourly, minutes []Point
		disk, forecast  want
	}{
		// About 1 GB a day: the 10% rule stays critical.
		{name: "a 10 GB cleanup 72 hours ago", free: 7 * gib, total: 100 * gib, hourly: cleanup(72 * time.Hour),
			disk:     want{state.SeverityCritical, "only 7.0 GB free of 100.0 GB (7%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 7 days at "}},
		{name: "a 10 GB cleanup 84 hours ago", free: 7 * gib, total: 100 * gib, hourly: cleanup(84 * time.Hour),
			disk:     want{state.SeverityCritical, "only 7.0 GB free of 100.0 GB (7%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 7 days at "}},
		{name: "a 10 GB cleanup 96 hours ago", free: 7 * gib, total: 100 * gib, hourly: cleanup(96 * time.Hour),
			disk:     want{state.SeverityCritical, "only 7.0 GB free of 100.0 GB (7%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 7 days at "}},
		// About 60 GB a day.
		{name: "a 300 GB cleanup 84 hours ago on a disk filling in 40 hours", free: 100 * gib, total: 1000 * gib,
			hourly:   series(week, time.Hour, stepped(week, time.Hour, 84*time.Hour, -300*gib, noisy(time.Hour, 2*gib, growing(782.5*gib, 60*gib)))),
			forecast: want{state.SeverityCritical, "fills in about 40 hours at "}},
		{name: "a 15 GB download 84 hours ago on a flat disk", free: 20 * gib, total: 100 * gib,
			hourly: series(week, time.Hour, stepped(week, time.Hour, 84*time.Hour, 15*gib, noisy(time.Hour, 0.2*gib, flat(65*gib))))},
		// The 9 GB took three minutes to land.
		{name: "a 9 GB download 3 hours ago on a flat 92% disk", free: 8 * gib, total: 100 * gib,
			hourly: series(week, time.Hour, stepped(week, time.Hour, 3*time.Hour, 9*gib, noisy(time.Hour, 0.2*gib, flat(83*gib)))),
			minutes: series(360, time.Minute, stepped(360, time.Minute, 180*time.Minute, 3*gib, stepped(360, time.Minute, 181*time.Minute, 3*gib,
				stepped(360, time.Minute, 182*time.Minute, 3*gib, noisy(time.Minute, 0.05*gib, flat(83*gib)))))),
			disk: want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /"}},
		// About 5 GB a day: steps every day are growth.
		{name: "a daily 5 GB staircase", free: 40 * gib, total: 100 * gib,
			hourly:   series(week, time.Hour, noisy(time.Hour, 0.1*gib, staircase)),
			forecast: want{state.SeverityWarning, "fills in about 8 days at "}},
		// About 2 GB a day.
		{name: "a nightly one-hour 10 GB spike on steady growth", free: 20 * gib, total: 100 * gib,
			hourly: series(week, time.Hour, noisy(time.Hour, 0.1*gib, func(since time.Duration) float64 {
				used := growing(66*gib, 2*gib)(since)
				if int(since.Hours())%24 == 20 {
					used += 10 * gib
				}
				return used
			})),
			forecast: want{state.SeverityWarning, "fills in about 10 days at "}},
		// The prober restarted two hours ago, and a log has grown 3 GB an
		// hour since one hour ago. It paged before steps were set aside.
		{name: "a runaway that started an hour ago", free: 8 * gib, total: 100 * gib,
			hourly: series(week, time.Hour, stepped(week, time.Hour, 0, 3*gib, flat(89*gib))),
			minutes: series(120, time.Minute, noisy(time.Minute, 0.02*gib, func(since time.Duration) float64 {
				return 89*gib + 3*gib*max(0, since.Hours()-1)
			})),
			disk:     want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"},
			forecast: want{state.SeverityCritical, "(6 hour trend), 8.0 GB free"}},
		// A temp file or dump that comes and goes is one passing bump. Read
		// as a rise and a fall, one of them lone and taken out, it would
		// leave a step that never happened.
		{name: "a 5 GB download and a one-sample 10 GB temp file on a flat disk", free: 8 * gib, total: 100 * gib,
			hourly: series(week, h, bump(week, h, 30*h, h, 10*gib, stepped(week, h, 84*h, 5*gib, flat(87*gib)))),
			disk:   want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"}},
		// About 1 GB a day.
		{name: "a 5 GB cleanup and a 10 GB temp file 6 hours ago", free: 7 * gib, total: 120 * gib,
			hourly:   series(week, h, bump(week, h, 6*h, h, 10*gib, stepped(week, h, 70*h, -5*gib, growing(111*gib, gib)))),
			disk:     want{state.SeverityCritical, "only 7.0 GB free of 120.0 GB (6%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 7 days at "}},
		{name: "a 5 GB spike and a 10 GB cleanup on a noisy disk", free: 7.1 * gib, total: 100 * gib,
			hourly:   series(week, h, bump(week, h, 84*h, h, 5*gib, stepped(week, h, 20*h, -10*gib, noisy(h, 0.2*gib, growing(95.9*gib, gib))))),
			disk:     want{state.SeverityCritical, "only 7.1 GB free of 100.0 GB (7%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 7 days at "}},
		{name: "a 5 GB spike and a 9 GB download on a flat 92% disk", free: 8 * gib, total: 100 * gib,
			hourly: series(week, h, bump(week, h, 84*h, h, 5*gib, stepped(week, h, 20*h, 9*gib, flat(83*gib)))),
			disk:   want{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"}},
		// Every night is a bump, so the cleanup is still the one fall.
		{name: "a 10 GB cleanup 84 hours ago on a disk with a nightly dump", free: 7 * gib, total: 100 * gib,
			hourly:   series(week, h, nightly(stepped(week, h, 84*h, -10*gib, noisy(h, 0.2*gib, growing(96*gib, gib))))),
			disk:     want{state.SeverityCritical, "only 7.0 GB free of 100.0 GB (7%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 7 days at "}},
		// 1% of this disk is 10 GB, but a step of 1 GiB or more counts.
		// About 2 GB a day.
		{name: "a 9 GB cleanup 84 hours ago on a 1000 GB disk", free: 25 * gib, total: 1000 * gib,
			hourly:   series(week, h, stepped(week, h, 84*h, -9*gib, noisy(h, 0.2*gib, growing(970*gib, 2*gib)))),
			disk:     want{state.SeverityCritical, "only 25.0 GB free of 1000.0 GB (2%) on /"},
			forecast: want{state.SeverityWarning, "fills in about 12 days at 2.0 GB a day (7 day trend), 25.0 GB free"}},
		// Since 3 days ago the disk has filled 1.2 GB an hour, each hour a
		// sudden change on its own. A run that long, still going at the
		// newest sample, is growth.
		{name: "an hourly regime change still going", free: 8 * gib, total: 100 * gib,
			hourly:   series(week, time.Hour, func(since time.Duration) float64 { return 5.6*gib + 1.2*gib*max(0, since.Hours()-95) }),
			minutes:  series(360, time.Minute, growing(84.8*gib, 28.8*gib)),
			disk:     want{state.SeverityCritical, "only 8.0 GB free of 100.0 GB (8%) on /"},
			forecast: want{state.SeverityCritical, "(7 day trend), 8.0 GB free"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			disk, forecast := diskConditions("/", uint64(c.free), uint64(c.total), c.hourly, c.minutes)
			checkDisk(t, disk, forecast, c.disk, c.forecast)
		})
	}
	// On a disk this noisy a 10 GB sample may stray past the noise on one
	// side only. The levels either side, not that one change, say the
	// size, so it still reads as a bump. About 1 GB a day, and the noise
	// is about 1 GB from the mean.
	for _, ago := range []time.Duration{10, 41, 84, 125, 150} {
		t.Run(fmt.Sprintf("a one-sample 10 GB plateau %d hours ago in 1 GB noise", ago), func(t *testing.T) {
			hourly := series(week, h, bump(week, h, ago*h, h, 10*gib, noisy(h, 1.7*gib, growing(106*gib, gib))))
			disk, forecast := diskConditions("/", uint64(7*gib), uint64(120*gib), hourly, nil)
			checkDisk(t, disk, forecast, want{state.SeverityCritical, "only 7.0 GB free of 120.0 GB (6%) on /"}, want{state.SeverityWarning, "fills in about 7 days at "})
		})
	}
}

// The 6 hour trend keeps reading a burst that stopped hours ago, a
// download however slow or uneven, as growth. It pages only while usage
// still climbs.
func TestTheShortForecastPagesOnlyWhileUsageStillClimbs(t *testing.T) {
	const ring = 360
	m := time.Minute
	flat92 := noisy(m, 0.05*gib, flat(83*gib))
	// The hourly samples hold the 9 GB that landed 3 hours ago.
	hourly := series(168, time.Hour, stepped(168, time.Hour, 3*time.Hour, 9*gib, noisy(time.Hour, 0.2*gib, flat(83*gib))))
	// The 9 GB took three minutes to land.
	quick := download(ring, m, 180*m, 9*gib, 3*gib/60, 0, flat92)
	cases := []struct {
		name    string
		hourly  []Point
		minutes []Point
	}{
		// 9 GB in 10 minutes is about 130 Mbit/s.
		{"a 9 GB pull over 10 minutes 3 hours ago", hourly, series(ring, m, download(ring, m, 180*m, 9*gib, 0.9*gib/60, 0, flat92))},
		{"a 9 GB download at a steady 5 MB/s 3 hours ago", hourly, series(ring, m, download(ring, m, 180*m, 9*gib, 5<<20, 0, flat92))},
		{"a 9 GB download at 5 MB/s give or take 40%", hourly, series(ring, m, download(ring, m, 180*m, 9*gib, 5<<20, 0.4, flat92))},
		{"a 9 GB download at 26 MB/s give or take 40%", hourly, series(ring, m, download(ring, m, 180*m, 9*gib, 26<<20, 0.4, flat92))},
		{"a 9 GB download and a 2 minute temp file an hour ago", hourly, series(ring, m, bump(ring, m, 60*m, 2*m, 1.5*gib, quick))},
		{"a 9 GB download and a 2 minute temp file 5 hours ago", hourly, series(ring, m, bump(ring, m, 300*m, 2*m, 1.5*gib, quick))},
		// A log grew 3 GB an hour from about 4 hours ago until about 2
		// hours ago.
		{"a runaway that stopped 2 hours ago",
			series(168, time.Hour, stepped(168, time.Hour, 2*time.Hour, 3*gib, stepped(168, time.Hour, 3*time.Hour, 3*gib, flat(86*gib)))),
			series(ring, m, noisy(m, 0.02*gib, func(since time.Duration) float64 {
				return 86*gib + 3*gib*min(2, max(0, since.Hours()-2))
			}))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			disk, forecast := diskConditions("/", uint64(8*gib), uint64(100*gib), c.hourly, c.minutes)
			checkDisk(t, disk, forecast, wantCondition{state.SeverityWarning, "only 8.0 GB free of 100.0 GB (8%) on /, but the 7 day trend isn't growing"}, wantCondition{})
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
			// Noise the forecast must not read: another key, and another
			// metric under the same key.
			{Hour: p.At, App: manifest.ReservedApp, Key: "other", Metric: state.SignalHostDiskUsed, Value: 1},
			{Hour: p.At, App: manifest.ReservedApp, Key: state.SignalHostDiskRoot, Metric: state.SignalDiskBytes, Value: 1},
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
		got.Message != "fills in about 36 hours at 10.0 GB a day (7 day trend), 15.0 GB free; of the apps, packrat grew most, by 7.0 GB in about 7 days" {
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

// A wall clock stepped back leaves samples in the ring from after now,
// which no round would age out, and rounds faster than once a minute
// would outgrow the window's minutes. The fit's cost grows with the
// square of the ring, so the ring stays bounded either way.
func TestTheForecastRingStaysBoundedWhenTheClockMisbehaves(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := forecastNow
	p := NewProber(store)
	p.Now = func() time.Time { return now }
	p.Disk = func(string) (uint64, uint64, bool) { return uint64(50 * gib), uint64(100 * gib), true }

	p.minutes = series(360, time.Minute, flat(50*gib))
	now = now.Add(-7 * 24 * time.Hour)
	start := now
	for range 30 {
		p.host(ctx)
		now = now.Add(time.Minute)
	}
	if n := len(p.minutes); n != 30 || p.minutes[0].At != start {
		t.Fatalf("a week after the clock stepped back, the ring keeps %d samples from %s", n, p.minutes[0].At)
	}

	p.minutes = series(2000, 10*time.Second, flat(50*gib))
	now = forecastNow.Add(10 * time.Second)
	p.host(ctx)
	if n := len(p.minutes); n != minutesKept || p.minutes[n-1].At != now {
		t.Fatalf("rounds every 10 seconds left %d samples, the newest from %s", n, p.minutes[n-1].At)
	}
}
