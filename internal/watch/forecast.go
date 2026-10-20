package watch

import (
	"math"
	"sort"
	"time"
)

// Point is one sample of the bytes in use on a filesystem.
type Point struct {
	At   time.Time
	Used float64
}

// TheilSen fits a line through the points. The slope is the median of the
// slopes between every pair of points, and the intercept the median of
// what each point leaves over that slope, so a few odd samples or a short
// burst can't swing the fit. A step that moves every later sample can,
// when it sits near the middle of the points: WithoutShifts takes a lone
// one out first. The slope is in bytes a second and the intercept is the
// fitted value at the first point's time. It is not ok without two points
// at different times.
func TheilSen(points []Point) (slope, intercept float64, ok bool) {
	if len(points) < 2 {
		return 0, 0, false
	}
	base := points[0].At
	slopes := make([]float64, 0, len(points)*(len(points)-1)/2)
	for i := range points {
		for j := i + 1; j < len(points); j++ {
			dt := points[j].At.Sub(points[i].At).Seconds()
			if dt == 0 {
				continue
			}
			slopes = append(slopes, (points[j].Used-points[i].Used)/dt)
		}
	}
	if len(slopes) == 0 {
		return 0, 0, false
	}
	slope = median(slopes)
	residuals := make([]float64, len(points))
	for i, p := range points {
		residuals[i] = p.Used - slope*p.At.Sub(base).Seconds()
	}
	return slope, median(residuals), true
}

// median sorts the values in place and returns the middle one, or the
// mean of the middle two.
func median(values []float64) float64 {
	sort.Float64s(values)
	mid := len(values) / 2
	if len(values)%2 == 0 {
		return (values[mid-1] + values[mid]) / 2
	}
	return values[mid]
}

// What WithoutShifts takes for a step in usage.
const (
	// ShiftSpread is how many times the usual stray from the steady rate
	// a change between two samples must stray to be sudden.
	ShiftSpread = 5.0
	// ShiftMaxSamples is the most samples a step may take. A longer run
	// of sudden changes is growth, and stays.
	ShiftMaxSamples = 10
)

// WithoutShifts returns a copy of the points with each lone step in usage
// taken out, such as a cleanup or a large download, so that only the
// steady growth around it counts. The change into a sample is sudden when
// it strays from the median rate between samples by more than ShiftSpread
// times the usual stray, and by more than floor bytes. A step is a run of
// at most ShiftMaxSamples sudden changes the same way that ends before
// the newest sample: a run that reaches it may be a runaway that is still
// growing. A step is taken out only when it is the one run of sudden
// changes its way. More than one is the series' rhythm, such as a nightly
// import or a log rotation, and Theil-Sen reads a rhythm right. Taking a
// step out moves every later sample back by its size.
func WithoutShifts(points []Point, floor float64) []Point {
	out := append([]Point(nil), points...)
	n := len(points)
	rates := make([]float64, 0, n)
	for i := 1; i < n; i++ {
		if dt := points[i].At.Sub(points[i-1].At).Seconds(); dt > 0 {
			rates = append(rates, (points[i].Used-points[i-1].Used)/dt)
		}
	}
	if len(rates) < 2 {
		return out
	}
	// The steady rate keeps a gap between samples from reading as a jump.
	rate := median(rates)
	strays := make([]float64, n)
	sizes := make([]float64, 0, n)
	for i := 1; i < n; i++ {
		strays[i] = points[i].Used - points[i-1].Used - rate*points[i].At.Sub(points[i-1].At).Seconds()
		sizes = append(sizes, math.Abs(strays[i]))
	}
	// 1.4826 times the median absolute stray estimates the noise's
	// standard deviation.
	limit := math.Max(ShiftSpread*1.4826*median(sizes), floor)
	sudden := func(i int) bool { return math.Abs(strays[i]) > limit }

	type run struct{ from, to int }
	var rises, falls []run
	for i := 1; i < n; i++ {
		if !sudden(i) {
			continue
		}
		r := run{from: i, to: i}
		for r.to+1 < n && sudden(r.to+1) && (strays[r.to+1] > 0) == (strays[i] > 0) {
			r.to++
		}
		if strays[i] > 0 {
			rises = append(rises, r)
		} else {
			falls = append(falls, r)
		}
		i = r.to
	}
	for _, runs := range [][]run{rises, falls} {
		if len(runs) != 1 || runs[0].to-runs[0].from+1 > ShiftMaxSamples || runs[0].to == n-1 {
			continue
		}
		taken := 0.0
		for i := runs[0].from; i < n; i++ {
			if i <= runs[0].to {
				taken += strays[i]
			}
			out[i].Used -= taken
		}
	}
	return out
}

// Trend is how fast a filesystem fills, and how long its free space lasts.
type Trend struct {
	// PerSecond is the fitted growth in bytes a second; always positive.
	PerSecond float64
	// Full is how long the free space lasts at that rate, counted from
	// the free space now rather than from the fitted line, so a cleanup
	// counts at once.
	Full time.Duration
}

// Forecast fits the points and says when the free bytes run out. It is
// not ok with fewer than minPoints points, or when usage isn't growing.
func Forecast(points []Point, minPoints int, free uint64) (Trend, bool) {
	if len(points) < minPoints {
		return Trend{}, false
	}
	slope, _, ok := TheilSen(points)
	if !ok || slope <= 0 || math.IsNaN(slope) || math.IsInf(slope, 0) {
		return Trend{}, false
	}
	seconds := float64(free) / slope
	full := time.Duration(math.MaxInt64)
	if seconds < full.Seconds() {
		full = time.Duration(seconds * float64(time.Second))
	}
	return Trend{PerSecond: slope, Full: full}, true
}
