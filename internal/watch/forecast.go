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
// when it sits near the middle of the points, and so can a burst that has
// since stopped: WithoutShifts sets a lone step aside first, and
// StillClimbing says whether a burst goes on. The slope is in bytes a
// second and the intercept is the fitted value at the first point's time.
// It is not ok without two points at different times.
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

// What WithoutShifts takes for a one-off change in usage.
const (
	// ShiftSpread is how many times the usual stray from the steady rate
	// a change between two samples must stray to be sudden.
	ShiftSpread = 5.0
	// ShiftMaxSamples is the most changes a step may take. A longer event
	// is growth, and stays.
	ShiftMaxSamples = 10
	// ShiftGap is how many quiet changes may fall between two sudden ones
	// of the same event, so a download whose throughput dips for a sample
	// or two, or a temp file that sits for a sample or two, is one event.
	ShiftGap = 2
	// ShiftLevelSamples is how many samples either side of an event give
	// its level, by their median, so one noisy sample can't set its size.
	ShiftLevelSamples = 3
)

// WithoutShifts returns a copy of the points with the one-off changes in
// usage set aside, so that only the steady growth around them counts.
//
// A change between two samples is sudden when it strays from the median
// rate between samples by more than ShiftSpread times the usual stray, or,
// on a series quieter than that, by more than floor over ShiftMaxSamples.
// Sudden changes either way, with at most ShiftGap quiet ones between
// them, make one event. Its size is the level after it less the level
// before, beyond the steady rate. An event is a passing bump, such as a
// temp file or a nightly dump, when its size is no more than floor, or
// than the stray a sudden change needs if that is larger: if it spans at
// most ShiftMaxSamples changes, the samples inside it are smoothed over
// and nothing later moves. A larger event is a step, a rise or a fall,
// when it spans at most ShiftMaxSamples changes, and growth when it spans
// more. A step is taken out, moving every later sample back by its size,
// when it is the only step or growth its way. More than one is the
// series' rhythm, such as a nightly import or a log rotation, and
// Theil-Sen reads a rhythm right. Nothing that reaches the newest sample
// is changed: it may be a runaway that is still going.
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
	// level is a sample less the steady growth since the first one.
	level := func(i int) float64 { return points[i].Used - rate*points[i].At.Sub(points[0].At).Seconds() }
	strays := make([]float64, n)
	sizes := make([]float64, 0, n)
	for i := 1; i < n; i++ {
		strays[i] = level(i) - level(i-1)
		sizes = append(sizes, math.Abs(strays[i]))
	}
	// 1.4826 times the median absolute stray estimates the noise's
	// standard deviation. On a quieter series, such as one whose strays
	// are rounding, a step of floor spread over ShiftMaxSamples changes
	// still reads as sudden, and rounding doesn't.
	limit := math.Max(ShiftSpread*1.4826*median(sizes), floor/ShiftMaxSamples)
	sudden := func(i int) bool { return math.Abs(strays[i]) > limit }

	// An event covers the changes into samples from through to.
	type event struct{ from, to int }
	var events []event
	for i := 1; i < n; i++ {
		if !sudden(i) {
			continue
		}
		e := event{from: i, to: i}
		for k := i + 1; k < n && k <= e.to+ShiftGap+1; k++ {
			if sudden(k) {
				e.to = k
			}
		}
		events = append(events, e)
		i = e.to
	}
	// levelOf is the median level of the samples from lo through hi.
	levelOf := func(lo, hi int) float64 {
		levels := make([]float64, 0, hi-lo+1)
		for k := lo; k <= hi; k++ {
			levels = append(levels, level(k))
		}
		return median(levels)
	}

	type step struct {
		event
		before, size float64
		removable    bool
	}
	var rises, falls []step
	for j, e := range events {
		// The levels either side never reach into a neighbouring event.
		lo, hi := max(0, e.from-ShiftLevelSamples), min(n-1, e.to+ShiftLevelSamples-1)
		if j > 0 {
			lo = max(lo, events[j-1].to)
		}
		if j+1 < len(events) {
			hi = min(hi, events[j+1].from-1)
		}
		before := levelOf(lo, e.from-1)
		size := levelOf(e.to, hi) - before
		short, done := e.to-e.from+1 <= ShiftMaxSamples, e.to < n-1
		switch {
		case math.Abs(size) > math.Max(limit, floor):
			s := step{event: e, before: before, size: size, removable: short && done}
			if size > 0 {
				rises = append(rises, s)
			} else {
				falls = append(falls, s)
			}
		case short && done:
			// A passing bump: a straight line joins the samples either side.
			a, b := points[e.from-1], points[e.to]
			span := b.At.Sub(a.At).Seconds()
			for k := e.from; k < e.to; k++ {
				if span > 0 {
					out[k].Used = a.Used + (b.Used-a.Used)*points[k].At.Sub(a.At).Seconds()/span
				} else {
					out[k].Used = a.Used
				}
			}
		}
	}
	for _, steps := range [][]step{rises, falls} {
		if len(steps) != 1 || !steps[0].removable {
			continue
		}
		s := steps[0]
		// The samples inside follow the level before at the steady rate,
		// and every one after moves back by the step's size. Both are
		// changes to what is already in out, so a rise and a fall both
		// taken out add up.
		for k := s.from; k < n; k++ {
			if k < s.to {
				out[k].Used += s.before - level(k)
			} else {
				out[k].Used -= s.size
			}
		}
	}
	return out
}

// StillClimbing reports whether the points within recent of the newest
// one, at least minPoints of them, climb at half of slope or more. A trend
// fitted over hours keeps reading a burst that has stopped, such as a
// finished download, as growth. A runaway still going climbs at its own
// rate, which the longer trend lags, so half leaves room either way.
func StillClimbing(points []Point, recent time.Duration, minPoints int, slope float64) bool {
	if len(points) == 0 {
		return false
	}
	since := points[len(points)-1].At.Add(-recent)
	first := len(points)
	for first > 0 && points[first-1].At.After(since) {
		first--
	}
	if len(points)-first < minPoints {
		return false
	}
	climb, _, ok := TheilSen(points[first:])
	return ok && climb >= slope/2
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
