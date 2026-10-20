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
// RecentClimb says whether a burst goes on. The slope is in bytes a
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
	// its level, by their median. On a noisy disk a temp file that sits
	// for a few hours can have only one of its edges sudden, and twelve
	// samples outvote one that sits in up to five of them. With three, one
	// that sits in two, as one that spans the end of an hour does in the
	// hourly maxima, would be the median, and that edge a step.
	ShiftLevelSamples = 12
	// ShiftPairSamples is how many samples after a step's end the step
	// that undoes it may start, for the two to be one passing bump, such
	// as a temp file that sits for hours or a staged dump: a day of the
	// hourly samples, or 24 minutes of the minute ones.
	ShiftPairSamples = 24
)

// WithoutShifts returns a copy of the points with the one-off changes in
// usage set aside, so that only the steady growth around them counts.
//
// The steady rate is the median rate between samples, and a sample's
// level is its usage less the steady growth since the first sample. A
// change in level between two samples is sudden when it is larger than
// ShiftSpread times the noise, which 1.4826 times the median change
// estimates, or, on a series quieter than that, than floor over
// ShiftMaxSamples. Sudden changes either way, with at most ShiftGap quiet
// ones between them, make one event, and the samples between its first
// change and its last are inside it. Its size is the median level of the
// ShiftLevelSamples samples from the one its last change lands on, less
// the median level of the ShiftLevelSamples samples before its first
// change. Neither run of samples reaches into a neighbouring event.
//
// An event larger than floor, or than a sudden change if that is larger,
// is a step, a rise or a fall. Two events one each way, with no event
// between them and at least one of them a step, are one passing bump,
// such as a temp file that sat for hours or a staged dump, when their
// sizes cancel to within that same amount, the second starts within
// ShiftPairSamples samples of the first's end, and the second ends before
// the newest sample. Only one need be a step, since noise can put one
// edge of a temp file just over that amount and the other just under it.
// A straight line then joins the samples either side of the two, and
// neither counts as a step. Pairs are taken oldest first. Any other event
// no larger than that is a passing bump too, such as a temp file or a
// nightly dump, when it spans at most ShiftMaxSamples changes and ends
// before the newest sample, and a straight line joins the samples either
// side of it.
//
// The steps left are tallied each way. A rise, or a fall, is taken out
// when it is the only one its way, spans at most ShiftMaxSamples changes
// and ends before the newest sample: the samples inside it follow the
// level before it, and every later sample moves back by its size. More
// than one is the series' rhythm, such as a nightly import or a log
// rotation, which Theil-Sen reads right, and a step that spans more
// changes is growth; neither is changed. Nothing that reaches the newest
// sample is changed: it may be a runaway that is still going.
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
	// big is how far an event must move the level to be a step, and how
	// close a pair of steps must come to cancelling to be a bump.
	big := math.Max(limit, floor)

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
	// smooth joins the samples either side of from through to-1 with a
	// straight line.
	smooth := func(from, to int) {
		a, b := points[from-1], points[to]
		span := b.At.Sub(a.At).Seconds()
		for k := from; k < to; k++ {
			if span > 0 {
				out[k].Used = a.Used + (b.Used-a.Used)*points[k].At.Sub(a.At).Seconds()/span
			} else {
				out[k].Used = a.Used
			}
		}
	}

	type step struct {
		event
		before, size float64
		// short is at most ShiftMaxSamples changes, and done ends before
		// the newest sample.
		short, done bool
	}
	steps := make([]step, len(events))
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
		steps[j] = step{event: e, before: before, size: levelOf(e.to, hi) - before, short: e.to-e.from+1 <= ShiftMaxSamples, done: e.to < n-1}
	}
	// A step and the one that undoes it soon after are one passing bump.
	// Tallied apart, each would block a real step its way from being
	// taken out, and leave its own partner to be taken out alone.
	paired := make([]bool, len(steps))
	for j := 0; j+1 < len(steps); j++ {
		a, b := steps[j], steps[j+1]
		if math.Max(math.Abs(a.size), math.Abs(b.size)) > big && (a.size > 0) != (b.size > 0) &&
			math.Abs(a.size+b.size) <= big && b.done && b.from-a.to <= ShiftPairSamples {
			paired[j], paired[j+1] = true, true
			smooth(a.from, b.to)
			j++
		}
	}
	var rises, falls []step
	for j, s := range steps {
		switch {
		case paired[j]:
		case s.size > big:
			rises = append(rises, s)
		case s.size < -big:
			falls = append(falls, s)
		case s.short && s.done:
			smooth(s.from, s.to)
		}
	}
	for _, steps := range [][]step{rises, falls} {
		if len(steps) != 1 || !steps[0].short || !steps[0].done {
			continue
		}
		s := steps[0]
		// The samples inside follow the level before at the steady rate,
		// and every one after moves back by the step's size. Both are
		// changes to what is already in out, so a rise and a fall both
		// taken out add up, and a bump smoothed after a step moves with it.
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

// RecentClimb is how fast usage climbed across the newest window of the
// points, in bytes a second. It takes the samples within end of the
// window's oldest one and those within end of its newest, and divides the
// change in their median usage by the time between their median times.
// When the points span less than window, as after a restart, the window
// is all of them. Medians keep a sample or two of noise at either end
// from setting the climb, and a burst anywhere between the ends counts in
// full, however quiet the rest of the window. It is not ok unless each
// end holds at least minPoints samples and the two ends share none.
func RecentClimb(points []Point, window, end time.Duration, minPoints int) (perSecond float64, ok bool) {
	n := len(points)
	if n == 0 {
		return 0, false
	}
	newest := points[n-1].At
	first := n - 1
	for first > 0 && !points[first-1].At.Before(newest.Add(-window)) {
		first--
	}
	oldest := points[first].At
	// The oldest end is first through head-1, the newest tail through n-1.
	head, tail := first, n
	for head < n && points[head].At.Before(oldest.Add(end)) {
		head++
	}
	for tail > first && points[tail-1].At.After(newest.Add(-end)) {
		tail--
	}
	minPoints = max(minPoints, 1)
	if head-first < minPoints || n-tail < minPoints || head > tail {
		return 0, false
	}
	fromAt, fromUsed := middle(points[first:head], oldest)
	toAt, toUsed := middle(points[tail:], oldest)
	if toAt <= fromAt {
		return 0, false
	}
	return (toUsed - fromUsed) / (toAt - fromAt), true
}

// middle is the median time of the points, in seconds after base, and
// their median usage.
func middle(points []Point, base time.Time) (at, used float64) {
	ats, useds := make([]float64, len(points)), make([]float64, len(points))
	for i, p := range points {
		ats[i], useds[i] = p.At.Sub(base).Seconds(), p.Used
	}
	return median(ats), median(useds)
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
	return filling(slope, free), true
}

// filling is the trend of usage growing perSecond, a positive rate, with
// free bytes left.
func filling(perSecond float64, free uint64) Trend {
	seconds := float64(free) / perSecond
	full := time.Duration(math.MaxInt64)
	if seconds < full.Seconds() {
		full = time.Duration(seconds * float64(time.Second))
	}
	return Trend{PerSecond: perSecond, Full: full}
}
