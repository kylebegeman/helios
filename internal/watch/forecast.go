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
// Climbing says whether usage still climbs. The slope is in bytes a
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

// steady is the median rate between the points, in bytes a second, and
// how far the change into each point strays from it: strays[i] is the
// change in level from point i-1 to point i, a point's level being its
// usage less the steady growth since the first point. The steady rate
// keeps a gap between samples from reading as a jump. It is not ok
// without two changes at different times.
func steady(points []Point) (rate float64, strays []float64, ok bool) {
	n := len(points)
	rates := make([]float64, 0, n)
	for i := 1; i < n; i++ {
		if dt := points[i].At.Sub(points[i-1].At).Seconds(); dt > 0 {
			rates = append(rates, (points[i].Used-points[i-1].Used)/dt)
		}
	}
	if len(rates) < 2 {
		return 0, nil, false
	}
	rate = median(rates)
	level := func(i int) float64 { return points[i].Used - rate*points[i].At.Sub(points[0].At).Seconds() }
	strays = make([]float64, n)
	for i := 1; i < n; i++ {
		strays[i] = level(i) - level(i-1)
	}
	return rate, strays, true
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
// change and its last are inside it. When they go one way and then the
// other, and each way and the two together move the level more than a
// step must (below), they are two events instead, such as a burst and a
// temp file deleted minutes after it. Its size is the median level of the
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
	rate, strays, ok := steady(points)
	if !ok {
		return out
	}
	// level is a sample less the steady growth since the first one.
	level := func(i int) float64 { return points[i].Used - rate*points[i].At.Sub(points[0].At).Seconds() }
	sizes := make([]float64, 0, n)
	for _, s := range strays[1:] {
		sizes = append(sizes, math.Abs(s))
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
	// split makes an event whose sudden changes go one way and then the
	// other two events, when each way and the two together move the level
	// more than big. Read as one, a burst and a temp file deleted minutes
	// after it would net to a fall that pairs with the burst before them,
	// and both bursts would be smoothed away.
	split := func(e event) []event {
		way := func(i int) bool { return strays[i] > 0 }
		// The sudden changes go one way through q and the other from p.
		p := e.from + 1
		for p <= e.to && !(sudden(p) && way(p) != way(e.from)) {
			p++
		}
		if p > e.to {
			return []event{e}
		}
		q := p - 1
		for !sudden(q) {
			q--
		}
		var first, second float64
		for k := e.from; k <= q; k++ {
			first += strays[k]
		}
		for k := p; k <= e.to; k++ {
			if sudden(k) && way(k) != way(p) {
				return []event{e}
			}
			second += strays[k]
		}
		if math.Abs(first) > big && math.Abs(second) > big && math.Abs(first+second) > big {
			return []event{{e.from, q}, {p, e.to}}
		}
		return []event{e}
	}
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
		events = append(events, split(e)...)
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

// What Climbing takes for usage that still climbs.
const (
	// ClimbSpread is how many times the usual stray from the steady rate
	// usage must rise past its high-water mark to make progress. Two
	// samples of uniform noise differ by at most 2.3 times its usual
	// stray, so noise around a level makes none. On a quieter series it
	// is floor over ShiftMaxSamples, as for a sudden change, so rounding
	// and small writes make none either.
	ClimbSpread = 3.0
	// ClimbFall is how many times that rise usage must fall below the
	// highest point of its climb for the fall to be real, such as a
	// cleanup. The climb then starts again from the bottom of the fall,
	// so a runaway that goes on under a cleanup makes progress again as
	// soon as it rises past the noise, not once it has made the cleanup
	// up.
	ClimbFall = 2.0
	// ClimbQuiet is how long usage may stall and still climb, without a
	// rhythm. A download that finished more than ClimbQuiet ago no longer
	// climbs, even seen by a round every 5 minutes.
	ClimbQuiet = 40 * time.Minute
	// ClimbEpisodeGap is the longest pause in progress within one episode
	// of it, such as one burst of a bursty runaway. A steady runaway seen
	// by a round every 5 minutes, or one that slips a round, is one long
	// episode.
	ClimbEpisodeGap = 15 * time.Minute
	// ClimbEpisodeRises is how many rises' worth of the climb's rate a
	// pause may also last within one episode. A steady climb makes
	// progress each time it rises past the noise, and noise can hold that
	// back by most of another rise, so on a noisy disk a slow steady
	// runaway is one episode too, not a rhythm of its own.
	ClimbEpisodeRises = 2.0
	// ClimbRhythm is how many episodes, each larger than the floor, make
	// a rhythm, such as a bursty runaway's: two gaps between them. While
	// usage holds one, it still climbs until ClimbRhythmSlack times the
	// longest of those gaps has passed since the newest episode, so a
	// burst may come late by half the longest wait so far, but no later.
	ClimbRhythm      = 3
	ClimbRhythmSlack = 1.5
)

// Climb is how usage climbs at the newest of the points.
type Climb struct {
	// Going says usage still climbs.
	Going bool
	// Since is how long usage has stayed about the top of its climb,
	// within the rise that makes progress, less the time a real fall took.
	Since time.Duration
	// PerSecond is how fast usage climbed, in bytes a second, measured
	// over the newest Span of the points.
	PerSecond float64
	Span      time.Duration
}

// Climbing says whether usage still climbs at the newest of the points,
// and how fast. The points may come as sampled, or with their one-off
// steps set aside as for the trend.
//
// Usage makes progress when it rises more than ClimbSpread times the
// noise, which 1.4826 times the median stray from the steady rate
// estimates, past its high-water mark, and the mark moves up to it. A dip
// doesn't lower the mark, so the climb back from it makes no progress,
// but a real fall, ClimbFall times that rise below the climb's highest
// point, starts the climb again from the fall's lowest point. Progress
// no more than ClimbEpisodeGap apart, or ClimbEpisodeRises rises at the
// climb's rate if longer, is one episode. The climb has stalled since
// usage first came within that rise of its highest point: noise about a
// level it has stopped at stays within the rise, so it never moves that
// time on. A real fall stops the clock, for ClimbQuiet at most, and after
// it the climb starts again from the bottom.
//
// Usage still climbs while it has stalled for at most ClimbQuiet. It also
// climbs while the points hold a rhythm, ClimbRhythm or more episodes
// each larger than floor, and the newest of them ended at most
// ClimbRhythmSlack times the longest gap between their ends ago. A bursty
// runaway's flat stretch is within its own period, while one download is
// one episode and no rhythm, and the flat stretch after it goes quiet.
//
// The rate is the progress over whole episodes, so that where the newest
// point falls in a burst's cycle can't undercount it, and a fall doesn't
// count against it, so a cleanup can't hide a runaway. With a rhythm it
// runs between episodes' ends, from the earliest within recent of the
// newest point, or else the one before the newest, to the newest.
// Otherwise it runs across the progress within recent of the newest
// point, or else the last two, or the first point and the only one. It
// is not ok without two changes at different times.
func Climbing(points []Point, floor float64, recent time.Duration) (Climb, bool) {
	n := len(points)
	_, strays, ok := steady(points)
	if !ok {
		return Climb{}, false
	}
	sizes := make([]float64, 0, n-1)
	for _, s := range strays[1:] {
		sizes = append(sizes, math.Abs(s))
	}
	rise := math.Max(ClimbSpread*1.4826*median(sizes), floor/ShiftMaxSamples)

	// progress is usage rising past its high-water mark at point i, and
	// total all the progress up to it.
	type progress struct {
		i     int
		total float64
	}
	var made []progress
	mark, total := points[0].Used, 0.0
	// The climb runs from start, the first point or the bottom of the
	// last real fall, and top is its highest point. While usage falls,
	// fell is where the fall began and bottom its lowest point so far,
	// and start and top still hold the climb before it.
	start, top, fell, bottom := 0, 0, -1, -1
	for i := 1; i < n; i++ {
		used := points[i].Used
		if bottom >= 0 {
			if used < points[bottom].Used {
				bottom = i
			}
			if used <= points[bottom].Used+rise {
				continue
			}
			start, top, mark, bottom = bottom, bottom, points[bottom].Used, -1
		}
		if used > mark+rise {
			total += used - mark
			mark = used
			made = append(made, progress{i, total})
		}
		if used > points[top].Used {
			top = i
		}
		if used < points[top].Used-ClimbFall*rise {
			fell, bottom = i, i
		}
	}
	last := top
	for last > start && points[last-1].Used >= points[top].Used-rise {
		last--
	}
	newest := points[n-1].At
	c := Climb{Since: newest.Sub(points[last].At)}
	if bottom >= 0 {
		// The clock stops while usage falls, from when it left the top
		// of its climb until it reached the bottom of the fall, so a
		// cleanup that takes a while doesn't run out a runaway's time.
		// It stops for ClimbQuiet at most: a disk that keeps shrinking
		// for longer has stopped climbing.
		left, reached := fell, bottom
		for points[left].Used < points[top].Used-rise {
			left--
		}
		for reached-1 > left && points[reached-1].Used <= points[bottom].Used+rise {
			reached--
		}
		c.Since -= min(points[reached].At.Sub(points[left].At), ClimbQuiet)
	}
	if len(made) == 0 {
		return c, true
	}

	// Each episode ends at progress more than pause before the next, and
	// ends holds those larger than floor.
	pause := ClimbEpisodeGap
	first, latest := made[0], made[len(made)-1]
	if climbed := latest.total - first.total; climbed > 0 {
		span := points[latest.i].At.Sub(points[first.i].At)
		pause = max(pause, time.Duration(ClimbEpisodeRises*rise/climbed*float64(span)))
	}
	var ends []progress
	before := 0.0
	for k, p := range made {
		if k+1 < len(made) && points[made[k+1].i].At.Sub(points[p.i].At) <= pause {
			continue
		}
		if p.total-before > floor {
			ends = append(ends, p)
		}
		before = p.total
	}
	rhythm := false
	if len(ends) >= ClimbRhythm {
		var longest time.Duration
		for k := 1; k < len(ends); k++ {
			longest = max(longest, points[ends[k].i].At.Sub(points[ends[k-1].i].At))
		}
		rhythm = newest.Sub(points[ends[len(ends)-1].i].At) <= time.Duration(ClimbRhythmSlack*float64(longest))
	}
	c.Going = c.Since <= ClimbQuiet || rhythm

	// The rate runs from progress from to progress to; the first point
	// has none before it.
	marks := made
	if rhythm {
		marks = ends
	}
	from, to := progress{0, 0}, marks[len(marks)-1]
	if k := len(marks) - 2; k >= 0 {
		from = marks[k]
		for k--; k >= 0 && !points[marks[k].i].At.Before(newest.Add(-recent)); k-- {
			from = marks[k]
		}
	}
	if span := points[to.i].At.Sub(points[from.i].At); span > 0 {
		c.PerSecond = (to.total - from.total) / span.Seconds()
		c.Span = newest.Sub(points[from.i].At)
	}
	return c, true
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
