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
// what each point leaves over that slope, so a few odd samples, such as a
// cleanup or a burst, can't swing the fit. The slope is in bytes a second
// and the intercept is the fitted value at the first point's time. It is
// not ok without two points at different times.
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
