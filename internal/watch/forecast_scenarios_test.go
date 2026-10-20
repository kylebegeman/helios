package watch

// The IA-06 round-five scenario corpus for the short window of the disk
// forecast.
//
// Each row is a named scenario: a generator of the bytes in use at any
// minute on a disk of a fixed size, plus what the operator should see.
// Every variant runs round by round through the real disk path: the
// Prober's minute ring and diskConditions through host, the hourly
// MaxSignal history the signals sampler keeps, and a real Watcher on a
// real temp state store. Noise is a fixed function of the seed and the
// sample time, so every run is the same.
//
// Minutes are each scenario's own clock, minute 0 being scnEpoch, and
// sizes are GiB. Expectations are about host:disk-forecast only, as the
// operator sees it: when its incident opens, at what severity, and
// whether it resolves before the disk is full.
//
// Standing decisions, never counted as failures, so no check asserts
// against them:
//   - The 6 hour trend lags a regime change.
//   - A runaway started an hour ago may not page yet.
//   - A 3 or 12 hour plateau in heavy noise is sometimes misread.
//   - Detrending is biased in heavy noise.
//   - A download in progress that really would fill the disk within 6
//     hours at its current rate may page while it runs.
//
// Where those leave the answer open, the row says so and checks only
// what they leave unambiguous.

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

const scnKey = "host:disk-forecast"

// scnEpoch is minute 0 of every scenario.
var scnEpoch = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// scnMiBps is GiB a minute for one MiB a second.
const scnMiBps = 60.0 / 1024

// scnScenario is one row: a named case and its variants (speeds, phases,
// seeds, cadences), each with its own checks.
type scnScenario struct {
	name     string
	source   string
	expect   string
	variants []scnSim
}

// scnSim is one variant: the disk, its usage, the daemon's rounds and
// what must hold.
type scnSim struct {
	name   string
	totalG float64
	// usedG is the GiB in use at minute m, before noise.
	usedG func(m float64) float64
	// noiseG is the amplitude of the uniform noise on every sample.
	noiseG float64
	seed   uint64
	// from is the first watched round and until the last; the run stops
	// early once the disk is full.
	from, until float64
	// gap is the minutes from round k to round k+1, and for k < 0 between
	// the ring's rounds before from. Nil is one minute.
	gap func(k int) float64
	// rounds, when set, are the round minutes instead of from, until and
	// gap; the ring before them is then one round a minute.
	rounds []float64
	// running means the daemon ran through the 6 hours before from, so
	// the ring already holds those rounds.
	running bool
	// noHistory leaves no hourly samples before from.
	noHistory bool
	// restarts are minutes at which a new Prober (empty ring) and a new
	// Watcher on the same store take over.
	restarts []float64
	// From stepAt on, the wall clock reads stepBy minutes behind.
	stepAt, stepBy float64
	checks         []scnCheck
}

func (s *scnSim) every(k int) float64 {
	if s.gap == nil {
		return 1
	}
	return s.gap(k)
}

type scnCheck struct {
	name string
	run  func(t *testing.T, r *scnRun)
}

// scnRound is what one round left: the condition and the incident.
type scnRound struct {
	m       float64
	freeG   float64
	sev     string
	msg     string
	inc     int64
	incSev  string
	ring    int
	notices []string
}

type scnRun struct {
	rounds []scnRound
	full   bool
}

func TestDiskForecastScenarios(t *testing.T) {
	for _, sc := range scnCorpus() {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("source: %s", sc.source)
			t.Logf("expect: %s", sc.expect)
			for _, v := range sc.variants {
				t.Run(v.name, func(t *testing.T) {
					t.Parallel()
					r := scnDrive(t, &v)
					for _, c := range v.checks {
						t.Run(c.name, func(t *testing.T) { c.run(t, r) })
					}
				})
			}
		})
	}
}

// scnDrive runs a variant round by round through host and Watcher.Round.
func scnDrive(t *testing.T, s *scnSim) *scnRun {
	t.Helper()
	ctx := context.Background()
	n := &fakeNotifier{}
	w, nowp := newWatcher(t, n)
	total := s.totalG * gib
	clock := func(m float64) time.Time {
		at := scnEpoch.Add(time.Duration(math.Round(m * float64(time.Minute))))
		if s.stepBy > 0 && m >= s.stepAt {
			at = at.Add(-time.Duration(s.stepBy * float64(time.Minute)))
		}
		return at
	}
	sample := func(m float64) float64 {
		u := s.usedG(m) * gib
		if s.noiseG > 0 {
			u += s.noiseG * gib * wobble(s.seed<<44^uint64(int64(math.Round(m*60000))+1<<42))
		}
		return math.Max(0, math.Min(total, u))
	}

	// The sampler keeps the hourly maximum of every minute's sample.
	written := map[time.Time]float64{}
	record := func(m float64) {
		at := clock(m)
		h, u := at.Truncate(time.Hour), sample(m)
		if old, ok := written[h]; ok && old >= u {
			return
		}
		written[h] = u
		sig := state.Signal{Hour: at, App: manifest.ReservedApp, Key: state.SignalHostDiskRoot, Metric: state.SignalHostDiskUsed, Value: u}
		if err := w.Store.MaxSignal(ctx, sig); err != nil {
			t.Fatal(err)
		}
	}
	lastRecorded := math.Floor(s.from)
	if !s.noHistory {
		best := map[time.Time]float64{}
		var hours []time.Time
		for m := lastRecorded - float64(ForecastLongWindow/time.Minute); m <= lastRecorded; m++ {
			h, u := clock(m).Truncate(time.Hour), sample(m)
			if old, ok := best[h]; !ok {
				hours = append(hours, h)
			} else if old >= u {
				continue
			}
			best[h] = u
		}
		for _, h := range hours {
			written[h] = best[h]
			sig := state.Signal{Hour: h, App: manifest.ReservedApp, Key: state.SignalHostDiskRoot, Metric: state.SignalHostDiskUsed, Value: best[h]}
			if err := w.Store.MaxSignal(ctx, sig); err != nil {
				t.Fatal(err)
			}
		}
	}

	cur := s.from
	newProber := func() *Prober {
		p := NewProber(w.Store)
		p.Now = func() time.Time { return *nowp }
		p.Disk = func(string) (uint64, uint64, bool) {
			return uint64(total - sample(cur)), uint64(total), true
		}
		return p
	}
	p := newProber()
	if s.running {
		var ring []Point
		m := s.from
		for k := -1; ; k-- {
			if s.rounds != nil {
				m--
			} else {
				m -= s.every(k)
			}
			if m <= s.from-float64(ForecastShortWindow/time.Minute) {
				break
			}
			ring = append(ring, Point{At: clock(m), Used: sample(m)})
		}
		for i, j := 0, len(ring)-1; i < j; i, j = i+1, j-1 {
			ring[i], ring[j] = ring[j], ring[i]
		}
		p.minutes = ring
	}

	times := s.rounds
	if times == nil {
		m := s.from
		for k := 0; m <= s.until; k++ {
			times = append(times, m)
			m += s.every(k)
		}
	}
	run := &scnRun{}
	restarts := s.restarts
	for _, m := range times {
		if len(restarts) > 0 && m >= restarts[0] {
			restarts = restarts[1:]
			p = newProber()
			w = &Watcher{Store: w.Store, Notifier: n, Hostname: "box", Now: w.Now}
		}
		for x := lastRecorded + 1; x <= m; x++ {
			record(x)
			lastRecorded = x
		}
		cur = m
		*nowp = clock(m)
		sent := len(n.sent)
		conditions := p.host(ctx)
		if err := w.Round(ctx, conditions); err != nil {
			t.Fatal(err)
		}
		r := scnRound{m: m, freeG: (total - sample(m)) / gib, ring: len(p.minutes)}
		for _, c := range conditions {
			if c.Key == scnKey {
				r.sev, r.msg = c.Severity, c.Message
			}
		}
		inc, err := w.Store.OpenIncidentByKey(ctx, scnKey)
		if err != nil {
			t.Fatal(err)
		}
		if inc != nil {
			r.inc, r.incSev = inc.ID, inc.Severity
		}
		for _, x := range n.sent[sent:] {
			if x.Key == scnKey {
				r.notices = append(r.notices, x.Transition)
			}
		}
		run.rounds = append(run.rounds, r)
		if sample(m) >= total {
			run.full = true
			break
		}
	}
	return run
}

// timeline lists the rounds where the condition, the incident or the
// notices changed.
func (r *scnRun) timeline() string {
	var b strings.Builder
	prev, lines := "", 0
	for _, x := range r.rounds {
		inc := "closed"
		if x.inc != 0 {
			inc = fmt.Sprintf("open #%d %s", x.inc, x.incSev)
		}
		key := fmt.Sprintf("%s|%s|%v", x.sev, inc, x.notices)
		if key == prev {
			continue
		}
		prev = key
		if lines++; lines > 120 {
			b.WriteString("  ...\n")
			break
		}
		cond := "none"
		if x.sev != "" {
			cond = x.sev + ": " + x.msg
		}
		fmt.Fprintf(&b, "  minute %8.2f  free %6.2f  incident %-18s notices %-10v condition %s\n", x.m, x.freeG, inc, x.notices, cond)
	}
	if n := len(r.rounds); n > 0 {
		fmt.Fprintf(&b, "  last round at minute %.2f, %.2f GiB free, full %v\n", r.rounds[n-1].m, r.rounds[n-1].freeG, r.full)
	}
	return b.String()
}

func scnFail(t *testing.T, r *scnRun, format string, args ...any) {
	t.Helper()
	t.Errorf(format+"\ntimeline:\n%s", append(args, r.timeline())...)
}

// scnFirst is the first round at or after minute m, or -1.
func scnFirst(r *scnRun, m float64) int {
	for i, x := range r.rounds {
		if x.m >= m-1e-9 {
			return i
		}
	}
	return -1
}

func scnAtMinute(m float64) func(*scnRun) int {
	return func(r *scnRun) int { return scnFirst(r, m) }
}

func scnAtRound(i int) func(*scnRun) int {
	return func(r *scnRun) int {
		if i < len(r.rounds) {
			return i
		}
		return -1
	}
}

func scnCritical(x scnRound) bool { return x.sev == state.SeverityCritical }

func scnPaging(x scnRound) bool { return x.inc != 0 && x.incSev == state.SeverityCritical }

// scnNeverOpens: no host:disk-forecast incident and no notice, ever.
func scnNeverOpens() scnCheck {
	return scnCheck{"never opens", func(t *testing.T, r *scnRun) {
		for _, x := range r.rounds {
			if x.inc != 0 || len(x.notices) > 0 {
				scnFail(t, r, "an incident is open at minute %.2f with %.2f GiB free", x.m, x.freeG)
				return
			}
		}
	}}
}

// scnNeverCritical: no critical condition at any round.
func scnNeverCritical() scnCheck {
	return scnCheck{"never critical", func(t *testing.T, r *scnRun) {
		for _, x := range r.rounds {
			if scnCritical(x) || scnPaging(x) {
				scnFail(t, r, "critical at minute %.2f with %.2f GiB free: %s", x.m, x.freeG, x.msg)
				return
			}
		}
	}}
}

// scnNoCriticalBefore: no critical condition at any round before m.
func scnNoCriticalBefore(m float64, label string) scnCheck {
	return scnCheck{"no critical condition before " + label, func(t *testing.T, r *scnRun) {
		for _, x := range r.rounds {
			if x.m < m && scnCritical(x) {
				scnFail(t, r, "critical at minute %.2f with %.2f GiB free: %s", x.m, x.freeG, x.msg)
				return
			}
		}
	}}
}

// scnNoConditionIn: no host:disk-forecast condition at all in [a, b).
func scnNoConditionIn(a, b float64, label string) scnCheck {
	return scnCheck{"no condition in " + label, func(t *testing.T, r *scnRun) {
		for _, x := range r.rounds {
			if x.m >= a && x.m < b && x.sev != "" {
				scnFail(t, r, "a %s condition at minute %.2f: %s", x.sev, x.m, x.msg)
				return
			}
		}
	}}
}

// scnNoCriticalAt: the round at m has no critical condition.
func scnNoCriticalAt(m float64, label string) scnCheck {
	return scnCheck{"no critical condition " + label, func(t *testing.T, r *scnRun) {
		i := scnFirst(r, m)
		if i < 0 {
			scnFail(t, r, "no round at or after minute %.2f", m)
			return
		}
		if x := r.rounds[i]; scnCritical(x) {
			scnFail(t, r, "critical at minute %.2f with %.2f GiB free: %s", x.m, x.freeG, x.msg)
		}
	}}
}

// scnCriticalAt: the round at m has a critical condition.
func scnCriticalAt(m float64, label string) scnCheck {
	return scnCheck{"critical condition " + label, func(t *testing.T, r *scnRun) {
		i := scnFirst(r, m)
		if i < 0 {
			scnFail(t, r, "no round at or after minute %.2f", m)
			return
		}
		if x := r.rounds[i]; !scnCritical(x) {
			scnFail(t, r, "no critical condition at minute %.2f with %.2f GiB free", x.m, x.freeG)
		}
	}}
}

// scnQuietFrom: no critical condition at any round from m on, and the
// incident, if one was open, is no longer critical from the round after.
func scnQuietFrom(m float64, label string) scnCheck {
	return scnCheck{"quiet from " + label, func(t *testing.T, r *scnRun) {
		i := scnFirst(r, m)
		if i < 0 {
			scnFail(t, r, "no round at or after minute %.2f", m)
			return
		}
		for j, x := range r.rounds[i:] {
			if scnCritical(x) {
				scnFail(t, r, "critical at minute %.2f with %.2f GiB free: %s", x.m, x.freeG, x.msg)
				return
			}
			if j > 0 && scnPaging(x) {
				scnFail(t, r, "the critical incident is still open at minute %.2f", x.m)
				return
			}
		}
	}}
}

// scnOpenBy: a critical incident is open at the given round.
func scnOpenBy(label string, at func(*scnRun) int) scnCheck {
	return scnCheck{"open critical by " + label, func(t *testing.T, r *scnRun) {
		i := at(r)
		if i < 0 {
			scnFail(t, r, "the run has no round at %s", label)
			return
		}
		if x := r.rounds[i]; !scnPaging(x) {
			scnFail(t, r, "no open critical incident at minute %.2f with %.2f GiB free", x.m, x.freeG)
		}
	}}
}

// scnHolds: a critical incident is open at the given round, stays open
// and critical at every round after it as the same incident, with no
// resolved notice, and the run reaches a full disk.
func scnHolds(label string, at func(*scnRun) int) scnCheck {
	return scnCheck{"held from " + label + " until the disk is full", func(t *testing.T, r *scnRun) {
		i := at(r)
		if i < 0 {
			scnFail(t, r, "the run has no round at %s", label)
			return
		}
		scnHeldFrom(t, r, i)
	}}
}

// scnHoldsOnceOpen: once the incident first opens it holds until full.
func scnHoldsOnceOpen() scnCheck {
	return scnCheck{"never resolved once open, until the disk is full", func(t *testing.T, r *scnRun) {
		for i, x := range r.rounds {
			if x.inc != 0 {
				scnHeldFrom(t, r, i)
				return
			}
		}
		scnFail(t, r, "the incident never opened")
	}}
}

func scnHeldFrom(t *testing.T, r *scnRun, i int) {
	t.Helper()
	first := r.rounds[i]
	if !scnPaging(first) {
		scnFail(t, r, "no open critical incident at minute %.2f with %.2f GiB free", first.m, first.freeG)
		return
	}
	for _, x := range r.rounds[i:] {
		for _, n := range x.notices {
			if n == TransitionResolved {
				scnFail(t, r, "resolved at minute %.2f with %.2f GiB free", x.m, x.freeG)
				return
			}
		}
		if x.inc != first.inc || x.incSev != state.SeverityCritical {
			scnFail(t, r, "at minute %.2f with %.2f GiB free the incident is not #%d critical", x.m, x.freeG, first.inc)
			return
		}
	}
	if !r.full {
		last := r.rounds[len(r.rounds)-1]
		scnFail(t, r, "the run ended at minute %.2f with %.2f GiB free, before the disk was full", last.m, last.freeG)
	}
}

// scnOnlyOpenNotices: the incident's only notices announce its opening.
func scnOnlyOpenNotices() scnCheck {
	return scnCheck{"only an open notice", func(t *testing.T, r *scnRun) {
		for _, x := range r.rounds {
			for _, n := range x.notices {
				if n != TransitionOpen {
					scnFail(t, r, "a %s notice at minute %.2f", n, x.m)
					return
				}
			}
		}
	}}
}

// scnRingBounded: the minute ring never holds more than minutesKept.
func scnRingBounded() scnCheck {
	return scnCheck{"the ring stays bounded", func(t *testing.T, r *scnRun) {
		for _, x := range r.rounds {
			if x.ring > minutesKept {
				scnFail(t, r, "the ring holds %d samples at minute %.2f", x.ring, x.m)
				return
			}
		}
	}}
}

// scnLogAt asserts nothing: the answer at m is open under the standing
// decisions, so the round is only logged.
func scnLogAt(m float64, label string) scnCheck {
	return scnCheck{"logged only " + label, func(t *testing.T, r *scnRun) {
		i := scnFirst(r, m)
		if i < 0 {
			return
		}
		x := r.rounds[i]
		t.Logf("minute %.2f, %.2f GiB free: condition %q %q, incident %d %s", x.m, x.freeG, x.sev, x.msg, x.inc, x.incSev)
	}}
}

// scnLogLastCritical asserts nothing: it logs the last round with a
// critical condition, to show how far inside its bound a quiet check is.
func scnLogLastCritical() scnCheck {
	return scnCheck{"logged only the last critical round", func(t *testing.T, r *scnRun) {
		for i := len(r.rounds) - 1; i >= 0; i-- {
			if x := r.rounds[i]; scnCritical(x) {
				t.Logf("last critical at minute %.2f, %.2f GiB free: %s", x.m, x.freeG, x.msg)
				return
			}
		}
		t.Logf("never critical")
	}}
}

// scnRamp is size spread evenly over dur minutes from start: none of it
// before, all of it after. A dur of 0 is a step at start.
func scnRamp(m, start, dur, size float64) float64 {
	switch {
	case m < start:
		return 0
	case dur <= 0 || m >= start+dur:
		return size
	default:
		return size * (m - start) / dur
	}
}

// scnRate is growth at rate GiB an hour between minutes start and end.
func scnRate(m, start, end, rate float64) float64 {
	return rate * (math.Max(start, math.Min(m, end)) - start) / 60
}

// scnBursts lands size every period from first to last, each over edge
// minutes.
func scnBursts(m, first, period, last, size, edge float64) float64 {
	if m < first {
		return 0
	}
	k := math.Floor((m - first) / period)
	if !math.IsInf(last, 1) {
		k = math.Min(k, math.Floor((last-first)/period))
	}
	return k*size + scnRamp(m, first+k*period, edge, size)
}

// scnAnchor is rise placed so that freeG is free at minute at.
func scnAnchor(totalG, freeG, at float64, rise func(float64) float64) func(float64) float64 {
	base := totalG - freeG - rise(at)
	return func(m float64) float64 { return base + rise(m) }
}

func scnEvery(minutes float64) func(int) float64 {
	return func(int) float64 { return minutes }
}

// scnJittered is a download of sizeG at about perMinute GiB a minute,
// each minute's rate off by up to jitter of it, that ends at minute 0.
// It returns the download's rise and its length in minutes.
func scnJittered(sizeG, perMinute, jitter float64, seed uint64) (func(float64) float64, float64) {
	done := []float64{0}
	for k := 0; done[k] < sizeG; k++ {
		step := perMinute * (1 + jitter*wobble(seed<<20+uint64(k)))
		done = append(done, math.Min(sizeG, done[k]+step))
	}
	length := float64(len(done) - 1)
	return func(m float64) float64 {
		switch x := m + length; {
		case x <= 0:
			return 0
		case x >= length:
			return sizeG
		default:
			k := int(x)
			return done[k] + (done[k+1]-done[k])*(x-float64(k))
		}
	}, length
}

// scnStallTicker is the daemon's one-minute ticker from minute from,
// each round under 5 ms late, where the first round at or after stall
// runs gap minutes. The ticker's one buffered tick starts a stale round
// as soon as it ends, and the next round is back on the minute grid.
func scnStallTicker(from, until, stall, gap float64, seed uint64) []float64 {
	late := func(k int) float64 { return 5e-3 / 60 * (wobble(seed<<24+uint64(k)) + 1) / 2 }
	var out []float64
	stalled := false
	for k := 0; from+float64(k) <= until; k++ {
		at := from + float64(k) + late(k)
		out = append(out, at)
		if !stalled && at >= stall {
			stalled = true
			end := at + gap
			out = append(out, end+late(k+1<<20))
			k = int(math.Floor(end - from))
		}
	}
	return out
}

func scnCorpus() []scnScenario {
	var out []scnScenario
	add := func(s scnScenario) { out = append(out, s) }
	inf := math.Inf(1)
	flat := func(level float64, rise func(float64) float64) func(float64) float64 {
		return func(m float64) float64 { return level + rise(m) }
	}
	runaway := func(start, rate float64) func(float64) float64 {
		return func(m float64) float64 { return scnRate(m, start, inf, rate) }
	}
	// download is a flat disk at level GiB of total with one download of
	// sizeG over dur minutes that ends at minute 0, watched by a daemon
	// that has run since well before it.
	download := func(name string, totalG, level, sizeG, dur, noise float64, checks ...scnCheck) scnSim {
		return scnSim{
			name: name, totalG: totalG, noiseG: noise, seed: 1,
			usedG: flat(level, func(m float64) float64 { return scnRamp(m, -dur, dur, sizeG) }),
			from:  -dur - 60, until: 240, running: true, checks: checks,
		}
	}
	quiet45 := scnQuietFrom(45, "45 minutes after the download")

	// Acceptance cases from the packet.

	add(scnScenario{
		name:   "acceptance steady growth",
		source: "packet acceptance: steady growth",
		expect: "2 GiB a day with 40 GiB free (20 days) never opens; 24 GiB a day on 1 TB with 200 GiB free (8 days) is never critical (the 7 day trend may warn)",
		variants: []scnSim{
			{name: "fills in 20 days", totalG: 100, usedG: func(m float64) float64 { return 60 + 2*m/1440 }, noiseG: 0.05, seed: 1, from: 0, until: 360, running: true,
				checks: []scnCheck{scnNeverOpens()}},
			{name: "fills in 8 days on 1 TB", totalG: 1000, usedG: func(m float64) float64 { return 800 + 24*m/1440 }, noiseG: 0.2, seed: 1, from: 0, until: 360, running: true,
				checks: []scnCheck{scnNeverCritical()}},
		},
	})

	add(scnScenario{
		name:   "acceptance a cleanup drop",
		source: "packet acceptance: a cleanup drop",
		expect: "a 2 GiB cleanup during a 3 GiB an hour runaway that still fills in 4.7 hours: open by round 3 and held until full; a cleanup on a flat 90% disk never opens",
		variants: []scnSim{
			{name: "2 GiB in a minute during a runaway", totalG: 100, noiseG: 0.02, seed: 1, from: 0, until: 600, running: true,
				usedG:  scnAnchor(100, 15, 0, func(m float64) float64 { return scnRate(m, -480, inf, 3) - scnRamp(m, 60, 1, 2) }),
				checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2))}},
			{name: "3 GiB in a minute on a flat disk", totalG: 100, noiseG: 0.05, seed: 1, from: 0, until: 360, running: true,
				usedG:  func(m float64) float64 { return 90 - scnRamp(m, 60, 1, 3) },
				checks: []scnCheck{scnNeverOpens()}},
		},
	})

	add(scnScenario{
		name:   "acceptance a runaway log",
		source: "packet acceptance: a runaway log",
		expect: "3 GiB an hour from 70 of 100 GiB starting at minute 0: no critical while more than 6.5 hours are left (before minute 210); open critical by minute 363, when the runaway is 6 hours old with 4 hours left, and held until full at 600. Between 210 and 360 is open (the 6 hour trend lags)",
		variants: []scnSim{
			{name: "3 GiB an hour", totalG: 100, usedG: flat(70, runaway(0, 3)), noiseG: 0.02, seed: 1, from: 0, until: 700, running: true,
				checks: []scnCheck{
					scnNoCriticalBefore(210, "minute 210 (more than 6.5 hours left)"),
					scnOpenBy("minute 363 (6 hours old, 4 hours left)", scnAtMinute(363)),
					scnHolds("minute 363", scnAtMinute(363)),
				}},
		},
	})

	add(scnScenario{
		name:   "acceptance flat usage at 90 percent",
		source: "packet acceptance: flat usage (the 10% rule is host:disk, not the forecast)",
		expect: "never opens, in 0.05 or 0.2 GiB noise",
		variants: []scnSim{
			{name: "0.05 GiB noise", totalG: 100, usedG: func(float64) float64 { return 90 }, noiseG: 0.05, seed: 1, from: 0, until: 360, running: true, checks: []scnCheck{scnNeverOpens()}},
			{name: "0.2 GiB noise", totalG: 100, usedG: func(float64) float64 { return 90 }, noiseG: 0.2, seed: 2, from: 0, until: 360, running: true, checks: []scnCheck{scnNeverOpens()}},
		},
	})

	add(scnScenario{
		name:   "acceptance a restart with an empty ring",
		source: "packet acceptance: a restart with an empty ring; R4 kept win: a restarted ring pages once it holds enough rounds",
		expect: "a 3 GiB an hour runaway with 12 GiB free at a restart at minute 60: no condition in the 59 rounds the new ring holds under 60 points; open critical by restart+65 and held until full. Whether the old incident resolves in the blind hour is open and not asserted",
		variants: []scnSim{
			{name: "restart at minute 60", totalG: 100, noiseG: 0.02, seed: 1, from: 0, until: 600, running: true, restarts: []float64{60},
				usedG: scnAnchor(100, 15, 0, runaway(-480, 3)),
				checks: []scnCheck{
					scnOpenBy("round 3, before the restart", scnAtRound(2)),
					scnNoConditionIn(60, 119, "the 59 rounds after the restart"),
					scnOpenBy("minute 125 (restart+65)", scnAtMinute(125)),
					scnHolds("minute 125", scnAtMinute(125)),
				}},
		},
	})

	add(scnScenario{
		name:   "acceptance nothing fires below the minimum point counts",
		source: "packet acceptance: nothing fires below the minimum point counts",
		expect: "a fresh daemon with no history and a 6 GiB an hour runaway: no condition in rounds 1 to 59, then open by minute 65 and held until full; rounds every 7.5 minutes (48 points) never open",
		variants: []scnSim{
			{name: "a fresh daemon with no history", totalG: 100, noiseG: 0.02, seed: 1, from: 0, until: 600, noHistory: true,
				usedG: scnAnchor(100, 14, 0, runaway(-360, 6)),
				checks: []scnCheck{
					scnNoConditionIn(0, 59, "rounds 1 to 59"),
					scnOpenBy("minute 65", scnAtMinute(65)),
					scnHolds("minute 65", scnAtMinute(65)),
				}},
			{name: "rounds every 7.5 minutes", totalG: 100, usedG: flat(70, runaway(0, 3)), noiseG: 0.02, seed: 1, from: 0, until: 360, running: true, gap: scnEvery(7.5),
				checks: []scnCheck{scnNeverOpens()}},
		},
	})

	// Round one.

	add(scnScenario{
		name:   "R1 0 a one-off write reads as growth",
		source: "R1 #0: A level shift in the middle of either window flips the Theil-Sen trend (probe 3, a one-off write on a flat 92% disk)",
		expect: "a 9 GiB write in one minute on a flat 83 of 100 GiB disk never opens",
		variants: []scnSim{
			{name: "9 GiB in one minute", totalG: 100, usedG: flat(83, func(m float64) float64 { return scnRamp(m, 0, 0, 9) }), noiseG: 0.05, seed: 1, from: -60, until: 360, running: true,
				checks: []scnCheck{scnNeverOpens()}},
		},
	})

	add(scnScenario{
		name:   "R1 12 DiskFullFast only tested where it fires",
		source: "R1 #12: The DiskFullFast threshold is only tested on the side where it fires",
		expect: "a steady 2 GiB an hour runaway with 16 GiB free: no critical while more than 6.5 hours are left (before minute 90); open by the round with 5.5 hours left (minute 153) and held until full",
		variants: []scnSim{
			{name: "2 GiB an hour", totalG: 100, usedG: flat(70, runaway(-420, 2)), noiseG: 0.02, seed: 1, from: 0, until: 600, running: true,
				checks: []scnCheck{
					scnNoCriticalBefore(90, "minute 90 (more than 6.5 hours left)"),
					scnOpenBy("minute 153 (5.5 hours left)", scnAtMinute(153)),
					scnHolds("minute 153", scnAtMinute(153)),
				}},
		},
	})

	add(scnScenario{
		name:   "R1 1 the ring when the wall clock steps back",
		source: "R1 #1: The minute ring stops trimming and grows without a cap when the wall clock steps backwards",
		expect: "the wall clock steps back a day at minute 60 during a runaway: the ring never exceeds minutesKept, and the forecast is critical again 65 rounds after the step. Whether the incident resolves in between is open",
		variants: []scnSim{
			{name: "a day back", totalG: 100, noiseG: 0.02, seed: 1, from: 0, until: 600, running: true, stepAt: 60, stepBy: 24 * 60,
				usedG:  scnAnchor(100, 15, 0, runaway(-480, 3)),
				checks: []scnCheck{scnRingBounded(), scnCriticalAt(125, "65 rounds after the step")}},
		},
	})

	// Round two.

	quick := func(m float64) float64 { return scnRamp(m, -3, 3, 9) }
	add(scnScenario{
		name:   "R2 0 a quick download beside a passing temp file",
		source: "R2 #0: a quick 9 GiB download with a 2 minute 1.5 GiB temp file 2 hours after or before it",
		expect: "quiet from 45 minutes after the download",
		variants: []scnSim{
			{name: "temp file 2 hours after", totalG: 100, noiseG: 0.05, seed: 1, from: -200, until: 300, running: true,
				usedG:  flat(83, func(m float64) float64 { return quick(m) + scnRamp(m, 120, 0, 1.5) - scnRamp(m, 122, 0, 1.5) }),
				checks: []scnCheck{quiet45}},
			{name: "temp file 2 hours before", totalG: 100, noiseG: 0.05, seed: 1, from: -200, until: 300, running: true,
				usedG:  flat(83, func(m float64) float64 { return quick(m) + scnRamp(m, -123, 0, 1.5) - scnRamp(m, -121, 0, 1.5) }),
				checks: []scnCheck{quiet45}},
		},
	})

	var r2rates []scnSim
	for _, mibps := range []float64{5, 10, 15} {
		r2rates = append(r2rates, download(fmt.Sprintf("%.0f MiB a second", mibps), 100, 83, 9, 9/(mibps*scnMiBps), 0.05, quiet45))
	}
	for i, mibps := range []float64{5, 12, 19} {
		rise, length := scnJittered(9, mibps*scnMiBps, 0.4, uint64(i+1))
		r2rates = append(r2rates, scnSim{name: fmt.Sprintf("%.0f MiB a second, 40 percent jitter", mibps), totalG: 100, noiseG: 0.05, seed: 1,
			usedG: flat(83, rise), from: -length - 60, until: 240, running: true, checks: []scnCheck{quiet45}})
	}
	add(scnScenario{
		name:     "R2 1 a 9 GiB download at a steady or jittered rate",
		source:   "R2 #1: 9 GiB downloads at 5 to 19 MiB/s, steady or with 40% jitter, on a flat 83 of 100 GiB disk",
		expect:   "quiet from 45 minutes after the download",
		variants: r2rates,
	})

	var r2quick []scnSim
	for _, dur := range []float64{9, 9.5, 10} {
		r2quick = append(r2quick, download(fmt.Sprintf("over %.1f minutes", dur), 100, 83, 9, dur, 0.05, quiet45))
	}
	add(scnScenario{
		name:     "R2 6b a 9 GiB download over 9 to 10 minutes",
		source:   "R2 #6b: a 9 GiB download over 9 to 10 minutes",
		expect:   "quiet from 45 minutes after the download",
		variants: r2quick,
	})

	// Round three.

	var r3bursts []scnSim
	for _, c := range []struct{ period, rate, free float64 }{{45, 3, 12}, {60, 3, 15}, {90, 3, 12}, {45, 6, 15}, {60, 6, 12}, {90, 6, 15}} {
		for i, phase := range []float64{0, c.period / 3, 2 * c.period / 3} {
			size := c.rate * c.period / 60
			first := -480 + phase
			r3bursts = append(r3bursts, scnSim{
				name:   fmt.Sprintf("every %.0f minutes at %.0f GiB an hour, %.0f GiB free, phase %.0f", c.period, c.rate, c.free, phase),
				totalG: 100, noiseG: 0.02, seed: uint64(i + 1), from: 0, until: 600, running: true,
				usedG:  scnAnchor(100, c.free, 0, func(m float64) float64 { return scnBursts(m, first, c.period, inf, size, 2) }),
				checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2))},
			})
		}
	}
	add(scnScenario{
		name:     "R3 0 a bursty runaway every 45 to 90 minutes",
		source:   "R3 #0: a job landing rate x period bytes over 2 minutes every 45, 60 or 90 minutes for 8 hours, 12 or 15 GiB free, 0.02 GiB noise",
		expect:   "open critical by round 3 and held until full, at every phase",
		variants: r3bursts,
	})

	var r3slowed []scnSim
	for _, c := range []struct{ r1, r2, free float64 }{{6, 2.5, 12}, {6, 2.9, 15}, {5, 2.4, 13}, {4, 1.9, 11}, {8, 3.5, 18}} {
		r3slowed = append(r3slowed, scnSim{
			name:   fmt.Sprintf("%.0f then %.1f GiB an hour, %.0f GiB free an hour after", c.r1, c.r2, c.free),
			totalG: 100, noiseG: 0.02, seed: 1, from: -60, until: 900, running: true,
			usedG:  scnAnchor(100, c.free, 60, func(m float64) float64 { return scnRate(m, -480, 0, c.r1) + scnRate(m, 0, inf, c.r2) }),
			checks: []scnCheck{scnHolds("an hour after the slowdown", scnAtMinute(60))},
		})
	}
	add(scnScenario{
		name:     "R3 1 a runaway that slowed",
		source:   "R3 #1: a runaway at r1 for 8 hours that slowed to r2, still filling within 6 hours at r2",
		expect:   "open critical at every round from an hour after the slowdown until full; the first hour after the slowdown is open (the 6 hour trend lags) and not asserted",
		variants: r3slowed,
	})

	var r3sparse []scnSim
	for _, cadence := range []float64{2, 2.5, 3, 5} {
		r3sparse = append(r3sparse, scnSim{
			name:   fmt.Sprintf("a round every %.1f minutes", cadence),
			totalG: 100, noiseG: 0.02, seed: 1, from: 0, until: 600, running: true, gap: scnEvery(cadence),
			usedG:  scnAnchor(100, 12, 0, runaway(-480, 3)),
			checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2))},
		})
	}
	r3sparse = append(r3sparse, scnSim{
		name:   "missed rounds, 1 to 4 minutes apart",
		totalG: 100, noiseG: 0.02, seed: 1, from: 0, until: 600, running: true,
		gap:    func(k int) float64 { return 1 + 1.5*(wobble(uint64(int64(k)+1<<32))+1) },
		usedG:  scnAnchor(100, 12, 0, runaway(-480, 3)),
		checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2))},
	})
	add(scnScenario{
		name:     "R3 4 and 8 a runaway seen by sparse or missed rounds",
		source:   "R3 #4 (rounds every 2.5, 3 or 5 minutes) and R3 #8 (a slow host misses rounds): a steady 3 GiB an hour runaway with 12 GiB free",
		expect:   "open critical by round 3 and held until full",
		variants: r3sparse,
	})

	add(scnScenario{
		name:   "R3 5 3 GiB in one minute every hour",
		source: "R3 #5: a job with broken retention writes 3 GiB in one minute every hour onto a disk at 80 of 100 GiB",
		expect: "open critical by minute 245 (5 bursts, 5 GiB free) and, once open, never resolved until full",
		variants: []scnSim{
			{name: "from 80 of 100 GiB", totalG: 100, noiseG: 0.02, seed: 1, from: -60, until: 600, running: true,
				usedG:  flat(80, func(m float64) float64 { return scnBursts(m, 0, 60, inf, 3, 1) }),
				checks: []scnCheck{scnOpenBy("minute 245", scnAtMinute(245)), scnHoldsOnceOpen()}},
		},
	})

	var r3log []scnSim
	for _, r2 := range []float64{1.4, 1.2, 1.0} {
		r3log = append(r3log, scnSim{
			name:   fmt.Sprintf("slowed to %.1f GiB an hour", r2),
			totalG: 100, noiseG: 0.02, seed: 1, from: -60, until: 900, running: true,
			usedG:  scnAnchor(100, 5.5, 60, func(m float64) float64 { return scnRate(m, -300, 0, 3) + scnRate(m, 0, inf, r2) }),
			checks: []scnCheck{scnHolds("an hour after the slowdown", scnAtMinute(60))},
		})
	}
	add(scnScenario{
		name:     "R3 6 a log that slowed to 1 to 1.4 GiB an hour",
		source:   "R3 #6: a log grew 3 GiB an hour for 5 hours, then slowed to 1 to 1.4 GiB an hour, 5.5 GiB free of 100",
		expect:   "open critical at every round from an hour after the slowdown until full",
		variants: r3log,
	})

	var r3temp []scnSim
	for _, after := range []float64{120, 180} {
		for _, last := range []float64{4, 5, 7, 10} {
			r3temp = append(r3temp, scnSim{
				name:   fmt.Sprintf("a %.0f minute temp file %.0f minutes after", last, after),
				totalG: 100, noiseG: 0.05, seed: 1, from: -60, until: 360, running: true,
				usedG: flat(83, func(m float64) float64 {
					return quick(m) + scnRamp(m, after, 0, 1.5) - scnRamp(m, after+last, 0, 1.5)
				}),
				checks: []scnCheck{quiet45},
			})
		}
	}
	add(scnScenario{
		name:     "R3 7 a temp file of 4 to 10 minutes after a download",
		source:   "R3 #7: ShiftGap = 2 bridges only two quiet changes (a 4 to 10 minute temp file beside one real step)",
		expect:   "quiet from 45 minutes after the download, temp file included",
		variants: r3temp,
	})

	// Round four.

	var r4slow []scnSim
	for _, mibps := range []float64{1.5, 2, 3} {
		r4slow = append(r4slow, download(fmt.Sprintf("%.1f MiB a second", mibps), 100, 83, 9, 9/(mibps*scnMiBps), 0.05, quiet45))
	}
	r4slow = append(r4slow, download("145 GiB over 95 minutes on 1 TB", 1000, 821, 145, 95, 0.05, quiet45))
	add(scnScenario{
		name:     "R4 0 a slow download on a flat disk",
		source:   "R4 #0: a one-off 9 GiB download at 1.5 to 3 MiB/s on a flat 83 of 100 GiB disk, or 145 GiB over 95 minutes on 1 TB",
		expect:   "quiet from 45 minutes after the download",
		variants: r4slow,
	})

	var r4cleanup []scnSim
	for _, c := range []struct {
		name                       string
		rate, free, size, dur, amp float64
	}{
		{"2 GiB over 12 minutes", 2, 8, 2, 12, 0.02},
		{"3 GiB over 15 minutes", 2, 8, 3, 15, 0.02},
		{"2 GiB over 20 minutes", 2, 8, 2, 20, 0.02},
		{"2 GiB over 30 minutes", 2, 8, 2, 30, 0.02},
		{"2 GiB over 3 minutes in 0.2 GiB noise", 2, 8, 2, 3, 0.2},
		{"1.5 GiB over 12 minutes", 2, 8, 1.5, 12, 0.02},
		{"3 GiB over 12 minutes at 3 GiB an hour, 13 GiB free", 3, 13, 3, 12, 0.02},
	} {
		r4cleanup = append(r4cleanup, scnSim{
			name: c.name, totalG: 100, noiseG: c.amp, seed: 1, from: -180, until: 900, running: true,
			usedG:  scnAnchor(100, c.free, 0, func(m float64) float64 { return scnRate(m, -660, inf, c.rate) - scnRamp(m, 0, c.dur, c.size) }),
			checks: []scnCheck{scnOpenBy("an hour before the cleanup", scnAtMinute(-60)), scnHolds("an hour before the cleanup", scnAtMinute(-60))},
		})
	}
	add(scnScenario{
		name:     "R4 1 a cleanup during a runaway",
		source:   "R4 #1: a steady 2 GiB an hour runaway with about 8 GiB free; a log rotation frees 1.5 to 3 GiB over 3 to 30 minutes",
		expect:   "open critical an hour before the cleanup and held until full (the disk fills within 5.3 hours throughout)",
		variants: r4cleanup,
	})

	var r4shrank []scnSim
	for i, offset := range []float64{0, 0.5} {
		seed := uint64(i + 1)
		r4shrank = append(r4shrank,
			scnSim{
				name:   fmt.Sprintf("8 then 4 GiB every 60 minutes, seed %d", seed),
				totalG: 100, noiseG: 0.02, seed: seed, from: offset, until: 1200, running: true,
				usedG: flat(24, func(m float64) float64 {
					return scnBursts(m, 60, 60, 360, 8, 0) + scnBursts(m, 420, 60, inf, 4, 0)
				}),
				checks: []scnCheck{scnHolds("minute 480 (20 GiB free, 5 hours)", scnAtMinute(480))},
			},
			scnSim{
				name:   fmt.Sprintf("10 then 5 GiB every 75 minutes, seed %d", seed),
				totalG: 100, noiseG: 0.02, seed: seed, from: offset, until: 1200, running: true,
				usedG: flat(20, func(m float64) float64 {
					return scnBursts(m, 75, 75, 375, 10, 0) + scnBursts(m, 450, 75, inf, 5, 0)
				}),
				checks: []scnCheck{scnHolds("minute 525 (20 GiB free, 5 hours)", scnAtMinute(525))},
			})
	}
	add(scnScenario{
		name:     "R4 2 a bursty runaway whose bursts shrank",
		source:   "R4 #2: bursts of 8 then 4 GiB every 60 minutes, or 10 then 5 GiB every 75 minutes, filling in 4 to 5 hours",
		expect:   "open critical at every round from the first burst after which 20 GiB is free (5 hours at the slowed rate) until full; the hour or so right after the bursts shrink is open (the 6 hour trend lags)",
		variants: r4shrank,
	})

	var r4merged []scnSim
	for _, c := range []struct {
		name                     string
		totalG, size, temp, free float64
		cadence                  float64
	}{
		{"40 GiB disk, 2.5 minute rounds", 40, 1.4, 2.8, 5.5, 2.5},
		{"40 GiB disk, 1 minute rounds", 40, 1.4, 2.8, 5.5, 1},
		{"100 GiB disk, 2.5 minute rounds", 100, 3, 6, 15, 2.5},
	} {
		r4merged = append(r4merged, scnSim{
			name: c.name, totalG: c.totalG, noiseG: 0.005, seed: 1, from: -132, until: 600, running: true, gap: scnEvery(c.cadence),
			usedG: scnAnchor(c.totalG, c.free, 0, func(m float64) float64 {
				return scnBursts(m, -18-37*18, 37, inf, c.size, 0) + scnRamp(m, -313, 1, c.temp) - scnRamp(m, -13, 1, c.temp)
			}),
			checks: []scnCheck{scnOpenBy("an hour before the deletion", scnAtMinute(-72)), scnHolds("an hour before the deletion", scnAtMinute(-72))},
		})
	}
	add(scnScenario{
		name:     "R4 3 a temp file deleted beside a burst",
		source:   "R4 #3: a bursty runaway every 37 minutes; a 5 hour temp file is deleted 6 minutes after a burst, and pairing cancels both bursts",
		expect:   "open critical an hour before the deletion and held until full (2.4 or 3.1 hours left)",
		variants: r4merged,
	})

	var r4sparse []scnSim
	for _, cadence := range []float64{1, 2.5, 5} {
		v := download(fmt.Sprintf("9 GiB at 0.1 GiB a minute, %.1f minute rounds", cadence), 100, 83, 9, 90, 0.05, quiet45)
		v.gap = scnEvery(cadence)
		r4sparse = append(r4sparse, v)
	}
	r4sparse = append(r4sparse, download("6 GiB at 0.05 GiB a minute, 8 GiB left free", 100, 86, 6, 120, 0.05, quiet45))
	grow := download("9 GiB at 0.1 GiB a minute on a disk growing 0.5 GiB a day", 100, 83, 9, 90, 0.05, quiet45)
	grow.usedG = func(m float64) float64 { return 83 + 0.5*m/1440 + scnRamp(m, -90, 90, 9) }
	r4sparse = append(r4sparse, grow)
	add(scnScenario{
		name:     "R4 4 a slow download seen by 1 to 5 minute rounds",
		source:   "R4 #4: an ordinary 9 GiB download at 0.1 GiB a minute on a flat disk, real Watcher and Prober, 1, 2.5 or 5 minute rounds",
		expect:   "quiet from 45 minutes after the download",
		variants: r4sparse,
	})

	var r4stall []scnSim
	for _, c := range []struct{ rate, level float64 }{{2.5, 86}, {4, 78}} {
		for seed := uint64(1); seed <= 8; seed++ {
			r4stall = append(r4stall, scnSim{
				name:   fmt.Sprintf("%.1f GiB an hour, ticker seed %d", c.rate, seed),
				totalG: 100, noiseG: 0.05, seed: seed, from: 0, running: true,
				rounds: scnStallTicker(0, 600, 30, 20, seed),
				usedG:  scnAnchor(100, 100-c.level, 0, runaway(-480, c.rate)),
				checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2))},
			})
		}
	}
	add(scnScenario{
		name:     "R4 5 a 20 minute round while a runaway pages",
		source:   "R4 #5: one watch round runs 20 minutes on a jittered one-minute ticker while a steady runaway pages",
		expect:   "open critical by round 3 and held until full, through the stall and its echo 120 minutes later",
		variants: r4stall,
	})

	// Boundary probes.

	var bdl []scnSim
	for _, c := range []struct {
		name string
		dur  float64
	}{
		{"3 GiB a minute", 3},
		{"0.9 GiB a minute", 10},
		{"15 MiB a second", 9 / (15 * scnMiBps)},
		{"5 MiB a second", 9 / (5 * scnMiBps)},
		{"0.1 GiB a minute", 90},
		{"1.5 MiB a second", 9 / (1.5 * scnMiBps)},
	} {
		bdl = append(bdl, download(c.name, 100, 83, 9, c.dur, 0.05,
			scnLogAt(30, "30 minutes after"),
			scnLogLastCritical(),
			scnNoCriticalAt(45, "45 minutes after"),
			scnNoCriticalAt(60, "60 minutes after"),
			scnNoCriticalAt(90, "90 minutes after"),
			scnNoCriticalAt(120, "120 minutes after"),
			quiet45,
		))
	}
	add(scnScenario{
		name:     "boundary a flat disk after one download",
		source:   "round 5 boundary probe: a flat disk after one 9 GiB download that finished 30, 45, 60, 90 and 120 minutes ago",
		expect:   "no critical condition 45, 60, 90 and 120 minutes after, and quiet from 45 on; 30 minutes after is open and only logged",
		variants: bdl,
	})

	var b90 []scnSim
	for _, edge := range []float64{1, 2} {
		for i, phase := range []float64{0, 30, 60} {
			for seed := uint64(1); seed <= 2; seed++ {
				first := -480 + phase
				b90 = append(b90, scnSim{
					name:   fmt.Sprintf("%.0f minute bursts, phase %.0f, seed %d", edge, phase, seed),
					totalG: 100, noiseG: 0.02, seed: seed + uint64(10*i), from: 0, until: 600, running: true,
					usedG:  scnAnchor(100, 15, 0, func(m float64) float64 { return scnBursts(m, first, 90, inf, 4.5, edge) }),
					checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2))},
				})
			}
		}
	}
	add(scnScenario{
		name:     "boundary a 90 minute bursty runaway",
		source:   "round 5 boundary probe: a bursty runaway with a 90 minute period, checked at every minute of its flat phase",
		expect:   "open critical by round 3 and held at every round until full (3 GiB an hour, 15 GiB free)",
		variants: b90,
	})

	var bstop []scnSim
	for _, period := range []float64{45, 60, 90} {
		for seed := uint64(1); seed <= 2; seed++ {
			first := 60 - period*math.Floor(540/period)
			quietAfter := math.Max(1.5*period+5, 120)
			bstop = append(bstop, scnSim{
				name:   fmt.Sprintf("every %.0f minutes, seed %d", period, seed),
				totalG: 100, noiseG: 0.02, seed: seed, from: 0, until: 62 + 300, running: true,
				usedG: scnAnchor(100, 11, 62, func(m float64) float64 {
					return scnBursts(m, first, period, 60, 3*period/60, 2)
				}),
				checks: []scnCheck{
					scnLogAt(62, "at the last burst"),
					scnLogLastCritical(),
					scnQuietFrom(62+quietAfter, fmt.Sprintf("%.0f minutes after the last burst", quietAfter)),
				},
			})
		}
	}
	add(scnScenario{
		name:     "boundary a bursty runaway that stops",
		source:   "round 5 boundary probe: a bursty runaway (3 GiB an hour, 11 GiB free) whose bursts stop",
		expect:   "quiet within about 1.5 periods of the last burst: from 140 minutes after it at a 90 minute period; at 45 and 60 minutes, from 120 minutes after it, since a steady runaway that stops is only required to be quiet after 2 hours",
		variants: bstop,
	})

	var bnoise []scnSim
	for _, c := range []struct{ rate, free float64 }{{2, 8}, {3, 12}} {
		for seed := uint64(1); seed <= 3; seed++ {
			bnoise = append(bnoise, scnSim{
				name:   fmt.Sprintf("%.0f GiB an hour, %.0f GiB free, seed %d", c.rate, c.free, seed),
				totalG: 100, noiseG: 0.2, seed: seed, from: 0, until: 600, running: true,
				usedG:  scnAnchor(100, c.free, 0, runaway(-480, c.rate)),
				checks: []scnCheck{scnOpenBy("round 5", scnAtRound(4)), scnHolds("round 5", scnAtRound(4))},
			})
		}
	}
	add(scnScenario{
		name:     "boundary a steady runaway in 0.2 GiB noise",
		source:   "round 5 boundary probe: a steady runaway in 0.2 GiB noise",
		expect:   "open critical by round 5 and held until full (4 hours left, so a detrending bias cannot push it past 6 hours)",
		variants: bnoise,
	})

	var gapRounds []float64
	for m := 0.0; m <= 30; m++ {
		gapRounds = append(gapRounds, m)
	}
	for m := 50.0; m <= 148; m++ {
		gapRounds = append(gapRounds, m)
	}
	gapRounds = append(gapRounds, 149.5)
	for m := 150.0; m <= 600; m++ {
		gapRounds = append(gapRounds, m)
	}
	add(scnScenario{
		name:   "boundary one 20 minute gap then two close rounds 120 minutes later",
		source: "round 5 boundary probe: a runaway with one 20 minute round gap followed, 120 minutes later, by two rounds less than 60 s apart",
		expect: "open critical by round 3 and held until full",
		variants: []scnSim{
			{name: "gap after minute 30, rounds at 149.5 and 150", totalG: 100, noiseG: 0.02, seed: 1, from: 0, running: true, rounds: gapRounds,
				usedG:  scnAnchor(100, 14, 0, runaway(-480, 3)),
				checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2))}},
		},
	})

	// Round four's kept wins.

	var kbursty []scnSim
	for _, period := range []float64{45, 60, 90} {
		size := 4 * period / 60
		first := 7 - period*math.Ceil(487/period)
		kbursty = append(kbursty, scnSim{
			name:   fmt.Sprintf("every %.0f minutes", period),
			totalG: 100, noiseG: 0, from: 0, until: 600, running: true,
			usedG:  scnAnchor(100, 16, 0, func(m float64) float64 { return scnBursts(m, first, period, inf, size, 0) }),
			checks: []scnCheck{scnOpenBy("round 3", scnAtRound(2)), scnHolds("round 3", scnAtRound(2)), scnOnlyOpenNotices()},
		})
	}
	add(scnScenario{
		name:     "kept win a bursty runaway keeps its incident open",
		source:   "R4 kept win: TestABurstyRunawayKeepsItsIncidentOpenUntilTheDiskIsFull (4 GiB an hour landing every 45, 60 or 90 minutes, 16 GiB free)",
		expect:   "open critical by round 3, held as one incident until full, and no notice but the open one",
		variants: kbursty,
	})

	var kslowed []scnSim
	for _, since := range []float64{40, 80, 120} {
		kslowed = append(kslowed, scnSim{
			name:   fmt.Sprintf("slowed %.0f minutes before 12 GiB free", since),
			totalG: 100, noiseG: 0.02, seed: 1, from: -60, until: 900, running: true,
			usedG:  scnAnchor(100, 12, since, func(m float64) float64 { return scnRate(m, -480, 0, 6) + scnRate(m, 0, inf, 2.5) }),
			checks: []scnCheck{scnHolds(fmt.Sprintf("minute %.0f", since), scnAtMinute(since))},
		})
	}
	add(scnScenario{
		name:     "kept win a slowed runaway still pages",
		source:   "R4 kept win: TestASlowedRunawayStillPages (6 GiB an hour, then 2.5 GiB an hour, 12 GiB free)",
		expect:   "open critical from 40, 80 or 120 minutes after the slowdown until full. Its 1.8 GiB an hour no-page half is open under the 6 hour lag decision and has no row",
		variants: kslowed,
	})

	add(scnScenario{
		name:   "kept win a runaway that stopped is quiet within 2 hours",
		source: "R4 kept win: TestTheShortForecastPagesOnlyWhileUsageStillClimbs (runaways that stopped 2 hours or 150 minutes ago, one shrinking)",
		expect: "open critical while it runs and quiet from 2 hours after the stop",
		variants: []scnSim{
			{name: "stops", totalG: 100, noiseG: 0.02, seed: 1, from: -60, until: 300, running: true,
				usedG:  scnAnchor(100, 12, 0, func(m float64) float64 { return scnRate(m, -480, 0, 3) }),
				checks: []scnCheck{scnOpenBy("round 3, while it runs", scnAtRound(2)), scnQuietFrom(120, "2 hours after the stop")}},
			{name: "stops and shrinks 0.5 GiB an hour", totalG: 100, noiseG: 0.02, seed: 1, from: -60, until: 300, running: true,
				usedG:  scnAnchor(100, 12, 0, func(m float64) float64 { return scnRate(m, -480, 0, 3) - scnRate(m, 0, inf, 0.5) }),
				checks: []scnCheck{scnOpenBy("round 3, while it runs", scnAtRound(2)), scnQuietFrom(120, "2 hours after the stop")}},
		},
	})

	var ksparse []scnSim
	for _, cadence := range []float64{2.5, 3, 5} {
		ksparse = append(ksparse, scnSim{
			name:   fmt.Sprintf("a round every %.1f minutes", cadence),
			totalG: 100, noiseG: 0.02, seed: 1, from: 0, until: 600, running: true, gap: scnEvery(cadence),
			usedG:  scnAnchor(100, 8, 0, runaway(-180, 3)),
			checks: []scnCheck{scnOpenBy("minute 30", scnAtMinute(30)), scnHolds("minute 30", scnAtMinute(30))},
		})
	}
	add(scnScenario{
		name:     "kept win sparse rounds page a 3 hour old runaway",
		source:   "R4 kept win: sparse rounds of 2.5, 3 and 5 minutes page a 3 GiB an hour runaway that has run 3 hours with 8 GiB free",
		expect:   "open critical within 30 minutes and held until full",
		variants: ksparse,
	})

	var soft []scnSim
	for _, c := range []struct{ total, free, rate, period, edge, noise float64 }{
		{1000, 120, 30, 90, 5, 0.2}, {1000, 120, 30, 75, 10, 0.2}, {100, 12, 3, 90, 30, 0.02}, {100, 12, 3, 75, 20, 0.02},
	} {
		first := -480 + 0.3*c.period
		soft = append(soft, scnSim{
			name:   fmt.Sprintf("%.0f GiB disk, %.0f GiB an hour every %.0f minutes written over %.0f", c.total, c.rate, c.period, c.edge),
			totalG: c.total, noiseG: c.noise, seed: 1, from: 0, until: 900, running: true,
			usedG:  scnAnchor(c.total, c.free, 0, func(m float64) float64 { return scnBursts(m, first, c.period, inf, c.rate*c.period/60, c.edge) }),
			checks: []scnCheck{scnHolds("minute 20", scnAtMinute(20))},
		})
	}
	add(scnScenario{
		name:     "judge a bursty runaway whose bursts are written slowly",
		source:   "round 5 judge: a burst still being written counted as the newest end, so the rate fell and the page resolved mid-burst",
		expect:   "open critical from minute 20 and held until full",
		variants: soft,
	})

	return out
}
