package peer

import (
	"fmt"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// What peer watch considers wrong with a peer.
const (
	// WatcherDownCritical is how long a peer's Helios may stay silent
	// while its machine still answers on the mesh before that is
	// critical: the peer can no longer send its own alerts.
	WatcherDownCritical = 15 * time.Minute
	// ObserverSilent is how long a Mac that watches this machine may go
	// without sending a view before that is a problem.
	ObserverSilent = 10 * time.Minute
	// LegsFresh is how recently each of a machine's alert legs must have
	// delivered something: a peer's leg quiet for longer is a problem,
	// and a machine with one is not trusted to send a page.
	LegsFresh = 8 * 24 * time.Hour
	// DrillGrace is how far past its due time a peer's restore drill may
	// be before it is overdue.
	DrillGrace = 24 * time.Hour
)

// The words a summary can end in besides a failure. Each is an answer
// from Helios on the peer; a failure word, such as timeout or refused, is
// none.
const (
	// WordOK is a path that passed.
	WordOK = "ok"
	// WordStale is a summary from a peer whose watch has stopped running.
	WordStale = "stale"
	// WordUntrusted is a peer's Helios refusing this machine's key.
	WordUntrusted = "untrusted"
	// WordMismatch is a summary from a machine other than the peer.
	WordMismatch = "mismatch"
)

// The names of peer watch's own incidents, beside one per machine it
// watches. No machine may take them.
const (
	selfName         = "self"
	edgeProviderName = "edge-provider"
	keyPrefix        = "peer:"
)

// Paths is what one look at a peer found on each of its three paths,
// one word each: its Helios's summary over the mesh, a TLS handshake
// with its edge over the mesh, and its public URLs through the edge
// provider.
type Paths struct {
	Summary string
	TLS     string
	Public  string
}

// Class is what a look at a peer makes of it.
type Class string

// The classes, in the order Classify tells them apart.
const (
	NotTrusted   Class = "not trusted"
	NeverSeen    Class = "never seen"
	Healthy      Class = "healthy"
	EdgeDegraded Class = "edge degraded"
	WatcherDown  Class = "peer watcher down"
	MeshDegraded Class = "mesh degraded"
	HostDown     Class = "host down"
)

// Classify tells what is wrong with a peer from its three paths and
// whether its summary has ever come back ok. A peer that has never
// answered is only never seen, however its paths fail, so a mistyped
// address never pages.
func Classify(p Paths, seen bool) Class {
	switch {
	case p.Summary == WordUntrusted || p.Summary == WordMismatch:
		return NotTrusted
	case !answered(p.Summary) && !seen:
		return NeverSeen
	case p.Summary == WordOK && p.TLS == WordOK && p.Public == WordOK:
		return Healthy
	case p.Summary == WordOK:
		return EdgeDegraded
	case p.Summary == WordStale, p.TLS == WordOK:
		return WatcherDown
	case p.Public == WordOK:
		return MeshDegraded
	default:
		return HostDown
	}
}

// answered reports whether a summary word is an answer from Helios on
// the peer, whatever it said.
func answered(summary string) bool {
	switch summary {
	case WordOK, WordStale, WordUntrusted, WordMismatch:
		return true
	}
	return false
}

// Sight is this machine's own look at one peer it watches this round.
type Sight struct {
	Name  string
	Paths Paths
	// LastGood is when its summary last came back ok; zero if it never
	// has.
	LastGood time.Time
	// Report is what its summary said, when one came back ok or stale.
	Report *Report
}

// Report is what a peer's summary says about itself that it may not be
// able to alert about: how its backups and drills stand, when each of its
// alert legs last worked, and what it has open.
type Report struct {
	Backups []Backup
	Legs    []Leg
	Open    []OpenIncident
}

// Backup is how one of a peer's apps stands on backups and drills, by
// the peer's own clock.
type Backup struct {
	App string
	// BackedUp is whether it has a good backup, and BackupAge how old
	// the last one is.
	BackedUp  bool
	BackupAge time.Duration
	// DeployedAge is how long ago it was first deployed.
	DeployedAge time.Duration
	// DrillOverdue is how far past due its restore drill is; zero when
	// it isn't, or it has no drill schedule.
	DrillOverdue time.Duration
}

// Leg is one of a machine's ways to send alerts.
type Leg struct {
	Name string
	// Worked is whether it has ever delivered an alert, and LastOK how
	// long ago it last did.
	Worked bool
	LastOK time.Duration
}

// fresh reports whether a leg has delivered within LegsFresh.
func (l Leg) fresh() bool { return l.Worked && l.LastOK <= LegsFresh }

// OpenIncident is one of a peer's open incidents, as it names it.
type OpenIncident struct {
	Subject  string
	Severity string
}

// Observer is a machine that only watches this one, such as a Mac.
type Observer struct {
	Name string
	// LastView is when its last view arrived; zero if none ever has.
	LastView time.Time
}

// Round is what this machine gathered in one round of watching its
// peers: its own look at each, what other observers saw, and when each
// Mac last sent a view.
type Round struct {
	// Self is this machine's name, Now the end of the round, and Started
	// when this process started. No clock runs from before Started: what
	// a peer did while this machine wasn't looking is not held against it.
	Self    string
	Now     time.Time
	Started time.Time
	// SelfCheck is whether this machine's own public URL answered.
	SelfCheck bool
	Peers     []Sight
	// Views are what other observers saw: the views in each summary that
	// came back this round, and the views Macs pushed.
	Views     []View
	Observers []Observer
	// Open are the keys of this machine's open incidents.
	Open []string
}

// Judge turns a round into its peer conditions: one per peer that has
// something wrong, with what its own summary shows folded in, and peer
// watch's own. A finding is critical only when the observers with a
// fresh view agree.
func Judge(r Round) []watch.Condition {
	if r.isolated() {
		return r.hold()
	}
	edgeDown := r.edgeProviderDegraded()
	var conditions []watch.Condition
	for _, s := range r.Peers {
		if c, ok := r.judge(s, edgeDown); ok {
			conditions = append(conditions, c)
		}
	}
	if edgeDown {
		conditions = append(conditions, watch.Condition{Key: keyPrefix + edgeProviderName, Subject: "public edge", Severity: state.SeverityWarning,
			Message: "every peer's public URL fails while the mesh works; the edge provider or this machine's internet is degraded"})
	}
	for _, o := range r.Observers {
		if c, ok := r.silent(o); ok {
			conditions = append(conditions, c)
		}
	}
	return conditions
}

// isolated reports whether this machine is cut off rather than its
// peers: its own public URL failed, no peer's Helios answered it, and no
// Mac's view has arrived within ViewFresh.
func (r Round) isolated() bool {
	if r.SelfCheck || len(r.Peers) == 0 {
		return false
	}
	for _, s := range r.Peers {
		if answered(s.Paths.Summary) {
			return false
		}
	}
	for _, o := range r.Observers {
		if !o.LastView.IsZero() && r.Now.Sub(o.LastView) <= ViewFresh {
			return false
		}
	}
	return true
}

// hold is an isolated round: this machine says it is cut off and holds
// every open peer incident as it is, so it neither pages about a peer nor
// sends a recovery it hasn't seen.
func (r Round) hold() []watch.Condition {
	self := keyPrefix + selfName
	conditions := []watch.Condition{{Key: self, Subject: "peer watch", Severity: state.SeverityWarning,
		Message: "this machine cannot reach its own public URL or any peer; peer findings are on hold"}}
	for _, key := range r.Open {
		if strings.HasPrefix(key, keyPrefix) && key != self {
			conditions = append(conditions, watch.Condition{Key: key, Unknown: true})
		}
	}
	return conditions
}

// edgeProviderDegraded reports whether every peer's public URL failed
// while the mesh reached it, in a way one peer's own edge can't explain:
// there are two peers or more, or this machine's own public URL failed
// too.
func (r Round) edgeProviderDegraded() bool {
	if len(r.Peers) == 0 || len(r.Peers) == 1 && r.SelfCheck {
		return false
	}
	for _, s := range r.Peers {
		if s.Paths.Public == WordOK || s.Paths.Summary != WordOK && s.Paths.TLS != WordOK {
			return false
		}
	}
	return true
}

// judge is one peer's condition: what its paths show, and what its own
// summary shows is quietly wrong, the gravest severity of the two. Its
// edge trouble is left out when the edge provider's explains it.
func (r Round) judge(s Sight, edgeDown bool) (watch.Condition, bool) {
	p := s.Paths
	mine := View{Observer: r.Self, Subject: s.Name, SelfCheck: r.SelfCheck, Paths: p}
	var severity, message string
	switch Classify(p, !s.LastGood.IsZero()) {
	case NotTrusted:
		severity = state.SeverityWarning
		message = fmt.Sprintf("it does not accept this machine's key; run helios peer key here and helios peer add on %s", s.Name)
		if p.Summary == WordMismatch {
			message = fmt.Sprintf("another machine answers at its mesh address (summary: %s); set the right one with helios peer add %s --mesh", p.Summary, s.Name)
		}
	case NeverSeen:
		severity = state.SeverityWarning
		message = fmt.Sprintf("it has never answered over the mesh (summary: %s); check the mesh address it was added with, and that it listens there", p.Summary)
	case EdgeDegraded:
		if !edgeDown {
			severity, message = state.SeverityWarning, edgeMessage(p)
		}
	case WatcherDown:
		clock := r.Now.Sub(later(s.LastGood, r.Started))
		severity = state.SeverityWarning
		if clock >= WatcherDownCritical && agreed(WatcherDown, mine, r.Views) {
			severity = state.SeverityCritical
		}
		message = fmt.Sprintf("its edge answers on the mesh but Helios does not (summary: %s) for %s; it cannot send its own alerts", p.Summary, span(clock))
		if p.Summary == WordStale {
			message = fmt.Sprintf("Helios answers on the mesh but its watch has stopped (summary: %s) for %s; it cannot send its own alerts", p.Summary, span(clock))
		}
	case MeshDegraded:
		severity = state.SeverityWarning
		message = fmt.Sprintf("the mesh cannot reach it (summary: %s, edge: %s), but its public URLs answer", p.Summary, p.TLS)
	case HostDown:
		severity = state.SeverityWarning
		if agreed(HostDown, mine, r.Views) {
			severity = state.SeverityCritical
		}
		message = fmt.Sprintf("no answer over the mesh, from its edge on the mesh, or at its public URLs (summary: %s, edge: %s, public: %s)", p.Summary, p.TLS, p.Public)
	}
	var found []string
	if message != "" {
		found = append(found, message)
	}
	if s.Report != nil {
		if quiet := deadMan(*s.Report); len(quiet) > 0 {
			found = append(found, quiet...)
			if severity == "" {
				severity = state.SeverityWarning
			}
		}
	}
	if len(found) == 0 {
		return watch.Condition{}, false
	}
	return watch.Condition{Key: keyPrefix + s.Name, Subject: s.Name, Severity: severity, Message: strings.Join(found, "; ")}, true
}

// edgeMessage says which of a peer's edge paths failed while its Helios
// answered.
func edgeMessage(p Paths) string {
	switch {
	case p.TLS != WordOK && p.Public != WordOK:
		return fmt.Sprintf("Helios answers over the mesh but its edge and public URLs do not (edge: %s, public: %s)", p.TLS, p.Public)
	case p.TLS != WordOK:
		return fmt.Sprintf("Helios answers over the mesh but its edge does not (edge: %s)", p.TLS)
	default:
		return fmt.Sprintf("Helios answers over the mesh but its public URLs do not (public: %s)", p.Public)
	}
}

// deadMan finds what a peer's own summary shows is quietly wrong: a
// backup too old, a restore drill overdue, or an alert leg that hasn't
// worked lately. With a leg quiet, nobody may have heard about what the
// peer has open, so that is named too.
func deadMan(rep Report) []string {
	var found []string
	for _, b := range rep.Backups {
		switch {
		case b.BackedUp && b.BackupAge > watch.BackupStale:
			found = append(found, fmt.Sprintf("its last good backup of %s is %s old", b.App, span(b.BackupAge)))
		case !b.BackedUp && b.DeployedAge > watch.BackupStale:
			found = append(found, fmt.Sprintf("it has never backed up %s, deployed %s ago", b.App, span(b.DeployedAge)))
		}
		if b.DrillOverdue > DrillGrace {
			found = append(found, fmt.Sprintf("its restore drill for %s is %s overdue", b.App, span(b.DrillOverdue)))
		}
	}
	quiet := false
	for _, l := range rep.Legs {
		switch {
		case !l.Worked:
			found = append(found, fmt.Sprintf("its %s alerts have never worked", l.Name))
		case !l.fresh():
			found = append(found, fmt.Sprintf("its %s alerts have not worked in %s", l.Name, span(l.LastOK)))
		default:
			continue
		}
		quiet = true
	}
	if quiet && len(rep.Open) > 0 {
		open := make([]string, len(rep.Open))
		for i, o := range rep.Open {
			open[i] = fmt.Sprintf("%s (%s)", o.Subject, o.Severity)
		}
		found = append(found, "open there: "+strings.Join(open, ", "))
	}
	return found
}

// silent is a Mac that has stopped sending views: once it has sent one,
// ObserverSilent without another is a warning. Its clock starts again
// with this process, since views sent while it was down never arrived.
func (r Round) silent(o Observer) (watch.Condition, bool) {
	if o.LastView.IsZero() || r.Now.Sub(later(o.LastView, r.Started)) <= ObserverSilent {
		return watch.Condition{}, false
	}
	return watch.Condition{Key: keyPrefix + o.Name, Subject: o.Name, Severity: state.SeverityWarning,
		Message: fmt.Sprintf("%s has sent no views for %s", o.Name, span(r.Now.Sub(o.LastView)))}, true
}

// rank orders severities, the same way the fan-out does: a severity it
// doesn't know counts as a warning.
func rank(severity string) int {
	switch severity {
	case state.SeverityNotice:
		return 0
	case state.SeverityCritical:
		return 2
	default:
		return 1
	}
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// span says how long d is, roughly, the way the watcher's notices do.
func span(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f h", d.Hours())
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
