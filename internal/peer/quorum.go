package peer

import (
	"strings"
	"time"
)

// ViewFresh is how long another observer's view of a peer counts toward
// agreeing on a page.
const ViewFresh = 3 * time.Minute

// View is one observer's look at one subject, as it reported it.
type View struct {
	Observer string
	Subject  string
	// Age is how long ago the observer looked.
	Age time.Duration
	// SelfCheck is whether the observer passed its own self-check when it
	// looked: a server reached its own public URL, a Mac reached anything
	// at all.
	SelfCheck bool
	Paths
}

// agreed reports whether a majority of the observers with a fresh view of
// mine's subject see what mine shows: every path failing for a host that
// is down, its summary failing for a watcher that is. The subject never
// votes on itself. Another observer votes while its view is fresh and it
// passed its own self-check, and this machine when it passed its own,
// except on a watcher, which it judges over the mesh alone.
func agreed(class Class, mine View, views []View) bool {
	sees := hostDown
	if class == WatcherDown {
		sees = summaryDown
	}
	voters, agreeing := 0, 0
	vote := func(p Paths) {
		voters++
		if sees(p) {
			agreeing++
		}
	}
	if mine.SelfCheck || class == WatcherDown {
		vote(mine.Paths)
	}
	for _, v := range pool(mine, views) {
		vote(v.Paths)
	}
	return 2*agreeing > voters
}

// pool keeps the views that vote on mine's subject: each other
// observer's freshest, while it is fresh and its observer passed its
// self-check, and never the subject's own.
func pool(mine View, views []View) []View {
	freshest := map[string]View{}
	for _, v := range views {
		if v.Subject != mine.Subject || v.Observer == mine.Subject || v.Observer == mine.Observer {
			continue
		}
		if have, ok := freshest[v.Observer]; !ok || v.Age < have.Age {
			freshest[v.Observer] = v
		}
	}
	var pooled []View
	for _, v := range freshest {
		if v.Age <= ViewFresh && v.SelfCheck {
			pooled = append(pooled, v)
		}
	}
	return pooled
}

func hostDown(p Paths) bool {
	return !answered(p.Summary) && p.TLS != WordOK && p.Public != WordOK
}

func summaryDown(p Paths) bool { return p.Summary == WordStale || !answered(p.Summary) }

// Candidate is a machine that might send a peer page: this one, or a
// server whose summary came back this round.
type Candidate struct {
	Name string
	// ObserverOnly is a machine that only watches, such as a Mac. It
	// never sends.
	ObserverOnly bool
	SelfCheck    bool
	Legs         []Leg
	// Findings are the peer conditions it found in its last round.
	Findings []Finding
}

// Finding is one peer condition a machine found, by key and severity.
type Finding struct {
	Key      string `json:"key"`
	Severity string `json:"severity"`
}

// Sender picks the one machine to send a peer page at severity, so every
// observer that sees it agrees on who tells. It is the lowest-named
// candidate that is neither the page's subject nor only an observer,
// passed its self-check, found the page at least as grave, and has had
// every alert leg work within LegsFresh. When none has its legs working,
// the legs are not asked; when still none qualifies, this machine, self,
// sends.
func Sender(self, key, severity string, candidates []Candidate) string {
	subject := strings.TrimPrefix(key, keyPrefix)
	pick := func(legs bool) string {
		sender := ""
		for _, c := range candidates {
			if c.Name == subject || c.ObserverOnly || !c.SelfCheck || !c.found(key, severity) || legs && !c.legsWork() {
				continue
			}
			if sender == "" || c.Name < sender {
				sender = c.Name
			}
		}
		return sender
	}
	if sender := pick(true); sender != "" {
		return sender
	}
	if sender := pick(false); sender != "" {
		return sender
	}
	return self
}

// found reports whether the candidate found key at severity or graver.
func (c Candidate) found(key, severity string) bool {
	for _, f := range c.Findings {
		if f.Key == key && rank(f.Severity) >= rank(severity) {
			return true
		}
	}
	return false
}

// legsWork reports whether the candidate has alert legs and every one has
// delivered within LegsFresh.
func (c Candidate) legsWork() bool {
	for _, l := range c.Legs {
		if !l.fresh() {
			return false
		}
	}
	return len(c.Legs) > 0
}
