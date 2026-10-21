// Package dns keeps the records an app's routes call for: made when the
// app deploys, checked before every switch, removed when the app leaves.
// Records helios makes carry a comment naming the app and the machine, so
// an audit can tell them from everything else.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/kylebegeman/helios/internal/cloudflare"
	"github.com/kylebegeman/helios/internal/manifest"
)

// Manager keeps records for one machine.
type Manager struct {
	CF *cloudflare.Client
	// Hostname names this machine in record comments.
	Hostname string
	// Addresses are this machine's public addresses.
	Addresses []string

	zones map[string]cloudflare.Zone
}

// Comment retains the historical ownership marker until the host migration,
// so existing records remain recognizable by both old and new binaries.
func Comment(app, hostname string) string { return "bedrock: " + app + " on " + hostname }

// commentApp reads an app and machine back out of a comment.
func commentApp(comment string) (app, hostname string, ok bool) {
	rest, found := strings.CutPrefix(comment, "bedrock: ")
	if !found {
		return "", "", false
	}
	app, hostname, ok = strings.Cut(rest, " on ")
	return app, hostname, ok
}

// IPv4 returns the machine's public IPv4 address, the one A records get.
func (m *Manager) IPv4() (string, error) {
	for _, a := range m.Addresses {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a, nil
		}
	}
	return "", errors.New("this machine has no public IPv4 address")
}

func (m *Manager) zone(ctx context.Context, host string) (cloudflare.Zone, error) {
	if m.zones == nil {
		zones, err := m.CF.Zones(ctx)
		if err != nil {
			return cloudflare.Zone{}, err
		}
		m.zones = make(map[string]cloudflare.Zone, len(zones))
		for _, z := range zones {
			m.zones[z.Name] = z
		}
	}
	best := cloudflare.Zone{}
	for name, z := range m.zones {
		if (host == name || strings.HasSuffix(host, "."+name)) && len(name) > len(best.Name) {
			best = z
		}
	}
	if best.ID == "" {
		return best, fmt.Errorf("%w for %s among %d zone(s) the token can see", cloudflare.ErrNoZone, host, len(m.zones))
	}
	return best, nil
}

// Outcome says what Ensure did to a record.
type Outcome struct {
	Host    string
	Action  string // "made", "updated", "kept"
	Content string
	Proxied bool
	// Zone is the zone the record is in.
	Zone string
	// Removed names the CNAME and AAAA records taken out of the A record's
	// way, when the host was taken over on purpose.
	Removed []string
}

// Depth is how many labels a host has below its zone: one for
// api.begam.in in begam.in, two for api.lane.begam.in.
func (o Outcome) Depth() int {
	rest := strings.TrimSuffix(o.Host, "."+o.Zone)
	if rest == o.Host || rest == "" {
		return 0
	}
	return strings.Count(rest, ".") + 1
}

func (o Outcome) String() string {
	mode := "direct"
	if o.Proxied {
		mode = "proxied"
	}
	s := fmt.Sprintf("%s %s (%s, %s)", o.Host, o.Action, o.Content, mode)
	if len(o.Removed) > 0 {
		s += "; removed " + strings.Join(o.Removed, ", ")
	}
	return s
}

// ErrElsewhere means a record exists and points at another machine. A
// deploy never takes it over silently: moving a name is a decision.
var ErrElsewhere = errors.New("points elsewhere")

// Ensure makes a host's A record name this machine, proxied or not as
// asked. A record that names another machine is left alone and reported,
// unless take is set.
func (m *Manager) Ensure(ctx context.Context, app, host string, mode manifest.DNSMode, take bool) (Outcome, error) {
	ip, err := m.IPv4()
	if err != nil {
		return Outcome{}, err
	}
	z, err := m.zone(ctx, host)
	if err != nil {
		return Outcome{}, err
	}
	records, err := m.CF.Records(ctx, z.ID, host)
	if err != nil {
		return Outcome{}, err
	}
	proxied := mode == manifest.DNSProxied
	want := cloudflare.Record{Type: "A", Name: host, Content: ip, Proxied: proxied, Comment: Comment(app, m.Hostname)}
	var a *cloudflare.Record
	var removed []string
	// Inspect the whole destination set before changing anything. One A
	// record pointing here cannot make a second destination safe to ignore.
	for i := range records {
		r := &records[i]
		if r.Type != "A" {
			continue
		}
		if r.Content != ip && !take {
			where := r.Content
			if other, machine, ok := commentApp(r.Comment); ok {
				where += fmt.Sprintf(" (%s on %s)", other, machine)
			}
			return Outcome{}, fmt.Errorf("%s %w: at %s, not this machine (%s); when it is time to move it, run helios dns point %s", host, ErrElsewhere, where, ip, host)
		}
		if a == nil || a.Content != ip && r.Content == ip {
			a = r
		}
	}
	for _, r := range records {
		if r.Type != "CNAME" && r.Type != "AAAA" && (r.Type != "A" || a == nil || r.ID == a.ID) {
			continue
		}
		if !take {
			return Outcome{}, fmt.Errorf("%s has an additional %s record (%s) that would split or shadow the A record helios keeps; remove it, or run helios dns point %s", host, r.Type, r.Content, host)
		}
		if err := m.CF.Delete(ctx, z.ID, r.ID); err != nil {
			return Outcome{}, err
		}
		removed = append(removed, r.Type+" "+r.Content)
	}
	if a == nil {
		if _, err := m.CF.Create(ctx, z.ID, want); err != nil {
			return Outcome{}, err
		}
		return Outcome{Host: host, Action: "made", Content: ip, Proxied: proxied, Zone: z.Name, Removed: removed}, nil
	}
	if a.Content == ip && a.Proxied == proxied && a.Comment == want.Comment && len(removed) == 0 {
		return Outcome{Host: host, Action: "kept", Content: ip, Proxied: proxied, Zone: z.Name, Removed: removed}, nil
	}
	want.ID = a.ID
	if err := m.CF.Update(ctx, z.ID, want); err != nil {
		return Outcome{}, err
	}
	return Outcome{Host: host, Action: "updated", Content: ip, Proxied: proxied, Zone: z.Name, Removed: removed}, nil
}

// Remove deletes the records helios made for an app on this machine: the
// ones carrying its comment that still name this machine. A record that
// has since been pointed elsewhere, by helios or by hand, stays.
func (m *Manager) Remove(ctx context.Context, app string, hosts []string) ([]string, error) {
	mine := m.mine()
	var removed []string
	for _, host := range hosts {
		z, err := m.zone(ctx, host)
		if errors.Is(err, cloudflare.ErrNoZone) {
			continue
		}
		if err != nil {
			return removed, err
		}
		records, err := m.CF.Records(ctx, z.ID, host)
		if err != nil {
			return removed, err
		}
		for _, r := range records {
			if r.Comment != Comment(app, m.Hostname) || !mine[r.Content] {
				continue
			}
			if err := m.CF.Delete(ctx, z.ID, r.ID); err != nil {
				return removed, err
			}
			removed = append(removed, host)
		}
	}
	return removed, nil
}

// Drop is what dropping a name's record deletes: every A and AAAA record
// at exactly that name, each of which points at this machine.
type Drop struct {
	Host    string
	Zone    string
	Records []cloudflare.Record
}

func (d Drop) String() string {
	parts := make([]string, len(d.Records))
	for i, r := range d.Records {
		parts[i] = r.Type + " " + r.Content
		if r.Comment != "" {
			parts[i] += " (" + r.Comment + ")"
		}
	}
	return strings.Join(parts, ", ")
}

// Droppable finds the records a drop of host would delete. Only records
// named exactly host count, so a wildcard that covers it is never one of
// them unless the wildcard's own name is the one given. Where a record
// points is what decides, never its comment: one at the name that points
// anywhere but this machine, a CNAME included, refuses the whole drop, so
// a name another machine answers for is never cleared from here.
func (m *Manager) Droppable(ctx context.Context, host string) (Drop, error) {
	z, err := m.zone(ctx, host)
	if err != nil {
		return Drop{}, err
	}
	records, err := m.CF.Records(ctx, z.ID, host)
	if err != nil {
		return Drop{}, err
	}
	mine := m.mine()
	d := Drop{Host: host, Zone: z.Name}
	for _, r := range records {
		if r.Name != host {
			continue
		}
		switch r.Type {
		case "A", "AAAA":
			if !mine[r.Content] {
				return Drop{}, fmt.Errorf("%s %w: its %s record names %s, not this machine; helios drops only a record that points here", host, ErrElsewhere, r.Type, r.Content)
			}
			d.Records = append(d.Records, r)
		case "CNAME":
			return Drop{}, fmt.Errorf("%s is a CNAME to %s, not a record that points at this machine; helios drops only those", host, r.Content)
		}
	}
	if len(d.Records) == 0 {
		return Drop{}, fmt.Errorf("%s has no A or AAAA record in %s", host, z.Name)
	}
	// The API's order is its own; a plan's words must not move with it.
	sort.Slice(d.Records, func(i, j int) bool {
		a, b := d.Records[i], d.Records[j]
		return a.Type < b.Type || (a.Type == b.Type && a.Content < b.Content)
	})
	return d, nil
}

// DropRecords deletes what Droppable found, reading each record again
// first: one that has changed since, or no longer points here, stops the
// drop, and one already gone is passed over.
func (m *Manager) DropRecords(ctx context.Context, d Drop) ([]string, error) {
	z, err := m.zone(ctx, d.Host)
	if err != nil {
		return nil, err
	}
	records, err := m.CF.Records(ctx, z.ID, d.Host)
	if err != nil {
		return nil, err
	}
	now := map[string]cloudflare.Record{}
	for _, r := range records {
		now[r.ID] = r
	}
	mine := m.mine()
	var dropped []string
	for _, want := range d.Records {
		r, ok := now[want.ID]
		if !ok {
			continue
		}
		if r.Name != d.Host || r.Type != want.Type || r.Content != want.Content || !mine[r.Content] {
			return dropped, fmt.Errorf("%s's %s record changed since the plan (it names %s now); nothing more is deleted", d.Host, r.Type, r.Content)
		}
		if err := m.CF.Delete(ctx, z.ID, r.ID); err != nil {
			return dropped, err
		}
		dropped = append(dropped, r.Type+" "+r.Content)
	}
	return dropped, nil
}

// Status is one host's record as helios sees it.
type Status struct {
	Host    string `json:"host"`
	App     string `json:"app"`
	Mode    string `json:"mode"`
	Record  string `json:"record,omitempty"`
	Proxied bool   `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
	// Verdict says whether the record does what the route wants.
	Verdict string `json:"verdict"`
}

// Route is a host an app is reached at, with how its record is kept.
type Route struct {
	App  string
	Host string
	Mode manifest.DNSMode
}

// Look reports every route's record without changing anything.
func (m *Manager) Look(ctx context.Context, routes []Route) ([]Status, error) {
	ip, ipErr := m.IPv4()
	mine := m.mine()
	var out []Status
	for _, r := range routes {
		st := Status{Host: r.Host, App: r.App, Mode: modeWord(r.Mode)}
		if ipErr != nil {
			st.Verdict = ipErr.Error()
			out = append(out, st)
			continue
		}
		z, err := m.zone(ctx, r.Host)
		if errors.Is(err, cloudflare.ErrNoZone) {
			st.Verdict = "not in a zone this token sees"
			out = append(out, st)
			continue
		}
		if err != nil {
			return nil, err
		}
		records, err := m.CF.Records(ctx, z.ID, r.Host)
		if err != nil {
			return nil, err
		}
		found := firstAddress(records, mine)
		if found == nil {
			wildcard, err := m.CF.Records(ctx, z.ID, wildcardFor(r.Host))
			if err != nil {
				return nil, err
			}
			if w := firstAddress(wildcard, mine); w != nil {
				st.Record, st.Proxied = w.Content, w.Proxied
				if mine[w.Content] {
					st.Verdict = "covered by " + w.Name + ", which points here"
				} else {
					st.Verdict = "covered by " + w.Name + ", which points elsewhere"
				}
				if r.Mode.Managed() {
					st.Verdict += "; the next deploy makes its own record"
				}
				out = append(out, st)
				continue
			}
			st.Verdict = "no record"
			if r.Mode.Managed() {
				st.Verdict = "no record yet; the next deploy makes it"
			}
			out = append(out, st)
			continue
		}
		st.Record, st.Proxied, st.Comment = found.Content, found.Proxied, found.Comment
		switch {
		case found.Type == "CNAME":
			st.Verdict = "CNAME to " + found.Content
		case found.Content != ip && !mine[found.Content]:
			st.Verdict = "points elsewhere"
		case r.Mode == manifest.DNSProxied && !found.Proxied:
			st.Verdict = "points here but not proxied"
		case r.Mode == manifest.DNSDirect && found.Proxied:
			st.Verdict = "points here but proxied"
		case r.Mode.Managed() && found.Comment != Comment(r.App, m.Hostname):
			st.Verdict = "points here, not made by helios"
		default:
			st.Verdict = "ok"
		}
		out = append(out, st)
	}
	return out, nil
}

func (m *Manager) mine() map[string]bool {
	mine := map[string]bool{}
	for _, a := range m.Addresses {
		mine[a] = true
	}
	return mine
}

// firstAddress picks an A, AAAA or CNAME, preferring any destination that
// does not point here. One healthy answer must not hide split traffic.
func firstAddress(records []cloudflare.Record, mine map[string]bool) *cloudflare.Record {
	var first *cloudflare.Record
	for i := range records {
		r := &records[i]
		switch r.Type {
		case "A", "AAAA", "CNAME":
			if r.Type == "CNAME" || !mine[r.Content] {
				return r
			}
			if first == nil {
				first = r
			}
		}
	}
	return first
}

// wildcardFor names the wildcard that would cover a host one level up.
func wildcardFor(host string) string {
	_, parent, _ := strings.Cut(host, ".")
	return "*." + parent
}

// Covers reports whether a wildcard record's name covers a host.
func Covers(wildcard, host string) bool {
	suffix := strings.TrimPrefix(wildcard, "*")
	return strings.HasPrefix(wildcard, "*.") && strings.HasSuffix(host, suffix) && host != suffix[1:]
}

// Finding is one thing an audit noticed.
type Finding struct {
	Zone    string `json:"zone,omitempty"`
	Host    string `json:"host"`
	Type    string `json:"type,omitempty"`
	Content string `json:"content,omitempty"`
	Comment string `json:"comment,omitempty"`
	What    string `json:"what"`
	// Droppable marks a record that points here with no route here to
	// answer for it: what helios dns drop deletes.
	Droppable bool `json:"droppable,omitempty"`
}

// Audit looks at every record in the zones the routes live in and reports
// what doesn't line up: records that point here without a route (a site
// answering 525 or 404), records helios made that no route keeps any more,
// routed hosts whose records point elsewhere, and routed hosts with no
// record at all.
func (m *Manager) Audit(ctx context.Context, routes []Route) ([]Finding, error) {
	mine := m.mine()
	routed := map[string]Route{}
	zones := map[string]cloudflare.Zone{}
	var findings []Finding
	for _, r := range routes {
		routed[r.Host] = r
		z, err := m.zone(ctx, r.Host)
		if errors.Is(err, cloudflare.ErrNoZone) {
			findings = append(findings, Finding{Host: r.Host, What: fmt.Sprintf("routed by %s but in no zone this token sees", r.App)})
			continue
		}
		if err != nil {
			return nil, err
		}
		zones[z.Name] = z
	}
	names := make([]string, 0, len(zones))
	for n := range zones {
		names = append(names, n)
	}
	sort.Strings(names)
	answered := map[string]bool{}
	for _, name := range names {
		z := zones[name]
		records, err := m.CF.Records(ctx, z.ID, "")
		if err != nil {
			return nil, err
		}
		for _, r := range records {
			if r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" {
				continue
			}
			f := Finding{Zone: z.Name, Host: r.Name, Type: r.Type, Content: r.Content, Comment: r.Comment}
			app, machine, byHelios := commentApp(r.Comment)
			if strings.HasPrefix(r.Name, "*.") {
				used := false
				for host := range routed {
					if Covers(r.Name, host) {
						used = true
						if mine[r.Content] {
							answered[host] = true
						}
					}
				}
				if mine[r.Content] && !used {
					f.What, f.Droppable = "a wildcard pointing at this machine that no route here uses", true
					findings = append(findings, f)
				}
				continue
			}
			route, hasRoute := routed[r.Name]
			if hasRoute {
				answered[r.Name] = true
			}
			switch {
			case mine[r.Content] && !hasRoute && byHelios:
				f.What, f.Droppable = fmt.Sprintf("made by helios for %s on %s, which no longer routes it", app, machine), true
			case mine[r.Content] && !hasRoute:
				f.What, f.Droppable = "points at this machine without a route: nothing answers for it", true
			case hasRoute && r.Type == "CNAME":
				f.What = fmt.Sprintf("routed by %s here but is a CNAME to %s", route.App, r.Content)
			case hasRoute && !mine[r.Content] && byHelios && machine != m.Hostname:
				f.What = fmt.Sprintf("routed by %s here but kept by helios for %s on %s", route.App, app, machine)
			case hasRoute && !mine[r.Content]:
				f.What = fmt.Sprintf("routed by %s here but points at %s", route.App, r.Content)
			default:
				continue
			}
			findings = append(findings, f)
		}
	}
	for _, r := range routes {
		if _, inZone := zones[zoneName(zones, r.Host)]; !inZone {
			continue
		}
		if !answered[r.Host] && !hasRecordFinding(findings, r.Host) {
			findings = append(findings, Finding{Zone: zoneName(zones, r.Host), Host: r.Host, What: fmt.Sprintf("routed by %s but no record points here", r.App)})
		}
	}
	return findings, nil
}

func zoneName(zones map[string]cloudflare.Zone, host string) string {
	best := ""
	for name := range zones {
		if (host == name || strings.HasSuffix(host, "."+name)) && len(name) > len(best) {
			best = name
		}
	}
	return best
}

func hasRecordFinding(findings []Finding, host string) bool {
	for _, f := range findings {
		if f.Host == host {
			return true
		}
	}
	return false
}

func modeWord(m manifest.DNSMode) string {
	if m == manifest.DNSManual {
		return "manual"
	}
	return string(m)
}
