package incident

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// minSecretValue is the shortest secret value replaced, and minEnvValue
// the shortest manifest env value: anything shorter matches too much
// ordinary text.
const (
	minSecretValue = 4
	minEnvValue    = 8
)

// redactor replaces known values, and the shapes of credentials and
// private addresses, in text. Its zero value knows no values and still
// replaces the shapes.
type redactor struct {
	// names maps each form a value can take in text to the name of the
	// secret or env var it came from.
	names map[string]string
	// forms are the keys of names, longest first, so a value is replaced
	// before a shorter one inside it can break it up.
	forms []string
}

// add makes value, and the forms it takes when escaped, replaceable by
// name when it is at least shortest bytes. Each line of a value written over
// several lines, such as a PEM key, is added too, since a log line can
// only hold one of them.
func (r *redactor) add(name, value string, shortest int) {
	r.addForms(name, value, shortest)
	if strings.Contains(value, "\n") {
		for line := range strings.SplitSeq(value, "\n") {
			r.addForms(name, strings.TrimSpace(line), max(shortest, minEnvValue))
		}
	}
}

func (r *redactor) addForms(name, value string, shortest int) {
	if len(value) < shortest {
		return
	}
	if r.names == nil {
		r.names = map[string]string{}
	}
	for _, v := range []string{value, clean(value)} {
		for _, form := range []string{v, url.QueryEscape(v), url.PathEscape(v), jsonEscape(v, true), jsonEscape(v, false)} {
			if len(form) < shortest {
				continue
			}
			if have, ok := r.names[form]; ok && have <= name {
				continue
			}
			if _, ok := r.names[form]; !ok {
				r.forms = append(r.forms, form)
			}
			r.names[form] = name
		}
	}
	slices.SortFunc(r.forms, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
}

// jsonEscape is v as it appears inside a JSON string, with or without
// <, > and & escaped as Go escapes them.
func jsonEscape(v string, html bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(html)
	if enc.Encode(v) != nil {
		return v
	}
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(b.String(), "\n"), `"`), `"`)
}

var (
	// userinfoPattern is a URL's user and password, up to the last @
	// before the host.
	userinfoPattern = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://)[^/?#\s"'<>]+@`)
	// authorizationPattern is an Authorization header's value, in a
	// header, a query or JSON.
	authorizationPattern = regexp.MustCompile(`(?i)(authorization"?\s*[:=]\s*"?)(?:(?:basic|bearer|digest|negotiate|token)\s+)?[^\s"',;]+`)
	bearerPattern        = regexp.MustCompile(`(?i)\b(bearer\s+)[a-z0-9\-._~+/]+=*`)
	// credentialPattern is name=value where the name ends in a word that
	// names a credential, as in a query string or a logfmt line.
	credentialPattern = regexp.MustCompile(`(?i)(^|[^a-z0-9_.\-])([a-z0-9_.\-]*(?:token|secret|key|password|signature|sig|auth))=[^\s&#;,"'<>]+`)
	// credentialJSONPattern is the same name with a string value in JSON.
	credentialJSONPattern = regexp.MustCompile(`(?i)("[a-z0-9_.\-]*(?:token|secret|key|password|signature|sig|auth)"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	tailnetNamePattern    = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+ts\.net\b`)
	// ulaPattern is an IPv6 address in fc00::/7, as Tailscale gives out.
	ulaPattern = regexp.MustCompile(`(?i)\bf[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){2,7}`)
	// ipv4Pattern has no word boundaries, so an address run into other
	// text is still found.
	ipv4Pattern = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)

	// meshPrefix is CGNAT space, where Tailscale gives out IPv4 addresses.
	meshPrefix      = netip.MustParsePrefix("100.64.0.0/10")
	privatePrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}
)

// String redacts s: known values become [redacted NAME], a URL's user
// and password, an Authorization or Bearer value and a credential's
// value become [redacted], tailnet names and addresses become [mesh],
// and RFC 1918 addresses become [private].
func (r *redactor) String(s string) string {
	if s == "" {
		return s
	}
	for _, form := range r.forms {
		s = strings.ReplaceAll(s, form, "[redacted "+r.names[form]+"]")
	}
	lower := strings.ToLower(s)
	if strings.Contains(s, "://") && strings.Contains(s, "@") {
		s = userinfoPattern.ReplaceAllString(s, "${1}[redacted]@")
	}
	if strings.Contains(lower, "authorization") {
		s = authorizationPattern.ReplaceAllString(s, "${1}[redacted]")
	}
	if strings.Contains(lower, "bearer") {
		s = bearerPattern.ReplaceAllString(s, "${1}[redacted]")
	}
	if strings.Contains(s, "=") {
		s = credentialPattern.ReplaceAllString(s, "${1}${2}=[redacted]")
	}
	if strings.Contains(s, `"`) && strings.Contains(s, ":") {
		s = credentialJSONPattern.ReplaceAllString(s, `${1}"[redacted]"`)
	}
	if strings.Contains(lower, "ts.net") {
		s = tailnetNamePattern.ReplaceAllString(s, "[mesh]")
	}
	if strings.Contains(s, ":") && (strings.Contains(lower, "fc") || strings.Contains(lower, "fd")) {
		s = ulaPattern.ReplaceAllString(s, "[mesh]")
	}
	if strings.Contains(s, ".") {
		s = ipv4Pattern.ReplaceAllStringFunc(s, func(m string) string {
			addr, err := netip.ParseAddr(m)
			switch {
			case err != nil:
				return m
			case meshPrefix.Contains(addr):
				return "[mesh]"
			case slices.ContainsFunc(privatePrefixes, func(p netip.Prefix) bool { return p.Contains(addr) }):
				return "[private]"
			}
			return m
		})
	}
	return s
}

// evidence redacts every string in e that came from outside helios.
func (r *redactor) evidence(e *Evidence) {
	e.Host = r.String(e.Host)
	e.Incident.Key = r.String(e.Incident.Key)
	e.Incident.Subject = r.String(e.Incident.Subject)
	e.Incident.Message = r.String(e.Incident.Message)
	if e.LastChange != nil {
		r.change(e.LastChange)
	}
	for i := range e.RecentDeploys {
		r.change(&e.RecentDeploys[i])
	}
	for i := range e.Logs {
		l := &e.Logs[i]
		l.Container, l.Workload, l.Revision = r.String(l.Container), r.String(l.Workload), r.String(l.Revision)
		for j := range l.Lines {
			l.Lines[j].Text = r.String(l.Lines[j].Text)
		}
	}
	if h := e.History; h != nil {
		for i := range h.Incidents {
			h.Incidents[i].Message = r.String(h.Incidents[i].Message)
		}
		for i := range h.Signals {
			h.Signals[i].Detail = r.String(h.Signals[i].Detail)
		}
	}
	for i := range e.Upstream {
		u := &e.Upstream[i]
		u.Indicator, u.Description, u.Error = r.String(u.Indicator), r.String(u.Description), r.String(u.Error)
	}
	for i := range e.Errors {
		e.Errors[i].Error = r.String(e.Errors[i].Error)
	}
}

func (r *redactor) change(c *Change) {
	c.App, c.Revision, c.Commit, c.Signer, c.Error = r.String(c.App), r.String(c.Revision), r.String(c.Commit), r.String(c.Signer), r.String(c.Error)
	for i := range c.Steps {
		s := &c.Steps[i]
		s.Name, s.Note, s.Error = r.String(s.Name), r.String(s.Note), r.String(s.Error)
	}
}

// leaks names the values still found in e's JSON, sorted. It reads the
// JSON's string values, not its keys, numbers or times, which can't
// carry a secret but which a short value such as 2026 would match.
func (r *redactor) leaks(e *Evidence) []string {
	if len(r.forms) == 0 {
		return nil
	}
	b, err := json.Marshal(e)
	if err != nil {
		return []string{"evidence that can't be encoded"}
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return []string{"evidence that can't be read back"}
	}
	found := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for _, item := range v {
				walk(item)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		case string:
			if _, err := time.Parse(time.RFC3339Nano, v); err == nil {
				return
			}
			for _, form := range r.forms {
				if strings.Contains(v, form) {
					found[r.names[form]] = true
				}
			}
		}
	}
	walk(v)
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// clean makes s valid UTF-8 and drops control characters other than tab.
func clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		if r != '\t' && unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// cut keeps the first limit bytes of s, ending on a whole character,
// and says how many bytes it left out.
func cut(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	end := limit
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "[+" + strconv.Itoa(len(s)-end) + " bytes]"
}
