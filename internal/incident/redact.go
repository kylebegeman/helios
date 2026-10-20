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
	"unicode/utf16"
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
	// raw are the forms a value takes in text: as it is, and as Go and
	// URLs escape it.
	raw forms
	// folded are those forms as fold reads them, with and without
	// base64's padding, which find a value another encoder escaped.
	folded forms
}

// forms maps each form a value can take in text to the name of the
// secret or env var it came from.
type forms struct {
	names map[string]string
	// list holds the keys of names, longest first, so a value is
	// replaced before a shorter one inside it can break it up.
	list []string
}

// add makes form stand for name when it is at least shortest bytes and
// no name that sorts first has it.
func (f *forms) add(form, name string, shortest int) {
	if len(form) < shortest {
		return
	}
	if f.names == nil {
		f.names = map[string]string{}
	}
	have, ok := f.names[form]
	if ok && have <= name {
		return
	}
	if !ok {
		f.list = append(f.list, form)
	}
	f.names[form] = name
}

func (f *forms) sort() {
	slices.SortFunc(f.list, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
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
	for _, v := range []string{value, clean(value)} {
		for _, form := range []string{v, url.QueryEscape(v), url.PathEscape(v), jsonEscape(v, true), jsonEscape(v, false)} {
			r.raw.add(form, name, shortest)
			folded := fold(form)
			r.folded.add(folded, name, shortest)
			r.folded.add(strings.TrimRight(folded, "="), name, shortest)
		}
	}
	r.raw.sort()
	r.folded.sort()
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

// fold reads s as the same text however an encoder escaped it: it
// decodes JSON's escapes, including \/ and \u in either case, and URL
// escapes in either case, and reads base64's URL alphabet as its standard
// one. A value and text folded alike can be compared.
func fold(s string) string {
	if !strings.ContainsAny(s, `\%-_`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for len(s) > 0 {
		out, n := unescape(s)
		b.WriteString(out)
		s = s[n:]
	}
	return b.String()
}

// unescape reads the escape or byte s starts with as fold does, and says
// how many bytes of s that took.
func unescape(s string) (string, int) {
	switch {
	case len(s) >= 3 && s[0] == '%':
		if c, err := strconv.ParseUint(s[1:3], 16, 8); err == nil {
			return base64Byte(byte(c)), 3
		}
	case len(s) >= 6 && s[:2] == `\u`:
		c, err := strconv.ParseUint(s[2:6], 16, 16)
		r := rune(c)
		switch {
		case err != nil:
		case utf16.IsSurrogate(r):
			if len(s) >= 12 && s[6:8] == `\u` {
				if low, err := strconv.ParseUint(s[8:12], 16, 16); err == nil {
					if pair := utf16.DecodeRune(r, rune(low)); pair != utf8.RuneError {
						return string(pair), 12
					}
				}
			}
		case r < utf8.RuneSelf:
			return base64Byte(byte(r)), 6
		default:
			return string(r), 6
		}
	case len(s) >= 2 && s[0] == '\\':
		if i := strings.IndexByte(`"\/bfnrt`, s[1]); i >= 0 {
			return "\"\\/\b\f\n\r\t"[i : i+1], 2
		}
	}
	if s[0] == '-' || s[0] == '_' {
		return base64Byte(s[0]), 1
	}
	return s[:1], 1
}

// base64Byte is c with base64's URL alphabet read as its standard one.
func base64Byte(c byte) string {
	switch c {
	case '-':
		return "+"
	case '_':
		return "/"
	}
	return string([]byte{c})
}

var (
	// userinfoPattern is a URL's user and password, up to the last @
	// before the host, after a scheme JSON may have written as :\/\/.
	userinfoPattern = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*:(?:\\?/){2})[^/?#\s"'<>]+@`)
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

// String redacts s: known values, however they were escaped, become
// [redacted NAME], a URL's user and password, an Authorization or Bearer
// value and a credential's value become [redacted], tailnet names and
// addresses become [mesh], and RFC 1918 addresses become [private].
func (r *redactor) String(s string) string {
	if s == "" {
		return s
	}
	for _, form := range r.raw.list {
		s = strings.ReplaceAll(s, form, "[redacted "+r.raw.names[form]+"]")
	}
	if len(r.folded.list) > 0 {
		f := fold(s)
		for _, form := range r.folded.list {
			if strings.Contains(f, form) {
				s = replaceFolded(s, f, form, "[redacted "+r.folded.names[form]+"]")
				f = fold(s)
			}
		}
	}
	lower := strings.ToLower(s)
	if strings.Contains(s, "@") && (strings.Contains(s, "://") || strings.Contains(s, `:\/\/`)) {
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

// replaceFolded replaces with repl the bytes of s that each form in f,
// s as fold reads it, was read from. Where two meet inside one escape,
// each is replaced whole.
func replaceFolded(s, f, form, repl string) string {
	var matches []int
	for at := 0; ; {
		i := strings.Index(f[at:], form)
		if i < 0 {
			break
		}
		matches = append(matches, at+i, at+i+len(form))
		at += i + len(form)
	}
	var b strings.Builder
	start, done := -1, 0
	for read, at := 0, 0; read < len(s) && len(matches) > 0; {
		out, n := unescape(s[read:])
		end := at + len(out)
		if start < 0 && end > matches[0] {
			start = read
		}
		if start >= 0 && end >= matches[1] {
			b.WriteString(s[done:start])
			b.WriteString(repl)
			done, start = read+n, -1
			for len(matches) > 0 && matches[1] <= end {
				matches = matches[2:]
			}
			if len(matches) > 0 && matches[0] < end {
				start = done
			}
		}
		read, at = read+n, end
	}
	b.WriteString(s[done:])
	return b.String()
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

// leaks names the values still found in e's JSON, sorted, however they
// were escaped. It reads the JSON's string values, not its keys, numbers
// or times, which can't carry a secret but which a short value such as
// 2026 would match.
func (r *redactor) leaks(e *Evidence) []string {
	if len(r.raw.list) == 0 {
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
			for _, form := range r.raw.list {
				if strings.Contains(v, form) {
					found[r.raw.names[form]] = true
				}
			}
			folded := fold(v)
			for _, form := range r.folded.list {
				if strings.Contains(folded, form) {
					found[r.folded.names[form]] = true
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
