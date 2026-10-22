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

// maxFolds is the most times text is read over for escapes, each reading
// undoing one escaping, as JSON in a JSON string or a URL in a URL's
// query needs. Text still escaped after that is replaced whole by
// escapedTooOften, since a value in it can't be found, and the leak check
// names any it meets escapedTooOftenLeak.
const (
	maxFolds            = 8
	escapedTooOften     = "[escaped too many times to read]"
	escapedTooOftenLeak = "text escaped too many times to read"
)

// redactor replaces known values, and the shapes of credentials and
// private addresses, in text. Its zero value knows no values and still
// replaces the shapes.
type redactor struct {
	// raw are the forms a value takes in text: as it is, and as Go and
	// URLs escape it.
	raw forms
	// folded are those forms as fold reads them, with and without
	// base64's padding, which find a value another encoder escaped, in
	// each reading folds gives of text escaped again and again.
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
// one. A value and text folded alike can be compared. It undoes one
// escaping; folds undoes the rest.
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

// folds is s and each reading fold gives of the one before, up to the
// first that fold reads as itself, so text escaped any number of times is
// read through. It says false when maxFolds readings still leave text
// escaped.
func folds(s string) ([]string, bool) {
	levels := []string{s, fold(s)}
	for len(levels) <= maxFolds {
		last := levels[len(levels)-1]
		f := fold(last)
		if f == last {
			return levels, true
		}
		levels = append(levels, f)
	}
	last := levels[len(levels)-1]
	return levels, fold(last) == last
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
	// names a credential, as in a query string or a logfmt line. Quoted
	// values can contain whitespace and delimiters until their closing quote.
	credentialPattern = regexp.MustCompile(`(?i)(^|[^a-z0-9_.\-])([a-z0-9_.\-]*(?:token|secret|key|password|signature|sig|auth))=(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s&#;,"'<>]+)`)
	// credentialJSONPattern is the same name with a string value in JSON.
	credentialJSONPattern = regexp.MustCompile(`(?i)("[a-z0-9_.\-]*(?:token|secret|key|password|signature|sig|auth)"\s*:\s*)"(?:[^"\\]|\\.)*"`)
	tailnetNamePattern    = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+ts\.net\b`)
	// ulaPattern is an IPv6 address in fc00::/7, as Tailscale gives out,
	// with its colons as they are or URL escaped.
	ulaPattern = regexp.MustCompile(`(?i)(^|[^0-9a-z_]|%[0-9a-f]{2})f[cd][0-9a-f]{2}(?:(?::|%3a)[0-9a-f]{0,4}){2,7}`)
	// reverseIPv4Pattern is a name a resolver looks an IPv4 address or
	// network up by, its numbers backwards.
	reverseIPv4Pattern = regexp.MustCompile(`(?i)\b(?:\d{1,3}\.){1,4}in-addr\.arpa\b`)
	// reverseULAPattern is the same for an address in fc00::/7, one hex
	// digit at a time.
	reverseULAPattern = regexp.MustCompile(`(?i)\b(?:[0-9a-f]\.){0,30}[cd]\.f\.ip6\.arpa\b`)

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
		levels, ok := folds(s)
		if !ok {
			return escapedTooOften
		}
		for _, form := range r.folded.list {
			if spans := foldedSpans(levels, form); len(spans) > 0 {
				s = replaceSpans(s, spans, "[redacted "+r.folded.names[form]+"]")
				// A replacement adds no escape, so s reads through as
				// before.
				levels, _ = folds(s)
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
	if strings.Contains(lower, "ip6.arpa") {
		s = reverseULAPattern.ReplaceAllString(s, "[mesh].ip6.arpa")
	}
	if (strings.Contains(s, ":") || strings.Contains(lower, "%3a")) && (strings.Contains(lower, "fc") || strings.Contains(lower, "fd")) {
		s = ulaPattern.ReplaceAllString(s, "${1}[mesh]")
	}
	if strings.Contains(lower, "in-addr.arpa") {
		s = reverseIPv4Pattern.ReplaceAllStringFunc(s, func(m string) string {
			numbers := strings.Split(strings.TrimSuffix(m[:len(m)-len("in-addr.arpa")], "."), ".")
			slices.Reverse(numbers)
			for len(numbers) < 4 {
				numbers = append(numbers, "0")
			}
			if label := addressLabel(strings.Join(numbers, ".")); label != "" {
				return label + m[len(m)-len(".in-addr.arpa"):]
			}
			return m
		})
	}
	if strings.Contains(s, ".") {
		s = replaceIPv4(s)
	}
	return s
}

// replaceIPv4 replaces each mesh or private IPv4 address in s. It reads
// one at every digit, without word boundaries, so an address run into
// other text or numbers, as in 1.100.64.0.1, is still found. Addresses
// that overlap are replaced as one.
func replaceIPv4(s string) string {
	var b strings.Builder
	done, start, end, label := 0, 0, 0, ""
	flush := func() {
		if label != "" {
			b.WriteString(s[done:start])
			b.WriteString(label)
			done, label = end, ""
		}
	}
	for i := range len(s) {
		n := quadAt(s[i:])
		if n == 0 {
			continue
		}
		found := addressLabel(s[i : i+n])
		switch {
		case found == "":
		case label != "" && i < end:
			end = max(end, i+n)
			if found == "[mesh]" {
				label = found
			}
		default:
			flush()
			start, end, label = i, i+n, found
		}
	}
	flush()
	if done == 0 {
		return s
	}
	b.WriteString(s[done:])
	return b.String()
}

// quadAt is the length of the dotted quad s starts with, each number up
// to three digits, or 0.
func quadAt(s string) int {
	n := 0
	for part := range 4 {
		if part > 0 {
			if n == len(s) || s[n] != '.' {
				return 0
			}
			n++
		}
		digits := n
		for n < len(s) && n-digits < 3 && '0' <= s[n] && s[n] <= '9' {
			n++
		}
		if n == digits {
			return 0
		}
	}
	return n
}

// addressLabel is [mesh] or [private] for an IPv4 address in mesh or
// RFC 1918 space, and empty for any other.
func addressLabel(text string) string {
	addr, err := netip.ParseAddr(text)
	switch {
	case err != nil:
		return ""
	case meshPrefix.Contains(addr):
		return "[mesh]"
	case slices.ContainsFunc(privatePrefixes, func(p netip.Prefix) bool { return p.Contains(addr) }):
		return "[private]"
	}
	return ""
}

// span is the bytes of a string from start up to end.
type span struct{ start, end int }

// foldedSpans is the spans of levels[0] that form, found in any later
// reading of it folds gave, was read from, in order and apart.
func foldedSpans(levels []string, form string) []span {
	var all []span
	for i := 1; i < len(levels); i++ {
		var spans []span
		for at := 0; ; {
			j := strings.Index(levels[i][at:], form)
			if j < 0 {
				break
			}
			spans = append(spans, span{at + j, at + j + len(form)})
			at += j + len(form)
		}
		for k := i - 1; k >= 0 && len(spans) > 0; k-- {
			spans = unfold(levels[k], spans)
		}
		all = append(all, spans...)
	}
	slices.SortFunc(all, func(a, b span) int { return a.start - b.start })
	var joined []span
	for _, sp := range all {
		if n := len(joined); n > 0 && sp.start < joined[n-1].end {
			joined[n-1].end = max(joined[n-1].end, sp.end)
			continue
		}
		joined = append(joined, sp)
	}
	return joined
}

// unfold maps spans of fold(s), in order and apart, to the bytes of s
// each was read from. A span that starts or ends inside an escape takes
// it whole, and spans that meet inside one escape are joined.
func unfold(s string, spans []span) []span {
	var out []span
	start := -1
	for read, at := 0, 0; read < len(s) && len(spans) > 0; {
		text, n := unescape(s[read:])
		end := at + len(text)
		if start < 0 && end > spans[0].start {
			start = read
		}
		if start >= 0 && end >= spans[0].end {
			for len(spans) > 0 && spans[0].end <= end {
				spans = spans[1:]
			}
			if len(spans) == 0 || spans[0].start >= end {
				out = append(out, span{start, read + n})
				start = -1
			}
		}
		read, at = read+n, end
	}
	return out
}

// replaceSpans replaces each of spans, in order and apart, in s with repl.
func replaceSpans(s string, spans []span, repl string) string {
	var b strings.Builder
	done := 0
	for _, sp := range spans {
		b.WriteString(s[done:sp.start])
		b.WriteString(repl)
		done = sp.end
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

// leaks names the values still found in e's JSON, sorted, however many
// times they were escaped, and any text escaped too many times to read as
// escapedTooOftenLeak. It reads the JSON's string values, not its keys,
// numbers or times, which can't carry a secret but which a short value
// such as 2026 would match, and not helios's own words, which an env value
// such as cloudflare or critical can be.
func (r *redactor) leaks(e *Evidence) []string {
	if len(r.raw.list) == 0 {
		return nil
	}
	b, err := json.Marshal(withoutOwnWords(e))
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
			levels, ok := folds(v)
			if !ok {
				found[escapedTooOftenLeak] = true
			}
			for _, folded := range levels[1:] {
				for _, form := range r.folded.list {
					if strings.Contains(folded, form) {
						found[r.folded.names[form]] = true
					}
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

// withoutOwnWords is a copy of e without the words helios writes itself:
// who collected it, severities, kinds, outcomes and statuses, operation
// IDs, streams and sources, the names of status pages, signals and
// sources that failed, and what was truncated. Every other string is
// kept, including those of a field added later.
func withoutOwnWords(e *Evidence) *Evidence {
	c := e.Clone()
	c.CollectedBy, c.Incident.Severity, c.Redaction.Status = "", "", ""
	change := func(ch *Change) {
		ch.Operation, ch.Kind, ch.Outcome = "", "", ""
		for i := range ch.Steps {
			ch.Steps[i].Status = ""
		}
	}
	if c.LastChange != nil {
		change(c.LastChange)
	}
	for i := range c.RecentDeploys {
		change(&c.RecentDeploys[i])
	}
	for i := range c.Logs {
		c.Logs[i].Source = ""
		for j := range c.Logs[i].Lines {
			c.Logs[i].Lines[j].Stream = ""
		}
	}
	if h := c.History; h != nil {
		for i := range h.Incidents {
			h.Incidents[i].Severity = ""
		}
		for i := range h.Signals {
			h.Signals[i].Kind = ""
		}
	}
	for i := range c.Upstream {
		c.Upstream[i].Name = ""
	}
	c.Truncated = nil
	for i := range c.Errors {
		c.Errors[i].Source = ""
	}
	return c
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
