package peer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

// How long a look at the peers may take, and how much of it is read.
const (
	// RoundDeadline bounds one look at every peer, all three paths of
	// each and this machine's own public URLs at once.
	RoundDeadline = 30 * time.Second
	// PathTimeout bounds one path to one peer.
	PathTimeout = 10 * time.Second
	// MaxSummaryBytes is as much of a peer's summary as is read.
	MaxSummaryBytes = 256 << 10
)

// The words a path ends in when it fails, beside "status" and the code a
// URL answered with. Nothing else of an error is kept, so no address or
// name it held reaches a message, a summary or a log.
const (
	WordTimeout     = "timeout"
	WordRefused     = "refused"
	WordReset       = "reset"
	WordDNS         = "dns"
	WordTLS         = "tls"
	WordUnreachable = "unreachable"
	WordFailed      = "failed"
)

var (
	// errOffMesh is a connection refused before it was made, because the
	// address it would reach isn't on the mesh or loopback.
	errOffMesh = errors.New("the address is not on the mesh")
	// errUntrusted is a peer's Helios refusing this machine's key.
	errUntrusted = errors.New("the peer does not accept this machine's key")
	// errUnreadable is an answer that isn't a summary.
	errUnreadable = errors.New("the summary can't be read")
	// errNoCertificate is an edge that shook hands without a certificate.
	errNoCertificate = errors.New("the edge served no certificate")
)

// statusError is an HTTP answer other than the one asked for.
type statusError int

func (e statusError) Error() string { return "answered " + strconv.Itoa(int(e)) }

// answeredStatus finds the code in a failed public check, which says what
// the URL answered.
var answeredStatus = regexp.MustCompile(`: answered ([1-5][0-9]{2})\b`)

// Source is this machine's watch of its peers. Each round it looks at
// every peer over three paths at once: its Helios's summary over the
// mesh, a TLS handshake with its edge over the mesh, and its public URLs
// through the edge provider. It checks this machine's own public URLs
// alongside, keeps what it found for this machine's summary, and keeps
// what observers push. What it must remember across a restart it keeps
// in the sidecar beside the state database.
type Source struct {
	Secrets *secrets.Store
	Store   *state.Store
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Log reports what the watch can't keep; nothing when nil.
	Log func(format string, args ...any)

	// The paths, replaced in tests; nil means the real ones. fetch reads
	// the summary at a peer's mesh address presenting token, handshake
	// shakes hands with the edge at addr as host, and check fetches a
	// public URL.
	fetch     func(ctx context.Context, mesh, token string) (Summary, error)
	handshake func(ctx context.Context, host, addr string) error
	check     func(ctx context.Context, url string) error
	// resolver resolves mesh names; nil means the system's.
	resolver *net.Resolver
	// deadline bounds a round; RoundDeadline when zero.
	deadline time.Duration

	// rounds keeps rounds from overlapping.
	rounds sync.Mutex

	mu sync.Mutex
	// started is when this machine started watching, and round when its
	// watch last finished a round.
	started time.Time
	round   time.Time
	last    Last
	// self is this machine's name to its peers.
	self string
	// lastGood is when each peer's summary last came back ok, and
	// lastView when each observer's last push arrived, by name.
	lastGood map[string]time.Time
	lastView map[string]time.Time
	// pushed is each observer's last push, by name.
	pushed map[string]received
	// seen is each peer's summary that came back ok in the last round,
	// by name.
	seen map[string]Summary
	// told and deferring are the gate's records: who told each peer
	// incident, and the notices held while another observer is to send
	// them. sending counts the notices the gate is passing to this
	// machine's own fan-out right now, by key, and missed holds the last
	// notice it passed there that some leg missed, by incident.
	told      []Told
	deferring []Deferral
	sending   map[string]int
	missed    map[int64]miss
}

// received is an observer's last push, and when it arrived.
type received struct {
	push Push
	at   time.Time
}

// look is one look at one peer: the word each path ended in, and its
// summary when one came back that is the peer's, ok or stale.
type look struct {
	paths   Paths
	summary *Summary
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Source) log(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

// begin starts the watch's clock the first time it is asked anything,
// and takes up what the sidecar kept. A sidecar that can't be read is
// started afresh, which only makes the clocks it kept start again. The
// caller holds mu.
func (s *Source) begin() {
	if !s.started.IsZero() {
		return
	}
	s.started = s.now()
	s.lastGood = map[string]time.Time{}
	s.lastView = map[string]time.Time{}
	s.pushed = map[string]received{}
	s.sending = map[string]int{}
	s.missed = map[int64]miss{}
	if s.Store == nil {
		return
	}
	sc, err := ReadSidecar(s.Store)
	if err != nil {
		s.log("peer state: unreadable, starting fresh")
		return
	}
	maps.Copy(s.lastGood, sc.LastGood)
	maps.Copy(s.lastView, sc.LastView)
	s.self, s.told, s.deferring = sc.Self, sc.Told, sc.Deferring
}

// Save writes what the watch must remember across a restart to the
// sidecar, leaving out what is past keeping. The watch saves once after
// each round.
func (s *Source) Save() error {
	s.mu.Lock()
	s.begin()
	sc := Sidecar{Self: s.self, LastGood: maps.Clone(s.lastGood), LastView: maps.Clone(s.lastView), Told: s.told, Deferring: s.deferring}
	sc.prune(s.now())
	s.told, s.deferring = sc.Told, sc.Deferring
	sc.Told, sc.Deferring = append([]Told{}, sc.Told...), append([]Deferral{}, sc.Deferring...)
	s.mu.Unlock()
	return writeSidecar(s.Store, sc)
}

// Observe looks at every peer once and returns the peer conditions that
// hold. Where peer watch isn't set up it finds nothing. Where its
// configuration can't be read it holds every open peer incident as it
// is, so nothing about a peer pages or recovers on a look never taken.
func (s *Source) Observe(ctx context.Context) []watch.Condition {
	s.rounds.Lock()
	defer s.rounds.Unlock()
	s.mu.Lock()
	s.begin()
	s.mu.Unlock()
	c, err := Load(s.Secrets)
	if err != nil {
		s.mu.Lock()
		s.seen = nil
		s.mu.Unlock()
	}
	switch {
	case errors.Is(err, ErrNotSet):
		return nil
	case err != nil:
		return s.held(ctx)
	}
	deadline := s.deadline
	if deadline == 0 {
		deadline = RoundDeadline
	}
	rctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	var selfCheck bool
	looks := make([]look, len(c.Peers))
	var wg sync.WaitGroup
	wg.Go(func() { selfCheck = s.public(rctx, c.Self.Public) == WordOK })
	for i, p := range c.Peers {
		wg.Go(func() { looks[i] = s.look(rctx, p, c.Token) })
	}
	wg.Wait()
	return s.judge(ctx, c, selfCheck, looks)
}

// judge turns a round's looks into conditions, with what the peers'
// summaries and the observers' pushes add, and keeps what it found for
// this machine's summary.
func (s *Source) judge(ctx context.Context, c Config, selfCheck bool, looks []look) []watch.Condition {
	r := Round{Self: c.Self.Name, Now: s.now(), SelfCheck: selfCheck, Open: s.openKeys(ctx)}
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Started = s.started
	s.self = c.Self.Name
	s.seen = map[string]Summary{}
	watched := map[string]bool{}
	paths := map[string]Paths{}
	for i, p := range c.Peers {
		l := looks[i]
		watched[p.Name] = true
		paths[p.Name] = l.paths
		if l.paths.Summary == WordOK {
			s.lastGood[p.Name] = r.Now
			s.seen[p.Name] = *l.summary
		}
		sight := Sight{Name: p.Name, Paths: l.paths, LastGood: s.lastGood[p.Name]}
		if l.summary != nil {
			sight.Report = l.summary.report()
			r.Views = append(r.Views, l.summary.views()...)
		}
		r.Peers = append(r.Peers, sight)
	}
	// A peer removed and added again is never seen until it answers.
	for name := range s.lastGood {
		if !watched[name] {
			delete(s.lastGood, name)
		}
	}
	for name, got := range s.pushed {
		if _, ok := c.Observers[name]; !ok {
			delete(s.pushed, name)
			continue
		}
		r.Views = append(r.Views, got.views(name, r.Now)...)
	}
	for name := range s.lastView {
		if _, ok := c.Observers[name]; !ok {
			delete(s.lastView, name)
		}
	}
	for name := range c.Observers {
		if !watched[name] {
			r.Observers = append(r.Observers, Observer{Name: name, LastView: s.lastView[name]})
		}
	}
	sort.Slice(r.Observers, func(i, j int) bool { return r.Observers[i].Name < r.Observers[j].Name })

	conditions := Judge(r)
	findings := []Finding{}
	for _, f := range conditions {
		if !f.Unknown {
			findings = append(findings, Finding{Key: f.Key, Severity: f.Severity})
		}
	}
	s.last = Last{Looked: r.Now, SelfCheck: selfCheck, Findings: findings, Paths: paths}
	return conditions
}

// openKeys are the keys of this machine's open incidents, none when they
// can't be read.
func (s *Source) openKeys(ctx context.Context) []string {
	open, err := s.Store.OpenIncidents(ctx)
	if err != nil {
		return nil
	}
	keys := make([]string, len(open))
	for i, incident := range open {
		keys[i] = incident.Key
	}
	return keys
}

// held holds every open peer incident as it is.
func (s *Source) held(ctx context.Context) []watch.Condition {
	var conditions []watch.Condition
	for _, key := range s.openKeys(ctx) {
		if strings.HasPrefix(key, keyPrefix) {
			conditions = append(conditions, watch.Condition{Key: key, Unknown: true})
		}
	}
	return conditions
}

// Last is what this machine's watching last found, for its summary, and
// what its gate is doing about its peer notices.
func (s *Source) Last() Last {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.begin()
	last := s.last
	last.Round = s.round
	if last.Round.IsZero() {
		last.Round = s.started
	}
	last.Sending = slices.Sorted(maps.Keys(s.sending))
	last.Sent = map[int64]time.Time{}
	for _, t := range s.told {
		if t.By == s.self {
			last.Sent[t.IncidentID] = later(last.Sent[t.IncidentID], t.At)
		}
	}
	return last
}

// Receive keeps what an observer pushed, as it arrived at at, until its
// next push.
func (s *Source) Receive(observer string, p Push, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.begin()
	s.pushed[observer] = received{push: p, at: at}
	s.lastView[observer] = at
}

// RoundDone records that this machine's watch finished a round at at.
func (s *Source) RoundDone(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.begin()
	s.round = at
}

// look tries one peer over its three paths at once. Its edge is asked
// for the host of its first public URL at its mesh address.
func (s *Source) look(ctx context.Context, p Peer, token string) look {
	host, _, _ := net.SplitHostPort(p.Mesh)
	handshake := s.handshake
	if handshake == nil {
		handshake = s.shake
	}
	var l look
	var wg sync.WaitGroup
	wg.Go(func() { l.paths.Summary, l.summary = s.summaryPath(ctx, p, token) })
	wg.Go(func() {
		l.paths.TLS = word(attempt(ctx, func(ctx context.Context) error {
			return handshake(ctx, hostname(p.Public[0]), net.JoinHostPort(host, "443"))
		}))
	})
	wg.Go(func() { l.paths.Public = s.public(ctx, p.Public) })
	wg.Wait()
	return l
}

// summaryPath asks the peer's Helios for its summary. One from another
// machine is a mismatch, and one whose watch has stopped is stale.
func (s *Source) summaryPath(ctx context.Context, p Peer, token string) (string, *Summary) {
	fetch := s.fetch
	if fetch == nil {
		fetch = s.fetchSummary
	}
	summary, err := within(ctx, func(ctx context.Context) (Summary, error) { return fetch(ctx, p.Mesh, token) })
	switch {
	case err != nil:
		return word(err), nil
	case summary.Name != p.Name:
		return WordMismatch, nil
	case elapsed(summary.LastRoundAgeS) > StaleRound:
		return WordStale, &summary
	}
	return WordOK, &summary
}

// public tries each URL at once. It passes if any answers, and fails as
// the first did otherwise; with no URL to try, it fails.
func (s *Source) public(ctx context.Context, urls []string) string {
	if len(urls) == 0 {
		return WordFailed
	}
	check := s.check
	if check == nil {
		check = func(ctx context.Context, u string) error { return app.RunCheck(ctx, manifest.Check{URL: u}) }
	}
	failures := make([]error, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Go(func() { failures[i] = attempt(ctx, func(ctx context.Context) error { return check(ctx, u) }) })
	}
	wg.Wait()
	for _, err := range failures {
		if err == nil {
			return WordOK
		}
	}
	return word(failures[0])
}

// fetchSummary reads a peer's summary at its mesh address, presenting
// token. It reaches only the mesh, never through a proxy, follows no
// redirect, and reads at most MaxSummaryBytes.
func (s *Source) fetchSummary(ctx context.Context, mesh, token string) (Summary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+mesh+SummaryPath, nil)
	if err != nil {
		return Summary{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	transport := &http.Transport{DialContext: s.dialer().DialContext, MaxResponseHeaderBytes: MaxHeaderBytes}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: PathTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return Summary{}, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized && resp.Header.Get(Header) != "":
		return Summary{}, errUntrusted
	case resp.StatusCode != http.StatusOK:
		return Summary{}, statusError(resp.StatusCode)
	}
	var summary Summary
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxSummaryBytes)).Decode(&summary); err != nil {
		return Summary{}, errUnreadable
	}
	return summary, nil
}

// shake shakes hands with a peer's edge on the mesh and passes when it
// serves any certificate at all: an edge behind Cloudflare may serve
// Cloudflare's origin certificate, which nothing else trusts.
func (s *Source) shake(ctx context.Context, host, addr string) error {
	certs, err := edge.Serves(ctx, s.dialer(), host, addr)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errNoCertificate
	}
	return nil
}

// dialer connects only to addresses on the mesh or loopback, whatever a
// name resolves to, so a mesh name that resolves anywhere else never
// gets this machine's key.
func (s *Source) dialer() *net.Dialer {
	return &net.Dialer{Timeout: PathTimeout, Resolver: s.resolver, Control: meshOnly}
}

// meshOnly refuses to connect to an address off the mesh.
func meshOnly(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !onMesh(ap.Addr().Unmap()) {
		return errOffMesh
	}
	return nil
}

// within runs one path under PathTimeout and calls it a timeout when it
// hasn't finished in time, even if it never returns.
func within[T any](ctx context.Context, path func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, PathTimeout)
	defer cancel()
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := path(ctx)
		done <- result{value, err}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		var none T
		return none, ctx.Err()
	}
}

// attempt is within, for a path that finds nothing but whether it failed.
func attempt(ctx context.Context, path func(context.Context) error) error {
	_, err := within(ctx, func(ctx context.Context) (struct{}, error) { return struct{}{}, path(ctx) })
	return err
}

// word is what a path's error comes to: one of a fixed few words, so
// nothing the error held goes any further.
func word(err error) string {
	var status statusError
	var dns *net.DNSError
	var timeout net.Error
	switch {
	case err == nil:
		return WordOK
	case errors.Is(err, errUntrusted):
		return WordUntrusted
	case errors.As(err, &status):
		return "status " + strconv.Itoa(int(status))
	case errors.Is(err, errOffMesh):
		return WordUnreachable
	case errors.As(err, &dns):
		return WordDNS
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		return WordTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return WordRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return WordReset
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTDOWN),
		errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EADDRNOTAVAIL):
		return WordUnreachable
	case errors.Is(err, errNoCertificate), failedTLS(err):
		return WordTLS
	}
	if m := answeredStatus.FindStringSubmatch(err.Error()); m != nil {
		return "status " + m[1]
	}
	return WordFailed
}

// failedTLS reports whether err is a TLS handshake or certificate that
// failed.
func failedTLS(err error) bool {
	var record tls.RecordHeaderError
	var verify *tls.CertificateVerificationError
	return errors.As(err, &record) || errors.As(err, &verify) || strings.Contains(err.Error(), "tls: ")
}

// hostname is a URL's host name, without its port.
func hostname(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// report is what a peer's summary says about itself that it may be
// unable to alert about.
func (s Summary) report() *Report {
	r := &Report{}
	for _, b := range s.Backups {
		r.Backups = append(r.Backups, Backup{App: b.App, BackedUp: b.LastGoodBackupAgeS != nil, BackupAge: elapsedIf(b.LastGoodBackupAgeS),
			DeployedAge: elapsedIf(b.DeployedAgeS), DrillOverdue: elapsedIf(b.DrillOverdueS)})
	}
	for _, l := range s.Legs {
		r.Legs = append(r.Legs, l.leg())
	}
	for _, i := range s.Incidents {
		r.Open = append(r.Open, OpenIncident{Subject: i.Subject, Severity: i.Severity})
	}
	return r
}

// views are what a peer's summary says it saw of its own peers.
func (s Summary) views() []View {
	views := make([]View, len(s.Views))
	for i, v := range s.Views {
		views[i] = View{Observer: s.Name, Subject: v.Subject, Age: elapsed(v.AgeS), SelfCheck: s.SelfCheck, Paths: v.Paths}
	}
	return views
}

// views are what an observer pushed, as old as the push is now.
func (r received) views(observer string, now time.Time) []View {
	age := max(now.Sub(r.at), 0)
	views := make([]View, len(r.push.Views))
	for i, v := range r.push.Views {
		views[i] = View{Observer: observer, Subject: v.Subject, Age: age, SelfCheck: r.push.SelfCheck, Paths: v.Paths}
	}
	return views
}

// elapsed is an age a peer gave in seconds, as a duration no shorter
// than nothing and no longer than a duration holds.
func elapsed(seconds int64) time.Duration {
	switch {
	case seconds <= 0:
		return 0
	case seconds > math.MaxInt64/int64(time.Second):
		return math.MaxInt64
	}
	return time.Duration(seconds) * time.Second
}

// elapsedIf is elapsed, and nothing for an age not given.
func elapsedIf(seconds *int64) time.Duration {
	if seconds == nil {
		return 0
	}
	return elapsed(*seconds)
}
