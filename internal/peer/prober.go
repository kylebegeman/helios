package peer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"runtime/debug"
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
	// Log reports what the watch can't keep, and a path that panicked
	// once nothing waited for it; nothing when nil.
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
// started afresh: the clocks it kept start again, and the recovery of an
// incident told with no record of who told it goes from this machine. The
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
// each round. A machine that has never watched a peer gets no sidecar.
func (s *Source) Save() error {
	s.mu.Lock()
	s.begin()
	sc := Sidecar{Self: s.self, LastGood: maps.Clone(s.lastGood), LastView: maps.Clone(s.lastView), Told: s.told, Deferring: s.deferring}
	sc.prune(s.now())
	s.told, s.deferring = sc.Told, sc.Deferring
	sc.Told, sc.Deferring = append([]Told{}, sc.Told...), append([]Deferral{}, sc.Deferring...)
	s.mu.Unlock()
	if nothingToKeep(s.Store, sc) {
		return nil
	}
	return writeSidecar(s.Store, sc)
}

// Observe looks at every peer once and returns the peer conditions that
// hold. Where peer watch isn't set up it finds nothing. Where its
// configuration can't be read it holds every open peer incident as it
// is, so nothing about a peer pages or recovers on a look never taken.
// A path that panics panics again here, on the caller's goroutine.
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
		return s.Held(ctx)
	}
	rctx, cancel := context.WithTimeout(ctx, s.roundDeadline())
	defer cancel()
	var selfCheck bool
	looks := make([]look, len(c.Peers))
	var g group
	g.Go(func() { selfCheck = s.public(rctx, c.Self.Public) == WordOK })
	for i, p := range c.Peers {
		g.Go(func() { looks[i] = s.look(rctx, p, c.Token) })
	}
	g.Wait()
	return s.judge(ctx, c, selfCheck, looks)
}

func (s *Source) roundDeadline() time.Duration {
	if s.deadline == 0 {
		return RoundDeadline
	}
	return s.deadline
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

// Held holds every open peer incident as it is, for a round in which
// the peers couldn't be looked at.
func (s *Source) Held(ctx context.Context) []watch.Condition {
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
	last.Sent = nil
	for _, t := range s.told {
		if t.By == s.self {
			last.Sent = append(last.Sent, t)
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
	var g group
	g.Go(func() { l.paths.Summary, l.summary = s.summaryPath(ctx, p, token) })
	g.Go(func() {
		l.paths.TLS = word(attempt(ctx, s.log, func(ctx context.Context) error {
			return handshake(ctx, hostname(p.Public[0]), net.JoinHostPort(host, "443"))
		}))
	})
	g.Go(func() { l.paths.Public = s.public(ctx, p.Public) })
	g.Wait()
	return l
}

// summaryPath asks the peer's Helios for its summary. One from another
// machine is a mismatch, and one whose watch has stopped is stale.
func (s *Source) summaryPath(ctx context.Context, p Peer, token string) (string, *Summary) {
	fetch := s.fetch
	if fetch == nil {
		fetch = s.fetchSummary
	}
	summary, err := within(ctx, s.log, func(ctx context.Context) (Summary, error) { return fetch(ctx, p.Mesh, token) })
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
	var g group
	for i, u := range urls {
		g.Go(func() { failures[i] = attempt(ctx, s.log, func(ctx context.Context) error { return check(ctx, u) }) })
	}
	g.Wait()
	for _, err := range failures {
		if err == nil {
			return WordOK
		}
	}
	return word(failures[0])
}

// fetchSummary reads a peer's summary at its mesh address, presenting
// token, and reads at most MaxSummaryBytes of it.
func (s *Source) fetchSummary(ctx context.Context, mesh, token string) (Summary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+mesh+SummaryPath, nil)
	if err != nil {
		return Summary{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.ask(req)
	if err != nil {
		return Summary{}, err
	}
	defer resp.Body.Close()
	if err := unexpected(resp, http.StatusOK); err != nil {
		return Summary{}, err
	}
	var summary Summary
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxSummaryBytes)).Decode(&summary); err != nil {
		return Summary{}, errUnreadable
	}
	return summary, nil
}

// ask sends req to a peer's Helios. It reaches only the mesh, never
// through a proxy, follows no redirect, gives up after PathTimeout, and
// closes its connection once the answer's body is closed.
func (s *Source) ask(req *http.Request) (*http.Response, error) {
	transport := &http.Transport{DialContext: s.dialer().DialContext, MaxResponseHeaderBytes: MaxHeaderBytes, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: PathTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client.Do(req)
}

// unexpected is a peer's answer other than the want it was asked for:
// its Helios refusing this machine's key, or any other code.
func unexpected(resp *http.Response, want int) error {
	switch {
	case resp.StatusCode == http.StatusUnauthorized && resp.Header.Get(Header) != "":
		return errUntrusted
	case resp.StatusCode != want:
		return statusError(resp.StatusCode)
	}
	return nil
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
// hasn't finished in time, even if it never returns. A path that panics
// in time panics again here, on the goroutine that asked. One that
// panics once its time is up has nobody waiting for it, and is logged
// with log instead.
func within[T any](ctx context.Context, log func(string, ...any), path func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, PathTimeout)
	defer cancel()
	type result struct {
		value T
		err   error
		panic *pathPanic
	}
	done := make(chan result, 1)
	// gone is set once within stops waiting, under mu, so a panic is
	// either raised here or logged, and never lost between the two.
	var mu sync.Mutex
	gone := false
	go func() {
		defer func() {
			if p := recover(); p != nil {
				kept := caught(p)
				mu.Lock()
				defer mu.Unlock()
				if gone {
					log("peer watch: panic once its path had timed out: %v", kept)
					return
				}
				done <- result{panic: &kept}
			}
		}()
		value, err := path(ctx)
		done <- result{value: value, err: err}
	}()
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		mu.Lock()
		gone = true
		mu.Unlock()
		select {
		case r = <-done:
		default:
			r.err = ctx.Err()
		}
	}
	if r.panic != nil {
		panic(*r.panic)
	}
	return r.value, r.err
}

// attempt is within, for a path that finds nothing but whether it failed.
func attempt(ctx context.Context, log func(string, ...any), path func(context.Context) error) error {
	_, err := within(ctx, log, func(ctx context.Context) (struct{}, error) { return struct{}{}, path(ctx) })
	return err
}

// group runs a round's paths on goroutines of their own, and waits for
// them. A panic on one of those goroutines would stop the daemon, as
// nothing on another goroutine can recover it, so the group keeps the
// first with the stack it was raised on, and Wait panics with it on the
// goroutine that waits. In the daemon that is the watch's own, where its
// guard holds the round's incidents.
type group struct {
	wg     sync.WaitGroup
	mu     sync.Mutex
	caught *pathPanic
}

// Go runs fn on a goroutine of the group's.
func (g *group) Go(fn func()) {
	g.wg.Go(func() {
		defer func() {
			if p := recover(); p != nil {
				kept := caught(p)
				g.mu.Lock()
				defer g.mu.Unlock()
				if g.caught == nil {
					g.caught = &kept
				}
			}
		}()
		fn()
	})
}

// Wait waits for the group's goroutines, and panics with the first panic
// on any of them.
func (g *group) Wait() {
	g.wg.Wait()
	if g.caught != nil {
		panic(*g.caught)
	}
}

// pathPanic is a panic on one of a round's goroutines, with the stack it
// was raised on, to be raised again where the round waits for it.
type pathPanic struct {
	value any
	stack []byte
}

func (p pathPanic) Error() string { return fmt.Sprintf("%v\n%s", p.value, p.stack) }

// caught keeps a panic just recovered with the stack it was raised on,
// which the deferred function that recovered it still runs on. A panic
// raised again from a goroutine further down goes on as it was kept.
func caught(p any) pathPanic {
	if kept, ok := p.(pathPanic); ok {
		return kept
	}
	return pathPanic{value: p, stack: debug.Stack()}
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
