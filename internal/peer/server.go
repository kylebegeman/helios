package peer

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// How much a peer listener does for whoever reaches it.
const (
	// SummaryCache is how long a summary is served before it is built
	// again, however many peers ask.
	SummaryCache = 10 * time.Second
	// MaxInFlight is how many requests are answered at once; one more is
	// turned away.
	MaxInFlight = 8
	// MaxHeaderBytes bounds a request's headers.
	MaxHeaderBytes = 8 << 10
	// MaxViewBytes bounds the views an observer pushes in one request.
	MaxViewBytes = 64 << 10
	// ListenerTick is how often the daemon reads where its peer listener
	// is to listen, and follows it.
	ListenerTick = 30 * time.Second
)

// Header is on every answer a peer listener gives, so an observer can
// tell Helios refusing its key from something else answering on the port.
const Header = "Helios-Peer"

// The listener's only routes.
const (
	SummaryPath = "/peer/v1/summary"
	ViewPath    = "/peer/v1/view"
)

// ErrAddressNotUp means the listen address isn't on any of this
// machine's interfaces yet, as before the mesh comes up.
var ErrAddressNotUp = errors.New("the listen address is not on this machine yet")

// Push is what an observer that only watches, such as a Mac, sends each
// server it watches: whether it reached anything at all, whether it
// sends pages itself, and what it saw of each server.
type Push struct {
	SelfCheck bool       `json:"self_check"`
	Sends     bool       `json:"sends"`
	Views     []PushView `json:"views"`
}

// PushView is an observer's look at one server.
type PushView struct {
	Subject string `json:"subject"`
	Paths
}

// Server answers this machine's peers on the mesh: its summary to each
// machine registered to read it, and the views each pushes. It answers
// nothing else, so the daemon's API is never reachable there. It reads
// the peer configuration on every request, so a key registered or
// rotated counts at once.
type Server struct {
	Deps Deps
	// Receive takes the views a registered machine pushed about this
	// machine's peers, with when they arrived by this machine's clock.
	Receive func(observer string, p Push, at time.Time)

	// headerWait is how long a request's headers may take to arrive; 5 s
	// when zero.
	headerWait time.Duration

	made     sync.Once
	inFlight chan struct{}

	cacheMu sync.Mutex
	cached  Summary
	builtAt time.Time

	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
}

// Start listens at addr and answers there until Stop. Requests carry
// ctx. Its errors never repeat the address.
func (s *Server) Start(ctx context.Context, addr netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return errors.New("the peer listener is already listening")
	}
	listener, err := net.Listen("tcp", addr.String())
	if err != nil {
		return listenError(err)
	}
	s.server, s.listener = s.httpServer(ctx), listener
	go func(server *http.Server) { _ = server.Serve(listener) }(s.server)
	return nil
}

// listenError says why listening failed, in words that never repeat the
// address the way net's errors do.
func listenError(err error) error {
	switch {
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return ErrAddressNotUp
	case errors.Is(err, syscall.EADDRINUSE):
		return errors.New("something else already listens on the listen port")
	case errors.Is(err, syscall.EACCES):
		return errors.New("this machine does not allow listening on the listen port")
	}
	return errors.New("cannot listen at the listen address")
}

// Addr is where the listener answers, or nil when it isn't listening.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Stop closes the listener, given a while to finish the requests it has,
// the same as the daemon's API.
func (s *Server) Stop() {
	s.mu.Lock()
	server := s.server
	s.server, s.listener = nil, nil
	s.mu.Unlock()
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
	}
}

// httpServer bounds every read, more tightly than the webhooks, since
// nothing here takes more than a small body. Its errors are discarded:
// the standard logger would print remote addresses.
func (s *Server) httpServer(ctx context.Context) *http.Server {
	headerWait := s.headerWait
	if headerWait == 0 {
		headerWait = 5 * time.Second
	}
	return &http.Server{Handler: s.Handler(), ReadHeaderTimeout: headerWait, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0)}
}

// Handler answers the listener's requests: only from the mesh or
// loopback, MaxInFlight at once, on its two routes, and only to a
// registered key.
func (s *Server) Handler() http.Handler {
	s.made.Do(func() { s.inFlight = make(chan struct{}, MaxInFlight) })
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(Header, "1")
	if !fromMesh(r.RemoteAddr) {
		http.Error(w, "only the mesh may ask", http.StatusForbidden)
		return
	}
	select {
	case s.inFlight <- struct{}{}:
		defer func() { <-s.inFlight }()
	default:
		http.Error(w, "busy; ask again", http.StatusServiceUnavailable)
		return
	}
	var method string
	switch r.URL.Path {
	case SummaryPath:
		method = http.MethodGet
	case ViewPath:
		method = http.MethodPost
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := Load(s.Deps.Secrets)
	if err != nil {
		http.Error(w, "peer watch can't be read here right now", http.StatusServiceUnavailable)
		return
	}
	observer, ok := c.observer(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "this key is not registered here", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == SummaryPath {
		s.summary(w, r, c.Self.Name)
		return
	}
	s.view(w, r, c, observer)
}

// fromMesh reports whether a request came from the mesh or loopback. The
// listener's address already keeps others out; this covers a listener on
// the wrong interface.
func fromMesh(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	return err == nil && onMesh(ap.Addr().Unmap())
}

// observer is the registered machine whose key authorization presents.
// Every fingerprint is compared, all the way through, so how long it
// takes says nothing about which matched.
func (c Config) observer(authorization string) (string, bool) {
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || token == "" {
		return "", false
	}
	presented := []byte(Fingerprint(token))
	names := make([]string, 0, len(c.Observers))
	for name := range c.Observers {
		names = append(names, name)
	}
	sort.Strings(names)
	match := ""
	for _, name := range names {
		if subtle.ConstantTimeCompare(presented, []byte(c.Observers[name])) == 1 && match == "" {
			match = name
		}
	}
	return match, match != ""
}

// summary answers with this machine's summary, built at most once every
// SummaryCache.
func (s *Server) summary(w http.ResponseWriter, r *http.Request, name string) {
	summary, err := s.current(r.Context(), name)
	if err != nil {
		http.Error(w, "the summary can't be built right now", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

func (s *Server) current(ctx context.Context, name string) (Summary, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	now := s.Deps.now()
	if s.cached.Name == name && !now.Before(s.builtAt) && now.Sub(s.builtAt) < SummaryCache {
		return s.cached, nil
	}
	summary, err := Build(ctx, s.Deps, name)
	if err != nil {
		return Summary{}, err
	}
	s.cached, s.builtAt = summary, now
	return summary, nil
}

// view takes an observer's pushed views. They are the key's owner's,
// whatever the body says. A view of a machine this one doesn't watch, or
// of this machine itself, can't count toward anything here, so it is
// dropped and the rest are kept.
func (s *Server) view(w http.ResponseWriter, r *http.Request, c Config, observer string) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxViewBytes))
	var body json.RawMessage
	if err := decoder.Decode(&body); err != nil {
		refuseBody(w, err)
		return
	}
	if err := decoder.Decode(&json.RawMessage{}); err != io.EOF {
		refuseBody(w, err)
		return
	}
	var p Push
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) || json.Unmarshal(body, &p) != nil {
		http.Error(w, "the body must be one JSON object of views", http.StatusBadRequest)
		return
	}
	watched := map[string]bool{}
	for _, peer := range c.Peers {
		watched[peer.Name] = true
	}
	kept := []PushView{}
	for _, v := range p.Views {
		if watched[v.Subject] && v.Subject != c.Self.Name {
			kept = append(kept, v)
		}
	}
	p.Views = kept
	if s.Receive != nil {
		s.Receive(observer, p, s.Deps.now())
	}
	w.WriteHeader(http.StatusNoContent)
}

// refuseBody turns away a body too large or not one JSON object.
func refuseBody(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "too many views at once", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "the body must be one JSON object of views", http.StatusBadRequest)
}
