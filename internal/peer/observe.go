package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Observation is what a machine that only watches found of one server in
// one run: the word each path ended in, and the word its push of what it
// saw ended in, ok when the server took it. It holds names and words,
// never an address.
type Observation struct {
	Name string `json:"name"`
	Paths
	View string `json:"view"`
}

// String is the observation as one line, for example
// web1: summary ok, edge ok, public ok; view sent.
func (o Observation) String() string {
	view := "view sent"
	if o.View != WordOK {
		view = "view not sent (" + o.View + ")"
	}
	return fmt.Sprintf("%s: summary %s, edge %s, public %s; %s", o.Name, o.Summary, o.TLS, o.Public, view)
}

// ObserveOnly is one run of a machine that only watches, such as a Mac,
// which launchd starts every minute. It looks at every server it watches
// over the three paths a server's watch takes, under RoundDeadline, then
// pushes what it saw to each, saying it sends no pages: the servers count
// its views, judge its silence and do the paging. It passed its
// self-check when any server's summary or public URL answered, since it
// has no public URL of its own. It holds no incident and keeps nothing
// from one run to the next. With no server to watch it finds nothing.
func (s *Source) ObserveOnly(ctx context.Context) ([]Observation, error) {
	c, err := Load(s.Secrets)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, s.roundDeadline())
	looks := make([]look, len(c.Peers))
	var g group
	for i, p := range c.Peers {
		g.Go(func() { looks[i] = s.look(rctx, p, c.Token) })
	}
	g.Wait()
	cancel()

	// A machine that only watches never sends a page, so no server ever
	// waits on it to.
	push := Push{Sends: false, Views: make([]PushView, len(c.Peers))}
	observed := make([]Observation, len(c.Peers))
	for i, p := range c.Peers {
		push.Views[i] = PushView{Subject: p.Name, Paths: looks[i].paths}
		push.SelfCheck = push.SelfCheck || reached(looks[i].paths)
		observed[i] = Observation{Name: p.Name, Paths: looks[i].paths}
	}
	body, err := json.Marshal(push)
	if err != nil {
		return nil, err
	}
	for i, p := range c.Peers {
		g.Go(func() {
			observed[i].View = word(attempt(ctx, s.log, func(ctx context.Context) error { return s.pushView(ctx, p.Mesh, c.Token, body) }))
		})
	}
	g.Wait()
	return observed, nil
}

// reached reports whether a look at a server got an answer a machine cut
// off from everything couldn't: from its Helios, or from one of its
// public URLs, whatever the code.
func reached(p Paths) bool {
	return answered(p.Summary) || p.Public == WordOK || strings.HasPrefix(p.Public, "status ")
}

// pushView pushes body, this machine's views, to the server at its mesh
// address, presenting token, the way a summary is asked for.
func (s *Source) pushView(ctx context.Context, mesh, token string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+mesh+ViewPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.ask(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return unexpected(resp, http.StatusNoContent)
}
