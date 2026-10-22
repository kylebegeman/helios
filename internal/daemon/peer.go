package daemon

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/kylebegeman/helios/internal/peer"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/watch"
)

// newWatcher is the daemon's one watcher. Every notice it sends passes
// the peer gate, which sends each notice about a peer from one machine
// and passes the rest straight to the daemon's fan-out.
func (d *daemon) newWatcher() *watch.Watcher {
	return &watch.Watcher{Store: d.store, Notifier: &peer.Gate{Next: d.alerts, Source: d.peers}, Hostname: d.machine, Log: d.logf}
}

// watchRound runs one round of the watch. observePeers looks at the
// peers, with its own recover, while observe looks at this machine, and
// what both found goes into the one round: a second watcher over the same
// store would resolve every incident the other opened. A look at the
// peers that panics holds their open incidents as they are, so none
// recovers on a look never taken. A round that finished is recorded for
// this machine's summary, and what peer watch must remember is saved
// after every round.
func (d *daemon) watchRound(ctx context.Context, watcher *watch.Watcher, observe, observePeers func(context.Context) []watch.Condition) {
	looked := make(chan []watch.Condition, 1)
	// A panic in the local observation still has to join its peer probe:
	// the daemon waits for this round before it closes the shared store.
	var probes sync.WaitGroup
	probes.Add(1)
	defer probes.Wait()
	go func() {
		defer probes.Done()
		var conditions []watch.Condition
		ok := false
		guarded(d.logf, "peer watch", func() { conditions, ok = observePeers(ctx), true })
		if !ok {
			guarded(d.logf, "peer watch", func() { conditions = d.peers.Held(ctx) })
		}
		looked <- conditions
	}()
	conditions := observe(ctx)
	conditions = append(conditions, <-looked...)
	if err := watcher.Round(ctx, conditions); err != nil {
		if ctx.Err() == nil {
			d.logf("watch: %v", err)
		}
	} else {
		d.peers.RoundDone(watcher.Now())
	}
	if err := d.peers.Save(); err != nil {
		d.logf("peer state: %v", err)
	}
}

// peerListener keeps the peer listener where peer watch is set up to
// listen: listening once an address is set, moved when it changes, and
// closed when it is removed. A configuration that can't be read leaves
// the listener as it is. What goes wrong is logged once until something
// changes, and nothing it logs names the address.
type peerListener struct {
	Secrets *secrets.Store
	Server  *peer.Server
	Log     func(format string, args ...any)

	// at is where the listener listens; not valid when it doesn't.
	at netip.AddrPort
	// said is the last trouble logged, so it is logged once.
	said string
}

// newPeerListener is the daemon's peer listener, answering with this
// machine's summary and handing what observers push to its peer watch.
func (d *daemon) newPeerListener() *peerListener {
	server := &peer.Server{Deps: peer.Deps{Store: d.store, Secrets: d.sec, Last: d.peers.Last}, Receive: d.peers.Receive}
	return &peerListener{Secrets: d.sec, Server: server, Log: d.logf}
}

// Tick reads peer watch's configuration and follows it. A listener that
// can't start, as before the mesh is up, is tried again next tick.
func (l *peerListener) Tick(ctx context.Context) {
	want, err := l.wanted()
	if err != nil {
		l.once("peer listener: peer watch can't be read, so the listener stays as it is: " + err.Error())
		return
	}
	if want == l.at {
		l.said = ""
		return
	}
	if l.at.IsValid() {
		l.Server.Stop()
		l.at = netip.AddrPort{}
		if !want.IsValid() {
			l.Log("peer listener: closed, as peer watch no longer listens here")
			return
		}
	}
	if err := l.Server.Start(ctx, want); err != nil {
		if errors.Is(err, peer.ErrAddressNotUp) {
			l.once("peer listener: waiting for the mesh address")
		} else {
			l.once("peer listener: " + err.Error())
		}
		return
	}
	l.at, l.said = want, ""
	l.Log("peer listener: listening for peers")
}

// wanted is where peer watch is set up to listen; not valid when it
// listens nowhere.
func (l *peerListener) wanted() (netip.AddrPort, error) {
	c, err := peer.Load(l.Secrets)
	switch {
	case errors.Is(err, peer.ErrNotSet):
		return netip.AddrPort{}, nil
	case err != nil:
		return netip.AddrPort{}, err
	case c.Self.Listen == "":
		return netip.AddrPort{}, nil
	}
	return peer.ParseListen(c.Self.Listen)
}

// once logs line unless it was the last trouble logged.
func (l *peerListener) once(line string) {
	if line != l.said {
		l.said = line
		l.Log("%s", line)
	}
}

// Close closes the listener, giving the requests it is answering a while
// to finish.
func (l *peerListener) Close() {
	l.Server.Stop()
	l.at = netip.AddrPort{}
}

// servePeers keeps l following peer watch's configuration every
// peer.ListenerTick, from right away until ctx ends, and then closes it.
// It is one of the daemon's loops, so Run waits for the listener to close
// before it closes the store a summary reads, and the close after the
// last tick means no tick can start the listener again.
func (d *daemon) servePeers(ctx context.Context, l *peerListener) {
	d.loops.Add(1)
	go func() {
		defer d.loops.Done()
		defer l.Close()
		every(ctx, peer.ListenerTick, true, func(time.Time) {
			guarded(d.logf, "peer listener", func() { l.Tick(ctx) })
		})
	}()
}
