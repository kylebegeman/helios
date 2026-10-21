package peer

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/watch"
)

// What peer watch remembers survives a restart, in a file of its own that
// names peers and holds no address or key: a recovery still goes from
// whoever told the open, and a peer seen before the restart is never read
// as one that has never answered. The file keeps a week of records, the
// newest SidecarKeepTold of them, and one that can't be read is started
// afresh.
func TestSidecarSurvivesRestartAndPrunes(t *testing.T) {
	p := paging(t)
	p.down("web3")
	p.rounds(t, watch.DefaultOpenAfter)
	p.restart(t)
	p.up("web3")
	p.down("web1")
	p.rounds(t, watch.DefaultResolveAfter)
	if got := p.told("peer:web3"); !slices.Equal(got, []string{watch.TransitionOpen, watch.TransitionResolved}) {
		t.Fatalf("after a restart web2 sent %v", got)
	}
	if c := p.observe(t)["peer:web1"]; c.Key == "" || strings.Contains(c.Message, "never answered") {
		t.Fatalf("web1 answered before the restart: %+v", c)
	}
	if err := p.src.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sidecarPath(p.store))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar mode: %v, %v", info, err)
	}
	data, _ := os.ReadFile(sidecarPath(p.store))
	if bytes.Contains(data, []byte(in("100.64.0.0/10").String())) || bytes.Contains(data, []byte(p.token)) || !bytes.Contains(data, []byte(`"web3"`)) {
		t.Fatalf("the sidecar must name peers and hold no address or key:\n%s", data)
	}

	// A week of records, and only the newest of them.
	store := stateStore(t)
	saved := func(sc Sidecar) Sidecar {
		t.Helper()
		if err := writeSidecar(store, sc); err != nil {
			t.Fatal(err)
		}
		if err := (&Source{Store: store, Now: func() time.Time { return now }}).Save(); err != nil {
			t.Fatal(err)
		}
		kept, err := ReadSidecar(store)
		if err != nil {
			t.Fatal(err)
		}
		return kept
	}
	week := now.Add(-SidecarKeep)
	kept := saved(Sidecar{Self: "web2",
		Told: []Told{
			{IncidentID: 1, Key: "peer:web3", By: "web1", At: week.Add(-time.Minute)},
			{IncidentID: 2, Key: "peer:web3", By: "web1", At: week.Add(time.Minute)},
		},
		Deferring: []Deferral{
			{IncidentID: 1, Key: "peer:web3", To: "web1", Since: week.Add(-time.Minute)},
			{IncidentID: 2, Key: "peer:web3", To: "web1", Since: week.Add(time.Minute)},
		}})
	if len(kept.Told) != 1 || kept.Told[0].IncidentID != 2 || len(kept.Deferring) != 1 || kept.Deferring[0].IncidentID != 2 {
		t.Fatalf("kept past a week: %+v, %+v", kept.Told, kept.Deferring)
	}
	var many Sidecar
	for i := range SidecarKeepTold + 100 {
		many.Told = append(many.Told, Told{IncidentID: int64(10 + i), Key: "peer:web3", By: "web2", At: now.Add(-time.Duration(i) * time.Minute)})
	}
	kept = saved(many)
	oldest := now.Add(-time.Duration(SidecarKeepTold-1) * time.Minute)
	if len(kept.Told) != SidecarKeepTold || !kept.Told[0].At.Equal(oldest) {
		t.Fatalf("kept %d told records from %v", len(kept.Told), kept.Told[0].At)
	}

	// A sidecar that can't be read is started afresh.
	if err := os.WriteFile(sidecarPath(store), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logged []string
	fresh := &Source{Store: store, Now: func() time.Time { return now }, Log: func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}}
	if err := fresh.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSidecar(store); err != nil || !slices.Equal(logged, []string{"peer state: unreadable, starting fresh"}) {
		t.Fatalf("logged %q, then %v", logged, err)
	}
}

// The recovery of a page this machine sent goes out when the record that
// it sent it is lost: the sidecar unreadable, deleted, or not yet saved
// when the daemon stopped. Every observer that stood down leaves that
// recovery to this machine, so nobody else sends it, and the alert would
// ring on. The loss is logged once, however many tries the recovery
// takes.
func TestALostRecordOfAPageSentHereLeavesItsRecoveryHere(t *testing.T) {
	for _, loss := range []struct {
		name string
		lose func(t *testing.T, p *pager)
	}{
		{"unreadable", func(t *testing.T, p *pager) {
			p.restart(t)
			if err := os.WriteFile(sidecarPath(p.store), []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted", func(t *testing.T, p *pager) {
			p.restart(t)
			if err := os.Remove(sidecarPath(p.store)); err != nil {
				t.Fatal(err)
			}
		}},
		{"not yet saved", func(t *testing.T, p *pager) { p.crash() }},
	} {
		t.Run(loss.name, func(t *testing.T) {
			p := paging(t)
			pushover, email := p.legs()
			p.down("web3")
			p.rounds(t, watch.DefaultOpenAfter-1)
			if err := p.src.Save(); err != nil {
				t.Fatal(err)
			}
			p.rounds(t, 1)
			loss.lose(t, p)
			logged := p.logging()
			p.up("web3")
			pushover.failing, email.failing = true, true
			p.rounds(t, watch.DefaultResolveAfter)
			pushover.failing, email.failing = false, false
			p.rounds(t, handoff)
			want := []string{watch.TransitionOpen, watch.TransitionResolved}
			if got, pending := transitions(pushover.got), p.pending(t); !slices.Equal(got, want) || !slices.Equal(transitions(email.got), want) || pending != nil {
				t.Fatalf("sent %v and %v, pending %v", got, transitions(email.got), pending)
			}
			lost := "peer state: no record of who told peer:web3; its recovery goes from here"
			if n := strings.Count(strings.Join(*logged, "\n"), lost); n != 1 {
				t.Fatalf("logged the loss %d times:\n%s", n, strings.Join(*logged, "\n"))
			}
		})
	}
}
