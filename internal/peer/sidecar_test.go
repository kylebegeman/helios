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
