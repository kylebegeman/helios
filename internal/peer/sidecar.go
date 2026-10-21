package peer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// SidecarFile is the file beside the state database that keeps what peer
// watch remembers across a restart: when each peer last answered and each
// Mac last sent a view, who told each peer incident, and which notices
// this machine holds while another is to send them. Keeping it out of the
// database keeps peer watch free of a migration.
const SidecarFile = "peer-state.json"

// How much the sidecar keeps.
const (
	// SidecarKeep is how long a told record or a deferral is kept.
	SidecarKeep = 7 * 24 * time.Hour
	// SidecarKeepTold is how many told records are kept, the newest.
	SidecarKeepTold = 500
)

// Sidecar is what the sidecar file holds. It names peers, never an
// address.
type Sidecar struct {
	// Self is the name of the machine that wrote it.
	Self string `json:"self"`
	// LastGood is when each peer's summary last came back ok, and
	// LastView when each Mac's last view arrived, by name.
	LastGood  map[string]time.Time `json:"last_good"`
	LastView  map[string]time.Time `json:"last_view"`
	Told      []Told               `json:"told"`
	Deferring []Deferral           `json:"deferring"`
}

// Told is a notice about one of this machine's peer incidents that went
// out, and who sent it: this machine, or another observer whose summary
// showed it told. At is when it went out, by this machine's clock.
type Told struct {
	IncidentID int64     `json:"incident_id"`
	Key        string    `json:"key"`
	Transition string    `json:"transition"`
	Severity   string    `json:"severity"`
	By         string    `json:"by"`
	At         time.Time `json:"at"`
}

// Deferral is a notice about one of this machine's peer incidents that it
// holds while another observer, To, is to send it, and since when.
type Deferral struct {
	IncidentID int64     `json:"incident_id"`
	Key        string    `json:"key"`
	Transition string    `json:"transition"`
	To         string    `json:"to"`
	Since      time.Time `json:"since"`
}

// ReadSidecar reads the sidecar beside store's database. Where there is
// none yet, it is empty.
func ReadSidecar(store *state.Store) (Sidecar, error) {
	data, err := os.ReadFile(sidecarPath(store))
	if errors.Is(err, os.ErrNotExist) {
		return Sidecar{}, nil
	}
	if err != nil {
		return Sidecar{}, err
	}
	var sc Sidecar
	if err := json.Unmarshal(data, &sc); err != nil {
		return Sidecar{}, fmt.Errorf("read %s: %w", SidecarFile, err)
	}
	return sc, nil
}

// SentBy is the observer that sent the latest notice about the incident,
// and when, where another observer sent it; ok is false where this
// machine sent it or nobody has.
func (sc Sidecar) SentBy(inc state.Incident) (by string, at time.Time, ok bool) {
	for _, t := range sc.Told {
		if t.IncidentID == inc.ID && t.Key == inc.Key && !t.At.Before(at) {
			by, at = t.By, t.At
		}
	}
	if by == "" || by == sc.Self {
		return "", time.Time{}, false
	}
	return by, at, true
}

// WaitingOn is the observer this machine holds the incident's latest
// notice for, where it holds it because another is to send it, and since
// when; since is zero where the sidecar doesn't have the hold yet.
func (sc Sidecar) WaitingOn(inc state.Incident) (to string, since time.Time, ok bool) {
	if !gated(inc.Key) {
		return "", time.Time{}, false
	}
	if to, ok = deferredTo(inc.NotifyError); !ok {
		return "", time.Time{}, false
	}
	for _, d := range sc.Deferring {
		if d.IncidentID == inc.ID && d.Key == inc.Key {
			since = d.Since
		}
	}
	return to, since, true
}

// prune drops the told records and deferrals older than SidecarKeep as of
// now, and every told record past the newest SidecarKeepTold.
func (sc *Sidecar) prune(now time.Time) {
	cutoff := now.Add(-SidecarKeep)
	told := sc.Told[:0]
	for _, t := range sc.Told {
		if t.At.After(cutoff) {
			told = append(told, t)
		}
	}
	sort.SliceStable(told, func(i, j int) bool { return told[i].At.Before(told[j].At) })
	sc.Told = told[max(len(told)-SidecarKeepTold, 0):]
	deferring := sc.Deferring[:0]
	for _, d := range sc.Deferring {
		if d.Since.After(cutoff) {
			deferring = append(deferring, d)
		}
	}
	sc.Deferring = deferring
}

// nothingToKeep reports whether sc keeps nothing and there is no sidecar
// beside store's database to replace, as on a machine that has never set
// up peer watch.
func nothingToKeep(store *state.Store, sc Sidecar) bool {
	if sc.Self != "" || len(sc.LastGood) > 0 || len(sc.LastView) > 0 || len(sc.Told) > 0 || len(sc.Deferring) > 0 {
		return false
	}
	_, err := os.Stat(sidecarPath(store))
	return errors.Is(err, os.ErrNotExist)
}

// writeSidecar replaces the sidecar beside store's database at once, so
// a crash leaves the old one or the new one, never part of either.
func writeSidecar(store *state.Store, sc Sidecar) error {
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	path := sidecarPath(store)
	f, err := os.CreateTemp(filepath.Dir(path), ".peer-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func sidecarPath(store *state.Store) string {
	return filepath.Join(filepath.Dir(store.Path()), SidecarFile)
}
