package incident

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// Names of an incident's files in its directory.
const (
	EvidenceFile = "evidence.json"
	// LoomFile marks the incident's one send to Loom.
	LoomFile = "loom.json"
)

// ErrStale means an incident's directory holds evidence of an earlier
// incident with the same ID, from before the state was replaced.
var ErrStale = errors.New("the evidence belongs to an earlier incident with the same id")

// LoomMarkerSchema is the version of the Loom marker's shape.
const LoomMarkerSchema = 1

// Where an incident's send to Loom stands.
const (
	// LoomSending is set before the request goes. A marker left sending
	// by a crash is never sent again.
	LoomSending = "sending"
	// LoomDelivered means the relay or Loom took it.
	LoomDelivered = "delivered"
	// LoomRefused means it was turned away, and won't be taken however
	// often it is sent.
	LoomRefused = "refused"
	// LoomAmbiguous means it was written but no clear answer came back,
	// so Loom may have it.
	LoomAmbiguous = "ambiguous"
)

// LoomMarker records an incident's send to Loom. It is created before
// the request goes, so an incident that might have arrived is never sent
// again; a request that never left removes it.
type LoomMarker struct {
	Schema   int       `json:"schema"`
	EventID  string    `json:"event_id"`
	OpenedAt time.Time `json:"opened_at"`
	State    string    `json:"state"`
	// Status is the HTTP status of the answer, or zero for none.
	Status     int       `json:"status"`
	DeliveryID string    `json:"delivery_id"`
	At         time.Time `json:"at"`
	Error      string    `json:"error"`
}

// Dir is where an incident's files are kept, beside the state.
func Dir(stateDir string, id int64) string {
	return filepath.Join(stateDir, "incidents", strconv.FormatInt(id, 10))
}

// LoadLoomMarker reads incident id's Loom marker. It returns an error
// satisfying errors.Is(err, fs.ErrNotExist) when there is none.
func LoadLoomMarker(stateDir string, id int64) (*LoomMarker, error) {
	data, err := os.ReadFile(filepath.Join(Dir(stateDir, id), LoomFile))
	if err != nil {
		return nil, err
	}
	var m LoomMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s can't be read: %w", LoomFile, err)
	}
	return &m, nil
}

// LoomMarkerOf reads inc's Loom marker. It returns nil and no error when
// there is none, or when the one there is an earlier incident's.
func LoomMarkerOf(stateDir string, inc state.Incident) (*LoomMarker, error) {
	m, err := LoadLoomMarker(stateDir, inc.ID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !m.OpenedAt.Equal(inc.OpenedAt) {
		return nil, nil
	}
	return m, nil
}

// Outcome says in a few words where the send stands, with the status
// Loom or the relay answered.
func (m *LoomMarker) Outcome() string {
	status := ""
	if m.Status != 0 {
		status = " " + strconv.Itoa(m.Status)
	}
	switch m.State {
	case LoomRefused:
		return "refused" + status
	case LoomAmbiguous:
		return "ambiguous" + status + ", not resent"
	case LoomSending:
		return "sending since " + m.At.UTC().Format(time.DateTime) + " UTC, not resent"
	}
	return m.State
}

// Save writes e to its incident's evidence.json, replacing what was
// there only once the new file is on disk. Evidence over FileMax is
// refused; Collect fits it first.
func Save(stateDir string, e *Evidence) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > FileMax {
		return fmt.Errorf("the evidence is %d bytes, over %d KiB", len(data), FileMax>>10)
	}
	dir := Dir(stateDir, e.Incident.ID)
	if err := ensureDir(dir); err != nil {
		return err
	}
	return WriteFile(filepath.Join(dir, EvidenceFile), data)
}

// Load reads inc's evidence. It returns an error satisfying
// errors.Is(err, fs.ErrNotExist) when none was saved, and ErrStale when
// what was saved is another incident's.
func Load(stateDir string, inc state.Incident) (*Evidence, error) {
	f, err := os.Open(filepath.Join(Dir(stateDir, inc.ID), EvidenceFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, FileMax+1))
	if err != nil {
		return nil, err
	}
	if len(data) > FileMax {
		return nil, fmt.Errorf("%s is over %d KiB", EvidenceFile, FileMax>>10)
	}
	var e Evidence
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("%s can't be read: %w", EvidenceFile, err)
	}
	if e.Schema != Schema {
		return nil, fmt.Errorf("%s has schema %d; this helios reads %d", EvidenceFile, e.Schema, Schema)
	}
	if e.Incident.ID != inc.ID || !e.Incident.OpenedAt.Equal(inc.OpenedAt) {
		return nil, ErrStale
	}
	return &e, nil
}

// WriteFile replaces path with data, readable only by its owner, and
// only once data is on disk, so a crash leaves the old file or the new,
// never a torn one.
func WriteFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// CreateExclusive writes data to path, readable only by its owner, when
// nothing is there yet, and returns an error satisfying
// errors.Is(err, fs.ErrExist) when something is. The file and its entry
// are on disk before it returns. A file whose write fails is left
// behind, so a caller that takes the file as a claim still holds it.
func CreateExclusive(path string, data []byte) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Remove deletes those of paths that exist, in order, and syncs their
// directories, so the files stay gone after a crash.
func Remove(paths ...string) error {
	dirs := map[string]bool{}
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return err
		}
		dirs[filepath.Dir(path)] = true
	}
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// ensureDir makes dir and any parents it lacks, readable only by their
// owner, and syncs each new one's parent so the entries outlive a crash.
func ensureDir(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := ensureDir(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return syncDir(parent)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
