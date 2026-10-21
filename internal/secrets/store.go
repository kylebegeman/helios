// Package secrets keeps each app's secrets sealed on the machine. Values are
// encrypted to a key the machine holds; every change makes a new version,
// so a revision can be rolled back with the secrets it was started with.
// Values never appear in arguments, logs, receipts or backups.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
)

// DefaultKeyPath is where a machine keeps its secrets key.
const DefaultKeyPath = "/etc/bedrock/secrets.key"

// Store is the sealed store for one machine.
type Store struct {
	// Dir holds one directory per app.
	Dir string
	// KeyPath is the machine's identity. KeyPath+".pub" is its recipient.
	KeyPath string
}

var namePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// reservedApp is the app whose secrets are helios's own, the integration
// credentials: manifest.ReservedApp, spelled here because this package
// sits beneath manifest. They are never transferred, copied or removed as
// an app's are.
const reservedApp = "bedrock"

// appPattern is what a manifest accepts as an app's name.
var appPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// ValidName reports whether name is an UPPER_CASE secret name.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// EnsureKey makes sure the machine has a key. When it creates one, it
// returns the identity once: the person keeps it somewhere safe, because
// it is the only way to read this store's backups on another machine.
func (s *Store) EnsureKey() (recipient string, created bool, identity string, err error) {
	if err := os.MkdirAll(filepath.Dir(s.KeyPath), 0o700); err != nil {
		return "", false, "", err
	}
	lock, err := os.OpenFile(s.KeyPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", false, "", err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", false, "", err
	}

	if data, err := os.ReadFile(s.KeyPath); err == nil {
		id, err := parseIdentity(string(data))
		if err != nil {
			return "", false, "", fmt.Errorf("%s: %w", s.KeyPath, err)
		}
		return id.Recipient().String(), false, "", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, "", err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", false, "", err
	}
	if err := os.MkdirAll(filepath.Dir(s.KeyPath), 0o700); err != nil {
		return "", false, "", err
	}
	if err := os.WriteFile(s.KeyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		return "", false, "", err
	}
	if err := os.WriteFile(s.KeyPath+".pub", []byte(id.Recipient().String()+"\n"), 0o644); err != nil {
		return "", false, "", err
	}
	return id.Recipient().String(), true, id.String(), nil
}

func parseIdentity(text string) (*age.X25519Identity, error) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return age.ParseX25519Identity(line)
		}
	}
	return nil, errors.New("no identity in the key file")
}

func (s *Store) identity() (*age.X25519Identity, error) {
	data, err := os.ReadFile(s.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("this machine has no secrets key yet: %w", err)
	}
	return parseIdentity(string(data))
}

// bundle is what one version holds.
type bundle struct {
	Version int               `json:"version"`
	At      time.Time         `json:"at"`
	Values  map[string]string `json:"values"`
}

// VersionInfo describes a version without its values.
type VersionInfo struct {
	Version int       `json:"version"`
	At      time.Time `json:"at"`
	Names   []string  `json:"names"`
}

func (s *Store) appDir(app string) string { return filepath.Join(s.Dir, app) }

// Current returns the app's current version, 0 when it has none.
func (s *Store) Current(app string) (int, error) {
	if !appPattern.MatchString(app) {
		return 0, errors.New("invalid secrets app name")
	}
	data, err := os.ReadFile(filepath.Join(s.appDir(app), "current"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	version, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || version <= 0 {
		return 0, errors.New("invalid current secrets version")
	}
	return version, nil
}

// Load decrypts one version's values. Version 0 is empty.
func (s *Store) Load(app string, version int) (map[string]string, error) {
	if !appPattern.MatchString(app) || version < 0 {
		return nil, errors.New("invalid secrets app name or version")
	}
	if version == 0 {
		return map[string]string{}, nil
	}
	id, err := s.identity()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(s.appDir(app), fmt.Sprintf("v%d.age", version)))
	if err != nil {
		return nil, fmt.Errorf("secrets version %d of %s: %w", version, app, err)
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		return nil, fmt.Errorf("secrets version %d of %s: %w", version, app, err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, errors.New("invalid sealed secret version")
	}
	if b.Version != version {
		return nil, errors.New("sealed secret version does not match the requested version")
	}
	if b.Values == nil {
		b.Values = map[string]string{}
	}
	return b.Values, nil
}

// LoadCurrent decrypts the current version.
func (s *Store) LoadCurrent(app string) (map[string]string, int, error) {
	v, err := s.Current(app)
	if err != nil {
		return nil, 0, err
	}
	values, err := s.Load(app, v)
	return values, v, err
}

// Set records a value and returns the new version.
func (s *Store) Set(app, name, value string) (int, error) {
	unlock, err := s.lock(app)
	if err != nil {
		return 0, err
	}
	defer unlock()
	if !ValidName(name) {
		return 0, fmt.Errorf("%q must be an UPPER_CASE name", name)
	}
	values, _, err := s.LoadCurrent(app)
	if err != nil {
		return 0, err
	}
	values[name] = value
	return s.write(app, values)
}

// SetAll records several values in one new version. A nil value in the
// map removes the name. Names outside the map are kept.
func (s *Store) SetAll(app string, changes map[string]*string) (int, error) {
	return s.Update(app, func(map[string]string) (map[string]*string, error) { return changes, nil })
}

// Update records the changes change makes from the current values in one
// new version, as SetAll does. The app's secrets are held from the read
// to the write, so a change made meanwhile is never lost. When change
// fails, nothing is written. With no changes, the current version is kept.
func (s *Store) Update(app string, change func(current map[string]string) (map[string]*string, error)) (int, error) {
	unlock, err := s.lock(app)
	if err != nil {
		return 0, err
	}
	defer unlock()
	values, version, err := s.LoadCurrent(app)
	if err != nil {
		return 0, err
	}
	changes, err := change(maps.Clone(values))
	if err != nil {
		return 0, err
	}
	if len(changes) == 0 {
		return version, nil
	}
	for name, value := range changes {
		if !ValidName(name) {
			return 0, fmt.Errorf("%q must be an UPPER_CASE name", name)
		}
		if value == nil {
			delete(values, name)
			continue
		}
		values[name] = *value
	}
	return s.write(app, values)
}

// Remove drops a name and returns the new version.
func (s *Store) Remove(app, name string) (int, error) {
	unlock, err := s.lock(app)
	if err != nil {
		return 0, err
	}
	defer unlock()
	values, _, err := s.LoadCurrent(app)
	if err != nil {
		return 0, err
	}
	if _, ok := values[name]; !ok {
		return 0, fmt.Errorf("%s has no secret named %s", app, name)
	}
	delete(values, name)
	return s.write(app, values)
}

// write seals a new version and points current at it.
func (s *Store) write(app string, values map[string]string) (int, error) {
	id, err := s.identity()
	if err != nil {
		return 0, err
	}
	current, err := s.Current(app)
	if err != nil {
		return 0, err
	}
	next := current + 1
	dir := s.appDir(app)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	b := bundle{Version: next, At: time.Now().UTC(), Values: values}
	plain, err := json.Marshal(b)
	if err != nil {
		return 0, err
	}
	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, id.Recipient())
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(plain); err != nil {
		return 0, err
	}
	if err := w.Close(); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("v%d.age", next)), sealed.Bytes(), 0o600); err != nil {
		return 0, err
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	meta, _ := json.Marshal(VersionInfo{Version: next, At: b.At, Names: names})
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("v%d.meta", next)), append(meta, '\n'), 0o600); err != nil {
		return 0, err
	}
	tmp := filepath.Join(dir, "current.tmp")
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(next)+"\n"), 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "current")); err != nil {
		return 0, err
	}
	return next, nil
}

// Locks live beside the store so removing an app never unlinks a lock that a
// waiting writer already opened. Keeping them outside Dir also leaves machine
// backup and recovery inputs as app directories only.
//
// Older builds use Dir/app/.lock and cannot coordinate with this layout. When
// upgrading or rolling back across layouts, drain CLI writers before switching
// binaries and pause writes until the old daemon has stopped and its replacement
// is ready. Restarting the daemon alone does not drain older CLI processes.
func (s *Store) lockPath(app string) string {
	return filepath.Join(filepath.Clean(s.Dir)+".locks", app+".lock")
}

// lock holds an app's secrets for one change, across processes: the CLI
// and the daemon can both set secrets, and each change reads the current
// version before writing the next.
func (s *Store) lock(app string) (func(), error) {
	if !appPattern.MatchString(app) {
		return nil, errors.New("invalid secrets app name")
	}
	path := s.lockPath(app)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// RemoveApp forgets every version of an app's secrets. It is for an app
// that is leaving the machine for good; helios's own never go this way.
func (s *Store) RemoveApp(app string) error {
	if !appPattern.MatchString(app) || app == reservedApp {
		return fmt.Errorf("%q isn't an app whose secrets can be removed", app)
	}
	unlock, err := s.lock(app)
	if err != nil {
		return err
	}
	defer unlock()
	return os.RemoveAll(s.appDir(app))
}

// Apps lists the apps that hold secrets here, helios's own left out:
// the ones deployed, and any an app left behind when it was removed.
func (s *Store) Apps() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && appPattern.MatchString(e.Name()) && e.Name() != reservedApp {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// Versions lists an app's versions, newest first, without values.
func (s *Store) Versions(app string) ([]VersionInfo, error) {
	if !appPattern.MatchString(app) {
		return nil, errors.New("invalid secrets app name")
	}
	entries, err := os.ReadDir(s.appDir(app))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []VersionInfo
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.appDir(app), e.Name()))
		if err != nil {
			return nil, err
		}
		var v VersionInfo
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

// Names lists the current version's names.
func (s *Store) Names(app string) ([]string, int, error) {
	version, err := s.Current(app)
	if err != nil || version == 0 {
		return nil, 0, err
	}
	data, err := os.ReadFile(filepath.Join(s.appDir(app), fmt.Sprintf("v%d.meta", version)))
	if err != nil {
		return nil, 0, err
	}
	var info VersionInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, 0, err
	}
	if info.Version != version {
		return nil, 0, errors.New("secrets metadata does not match the current version")
	}
	return info.Names, version, nil
}

// Missing returns the names a workload asks for that a version lacks.
func Missing(values map[string]string, wanted []string) []string {
	var missing []string
	for _, n := range wanted {
		if _, ok := values[n]; !ok {
			missing = append(missing, n)
		}
	}
	return missing
}

// DefaultStore is the store for a machine whose state lives in stateDir:
// the key under /etc/bedrock for root on Linux, beside the state elsewhere.
func DefaultStore(stateDir string) *Store {
	keyPath := filepath.Join(stateDir, "secrets.key")
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		keyPath = DefaultKeyPath
	}
	return &Store{Dir: filepath.Join(stateDir, "secrets"), KeyPath: keyPath}
}
