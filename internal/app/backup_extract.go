package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/secrets"
)

// BackupExtractKind copies explicitly selected files into a new private directory.
// It never restores application volumes or starts application workloads.
const BackupExtractKind = "app.backup.extract"

const (
	extractMaxFiles       = 16
	extractMaxDepth       = 16
	extractMaxBytes int64 = 8 << 30
	extractTimeout        = 2 * time.Hour
)

var extractComponent = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// BackupExtract uses the same sealed storage integration as backups. The CLI
// requires --socket= so a separately built operator does not call an old daemon.
type BackupExtract struct {
	Secrets  *secrets.Store
	StateDir string
}

// BackupExtractInput contains metadata only. Paths are exact /data file paths,
// not restic patterns. Destination must not exist and its parent must be private.
type BackupExtractInput struct {
	App         string   `json:"app"`
	Snapshot    string   `json:"snapshot"`
	Paths       []string `json:"paths"`
	Destination string   `json:"destination"`
}

type extractFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type extractReceipt struct {
	SchemaVersion int           `json:"schema_version"`
	State         string        `json:"state"`
	App           string        `json:"app"`
	Snapshot      string        `json:"snapshot"`
	Verified      bool          `json:"verified"`
	Files         []extractFile `json:"files"`
}

type extractAttempt struct {
	SchemaVersion int      `json:"schema_version"`
	State         string   `json:"state"`
	Operation     string   `json:"operation"`
	App           string   `json:"app"`
	Snapshot      string   `json:"snapshot"`
	Paths         []string `json:"paths"`
}

func (BackupExtract) Kind() string { return BackupExtractKind }

func (b BackupExtract) Plan(_ context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in BackupExtractInput
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("backup extraction needs valid metadata only")
	}
	if err := validateExtractInput(in); err != nil {
		return nil, err
	}
	if err := b.extractParent(in.Destination); err != nil {
		return nil, err
	}
	// Change, not Note or only raw input, is what the kernel hashes. JSON makes
	// path boundaries unambiguous and keeps every approved input in that digest.
	inputs, _ := json.Marshal(in)
	return &kernel.Plan{Target: in.App, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "extract", Change: "extract verified files into exclusive private staging: " + string(inputs),
		Apply: func(ctx context.Context, out io.Writer) error { return b.extract(ctx, in, out) },
	}}}, nil
}

func validateExtractInput(in BackupExtractInput) error {
	if !manifest.ValidApp(in.App) || !fullSnapshotID.MatchString(in.Snapshot) {
		return errors.New("backup extraction requires an app and its full lowercase 64-hex snapshot ID")
	}
	if len(in.Paths) == 0 || len(in.Paths) > extractMaxFiles {
		return errors.New("backup extraction requires 1 to 16 exact regular-file paths")
	}
	seen := map[string]bool{}
	for _, p := range in.Paths {
		parts := strings.Split(strings.TrimPrefix(p, "/data/"), "/")
		if !strings.HasPrefix(p, "/data/") || len(p) > 512 || len(parts) > extractMaxDepth || path.Clean(p) != p || seen[p] {
			return errors.New("backup extraction paths must be distinct canonical files beneath /data")
		}
		for _, part := range parts {
			if part == "." || part == ".." || !extractComponent.MatchString(part) {
				return errors.New("backup extraction paths cannot contain traversal, patterns or control characters")
			}
		}
		seen[p] = true
	}
	for _, p := range in.Paths {
		for _, other := range in.Paths {
			if strings.HasPrefix(other, p+"/") {
				return errors.New("backup extraction selections cannot overlap")
			}
		}
	}
	if !filepath.IsAbs(in.Destination) || filepath.Clean(in.Destination) != in.Destination || len(in.Destination) > 1024 || strings.ContainsAny(in.Destination, ":\\\x00\r\n\t") {
		return errors.New("backup extraction needs a canonical absolute destination")
	}
	return nil
}

func extractWithin(p, root string) bool {
	relative, err := filepath.Rel(root, p)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// No symlink ancestor is accepted. Every ancestor must be controlled by root or
// this operator, with no group/other writes; the immediate parent is private.
func (b BackupExtract) extractParent(destination string) error {
	parent := filepath.Dir(destination)
	if parent == destination {
		return errors.New("backup extraction destination cannot be a filesystem root")
	}
	for p := parent; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("backup extraction requires existing directories without symlink ancestors")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("backup extraction destination ancestors are not owner controlled")
		}
		if p == parent && (int(st.Uid) != os.Geteuid() || info.Mode().Perm() != 0o700) {
			return errors.New("backup extraction destination parent must be owned by the operator with mode 0700")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	state, err := filepath.Abs(b.StateDir)
	if err != nil {
		return errors.New("backup extraction cannot verify the state location")
	}
	if resolved, err := filepath.EvalSymlinks(state); err == nil {
		state = resolved
	}
	if extractWithin(destination, state) {
		return errors.New("backup extraction destination must be outside Helios state")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("backup extraction destination exists or is ambiguous; inspect privately, never retry into it")
	}
	return nil
}

func (b BackupExtract) extract(ctx context.Context, in BackupExtractInput, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, extractTimeout)
	defer cancel()
	if err := b.extractParent(in.Destination); err != nil {
		return err
	}
	if endpoint := os.Getenv("DOCKER_HOST"); endpoint != "" && !strings.HasPrefix(endpoint, "unix://") {
		return errors.New("backup extraction requires a local Docker Unix socket")
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return errors.New("backup extraction Docker connection failed; inspect privately")
	}
	defer e.Close()
	// A private-looking destination can still be inside a Docker volume. Inspect
	// all named volumes before making the only writable bind mount this uses.
	volumes, err := e.Volumes(ctx, "")
	if err != nil || len(volumes) > 4096 {
		return errors.New("backup extraction cannot verify destination isolation")
	}
	for _, volume := range volumes {
		mountpoint, err := e.VolumeMountpoint(ctx, volume)
		if err != nil || !filepath.IsAbs(mountpoint) {
			return errors.New("backup extraction cannot verify destination isolation")
		}
		mountpoint, err = filepath.EvalSymlinks(mountpoint)
		if err != nil || extractWithin(in.Destination, mountpoint) {
			return errors.New("backup extraction destination overlaps a volume or cannot be verified")
		}
	}
	r, _, err := openRepo(b.Secrets, e, in.App, in.App, nil)
	if err != nil {
		return errors.New("backup extraction storage integration unavailable; inspect privately")
	}
	r.Deadlines.Restore = extractTimeout
	snaps, err := r.Snapshots(ctx, in.App)
	if err != nil {
		return errors.New("backup extraction snapshot lookup failed; inspect privately")
	}
	found, err := resolveRecoverySnapshot(snaps, in.Snapshot)
	if err != nil || found.Hostname != in.App || !slices.Contains(found.Tags, restic.Tag) || !slices.Contains(found.Paths, restic.DataRoot) {
		return errors.New("backup extraction snapshot is missing, ambiguous or belongs to another app")
	}
	// Counting the whole immutable snapshot is conservative for selected files.
	size, err := r.RestoreSize(ctx, in.Snapshot, in.App)
	if err != nil {
		return errors.New("backup extraction size lookup failed; inspect privately")
	}
	if err := checkRestoreSpace([]string{filepath.Dir(in.Destination)}, allocated(size), restoreFreeReserve); err != nil {
		return errors.New("backup extraction has insufficient space or cannot verify the free-space reserve")
	}
	if err := b.extractParent(in.Destination); err != nil {
		return err
	}
	// The exclusive directory itself is a durable ambiguity fence, even if the
	// first receipt write fails. Never remove it or reuse it after any outcome.
	if os.Mkdir(in.Destination, 0o700) != nil {
		return errors.New("backup extraction destination creation refused; inspect privately")
	}
	parent, err := os.Open(filepath.Dir(in.Destination))
	if err != nil {
		return errors.New("backup extraction destination durability is ambiguous; inspect privately, do not retry")
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("backup extraction destination durability is ambiguous; inspect privately, do not retry")
	}
	attempt := extractAttempt{SchemaVersion: 1, State: "incomplete-owner-inspection-required", Operation: kernel.OperationID(ctx), App: in.App, Snapshot: in.Snapshot, Paths: in.Paths}
	if writeExtractReceipt(in.Destination, "incomplete.json", attempt) != nil {
		return errors.New("backup extraction fence could not be persisted; inspect privately, do not retry")
	}
	payload := filepath.Join(in.Destination, "payload")
	if os.Mkdir(payload, 0o700) != nil {
		return errors.New("backup extraction staging unavailable; inspect privately, do not retry")
	}
	if _, err := r.Restore(ctx, in.Snapshot, in.App, []string{restic.DirMount(payload, false)}, in.Paths...); err != nil {
		return errors.New("backup extraction restore or helper cleanup failed; inspect privately, do not retry")
	}
	files, err := verifyExtracted(ctx, payload, in.Paths)
	if err != nil {
		return errors.New("backup extraction file verification failed; inspect privately, do not retry")
	}
	receipt := extractReceipt{SchemaVersion: 1, State: "extracted", App: in.App, Snapshot: in.Snapshot, Verified: true, Files: files}
	if writeExtractReceipt(in.Destination, "extraction.json", receipt) != nil {
		return errors.New("backup extraction completion is ambiguous; inspect privately, do not retry")
	}
	// Retain incomplete.json as the immutable attempt record. Only extraction.json
	// marks completion, and neither permits another extraction into this directory.
	if err := json.NewEncoder(out).Encode(receipt); err != nil {
		return errors.New("backup extraction output unavailable; inspect private extraction.json before any retry")
	}
	return nil
}

func writeExtractReceipt(destination, name string, receipt any) error {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(destination, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(body, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	dir, err := os.Open(destination)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// verifyExtracted walks only the expected topology, one directory entry at a
// time. It bounds file count, depth and bytes, rejects extra entries and every
// nonregular file/link, and hashes bytes rather than trusting restore counters.
func verifyExtracted(ctx context.Context, payload string, selections []string) ([]extractFile, error) {
	want := map[string]bool{".": false} // true means an explicitly selected file
	for _, selected := range selections {
		p := strings.TrimPrefix(selected, "/data/")
		want[p] = true
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			want[d] = false
		}
	}
	beforeRoot, err := os.Lstat(payload)
	if err != nil || !beforeRoot.IsDir() {
		return nil, errors.New("unsafe extraction root")
	}
	root, err := os.OpenRoot(payload)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	openedRoot, err := root.Stat(".")
	if err != nil || !os.SameFile(beforeRoot, openedRoot) {
		return nil, errors.New("extraction root changed")
	}
	remaining, visited := extractMaxBytes, 0
	var files []extractFile
	var walk func(string) error
	walk = func(p string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		fileExpected, ok := want[p]
		if !ok || visited >= len(want) {
			return errors.New("unexpected extracted entry")
		}
		visited++
		before, err := root.Lstat(p)
		if err != nil {
			return err
		}
		if fileExpected && !before.Mode().IsRegular() || !fileExpected && !before.IsDir() {
			return errors.New("unexpected extracted type")
		}
		f, err := root.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !os.SameFile(before, info) {
			return errors.New("extracted entry changed")
		}
		if !fileExpected {
			if f.Chmod(0o700) != nil {
				return errors.New("cannot protect extracted directory")
			}
			for {
				entries, err := f.ReadDir(1)
				for _, entry := range entries {
					if err := walk(path.Join(p, entry.Name())); err != nil {
						return err
					}
				}
				if err == io.EOF {
					return f.Sync()
				}
				if err != nil {
					return err
				}
			}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Nlink != 1 || info.Size() < 0 || info.Size() > remaining {
			return errors.New("unsafe extracted file or size limit exceeded")
		}
		if f.Chmod(0o600) != nil {
			return errors.New("cannot protect extracted file")
		}
		hashed := sha256.New()
		buffer := make([]byte, 1<<20)
		var count int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := f.Read(buffer)
			count += int64(n)
			if count > info.Size() {
				return errors.New("extracted file grew")
			}
			hashed.Write(buffer[:n])
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		after, err := f.Stat()
		if err != nil || count != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || after.Sys().(*syscall.Stat_t).Nlink != 1 {
			return errors.New("extracted file changed")
		}
		if err := f.Sync(); err != nil {
			return err
		}
		remaining -= count
		files = append(files, extractFile{Path: "/data/" + p, Size: count, SHA256: hex.EncodeToString(hashed.Sum(nil))})
		return nil
	}
	if err := walk("."); err != nil {
		return nil, err
	}
	if visited != len(want) || len(files) != len(selections) {
		return nil, errors.New("selected files are missing")
	}
	slices.SortFunc(files, func(a, b extractFile) int { return strings.Compare(a.Path, b.Path) })
	return files, nil
}
