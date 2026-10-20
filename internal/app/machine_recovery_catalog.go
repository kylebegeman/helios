package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

const machineRecoveryFormat = 1
const machineCatalogFile = "recovery.json"
const machineImagesFile = "images.tar"
const machineProfileFile = "profile.json"
const machineAppDataDir = "app-data"

// machineRecoveryCatalog binds workloads and their data recovery points to
// one machine snapshot. Recovery never follows "latest" after this point.
type machineRecoveryCatalog struct {
	Format       int                            `json:"format"`
	Hostname     string                         `json:"hostname"`
	Version      string                         `json:"bedrock"`
	OS           string                         `json:"os"`
	Arch         string                         `json:"arch"`
	TakenAt      time.Time                      `json:"taken_at"`
	Recipient    string                         `json:"recipient"`
	Revisions    []state.Revision               `json:"revisions"`
	AppSnapshots map[string]string              `json:"app_snapshots"`
	AppData      map[string]appBackupProvenance `json:"app_data_provenance"`
	Images       []string                       `json:"images"`
	Profile      bool                           `json:"profile"`
	EmbeddedData bool                           `json:"embedded_data"`
}

var fullSnapshotID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var snapshotPrefix = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

func resolveRecoverySnapshot(snaps []restic.Snapshot, asked string) (*restic.Snapshot, error) {
	if !snapshotPrefix.MatchString(asked) {
		return nil, errors.New("recovery needs an explicit snapshot ID of at least eight hexadecimal characters")
	}
	var found *restic.Snapshot
	for i := range snaps {
		if strings.HasPrefix(snaps[i].ID, asked) {
			if found != nil {
				return nil, fmt.Errorf("snapshot prefix %s is ambiguous; provide its full ID", asked)
			}
			found = &snaps[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("snapshot %s was not found", asked)
	}
	if !fullSnapshotID.MatchString(found.ID) {
		return nil, errors.New("the repository returned an invalid snapshot ID")
	}
	return found, nil
}

func checkMachineRecoveryCompatibility(c machineRecoveryCatalog, target version.Info) error {
	if c.Format != machineRecoveryFormat {
		return fmt.Errorf("machine recovery format %d is unsupported by this build (supports %d)", c.Format, machineRecoveryFormat)
	}
	if c.OS != target.OS || c.Arch != target.Arch {
		return fmt.Errorf("this machine snapshot contains %s/%s images; the target is %s/%s", c.OS, c.Arch, target.OS, target.Arch)
	}
	parse := func(v string) ([3]int, bool) {
		var n [3]int
		parts := strings.Split(strings.SplitN(strings.TrimPrefix(v, "v"), "-", 2)[0], ".")
		if len(parts) != 3 {
			return n, false
		}
		for i := range n {
			v, err := strconv.Atoi(parts[i])
			if err != nil || v < 0 {
				return n, false
			}
			n[i] = v
		}
		return n, true
	}
	source, ok := parse(c.Version)
	current, valid := parse(target.Version)
	if !ok || !valid {
		return errors.New("the machine snapshot or running build has an unknown version; recovery compatibility cannot be checked")
	}
	if source[0] != current[0] {
		return fmt.Errorf("machine snapshot version %s is incompatible with %s", c.Version, target.Version)
	}
	for i := range source {
		if source[i] > current[i] {
			return fmt.Errorf("machine snapshot was made by newer helios %s; upgrade the target before recovery", c.Version)
		}
		if source[i] < current[i] {
			break
		}
	}
	return nil
}

func writeRecoveryJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeRecoveryFile(path, append(data, '\n'))
}

func writeRecoveryFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".recovery-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncRecoveryDirectory(filepath.Dir(path))
}

func syncRecoveryDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// machineDockerTimeout bounds each Docker call the machine catalog makes
// outside a restic run: connecting, resolving and sizing images. Tests
// shorten it.
var machineDockerTimeout = 2 * time.Minute

// machineDocker runs one docker command for the machine catalog, which
// holds the operation lock, so a Docker that stops answering can't hold
// the lock with it.
func machineDocker(ctx context.Context, args ...string) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, machineDockerTimeout)
	defer cancel()
	out, err := exec.CommandContext(callCtx, "docker", args...).Output()
	if err != nil && ctx.Err() == nil && errors.Is(callCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("docker did not answer within %s", machineDockerTimeout)
	}
	return out, err
}

// recoveryImageID archives immutable image IDs. Docker save/load does not
// preserve registry RepoDigests, and mutable tags can change after deploy.
func recoveryImageID(ctx context.Context, ref, container string) (string, error) {
	args := []string{"image", "inspect", "--format={{.Id}}", ref}
	if container != "" {
		args = []string{"container", "inspect", "--format={{.Image}}", container}
	}
	out, err := machineDocker(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("resolve the recorded recovery image: %w", err)
	}
	id := strings.TrimSpace(string(out))
	if !strings.HasPrefix(id, "sha256:") || !fullSnapshotID.MatchString(strings.TrimPrefix(id, "sha256:")) {
		return "", errors.New("Docker returned an invalid immutable recovery image ID")
	}
	return id, nil
}

// The sizes Docker reports add up to an estimate of the image archive,
// not a bound: docker image save wraps each layer in a tar of its own,
// with a header and block padding for every file, and the containerd
// image store may report a size other than what it saves. So the
// estimate keeps a tenth of the sum and 64 MiB on top, until the archive
// is measured against the sum on a real host.
const (
	imageArchiveSlackPercent = 10
	imageArchiveSlackBytes   = 64 << 20
)

// recoveryImageSizes estimates what archiving images writes: the sum of
// the size Docker reports for each image, with the archive's slack on
// top. Tests replace it.
var recoveryImageSizes = func(ctx context.Context, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	out, err := machineDocker(ctx, append([]string{"image", "inspect", "--format={{.Size}}"}, ids...)...)
	if err != nil {
		return 0, fmt.Errorf("size the workload images: %w", err)
	}
	sizes := strings.Fields(string(out))
	if len(sizes) != len(ids) {
		return 0, fmt.Errorf("size the workload images: docker reported %d sizes for %d images", len(sizes), len(ids))
	}
	var sum int64
	for _, s := range sizes {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("size the workload images: docker reported %q as an image's size", s)
		}
		sum = addSize(sum, n)
	}
	return addSize(sum, addSize(sum/100*imageArchiveSlackPercent, imageArchiveSlackBytes)), nil
}

// addSize adds two non-negative sizes, saturating rather than wrapping.
func addSize(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

// machineImagesTimeout bounds archiving the workload images into a machine
// backup, which runs under the operation lock.
const machineImagesTimeout = time.Hour

func saveMachineImages(ctx context.Context, path string, refs []string) error {
	if len(refs) == 0 {
		return nil
	}
	saveCtx, cancel := context.WithTimeout(ctx, machineImagesTimeout)
	defer cancel()
	args := append([]string{"image", "save", "--output", path + ".tmp"}, refs...)
	if _, err := exec.CommandContext(saveCtx, "docker", args...).CombinedOutput(); err != nil {
		_ = os.Remove(path + ".tmp")
		if ctx.Err() == nil && errors.Is(saveCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("archive the machine's workload images: did not finish within %s and was stopped", machineImagesTimeout)
		}
		return fmt.Errorf("archive the machine's workload images: %w", err)
	}
	if err := os.Chmod(path+".tmp", 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func loadMachineImages(ctx context.Context, path string) error {
	if err := recoveryPlainFile(path); err != nil {
		return err
	}
	if _, err := exec.CommandContext(ctx, "docker", "image", "load", "--input", path).CombinedOutput(); err != nil {
		return fmt.Errorf("load the machine's workload image archive: %w", err)
	}
	return nil
}

// machineAppPin is one data app's pinned recovery point, found before
// anything is copied.
type machineAppPin struct {
	rev  *state.Revision // points into the catalog's Revisions
	m    manifest.Manifest
	last *state.BackupRun // the last good backup run: the pin
	size restic.Size      // what restoring it writes
	snap *restic.Snapshot // nil until resolved in the repository
	r    restic.Runner    // valid once snap is set
}

// checkMachineCopySpace refuses a machine backup whose pinned app data and
// image archive can't all fit in its staging with the reserve left, before
// any of it is written.
func checkMachineCopySpace(staging string, pins []*machineAppPin, images int64) error {
	if len(pins) == 0 {
		return nil // the image check before the archive covers images alone
	}
	var need int64
	parts := make([]string, 0, len(pins)+1)
	for _, p := range pins {
		n := allocated(p.size)
		if n < 0 {
			return fmt.Errorf("count %s's pinned data: the size is negative", p.rev.App)
		}
		need = addSize(need, n)
		parts = append(parts, p.rev.App+" "+HumanBytes(n))
	}
	if images > 0 {
		need = addSize(need, images)
		parts = append(parts, "workload images up to "+HumanBytes(images))
	}
	if err := checkRestoreSpace([]string{staging}, need, restoreFreeReserve); err != nil {
		return fmt.Errorf("copy the pinned app data into the machine backup: %w (%s); no app data was copied; free space and back up the machine again", err, strings.Join(parts, ", "))
	}
	return nil
}

// resolveMachinePin finds a pin's snapshot in its repository and keeps
// the runner that copies it.
func (b Backup) resolveMachinePin(ctx context.Context, connect func() (*docker.Engine, error), pin *machineAppPin) error {
	e, err := connect()
	if err != nil {
		return err
	}
	r, _, err := openRepo(b.Secrets, e, manifest.ReservedApp, pin.rev.App, nil)
	if err != nil {
		return err
	}
	// The machine backup holds the operation lock while it copies the
	// app's data in, so the copy has a limit like its other calls.
	r.Deadlines = b.Deadlines
	if r.Deadlines.Restore <= 0 {
		r.Deadlines.Restore = restic.RestoreTimeout
	}
	snaps, err := r.Snapshots(ctx, pin.rev.App)
	if err != nil {
		return err
	}
	snap, err := resolveRecoverySnapshot(snaps, pin.last.Snapshot)
	if err != nil {
		return fmt.Errorf("pin %s's data recovery point: %w", pin.rev.App, err)
	}
	pin.r, pin.snap = r, snap
	return nil
}

// prepareMachineRecoveryCatalog is called after taking the SQLite copy,
// so its revisions and backup records describe the copied state. It
// plans every pinned copy and the image archive, and checks that they
// all fit, before it copies any of them.
func (b Backup) prepareMachineRecoveryCatalog(ctx context.Context, hostname, staging string, out io.Writer) error {
	source, err := state.OpenReadOnly(filepath.Join(staging, "state.db"))
	if err != nil {
		return err
	}
	defer source.Close()
	revs, err := source.ActiveRevisions(ctx)
	if err != nil {
		return err
	}
	info := version.Current()
	c := machineRecoveryCatalog{EmbeddedData: true, Format: machineRecoveryFormat, Hostname: hostname, Version: info.Version,
		OS: info.OS, Arch: info.Arch, TakenAt: time.Now().UTC(), Revisions: revs, AppSnapshots: map[string]string{}, AppData: map[string]appBackupProvenance{}}
	identity, err := targetRecoveryIdentity(b.Secrets)
	if err != nil {
		return err
	}
	c.Recipient = identity.Recipient().String()
	if b.Profile != "" {
		if data, err := os.ReadFile(b.Profile); err == nil {
			if err := os.WriteFile(filepath.Join(staging, machineProfileFile), data, 0o600); err != nil {
				return err
			}
			c.Profile = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	var e *docker.Engine
	defer func() {
		if e != nil {
			e.Close()
		}
	}()
	// Connect uses its context only to ping, so the limit bounds the wait
	// for Docker's answer and the connection outlives it.
	connect := func() (*docker.Engine, error) {
		if e != nil {
			return e, nil
		}
		pingCtx, cancel := context.WithTimeout(ctx, machineDockerTimeout)
		defer cancel()
		var err error
		e, err = docker.Connect(pingCtx)
		return e, err
	}
	// Plan every copy before writing any app data: resolve the images, and
	// find each data app's pin and what restoring it writes, from its
	// backup record when the record kept a size.
	seen := map[string]bool{}
	var pins []*machineAppPin
	for i := range c.Revisions {
		rev := &c.Revisions[i]
		images := map[string]string{}
		for name, image := range rev.Images {
			if image == "" {
				continue
			}
			id, err := recoveryImageID(ctx, image, rev.Containers[name])
			if err != nil {
				return fmt.Errorf("%s/%s recovery image: %w", rev.App, name, err)
			}
			images[name] = id
			image = id
			if !seen[image] {
				seen[image] = true
				c.Images = append(c.Images, image)
			}
		}
		rev.Images = images
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return err
		}
		if !m.HasData() {
			continue
		}
		last, err := source.LastGoodBackupRun(ctx, rev.App, state.BackupRunBackup)
		if err != nil {
			return err
		}
		if last == nil || last.Snapshot == "" {
			return fmt.Errorf("%s has no successful data backup; run helios backup %s before backing up the whole machine", rev.App, rev.App)
		}
		// The snapshot step writes the provenance this copy is checked
		// against before its run finishes, so a run that finished before
		// this revision was created can't prove it. The check after the
		// copy still decides; this one spares copying what it would refuse.
		if last.FinishedAt.Before(rev.CreatedAt) {
			return freshRecoveryBackupRequired(*rev)
		}
		pin := &machineAppPin{rev: rev, m: m, last: last}
		if last.Bytes > 0 && last.Files >= 0 {
			pin.size = restic.Size{Bytes: last.Bytes, Files: last.Files}
		} else {
			// A record from before sizes were kept: ask the repository,
			// and keep the answer for the copy.
			if err := b.resolveMachinePin(ctx, connect, pin); err != nil {
				return err
			}
			if pin.size, err = snapshotSize(ctx, pin.r, pin.snap, rev.App); err != nil {
				return err
			}
		}
		pins = append(pins, pin)
	}
	slices.Sort(c.Images)
	archive, err := recoveryImageSizes(ctx, c.Images)
	if err != nil {
		return err
	}
	if err := checkMachineCopySpace(staging, pins, archive); err != nil {
		return err
	}
	// Find every pin in its repository before copying any, so one that
	// retention removed refuses before the apps ahead of it are copied.
	for _, pin := range pins {
		if pin.snap == nil {
			if err := b.resolveMachinePin(ctx, connect, pin); err != nil {
				return err
			}
		}
	}
	for _, pin := range pins {
		rev := pin.rev
		c.AppSnapshots[rev.App] = pin.snap.ID
		appData := filepath.Join(staging, machineAppDataDir, rev.App)
		if err := os.MkdirAll(appData, 0o700); err != nil {
			return err
		}
		// Every copy fit together when planned, but the running apps keep
		// writing beside them, so like a drill each copy checks again
		// before it lands.
		if err := checkRestoreSpace([]string{appData}, allocated(pin.size), restoreFreeReserve); err != nil {
			return fmt.Errorf("copy %s's snapshot %s into the machine backup: %w; free space and back up the machine again", rev.App, short(pin.snap.ID), err)
		}
		if _, err := pin.r.Restore(ctx, pin.snap.ID, rev.App, []string{restic.DirMount(appData, false)}); err != nil {
			return fmt.Errorf("preserve %s's pinned data inside the machine backup: %w", rev.App, err)
		}
		data, err := os.ReadFile(filepath.Join(appData, "manifest.json"))
		if err != nil {
			return err
		}
		var backed manifest.Manifest
		if json.Unmarshal(data, &backed) != nil {
			return errors.New("invalid backed-up app manifest")
		}
		if err := compatibleRecoveryData(&pin.m, &backed); err != nil {
			return err
		}
		provenance, err := readAppBackupProvenance(appData, *rev)
		if err != nil {
			return err
		}
		c.AppData[rev.App] = provenance
		fmt.Fprintf(out, "%s's pinned app snapshot embedded in the machine backup\n", rev.App)
	}
	// The archive lands after the copies, so it checks the room they left.
	if archive > 0 {
		if err := checkRestoreSpace([]string{staging}, archive, restoreFreeReserve); err != nil {
			return fmt.Errorf("archive the machine's workload images: %w; free space and back up the machine again", err)
		}
	}
	if err := saveMachineImages(ctx, filepath.Join(staging, machineImagesFile), c.Images); err != nil {
		return err
	}
	if err := writeRecoveryJSON(filepath.Join(staging, machineCatalogFile), c); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d app revisions and %d workload images preserved\n", len(revs), len(c.Images))
	return nil
}
