package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// recoveryImageID archives immutable image IDs. Docker save/load does not
// preserve registry RepoDigests, and mutable tags can change after deploy.
func recoveryImageID(ctx context.Context, ref, container string) (string, error) {
	args := []string{"image", "inspect", "--format={{.Id}}", ref}
	if container != "" {
		args = []string{"container", "inspect", "--format={{.Image}}", container}
	}
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return "", fmt.Errorf("resolve the recorded recovery image: %w", err)
	}
	id := strings.TrimSpace(string(out))
	if !strings.HasPrefix(id, "sha256:") || !fullSnapshotID.MatchString(strings.TrimPrefix(id, "sha256:")) {
		return "", errors.New("Docker returned an invalid immutable recovery image ID")
	}
	return id, nil
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

// prepareMachineRecoveryCatalog is called after taking the SQLite copy,
// so its revisions and backup records describe the copied state.
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
	seen := map[string]bool{}
	var e *docker.Engine
	defer func() {
		if e != nil {
			e.Close()
		}
	}()
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
		if e == nil {
			e, err = docker.Connect(ctx)
			if err != nil {
				return err
			}
		}
		r, _, err := openRepo(b.Secrets, e, manifest.ReservedApp, rev.App, nil)
		if err != nil {
			return err
		}
		// The machine backup holds the operation lock while it copies the
		// app's data in, so the copy has a limit like its other calls.
		r.Deadlines = b.Deadlines
		if r.Deadlines.Restore <= 0 {
			r.Deadlines.Restore = restic.RestoreTimeout
		}
		snaps, err := r.Snapshots(ctx, rev.App)
		if err != nil {
			return err
		}
		snap, err := resolveRecoverySnapshot(snaps, last.Snapshot)
		if err != nil {
			return fmt.Errorf("pin %s's data recovery point: %w", rev.App, err)
		}
		c.AppSnapshots[rev.App] = snap.ID
		appData := filepath.Join(staging, machineAppDataDir, rev.App)
		if err := os.MkdirAll(appData, 0o700); err != nil {
			return err
		}
		// The copy lands beside the machine's running apps, after the
		// copies before it, so like a drill it keeps the reserve and
		// refuses what it can't count.
		size, err := snapshotSize(ctx, r, snap, rev.App)
		if err != nil {
			return err
		}
		if err := checkRestoreSpace([]string{appData}, allocated(size), restoreFreeReserve); err != nil {
			return fmt.Errorf("copy %s's snapshot %s into the machine backup: %w; free space and back up the machine again", rev.App, short(snap.ID), err)
		}
		if _, err := r.Restore(ctx, snap.ID, rev.App, []string{restic.DirMount(appData, false)}); err != nil {
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
		if err := compatibleRecoveryData(&m, &backed); err != nil {
			return err
		}
		provenance, err := readAppBackupProvenance(appData, *rev)
		if err != nil {
			return err
		}
		c.AppData[rev.App] = provenance
		fmt.Fprintf(out, "%s's pinned app snapshot embedded in the machine backup\n", rev.App)

	}
	slices.Sort(c.Images)
	if err := saveMachineImages(ctx, filepath.Join(staging, machineImagesFile), c.Images); err != nil {
		return err
	}
	if err := writeRecoveryJSON(filepath.Join(staging, machineCatalogFile), c); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d app revisions and %d workload images preserved\n", len(revs), len(c.Images))
	return nil
}
