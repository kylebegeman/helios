package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/version"
)

const RecoverMachineKind = "machine.recover"
const RecoverCutoverKind = "machine.recover.cutover"
const RecoverAbandonKind = "machine.recover.abandon"

// RecoverMachine restores privately. A separate reviewed cutover is the
// only operation that can activate workloads and change live DNS/routes.
type RecoverMachine struct {
	Store               *state.Store
	Secrets             *secrets.Store
	StateDir            string
	ApplyProfile        func(context.Context, json.RawMessage, io.Writer) error
	RecoverIntegrations func(context.Context, *secrets.Store, io.Writer) error
}

type RecoverMachineInput struct {
	Source         string `json:"source"`
	Snapshot       string `json:"snapshot"`
	ID             string `json:"id"`
	Rehearsal      bool   `json:"rehearsal,omitempty"`
	IdentitySHA256 string `json:"identity_sha256,omitempty"`
}

func (RecoverMachine) Kind() string { return RecoverMachineKind }

// machineRecoveryRecord is persisted between steps independently of the
// target's journal. No private identity or decrypted values are stored here.
type machineRecoveryRecord struct {
	Input                   RecoverMachineInput    `json:"input"`
	Snapshot                restic.Snapshot        `json:"machine_snapshot"`
	Catalog                 machineRecoveryCatalog `json:"catalog"`
	StartedAt               time.Time              `json:"started_at"`
	FinishedAt              time.Time              `json:"finished_at,omitempty"`
	Fetched                 bool                   `json:"fetched"`
	SecretsReady            bool                   `json:"secrets_ready"`
	ImagesReady             bool                   `json:"images_ready"`
	ResourcesClaimed        bool                   `json:"resources_claimed"`
	RehearsalCleanupStarted bool                   `json:"rehearsal_cleanup_started,omitempty"`
	ProfileApplied          bool                   `json:"profile_applied"`
	IntegrationsRecovered   bool                   `json:"integrations_recovered"`
	StateInstalled          bool                   `json:"state_installed"`
	DataReady               map[string]bool        `json:"data_ready"`
	DatabaseReady           map[string]bool        `json:"database_ready"`
	Ready                   map[string]bool        `json:"ready"`
	SecretVersions          map[string]map[int]int `json:"secret_versions"`
	CutoverReady            map[string]bool        `json:"cutover_ready"`
	CutoverStarted          bool                   `json:"cutover_started"`
	Cutover                 bool                   `json:"cutover"`
	AbandonedAt             time.Time              `json:"abandoned_at,omitempty"`
}

type machineRecovering struct {
	r   RecoverMachine
	in  RecoverMachineInput
	dir string
}

func (x *machineRecovering) recordPath() string { return filepath.Join(x.dir, "recovery-record.json") }
func (x *machineRecovering) stage() string      { return filepath.Join(x.dir, "snapshot") }
func (x *machineRecovering) stagedSecrets() *secrets.Store {
	return &secrets.Store{Dir: filepath.Join(x.dir, "sealed-secrets"), KeyPath: x.r.Secrets.KeyPath}
}
func (x *machineRecovering) save(rec *machineRecoveryRecord) error {
	return writeRecoveryJSON(x.recordPath(), rec)
}
func (x *machineRecovering) load() (*machineRecoveryRecord, error) {
	if err := recoveryPlainFile(x.recordPath()); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(x.recordPath())
	if err != nil {
		return nil, err
	}
	var rec machineRecoveryRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, errors.New("invalid machine recovery record")
	}
	if rec.DataReady == nil {
		rec.DataReady = map[string]bool{}
	}
	if rec.DatabaseReady == nil {
		rec.DatabaseReady = map[string]bool{}
	}
	if rec.Ready == nil {
		rec.Ready = map[string]bool{}
	}
	if rec.CutoverReady == nil {
		rec.CutoverReady = map[string]bool{}
	}
	if rec.Input.Source != x.in.Source || rec.Input.Snapshot != x.in.Snapshot || rec.Input.ID != x.in.ID || rec.Input.Rehearsal != x.in.Rehearsal {
		return nil, errors.New("this recovery ID is already bound to a different source, snapshot or mode")
	}
	if x.in.IdentitySHA256 != "" && rec.Input.IdentitySHA256 != x.in.IdentitySHA256 {
		return nil, errors.New("this recovery's sealed identity checksum changed")
	}
	return &rec, nil
}

func ValidateMachineRecoveryInput(in RecoverMachineInput) error {
	if !recoverySourcePattern.MatchString(in.Source) {
		return errors.New("recovery needs the explicit source machine hostname")
	}
	if !snapshotPrefix.MatchString(in.Snapshot) {
		return errors.New("recovery needs an explicit machine snapshot ID; latest is not accepted")
	}
	if !recoveryIDPattern.MatchString(in.ID) {
		return errors.New("recovery ID must be 8 to 48 lowercase letters, digits or hyphens")
	}
	if in.IdentitySHA256 != "" && !fullSnapshotID.MatchString(in.IdentitySHA256) {
		return errors.New("invalid sealed recovery identity checksum")
	}
	return nil
}

func (r RecoverMachine) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in RecoverMachineInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, errors.New("invalid machine recovery input")
	}
	if err := ValidateMachineRecoveryInput(in); err != nil {
		return nil, err
	}
	if _, err := integration.LoadStorage(r.Secrets); err != nil {
		return nil, fmt.Errorf("configure target storage to read the source backup first: %w", err)
	}
	if _, err := targetRecoveryIdentity(r.Secrets); err != nil {
		return nil, err
	}
	x := &machineRecovering{r: r, in: in, dir: RecoveryDirectory(r.StateDir, in.ID)}
	if _, err := os.Lstat(x.recordPath()); err == nil {
		if rec, err := x.load(); err != nil {
			return nil, err
		} else if !rec.AbandonedAt.IsZero() {
			return nil, errors.New("this recovery was abandoned; use a new --id for a new recovery")
		} else if rec.Fetched {
			if err := validateRecoveryCatalog(rec.Catalog); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if !in.Rehearsal {
		if err := r.cleanTarget(ctx); err != nil {
			return nil, err
		}
	}
	mode := "restore privately onto this clean target"
	if in.Rehearsal {
		mode = "restore into disposable isolated resources"
	}
	plan := &kernel.Plan{Target: "recovery " + in.ID, Recovery: kernel.Resume}
	plan.Steps = []kernel.Step{
		x.step("fetch", fmt.Sprintf("%s from %s, machine snapshot %s", mode, in.Source, in.Snapshot), x.fetch),
		x.step("secrets", "reseal every source secret version with the target identity", x.reseal),
		x.step("images", "load the recorded workload images preserved in the snapshot", x.images),
		x.step("data", "restore each app's pinned data snapshot into recovery-owned volumes", x.data),
		x.step("ready", "start isolated workloads and prove private readiness without live routes or published ports", x.ready),
	}
	if !in.Rehearsal {
		plan.Steps = append(plan.Steps, x.step("profile", "apply the source host profile and recover explicitly selected integrations", x.profile),
			x.step("state", "import operational state and history while preserving the target journal and inactive source history", x.installState))
	}
	plan.Steps = append(plan.Steps, x.step("finish", "record readiness and remove the sealed source identity"+map[bool]string{true: " and every disposable resource", false: "; live cutover remains a separate operation"}[in.Rehearsal], x.finish))
	return plan, nil
}

func (r RecoverMachine) cleanTarget(ctx context.Context) error {
	names, err := r.Store.AppNames(ctx)
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return errors.New("machine recovery requires a clean target with no app revisions; use --rehearsal to test beside existing apps")
	}
	apps, err := r.Secrets.Apps()
	if err != nil {
		return err
	}
	if len(apps) > 0 {
		return errors.New("machine recovery requires a clean target with no app secrets; target integration credentials and identity are preserved")
	}
	return nil
}

func (x *machineRecovering) step(name, change string, apply func(context.Context, io.Writer) error) kernel.Step {
	return kernel.Step{Name: name, Change: change, Apply: func(ctx context.Context, out io.Writer) error {
		if rec, err := x.load(); err == nil {
			if !rec.FinishedAt.IsZero() || x.in.Rehearsal && rec.RehearsalCleanupStarted && name != "finish" {
				return nil
			}
			if rec.Fetched && !x.in.Rehearsal {
				// An earlier preclaim failure may have released the gate.
				// Completed fetch steps are skipped on kernel recovery, so
				// every resumed step must restore that reservation itself.
				if !rec.ResourcesClaimed && !rec.StateInstalled {
					gate, err := readMachineRecoveryReservation(x.r.Store.Path())
					if err != nil {
						return err
					}
					if gate == nil {
						if err := x.r.cleanTarget(ctx); err != nil {
							return err
						}
					}
				}
				if err := x.reserve(rec); err != nil {
					return err
				}
			}
		}
		err := apply(ctx, out)
		if err != nil && !x.in.Rehearsal {
			if rec, loadErr := x.load(); loadErr == nil && !rec.ResourcesClaimed && !rec.StateInstalled {
				imported, checkErr := x.r.Store.MachineRecoveryImported(context.Background(), x.in.ID)
				if checkErr == nil && !imported {
					if releaseErr := x.releaseReservation(); releaseErr != nil {
						return errors.Join(err, releaseErr)
					}
				}
			}
		}
		if err != nil && x.in.Rehearsal {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if rec, loadErr := x.load(); loadErr == nil && rec.ResourcesClaimed && !rec.RehearsalCleanupStarted {
				if e, connectErr := docker.Connect(cleanupCtx); connectErr == nil {
					cleanupErr := x.cleanup(rec, e)
					e.Close()
					if cleanupErr != nil {
						return errors.Join(err, fmt.Errorf("rehearsal cleanup: %w", cleanupErr))
					}
				} else {
					return errors.Join(err, fmt.Errorf("rehearsal cleanup cannot connect to Docker: %w", connectErr))
				}
				rec.ResourcesClaimed = false
				rec.DataReady = map[string]bool{}
				rec.DatabaseReady = map[string]bool{}
				rec.Ready = map[string]bool{}
				_ = x.save(rec)
			}
		}
		return err
	}}
}

func (x *machineRecovering) fetch(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if rec != nil && rec.Fetched {
		return x.reserve(rec)
	}
	if rec == nil {
		if !x.in.Rehearsal {
			if err := x.r.cleanTarget(ctx); err != nil {
				return err
			}
		}
		if x.in.IdentitySHA256 == "" {
			return errors.New("supply the source recovery identity through --identity-file or --identity-stdin")
		}
		rec = &machineRecoveryRecord{Input: x.in, StartedAt: time.Now().UTC(), DataReady: map[string]bool{}, DatabaseReady: map[string]bool{}, Ready: map[string]bool{}, CutoverReady: map[string]bool{}}
	}
	if _, err := openRecoveryIdentity(x.r.Secrets, x.r.StateDir, x.in.ID, rec.Input.IdentitySHA256); err != nil {
		return err
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	target := MachineTarget(x.in.Source)
	r, _, err := openRepo(x.r.Secrets, e, manifest.ReservedApp, target, nil)
	if err != nil {
		return err
	}
	if rec.Snapshot.ID == "" {
		snaps, err := r.Snapshots(ctx, target)
		if err != nil {
			return err
		}
		snap, err := resolveRecoverySnapshot(snaps, x.in.Snapshot)
		if err != nil {
			return err
		}
		rec.Snapshot = *snap
		// Pin before restore starts, so an interruption never follows a
		// moving repository selection or an ambiguous prefix again.
		if err := x.save(rec); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(x.stage(), 0o700); err != nil {
		return err
	}
	if _, err := r.Restore(ctx, rec.Snapshot.ID, target, []string{restic.DirMount(x.stage(), false)},
		restic.DataRoot+"/state.db", restic.DataRoot+"/secrets", restic.DataRoot+"/"+machineCatalogFile, restic.DataRoot+"/"+machineImagesFile, restic.DataRoot+"/"+machineProfileFile); err != nil {
		return err
	}
	catalogPath := filepath.Join(x.stage(), machineCatalogFile)
	if err := recoveryPlainFile(catalogPath); err != nil {
		return errors.New("this legacy machine snapshot has no recovery catalog or workload image archive; create a new machine backup with this helios version")
	}
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &rec.Catalog); err != nil {
		return errors.New("machine recovery catalog is invalid")
	}
	if rec.Catalog.Hostname != x.in.Source {
		return errors.New("the machine snapshot does not belong to the requested source hostname")
	}
	if err := checkMachineRecoveryCompatibility(rec.Catalog, version.Current()); err != nil {
		return err
	}
	if err := recoveryPlainFile(filepath.Join(x.stage(), "state.db")); err != nil {
		return err
	}
	source, err := state.OpenReadOnly(filepath.Join(x.stage(), "state.db"))
	if err != nil {
		return fmt.Errorf("source state compatibility: %w", err)
	}
	source.Close()
	if err := validateRecoveryCatalog(rec.Catalog); err != nil {
		return err
	}
	if err := x.reserve(rec); err != nil {
		return err
	}
	rec.Fetched = true
	if err := x.save(rec); err != nil {
		return err
	}
	fmt.Fprintf(out, "pinned machine snapshot %s; %d app revisions\n", rec.Snapshot.ID, len(rec.Catalog.Revisions))
	return nil
}

func validateRecoveryCatalog(c machineRecoveryCatalog) error {
	seen := map[string]bool{}
	for _, rev := range c.Revisions {
		if seen[rev.App] {
			return errors.New("machine recovery catalog repeats an app")
		}
		seen[rev.App] = true
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return errors.New("machine snapshot has an invalid workload manifest")
		}
		if err := m.Validate(); err != nil {
			return fmt.Errorf("%s snapshot manifest: %w", rev.App, err)
		}
		if m.App != rev.App {
			return errors.New("machine snapshot revision belongs to a different app")
		}
		for name, w := range m.Workloads {
			if w.LongRunning() && w.Privileged {
				return fmt.Errorf("cannot safely recover privileged workload %s/%s privately", m.App, name)
			}
			if w.LongRunning() && rev.Images[name] == "" {
				return fmt.Errorf("machine snapshot records no image for %s/%s", m.App, name)
			}
		}
		if m.HasData() && !fullSnapshotID.MatchString(c.AppSnapshots[rev.App]) {
			return fmt.Errorf("%s has no pinned successful data backup in this machine snapshot; take its data backup before the machine backup", rev.App)
		}
		if m.HasData() {
			if err := validateAppBackupProvenance(rev, c.AppData[rev.App]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (x *machineRecovering) reseal(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil {
		return err
	}
	if rec.SecretsReady {
		return nil
	}
	source, err := openRecoveryIdentity(x.r.Secrets, x.r.StateDir, x.in.ID, rec.Input.IdentitySHA256)
	if err != nil {
		return err
	}
	if rec.Catalog.Recipient != "" && source.Recipient().String() != rec.Catalog.Recipient {
		return errors.New("the recovery identity does not match the source machine")
	}
	target, err := targetRecoveryIdentity(x.r.Secrets)
	if err != nil {
		return err
	}
	if !x.in.Rehearsal && target.Recipient().String() == source.Recipient().String() {
		return errors.New("real recovery requires the target's own different identity; use --rehearsal on the source machine")
	}
	rec.SecretVersions, err = resealRecoverySecrets(filepath.Join(x.stage(), "secrets"), x.stagedSecrets().Dir, source, target)
	if err != nil {
		return err
	}
	for _, rev := range rec.Catalog.Revisions {
		if rev.SecretsVersion > 0 && rec.SecretVersions[rev.App][rev.SecretsVersion] != rev.SecretsVersion {
			return fmt.Errorf("%s's recorded secret version %d is missing from the snapshot", rev.App, rev.SecretsVersion)
		}
	}
	rec.SecretsReady = true
	if err := x.save(rec); err != nil {
		return err
	}
	fmt.Fprintln(out, "source secret versions resealed; target private identity preserved")
	return nil
}

func (x *machineRecovering) images(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil {
		return err
	}
	if rec.ImagesReady {
		return nil
	}
	if len(rec.Catalog.Images) > 0 {
		if err := loadMachineImages(ctx, filepath.Join(x.stage(), machineImagesFile)); err != nil {
			return err
		}
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	for _, rev := range rec.Catalog.Revisions {
		for name, image := range rev.Images {
			if image != "" && !e.HasImage(ctx, image) {
				return fmt.Errorf("image %s for %s/%s did not load from the archive", image, rev.App, name)
			}
		}
	}
	rec.ImagesReady = true
	if err := x.save(rec); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d recorded images available\n", len(rec.Catalog.Images))
	return nil
}

func (x *machineRecovering) profile(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil {
		return err
	}
	if !rec.ProfileApplied && rec.Catalog.Profile {
		if x.r.ApplyProfile == nil {
			return errors.New("this recovery definition cannot apply a host profile")
		}
		path := filepath.Join(x.stage(), machineProfileFile)
		if err := recoveryPlainFile(path); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !json.Valid(data) {
			return errors.New("invalid source host profile")
		}
		if err := x.r.ApplyProfile(ctx, json.RawMessage(data), out); err != nil {
			return err
		}
		rec.ProfileApplied = true
		if err := x.save(rec); err != nil {
			return err
		}
	}
	if !rec.IntegrationsRecovered {
		if x.r.RecoverIntegrations != nil {
			if err := x.r.RecoverIntegrations(ctx, x.stagedSecrets(), out); err != nil {
				return err
			}
		}
		rec.IntegrationsRecovered = true
		return x.save(rec)
	}
	return nil
}

func (x *machineRecovering) installState(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil {
		return err
	}
	if rec.StateInstalled {
		return nil
	}
	for _, rev := range rec.Catalog.Revisions {
		if !rec.Ready[rev.App] {
			return fmt.Errorf("%s has not passed private recovery readiness", rev.App)
		}
	}
	if err := x.installAppSecrets(rec); err != nil {
		return err
	}
	for _, rev := range rec.Catalog.Revisions {
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		if keepsOwners(&m) {
			if _, err := restoreInit(x.names(&m).dir, x.r.StateDir, m.App); err != nil {
				return err
			}
		}
	}
	var revisions []state.Revision
	for _, source := range rec.Catalog.Revisions {
		rev := source
		rev.ID = recoveryRevisionID(x.in.ID)
		rev.Status = state.RevisionFailed
		rev.CreatedAt = rec.StartedAt
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		rev.Containers = x.names(&m).containers
		revisions = append(revisions, rev)
	}
	if err := x.r.Store.ImportMachineRecovery(ctx, filepath.Join(x.stage(), "state.db"), x.in.ID, rec.SecretVersions, revisions); err != nil {
		return err
	}
	rec.StateInstalled = true
	if err := x.save(rec); err != nil {
		return err
	}
	fmt.Fprintln(out, "operational state imported; restored revisions remain inactive until cutover")
	return nil
}

func recoveryRevisionID(id string) string {
	return "recovered-" + strings.TrimPrefix(strings.TrimPrefix(id, "recover-"), "rehearse-")
}

func (x *machineRecovering) installAppSecrets(rec *machineRecoveryRecord) error {
	if err := os.MkdirAll(x.r.Secrets.Dir, 0o700); err != nil {
		return err
	}
	for app := range rec.SecretVersions {
		if app == manifest.ReservedApp {
			continue
		}
		src := filepath.Join(x.stagedSecrets().Dir, app)
		dst := filepath.Join(x.r.Secrets.Dir, app)
		if info, err := os.Lstat(dst); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("target app secret directory is invalid")
			}
			// Only exact equivalent secret histories can be adopted after
			// an interrupted per-app installation. Never overwrite a target.
			staged := x.stagedSecrets()
			sourceCurrent, err := staged.Current(app)
			if err != nil {
				return err
			}
			targetCurrent, err := x.r.Secrets.Current(app)
			if err != nil {
				return err
			}
			versions, err := x.r.Secrets.Versions(app)
			if err != nil {
				return err
			}
			if sourceCurrent != targetCurrent || len(versions) != len(rec.SecretVersions[app]) {
				return fmt.Errorf("target secret history for %s conflicts with this recovery", app)
			}
			for v := range rec.SecretVersions[app] {
				a, err := staged.Load(app, v)
				if err != nil {
					return err
				}
				b, err := x.r.Secrets.Load(app, v)
				if err != nil {
					return err
				}
				aa, _ := json.Marshal(a)
				bb, _ := json.Marshal(b)
				if string(aa) != string(bb) {
					return fmt.Errorf("target secrets for %s conflict with this recovery", app)
				}
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		temp, err := os.MkdirTemp(x.r.Secrets.Dir, ".recovery-*")
		if err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			os.RemoveAll(temp)
			return err
		}
		for _, f := range entries {
			if err := recoveryPlainFile(filepath.Join(src, f.Name())); err != nil {
				os.RemoveAll(temp)
				return err
			}
			data, err := os.ReadFile(filepath.Join(src, f.Name()))
			if err != nil {
				os.RemoveAll(temp)
				return err
			}
			if err := writeRecoveryFile(filepath.Join(temp, f.Name()), data); err != nil {
				os.RemoveAll(temp)
				return err
			}
		}
		if err := os.Rename(temp, dst); err != nil {
			os.RemoveAll(temp)
			return err
		}
		if err := syncRecoveryDirectory(x.r.Secrets.Dir); err != nil {
			return err
		}
	}
	return nil
}

func (x *machineRecovering) finish(ctx context.Context, out io.Writer) error {
	rec, err := x.load()
	if err != nil {
		return err
	}
	if !rec.FinishedAt.IsZero() {
		return nil
	}
	for _, rev := range rec.Catalog.Revisions {
		if !rec.Ready[rev.App] {
			return fmt.Errorf("%s has not passed readiness", rev.App)
		}
	}
	if x.in.Rehearsal {
		if !rec.RehearsalCleanupStarted {
			// Once cleanup starts, retries must finish removing scratch
			// resources without depending on their deleted staged secrets.
			rec.RehearsalCleanupStarted = true
			if err := x.save(rec); err != nil {
				return err
			}
		}
		e, err := docker.Connect(ctx)
		if err != nil {
			return err
		}
		cleanupErr := x.cleanup(rec, e)
		e.Close()
		if cleanupErr != nil {
			return cleanupErr
		}
		if err := os.RemoveAll(x.stagedSecrets().Dir); err != nil {
			return err
		}
		if err := os.RemoveAll(x.stage()); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(x.dir, "identity.age")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rec.FinishedAt = time.Now().UTC()
	if err := x.save(rec); err != nil {
		return err
	}
	if x.in.Rehearsal {
		fmt.Fprintln(out, "machine recovery rehearsal passed; disposable resources removed")
	} else {
		fmt.Fprintf(out, "private recovery ready; review helios recover cutover %s --plan before changing live traffic\n", x.in.ID)
	}
	return nil
}
