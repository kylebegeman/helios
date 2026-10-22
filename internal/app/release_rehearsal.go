package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

const RehearseKind = "app.rehearse"

// Rehearse tests candidate release jobs on a restored copy of the app's data.
// It never publishes routes, mounts live volumes, activates a revision or cron.
type Rehearse struct {
	Store    *state.Store
	Secrets  *secrets.Store
	StateDir string
}
type RehearseInput struct {
	Source   string `json:"source"`
	Snapshot string `json:"snapshot,omitempty"`
	Revision string `json:"revision"`
}

func (Rehearse) Kind() string { return RehearseKind }

// RehearsalProof identifies the exact code, images and data tested. A successful
// rehearsal proves this combination; it does not claim later data is identical.
type RehearsalProof struct {
	App            string            `json:"app"`
	Revision       string            `json:"revision"`
	ActiveRevision string            `json:"active_revision"`
	SourceSHA256   string            `json:"source_sha256"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	Snapshot       string            `json:"snapshot,omitempty"`
	Images         map[string]string `json:"images"`
	Releases       []string          `json:"releases"`
	Status         string            `json:"status"`
	Error          string            `json:"error,omitempty"`
	StartedAt      time.Time         `json:"started_at"`
	FinishedAt     time.Time         `json:"finished_at,omitempty"`
}

type releaseRehearsal struct {
	def               Rehearse
	input             RehearseInput
	candidate         *manifest.Manifest
	active            *state.Revision
	proof             RehearsalProof
	redactions        []string
	workspace, report string
	reservation       string
	names             drillNames
}

type rehearsalReservation struct {
	Input     RehearseInput     `json:"input"`
	Candidate manifest.Manifest `json:"candidate"`
	Active    state.Revision    `json:"active"`
	Proof     RehearsalProof    `json:"proof"`
}

func rehearsalReservationPath(stateDir string, in RehearseInput) string {
	key := sha256.Sum256([]byte(in.Source + "\x00" + in.Revision))
	return filepath.Join(stateDir, "rehearsals", ".pending", hex.EncodeToString(key[:])+".json")
}

func (r Rehearse) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in RehearseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("rehearsal input: %w", err)
	}
	if !filepath.IsAbs(in.Source) {
		return nil, errors.New("rehearsal needs an absolute source directory")
	}
	if !revisionPattern.MatchString(in.Revision) {
		return nil, errors.New("rehearsal needs a valid candidate revision")
	}
	stateDir := r.StateDir
	if stateDir == "" {
		stateDir = defaultStateDir
	}
	reservation := rehearsalReservationPath(stateDir, in)
	var captured rehearsalReservation
	cached, cacheErr := os.ReadFile(reservation)
	if cacheErr != nil && !errors.Is(cacheErr, os.ErrNotExist) {
		return nil, cacheErr
	}
	var candidate *manifest.Manifest
	var active *state.Revision
	var proof RehearsalProof
	if cacheErr == nil {
		if err := json.Unmarshal(cached, &captured); err != nil {
			return nil, fmt.Errorf("read interrupted rehearsal reservation: %w", err)
		}
		if captured.Input.Source != in.Source || captured.Input.Revision != in.Revision || captured.Input.Snapshot != in.Snapshot {
			return nil, errors.New("interrupted rehearsal reservation does not match this request")
		}
		if err := captured.Candidate.Validate(); err != nil {
			return nil, err
		}
		candidate, active, proof = &captured.Candidate, &captured.Active, captured.Proof
		if candidate.App != active.App || proof.App != candidate.App || proof.Revision != in.Revision || proof.ActiveRevision != active.ID || len(proof.SourceSHA256) != 64 {
			return nil, errors.New("interrupted rehearsal reservation has an invalid identity")
		}
	} else {
		var err error
		candidate, err = manifest.Load(in.Source)
		if err != nil {
			return nil, err
		}
		if !candidate.HasData() {
			return nil, errors.New("release rehearsal needs an app with backed-up data")
		}
		for name, w := range candidate.Workloads {
			if w.Privileged {
				return nil, fmt.Errorf("cannot rehearse privileged workload %s on scratch data", name)
			}
		}
		active, err = r.Store.RevisionWithStatus(ctx, candidate.App, state.RevisionActive)
		if err != nil {
			return nil, err
		}
		if active == nil {
			return nil, fmt.Errorf("%s is not deployed; rehearsal needs its pinned secrets and backup", candidate.App)
		}
		sourceHash, err := rehearsalSourceHash(in.Source)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(candidate)
		if err != nil {
			return nil, err
		}
		manifestHash := sha256.Sum256(encoded)
		proof = RehearsalProof{App: candidate.App, Revision: in.Revision, ActiveRevision: active.ID, SourceSHA256: sourceHash, ManifestSHA256: hex.EncodeToString(manifestHash[:]), Images: map[string]string{}, Status: "started"}
	}
	asked := in.Snapshot
	if asked == "" {
		asked = "latest"
	}
	x := &releaseRehearsal{def: r, input: in, candidate: candidate, active: active, reservation: reservation,
		workspace: filepath.Join(stateDir, "rehearsals", candidate.App, "scratch-"+in.Revision),
		report:    filepath.Join(stateDir, "rehearsals", candidate.App, in.Revision+".json"), proof: proof}
	x.input.Snapshot = asked
	x.names = rehearsalNames(x.workspace, candidate, in.Revision)
	// Reserving first gives crash recovery a completed cleanup step to undo,
	// even if a release container is still running when the daemon is killed.
	return &kernel.Plan{Target: candidate.App, Recovery: kernel.Compensate, Steps: []kernel.Step{
		{Name: "reserve-rehearsal", Change: "capture candidate source " + proof.SourceSHA256 + " for " + candidate.App + fmt.Sprintf(" using active revision %s and secrets version %d", active.ID, active.SecretsVersion),
			Apply: func(_ context.Context, _ io.Writer) error {
				if err := os.MkdirAll(x.workspace, 0o700); err != nil {
					return err
				}
				x.proof.StartedAt = time.Now().UTC()
				return writeRehearsalJSON(x.reservation, rehearsalReservation{Input: in, Candidate: *candidate, Active: *active, Proof: x.proof})
			}, Undo: x.abort},
		{Name: "rehearse", Change: "restore snapshot " + asked + ", build the candidate, run releases in order and check scratch workloads", Note: "no public routes, live volumes or cron; proof " + x.report, Apply: x.run},
	}}, nil
}

func rehearsalNames(workspace string, m *manifest.Manifest, revision string) drillNames {
	prefix := "bedrock." + m.App + ".rehearse." + revision
	n := drillNames{app: m.App, dir: filepath.Join(workspace, "restore"), network: prefix, postgres: prefix + ".postgres", postgresVolume: prefix + ".postgres", objects: prefix + ".objects", volumes: map[string]string{}, containers: map[string]string{}}
	for _, v := range m.DataVolumes() {
		n.volumes[v] = prefix + ".volume." + v
	}
	for _, w := range m.WorkloadNames() {
		if m.Workloads[w].Kind != manifest.Cron {
			n.containers[w] = prefix + ".workload." + w
		}
	}
	return n
}

func (x *releaseRehearsal) cleanup(ctx context.Context, out io.Writer) error {
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	if err := checkScratchRemoval(ctx, e, x.names, x.candidate.App); err != nil {
		return err
	}
	var failures []error
	for _, name := range sortedKeys(x.names.containers) {
		failures = append(failures, e.Remove(ctx, x.names.containers[name], 5*time.Second))
	}
	failures = append(failures, e.Remove(ctx, x.names.postgres, 10*time.Second), e.Remove(ctx, x.names.objects, 10*time.Second))
	if err := errors.Join(failures...); err != nil {
		return err // Keep restored data and staging until all writers are gone.
	}
	failures = append(failures, e.RemoveNetwork(ctx, x.names.network))
	_, err = e.RemoveVolume(ctx, x.names.postgresVolume)
	failures = append(failures, err)
	for _, name := range sortedKeys(x.names.volumes) {
		_, err := e.RemoveVolume(ctx, x.names.volumes[name])
		failures = append(failures, err)
	}
	images, err := e.OwnedImages(ctx)
	failures = append(failures, err)
	for _, group := range buildGroups(x.candidate) {
		name := group[0]
		w := x.candidate.Workloads[name]
		if w.Build != nil || w.Kind == manifest.Static {
			ref := docker.ImageRef(x.candidate.App, name, "rehearse-"+x.input.Revision)
			for _, image := range images {
				if slices.Contains(image.Tags, ref) && image.Labels[docker.LabelApp] == x.candidate.App && image.Labels[docker.LabelWorkload] == name && image.Labels[docker.LabelRevision] == x.input.Revision {
					failures = append(failures, e.RemoveImage(ctx, ref))
				}
			}
		}
	}
	failures = append(failures, os.RemoveAll(x.workspace))
	if errors.Join(failures...) == nil {
		if err := os.Remove(x.reservation); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	fmt.Fprintln(out, "rehearsal scratch resources removed")
	return nil
}

func (x *releaseRehearsal) abort(ctx context.Context, out io.Writer) error {
	cleanupErr := x.cleanup(ctx, out)
	data, err := os.ReadFile(x.report)
	if err == nil {
		var proof RehearsalProof
		if json.Unmarshal(data, &proof) == nil && proof.Status != "started" {
			return cleanupErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cleanupErr, err)
	}
	x.proof.Status = "failed"
	x.proof.Error = "rehearsal was interrupted; scratch resources were removed"
	if cleanupErr != nil {
		x.proof.Error = "rehearsal was interrupted; scratch cleanup failed"
	}
	x.proof.FinishedAt = time.Now().UTC()
	return errors.Join(cleanupErr, writeRehearsalJSON(x.report, x.proof))
}

func (x *releaseRehearsal) run(ctx context.Context, out io.Writer) (result error) {
	x.proof.StartedAt = time.Now().UTC()
	var rehearsalRun *backupRun
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		result = errors.Join(result, x.cleanup(cleanup, out))
		x.proof.FinishedAt = time.Now().UTC()
		x.proof.Status = "passed"
		if result != nil {
			if rehearsalRun != nil {
				result = rehearsalRun.fail(result)
			}
			x.proof.Status = "failed"
			x.proof.Error = result.Error()
			for _, value := range x.redactions {
				x.proof.Error = strings.ReplaceAll(x.proof.Error, value, "[redacted]")
			}
		}
		result = errors.Join(result, writeRehearsalJSON(x.report, x.proof))
		fmt.Fprintf(out, "rehearsal proof: %s\n", x.report)
	}()
	originalHash, err := rehearsalSourceHash(x.input.Source)
	if err != nil {
		return err
	}
	if originalHash != x.proof.SourceSHA256 {
		return errors.New("candidate source changed after planning; plan the rehearsal again")
	}
	source := filepath.Join(x.workspace, "source")
	if err := copyRehearsalSource(x.input.Source, source); err != nil {
		return err
	}
	copiedHash, err := rehearsalSourceHash(source)
	if err != nil {
		return err
	}
	if copiedHash != originalHash {
		return errors.New("candidate source changed while being captured; plan the rehearsal again")
	}
	scratchSecrets, err := copyPinnedRehearsalSecrets(x.def.Secrets, x.active, x.workspace)
	if err != nil {
		return err
	}
	for _, app := range []string{x.candidate.App, manifest.ReservedApp} {
		values, _, err := scratchSecrets.LoadCurrent(app)
		if err != nil {
			return err
		}
		for _, value := range values {
			if len(value) >= 4 {
				x.redactions = append(x.redactions, value)
			}
		}
	}
	if err := ensureAppSecrets(scratchSecrets, x.candidate, out); err != nil {
		return err
	}
	values, version, err := scratchSecrets.LoadCurrent(x.candidate.App)
	if err != nil {
		return err
	}
	for _, value := range values {
		if len(value) >= 4 {
			x.redactions = append(x.redactions, value)
		}
	}
	candidateJSON, _ := json.Marshal(x.candidate)
	rev := &state.Revision{App: x.candidate.App, ID: x.input.Revision, Manifest: candidateJSON, SecretsVersion: version, Images: x.proof.Images}
	d := &drillState{dr: Drill{Store: x.def.Store, Secrets: scratchSecrets, StateDir: x.def.StateDir}, app: x.candidate.App, snapshot: x.input.Snapshot, rev: rev, m: *x.candidate,
		run: &backupRun{store: x.def.Store, app: x.candidate.App, kind: "rehearse"}, names: x.names, advice: "free space and rehearse again"}
	rehearsalRun = d.run
	// Only long-running workloads belong to the startup step. Release containers
	// are tracked separately so cleanup can remove interrupted release jobs too.
	if err := d.restoreStep().Apply(ctx, out); err != nil {
		return err
	}
	x.proof.Snapshot = d.found.ID
	if err := writeRehearsalJSON(x.report, x.proof); err != nil {
		return err
	}
	if x.candidate.PostgresVersion() != "" {
		if err := d.databaseStep().Apply(ctx, out); err != nil {
			return err
		}
	}
	if x.candidate.HasObjects() {
		if err := d.objectsStep().Apply(ctx, out); err != nil {
			return err
		}
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	if err := e.EnsureInternalNetwork(ctx, x.names.network); err != nil {
		return err
	}
	if err := x.build(ctx, e, source, out); err != nil {
		return err
	}
	jobs := NewJobs(x.def.Store, scratchSecrets)
	for _, name := range x.candidate.ReleaseWorkloads() {
		spec, err := rehearsalReleaseSpec(x.candidate, x.input.Revision, name, x.proof.Images[name], values, x.names)
		if err != nil {
			return err
		}
		w := x.candidate.Workloads[name]
		user, err := isolate(ctx, e, &spec, w, spec.Image)
		if err != nil {
			return err
		}
		if err := restoredWritable(name, w, user, x.names.volumes, func(v string) (string, error) { return e.VolumeMountpoint(ctx, v) }); err != nil {
			return err
		}
		timeout := time.Hour
		if w.Timeout != "" {
			timeout, _ = time.ParseDuration(w.Timeout)
		}
		releaseCtx, cancel := context.WithTimeout(ctx, timeout)
		_, err = jobs.execute(releaseCtx, e, spec, out)
		cancel()
		if err != nil {
			return fmt.Errorf("scratch release %s failed: %w; live data was not mounted", name, err)
		}
		x.proof.Releases = append(x.proof.Releases, name)
		if err := writeRehearsalJSON(x.report, x.proof); err != nil {
			return err
		}
	}
	long := map[string]string{}
	for _, name := range x.candidate.WorkloadNames() {
		if x.candidate.Workloads[name].LongRunning() {
			long[name] = x.names.containers[name]
		}
	}
	d.names.containers = long
	if len(long) > 0 {
		if err := d.appStep().Apply(ctx, out); err != nil {
			return err
		}
	}
	for _, check := range verificationChecks(x.candidate).application {
		if err := runCheckDirect(ctx, e, x.candidate, long, check); err != nil {
			return d.run.fail(fmt.Errorf("candidate on restored data: %w", err))
		}
	}
	if len(verificationChecks(x.candidate).edge) > 0 {
		fmt.Fprintln(out, "public edge checks are deferred until deployment; scratch routes were not published")
	}
	return d.run.done(ctx, state.BackupRun{Snapshot: d.found.ID, SnapshotAt: d.found.Time, Detail: "candidate releases and application checks passed on isolated restored data"})
}

func (x *releaseRehearsal) build(ctx context.Context, e *docker.Engine, source string, out io.Writer) error {
	for _, group := range buildGroups(x.candidate) {
		name := group[0]
		w := x.candidate.Workloads[name]
		image := w.Image
		if w.Build != nil || w.Kind == manifest.Static {
			image = docker.ImageRef(x.candidate.App, name, "rehearse-"+x.input.Revision)
			spec := docker.BuildSpec{Ref: image, Labels: imageLabels(x.candidate.App, name, x.input.Revision)}
			if w.Kind == manifest.Static {
				context, err := docker.StaticContext(source, w.Dir)
				if err != nil {
					return err
				}
				defer os.RemoveAll(context)
				spec.Context = context
			} else {
				spec.Context = filepath.Join(source, orDot(w.Build.Context))
				spec.Dockerfile = w.Build.Dockerfile
				spec.Target = w.Build.Target
				spec.Args = w.Build.Args
			}
			if err := docker.Build(ctx, spec, filtered(out)); err != nil {
				return err
			}
		} else if !e.HasImage(ctx, image) {
			if err := e.Pull(ctx, image, out); err != nil {
				return err
			}
		}
		digest, err := e.Digest(ctx, image)
		if err != nil {
			return err
		}
		for _, workload := range group {
			x.proof.Images[workload] = digest
		}
	}
	return writeRehearsalJSON(x.report, x.proof)
}

func rehearsalReleaseSpec(m *manifest.Manifest, revision, name, image string, values map[string]string, names drillNames) (docker.Spec, error) {
	spec, err := drillSpec(m, revision, name, image, values, names)
	if err != nil {
		return spec, err
	}
	spec.Aliases = nil
	if spec.Name == "" || spec.Networks[0] == docker.AppNetwork(m.App) {
		return spec, errors.New("release rehearsal needs a private scratch identity")
	}
	return spec, nil
}

func writeRehearsalJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".proof-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncMigrationDir(filepath.Dir(path))
}

func rehearsalSourceHash(root string) (string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !rootInfo.IsDir() {
		return "", errors.New("candidate source must be a plain directory")
	}
	hash := sha256.New()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(hash, "%s\x00%o\x00", rel, info.Mode().Perm())
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("candidate source %s is not a plain file; capture a source tree without links or devices", rel)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		io.WriteString(hash, "\x00")
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyRehearsalSource(from, to string) error {
	type directoryMode struct {
		path string
		mode fs.FileMode
	}
	var directories []directoryMode
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(to, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if err := os.MkdirAll(dest, 0o700); err != nil {
				return err
			}
			directories = append(directories, directoryMode{dest, info.Mode().Perm()})
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source %s is not a plain file", rel)
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		modeErr := dst.Chmod(info.Mode().Perm())
		return errors.Join(copyErr, modeErr, dst.Close(), src.Close())
	})
	if err != nil {
		return err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := os.Chmod(directories[i].path, directories[i].mode); err != nil {
			return err
		}
	}
	return nil
}

// A rehearsal or checkpoint restore reads exactly the target's original
// credentials from a separate encrypted store. It cannot rotate live secrets.
func copyPinnedRehearsalSecrets(source *secrets.Store, revision *state.Revision, workspace string) (*secrets.Store, error) {
	store := &secrets.Store{Dir: filepath.Join(workspace, "secrets"), KeyPath: filepath.Join(workspace, "key")}
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(store.Dir); err != nil {
		return nil, err
	}
	if err := os.Remove(store.KeyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, _, _, err := store.EnsureKey(); err != nil {
		return nil, err
	}
	for _, app := range []string{revision.App, manifest.ReservedApp} {
		version := revision.SecretsVersion
		if app == manifest.ReservedApp {
			var err error
			version, err = source.Current(app)
			if err != nil {
				return nil, err
			}
		}
		values, err := source.Load(app, version)
		if err != nil {
			return nil, err
		}
		changes := map[string]*string{}
		for name, value := range values {
			changes[name] = new(value)
		}
		if _, err := store.SetAll(app, changes); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// RehearsalProofPath exposes the durable, credential-free proof to the CLI.
func RehearsalProofPath(stateDir, app, revision string) string {
	if stateDir == "" {
		stateDir = defaultStateDir
	}
	return filepath.Join(stateDir, "rehearsals", app, revision+".json")
}

// ReadRehearsalProof validates its identity before returning a saved report.
func ReadRehearsalProof(stateDir, app, revision string) (*RehearsalProof, error) {
	if !manifest.ValidApp(app) || !revisionPattern.MatchString(revision) {
		return nil, errors.New("invalid rehearsal app or candidate revision")
	}
	path := RehearsalProofPath(stateDir, app, revision)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("rehearsal proof must be a plain file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var proof RehearsalProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}
	if proof.App != app || proof.Revision != revision {
		return nil, errors.New("rehearsal proof identity does not match its location")
	}
	return &proof, nil
}
