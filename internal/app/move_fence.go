package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
)

type migrationWriter struct {
	ID      string               `json:"id"`
	Name    string               `json:"name"`
	Grace   time.Duration        `json:"grace"`
	Running bool                 `json:"running"`
	Objects bool                 `json:"objects,omitempty"`
	Policy  docker.RestartPolicy `json:"restart_policy"`
}

type migrationRecord struct {
	Handoff          Handoff           `json:"handoff"`
	Role             string            `json:"role"`
	Phase            string            `json:"phase"`
	TargetRevision   string            `json:"target_revision,omitempty"`
	Writers          []migrationWriter `json:"writers,omitempty"`
	RestoringVolumes map[string]bool   `json:"restoring_volumes,omitempty"`
	RestoredVolumes  map[string]bool   `json:"restored_volumes,omitempty"`
	DatabaseStarted  bool              `json:"database_started,omitempty"`
	DatabaseRestored bool              `json:"database_restored,omitempty"`
	LiveContainers   map[string]bool   `json:"live_containers,omitempty"`
}

func migrationFile(stateFile, app string) string {
	return filepath.Join(filepath.Dir(stateFile), "locks", app+".migration.json")
}

func readMigration(stateFile, app string) (*migrationRecord, error) {
	data, err := os.ReadFile(migrationFile(stateFile, app))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record migrationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("read %s migration fence: %w", app, err)
	}
	h := record.Handoff
	valid := h.App == app && manifest.ValidApp(app) && h.Phase == "final" && migrationIDPattern.MatchString(h.Migration) &&
		h.From != "" && h.To != "" && h.From != h.To && h.Revision != "" && snapshotIDPattern.MatchString(h.ManifestDigest)
	switch record.Role {
	case "source":
		valid = valid && (record.Phase == "fencing" || record.Phase == "fenced" || record.Phase == "captured")
		if h.HasData && record.Phase == "captured" {
			valid = valid && snapshotIDPattern.MatchString(h.Snapshot)
		}
	case "target":
		valid = valid && revisionPattern.MatchString(record.TargetRevision) &&
			(record.Phase == "restoring" || record.Phase == "staged" || record.Phase == "cutting-over" || record.Phase == "cutover")
		if h.HasData {
			valid = valid && snapshotIDPattern.MatchString(h.Snapshot)
		}
	default:
		valid = false
	}
	if h.HasData {
		valid = valid && h.Bucket != ""
	}
	if !valid {
		return nil, fmt.Errorf("%s has an invalid migration fence; repair it before admitting writers", app)
	}
	return &record, nil
}

// CheckMigrationAccess refuses all new operator commands, jobs, deploys and
// rollbacks while a migration fence exists. A cut-over target admits writers.
func CheckMigrationAccess(stateFile, app string) error {
	record, err := readMigration(stateFile, app)
	if err != nil {
		return err
	}
	if record == nil || record.Role == "target" && record.Phase == "cutover" {
		return nil
	}
	return fmt.Errorf("%s is fenced for migration %s (%s); use helios move resume deliberately on the source, or finish target cutover", app, record.Handoff.Migration, record.Role)
}

func saveMigration(stateFile string, record *migrationRecord) error {
	return writeMigrationRecord(migrationFile(stateFile, record.Handoff.App), record)
}

func writeMigrationRecord(file string, record *migrationRecord) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(file), ".migration-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), file); err != nil {
		return err
	}
	return syncMigrationDir(filepath.Dir(file))
}

func syncMigrationDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type migrationEngine interface {
	quiesceEngine
	RestartPolicy(context.Context, string) (docker.RestartPolicy, error)
	SetRestartPolicy(context.Context, string, docker.RestartPolicy) error
}

func sameMigration(a, b Handoff) bool {
	return a.App == b.App && a.Migration == b.Migration && a.From == b.From && a.To == b.To &&
		a.Revision == b.Revision && a.ManifestDigest == b.ManifestDigest && a.SourceCommit == b.SourceCommit &&
		a.Phase == b.Phase && a.HasData == b.HasData && a.Bucket == b.Bucket
}

// fenceMigration drains commands under the exclusive data lock, persists all
// writer identities and restart policies, and leaves them stopped on failure.
// Recovery reasserts the fence; it never resumes the source automatically.
func fenceMigration(ctx context.Context, e migrationEngine, stateFile string, m *manifest.Manifest, h Handoff, out io.Writer) error {
	unlock, err := lockAppData(ctx, stateFile, m.App, true)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := readMigration(stateFile, m.App)
	if err != nil {
		return err
	}
	var completed *migrationRecord
	if record != nil && record.Role == "target" && record.Phase == "cutover" {
		// A completed destination may become the source of a reverse move.
		// Archive its old cutover before installing a new source fence.
		completed, record = record, nil
	}
	if record != nil {
		if record.Role != "source" || !sameMigration(record.Handoff, h) {
			return fmt.Errorf("%s is already fenced for another migration", m.App)
		}
		return enforceMigration(ctx, e, record)
	}
	if _, err := os.Stat(quiesceFile(stateFile, m.App)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s has an unfinished backup pause; recover it before final capture", m.App)
	}
	containers, err := e.Owned(ctx)
	if err != nil {
		return err
	}
	record = &migrationRecord{Handoff: h, Role: "source", Phase: "fencing"}
	for _, c := range containers {
		if c.Labels[docker.LabelApp] != m.App || c.Labels[docker.LabelWorkload] == postgresWorkload {
			continue
		}
		role := c.Labels[docker.LabelWorkload]
		grace := time.Minute
		if w, ok := m.Workloads[role]; ok {
			grace = w.GraceOr(time.Minute)
		} else if role != objectsWorkload && !strings.Contains(c.Name, "-job-") {
			return fmt.Errorf("cannot fence unknown writer %s", c.Name)
		}
		policy, err := e.RestartPolicy(ctx, c.ID)
		if err != nil {
			return err
		}
		record.Writers = append(record.Writers, migrationWriter{ID: c.ID, Name: c.Name, Grace: grace, Running: c.Running, Objects: role == objectsWorkload, Policy: policy})
	}
	sort.SliceStable(record.Writers, func(i, j int) bool { return !record.Writers[i].Objects && record.Writers[j].Objects })
	if completed != nil {
		archive := filepath.Join(filepath.Dir(stateFile), "moves", m.App, "completed", completed.Handoff.Migration+".json")
		if err := writeMigrationRecord(archive, completed); err != nil {
			return err
		}
	}
	if err := saveMigration(stateFile, record); err != nil {
		return err
	}
	if err := enforceMigration(ctx, e, record); err != nil {
		return err
	}
	record.Phase = "fenced"
	if err := saveMigration(stateFile, record); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d source writers fenced; restart policies disabled and source remains stopped until deliberate resume\n", len(record.Writers))
	return nil
}

func enforceMigration(ctx context.Context, e migrationEngine, record *migrationRecord) error {
	err := enforceMigrationWriters(ctx, e, record, true)
	if ctx.Err() == nil {
		return err
	}
	// Once the fence is durable, cancellation must not leave the remaining
	// writers running or able to restart. Keep the cancellation result and
	// retry their stops with a bounded context, without ever resuming them.
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return errors.Join(ctx.Err(), err, enforceMigrationWriters(cleanup, e, record, true))
}

func enforceMigrationWriters(ctx context.Context, e migrationEngine, record *migrationRecord, requireCleanStop bool) error {
	var failures []error
	// Disable every automatic restart before stopping writers. One writer's
	// failure must not leave the remaining writers accepting new data.
	for _, writer := range record.Writers {
		if err := e.SetRestartPolicy(ctx, writer.ID, docker.RestartPolicy{Name: "no"}); err != nil && !docker.IsNotFound(err) {
			failures = append(failures, fmt.Errorf("disable source writer %s restart: %w", writer.Name, err))
		}
	}
	for _, writer := range record.Writers {
		info, err := e.Inspect(ctx, writer.ID)
		if docker.IsNotFound(err) {
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if info.Running {
			if err := e.Stop(ctx, writer.ID, writer.Grace); err != nil {
				failures = append(failures, fmt.Errorf("stop source writer %s: %w", writer.Name, err))
			}
			info, err = e.Inspect(ctx, writer.ID)
			if err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if info.Running {
			failures = append(failures, fmt.Errorf("source writer %s is still running behind its migration fence", writer.Name))
		} else if requireCleanStop && info.ExitCode == 137 {
			failures = append(failures, fmt.Errorf("source writer %s did not stop cleanly; no final snapshot is safe", writer.Name))
		}
	}
	return errors.Join(failures...)
}

// EnforceMigrationFences runs before startup job and operation recovery. It
// disables any reintroduced Docker restart policy and stops surviving source
// writers, retaining every fence until an explicit operator action.
func EnforceMigrationFences(ctx context.Context, stateFile string) error {
	files, err := filepath.Glob(filepath.Join(filepath.Dir(stateFile), "locks", "*.migration.json"))
	if err != nil || len(files) == 0 {
		return err
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	for _, file := range files {
		app := strings.TrimSuffix(filepath.Base(file), ".migration.json")
		record, err := readMigration(stateFile, app)
		if err != nil {
			return err
		}
		if record.Role != "source" {
			continue
		}
		unlock, err := lockAppData(ctx, stateFile, app, true)
		if err != nil {
			return err
		}
		// A stopped writer's old exit status cannot admit writes. Allow
		// daemon startup so an operator can explicitly resume or remove
		// an unclean source; final captures still require clean stops.
		err = enforceMigrationWriters(ctx, e, record, false)
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// MigrationSourceFenced distinguishes an intentional source fence from an
// unreadable record, so startup backup recovery never conceals corruption.
func MigrationSourceFenced(stateFile, app string) (bool, error) {
	record, err := readMigration(stateFile, app)
	if err != nil {
		return false, err
	}
	return record != nil && record.Role == "source", nil
}
