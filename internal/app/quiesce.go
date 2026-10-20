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

	"golang.org/x/sys/unix"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
)

// Jobs hold a shared lock for their entire lifetime, including cleanup. Backups
// take the exclusive lock before stopping writers. A file lock also covers CLI
// jobs with stdin, which run outside the daemon process and its operation lock.
func lockAppData(ctx context.Context, stateFile, app string, exclusive bool) (func(), error) {
	if app != manifest.ReservedApp && !manifest.ValidApp(app) {
		return nil, fmt.Errorf("%q is not a valid app name", app)
	}
	dir := filepath.Join(filepath.Dir(stateFile), "locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, app+".data.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	for {
		err = unix.Flock(int(f.Fd()), mode|unix.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// BackupPauseLimit is the longest a backup keeps an app's writers stopped.
const BackupPauseLimit = 30 * time.Minute

func quiesceFile(stateFile, app string) string {
	return filepath.Join(filepath.Dir(stateFile), "locks", app+".quiesce.json")
}

// BackupPause is a backup that has stopped an app's writers, and since
// when: the recovery record is written once, before the first stop.
type BackupPause struct {
	Since   time.Time
	writers []pausedWriter
}

// Holds reports whether the pause stopped a container, named by its ID
// or its name.
func (p *BackupPause) Holds(id, name string) bool {
	for _, w := range p.writers {
		if id != "" && w.ID == id || name != "" && w.Name == name {
			return true
		}
	}
	return false
}

// ReadBackupPause returns the app's backup pause, or nil when its writers
// aren't paused.
func ReadBackupPause(stateFile, app string) (*BackupPause, error) {
	file := quiesceFile(stateFile, app)
	info, err := os.Stat(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var writers []pausedWriter
	if err := json.Unmarshal(data, &writers); err != nil {
		return nil, fmt.Errorf("read backup recovery record: %w", err)
	}
	return &BackupPause{Since: info.ModTime().UTC(), writers: writers}, nil
}

// AcquireDataAccess protects operator commands and jobs from a backup pause.
func AcquireDataAccess(ctx context.Context, stateFile, app string) (func(), error) {
	unlock, err := lockAppData(ctx, stateFile, app, false)
	if err != nil {
		return nil, err
	}
	if err := CheckMachineRecoveryWriteAccess(stateFile); err != nil {
		unlock()
		return nil, err
	}
	if err := CheckMigrationAccess(stateFile, app); err != nil {
		unlock()
		return nil, err
	}
	if err := CheckReleaseDataAccess(ctx, stateFile, app); err != nil {
		unlock()
		return nil, err
	}
	if _, err := os.Stat(quiesceFile(stateFile, app)); !errors.Is(err, os.ErrNotExist) {
		unlock()
		return nil, fmt.Errorf("%s has an unfinished backup pause; recover the backup before running commands", app)
	}
	return unlock, nil
}

// RecoverBackupPauses restores availability before the daemon admits any jobs
// or recovers operations, even when an old operation's lease has not expired.
func RecoverBackupPauses(ctx context.Context, stateFile string) error {
	files, err := filepath.Glob(filepath.Join(filepath.Dir(stateFile), "locks", "*.quiesce.json"))
	if err != nil || len(files) == 0 {
		return err
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	for _, file := range files {
		app := strings.TrimSuffix(filepath.Base(file), ".quiesce.json")
		fenced, err := MigrationSourceFenced(stateFile, app)
		if err != nil {
			return err
		}
		if fenced {
			continue
		}
		if err := CheckReleaseDataAccess(ctx, stateFile, app); err != nil {
			if errors.Is(err, ErrReleaseRestorePending) {
				continue
			}
			return err
		}
		unlock, err := lockAppData(ctx, stateFile, app, true)
		if err != nil {
			return err
		}
		err = resumeWriters(ctx, e, file)
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

type quiesceEngine interface {
	Owned(context.Context) ([]docker.Info, error)
	Inspect(context.Context, string) (*docker.Info, error)
	Stop(context.Context, string, time.Duration) error
	Start(context.Context, string) error
}

type pausedWriter struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Grace   time.Duration `json:"grace"`
	Objects bool          `json:"objects,omitempty"`
}

// Persist before the first stop. fsync both file and directory so a machine
// interruption cannot leave stopped writers without their recovery record.
func savePausedWriters(file string, writers []pausedWriter) error {
	data, err := json.Marshal(writers)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(file), ".quiesce-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), file); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(file))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func resumeWriters(ctx context.Context, e quiesceEngine, file string) error {
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var writers []pausedWriter
	if err = json.Unmarshal(data, &writers); err != nil {
		return fmt.Errorf("read backup recovery record: %w", err)
	}
	// The object store must be available before its clients restart.
	sort.SliceStable(writers, func(i, j int) bool { return writers[i].Objects && !writers[j].Objects })
	var failures []error
	for _, w := range writers {
		info, err := e.Inspect(ctx, w.ID)
		if err == nil && !info.Running {
			err = e.Start(ctx, w.ID)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("restart %s after backup: %w", w.Name, err))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	return os.Remove(file)
}

// withQuiescedWriters is one recoverable capture step. It never backs up live
// volume files. A failed or cancelled capture resumes under a fresh context;
// replay after daemon death first repairs the persisted previous pause.
func withQuiescedWriters(ctx context.Context, e quiesceEngine, stateFile string, m *manifest.Manifest, out io.Writer, capture func(context.Context) error) (result error) {
	ctx, cancel := context.WithTimeout(ctx, BackupPauseLimit)
	defer cancel()
	unlock, err := lockAppData(ctx, stateFile, m.App, true)
	if err != nil {
		return err
	}
	defer unlock()
	file := quiesceFile(stateFile, m.App)
	if err := resumeWriters(ctx, e, file); err != nil {
		return err
	}
	containers, err := e.Owned(ctx)
	if err != nil {
		return err
	}
	var writers []pausedWriter
	for _, c := range containers {
		if c.Labels[docker.LabelApp] != m.App || !c.Running {
			continue
		}
		if strings.Contains(c.Name, "-job-") {
			return fmt.Errorf("orphaned job %s is still running; finish it before backing up", c.Name)
		}
		role := c.Labels[docker.LabelWorkload]
		if role == postgresWorkload {
			continue
		}
		grace := time.Minute
		if w, ok := m.Workloads[role]; ok {
			if !w.LongRunning() {
				return fmt.Errorf("%s is still running; retry the backup after its job finishes", c.Name)
			}
			grace = w.GraceOr(time.Minute)
		} else if role != objectsWorkload {
			return fmt.Errorf("cannot quiesce unknown writer %s", c.Name)
		}
		writers = append(writers, pausedWriter{ID: c.ID, Name: c.Name, Grace: grace, Objects: role == objectsWorkload})
	}
	// Drain the clients before shutting down MinIO.
	sort.SliceStable(writers, func(i, j int) bool { return !writers[i].Objects && writers[j].Objects })
	if err := savePausedWriters(file, writers); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		result = errors.Join(result, resumeWriters(cleanup, e, file))
	}()
	for _, w := range writers {
		if err := e.Stop(ctx, w.ID, w.Grace); err != nil {
			return err
		}
		info, err := e.Inspect(ctx, w.ID)
		if err != nil {
			return err
		}
		if info.Running || info.ExitCode == 137 {
			return fmt.Errorf("%s did not stop cleanly; no backup was captured", w.Name)
		}
	}
	fmt.Fprintf(out, "%d writers stopped; capturing a consistent database and volume snapshot\n", len(writers))
	return capture(ctx)
}
