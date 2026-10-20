// Package restic drives restic in a container: one repository per app in
// its own bucket, encrypted with the machine's backup password. helios
// mounts what to back up under /data and restores back into the same
// places, so a snapshot's paths mean the same thing on every machine.
package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
)

// Image is restic, pinned by digest.
const Image = "restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510"

// CacheVolume keeps restic's index cache between runs, for every repository.
const CacheVolume = "bedrock-restic-cache"

// DataRoot is where the backed-up tree sits inside the container.
const DataRoot = "/data"

// Tag marks snapshots helios made.
const Tag = "bedrock"

// ReleaseCheckpointTag keeps explicit rollback points beyond ordinary retention.
const ReleaseCheckpointTag = "bedrock-release-checkpoint"

// Repo is one repository and how to open it.
type Repo struct {
	// Repository is restic's repository string, such as b2:bucket:/ .
	Repository string
	// Password encrypts the repository.
	Password string
	// Env carries the storage credentials, as restic reads them.
	Env []string
}

// Runner runs restic for one app.
type Runner struct {
	Engine *docker.Engine
	Repo   Repo
	// Owner is the app the containers are labeled with.
	Owner string
	// BackupTags are additional tags applied when capturing a snapshot.
	BackupTags []string
	// Log receives restic's lines, when set.
	Log func(line string)
	// Deadlines bound the calls a backup makes; a zero field takes its
	// default.
	Deadlines Deadlines
}

// Default deadlines for the repository calls a backup makes while it holds
// the machine's operation lock. They are generous for real data and slow
// links, but finite: a call that outlives one is stopped, so a repository
// or network that stops answering cannot hold every later backup and deploy.
const (
	// EnsureTimeout bounds init, which fails at once on an existing
	// repository and otherwise only creates a bucket and a few files.
	EnsureTimeout = 5 * time.Minute
	// UnlockTimeout bounds clearing stale locks, a list and a few deletes.
	UnlockTimeout = 5 * time.Minute
	// BackupTimeout bounds one upload. An app's capture is also inside its
	// 30 minute maintenance window, whichever ends first.
	BackupTimeout = 2 * time.Hour
	// ForgetTimeout bounds forgetting snapshots the policy no longer keeps,
	// which reads the snapshot list and deletes a few files.
	ForgetTimeout = 15 * time.Minute
	// PruneTimeout bounds the prune that frees what forgotten snapshots
	// used. PruneMaxRepack keeps one prune's rewriting small enough to
	// finish inside it, so successive prunes make progress.
	PruneTimeout = time.Hour
	// RestoreTimeout bounds a restore a backup makes, such as a machine
	// backup copying an app's pinned snapshot into itself. A restore an
	// operator asks for has no limit unless its runner sets one.
	RestoreTimeout = 2 * time.Hour
)

// PruneMaxRepack is how much data one prune may rewrite. restic leaves
// the rest for the next prune; packs that are wholly unused are deleted
// whatever their size.
const PruneMaxRepack = "2G"

// Deadlines bound individual repository calls. A zero field takes its
// default, except Restore: zero leaves a restore unbounded. Tests shorten
// them.
type Deadlines struct {
	Ensure, Unlock, Backup, Forget, Prune, Restore time.Duration
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// DeadlineError is a repository call that ran out of time and was stopped.
// It matches context.DeadlineExceeded with errors.Is.
type DeadlineError struct {
	Action string
	Limit  time.Duration
	// Err is what the stopped run returned, including any cleanup failure.
	Err error
}

func (e *DeadlineError) Error() string {
	msg := fmt.Sprintf("restic %s did not finish within %s and was stopped", e.Action, e.Limit)
	if e.Err != nil && e.Err.Error() != context.DeadlineExceeded.Error() {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *DeadlineError) Unwrap() []error { return []error{context.DeadlineExceeded, e.Err} }

// errCallDeadline is the cause bounded gives a call's own deadline, which
// tells it apart from the caller's cancellation or deadline.
var errCallDeadline = errors.New("restic call deadline")

// bounded runs restic under its own deadline. Running out of that deadline
// is reported as a DeadlineError; the caller's own cancellation or deadline
// is not.
func (r Runner) bounded(ctx context.Context, limit time.Duration, mounts []string, args ...string) ([]string, error) {
	callCtx, cancel := context.WithTimeoutCause(ctx, limit, errCallDeadline)
	defer cancel()
	lines, err := r.run(callCtx, mounts, args...)
	if err != nil && errors.Is(context.Cause(callCtx), errCallDeadline) {
		return lines, &DeadlineError{Action: args[0], Limit: limit, Err: err}
	}
	return lines, err
}

// Summary is what restic reports after a backup.
type Summary struct {
	SnapshotID      string    `json:"snapshot_id"`
	FilesNew        int64     `json:"files_new"`
	FilesChanged    int64     `json:"files_changed"`
	FilesUnmodified int64     `json:"files_unmodified"`
	DataAdded       int64     `json:"data_added"`
	TotalFiles      int64     `json:"total_files_processed"`
	TotalBytes      int64     `json:"total_bytes_processed"`
	BackupStart     time.Time `json:"backup_start"`
	BackupEnd       time.Time `json:"backup_end"`
}

// Snapshot is one restic snapshot.
type Snapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Paths    []string  `json:"paths"`
	Hostname string    `json:"hostname"`
	Tags     []string  `json:"tags"`
	Summary  *Summary  `json:"summary,omitempty"`
}

// RestoreSummary contains restic's restore progress counters. Selected
// ancestor directories and files skipped on retry are accounted differently,
// so the file counts cannot establish restore completeness.
type RestoreSummary struct {
	TotalFiles    int64 `json:"total_files"`
	FilesRestored int64 `json:"files_restored"`
	TotalBytes    int64 `json:"total_bytes"`
	BytesRestored int64 `json:"bytes_restored"`
}

// Keep is a retention policy.
type Keep struct {
	Daily, Weekly, Monthly int
}

// ErrNoRepository means the bucket holds no repository yet.
var ErrNoRepository = errors.New("no repository")

// secretsInside is where the repository's password and the storage
// credentials are mounted in a restic container.
const secretsInside = "/run/bedrock-restic"

// run executes restic with the mounts and returns its output lines.
//
// The repository's password and the storage credentials never go in the
// container's environment, which Docker keeps in the container's config on
// disk and shows to anyone who can inspect it. They go in a file only root
// reads, mounted read-only, which a shell reads before it becomes restic,
// and the file is gone when the run is.
func (r Runner) run(ctx context.Context, mounts []string, args ...string) ([]string, error) {
	secrets, err := secretsFile(append([]string{"RESTIC_PASSWORD=" + r.Repo.Password}, r.Repo.Env...))
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(secrets)
	spec := docker.Spec{
		Name:        "bedrock-" + r.Owner + "-restic-" + strings.TrimPrefix(filepath.Base(secrets), "bedrock-restic-"),
		Image:       Image,
		Entrypoint:  []string{"/bin/sh", "-c", `set -a && . ` + secretsInside + `/env && set +a && exec /usr/bin/restic "$@"`, "restic"},
		Cmd:         args,
		Env:         []string{"RESTIC_REPOSITORY=" + r.Repo.Repository, "RESTIC_CACHE_DIR=/cache"},
		Labels:      map[string]string{docker.LabelApp: r.Owner, docker.LabelWorkload: "backup"},
		Mounts:      append(append([]string{}, mounts...), CacheVolume+":/cache", secrets+":"+secretsInside+":ro"),
		HostNetwork: true,
	}
	e := r.Engine
	if !e.HasImage(ctx, Image) {
		if err := e.Pull(ctx, Image, nopWriter{}); err != nil {
			return nil, err
		}
	}
	if err := e.Run(ctx, spec); err != nil {
		lines, cleanupErr := finish(e, spec, graceFor(ctx))
		return lines, errors.Join(err, cleanupErr)
	}
	code, waitErr := e.WaitExit(ctx, spec.Name)
	// The wait may have taken an hour, or ended with ctx. The container's
	// last words and its removal get a context of their own, made now: one
	// made before the wait would have been spent by it.
	lines, cleanupErr := finish(e, spec, graceFor(ctx))
	if waitErr != nil {
		return lines, errors.Join(waitErr, cleanupErr)
	}
	if r.Log != nil {
		for _, l := range lines {
			if l != "" && !strings.Contains(l, `"message_type":"status"`) {
				r.Log(l)
			}
		}
	}
	if code != 0 {
		failure := &commandError{action: args[0], reason: explain(lines)}
		if cleanupErr != nil {
			return lines, errors.Join(failure, cleanupErr)
		}
		return lines, failure
	}
	return lines, cleanupErr
}

// secretsFile writes NAME=value pairs where only this machine's root reads
// them, as a shell reads assignments, and returns the directory holding
// the file. The caller removes it.
func secretsFile(pairs []string) (string, error) {
	dir, err := os.MkdirTemp("", "bedrock-restic-")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || !shellName.MatchString(name) || strings.ContainsRune(value, 0) {
			os.RemoveAll(dir)
			return "", errors.New("restic credentials must be valid shell NAME=value assignments")
		}
		// Single quotes hold anything but a single quote, which is closed,
		// escaped and reopened.
		fmt.Fprintf(&b, "%s='%s'\n", name, strings.ReplaceAll(value, "'", `'\''`))
	}
	if err := os.WriteFile(filepath.Join(dir, "env"), []byte(b.String()), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

var shellName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type commandError struct {
	action, reason string
}

func (e *commandError) Error() string { return fmt.Sprintf("restic %s: %s", e.action, e.reason) }

// stopGrace is how long a restic helper still running when its call's own
// deadline ended has to stop before it is killed. restic treats SIGTERM as
// an interruption: it cancels its work and then spends up to a minute of
// its own removing its repository lock. A helper that already exited is
// removed at once.
const stopGrace = time.Minute

// shutdownStopGrace is the grace when the caller went away instead, as a
// daemon stopping does: the daemon's stop budget (TimeoutStopSec=60) must
// still cover reading the output, stopping the helper and removing its
// credentials file, or systemd kills the daemon partway through.
const shutdownStopGrace = 5 * time.Second

// graceFor is how long a helper whose run ended with ctx gets to stop.
func graceFor(ctx context.Context) time.Duration {
	if errors.Is(context.Cause(ctx), errCallDeadline) {
		return stopGrace
	}
	return shutdownStopGrace
}

// finish reads the helper's output and removes only that helper. Logging
// and cleanup have separate budgets, so a slow log endpoint cannot spend
// the time needed to stop a writer and remove the container.
func finish(e *docker.Engine, spec docker.Spec, grace time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	info, err := e.Inspect(ctx, spec.Name)
	if docker.IsNotFound(err) {
		cancel()
		return nil, nil
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("inspect restic helper before cleanup: %w", err)
	}
	if info.Labels[docker.LabelOwner] != docker.OwnerValue || info.Labels[docker.LabelApp] != spec.Labels[docker.LabelApp] || info.Labels[docker.LabelWorkload] != "backup" {
		cancel()
		return nil, fmt.Errorf("restic helper %s has another owner; refusing cleanup", spec.Name)
	}
	var buf bytes.Buffer
	logErr := e.Logs(ctx, spec.Name, false, "all", &buf)
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), grace+25*time.Second)
	removeErr := e.Remove(cleanup, info.ID, grace)
	stop()
	var errs []error
	if logErr != nil {
		errs = append(errs, fmt.Errorf("read restic output: %w", logErr))
	}
	if removeErr != nil {
		errs = append(errs, fmt.Errorf("remove restic helper %s: %w", spec.Name, removeErr))
	}
	return strings.Split(strings.TrimSpace(buf.String()), "\n"), errors.Join(errs...)
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// explain turns restic's last words into one line.
func explain(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		var msg struct {
			Type    string `json:"message_type"`
			Message string `json:"message"`
			Error   struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &msg); err == nil && (msg.Type == "exit_error" || msg.Type == "error") {
			text := msg.Message
			if text == "" {
				text = msg.Error.Message
			}
			return strings.SplitN(strings.TrimPrefix(text, "Fatal: "), "\n", 2)[0]
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" && !strings.HasPrefix(t, "{") {
			return t
		}
	}
	return "failed without a message"
}

// Ensure makes sure the repository exists, reporting whether it was made.
// It asks restic to initialize the repository: on a store that lets it,
// that creates the bucket too, and on an existing repository it fails at
// once. (Asking restic to read a missing bucket instead would retry for
// a quarter of an hour, because it treats "no such bucket" as transient.)
func (r Runner) Ensure(ctx context.Context) (bool, error) {
	lines, err := r.bounded(ctx, orDefault(r.Deadlines.Ensure, EnsureTimeout), nil, "init", "--json")
	if err == nil {
		return true, nil
	}
	joined := strings.Join(lines, "\n")
	// Only the expected init exit can mean success. A joined cleanup or
	// log failure must still reach the caller even if the repository exists.
	if _, failedInit := err.(*commandError); failedInit && (strings.Contains(joined, "already initialized") || strings.Contains(joined, "already exists")) {
		return false, nil
	}
	return false, err
}

// ListTimeout bounds the calls that only read the repository's index, so
// a bucket that doesn't answer is reported instead of waited on.
const ListTimeout = 5 * time.Minute

// Backup snapshots the mounted paths under a host name.
func (r Runner) Backup(ctx context.Context, host string, mounts []string, paths ...string) (*Summary, error) {
	args := []string{"backup", "--json", "--host", host, "--tag", Tag, "--one-file-system=false"}
	for _, tag := range r.BackupTags {
		args = append(args, "--tag", tag)
	}
	args = append(args, paths...)
	lines, err := r.bounded(ctx, orDefault(r.Deadlines.Backup, BackupTimeout), mounts, args...)
	if err != nil {
		return nil, err
	}
	for i := len(lines) - 1; i >= 0; i-- {
		var s struct {
			Type string `json:"message_type"`
			Summary
		}
		if json.Unmarshal([]byte(lines[i]), &s) == nil && s.Type == "summary" {
			return &s.Summary, nil
		}
	}
	return nil, errors.New("restic backup: no summary in the output")
}

// Snapshots lists a host's snapshots, newest first.
func (r Runner) Snapshots(ctx context.Context, host string) ([]Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, ListTimeout)
	defer cancel()
	lines, err := r.run(ctx, nil, "snapshots", "--json", "--host", host, "--tag", Tag)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("restic snapshots: no answer from the repository within %s (does the bucket exist, and do the credentials reach it?): %s", ListTimeout, explain(lines))
	}
	if err != nil {
		return nil, err
	}
	var out []Snapshot
	for _, l := range lines {
		if strings.HasPrefix(l, "[") {
			if err := json.Unmarshal([]byte(l), &out); err != nil {
				return nil, fmt.Errorf("restic snapshots: %w", err)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out, nil
}

// Latest returns the newest snapshot, or ErrNoRepository when there is
// none.
func (r Runner) Latest(ctx context.Context, host string) (*Snapshot, error) {
	snaps, err := r.Snapshots(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(snaps) == 0 {
		return nil, ErrNoRepository
	}
	return &snaps[0], nil
}

// Unlock removes the repository's stale locks: those whose holder restic
// can tell is gone, or that nobody refreshed for 30 minutes. It never
// removes a live lock, so it is safe beside another restic; a prune killed
// at its deadline leaves an exclusive lock that every later backup would
// otherwise trip over, because restic does not skip stale locks on its own.
func (r Runner) Unlock(ctx context.Context) error {
	_, err := r.bounded(ctx, orDefault(r.Deadlines.Unlock, UnlockTimeout), nil, "unlock")
	return err
}

// Forget applies the retention policy, then prunes. It returns how many
// snapshots were removed, also when the prune then fails.
//
// The prune is a call of its own and runs even when nothing was forgotten
// this time: forgotten snapshots are gone as soon as forget returns, so a
// prune an earlier backup lost to its deadline would otherwise wait until
// the policy next removes one. Each prune rewrites at most PruneMaxRepack,
// so a repository with a lot to reclaim catches up over several backups.
func (r Runner) Forget(ctx context.Context, host string, keep Keep) (int, error) {
	args := []string{"forget", "--json", "--host", host, "--tag", Tag, "--keep-tag", ReleaseCheckpointTag}
	if keep.Daily > 0 {
		args = append(args, "--keep-daily", fmt.Sprint(keep.Daily))
	}
	if keep.Weekly > 0 {
		args = append(args, "--keep-weekly", fmt.Sprint(keep.Weekly))
	}
	if keep.Monthly > 0 {
		args = append(args, "--keep-monthly", fmt.Sprint(keep.Monthly))
	}
	lines, err := r.bounded(ctx, orDefault(r.Deadlines.Forget, ForgetTimeout), nil, args...)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, l := range lines {
		if !strings.HasPrefix(l, "[") {
			continue
		}
		var groups []struct {
			Remove []json.RawMessage `json:"remove"`
		}
		if json.Unmarshal([]byte(l), &groups) == nil {
			for _, g := range groups {
				removed += len(g.Remove)
			}
		}
	}
	_, err = r.bounded(ctx, orDefault(r.Deadlines.Prune, PruneTimeout), nil, "prune", "--max-repack-size", PruneMaxRepack)
	return removed, err
}

// Restore puts a snapshot's files back under /data, into whatever is
// mounted there and verifies restored file contents before returning success.
// Includes limit it to paths inside the snapshot. It runs as long as the
// data needs unless Deadlines.Restore sets a limit.
func (r Runner) Restore(ctx context.Context, snapshot, host string, mounts []string, includes ...string) (*RestoreSummary, error) {
	args := []string{"restore", snapshot, "--json", "--verify", "--target", "/"}
	if snapshot == "latest" {
		args = append(args, "--host", host, "--tag", Tag)
	}
	for _, inc := range includes {
		args = append(args, "--include", inc)
	}
	var lines []string
	var err error
	if r.Deadlines.Restore > 0 {
		lines, err = r.bounded(ctx, r.Deadlines.Restore, mounts, args...)
	} else {
		lines, err = r.run(ctx, mounts, args...)
	}
	if err != nil {
		return nil, err
	}
	for i := len(lines) - 1; i >= 0; i-- {
		var s struct {
			Type string `json:"message_type"`
			RestoreSummary
		}
		if json.Unmarshal([]byte(lines[i]), &s) == nil && s.Type == "summary" {
			return &s.RestoreSummary, nil
		}
	}
	return nil, errors.New("restic restore: no summary in the output")
}

// StatsTimeout bounds a restore-size count, which walks the snapshot's
// whole tree but reads none of its file contents.
const StatsTimeout = 30 * time.Minute

// Size is what restoring a snapshot writes: its files' bytes, and how
// many files hold them.
type Size struct {
	Bytes, Files int64
}

// RestoreSize is what restoring a snapshot writes, as restic counts it
// from the snapshot's tree.
func (r Runner) RestoreSize(ctx context.Context, snapshot, host string) (Size, error) {
	args := []string{"stats", snapshot, "--mode", "restore-size", "--json"}
	if snapshot == "latest" {
		args = append(args, "--host", host, "--tag", Tag)
	}
	lines, err := r.bounded(ctx, StatsTimeout, nil, args...)
	if err != nil {
		return Size{}, err
	}
	return restoreSize(lines)
}

// restoreSize reads what restic stats --mode restore-size --json printed.
// restic leaves out a file count of zero.
func restoreSize(lines []string) (Size, error) {
	for i := len(lines) - 1; i >= 0; i-- {
		var s struct {
			TotalSize *int64 `json:"total_size"`
			Files     int64  `json:"total_file_count"`
		}
		if json.Unmarshal([]byte(lines[i]), &s) == nil && s.TotalSize != nil {
			if *s.TotalSize < 0 || s.Files < 0 {
				return Size{}, fmt.Errorf("restic stats: a restore size of %d bytes in %d files", *s.TotalSize, s.Files)
			}
			return Size{Bytes: *s.TotalSize, Files: s.Files}, nil
		}
	}
	return Size{}, errors.New("restic stats: no restore size in the output")
}

// VolumeMount mounts a volume where a named volume lives in the tree.
func VolumeMount(volume, name string, readOnly bool) string {
	m := volume + ":" + DataRoot + "/volumes/" + name
	if readOnly {
		m += ":ro"
	}
	return m
}

// VolumePath is where a named volume lives in the tree.
func VolumePath(name string) string { return DataRoot + "/volumes/" + name }

// DirMount mounts a host directory as the tree's root.
func DirMount(dir string, readOnly bool) string {
	m := dir + ":" + DataRoot
	if readOnly {
		m += ":ro"
	}
	return m
}
