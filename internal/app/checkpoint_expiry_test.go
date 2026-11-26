package app

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

var (
	checkpointA = strings.Repeat("a", 64)
	checkpointB = strings.Repeat("b", 64)
)

// checkpointScenario is an app with one earlier revision and one release
// over it whose boundary records checkpointA.
type checkpointScenario struct {
	store    *state.Store
	m        *manifest.Manifest
	at       time.Time
	rollback Rollback
}

func newCheckpointScenario(t *testing.T) *checkpointScenario {
	t.Helper()
	return newCheckpointScenarioAged(t, time.Hour)
}

// newCheckpointScenarioAged is the scenario with everything in it that long
// ago.
func newCheckpointScenarioAged(t *testing.T, age time.Duration) *checkpointScenario {
	t.Helper()
	s := &checkpointScenario{store: releaseTestStore(t), m: releaseTestManifest(), at: time.Now().UTC().Truncate(time.Millisecond).Add(-age)}
	releaseTestRevision(t, s.store, s.m, "old-rev", state.RevisionPrevious, s.at)
	releaseTestRevision(t, s.store, s.m, "new-rev", state.RevisionActive, s.at.Add(time.Minute))
	s.rollback = Rollback{Deploy: Deploy{Store: s.store, Secrets: newSecrets(t), StateDir: t.TempDir()}}
	return s
}

func (s *checkpointScenario) boundary(t *testing.T, revision, previous, snapshot string, after time.Duration, status string) state.ReleaseBoundary {
	t.Helper()
	ctx := context.Background()
	b := state.ReleaseBoundary{App: s.m.App, Revision: revision, PreviousRevision: previous, Compatibility: manifest.DataRestoreRequired, Snapshot: snapshot, StartedAt: s.at.Add(after)}
	var err error
	switch status {
	case state.ReleasePrepared:
		err = s.store.PrepareReleaseBoundary(ctx, b)
	case state.ReleaseStarted:
		err = s.store.BeginReleaseBoundary(ctx, b)
	case state.ReleaseRestoring:
		if err = s.store.BeginReleaseBoundary(ctx, b); err == nil {
			err = s.store.BeginReleaseRestore(ctx, b.App, b.Revision, b.Snapshot)
		}
	default:
		if err = s.store.BeginReleaseBoundary(ctx, b); err == nil {
			err = s.store.FinishReleaseBoundary(ctx, b.App, b.Revision, status, "", s.at.Add(after+time.Second))
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (s *checkpointScenario) expired(t *testing.T, snapshot string) bool {
	t.Helper()
	rule, err := releaseCheckpointRule(context.Background(), s.store, s.m.App)
	if err != nil {
		t.Fatal(err)
	}
	return rule(restic.Snapshot{ID: snapshot, Tags: []string{restic.Tag, restic.ReleaseCheckpointTag}})
}

// restores reports whether a rollback naming the checkpoint is accepted and
// would read it: planned with a restore step that does not return at once.
// The step is applied without Docker, so one that goes on to restore fails
// to connect, and only a boundary already restored returns nil.
func (s *checkpointScenario) restores(t *testing.T, snapshot string) bool {
	t.Helper()
	dockerUnreachable(t)
	raw, _ := json.Marshal(RollbackInput{App: s.m.App, RestoreData: snapshot})
	plan, err := s.rollback.Plan(context.Background(), raw)
	if err != nil {
		return false
	}
	if plan.Steps[0].Name != "restore-release-checkpoint" {
		t.Fatalf("a checkpoint rollback without its restore step: %v", plan.Steps[0].Name)
	}
	return plan.Steps[0].Apply(context.Background(), io.Discard) != nil
}

func dockerUnreachable(t *testing.T) {
	t.Helper()
	t.Setenv("DOCKER_HOST", "unix://"+t.TempDir()+"/no-docker.sock")
}

// Every checkpoint a rollback Helios accepts would restore keeps its
// protection.
func TestACheckpointARollbackStillAcceptsNeverExpires(t *testing.T) {
	for _, status := range []string{state.ReleasePrepared, state.ReleaseStarted, state.ReleaseCompleted, state.ReleaseFailed} {
		t.Run(status, func(t *testing.T) {
			s := newCheckpointScenario(t)
			s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, status)
			if !s.restores(t, checkpointA) {
				t.Fatal("the scenario is wrong: rollback does not accept this checkpoint")
			}
			if s.expired(t, checkpointA) {
				t.Fatal("a checkpoint a rollback accepts lost its protection")
			}
		})
	}

	t.Run("a restore that was interrupted", func(t *testing.T) {
		s := newCheckpointScenario(t)
		s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseRestoring)
		if !s.restores(t, checkpointA) {
			t.Fatal("the scenario is wrong: an interrupted restore cannot be retried")
		}
		if s.expired(t, checkpointA) {
			t.Fatal("the checkpoint of a restore in progress lost its protection")
		}
	})

	t.Run("an older checkpoint behind a newer release", func(t *testing.T) {
		s := newCheckpointScenario(t)
		s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseCompleted)
		releaseTestRevision(t, s.store, s.m, "newer-rev", state.RevisionActive, s.at.Add(3*time.Minute))
		s.boundary(t, "newer-rev", "new-rev", checkpointB, 4*time.Minute, state.ReleaseCompleted)
		for _, snapshot := range []string{checkpointA, checkpointB} {
			if !s.restores(t, snapshot) || s.expired(t, snapshot) {
				t.Fatalf("checkpoint %s is still accepted and must stay", snapshot[:8])
			}
		}
	})

	t.Run("one boundary restored and another not", func(t *testing.T) {
		s := newCheckpointScenario(t)
		s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseRestored)
		releaseTestRevision(t, s.store, s.m, "retry-rev", state.RevisionFailed, s.at.Add(3*time.Minute))
		s.boundary(t, "retry-rev", "old-rev", checkpointA, 4*time.Minute, state.ReleaseFailed)
		if s.expired(t, checkpointA) {
			t.Fatal("a checkpoint one live boundary still records lost its protection")
		}
	})
}

// The refusals that can lift again do not expire a checkpoint either.
func TestACheckpointRollbackRefusesOnlyForNowStaysProtected(t *testing.T) {
	s := newCheckpointScenario(t)
	releaseTestRevision(t, s.store, s.m, "first-failed", state.RevisionFailed, s.at.Add(2*time.Minute))
	s.boundary(t, "first-failed", "old-rev", checkpointA, 2*time.Minute, state.ReleaseFailed)
	releaseTestRevision(t, s.store, s.m, "second-failed", state.RevisionFailed, s.at.Add(3*time.Minute))
	s.boundary(t, "second-failed", "old-rev", checkpointB, 3*time.Minute, state.ReleaseFailed)
	if s.restores(t, checkpointB) {
		t.Fatal("the scenario is wrong: rollback accepts a checkpoint taken after an unsafe release")
	}
	if s.expired(t, checkpointB) {
		t.Fatal("a refusal that lifts once the earlier release is restored expired the checkpoint")
	}
}

// A checkpoint expires only when no rollback Helios accepts would read it.
func TestACheckpointNoRollbackCanRestoreExpires(t *testing.T) {
	t.Run("its boundary was restored", func(t *testing.T) {
		s := newCheckpointScenario(t)
		s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseRestored)
		if s.restores(t, checkpointA) {
			t.Fatal("the scenario is wrong: a restored boundary is restored again")
		}
		if !s.expired(t, checkpointA) {
			t.Fatal("a restored checkpoint kept its protection")
		}
	})

	t.Run("a restore to an earlier checkpoint superseded it", func(t *testing.T) {
		s := newCheckpointScenario(t)
		first := s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseRestoring)
		releaseTestRevision(t, s.store, s.m, "newer-rev", state.RevisionFailed, s.at.Add(3*time.Minute))
		s.boundary(t, "newer-rev", "new-rev", checkpointB, 4*time.Minute, state.ReleaseFailed)
		if s.expired(t, checkpointB) {
			t.Fatal("expired before the restore completed")
		}
		// Completing the restore of the first marks the later one restored.
		if err := s.store.CompleteReleaseRestore(context.Background(), first, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		for _, snapshot := range []string{checkpointA, checkpointB} {
			if s.restores(t, snapshot) {
				t.Fatalf("the scenario is wrong: %s is restored again", snapshot[:8])
			}
			if !s.expired(t, snapshot) {
				t.Fatalf("checkpoint %s kept its protection after the restore", snapshot[:8])
			}
		}
	})

	t.Run("its app was removed here and deployed again", func(t *testing.T) {
		s := newCheckpointScenario(t)
		ctx := context.Background()
		s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseCompleted)
		id, err := s.store.StartBackupRun(ctx, s.m.App, releaseCheckpointRun, s.at)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.store.FinishBackupRun(ctx, id, state.BackupRun{OK: true, Snapshot: checkpointA, FinishedAt: s.at}); err != nil {
			t.Fatal(err)
		}
		if s.expired(t, checkpointA) {
			t.Fatal("expired while its boundary records it")
		}
		if err := s.store.RemoveApp(ctx, s.m.App); err != nil {
			t.Fatal(err)
		}
		releaseTestRevision(t, s.store, s.m, "old-rev", state.RevisionPrevious, s.at)
		releaseTestRevision(t, s.store, s.m, "new-rev", state.RevisionActive, s.at.Add(time.Minute))
		if s.restores(t, checkpointA) {
			t.Fatal("the scenario is wrong: rollback accepts a checkpoint without a boundary")
		}
		if !s.expired(t, checkpointA) {
			t.Fatal("a checkpoint this machine took and no boundary records kept its protection")
		}
	})
}

// A checkpoint this machine knows nothing about may belong to another
// machine that backs up to the same bucket. When in doubt it stays.
func TestACheckpointThisMachineHasNoRecordOfStaysProtected(t *testing.T) {
	s := newCheckpointScenario(t)
	ctx := context.Background()
	if s.expired(t, checkpointA) {
		t.Fatal("an unknown checkpoint lost its protection")
	}
	// A run that failed proves nothing either.
	id, err := s.store.StartBackupRun(ctx, s.m.App, releaseCheckpointRun, s.at)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.FinishBackupRun(ctx, id, state.BackupRun{OK: false, Snapshot: checkpointA, FinishedAt: s.at, Error: "boom"}); err != nil {
		t.Fatal(err)
	}
	// Nor does an ordinary backup run that happens to name the snapshot.
	id, _ = s.store.StartBackupRun(ctx, s.m.App, state.BackupRunBackup, s.at)
	if err := s.store.FinishBackupRun(ctx, id, state.BackupRun{OK: true, Snapshot: checkpointA, FinishedAt: s.at}); err != nil {
		t.Fatal(err)
	}
	// Nor another app's checkpoint run.
	id, _ = s.store.StartBackupRun(ctx, "other", releaseCheckpointRun, s.at)
	if err := s.store.FinishBackupRun(ctx, id, state.BackupRun{OK: true, Snapshot: checkpointA, FinishedAt: s.at}); err != nil {
		t.Fatal(err)
	}
	if s.expired(t, checkpointA) {
		t.Fatal("a checkpoint without a successful checkpoint run of this app lost its protection")
	}
}

// A completed release's checkpoint is kept for a rollback for thirty days.
// The rollback refuses it from then on, and retention lets go of it a day
// later, so there is never a checkpoint a rollback would read that
// retention is free to drop.
func TestACompletedReleasesCheckpointAgesOutAndRollbackRefusesItFirst(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		name              string
		age               time.Duration
		restores, expired bool
	}{
		{"inside the horizon", 29 * day, true, false},
		{"past the horizon, inside the slack", 30*day + 2*time.Hour, false, false},
		{"past both", 31*day + 2*time.Hour, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newCheckpointScenarioAged(t, c.age)
			s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseCompleted)
			if got := s.restores(t, checkpointA); got != c.restores {
				t.Fatalf("a rollback restores the checkpoint: %v, want %v", got, c.restores)
			}
			if got := s.expired(t, checkpointA); got != c.expired {
				t.Fatalf("the checkpoint lost its protection: %v, want %v", got, c.expired)
			}
		})
	}

	// The refusal says why, and what is left to do.
	s := newCheckpointScenarioAged(t, 45*day)
	s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseCompleted)
	dockerUnreachable(t)
	raw, _ := json.Marshal(RollbackInput{App: s.m.App, RestoreData: checkpointA})
	_, err := s.rollback.Plan(context.Background(), raw)
	if err == nil {
		t.Fatal("a rollback planned to restore a checkpoint past the horizon")
	}
	for _, want := range []string{checkpointA, "30 days", "no longer kept for a rollback", "separately verified backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal does not say %q: %v", want, err)
		}
	}
}

// Only a release that completed ages. One that failed, or is still under
// way or being restored, keeps its checkpoint however old it is, and a
// rollback still accepts it.
func TestOnlyACompletedReleasesCheckpointAges(t *testing.T) {
	for _, status := range []string{state.ReleasePrepared, state.ReleaseStarted, state.ReleaseFailed, state.ReleaseRestoring} {
		t.Run(status, func(t *testing.T) {
			s := newCheckpointScenarioAged(t, 400*24*time.Hour)
			s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, status)
			if !s.restores(t, checkpointA) {
				t.Fatal("a rollback no longer accepts an old checkpoint of a release that did not complete")
			}
			if s.expired(t, checkpointA) {
				t.Fatal("an old checkpoint of a release that did not complete lost its protection")
			}
		})
	}
	// A boundary that does not say when it began is never aged.
	undated := []state.ReleaseBoundary{{App: "site", Revision: "r", Snapshot: checkpointA, Status: state.ReleaseCompleted}}
	if checkpointExpired(checkpointA, undated, nil, time.Now()) {
		t.Fatal("a checkpoint of a release with no start time aged out")
	}
}

// A checkpoint is past the horizon when the release it was taken for is.
// A second, recent release that records the same snapshot keeps it.
func TestACheckpointARecentReleaseAlsoRecordsStays(t *testing.T) {
	now := time.Now()
	old := state.ReleaseBoundary{App: "site", Revision: "one", Snapshot: checkpointA, Status: state.ReleaseCompleted, StartedAt: now.Add(-90 * 24 * time.Hour)}
	recent := state.ReleaseBoundary{App: "site", Revision: "two", Snapshot: checkpointA, Status: state.ReleaseCompleted, StartedAt: now.Add(-time.Hour)}
	if !checkpointExpired(checkpointA, []state.ReleaseBoundary{old}, nil, now) {
		t.Fatal("the scenario is wrong: the old release alone does not age the checkpoint out")
	}
	if checkpointExpired(checkpointA, []state.ReleaseBoundary{old, recent}, nil, now) {
		t.Fatal("a checkpoint a recent release records aged out with the old one")
	}
}

// A code-only rollback across a data-changing release names the checkpoint
// to restore. Once that checkpoint is past the horizon it says so, and does
// not advise a restore the rollback would refuse.
func TestAnUnsafeRollbackDoesNotAdviseACheckpointPastTheHorizon(t *testing.T) {
	now := time.Now()
	recent := state.ReleaseBoundary{App: "site", Revision: "two", Compatibility: manifest.DataRestoreRequired, Snapshot: checkpointB, Status: state.ReleaseCompleted, StartedAt: now.Add(-time.Hour)}
	err := unsafeRollbackError("site", []state.ReleaseBoundary{recent})
	if !strings.Contains(err.Error(), "--restore-data") || !strings.Contains(err.Error(), "checkpoint "+checkpointB) || strings.Contains(err.Error(), "horizon") {
		t.Fatalf("a recent checkpoint is not advised as before: %v", err)
	}
	old := state.ReleaseBoundary{App: "site", Revision: "one", Compatibility: manifest.DataRestoreRequired, Snapshot: checkpointA, Status: state.ReleaseCompleted, StartedAt: now.Add(-60 * 24 * time.Hour)}
	err = unsafeRollbackError("site", []state.ReleaseBoundary{recent, old})
	for _, want := range []string{checkpointA, "older than 30 days", "past the rollback horizon", "separately verified backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal does not say %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "--restore-data") {
		t.Fatalf("a restore the rollback would refuse is still advised: %v", err)
	}
}

// A checkpoint whose release could not write its boundary is one nothing
// can name. The run that took it failed, but restic had returned its id.
func TestACheckpointWhoseBoundaryWasNeverWrittenExpires(t *testing.T) {
	ctx := context.Background()
	s := newCheckpointScenario(t)
	id, err := s.store.StartBackupRun(ctx, s.m.App, releaseCheckpointRun, s.at)
	if err != nil {
		t.Fatal(err)
	}
	if s.expired(t, checkpointA) {
		t.Fatal("a checkpoint nobody recorded making lost its protection")
	}
	if err := s.store.RecordSnapshotMade(ctx, id, checkpointA); err != nil {
		t.Fatal(err)
	}
	// The release is between its capture and its boundary.
	if s.expired(t, checkpointA) {
		t.Fatal("a checkpoint lost its protection while its run was still going")
	}
	if err := s.store.FinishBackupRun(ctx, id, state.BackupRun{OK: false, Error: "the boundary could not be written", FinishedAt: s.at}); err != nil {
		t.Fatal(err)
	}
	if !s.expired(t, checkpointA) {
		t.Fatal("a checkpoint this machine took, which no boundary records, stayed protected")
	}
	// Another app's failed checkpoint says nothing about this app's.
	other, err := s.store.StartBackupRun(ctx, "other", releaseCheckpointRun, s.at)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.RecordSnapshotMade(ctx, other, checkpointB); err != nil {
		t.Fatal(err)
	}
	if s.expired(t, checkpointB) {
		t.Fatal("another app's checkpoint run expired this app's checkpoint")
	}
}

func TestCheckpointRuleProtectsEverythingItCannotJudge(t *testing.T) {
	// A status this code does not know is not "restored".
	odd := []state.ReleaseBoundary{{App: "site", Revision: "r", Snapshot: checkpointA, Status: "archived"}}
	if checkpointExpired(checkpointA, odd, map[string]bool{checkpointA: true}, time.Now()) {
		t.Fatal("an unknown boundary status expired a checkpoint")
	}
	// State that cannot be read yields no rule at all, and an error to report.
	s := newCheckpointScenario(t)
	s.boundary(t, "new-rev", "old-rev", checkpointA, 2*time.Minute, state.ReleaseRestored)
	s.store.Close()
	rule, err := releaseCheckpointRule(context.Background(), s.store, s.m.App)
	if rule != nil || err == nil || !strings.Contains(err.Error(), "stay protected") {
		t.Fatalf("unreadable state gave a rule: %v", err)
	}
}

// resticRuns stands in for an existing repository and records every restic
// command in full. dryRun is what the policy says it would remove.
func resticRuns(t *testing.T, summary restic.Summary, dryRun string, hangFullPrune *bool) *[][]string {
	t.Helper()
	fake := dockertest.New(t)
	var commands [][]string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, append([]string(nil), c.Cmd...))
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			switch c.Cmd[0] {
			case "init":
				c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":1,"message":"Fatal: config file already exists"}`
			case "backup":
				body, _ := json.Marshal(struct {
					Type string `json:"message_type"`
					restic.Summary
				}{"summary", summary})
				c.Logs = string(body)
			case "forget":
				if slices.Contains(c.Cmd, "--dry-run") {
					c.Logs = dryRun
				}
			case "prune":
				if hangFullPrune != nil && *hangFullPrune && len(c.Cmd) == 1 {
					c.ExitAfter, c.Logs = 0, `{"message_type":"status"}`
				}
			}
		})
	}
	return &commands
}

func runBackup(t *testing.T, b backupIdentityDefinition, raw json.RawMessage) string {
	t.Helper()
	reg := kernel.Registry{}
	reg.Add(b)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var lines []string
	receipt, err := kernel.New(b.Store, reg, "daemon").Run(ctx, BackupKind, raw, func(ev kernel.Event) {
		if ev.Line != "" {
			lines = append(lines, ev.Line)
		}
	})
	if err != nil || receipt.Status != state.Succeeded {
		t.Fatalf("backup: %+v %v", receipt, err)
	}
	return strings.Join(lines, "\n")
}

func commandsNamed(commands [][]string, name string) [][]string {
	var out [][]string
	for _, c := range commands {
		if c[0] == name {
			out = append(out, c)
		}
	}
	return out
}

// The nightly backup applies the rule: of three checkpoints the policy no
// longer keeps, only the one whose boundary was restored is forgotten.
func TestBackupRetentionForgetsOnlyExpiredCheckpoints(t *testing.T) {
	b, raw := backupIdentityFixture(t, false)
	var in BackupInput
	_ = json.Unmarshal(raw, &in)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second)
	ordinary, live, restored, unknown := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64)
	for revision, c := range map[string]struct{ snapshot, status string }{"rel-live": {live, state.ReleaseCompleted}, "rel-restored": {restored, state.ReleaseRestored}} {
		boundary := state.ReleaseBoundary{App: in.App, Revision: revision, PreviousRevision: "active-code", Compatibility: manifest.DataRestoreRequired, Snapshot: c.snapshot, StartedAt: at.Add(-time.Hour)}
		if err := b.Store.BeginReleaseBoundary(ctx, boundary); err != nil {
			t.Fatal(err)
		}
		if err := b.Store.FinishReleaseBoundary(ctx, in.App, revision, c.status, "", at); err != nil {
			t.Fatal(err)
		}
	}
	checkpoint := `"tags":["bedrock","bedrock-release-checkpoint"]`
	dryRun := `[{"remove":[{"id":"` + ordinary + `","tags":["bedrock"]},{"id":"` + live + `",` + checkpoint + `},{"id":"` + restored + `",` + checkpoint + `},{"id":"` + unknown + `",` + checkpoint + `}]}]`
	summary := restic.Summary{SnapshotID: strings.Repeat("c", 64), BackupStart: at, BackupEnd: at.Add(time.Second), TotalFiles: 3, TotalBytes: 300}
	commands := resticRuns(t, summary, dryRun, nil)
	output := runBackup(t, b, raw)

	forgets := commandsNamed(*commands, "forget")
	if len(forgets) != 2 {
		t.Fatalf("forget runs: %v", forgets)
	}
	if slices.Contains(forgets[0], "--keep-tag") || !slices.Contains(forgets[0], "--dry-run") {
		t.Fatalf("the policy run must be a dry run that judges checkpoints itself: %v", forgets[0])
	}
	if want := []string{"forget", "--json", ordinary, restored}; !slices.Equal(forgets[1], want) {
		t.Fatalf("forgot %v, want %v", forgets[1], want)
	}
	for _, want := range []string{"removed 2 old snapshot(s)", "1 of them were release checkpoints", "kept 2 older release checkpoint(s)"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output lacks %q:\n%s", want, output)
		}
	}
}

func TestFullPruneIsDueOnceAWeekCountingAttempts(t *testing.T) {
	now := time.Date(2026, 11, 25, 3, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		last state.StoragePrune
		want bool
	}{
		{"never pruned in full", state.StoragePrune{}, true},
		{"last night", state.StoragePrune{AttemptedAt: now.Add(-24 * time.Hour), CompletedAt: now.Add(-23 * time.Hour)}, false},
		{"six days ago", state.StoragePrune{AttemptedAt: now.Add(-6 * 24 * time.Hour)}, false},
		{"a week ago to the minute", state.StoragePrune{AttemptedAt: now.Add(-7 * 24 * time.Hour)}, true},
		{"three weeks ago, a missed fortnight", state.StoragePrune{AttemptedAt: now.Add(-21 * 24 * time.Hour)}, true},
		{"stopped at its deadline last night", state.StoragePrune{AttemptedAt: now.Add(-24 * time.Hour), CompletedAt: now.Add(-9 * 24 * time.Hour)}, false},
		{"recorded in the future by a clock that moved", state.StoragePrune{AttemptedAt: now.Add(48 * time.Hour)}, true},
	} {
		if got := fullPruneDue(tc.last, now); got != tc.want {
			t.Errorf("%s: due %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestBackupPrunesInFullOnceAWeekAndCappedOtherwise(t *testing.T) {
	for _, machine := range []bool{false, true} {
		t.Run(map[bool]string{false: "app", true: "machine"}[machine], func(t *testing.T) {
			b, raw := backupIdentityFixture(t, machine)
			b.Deadlines = restic.Deadlines{Prune: 100 * time.Millisecond}
			ctx := context.Background()
			at := time.Now().UTC().Truncate(time.Second)
			summary := restic.Summary{SnapshotID: strings.Repeat("c", 64), BackupStart: at, BackupEnd: at.Add(time.Second), TotalFiles: 3, TotalBytes: 300}
			hang := false
			commands := resticRuns(t, summary, `[{"remove":[]}]`, &hang)
			capped := []string{"prune", "--max-repack-size", restic.PruneMaxRepack}
			prunes := func() [][]string {
				t.Helper()
				out := commandsNamed(*commands, "prune")
				*commands = nil
				return out
			}
			// The fixture's storage prefix is "target".
			bucket := "target-hello"
			if machine {
				bucket = "target-" + MachineTarget("old-host")
			}
			record := func() state.StoragePrune {
				t.Helper()
				last, err := b.Store.StoragePruneOf(ctx, bucket)
				if err != nil {
					t.Fatal(err)
				}
				return last
			}

			// The first backup after the upgrade catches up at once.
			output := runBackup(t, b, raw)
			if got := prunes(); len(got) != 1 || !slices.Equal(got[0], []string{"prune"}) {
				t.Fatalf("first backup pruned %v, want one full prune", got)
			}
			first := record()
			if first.AttemptedAt.IsZero() || first.CompletedAt.IsZero() || !strings.Contains(output, "weekly full prune") {
				t.Fatalf("the full prune was not recorded: %+v\n%s", first, output)
			}

			// The same week: capped, and the record does not move.
			runBackup(t, b, raw)
			if got := prunes(); len(got) != 1 || !slices.Equal(got[0], capped) {
				t.Fatalf("second backup pruned %v, want the capped prune", got)
			}
			if record() != first {
				t.Fatalf("a capped prune changed the record: %+v", record())
			}

			// A week on, and a full prune that runs out of its deadline: the
			// backup still succeeds, the attempt counts, completion does not.
			weekAgo := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Millisecond)
			if err := b.Store.StoragePruneAttempted(ctx, bucket, weekAgo); err != nil {
				t.Fatal(err)
			}
			hang = true
			output = runBackup(t, b, raw)
			if got := prunes(); len(got) != 1 || !slices.Equal(got[0], []string{"prune"}) {
				t.Fatalf("a week later pruned %v, want one full prune", got)
			}
			stopped := record()
			if !stopped.AttemptedAt.After(weekAgo) || !stopped.CompletedAt.Equal(first.CompletedAt) {
				t.Fatalf("a stopped full prune was recorded as %+v", stopped)
			}
			if !strings.Contains(output, RetentionDeferred) || !strings.Contains(output, "restic prune did not finish") {
				t.Fatalf("the stopped prune was not reported:\n%s", output)
			}

			// The next backup clears the lock the stopped prune left, and goes
			// back to the capped prune until another week has passed.
			runBackup(t, b, raw)
			var names []string
			for _, c := range *commands {
				names = append(names, c[0])
			}
			if want := []string{"init", "unlock", "backup", "forget", "prune"}; !slices.Equal(names, want) {
				t.Fatalf("restic ran %v, want %v", names, want)
			}
			if got := prunes(); !slices.Equal(got[0], capped) {
				t.Fatalf("after a stopped full prune the next one was %v", got)
			}
			last, err := b.Store.LastBackupRun(ctx, map[bool]string{false: "hello", true: manifest.ReservedApp}[machine], state.BackupRunBackup)
			if err != nil || last == nil || strings.Contains(last.Detail, RetentionDeferred) {
				t.Fatalf("the following backup still carries the deferral: %+v %v", last, err)
			}
		})
	}
}
