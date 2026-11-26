package watch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/state"
)

const storageGiB = int64(1) << 30

// storageWatch is a watcher and a prober over one store, with a clock the
// test moves. Only the storage watch's conditions go into its rounds.
type storageWatch struct {
	t        *testing.T
	w        *Watcher
	p        *Prober
	now      *time.Time
	notifier *fakeNotifier
}

func newStorageWatch(t *testing.T) *storageWatch {
	t.Helper()
	notifier := &fakeNotifier{}
	w, now := newWatcher(t, notifier)
	p := NewProber(w.Store)
	p.Root = t.TempDir()
	p.Now = func() time.Time { return *now }
	p.Connect = func(context.Context) (*docker.Engine, error) { return nil, errors.New("Docker unavailable") }
	p.StorageSet = func() bool { return true }
	return &storageWatch{t: t, w: w, p: p, now: now, notifier: notifier}
}

// observe returns the storage watch's conditions as of now.
func (s *storageWatch) observe() []Condition {
	var out []Condition
	for _, c := range s.p.Observe(context.Background()) {
		if strings.HasPrefix(c.Key, storageBucketKey) || c.Key == storageExpiryKey || c.Key == storageSweepKey {
			out = append(out, c)
		}
	}
	return out
}

// rounds runs watch rounds a minute apart and returns what the last saw.
func (s *storageWatch) rounds(n int) []Condition {
	s.t.Helper()
	var found []Condition
	for range n {
		*s.now = s.now.Add(time.Minute)
		found = s.observe()
		if err := s.w.Round(context.Background(), found); err != nil {
			s.t.Fatal(err)
		}
	}
	return found
}

func (s *storageWatch) open(key string) *state.Incident {
	s.t.Helper()
	incident, err := s.w.Store.OpenIncidentByKey(context.Background(), key)
	if err != nil {
		s.t.Fatal(err)
	}
	return incident
}

// night records one sweep's reading of a bucket, taken at 05:00 on the
// given night, and moves the clock to the morning after it.
func (s *storageWatch) night(first time.Time, night int, sample state.StorageSample) {
	s.t.Helper()
	sample.TakenAt = first.Add(time.Duration(night) * 24 * time.Hour)
	if sample.Kind == "" {
		sample.Kind = state.StorageApp
	}
	if sample.UsedBytes == 0 {
		sample.UsedBytes = state.StorageUnknown
	}
	if sample.NewestSnapshotBytes == 0 {
		sample.NewestSnapshotBytes = state.StorageUnknown
	}
	if err := s.w.Store.AddStorageSamples(context.Background(), []state.StorageSample{sample}, sample.TakenAt.Add(-app.StorageSampleWindow)); err != nil {
		s.t.Fatal(err)
	}
	*s.now = sample.TakenAt.Add(time.Hour)
}

var storageFirstNight = time.Date(2026, 10, 1, 5, 0, 0, 0, time.UTC)

// A bucket half as large again as a week before is told once, as an
// incident of its own, and the incident ends when the week-old sample has
// caught up with it.
func TestUnusualBucketGrowthOpensAnIncidentAndClears(t *testing.T) {
	s := newStorageWatch(t)
	const key = "storage:helios-site"
	size := func(night int) int64 {
		switch {
		case night < 21:
			return 10 * storageGiB
		case night < 27:
			return (10 + int64(night-20)) * storageGiB
		}
		return 16 * storageGiB
	}
	for night := 0; night < 36; night++ {
		s.night(storageFirstNight, night, state.StorageSample{Bucket: "helios-site", Owner: "site", StoredBytes: size(night), Snapshots: 7})
		found := s.rounds(3)
		// 16 GB against 10 GB a week before, on two nights; the second of
		// them the week-old sample is 11 GB and it is still half as much
		// again.
		unusual := night == 26 || night == 27
		if (len(found) > 0) != unusual {
			t.Fatalf("night %d: %+v", night, found)
		}
		if (s.open(key) != nil) != unusual {
			t.Fatalf("night %d: incident %+v", night, s.open(key))
		}
		if night == 26 {
			c := found[0]
			if c.Key != key || c.Subject != "bucket helios-site" || c.Severity != state.SeverityWarning ||
				c.Message != "grew by 6.0 GB in 7 days, from 10.0 GB to 16.0 GB; helios storage shows every bucket" {
				t.Fatalf("condition: %+v", c)
			}
		}
	}
	var told []string
	for _, notice := range s.notifier.sent {
		told = append(told, notice.Subject)
	}
	// Told when it opens, again a day later while it still holds, and
	// when it ends.
	want := []string{"box: bucket helios-site has a problem", "box: bucket helios-site has a problem", "box: bucket helios-site recovered"}
	if strings.Join(told, "\n") != strings.Join(want, "\n") {
		t.Fatalf("notices: %q", told)
	}
}

// A new repository's first week is all growth. It says nothing then, and
// nothing in the week after, when the only week-old samples are from the
// days it was filling up.
func TestANewRepositoryRaisesNothingInItsFirstWeek(t *testing.T) {
	s := newStorageWatch(t)
	for night := 0; night < 21; night++ {
		size := 12 * storageGiB
		if night < 6 {
			size = 100<<20 + int64(night)*2*storageGiB
		}
		s.night(storageFirstNight, night, state.StorageSample{Bucket: "helios-new", Owner: "new", StoredBytes: size, Snapshots: int64(night + 1),
			OldestSnapshotAt: storageFirstNight.Add(-time.Hour), NewestSnapshotAt: storageFirstNight.Add(time.Duration(night)*24*time.Hour - time.Hour)})
		if found := s.rounds(3); len(found) != 0 {
			t.Fatalf("night %d of a new repository: %+v", night, found)
		}
	}
	if len(s.notifier.sent) != 0 {
		t.Fatalf("a new repository was told: %+v", s.notifier.sent)
	}
}

// Each bucket has its own incident, so one that recovers does not hide
// another that has not.
func TestEachBucketIsItsOwnIncident(t *testing.T) {
	s := newStorageWatch(t)
	// Two weeks of samples, so the week-old one is a fair baseline.
	for night := 0; night < 16; night++ {
		grown := 10 * storageGiB
		if night == 15 {
			grown = 40 * storageGiB
		}
		s.night(storageFirstNight, night, state.StorageSample{Bucket: "helios-shop", Owner: "shop", StoredBytes: grown, Snapshots: 7})
		// A repository fifty times its newest snapshot, all of it dead.
		s.night(storageFirstNight, night, state.StorageSample{Bucket: "helios-site", Owner: "site", StoredBytes: 100 * storageGiB, UsedBytes: 20 * storageGiB,
			NewestSnapshotBytes: 2 * storageGiB, Snapshots: 53})
	}
	found := s.rounds(3)
	if len(found) != 2 || found[0].Key != "storage:helios-shop" || found[1].Key != "storage:helios-site" {
		t.Fatalf("conditions: %+v", found)
	}
	if !strings.Contains(found[1].Message, "holds 100.0 GB, 50 times its newest snapshot of 2.0 GB") || !strings.Contains(found[1].Message, "80.0 GB of its 100.0 GB is data no snapshot uses") {
		t.Fatalf("message: %s", found[1].Message)
	}
	if s.open("storage:helios-shop") == nil || s.open("storage:helios-site") == nil {
		t.Fatal("each bucket should have an incident")
	}
}

// A removed app's bucket the sweep refuses to delete is a condition until
// the sweep deletes it or the operator keeps it.
func TestABucketTheSweepHoldsIsACondition(t *testing.T) {
	ctx := context.Background()
	s := newStorageWatch(t)
	removed := s.now.Add(-31 * 24 * time.Hour)
	if err := s.w.Store.RemoveAppLeavingTombstone(ctx, "blog", "helios-blog", "key:abcd", removed); err != nil {
		t.Fatal(err)
	}
	if found := s.rounds(1); len(found) != 0 {
		t.Fatalf("a tombstone that waits is no condition: %+v", found)
	}
	if err := s.w.Store.SetStorageTombstoneProblem(ctx, "blog", "it was written to after blog was removed"); err != nil {
		t.Fatal(err)
	}
	found := s.rounds(3)
	if len(found) != 1 || found[0].Key != storageExpiryKey || !strings.Contains(found[0].Message, "bucket helios-blog of blog, removed "+removed.Format("2006-01-02")+", is not being deleted: it was written to after blog was removed") ||
		!strings.Contains(found[0].Message, "helios storage keep <app>") {
		t.Fatalf("conditions: %+v", found)
	}
	if s.open(storageExpiryKey) == nil {
		t.Fatal("a held bucket should open an incident")
	}
	if err := s.w.Store.KeepStorageTombstone(ctx, "blog", *s.now); err != nil {
		t.Fatal(err)
	}
	if found := s.rounds(2); len(found) != 0 || s.open(storageExpiryKey) != nil {
		t.Fatalf("a kept bucket is still a condition: %+v", found)
	}
	// The sweep records one thing against a kept bucket: a deletion that
	// was begun and not finished. Keeping does not end that, and the
	// condition does not say it would.
	if err := s.w.Store.SetStorageTombstoneProblem(ctx, "blog", "its deletion was started and did not finish"); err != nil {
		t.Fatal(err)
	}
	found = s.rounds(3)
	if len(found) != 1 || found[0].Key != storageExpiryKey || !strings.Contains(found[0].Message, "bucket helios-blog of blog, removed "+removed.Format("2006-01-02")+" and kept: its deletion was started and did not finish") ||
		strings.Contains(found[0].Message, "helios storage keep") || s.open(storageExpiryKey) == nil {
		t.Fatalf("a kept bucket whose deletion did not finish: %+v", found)
	}
}

func recordSweep(t *testing.T, store *state.Store, id string, at time.Time, status state.OperationStatus, opErr string) {
	t.Helper()
	ctx := context.Background()
	if err := store.CreateOperation(ctx, state.NewOperation{ID: id, Kind: app.StorageSweepKind, Input: []byte(`{}`), Plan: []byte(`{}`), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(ctx, id, status, opErr, nil, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

// A sweep that failed measured nothing and deleted nothing. That is a
// condition until a sweep succeeds.
func TestAFailedSweepIsAConditionUntilOneSucceeds(t *testing.T) {
	s := newStorageWatch(t)
	recordSweep(t, s.w.Store, "op-1", s.now.Add(-time.Hour), state.Failed, "sample: list buckets: storage answered HTTP 401 unauthorized: bad key\nmore")
	found := s.rounds(3)
	if len(found) != 1 || found[0].Key != storageSweepKey || !strings.Contains(found[0].Message, "the last storage sweep failed") ||
		!strings.Contains(found[0].Message, "storage answered HTTP 401 unauthorized: bad key (helios operations show op-1)") || strings.Contains(found[0].Message, "more") {
		t.Fatalf("conditions: %+v", found)
	}
	recordSweep(t, s.w.Store, "op-2", *s.now, state.Succeeded, "")
	if found := s.rounds(2); len(found) != 0 || s.open(storageSweepKey) != nil {
		t.Fatalf("after a sweep that succeeded: %+v", found)
	}
}

// Samples that stop arriving mean the sweep stopped running. Without the
// storage integration there is no sweep to miss.
func TestASweepThatStoppedRunningIsACondition(t *testing.T) {
	s := newStorageWatch(t)
	s.night(storageFirstNight, 0, state.StorageSample{Bucket: "helios-site", Owner: "site", StoredBytes: storageGiB, Snapshots: 1})
	*s.now = storageFirstNight.Add(app.StorageSampleStale - time.Hour)
	if found := s.rounds(1); len(found) != 0 {
		t.Fatalf("one missed night is not a stopped sweep: %+v", found)
	}
	*s.now = storageFirstNight.Add(app.StorageSampleStale + time.Hour)
	found := s.rounds(1)
	if len(found) != 1 || found[0].Key != storageSweepKey || !strings.Contains(found[0].Message, "no bucket has been measured since 2026-10-01 05:00 UTC") {
		t.Fatalf("conditions: %+v", found)
	}
	s.p.StorageSet = func() bool { return false }
	if found := s.rounds(1); len(found) != 0 {
		t.Fatalf("storage is not set, so nothing is swept: %+v", found)
	}
	s.p.StorageSet = nil
	if found := s.rounds(1); len(found) != 0 {
		t.Fatalf("a prober that cannot tell must stay quiet: %+v", found)
	}
}

// One full prune that runs out of its hour is ordinary. Three in a row
// that never finish is a repository whose dead data is not going away.
func TestAFullPruneThatNeverFinishesIsACondition(t *testing.T) {
	ctx := context.Background()
	s := newStorageWatch(t)
	store := s.w.Store
	week := 7 * 24 * time.Hour
	for attempt := 1; attempt <= FullPruneUnfinished; attempt++ {
		if err := store.StoragePruneAttempted(ctx, "helios-site", *s.now); err != nil {
			t.Fatal(err)
		}
		// While the attempt could still be running it is not judged.
		if found := s.rounds(1); len(found) != 0 {
			t.Fatalf("attempt %d, still running: %+v", attempt, found)
		}
		*s.now = s.now.Add(OperationLockStale + time.Hour)
		found := s.rounds(1)
		if (len(found) > 0) != (attempt == FullPruneUnfinished) {
			t.Fatalf("attempt %d: %+v", attempt, found)
		}
		if attempt == FullPruneUnfinished {
			if found[0].Key != "storage:helios-site" || !strings.Contains(found[0].Message, "its weekly full prune has not finished in its last 3 attempts") {
				t.Fatalf("condition: %+v", found[0])
			}
			break
		}
		*s.now = s.now.Add(week)
	}
	if err := store.StoragePruneCompleted(ctx, "helios-site", *s.now); err != nil {
		t.Fatal(err)
	}
	if found := s.rounds(1); len(found) != 0 {
		t.Fatalf("after a full prune that finished: %+v", found)
	}
}

// When the sweep's records cannot be read, nothing is known. The storage
// incidents that are open stay open: no reading is not a recovery.
func TestUnreadableStorageRecordsHoldTheOpenIncidents(t *testing.T) {
	ctx := context.Background()
	s := newStorageWatch(t)
	if err := s.w.Store.RemoveAppLeavingTombstone(ctx, "blog", "helios-blog", "key:abcd", s.now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.w.Store.SetStorageTombstoneProblem(ctx, "blog", "the account changed"); err != nil {
		t.Fatal(err)
	}
	s.rounds(3)
	if s.open(storageExpiryKey) == nil {
		t.Fatal("the held bucket should have an incident")
	}
	alterState(t, s.w.Store, `ALTER TABLE storage_samples RENAME COLUMN stored_bytes TO damaged`)
	for range 4 {
		found := s.rounds(1)
		if len(found) != 1 || found[0].Key != storageExpiryKey || !found[0].Unknown {
			t.Fatalf("unreadable records: %+v", found)
		}
	}
	if s.open(storageExpiryKey) == nil {
		t.Fatal("an unreadable store was reported as a recovery")
	}
}
