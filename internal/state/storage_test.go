package state

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/compat"
)

var storageDay = time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC)

func deployed(t *testing.T, s *Store, app, id string) {
	t.Helper()
	if err := s.CreateRevision(context.Background(), Revision{App: app, ID: id, Status: RevisionActive, CreatedAt: storageDay}); err != nil {
		t.Fatal(err)
	}
}

func TestRemovingAnAppLeavesATombstoneAndARedeployClearsIt(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	deployed(t, s, "site", "r1")
	if got, err := s.StorageTombstones(ctx); err != nil || len(got) != 0 {
		t.Fatalf("a running app has a tombstone: %v %v", got, err)
	}
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "helios-site", "key:one", storageDay); err != nil {
		t.Fatal(err)
	}
	got, err := s.StorageTombstone(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	if got.Bucket != "helios-site" || !got.RemovedAt.Equal(storageDay) || got.Kept() {
		t.Fatalf("tombstone: %+v", got)
	}
	if revs, _ := s.Revisions(ctx, "site"); len(revs) != 0 {
		t.Fatalf("the app's revisions survived its removal: %v", revs)
	}

	// Any new revision means the app is back, whichever path recorded it.
	deployed(t, s, "site", "r2")
	if _, err := s.StorageTombstone(ctx, "site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a redeployed app kept its tombstone: %v", err)
	}
}

func TestSavingARevisionAlsoClearsTheTombstone(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "helios-site", "key:one", storageDay); err != nil {
		t.Fatal(err)
	}
	// SaveRevision is the upsert the deploy uses.
	if err := s.SaveRevision(ctx, Revision{App: "site", ID: "r9", Status: RevisionActive, CreatedAt: storageDay}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StorageTombstone(ctx, "site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tombstone survived a saved revision: %v", err)
	}
	// Another app's revision leaves a tombstone alone.
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "helios-site", "key:one", storageDay); err != nil {
		t.Fatal(err)
	}
	deployed(t, s, "other", "r1")
	if _, err := s.StorageTombstone(ctx, "site"); err != nil {
		t.Fatalf("another app's deploy cleared the tombstone: %v", err)
	}
}

func TestPlainRemovalLeavesNoTombstone(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	deployed(t, s, "site", "r1")
	if err := s.RemoveApp(ctx, "site"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.StorageTombstones(ctx); len(got) != 0 {
		t.Fatalf("tombstone without being asked for: %v", got)
	}
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "", "key:one", storageDay); err == nil {
		t.Fatal("a tombstone without a bucket was recorded")
	}
}

func TestKeepingBindingAndDroppingATombstone(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if err := s.KeepStorageTombstone(ctx, "site", storageDay); !errors.Is(err, ErrNotFound) {
		t.Fatalf("kept a tombstone that is not there: %v", err)
	}
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "helios-site", "key:one", storageDay); err != nil {
		t.Fatal(err)
	}
	if err := s.BindStorageTombstone(ctx, "site", "key:one", "b2:one"); err != nil {
		t.Fatal(err)
	}
	// The first account a bucket was seen in stays.
	if err := s.BindStorageTombstone(ctx, "site", "key:one", "b2:two"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bound a second account: %v", err)
	}
	if err := s.SetStorageTombstoneProblem(ctx, "site", "written since removal"); err != nil {
		t.Fatal(err)
	}
	if err := s.KeepStorageTombstone(ctx, "site", storageDay.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.StorageTombstone(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	if got.Account != "b2:one" || !got.Kept() || got.Problem != "" {
		t.Fatalf("tombstone: %+v", got)
	}

	// Removing the app again restarts the clock and withdraws the keep.
	later := storageDay.Add(48 * time.Hour)
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "helios-site", "key:two", later); err != nil {
		t.Fatal(err)
	}
	got, _ = s.StorageTombstone(ctx, "site")
	if got.Kept() || !got.RemovedAt.Equal(later) || got.Account != "key:two" {
		t.Fatalf("second removal: %+v", got)
	}
	if err := s.DeleteStorageTombstone(ctx, "site"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.StorageTombstones(ctx); len(got) != 0 {
		t.Fatalf("dropped tombstone is still listed: %v", got)
	}
}

func TestStorageSamplesStayABoundedWindow(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	window := 35 * 24 * time.Hour
	for day := 0; day < 60; day++ {
		at := storageDay.Add(time.Duration(day) * 24 * time.Hour)
		sample := StorageSample{Bucket: "helios-site", TakenAt: at, Owner: "site", Kind: StorageApp, StoredBytes: int64(day), Files: 1,
			UsedBytes: StorageUnknown, Snapshots: 3, NewestSnapshotAt: at, OldestSnapshotAt: storageDay, NewestSnapshotBytes: 9, LastWriteAt: at, Note: "n"}
		if err := s.AddStorageSamples(ctx, []StorageSample{sample}, at.Add(-window)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.StorageSamples(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 36 {
		t.Fatalf("%d samples kept, want the 36 inside 35 days", len(got))
	}
	last := got[len(got)-1]
	if last.StoredBytes != 59 || last.UsedBytes != StorageUnknown || last.Owner != "site" || !last.OldestSnapshotAt.Equal(storageDay) || last.Note != "n" || last.NewestSnapshotBytes != 9 {
		t.Fatalf("newest sample: %+v", last)
	}
	if !got[0].TakenAt.Before(got[1].TakenAt) {
		t.Fatal("samples are not oldest first")
	}

	// A sweep run in a loop cannot grow one bucket without limit either.
	for i := 0; i < 2*StorageSamplesPerBucket; i++ {
		at := storageDay.Add(60*24*time.Hour + time.Duration(i)*time.Minute)
		if err := s.AddStorageSamples(ctx, []StorageSample{{Bucket: "helios-site", TakenAt: at, Kind: StorageApp}}, storageDay); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.StorageSamples(ctx, time.Time{}); len(got) != StorageSamplesPerBucket {
		t.Fatalf("%d samples for one bucket, want at most %d", len(got), StorageSamplesPerBucket)
	}
	if err := s.DeleteStorageSamples(ctx, "helios-site"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.StorageSamples(ctx, time.Time{}); len(got) != 0 {
		t.Fatalf("samples of a deleted bucket remain: %d", len(got))
	}
}

func TestFullPruneRecordKeepsAttemptAndCompletionApart(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	p, err := s.StoragePruneOf(ctx, "helios-site")
	if err != nil || !p.AttemptedAt.IsZero() || !p.CompletedAt.IsZero() {
		t.Fatalf("never pruned: %+v %v", p, err)
	}
	if err := s.StoragePruneAttempted(ctx, "helios-site", storageDay); err != nil {
		t.Fatal(err)
	}
	p, _ = s.StoragePruneOf(ctx, "helios-site")
	if !p.AttemptedAt.Equal(storageDay) || !p.CompletedAt.IsZero() {
		t.Fatalf("after an attempt: %+v", p)
	}
	done := storageDay.Add(40 * time.Minute)
	if err := s.StoragePruneCompleted(ctx, "helios-site", done); err != nil {
		t.Fatal(err)
	}
	p, _ = s.StoragePruneOf(ctx, "helios-site")
	if !p.AttemptedAt.Equal(storageDay) || !p.CompletedAt.Equal(done) {
		t.Fatalf("after completion: %+v", p)
	}
}

// The tables are additive: they must not raise the state version, or an
// upgrade would refuse the store, and a store an older binary made must
// read as "nothing recorded" until a daemon has opened it for writing.
func TestStorageTablesDoNotChangeTheStateVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Version(ctx); v != compat.StateVersion {
		t.Fatalf("state version %d, want %d", v, compat.StateVersion)
	}
	s.Close()

	// What an older binary left behind: the same version, no storage tables.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TRIGGER storage_tombstone_cleared_by_revision; DROP TABLE storage_tombstones; DROP TABLE storage_samples; DROP TABLE storage_prunes`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ro.StorageTombstones(ctx); err != nil || got != nil {
		t.Fatalf("tombstones on an older store: %v %v", got, err)
	}
	if _, err := ro.StorageTombstone(ctx, "site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("one tombstone on an older store: %v", err)
	}
	if got, err := ro.StorageSamples(ctx, time.Time{}); err != nil || got != nil {
		t.Fatalf("samples on an older store: %v %v", got, err)
	}
	if _, err := ro.StoragePruneOf(ctx, "b"); err != nil {
		t.Fatalf("prune record on an older store: %v", err)
	}
	ro.Close()

	// The next writable open adds them back without a migration.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "helios-site", "key:one", storageDay); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Version(ctx); v != compat.StateVersion {
		t.Fatalf("state version %d after adding the tables", v)
	}
}

// An app that leaves through a move keeps a row that never expires, and a
// retried removal cannot turn it into one that does.
func TestAnAppThatMovedAwayNeverGetsAnExpiringTombstone(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if err := s.MarkStorageMoved(ctx, "site", "helios-site", storageDay); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAppLeavingTombstone(ctx, "site", "helios-site", "key:one", storageDay.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := s.StorageTombstone(ctx, "site")
	if err != nil || !got.Moved || !got.Kept() || !got.RemovedAt.Equal(storageDay) || got.Account != "" {
		t.Fatalf("a retried removal changed the moved row: %+v %v", got, err)
	}
	if err := s.BindStorageTombstone(ctx, "site", "", "b2:one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bound an account to a bucket that moved away: %v", err)
	}
	// Marking a move withdraws an expiry recorded before it.
	if err := s.RemoveAppLeavingTombstone(ctx, "blog", "helios-blog", "key:one", storageDay); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkStorageMoved(ctx, "blog", "helios-blog", storageDay.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.StorageTombstone(ctx, "blog"); !got.Moved || !got.Kept() || got.Account != "" {
		t.Fatalf("moved after removal: %+v", got)
	}
	// Deploying it here again makes the bucket this machine's once more.
	if err := s.SaveRevision(ctx, Revision{App: "site", ID: "r1", Manifest: []byte(`{}`), CreatedAt: storageDay}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StorageTombstone(ctx, "site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a redeploy left the moved row: %v", err)
	}
}
