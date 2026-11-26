package app

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

const dataManifest = `{"app":"blog","data":{"volumes":{"uploads":{}}},"workloads":{"web":{"kind":"web","image":"x","port":80,"routes":[{"host":"blog.example.com"}]}}}`

// removeFixture is a machine with storage set under the prefix "helios".
func removeFixture(t *testing.T) (Remove, *secrets.Store) {
	t.Helper()
	dockertest.New(t)
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sec := newSecrets(t)
	setStorage(t, sec, "helios", "key-one")
	return Remove{Store: store, Secrets: sec, StateDir: dir}, sec
}

// remove plans and applies a removal, and returns the plan's last change.
func remove(t *testing.T, r Remove, in RemoveInput) string {
	t.Helper()
	raw, _ := json.Marshal(in)
	plan, err := r.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if err := step.Apply(context.Background(), io.Discard); err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
	}
	return plan.Steps[len(plan.Steps)-1].Change
}

// backedUp records a finished run of a kind for an app that names a
// snapshot.
func backedUp(t *testing.T, store *state.Store, app, kind, snapshot string) {
	t.Helper()
	ctx := context.Background()
	id, err := store.StartBackupRun(ctx, app, kind, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishBackupRun(ctx, id, state.BackupRun{OK: true, FinishedAt: time.Now().UTC(), Snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
}

func TestRemovingAnAppStartsItsBucketsThirtyDays(t *testing.T) {
	r, sec := removeFixture(t)
	ctx := context.Background()
	seedManifest(t, r.Store, "blog", dataManifest)
	backedUp(t, r.Store, "blog", state.BackupRunBackup, strings.Repeat("a", 64))
	before := time.Now().UTC().Add(-time.Second)
	change := remove(t, r, RemoveInput{App: "blog"})
	if want := "; its backups in bucket helios-blog are deleted after 30 days unless helios storage keep blog cancels that"; !strings.HasSuffix(change, want) {
		t.Fatalf("the plan does not say the bucket expires: %s", change)
	}
	got, err := r.Store.StorageTombstone(ctx, "blog")
	if err != nil {
		t.Fatal(err)
	}
	st := StorageWatch{Secrets: sec}
	current, _ := st.storage()
	if got.Bucket != "helios-blog" || got.RemovedAt.Before(before) || got.Kept() || got.Moved || got.Account != storageCredentials(current) {
		t.Fatalf("tombstone: %+v", got)
	}
	if revs, _ := r.Store.Revisions(ctx, "blog"); len(revs) != 0 {
		t.Fatal("the app was not forgotten")
	}

	// What is left of it can go without touching the clock, and the plan
	// says when the backups go.
	fake := dockertest.New(t)
	fake.AddVolume("bedrock-blog-uploads", map[string]string{"bedrock.owner": "bedrock", "bedrock.app": "blog"})
	change = remove(t, r, RemoveInput{App: "blog", Data: true})
	expires := got.RemovedAt.Add(BucketExpiry).Format("2006-01-02")
	if !strings.Contains(change, "its backups in bucket helios-blog stay until "+expires+" unless helios storage keep blog cancels their expiry") {
		t.Fatalf("the leftovers plan: %s", change)
	}
	after, err := r.Store.StorageTombstone(ctx, "blog")
	if err != nil || !after.RemovedAt.Equal(got.RemovedAt) {
		t.Fatalf("removing what was left moved the clock: %+v %v", after, err)
	}

	// Deploying an app of the same name again clears the tombstone.
	seedManifest(t, r.Store, "blog", dataManifest)
	if _, err := r.Store.StorageTombstone(ctx, "blog"); err != state.ErrNotFound {
		t.Fatalf("a redeploy left the tombstone: %v", err)
	}
	// Removed with its data, the data step says how long the backups last.
	raw, _ := json.Marshal(RemoveInput{App: "blog", Data: true})
	plan, err := r.Plan(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Name == "data" && !strings.Contains(step.Change, "no way back except a backup; its backups in the storage bucket stay for 30 more days") {
			t.Fatalf("the data step: %s", step.Change)
		}
	}
}

func TestRemovingAnAppWithNothingBackedUpRecordsNoTombstone(t *testing.T) {
	ctx := context.Background()
	t.Run("an app that keeps no data", func(t *testing.T) {
		r, _ := removeFixture(t)
		seedApp(t, r.Store, "hello")
		if change := remove(t, r, RemoveInput{App: "hello"}); strings.Contains(change, "bucket") {
			t.Fatalf("plan: %s", change)
		}
		if got, _ := r.Store.StorageTombstones(ctx); len(got) != 0 {
			t.Fatalf("tombstones: %+v", got)
		}
	})
	t.Run("an app that keeps no data now and was backed up once", func(t *testing.T) {
		r, _ := removeFixture(t)
		seedApp(t, r.Store, "hello")
		backedUp(t, r.Store, "hello", releaseCheckpointRun, strings.Repeat("a", 64))
		remove(t, r, RemoveInput{App: "hello"})
		if got, err := r.Store.StorageTombstone(ctx, "hello"); err != nil || got.Bucket != "helios-hello" {
			t.Fatalf("tombstone: %+v %v", got, err)
		}
	})
	// Another machine may run a blog of its own against the same account
	// and prefix. This machine never wrote to that bucket, so removing its
	// blog must not start a clock on it.
	t.Run("an app that keeps data and was never backed up here", func(t *testing.T) {
		r, _ := removeFixture(t)
		seedManifest(t, r.Store, "blog", dataManifest)
		// What this machine recorded reading, or failing to make, is not a
		// snapshot it made.
		backedUp(t, r.Store, "blog", state.BackupRunDrill, strings.Repeat("b", 64))
		backedUp(t, r.Store, "blog", state.BackupRunRestore, strings.Repeat("b", 64))
		backedUp(t, r.Store, "blog", state.BackupRunBackup, "")
		backedUp(t, r.Store, "shop", state.BackupRunBackup, strings.Repeat("c", 64))
		if change := remove(t, r, RemoveInput{App: "blog"}); strings.Contains(change, "bucket") {
			t.Fatalf("plan: %s", change)
		}
		if got, _ := r.Store.StorageTombstones(ctx); len(got) != 0 {
			t.Fatalf("tombstones: %+v", got)
		}
	})
	t.Run("storage is not set", func(t *testing.T) {
		r, _ := removeFixture(t)
		r.Secrets = newSecrets(t)
		seedManifest(t, r.Store, "blog", dataManifest)
		if change := remove(t, r, RemoveInput{App: "blog"}); strings.Contains(change, "bucket") {
			t.Fatalf("plan: %s", change)
		}
		if got, _ := r.Store.StorageTombstones(ctx); len(got) != 0 {
			t.Fatalf("tombstones: %+v", got)
		}
	})
	t.Run("what an app left without a tombstone", func(t *testing.T) {
		r, _ := removeFixture(t)
		fake := dockertest.New(t)
		fake.AddVolume("bedrock-old-uploads", map[string]string{"bedrock.owner": "bedrock", "bedrock.app": "old"})
		change := remove(t, r, RemoveInput{App: "old", Data: true})
		if !strings.Contains(change, "its backups in the storage bucket stay, and are the only way to bring its data back") {
			t.Fatalf("plan: %s", change)
		}
		if got, _ := r.Store.StorageTombstones(ctx); len(got) != 0 {
			t.Fatalf("removing leftovers recorded %+v", got)
		}
	})
}

// moveRecord is the record a move leaves on either machine for "blog".
func moveRecord(role string) *migrationRecord {
	h := Handoff{App: "blog", From: "vps", To: "other", Migration: "move-0123456789abcdef", Phase: "final", Revision: "r1", ManifestDigest: strings.Repeat("d", 64)}
	if role == "target" {
		return &migrationRecord{Handoff: h, Role: role, Phase: "staged", TargetRevision: "rev-1"}
	}
	return &migrationRecord{Handoff: h, Role: role, Phase: "fenced"}
}

// An app that moved to another machine left its bucket to that machine.
func TestRemovingAnAppThatMovedNeverStartsAnExpiry(t *testing.T) {
	ctx := context.Background()
	moved := func(t *testing.T, r Remove) {
		t.Helper()
		got, err := r.Store.StorageTombstone(ctx, "blog")
		if err != nil || !got.Moved || !got.Kept() || got.Bucket != "helios-blog" {
			t.Fatalf("tombstone: %+v %v", got, err)
		}
		if bucketDue(*got, time.Now().Add(10*BucketExpiry)) {
			t.Fatal("a moved app's bucket comes due")
		}
	}
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			r, _ := removeFixture(t)
			seedManifest(t, r.Store, "blog", dataManifest)
			if err := saveMigration(r.Store.Path(), moveRecord(role)); err != nil {
				t.Fatal(err)
			}
			change := remove(t, r, RemoveInput{App: "blog"})
			if !strings.Contains(change, "its backups in bucket helios-blog stay, because a move is on record for it") {
				t.Fatalf("plan: %s", change)
			}
			moved(t, r)
		})
	}

	// A record of a move that cannot be read is still one. The removal goes
	// on, since that is how such a record is cleared, and the bucket stays.
	t.Run("a move record that does not read", func(t *testing.T) {
		r, _ := removeFixture(t)
		seedManifest(t, r.Store, "blog", dataManifest)
		if err := saveMigration(r.Store.Path(), &migrationRecord{Handoff: Handoff{App: "blog"}, Role: "source", Phase: "captured"}); err != nil {
			t.Fatal(err)
		}
		remove(t, r, RemoveInput{App: "blog"})
		moved(t, r)
	})

	// The removal marked the move, forgot the move's record, and then failed
	// before it forgot the app. The retry finds the app without its move.
	t.Run("a removal interrupted after it forgot the move", func(t *testing.T) {
		r, _ := removeFixture(t)
		seedManifest(t, r.Store, "blog", dataManifest)
		// SaveRevision clears tombstones, so the mark goes in after it.
		if err := r.Store.MarkStorageMoved(ctx, "blog", "helios-blog", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		change := remove(t, r, RemoveInput{App: "blog"})
		if !strings.Contains(change, "stay, because a move is on record") {
			t.Fatalf("plan: %s", change)
		}
		moved(t, r)
	})

	t.Run("a move recorded after the removal was reviewed", func(t *testing.T) {
		r, _ := removeFixture(t)
		seedManifest(t, r.Store, "blog", dataManifest)
		backedUp(t, r.Store, "blog", state.BackupRunBackup, strings.Repeat("a", 64))
		raw, _ := json.Marshal(RemoveInput{App: "blog"})
		plan, err := r.Plan(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveMigration(r.Store.Path(), moveRecord("source")); err != nil {
			t.Fatal(err)
		}
		forget := plan.Steps[len(plan.Steps)-1]
		if err := forget.Apply(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "review the removal again") {
			t.Fatalf("the removal went on: %v", err)
		}
		if revs, _ := r.Store.Revisions(ctx, "blog"); len(revs) == 0 {
			t.Fatal("the app was forgotten on a stale plan")
		}
		if got, _ := r.Store.StorageTombstones(ctx); len(got) != 0 {
			t.Fatalf("tombstones: %+v", got)
		}
	})
}

func TestMoveRecordsOfTheFixtureRead(t *testing.T) {
	r, _ := removeFixture(t)
	for _, role := range []string{"source", "target"} {
		if err := saveMigration(r.Store.Path(), moveRecord(role)); err != nil {
			t.Fatal(err)
		}
		if record, err := readMigration(r.Store.Path(), "blog"); err != nil || record == nil {
			t.Fatalf("%s: %v", role, err)
		}
	}
}
