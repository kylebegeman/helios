package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/objectstore"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// fakeAccount is a storage account: its buckets, and what it refuses.
type fakeAccount struct {
	id      string
	buckets map[string]*fakeBucket
	// listErr and accountErr fail the two calls every pass starts with.
	listErr, accountErr error
	usageErr            map[string]error
	deleteErr           map[string]error
	// deleted names the buckets that are gone, with the time each deletion
	// was allowed from.
	deleted map[string]time.Time
}

type fakeBucket struct {
	bytes, files int64
	lastWrite    time.Time
	// keys are the bucket's files in the order of their names, as a
	// listing returns them and a deletion takes them.
	keys []string
	// arrives is a file that turns up once the bucket was read: someone
	// wrote to it while it was being deleted.
	arrives string
}

// repository is the files of a restic repository with the given snapshots.
func repository(snapshots ...string) []string {
	keys := []string{"config", "data/0f/0f11", "index/a1", "keys/k1"}
	for _, id := range snapshots {
		keys = append(keys, "snapshots/"+id)
	}
	return keys
}

func (a *fakeAccount) Account(context.Context) (string, error) { return a.id, a.accountErr }

func (a *fakeAccount) Buckets(context.Context) ([]objectstore.Bucket, error) {
	if a.listErr != nil {
		return nil, a.listErr
	}
	var out []objectstore.Bucket
	for _, name := range sortedKeys(a.buckets) {
		out = append(out, objectstore.Bucket{Name: name, ID: "id-" + name})
	}
	return out, nil
}

func (a *fakeAccount) Usage(_ context.Context, b objectstore.Bucket) (objectstore.Usage, error) {
	if err := a.usageErr[b.Name]; err != nil {
		return objectstore.Usage{}, err
	}
	bucket, ok := a.buckets[b.Name]
	if !ok {
		return objectstore.Usage{}, objectstore.ErrNoBucket
	}
	return objectstore.Usage{Bytes: bucket.bytes, Files: bucket.files, LastWrite: bucket.lastWrite}, nil
}

func (a *fakeAccount) examine(b objectstore.Bucket, check objectstore.Check) (*fakeBucket, error) {
	bucket, ok := a.buckets[b.Name]
	if !ok || b.ID != "id-"+b.Name {
		return nil, objectstore.ErrNoBucket
	}
	if err := a.usageErr[b.Name]; err != nil {
		return nil, err
	}
	if !check.NotWrittenSince.IsZero() && bucket.lastWrite.After(check.NotWrittenSince) {
		return nil, fmt.Errorf("%w: data/0f on %s", objectstore.ErrWrittenSince, bucket.lastWrite.Format(time.RFC3339))
	}
	for _, key := range bucket.keys {
		if check.Key != nil {
			if err := check.Key(key); err != nil {
				return nil, err
			}
		}
	}
	if check.Whole != nil {
		if err := check.Whole(); err != nil {
			return nil, err
		}
	}
	return bucket, nil
}

func (a *fakeAccount) Examine(_ context.Context, b objectstore.Bucket, check objectstore.Check) error {
	_, err := a.examine(b, check)
	return err
}

// DeleteBucket deletes as the real stores do: the whole bucket is read
// first, then its files go in the order of their names, each checked again.
// A deleteErr stops it after two files, which stay deleted.
func (a *fakeAccount) DeleteBucket(_ context.Context, b objectstore.Bucket, check objectstore.Check) (objectstore.Deleted, error) {
	bucket, err := a.examine(b, check)
	if err != nil {
		return objectstore.Deleted{}, err
	}
	if bucket.arrives != "" {
		bucket.keys, bucket.arrives = append(bucket.keys, bucket.arrives), ""
	}
	var done objectstore.Deleted
	for len(bucket.keys) > 0 {
		if err := a.deleteErr[b.Name]; err != nil && done.Files == 2 {
			return done, err
		}
		if check.Key != nil {
			if err := check.Key(bucket.keys[0]); err != nil {
				return done, err
			}
		}
		bucket.keys = bucket.keys[1:]
		done.Files++
	}
	delete(a.buckets, b.Name)
	if a.deleted == nil {
		a.deleted = map[string]time.Time{}
	}
	a.deleted[b.Name] = check.NotWrittenSince
	return objectstore.Deleted{Files: bucket.files, Bytes: bucket.bytes, Bucket: true}, nil
}

// storageFixture is a machine named "vps" with the storage prefix "helios",
// one account, and a clock the test moves.
type storageFixture struct {
	t       *testing.T
	store   *state.Store
	secrets *secrets.Store
	account *fakeAccount
	now     time.Time
	watch   StorageWatch
}

// snapshotOf is the id of the one snapshot a fixture machine made of an
// app: "blog" on "vps" and "blog" on "other" are different snapshots.
func snapshotOf(machine, app string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(machine+"/"+app)))
}

var storageDay = time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC)

func setStorage(t *testing.T, sec *secrets.Store, prefix, keyID string) {
	t.Helper()
	if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "https://storage.example.test", "key_id": keyID, "key": "fixture", "bucket_prefix": prefix, "password": "fixture"}); err != nil {
		t.Fatal(err)
	}
}

func newStorageFixture(t *testing.T) *storageFixture {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	f := &storageFixture{t: t, store: store, secrets: newSecrets(t), now: storageDay,
		account: &fakeAccount{id: "b2:acct", buckets: map[string]*fakeBucket{}}}
	setStorage(t, f.secrets, "helios", "key-one")
	f.watch = StorageWatch{Store: store, Secrets: f.secrets, Hostname: func() string { return "vps" },
		Objects: func(objectstore.Config) (objectstore.Store, error) { return f.account, nil },
		Now:     func() time.Time { return f.now }}
	return f
}

// ran records a finished run of a kind for an app that names a snapshot,
// as this machine's state does.
func (f *storageFixture) ran(app, kind, snapshot string) {
	f.t.Helper()
	ctx := context.Background()
	id, err := f.store.StartBackupRun(ctx, app, kind, storageDay.Add(-24*time.Hour))
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.store.FinishBackupRun(ctx, id, state.BackupRun{OK: true, FinishedAt: storageDay.Add(-24 * time.Hour), Snapshot: snapshot}); err != nil {
		f.t.Fatal(err)
	}
}

// bucket puts a bucket in the account, last written at the given time. It
// holds a repository without a snapshot until holds says otherwise.
func (f *storageFixture) bucket(name string, bytes int64, lastWrite time.Time) {
	f.account.buckets[name] = &fakeBucket{bytes: bytes, files: 12, lastWrite: lastWrite, keys: repository()}
}

// holds sets the snapshots in a bucket's repository.
func (f *storageFixture) holds(bucket string, snapshots ...string) {
	f.t.Helper()
	b := f.account.buckets[bucket]
	if b == nil {
		f.t.Fatalf("no bucket %s", bucket)
	}
	b.keys = repository(snapshots...)
}

// removed is an app this machine backed up once and then removed: the run
// that made its snapshot, that snapshot in its bucket, and its tombstone.
func (f *storageFixture) removed(app string, at time.Time) {
	f.t.Helper()
	st, err := integration.LoadStorage(f.secrets)
	if err != nil {
		f.t.Fatal(err)
	}
	f.ran(app, state.BackupRunBackup, snapshotOf("vps", app))
	_, existed := f.account.buckets[st.Bucket(app)]
	f.tombstoned(app, at)
	if !existed {
		f.holds(st.Bucket(app), snapshotOf("vps", app))
	}
}

// tombstoned records only what helios remove records: the app's tombstone,
// with a bucket last written a day before.
func (f *storageFixture) tombstoned(app string, at time.Time) {
	f.t.Helper()
	st, err := integration.LoadStorage(f.secrets)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.store.RemoveAppLeavingTombstone(context.Background(), app, st.Bucket(app), storageCredentials(st), at); err != nil {
		f.t.Fatal(err)
	}
	if _, ok := f.account.buckets[st.Bucket(app)]; !ok {
		f.bucket(st.Bucket(app), 4<<30, at.Add(-24*time.Hour))
	}
}

func (f *storageFixture) run(kind string, input any) (string, error) {
	f.t.Helper()
	reg := kernel.Registry{}
	reg.Add(StorageSweep{f.watch})
	reg.Add(StorageKeep{f.watch})
	reg.Add(StoragePurge{f.watch})
	raw, _ := json.Marshal(input)
	var lines []string
	receipt, err := kernel.New(f.store, reg, "daemon").Run(context.Background(), kind, raw, func(ev kernel.Event) {
		if ev.Line != "" {
			lines = append(lines, ev.Line)
		}
		if ev.Step != nil && ev.Step.Error != "" {
			lines = append(lines, "ERROR "+ev.Step.Error)
		}
	})
	output := strings.Join(lines, "\n")
	if err == nil && receipt.Status != state.Succeeded {
		err = fmt.Errorf("%s %s: %s", kind, receipt.Status, output)
	}
	return output, err
}

// sweep runs the nightly pass with no restic to ask.
func (f *storageFixture) sweep() (string, error) {
	f.t.Helper()
	dockerUnreachable(f.t)
	return f.run(StorageSweepKind, StorageSweepInput{})
}

func (f *storageFixture) tombstone(app string) *state.StorageTombstone {
	f.t.Helper()
	got, err := f.store.StorageTombstone(context.Background(), app)
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func TestARemovedAppsBucketIsDeletedOnlyAfterThirtyDays(t *testing.T) {
	f := newStorageFixture(t)
	removedAt := storageDay
	f.removed("blog", removedAt)

	// The first sweep binds the tombstone to the account and deletes nothing.
	f.now = removedAt.Add(time.Hour)
	if out, err := f.sweep(); err != nil {
		t.Fatal(err, out)
	}
	if got := f.tombstone("blog"); got == nil || got.Account != "b2:acct" || got.Problem != "" {
		t.Fatalf("after the first sweep: %+v", got)
	}

	// One minute short of thirty days.
	f.now = removedAt.Add(BucketExpiry - time.Minute)
	out, err := f.sweep()
	if err != nil {
		t.Fatal(err, out)
	}
	if len(f.account.deleted) != 0 || f.tombstone("blog") == nil {
		t.Fatalf("deleted before its 30 days: %v\n%s", f.account.deleted, out)
	}

	// Thirty days to the minute.
	f.now = removedAt.Add(BucketExpiry)
	out, err = f.sweep()
	if err != nil {
		t.Fatal(err, out)
	}
	allowedFrom, gone := f.account.deleted["helios-blog"]
	if !gone || !allowedFrom.Equal(removedAt.Add(bucketWriteSlack)) {
		t.Fatalf("the bucket was not deleted, or without the write check: %v\n%s", f.account.deleted, out)
	}
	if f.tombstone("blog") != nil {
		t.Fatal("the tombstone outlived its bucket")
	}
	if samples, _ := f.store.StorageSamples(context.Background(), time.Time{}); len(samples) != 0 {
		t.Fatalf("samples of a deleted bucket stay: %+v", samples)
	}
	if !strings.Contains(out, "deleted bucket helios-blog: 12 file(s), 4.0 GB") {
		t.Fatalf("output: %s", out)
	}
}

// The plan a sweep shows names every bucket it may delete, and its digest
// covers them.
func TestTheSweepsPlanNamesWhatItDeletes(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.removed("shop", storageDay.Add(10*24*time.Hour))
	plan := func() string {
		t.Helper()
		p, err := StorageSweep{f.watch}.Plan(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		return p.Steps[1].Change
	}
	f.now = storageDay.Add(29 * 24 * time.Hour)
	if got := plan(); got != "no removed app's bucket has reached its 30 days; delete nothing" {
		t.Fatalf("plan: %s", got)
	}
	f.now = storageDay.Add(31 * 24 * time.Hour)
	if got := plan(); !strings.Contains(got, "helios-blog (blog, removed 2026-11-25)") || strings.Contains(got, "shop") {
		t.Fatalf("plan: %s", got)
	}
	// A bucket that came due after the plan was read is left for the next
	// sweep: the step deletes only what its plan named.
	f.now = storageDay.Add(41 * 24 * time.Hour)
	var out strings.Builder
	if err := f.watch.expire(context.Background(), []string{"blog"}, &out); err != nil {
		t.Fatal(err)
	}
	if _, gone := f.account.deleted["helios-shop"]; gone || f.tombstone("shop") == nil {
		t.Fatalf("deleted a bucket the plan did not name:\n%s", out.String())
	}
	if _, gone := f.account.deleted["helios-blog"]; !gone || !strings.Contains(out.String(), "the plan that was reviewed does not name it") {
		t.Fatalf("output: %s", out.String())
	}
}

// From one machine, another machine's buckets under the same prefix look
// like buckets nobody uses. None of them is ever deleted.
func TestABucketWithoutATombstoneIsNeverDeleted(t *testing.T) {
	f := newStorageFixture(t)
	ctx := context.Background()
	seedApp(t, f.store, "site")
	old := storageDay.Add(-400 * 24 * time.Hour)
	for _, name := range []string{"helios-site", "helios-machine-vps", "helios-machine-other", "helios-forgotten", "helios-loom", "unrelated"} {
		f.bucket(name, 9<<30, old)
	}
	for _, at := range []time.Duration{0, 31 * 24 * time.Hour, 400 * 24 * time.Hour} {
		f.now = storageDay.Add(at)
		if out, err := f.sweep(); err != nil {
			t.Fatal(err, out)
		}
	}
	if len(f.account.deleted) != 0 || len(f.account.buckets) != 6 {
		t.Fatalf("a sweep deleted %v", f.account.deleted)
	}
	// Nor by hand: purge and keep only take an app this machine removed.
	for _, kind := range []string{StoragePurgeKind, StorageKeepKind} {
		for _, app := range []string{"forgotten", "loom", "site", "machine-other", ""} {
			_, err := f.run(kind, StorageAppInput{App: app})
			if err == nil {
				t.Fatalf("%s accepted %q, which has no tombstone", kind, app)
			}
			if app != "" && !strings.Contains(err.Error(), "only takes an app that helios remove took off this machine") {
				t.Fatalf("%s %s: %v", kind, app, err)
			}
		}
	}
	if len(f.account.deleted) != 0 {
		t.Fatalf("a purge deleted %v", f.account.deleted)
	}
	// What the sweep recorded says whose each one is.
	samples, err := f.store.StorageSamples(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, s := range samples {
		kinds[s.Bucket] = s.Kind
	}
	want := map[string]string{"helios-site": state.StorageApp, "helios-machine-vps": state.StorageMachine,
		"helios-machine-other": state.StorageForeign, "helios-forgotten": state.StorageForeign, "helios-loom": state.StorageForeign}
	if fmt.Sprint(kinds) != fmt.Sprint(want) {
		t.Fatalf("kinds %v, want %v", kinds, want)
	}
}

func TestAKeptBucketNeverExpiresAndCanStillBePurged(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.now = storageDay.Add(24 * time.Hour)
	out, err := f.run(StorageKeepKind, StorageAppInput{App: "blog"})
	if err != nil || !strings.Contains(out, "bucket helios-blog is kept") {
		t.Fatal(err, out)
	}
	if got := f.tombstone("blog"); got == nil || !got.Kept() {
		t.Fatalf("not kept: %+v", got)
	}
	if _, err := f.run(StorageKeepKind, StorageAppInput{App: "blog"}); err == nil || !strings.Contains(err.Error(), "kept already") {
		t.Fatalf("a second keep: %v", err)
	}
	f.now = storageDay.Add(90 * 24 * time.Hour)
	if out, err := f.sweep(); err != nil || len(f.account.deleted) != 0 {
		t.Fatalf("a kept bucket expired: %v %v\n%s", f.account.deleted, err, out)
	}
	if got := f.tombstone("blog"); got == nil || got.Problem != "" {
		t.Fatalf("a kept bucket is reported as a problem: %+v", got)
	}
	// Keeping cancels the expiry; it does not take away the way to delete.
	if out, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"}); err != nil {
		t.Fatal(err, out)
	}
	if _, gone := f.account.deleted["helios-blog"]; !gone || f.tombstone("blog") != nil {
		t.Fatal("purge left a kept bucket")
	}
}

func TestPurgeDeletesARemovedAppsBucketNow(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.now = storageDay.Add(2 * time.Hour)
	plan, err := StoragePurge{f.watch}.Plan(context.Background(), json.RawMessage(`{"app":"blog"}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "delete bucket helios-blog and every backup in it, the backups of blog removed on 2026-11-25 (no way back)"; plan.Steps[0].Change != want {
		t.Fatalf("plan: %s", plan.Steps[0].Change)
	}
	// Removed again, later, between the review and the apply: the plan no
	// longer describes the removal it would act on.
	later := storageDay.Add(time.Hour)
	f.removed("blog", later)
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err == nil || !strings.Contains(err.Error(), "review it again") {
		t.Fatalf("purge of a later removal: %v", err)
	}
	if len(f.account.deleted) != 0 {
		t.Fatal("deleted on a stale plan")
	}
	out, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"})
	if err != nil {
		t.Fatal(err, out)
	}
	allowedFrom, gone := f.account.deleted["helios-blog"]
	if !gone || !allowedFrom.Equal(later.Add(bucketWriteSlack)) || f.tombstone("blog") != nil {
		t.Fatalf("purge: %v\n%s", f.account.deleted, out)
	}
	// Once more: there is nothing left to purge.
	if _, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"}); err == nil {
		t.Fatal("purged a bucket that is gone")
	}
}

// Every doubt holds the bucket, records why, and deletes nothing.
func TestAnyDoubtHoldsTheBucket(t *testing.T) {
	due := storageDay.Add(BucketExpiry + time.Hour)
	for _, tc := range []struct {
		name    string
		arrange func(f *storageFixture)
		want    string
	}{
		{"written after the removal", func(f *storageFixture) {
			f.account.buckets["helios-blog"].lastWrite = storageDay.Add(3 * 24 * time.Hour)
		}, "something was uploaded to it after blog was removed"},
		{"written just past the slack", func(f *storageFixture) {
			f.account.buckets["helios-blog"].lastWrite = storageDay.Add(bucketWriteSlack + time.Second)
		}, "something was uploaded to it after blog was removed"},
		{"another account behind the same integration", func(f *storageFixture) {
			f.now = storageDay.Add(time.Hour)
			if out, err := f.sweep(); err != nil {
				f.t.Fatal(err, out)
			}
			f.account.id = "b2:another"
		}, "reaches another account"},
		{"other credentials before the first check", func(f *storageFixture) {
			setStorage(f.t, f.secrets, "helios", "key-two")
		}, "the storage credentials changed before bucket helios-blog was first checked"},
		{"another prefix", func(f *storageFixture) {
			setStorage(f.t, f.secrets, "other", "key-one")
			f.bucket("other-blog", 1<<30, storageDay.Add(-time.Hour))
		}, "the storage prefix changed since blog was removed"},
		{"a deletion that fails part way", func(f *storageFixture) {
			f.account.deleteErr = map[string]error{"helios-blog": errors.New("storage answered HTTP 503")}
		}, "deleting it did not finish after 2 file(s)"},
		// Another machine shares the account and the prefix and runs a blog
		// of its own. Its backups are in this bucket, uploaded before blog
		// was removed here and none since, so the upload check sees nothing.
		{"another machine's snapshot beside this machine's", func(f *storageFixture) {
			f.holds("helios-blog", snapshotOf("vps", "blog"), snapshotOf("other", "blog"))
		}, "1 of its 2 snapshot(s) were not made by this machine (the first is " + snapshotOf("other", "blog")[:8] + ")"},
		{"only another machine's snapshots", func(f *storageFixture) {
			f.holds("helios-blog", snapshotOf("other", "blog"))
		}, "1 of its 1 snapshot(s) were not made by this machine"},
		{"a snapshot this machine drilled and restored but did not make", func(f *storageFixture) {
			theirs := snapshotOf("other", "blog")
			f.holds("helios-blog", snapshotOf("vps", "blog"), theirs)
			f.ran("blog", state.BackupRunDrill, theirs)
			f.ran("blog", state.BackupRunRestore, theirs)
		}, "1 of its 2 snapshot(s) were not made by this machine"},
		{"another app's snapshot", func(f *storageFixture) {
			f.ran("shop", state.BackupRunBackup, snapshotOf("vps", "shop"))
			f.holds("helios-blog", snapshotOf("vps", "shop"))
		}, "1 of its 1 snapshot(s) were not made by this machine"},
		{"a snapshot file that is not a snapshot id", func(f *storageFixture) {
			f.account.buckets["helios-blog"].keys = append(repository(snapshotOf("vps", "blog")), "snapshots/tmp-upload")
		}, "1 of its 2 snapshot(s) were not made by this machine"},
		// Not a repository this machine could have made a snapshot in and
		// then deleted from: files, and no snapshot at all.
		{"files and no snapshot", func(f *storageFixture) {
			f.holds("helios-blog")
		}, "it holds files but no snapshot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStorageFixture(t)
			f.removed("blog", storageDay)
			tc.arrange(f)
			f.now = due
			out, err := f.sweep()
			if err != nil {
				t.Fatalf("a held bucket must not fail the sweep: %v\n%s", err, out)
			}
			if len(f.account.deleted) != 0 || f.account.buckets["helios-blog"] == nil {
				t.Fatalf("deleted in doubt: %v", f.account.deleted)
			}
			got := f.tombstone("blog")
			if got == nil || !strings.Contains(got.Problem, tc.want) || !strings.Contains(out, "bucket helios-blog stays: ") {
				t.Fatalf("problem %+v, want %q\n%s", got, tc.want, out)
			}
			// By hand it is refused for the same reason, and says so.
			if _, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("purge in doubt: %v", err)
			}
			if len(f.account.deleted) != 0 {
				t.Fatalf("purge deleted in doubt: %v", f.account.deleted)
			}
		})
	}
}

// A tombstone alone proves nothing about whose backups a bucket holds. A
// machine that removed an app it never backed up has one only if something
// went wrong, and it must still not delete the bucket: an app of the same
// name on another machine may be all that ever wrote to it.
func TestATombstoneWithoutABackupMadeHereDeletesNothing(t *testing.T) {
	f := newStorageFixture(t)
	f.tombstoned("blog", storageDay)
	f.holds("helios-blog", snapshotOf("other", "blog"))
	f.now = storageDay.Add(BucketExpiry + time.Hour)
	out, err := f.sweep()
	if err != nil {
		t.Fatal(err, out)
	}
	const want = "this machine has no record of a backup of blog"
	if got := f.tombstone("blog"); len(f.account.deleted) != 0 || got == nil || !strings.Contains(got.Problem, want) {
		t.Fatalf("deleted %v, tombstone %+v\n%s", f.account.deleted, got, out)
	}
	// An empty repository changes nothing: there is still no proof.
	f.holds("helios-blog")
	if _, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"}); err == nil || !strings.Contains(err.Error(), want) || len(f.account.deleted) != 0 {
		t.Fatalf("purge without a backup made here: %v, deleted %v", err, f.account.deleted)
	}
}

// Purging minutes after a removal is the case the upload check cannot see:
// everything in the bucket was uploaded before the removal, including what
// another machine that runs the same app uploaded a moment ago.
func TestPurgeRightAfterARemovalLeavesAnotherMachinesBackups(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.holds("helios-blog", snapshotOf("vps", "blog"), snapshotOf("other", "blog"))
	f.account.buckets["helios-blog"].lastWrite = storageDay.Add(20 * time.Minute)
	f.now = storageDay.Add(30 * time.Minute)
	if _, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"}); err == nil || !strings.Contains(err.Error(), "were not made by this machine") {
		t.Fatalf("purge: %v", err)
	}
	if len(f.account.deleted) != 0 || f.account.buckets["helios-blog"] == nil {
		t.Fatalf("purge deleted a bucket another machine backs up to: %v", f.account.deleted)
	}
	// Once the other machine's snapshot is gone, the same purge goes through.
	f.holds("helios-blog", snapshotOf("vps", "blog"))
	if out, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"}); err != nil || f.account.buckets["helios-blog"] != nil {
		t.Fatalf("purge of this machine's own bucket: %v\n%s", err, out)
	}
}

// A deletion that stops part way has already deleted the repository's
// config, so restic could no longer open it. The bucket's own listing still
// says whose snapshots are left, and the next night finishes the job.
func TestAnInterruptedDeletionCarriesOn(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.account.deleteErr = map[string]error{"helios-blog": errors.New("storage answered HTTP 503")}
	f.now = storageDay.Add(BucketExpiry)
	if out, err := f.sweep(); err != nil || !strings.Contains(f.tombstone("blog").Problem, "the next sweep carries on") {
		t.Fatal(err, out)
	}
	if left := f.account.buckets["helios-blog"].keys; slices.Contains(left, "config") || !slices.Contains(left, "snapshots/"+snapshotOf("vps", "blog")) {
		t.Fatalf("the fixture did not stop after the config: %v", left)
	}
	// While it waits, another machine initialises a repository in what is
	// left and backs up into it. That stops the deletion for good.
	theirs := "snapshots/" + snapshotOf("other", "blog")
	f.account.buckets["helios-blog"].keys = append(f.account.buckets["helios-blog"].keys, theirs)
	f.account.deleteErr = nil
	f.now = f.now.Add(24 * time.Hour)
	if out, err := f.sweep(); err != nil || !strings.Contains(f.tombstone("blog").Problem, "were not made by this machine") {
		t.Fatal(err, out)
	}
	// Without it, the next night finishes.
	keys := f.account.buckets["helios-blog"].keys
	f.account.buckets["helios-blog"].keys = keys[:len(keys)-1]
	f.now = f.now.Add(24 * time.Hour)
	if out, err := f.sweep(); err != nil || f.tombstone("blog") != nil || f.account.buckets["helios-blog"] != nil {
		t.Fatalf("the next sweep did not carry on: %v\n%s", err, out)
	}
}

// A snapshot that turns up between reading the bucket and deleting it
// stops the deletion where it is.
func TestASnapshotThatArrivesDuringTheDeletionStopsIt(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.account.buckets["helios-blog"].arrives = "snapshots/" + snapshotOf("other", "blog")
	f.now = storageDay.Add(BucketExpiry)
	out, err := f.sweep()
	if err != nil {
		t.Fatal(err, out)
	}
	if got := f.tombstone("blog"); got == nil || !strings.Contains(got.Problem, "appeared in it while it was being deleted") || f.account.buckets["helios-blog"] == nil {
		t.Fatalf("tombstone %+v\n%s", got, out)
	}
	if left := f.account.buckets["helios-blog"].keys; len(left) != 1 || !strings.HasSuffix(left[0], snapshotOf("other", "blog")) {
		t.Fatalf("the other machine's snapshot did not survive: %v", left)
	}
}

// For a few weeks in 2026 a backup recorded its snapshot's short id. Such
// a record still proves the snapshot it begins was made here.
func TestASnapshotRecordedByItsShortIDIsThisMachines(t *testing.T) {
	f := newStorageFixture(t)
	f.ran("blog", state.BackupRunBackup, snapshotOf("vps", "blog")[:8])
	f.tombstoned("blog", storageDay)
	f.holds("helios-blog", snapshotOf("vps", "blog"), snapshotOf("other", "blog"))
	f.now = storageDay.Add(BucketExpiry)
	if out, err := f.sweep(); err != nil || !strings.Contains(f.tombstone("blog").Problem, "1 of its 2 snapshot(s) were not made by this machine") {
		t.Fatal(err, out)
	}
	f.holds("helios-blog", snapshotOf("vps", "blog"))
	if out, err := f.sweep(); err != nil || f.tombstone("blog") != nil {
		t.Fatalf("a bucket with only this machine's snapshot stays: %v\n%s", err, out)
	}
}

// A bucket that will not pass on its day says so on the first night, while
// the report still shows a date for it. A night on which it cannot be read
// says nothing either way.
func TestABucketThatWillNotExpireSaysSoBeforeItsDay(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.holds("helios-blog", snapshotOf("vps", "blog"), snapshotOf("other", "blog"))
	f.now = storageDay.Add(24 * time.Hour)
	if out, err := f.sweep(); err != nil || !strings.Contains(f.tombstone("blog").Problem, "were not made by this machine") {
		t.Fatal(err, out)
	}
	f.account.usageErr = map[string]error{"helios-blog": errors.New("storage answered HTTP 503")}
	f.now = f.now.Add(24 * time.Hour)
	if out, err := f.sweep(); err != nil || f.tombstone("blog").Problem == "" {
		t.Fatalf("an unread night cleared the hold: %v\n%s", err, out)
	}
	// The other machine's snapshot goes, and so does the hold.
	f.account.usageErr = nil
	f.holds("helios-blog", snapshotOf("vps", "blog"))
	f.now = f.now.Add(24 * time.Hour)
	if out, err := f.sweep(); err != nil || f.tombstone("blog").Problem != "" || len(f.account.deleted) != 0 {
		t.Fatalf("the hold outlived its cause, or the bucket went early: %v\n%s", err, out)
	}
	// A kept bucket is never examined: it is not going anywhere.
	f.holds("helios-blog", snapshotOf("other", "blog"))
	if out, err := f.run(StorageKeepKind, StorageAppInput{App: "blog"}); err != nil {
		t.Fatal(err, out)
	}
	if out, err := f.sweep(); err != nil || f.tombstone("blog").Problem != "" {
		t.Fatalf("a kept bucket raised a hold: %v\n%s", err, out)
	}
}

// A hold ends when its cause does, or when the operator keeps the bucket.
func TestAHeldBucketIsReleasedOrKept(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	f.account.deleteErr = map[string]error{"helios-blog": errors.New("storage answered HTTP 503")}
	f.now = storageDay.Add(BucketExpiry)
	if out, err := f.sweep(); err != nil || f.tombstone("blog").Problem == "" {
		t.Fatal(err, out)
	}
	f.account.deleteErr = nil
	f.now = f.now.Add(24 * time.Hour)
	if out, err := f.sweep(); err != nil || f.tombstone("blog") != nil {
		t.Fatalf("the next sweep did not carry on: %v\n%s", err, out)
	}

	f.removed("shop", storageDay)
	f.account.buckets["helios-shop"].lastWrite = f.now
	if out, err := f.sweep(); err != nil || f.tombstone("shop").Problem == "" {
		t.Fatal(err, out)
	}
	if out, err := f.run(StorageKeepKind, StorageAppInput{App: "shop"}); err != nil {
		t.Fatal(err, out)
	}
	if got := f.tombstone("shop"); got.Problem != "" || !got.Kept() {
		t.Fatalf("keeping did not settle the hold: %+v", got)
	}
}

// A listing or an account that cannot be read, or state that cannot, stops
// the pass before it decides anything.
func TestAFailedReadDeletesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(f *storageFixture)
	}{
		{"the bucket listing fails", func(f *storageFixture) { f.account.listErr = errors.New("storage answered HTTP 500") }},
		{"the account cannot be identified", func(f *storageFixture) { f.account.accountErr = errors.New("authorize with Backblaze: HTTP 401") }},
		{"the account has no identity", func(f *storageFixture) { f.account.id = "" }},
		{"the storage integration is gone", func(f *storageFixture) {
			if _, err := integration.Remove(f.secrets, integration.StorageName); err != nil {
				f.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStorageFixture(t)
			f.removed("blog", storageDay)
			f.now = storageDay.Add(BucketExpiry + time.Hour)
			tc.break_(f)
			if out, err := f.sweep(); err == nil {
				t.Fatalf("the sweep succeeded:\n%s", out)
			}
			if _, err := f.run(StoragePurgeKind, StorageAppInput{App: "blog"}); err == nil {
				t.Fatal("the purge succeeded")
			}
			var out strings.Builder
			if err := f.watch.expire(context.Background(), []string{"blog"}, &out); err == nil {
				t.Fatalf("the expiry step succeeded:\n%s", out.String())
			}
			if got := f.tombstone("blog"); len(f.account.deleted) != 0 || got == nil || got.Problem != "" {
				t.Fatalf("something changed: %v %+v", f.account.deleted, got)
			}
		})
	}

	t.Run("the state store cannot be read", func(t *testing.T) {
		f := newStorageFixture(t)
		f.removed("blog", storageDay)
		f.now = storageDay.Add(BucketExpiry + time.Hour)
		f.store.Close()
		if _, err := (StorageSweep{f.watch}).Plan(context.Background(), nil); err == nil {
			t.Fatal("planned a sweep without state")
		}
		if err := f.watch.expire(context.Background(), []string{"blog"}, io.Discard); err == nil {
			t.Fatal("expired without state")
		}
		if len(f.account.deleted) != 0 {
			t.Fatalf("deleted without state: %v", f.account.deleted)
		}
	})
}

func TestTheVerdictOnATombstone(t *testing.T) {
	removedAt := storageDay
	base := state.StorageTombstone{App: "blog", Bucket: "helios-blog", RemovedAt: removedAt, Account: "b2:acct"}
	facts := tombstoneFacts{bucket: "helios-blog", credentials: "key:aa", account: "b2:acct", listed: true, now: removedAt.Add(BucketExpiry)}
	change := func(edit func(*state.StorageTombstone, *tombstoneFacts)) (state.StorageTombstone, tombstoneFacts) {
		t, f := base, facts
		edit(&t, &f)
		return t, f
	}
	for _, tc := range []struct {
		name string
		edit func(*state.StorageTombstone, *tombstoneFacts)
		want int
	}{
		{"due and as the removal left it", func(*state.StorageTombstone, *tombstoneFacts) {}, bucketDelete},
		{"a second short of its 30 days", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.now = f.now.Add(-time.Second) }, bucketWait},
		{"kept", func(t *state.StorageTombstone, _ *tombstoneFacts) { t.KeptAt = removedAt.Add(time.Hour) }, bucketWait},
		{"kept, by hand", func(t *state.StorageTombstone, f *tombstoneFacts) {
			t.KeptAt, f.byHand = removedAt.Add(time.Hour), true
		}, bucketDelete},
		{"a day old, by hand", func(_ *state.StorageTombstone, f *tombstoneFacts) {
			f.now, f.byHand = removedAt.Add(24*time.Hour), true
		}, bucketDelete},
		{"the bucket is gone", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.listed = false }, bucketGone},
		{"the app moved away", func(t *state.StorageTombstone, _ *tombstoneFacts) { t.Moved = true }, bucketHold},
		{"the app moved away, by hand", func(t *state.StorageTombstone, f *tombstoneFacts) { t.Moved, f.byHand = true, true }, bucketHold},
		{"the app is here again", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.revisions = 1 }, bucketHold},
		{"the app is here again, by hand", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.revisions, f.byHand = 1, true }, bucketHold},
		{"the prefix changed", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.bucket = "other-blog" }, bucketHold},
		{"no bucket recorded", func(t *state.StorageTombstone, _ *tombstoneFacts) { t.Bucket = "" }, bucketHold},
		{"no account recorded", func(t *state.StorageTombstone, _ *tombstoneFacts) { t.Account = "" }, bucketHold},
		{"another account", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.account = "b2:other" }, bucketHold},
		{"another account, by hand", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.account, f.byHand = "b2:other", true }, bucketHold},
		{"the same credentials, not yet bound", func(t *state.StorageTombstone, _ *tombstoneFacts) { t.Account = "key:aa" }, bucketDelete},
		{"other credentials, not yet bound", func(t *state.StorageTombstone, _ *tombstoneFacts) { t.Account = "key:bb" }, bucketHold},
		{"another account whose bucket is gone", func(_ *state.StorageTombstone, f *tombstoneFacts) { f.account, f.listed = "b2:other", false }, bucketHold},
	} {
		tombstone, f := change(tc.edit)
		if got, why := tombstoneVerdict(tombstone, f); got != tc.want || (got == bucketHold) != (why != "") {
			t.Errorf("%s: verdict %d (%s), want %d", tc.name, got, why, tc.want)
		}
	}
}

// A tombstone whose bucket no longer exists is spent.
func TestATombstoneWhoseBucketIsGoneIsDropped(t *testing.T) {
	f := newStorageFixture(t)
	f.removed("blog", storageDay)
	delete(f.account.buckets, "helios-blog")
	f.now = storageDay.Add(time.Hour)
	out, err := f.sweep()
	if err != nil || f.tombstone("blog") != nil || len(f.account.deleted) != 0 {
		t.Fatalf("%v %v\n%s", err, f.account.deleted, out)
	}
}

// storageRepositories answers restic for the buckets named: so many
// snapshots, the newest of the given size, and so many bytes in use.
func storageRepositories(t *testing.T, used map[string]int64) (*dockertest.Server, *[][]string) {
	t.Helper()
	fake := dockertest.New(t)
	var commands [][]string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, append([]string{c.Labels["bedrock.app"]}, c.Cmd...))
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			repository := ""
			for _, env := range c.Env {
				if v, ok := strings.CutPrefix(env, "RESTIC_REPOSITORY="); ok {
					repository = v[strings.LastIndex(v, "/")+1:]
				}
			}
			bytes, known := used[repository]
			if !known {
				c.ExitCode, c.Logs = 1, `{"message_type":"exit_error","code":10,"message":"Fatal: repository does not exist"}`
				return
			}
			switch c.Cmd[0] {
			case "snapshots":
				if !slices.Contains(c.Cmd, "--no-lock") {
					c.ExitCode = 1
					return
				}
				c.Logs = `[{"id":"` + strings.Repeat("a", 64) + `","time":"2026-11-01T03:00:00Z"},{"id":"` + strings.Repeat("b", 64) + `","time":"2026-11-25T03:00:00Z","summary":{"total_bytes_processed":2000}},{"id":"` + strings.Repeat("c", 64) + `","time":"2026-11-10T03:00:00Z"}]`
			case "stats":
				if !slices.Contains(c.Cmd, "--no-lock") {
					c.ExitCode = 1
					return
				}
				c.Logs = fmt.Sprintf(`{"total_size":%d,"snapshots_count":3}`, bytes)
			}
		})
	}
	return fake, &commands
}

func TestTheSweepRecordsEveryBucketUnderThePrefix(t *testing.T) {
	f := newStorageFixture(t)
	ctx := context.Background()
	seedApp(t, f.store, "site")
	seedApp(t, f.store, "idle") // never backed up: no bucket
	f.removed("blog", storageDay.Add(-24*time.Hour))
	written := storageDay.Add(-2 * time.Hour)
	f.bucket("helios-site", 9000, written)
	f.bucket("helios-machine-vps", 700, written)
	f.bucket("helios-loom", 50000, written)
	f.bucket("helios-broken", 1, written)
	f.bucket("elsewhere-site", 1, written)
	f.account.usageErr = map[string]error{"helios-broken": errors.New("storage answered HTTP 500\nwith a second line")}
	fake, commands := storageRepositories(t, map[string]int64{"helios-site": 6000, "helios-blog": 100})
	// A sample older than the window goes when the next is recorded.
	if err := f.store.AddStorageSamples(ctx, []state.StorageSample{{Bucket: "helios-site", TakenAt: storageDay.Add(-StorageSampleWindow - time.Hour), Kind: state.StorageApp, StoredBytes: 1}}, time.Time{}); err != nil {
		t.Fatal(err)
	}

	out, err := f.run(StorageSweepKind, StorageSweepInput{})
	if err != nil {
		t.Fatal(err, out)
	}
	samples, err := f.store.StorageSamples(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]state.StorageSample{}
	for _, s := range samples {
		if !s.TakenAt.Equal(storageDay) {
			t.Fatalf("a sample outside the window stays: %+v", s)
		}
		got[s.Bucket] = s
	}
	if len(got) != 5 {
		t.Fatalf("sampled %v", sortedKeys(got))
	}
	site := got["helios-site"]
	if site.Kind != state.StorageApp || site.Owner != "site" || site.StoredBytes != 9000 || site.Files != 12 || site.UsedBytes != 6000 || site.Snapshots != 3 ||
		site.NewestSnapshotBytes != 2000 || !site.NewestSnapshotAt.Equal(time.Date(2026, 11, 25, 3, 0, 0, 0, time.UTC)) ||
		!site.OldestSnapshotAt.Equal(time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)) || !site.LastWriteAt.Equal(written) || site.Note != "" {
		t.Fatalf("the app's sample: %+v", site)
	}
	// What cannot be read is unknown, with the reason, and not a guess.
	machine := got["helios-machine-vps"]
	if machine.Kind != state.StorageMachine || machine.StoredBytes != 700 || machine.Snapshots != state.StorageUnknown || machine.UsedBytes != state.StorageUnknown || !strings.Contains(machine.Note, "snapshots not read: ") {
		t.Fatalf("the machine's sample: %+v", machine)
	}
	if removed := got["helios-blog"]; removed.Kind != state.StorageRemoved || removed.Owner != "blog" || removed.UsedBytes != 100 {
		t.Fatalf("the removed app's sample: %+v", removed)
	}
	if foreign := got["helios-loom"]; foreign.Kind != state.StorageForeign || foreign.Owner != "" || foreign.StoredBytes != 50000 || foreign.Snapshots != state.StorageUnknown || foreign.Note != "" {
		t.Fatalf("the foreign sample: %+v", foreign)
	}
	if broken := got["helios-broken"]; broken.StoredBytes != state.StorageUnknown || broken.Note != "size not read: storage answered HTTP 500" {
		t.Fatalf("the unreadable sample: %+v", broken)
	}
	// restic is never asked about a bucket that is not this machine's.
	for _, call := range fake.Calls() {
		if strings.Contains(call, "helios-loom") || strings.Contains(call, "helios-broken") {
			t.Fatalf("restic was run against a foreign bucket: %s", call)
		}
	}
	if len(*commands) != 5 {
		t.Fatalf("restic ran %v", *commands)
	}
	for _, c := range *commands {
		if !slices.Contains(c, "--no-lock") {
			t.Fatalf("the sweep ran a restic command that takes a lock: %v", c)
		}
		// Only a live app's helper carries that app's label.
		if c[0] != "site" && c[0] != "bedrock" {
			t.Fatalf("a restic helper is labeled for %q: %v", c[0], c)
		}
	}
}
