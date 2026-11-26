package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

const storageTestGiB = int64(1) << 30

// seedStorage records what two weeks of nightly sweeps would have: an app's
// bucket that grew, the machine's own, a removed app's, and one under the
// prefix that belongs to another machine.
func seedStorage(t *testing.T, dir string) (last, removed time.Time) {
	t.Helper()
	ctx := context.Background()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	last = time.Now().UTC().Truncate(time.Minute).Add(-3 * time.Hour)
	removed = last.Add(-10 * 24 * time.Hour)
	for night := 14; night >= 0; night-- {
		at := last.Add(-time.Duration(night) * 24 * time.Hour)
		site := 10 * storageTestGiB
		if night == 0 {
			site = 16 * storageTestGiB
		}
		samples := []state.StorageSample{
			{Bucket: "helios-site", Owner: "site", Kind: state.StorageApp, TakenAt: at, StoredBytes: site, UsedBytes: 9 * storageTestGiB, Snapshots: 53,
				NewestSnapshotAt: at.Add(-2 * time.Hour), NewestSnapshotBytes: 8 * storageTestGiB},
			{Bucket: "helios-vps-machine", Owner: "vps-machine", Kind: state.StorageMachine, TakenAt: at, StoredBytes: 200 << 20, UsedBytes: 190 << 20, Snapshots: 14,
				NewestSnapshotAt: at.Add(-90 * time.Minute), NewestSnapshotBytes: 100 << 20},
			{Bucket: "helios-blog", Owner: "blog", Kind: state.StorageApp, TakenAt: at, StoredBytes: 3 * storageTestGiB, UsedBytes: state.StorageUnknown, Snapshots: state.StorageUnknown,
				NewestSnapshotBytes: state.StorageUnknown, Note: "its repository could not be read: wrong password"},
			{Bucket: "helios-other", Kind: state.StorageForeign, TakenAt: at, StoredBytes: 5 * storageTestGiB, UsedBytes: state.StorageUnknown, Snapshots: state.StorageUnknown,
				NewestSnapshotBytes: state.StorageUnknown, LastWriteAt: at.Add(-time.Hour)},
		}
		if err := store.AddStorageSamples(ctx, samples, at.Add(-apps.StorageSampleWindow)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RemoveAppLeavingTombstone(ctx, "blog", "helios-blog", "key:abcd", removed); err != nil {
		t.Fatal(err)
	}
	return last, removed
}

// setTestStorage sets a storage integration that reaches nothing.
func setTestStorage(t *testing.T, dir string) {
	t.Helper()
	sec := secrets.DefaultStore(dir)
	if _, _, _, err := sec.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "https://storage.example.test", "key_id": "key-id", "key": "storage-value", "bucket_prefix": "helios", "password": "backup-password"}); err != nil {
		t.Fatal(err)
	}
}

func TestStorageBeforeTheFirstSweepSaysSo(t *testing.T) {
	dir := t.TempDir()
	out, errOut, code := run(t, dir, "storage")
	if code != 0 || !strings.Contains(out, "no bucket has been measured yet") || !strings.Contains(out, "helios storage sweep") {
		t.Fatalf("exit %d, out %q, stderr %q", code, out, errOut)
	}
	out, _, code = run(t, dir, "--json", "storage")
	var report apps.StorageReport
	if err := json.Unmarshal([]byte(out), &report); code != 0 || err != nil || report.Buckets == nil || report.Unowned == nil || len(report.Buckets)+len(report.Unowned) != 0 {
		t.Fatalf("json: exit %d, %v, %q", code, err, out)
	}
}

func TestStorageReportsEveryOwnedBucketAndListsTheRest(t *testing.T) {
	dir := t.TempDir()
	last, removed := seedStorage(t, dir)
	out, errOut, code := run(t, dir, "storage")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	date := func(at time.Time) string { return at.Local().Format("2006-01-02") }
	owned, unowned, found := strings.Cut(out, "Under this machine's prefix, not owned by it (reported only, never deleted):")
	if !found {
		t.Fatalf("no section for buckets this machine does not own:\n%s", out)
	}
	lines := map[string][]string{}
	for _, line := range strings.Split(owned, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			lines[fields[0]] = fields
		}
	}
	for bucket, want := range map[string]string{
		"BUCKET":             "BUCKET OF SIZE SNAPSHOTS NEWEST 7D GROWTH DEAD STATE",
		"helios-site":        "helios-site site 16.0 GB 53 " + date(last.Add(-2*time.Hour)) + " +6.0 GB 7.0 GB -",
		"helios-vps-machine": "helios-vps-machine this machine 200.0 MB 14 " + date(last.Add(-90*time.Minute)) + " 0 B 10.0 MB -",
		"helios-blog":        "helios-blog blog 3.0 GB ? - 0 B ? removed " + date(removed) + ", deleted after " + date(removed.Add(apps.BucketExpiry)),
	} {
		if got := strings.Join(lines[bucket], " "); got != want {
			t.Errorf("row of %s:\n got %s\nwant %s\n%s", bucket, got, want, out)
		}
	}
	if strings.Contains(owned, "helios-other") {
		t.Errorf("a bucket of another machine is listed as owned:\n%s", out)
	}
	if !strings.Contains(unowned, "helios-other") || !strings.Contains(unowned, "5.0 GB") {
		t.Errorf("the bucket this machine does not own is missing:\n%s", out)
	}
	for _, want := range []string{
		"Measured ",
		"helios-site: grew by 6.0 GB in 7 days, from 10.0 GB to 16.0 GB",
		"helios-blog: its repository could not be read: wrong password",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report doesn't say %q:\n%s", want, out)
		}
	}

	out, _, code = run(t, dir, "--json", "storage")
	var report apps.StorageReport
	if err := json.Unmarshal([]byte(out), &report); code != 0 || err != nil {
		t.Fatalf("json: exit %d, %v, %q", code, err, out)
	}
	if len(report.Buckets) != 3 || len(report.Unowned) != 1 || report.Unowned[0].Bucket != "helios-other" {
		t.Fatalf("json report: %+v", report)
	}
	blog := report.Buckets[2]
	if blog.Bucket != "helios-blog" || blog.Kind != state.StorageRemoved || !blog.ExpiresAt.Equal(removed.Add(apps.BucketExpiry)) || blog.Kept {
		t.Fatalf("removed app's row: %+v", blog)
	}
	if site := report.Buckets[0]; site.GrowthBytes != 6*storageTestGiB || site.DeadBytes != 7*storageTestGiB || len(site.Unusual) != 1 {
		t.Fatalf("site's row: %+v", site)
	}
}

func TestStorageKeepCancelsAnExpiryAndOnlyTakesARemovedApp(t *testing.T) {
	dir := t.TempDir()
	_, removed := seedStorage(t, dir)
	// site runs here and other was never this machine's: neither has a
	// tombstone, so neither can be kept or purged.
	for _, args := range [][]string{
		{"storage", "keep", "site", "--yes"},
		{"storage", "purge", "site", "--yes"},
		{"storage", "purge", "other", "--yes"},
		{"storage", "purge", "helios-other", "--plan"},
	} {
		_, errOut, code := run(t, dir, args...)
		if code == 0 || !strings.Contains(errOut, "only takes an app that helios remove took off this machine") {
			t.Fatalf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}

	out, errOut, code := run(t, dir, "storage", "keep", "blog", "--plan")
	if code != 0 || !strings.Contains(out, "cancel the expiry of bucket helios-blog") || !strings.Contains(out, "plan digest ") {
		t.Fatalf("plan: exit %d, out %q, stderr %q", code, out, errOut)
	}
	if out, _, _ := run(t, dir, "storage"); !strings.Contains(out, "deleted after") {
		t.Fatalf("--plan kept the bucket:\n%s", out)
	}
	if _, errOut, code := run(t, dir, "storage", "keep", "blog", "--yes"); code != 0 {
		t.Fatalf("keep: exit %d, stderr %q", code, errOut)
	}
	out, _, _ = run(t, dir, "storage")
	if want := "removed " + removed.Local().Format("2006-01-02") + ", kept"; !strings.Contains(out, want) || strings.Contains(out, "deleted after") {
		t.Fatalf("the report doesn't say %q:\n%s", want, out)
	}
	if _, errOut, code := run(t, dir, "storage", "keep", "blog", "--yes"); code == 0 || !strings.Contains(errOut, "is kept already") {
		t.Fatalf("keeping twice: exit %d, stderr %q", code, errOut)
	}
}

// A purge is planned without reaching storage, and deletes nothing until
// its plan is confirmed.
func TestStoragePurgeShowsItsPlanFirst(t *testing.T) {
	dir := t.TempDir()
	_, removed := seedStorage(t, dir)
	if _, errOut, code := run(t, dir, "storage", "purge", "blog", "--plan"); code == 0 || !strings.Contains(errOut, "storage") {
		t.Fatalf("purge without the storage integration: exit %d, stderr %q", code, errOut)
	}
	setTestStorage(t, dir)
	out, errOut, code := run(t, dir, "storage", "purge", "blog", "--plan")
	want := "delete bucket helios-blog and every backup in it, the backups of blog removed on " + removed.Format("2006-01-02") + " (no way back)"
	if code != 0 || !strings.Contains(out, want) || !strings.Contains(out, "plan digest ") {
		t.Fatalf("plan: exit %d, out %q, stderr %q", code, out, errOut)
	}
	if out, _, _ := run(t, dir, "storage"); !strings.Contains(out, "helios-blog") {
		t.Fatalf("--plan dropped the bucket:\n%s", out)
	}
	// Without a terminal and without --yes or --digest nothing is applied.
	if _, _, code := run(t, dir, "storage", "purge", "blog"); code == 0 {
		t.Fatal("a purge nobody confirmed was applied")
	}
	if out, _, _ := run(t, dir, "storage"); !strings.Contains(out, "helios-blog") {
		t.Fatalf("an unconfirmed purge dropped the bucket:\n%s", out)
	}
}
