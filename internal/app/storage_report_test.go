package app

import (
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

const gib = int64(1) << 30

// nightly builds one bucket's samples, one a night from the first night,
// each as large as size says for that night.
func nightly(first time.Time, nights int, size func(night int) int64) []state.StorageSample {
	var out []state.StorageSample
	for n := 0; n < nights; n++ {
		at := first.Add(time.Duration(n)*24*time.Hour + time.Duration(n%7)*time.Minute)
		out = append(out, state.StorageSample{Bucket: "helios-site", Owner: "site", Kind: state.StorageApp, TakenAt: at,
			StoredBytes: size(n), UsedBytes: state.StorageUnknown, Snapshots: 7, NewestSnapshotBytes: state.StorageUnknown})
	}
	return out
}

// findingsEachNight is what the growth rule says on every night of a
// history, as a watch round the morning after would see it.
func findingsEachNight(history []state.StorageSample) [][]string {
	out := make([][]string, len(history))
	for n := range history {
		out[n] = StorageFindings(history[:n+1], history[n].TakenAt.Add(4*time.Hour))
	}
	return out
}

func TestUnusualGrowthFiresAndClears(t *testing.T) {
	// Level at 10 GB for three weeks, then 1 GB more each night for six
	// nights, then level again.
	history := nightly(storageDay, 40, func(n int) int64 {
		switch {
		case n < 21:
			return 10 * gib
		case n < 27:
			return (10 + int64(n-20)) * gib
		}
		return 16 * gib
	})
	said := findingsEachNight(history)
	for n, findings := range said {
		// Half as large again as a week before: from the night it reaches
		// 16 GB against 10, until the week-old sample has caught up.
		want := n >= 26 && n <= 27
		if (len(findings) > 0) != want {
			t.Fatalf("night %d (%s): %v", n, HumanBytes(history[n].StoredBytes), findings)
		}
	}
	if got := said[26][0]; got != "grew by 6.0 GB in 7 days, from 10.0 GB to 16.0 GB" {
		t.Fatalf("message: %s", got)
	}
}

func TestOrdinaryGrowthIsNotUnusual(t *testing.T) {
	for name, size := range map[string]func(int) int64{
		"a third more in a week":              func(n int) int64 { return 30*gib + int64(n)*gib*10/7 },
		"a small bucket that triples":         func(n int) int64 { return 100<<20 + int64(n)*(40<<20) },
		"a bucket that shrinks":               func(n int) int64 { return 50*gib - int64(n)*gib },
		"exactly half as large again":         func(n int) int64 { return []int64{10 * gib, 15 * gib}[n/14] },
		"exactly the floor, from very little": func(n int) int64 { return []int64{gib / 2, gib/2 + gib}[n/14] },
	} {
		for n, findings := range findingsEachNight(nightly(storageDay, 28, size)) {
			if len(findings) > 0 {
				t.Errorf("%s, night %d: %v", name, n, findings)
			}
		}
	}
}

// A new repository's first week is all growth, and says nothing.
func TestANewRepositoryIsQuietInItsFirstWeek(t *testing.T) {
	// 100 MB on the first night, 12 GB by the end of the week, then level.
	grows := func(n int) int64 {
		if n >= 6 {
			return 12 * gib
		}
		return 100<<20 + int64(n)*2*gib
	}
	history := nightly(storageDay, 30, grows)
	for n := range history {
		// Its oldest snapshot is as old as the repository.
		history[n].OldestSnapshotAt = storageDay.Add(-time.Hour)
	}
	for n, findings := range findingsEachNight(history) {
		if len(findings) > 0 {
			t.Fatalf("night %d of a new repository: %v", n, findings)
		}
	}
	// The same numbers in a repository that was a year old when sampling
	// began are not a first week: the week-old sample is a fair baseline.
	old := nightly(storageDay, 30, grows)
	for n := range old {
		old[n].OldestSnapshotAt = storageDay.Add(-365 * 24 * time.Hour)
	}
	if said := findingsEachNight(old); len(said[6]) != 0 || len(said[7]) != 1 {
		t.Fatalf("an old repository that grew 120 times in a week: night 6 %v, night 7 %v", said[6], said[7])
	}
	// Retention can keep a repository's oldest snapshot under a week old
	// for ever. A week of samples then stands in for its age.
	short := nightly(storageDay, 30, func(n int) int64 {
		if n >= 20 {
			return 30 * gib
		}
		return 10 * gib
	})
	for n := range short {
		short[n].OldestSnapshotAt = short[n].TakenAt.Add(-6 * 24 * time.Hour)
	}
	if said := findingsEachNight(short); len(said[20]) != 1 {
		t.Fatalf("a repository with a short history never alerts: %v", said[20])
	}
}

func TestGrowthIsNotJudgedFromWhatWasNotRead(t *testing.T) {
	grew := func(n int) int64 {
		if n >= 20 {
			return 30 * gib
		}
		return 10 * gib
	}
	history := nightly(storageDay, 21, grew)
	now := history[20].TakenAt.Add(4 * time.Hour)
	if len(StorageFindings(history, now)) != 1 {
		t.Fatal("the scenario is wrong: this growth is unusual")
	}
	// A sample two days old says nothing about today.
	if got := StorageFindings(history, history[20].TakenAt.Add(StorageSampleStale+time.Minute)); len(got) != 0 {
		t.Fatalf("judged a stale sample: %v", got)
	}
	// Nor does one whose size could not be read.
	unread := nightly(storageDay, 21, grew)
	unread[20].StoredBytes = state.StorageUnknown
	if got := StorageFindings(unread, now); len(got) != 0 {
		t.Fatalf("judged an unread sample: %v", got)
	}
	// An unread sample a week ago is passed over for the one before it.
	gap := nightly(storageDay, 21, grew)
	gap[13].StoredBytes = state.StorageUnknown
	if got := StorageFindings(gap, now); len(got) != 1 || !strings.Contains(got[0], "in 8 days") {
		t.Fatalf("with a gap a week ago: %v", got)
	}
	// Another machine's bucket is reported, never judged.
	foreign := nightly(storageDay, 21, grew)
	for n := range foreign {
		foreign[n].Kind = state.StorageForeign
	}
	if got := StorageFindings(foreign, now); len(got) != 0 {
		t.Fatalf("judged a bucket this machine does not own: %v", got)
	}
	if got := StorageFindings(nil, now); got != nil {
		t.Fatalf("no samples: %v", got)
	}
}

func TestARepositoryFarLargerThanItsDataIsUnusual(t *testing.T) {
	level := func(size int64) []state.StorageSample {
		return nightly(storageDay, 15, func(int) int64 { return size })
	}
	last := func(history []state.StorageSample, edit func(*state.StorageSample)) []string {
		edit(&history[len(history)-1])
		return StorageFindings(history, history[len(history)-1].TakenAt.Add(time.Hour))
	}
	if got := last(level(100*gib), func(s *state.StorageSample) { s.NewestSnapshotBytes = 2 * gib }); len(got) != 1 || got[0] != "holds 100.0 GB, 50 times its newest snapshot of 2.0 GB" {
		t.Fatalf("50 times its newest snapshot: %v", got)
	}
	// Seventeen snapshots that share nothing is the default retention's
	// honest worst case.
	if got := last(level(34*gib), func(s *state.StorageSample) { s.NewestSnapshotBytes = 2 * gib }); len(got) != 0 {
		t.Fatalf("17 times its newest snapshot: %v", got)
	}
	if got := last(level(4*gib), func(s *state.StorageSample) { s.NewestSnapshotBytes = 10 << 20 }); len(got) != 0 {
		t.Fatalf("a small repository with a long history: %v", got)
	}
	if got := last(level(20*gib), func(s *state.StorageSample) { s.UsedBytes = 6 * gib }); len(got) != 1 || got[0] != "14.0 GB of its 20.0 GB is data no snapshot uses" {
		t.Fatalf("mostly dead data: %v", got)
	}
	if got := last(level(20*gib), func(s *state.StorageSample) { s.UsedBytes = 12 * gib }); len(got) != 0 {
		t.Fatalf("40%% dead data: %v", got)
	}
	// More in use than stored is a reading that cannot be right; it is not
	// turned into a figure.
	if got := last(level(20*gib), func(s *state.StorageSample) { s.UsedBytes = 21 * gib }); len(got) != 0 {
		t.Fatalf("an impossible reading: %v", got)
	}
	// In its first week nothing is unusual.
	young := nightly(storageDay, 5, func(int) int64 { return 100 * gib })
	if got := last(young, func(s *state.StorageSample) { s.NewestSnapshotBytes, s.UsedBytes = 2*gib, gib }); len(got) != 0 {
		t.Fatalf("a first week: %v", got)
	}
}

func TestTheReportShowsOwnedAndUnownedBucketsAsOfTheLastSweep(t *testing.T) {
	weekAgo, last := storageDay.Add(-7*24*time.Hour), storageDay
	now := storageDay.Add(3 * time.Hour)
	sample := func(bucket, owner, kind string, at time.Time, stored int64) state.StorageSample {
		return state.StorageSample{Bucket: bucket, Owner: owner, Kind: kind, TakenAt: at, StoredBytes: stored,
			UsedBytes: state.StorageUnknown, Snapshots: state.StorageUnknown, NewestSnapshotBytes: state.StorageUnknown}
	}
	site := sample("helios-site", "site", state.StorageApp, last, 12*gib)
	site.UsedBytes, site.Snapshots, site.NewestSnapshotAt = 9*gib, 17, last.Add(-2*time.Hour)
	samples := []state.StorageSample{
		sample("helios-site", "site", state.StorageApp, weekAgo, 10*gib), site,
		sample("helios-machine-vps", "machine-vps", state.StorageMachine, last, gib),
		// Sampled as an app last night, removed since.
		sample("helios-blog", "blog", state.StorageApp, last, 3*gib),
		sample("helios-kept", "kept", state.StorageRemoved, last, 2*gib),
		sample("helios-held", "held", state.StorageRemoved, last, 2*gib),
		sample("helios-loom", "", state.StorageForeign, last, 40*gib),
		sample("helios-moved", "", state.StorageForeign, last, 5*gib),
		// Gone from the account since the sweep before last.
		sample("helios-vanished", "", state.StorageForeign, weekAgo, 7*gib),
	}
	removed := storageDay.Add(-10 * 24 * time.Hour)
	tombstones := []state.StorageTombstone{
		{App: "blog", Bucket: "helios-blog", RemovedAt: now.Add(-time.Hour)},
		{App: "kept", Bucket: "helios-kept", RemovedAt: removed, KeptAt: removed.Add(time.Hour)},
		{App: "held", Bucket: "helios-held", RemovedAt: removed, Problem: "something was uploaded to it"},
		{App: "moved", Bucket: "helios-moved", RemovedAt: removed, KeptAt: removed, Moved: true},
		{App: "fresh", Bucket: "helios-fresh", RemovedAt: now.Add(-time.Minute)},
	}
	report := BuildStorageReport(samples, tombstones, now)
	if !report.SampledAt.Equal(last) {
		t.Fatalf("sampled at %s", report.SampledAt)
	}
	var owned, unowned []string
	rows := map[string]StorageRow{}
	for _, r := range report.Buckets {
		owned = append(owned, r.Bucket+"="+r.Kind)
		rows[r.Bucket] = r
	}
	for _, r := range report.Unowned {
		unowned = append(unowned, r.Bucket)
		rows[r.Bucket] = r
	}
	if got, want := strings.Join(owned, " "), "helios-site=app helios-machine-vps=machine helios-blog=removed helios-fresh=removed helios-held=removed helios-kept=removed"; got != want {
		t.Fatalf("owned: %s", got)
	}
	if got := strings.Join(unowned, " "); got != "helios-loom helios-moved" {
		t.Fatalf("unowned: %s", got)
	}
	if r := rows["helios-site"]; r.StoredBytes != 12*gib || r.GrowthBytes != 2*gib || !r.GrowthSince.Equal(weekAgo) || r.DeadBytes != 3*gib || r.Snapshots != 17 || !r.NewestSnapshotAt.Equal(last.Add(-2*time.Hour)) {
		t.Fatalf("the app's row: %+v", r)
	}
	if r := rows["helios-machine-vps"]; !r.GrowthSince.IsZero() || r.DeadBytes != state.StorageUnknown {
		t.Fatalf("a bucket with one sample: %+v", r)
	}
	if r := rows["helios-blog"]; r.Owner != "blog" || r.StoredBytes != 3*gib || !r.ExpiresAt.Equal(now.Add(-time.Hour).Add(BucketExpiry)) || r.Kept {
		t.Fatalf("the removed app's row: %+v", r)
	}
	if r := rows["helios-kept"]; !r.Kept || !r.ExpiresAt.IsZero() {
		t.Fatalf("the kept row: %+v", r)
	}
	if r := rows["helios-held"]; r.Held != "something was uploaded to it" || r.ExpiresAt.IsZero() {
		t.Fatalf("the held row: %+v", r)
	}
	if r := rows["helios-fresh"]; r.StoredBytes != state.StorageUnknown || r.Note == "" || r.ExpiresAt.IsZero() {
		t.Fatalf("a bucket removed since the last sweep: %+v", r)
	}
	if r := rows["helios-moved"]; !r.Moved || r.Owner != "moved" || !r.ExpiresAt.IsZero() {
		t.Fatalf("the moved row: %+v", r)
	}
	if empty := BuildStorageReport(nil, nil, now); !empty.SampledAt.IsZero() || empty.Buckets == nil || empty.Unowned == nil {
		t.Fatalf("before the first sweep: %+v", empty)
	}
}
