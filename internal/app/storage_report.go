package app

import (
	"fmt"
	"sort"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// The growth alert's thresholds. Backup storage is billed by the gigabyte
// each month and nothing caps it, so the alert exists to be told within a
// week that a bucket has started to cost more, not to be exact about how
// much.
const (
	// StorageGrowthWindow is the span growth is measured over. Retention
	// drops daily snapshots after a week by default, so a repository that
	// backs up the same amount of data every day is level from one week to
	// the next, and a week of real growth stands out against that.
	StorageGrowthWindow = 7 * 24 * time.Hour

	// StorageGrowthFactor is how much larger than a week ago a bucket may
	// be before it is called unusual: half as large again. An app whose
	// data grows steadily adds a few percent a week; half again in one week
	// doubles the bill in under a fortnight, which is retention that
	// stopped working or an app that started writing far more.
	StorageGrowthFactor = 1.5

	// StorageGrowthFloor is the least a bucket must have grown for the
	// factor to count. Half again of a 200 MB repository is one large
	// upload and costs nothing worth a message; a gigabyte in a week is
	// where growth starts to show on a bill if it goes on.
	StorageGrowthFloor = 1 << 30

	// StorageBloatFactor is how many times its newest snapshot a repository
	// may hold. The default retention keeps 17 snapshots (7 daily, 4
	// weekly, 6 monthly), so even an app whose every backup shares nothing
	// with the one before, such as a compressed database dump, stays under
	// 17 times its newest snapshot. More than 20 times is data that no
	// snapshot within the policy accounts for.
	StorageBloatFactor = 20

	// StorageDeadShare is how much of a bucket may be dead data: bytes no
	// snapshot references. The capped prune after each backup tolerates a
	// few percent and the weekly full prune removes the rest, so a
	// repository that is more than half dead is one prune has not kept up
	// with for weeks.
	StorageDeadShare = 0.5

	// StorageWasteFloor is the least a bucket must hold for the last two to
	// count. Below a few gigabytes a small app with a long history trips
	// any ratio and wastes almost nothing.
	StorageWasteFloor = 5 << 30

	// StorageNewRepository is how long a repository is left alone. Its
	// first week is all growth: the first backups, and often the import of
	// the app's real data after a deploy with an empty database.
	StorageNewRepository = 7 * 24 * time.Hour

	// StorageSampleStale is how old the newest sample may be and still be
	// judged. Two nights without a sample is a sweep that is not running,
	// which is its own condition; an old sample says nothing about now.
	StorageSampleStale = 48 * time.Hour

	// storageBaselineSlack lets a sample taken a little under seven days
	// ago serve as the week-old one: the sweep starts at the same hour each
	// night but not at the same minute.
	storageBaselineSlack = 2 * time.Hour
)

// storageBaseline picks the sample a bucket's newest one is compared with:
// the newest one that is at least a week older and knows its size. history
// is one bucket's samples, oldest first.
func storageBaseline(history []state.StorageSample) (state.StorageSample, bool) {
	if len(history) < 2 {
		return state.StorageSample{}, false
	}
	latest := history[len(history)-1]
	cutoff := latest.TakenAt.Add(-StorageGrowthWindow + storageBaselineSlack)
	for i := len(history) - 2; i >= 0; i-- {
		if s := history[i]; !s.TakenAt.After(cutoff) && s.StoredBytes >= 0 {
			return s, true
		}
	}
	return state.StorageSample{}, false
}

// storageEstablished reports whether a repository was past its first week
// when a sample was taken: its oldest snapshot was a week old by then, or
// this machine had been sampling it for a week. Retention can leave a
// repository whose oldest snapshot is always about a week old, which is why
// the samples count too. With neither, it is treated as new.
func storageEstablished(history []state.StorageSample, at state.StorageSample) bool {
	if !at.OldestSnapshotAt.IsZero() && at.TakenAt.Sub(at.OldestSnapshotAt) >= StorageNewRepository {
		return true
	}
	return len(history) > 0 && at.TakenAt.Sub(history[0].TakenAt) >= StorageNewRepository
}

// StorageFindings says what is unusual about one bucket, from its samples
// oldest first. It is silent about a bucket this machine does not own, one
// it has no fresh sample of, and a repository in its first week.
func StorageFindings(history []state.StorageSample, now time.Time) []string {
	if len(history) == 0 {
		return nil
	}
	latest := history[len(history)-1]
	if latest.Kind == state.StorageForeign || latest.StoredBytes < 0 || now.Sub(latest.TakenAt) > StorageSampleStale {
		return nil
	}
	var out []string
	// Growth compares two samples, and the older one must already describe
	// a settled repository: a first week measured against its own start is
	// growth by definition.
	if base, ok := storageBaseline(history); ok && storageEstablished(history, base) {
		grew := latest.StoredBytes - base.StoredBytes
		if grew > StorageGrowthFloor && float64(latest.StoredBytes) > StorageGrowthFactor*float64(base.StoredBytes) {
			out = append(out, fmt.Sprintf("grew by %s in %s, from %s to %s", HumanBytes(grew), days(latest.TakenAt.Sub(base.TakenAt)), HumanBytes(base.StoredBytes), HumanBytes(latest.StoredBytes)))
		}
	}
	if latest.StoredBytes <= StorageWasteFloor || !storageEstablished(history, latest) {
		return out
	}
	if latest.NewestSnapshotBytes > 0 && float64(latest.StoredBytes) > StorageBloatFactor*float64(latest.NewestSnapshotBytes) {
		out = append(out, fmt.Sprintf("holds %s, %.0f times its newest snapshot of %s", HumanBytes(latest.StoredBytes), float64(latest.StoredBytes)/float64(latest.NewestSnapshotBytes), HumanBytes(latest.NewestSnapshotBytes)))
	}
	if dead := deadBytes(latest); dead >= 0 && float64(dead) > StorageDeadShare*float64(latest.StoredBytes) {
		out = append(out, fmt.Sprintf("%s of its %s is data no snapshot uses", HumanBytes(dead), HumanBytes(latest.StoredBytes)))
	}
	return out
}

func days(d time.Duration) string {
	n := int((d + 12*time.Hour) / (24 * time.Hour))
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// deadBytes is what a bucket stores beyond what its snapshots reference, or
// unknown when either figure is.
func deadBytes(s state.StorageSample) int64 {
	if s.StoredBytes < 0 || s.UsedBytes < 0 || s.UsedBytes > s.StoredBytes {
		return state.StorageUnknown
	}
	return s.StoredBytes - s.UsedBytes
}

// StorageRow is one bucket in the storage report. A figure of -1 is one
// the last sweep could not read.
type StorageRow struct {
	Bucket string `json:"bucket"`
	// Owner is the app, or this machine's backup target; empty for a
	// bucket this machine does not own.
	Owner string `json:"owner,omitempty"`
	// Kind is app, machine, removed or foreign.
	Kind             string    `json:"kind"`
	SampledAt        time.Time `json:"sampled_at,omitzero"`
	StoredBytes      int64     `json:"stored_bytes"`
	Snapshots        int64     `json:"snapshots"`
	NewestSnapshotAt time.Time `json:"newest_snapshot_at,omitzero"`
	// GrowthBytes is how much the bucket grew since GrowthSince, the sample
	// of a week ago or, in a bucket's first week of samples, its first.
	// GrowthSince is zero when there is nothing to compare with.
	GrowthBytes int64     `json:"growth_bytes"`
	GrowthSince time.Time `json:"growth_since,omitzero"`
	// DeadBytes is what the bucket stores beyond what its snapshots use.
	DeadBytes   int64     `json:"dead_bytes"`
	LastWriteAt time.Time `json:"last_write_at,omitzero"`
	// RemovedAt and ExpiresAt are set for a removed app's bucket; ExpiresAt
	// is zero when the expiry was cancelled.
	RemovedAt time.Time `json:"removed_at,omitzero"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Kept      bool      `json:"kept,omitempty"`
	// Moved marks the bucket of an app that left this machine by a move.
	Moved bool `json:"moved,omitempty"`
	// Held is why the sweep refuses to delete the bucket.
	Held string `json:"held,omitempty"`
	// Unusual is what the growth alert says about the bucket.
	Unusual []string `json:"unusual,omitempty"`
	// Note is what the last sweep could not read.
	Note string `json:"note,omitempty"`
}

// StorageReport is what helios storage prints.
type StorageReport struct {
	// SampledAt is when the last sweep read the buckets; zero before the
	// first.
	SampledAt time.Time `json:"sampled_at,omitzero"`
	// Buckets are the ones this machine owns.
	Buckets []StorageRow `json:"buckets"`
	// Unowned carry this machine's prefix and belong to another machine or
	// to nobody. They are reported and never touched.
	Unowned []StorageRow `json:"unowned"`
}

// BuildStorageReport turns the recorded samples and tombstones into the
// report. It reads nothing else, so it shows the account as of the last
// sweep.
func BuildStorageReport(samples []state.StorageSample, tombstones []state.StorageTombstone, now time.Time) StorageReport {
	report := StorageReport{Buckets: []StorageRow{}, Unowned: []StorageRow{}}
	histories := map[string][]state.StorageSample{}
	for _, s := range samples {
		histories[s.Bucket] = append(histories[s.Bucket], s)
		if s.TakenAt.After(report.SampledAt) {
			report.SampledAt = s.TakenAt
		}
	}
	byBucket := map[string]state.StorageTombstone{}
	for _, t := range tombstones {
		byBucket[t.Bucket] = t
	}
	rows := map[string]StorageRow{}
	for bucket, history := range histories {
		sort.Slice(history, func(i, j int) bool { return history[i].TakenAt.Before(history[j].TakenAt) })
		latest := history[len(history)-1]
		// A bucket the last sweep did not find is gone, or no longer under
		// this prefix. Its old samples say nothing about the account now.
		if !latest.TakenAt.Equal(report.SampledAt) {
			continue
		}
		row := StorageRow{Bucket: bucket, Owner: latest.Owner, Kind: latest.Kind, SampledAt: latest.TakenAt,
			StoredBytes: latest.StoredBytes, Snapshots: latest.Snapshots, NewestSnapshotAt: latest.NewestSnapshotAt,
			DeadBytes: deadBytes(latest), LastWriteAt: latest.LastWriteAt, Note: latest.Note}
		if latest.StoredBytes >= 0 {
			base, ok := storageBaseline(history)
			if !ok {
				// Not a week of samples yet: say how far it has come.
				for _, s := range history[:len(history)-1] {
					if s.StoredBytes >= 0 {
						base, ok = s, true
						break
					}
				}
			}
			if ok {
				row.GrowthBytes, row.GrowthSince = latest.StoredBytes-base.StoredBytes, base.TakenAt
			}
		}
		row.Unusual = StorageFindings(history, now)
		rows[bucket] = row
	}
	// The tombstones decide what a removed app's bucket is, whatever the
	// last sweep took it for: an app removed since then was still an app.
	for bucket, t := range byBucket {
		row, sampled := rows[bucket]
		if !sampled {
			row = StorageRow{Bucket: bucket, StoredBytes: state.StorageUnknown, Snapshots: state.StorageUnknown, DeadBytes: state.StorageUnknown,
				Note: "not sampled since the app was removed"}
		}
		row.Owner, row.RemovedAt, row.Kept, row.Moved, row.Held = t.App, t.RemovedAt, t.Kept(), t.Moved, t.Problem
		switch {
		case t.Moved:
			row.Kind = state.StorageForeign
		default:
			row.Kind = state.StorageRemoved
			if !t.Kept() {
				row.ExpiresAt = t.RemovedAt.Add(BucketExpiry)
			}
		}
		rows[bucket] = row
	}
	for _, row := range rows {
		if row.Kind == state.StorageForeign {
			report.Unowned = append(report.Unowned, row)
		} else {
			report.Buckets = append(report.Buckets, row)
		}
	}
	order := map[string]int{state.StorageApp: 0, state.StorageMachine: 1, state.StorageRemoved: 2}
	sort.Slice(report.Buckets, func(i, j int) bool {
		a, b := report.Buckets[i], report.Buckets[j]
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		return a.Bucket < b.Bucket
	})
	sort.Slice(report.Unowned, func(i, j int) bool { return report.Unowned[i].Bucket < report.Unowned[j].Bucket })
	return report
}
