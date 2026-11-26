package watch

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/state"
)

// FullPruneUnfinished is how many weekly full prunes in a row may start
// without finishing before it is a problem. One that runs out of its hour
// is ordinary: a first full prune of a neglected repository has weeks of
// dead data to rewrite. Three in a row is three weeks in which the prune
// made no headway, and by then it is not going to on its own.
const FullPruneUnfinished = 3

// The storage watch's conditions. A bucket's condition carries its name,
// so each bucket opens and clears on its own.
const (
	storageBucketKey = "storage:"
	storageExpiryKey = "host:storage-expiry"
	storageSweepKey  = "host:storage-sweep"
)

// storage reports what the nightly storage sweep found: a bucket that grew
// unusually or holds far more than its snapshots account for, a full prune
// that never finishes, a removed app's bucket the sweep refuses to delete,
// and a sweep that failed or stopped running.
//
// It reads only what the sweep recorded. When that cannot be read, the
// incidents already open are held as unknown: no reading is not a recovery.
func (p *Prober) storage(ctx context.Context) []Condition {
	now := p.Now()
	samples, err := p.Store.StorageSamples(ctx, now.Add(-app.StorageSampleWindow))
	if err != nil {
		return p.unobservedStorage(ctx)
	}
	tombstones, err := p.Store.StorageTombstones(ctx)
	if err != nil {
		return p.unobservedStorage(ctx)
	}
	prunes, err := p.Store.StoragePrunes(ctx)
	if err != nil {
		return p.unobservedStorage(ctx)
	}

	problems := map[string][]string{}
	var order []string
	add := func(bucket string, found ...string) {
		if len(found) == 0 {
			return
		}
		if _, seen := problems[bucket]; !seen {
			order = append(order, bucket)
		}
		problems[bucket] = append(problems[bucket], found...)
	}
	var newest time.Time
	// The samples come by bucket, oldest first.
	for start := 0; start < len(samples); {
		end := start
		for end < len(samples) && samples[end].Bucket == samples[start].Bucket {
			end++
		}
		history := samples[start:end]
		if last := history[len(history)-1].TakenAt; last.After(newest) {
			newest = last
		}
		add(history[0].Bucket, app.StorageFindings(history, now)...)
		start = end
	}
	for _, prune := range prunes {
		// The attempt under way counts as unfinished until it finishes, so
		// it is only judged once no healthy operation could still be it.
		if prune.Unfinished >= FullPruneUnfinished && now.Sub(prune.AttemptedAt) > OperationLockStale {
			add(prune.Bucket, fmt.Sprintf("its weekly full prune has not finished in its last %d attempts, so data no snapshot uses stays in it; the backups that tried say why (helios backups)", prune.Unfinished))
		}
	}
	var conditions []Condition
	for _, bucket := range order {
		conditions = append(conditions, Condition{Key: storageBucketKey + bucket, Subject: "bucket " + bucket, Severity: state.SeverityWarning,
			Message: strings.Join(problems[bucket], "; ") + "; helios storage shows every bucket"})
	}

	// A kept bucket is not waiting to be deleted, so the sweep records
	// nothing against it but a deletion that was begun and left unfinished.
	// Keeping does not end that one.
	var held []string
	waiting := false
	for _, t := range tombstones {
		switch {
		case t.Problem == "" || t.Moved:
		case t.Kept():
			held = append(held, fmt.Sprintf("bucket %s of %s, removed %s and kept: %s", t.Bucket, t.App, t.RemovedAt.UTC().Format("2006-01-02"), t.Problem))
		default:
			waiting = true
			held = append(held, fmt.Sprintf("bucket %s of %s, removed %s, is not being deleted: %s", t.Bucket, t.App, t.RemovedAt.UTC().Format("2006-01-02"), t.Problem))
		}
	}
	if len(held) > 0 {
		advice := "; helios storage shows each one"
		if waiting {
			advice += ", and helios storage keep <app> ends this for a bucket whose backups should stay"
		}
		conditions = append(conditions, Condition{Key: storageExpiryKey, Subject: "removed apps' buckets", Severity: state.SeverityWarning,
			Message: strings.Join(held, "; ") + advice})
	}
	if why := p.sweepProblem(ctx, newest, now); why != "" {
		conditions = append(conditions, Condition{Key: storageSweepKey, Subject: "the storage sweep", Severity: state.SeverityWarning, Message: why})
	}
	return conditions
}

// sweepProblem says why the nightly sweep is not doing its work. newest is
// when the last sample was taken.
func (p *Prober) sweepProblem(ctx context.Context, newest, now time.Time) string {
	last, err := p.Store.LastOfKind(ctx, app.StorageSweepKind)
	if err != nil {
		return ""
	}
	if last != nil && last.Status.Final() && last.Status != state.Succeeded {
		return fmt.Sprintf("the last storage sweep failed %s ago, so no bucket was measured and none of a removed app expired: %s (helios operations show %s)", ago(last.CreatedAt, now), firstLine(last.Error), last.ID)
	}
	// Without the storage integration there is nothing to sweep, and old
	// samples are not a sweep that stopped.
	if p.StorageSet == nil || !p.StorageSet() || newest.IsZero() || now.Sub(newest) <= app.StorageSampleStale {
		return ""
	}
	return fmt.Sprintf("no bucket has been measured since %s (%s ago); the nightly storage sweep is not running, so growth goes unseen and no removed app's bucket expires", newest.UTC().Format("2006-01-02 15:04 UTC"), ago(newest, now))
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}

// unobservedStorage holds the storage incidents that are open.
func (p *Prober) unobservedStorage(ctx context.Context) []Condition {
	incidents, err := p.Store.OpenIncidents(ctx)
	if err != nil {
		return nil
	}
	var conditions []Condition
	for _, incident := range incidents {
		if strings.HasPrefix(incident.Key, storageBucketKey) || incident.Key == storageExpiryKey || incident.Key == storageSweepKey {
			conditions = append(conditions, Condition{Key: incident.Key, Unknown: true})
		}
	}
	return conditions
}
