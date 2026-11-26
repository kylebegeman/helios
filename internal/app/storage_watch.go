package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/objectstore"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// The storage watch.
//
// Nothing else looks at what backups cost: a bucket outlives its app, a
// repository keeps data no snapshot uses, and the bill is the first to say
// so. The watch is three operations over the same records:
//
//   - StorageSweepKind runs every night after the backups. It records how
//     large each bucket is and deletes the buckets of removed apps whose 30
//     days are up.
//   - StorageKeepKind cancels one bucket's expiry.
//   - StoragePurgeKind deletes one removed app's bucket now.
//
// Which buckets may be deleted is the whole of the danger here, and the
// rule is narrow on purpose. Two machines can share one storage account,
// one key and one bucket prefix; from either, the other's buckets look like
// buckets nobody uses. So "no app here uses it" is never a reason to delete
// anything. A bucket is deleted only when this machine holds a tombstone
// for it, which `helios remove` alone records, only while every check in
// tombstoneVerdict still holds, and only when every snapshot in it is one
// this machine recorded making (see strangers). A tombstone says this
// machine gave the app up; the snapshots say whose backups the bucket
// holds, and only that makes the bucket this machine's to delete. Anything
// this machine cannot read or does not recognise stays, and says why.
const (
	// StorageSweepKind is the nightly pass: sample every bucket, then expire
	// the buckets of removed apps.
	StorageSweepKind = "storage.sweep"
	// StorageKeepKind cancels the expiry of a removed app's bucket.
	StorageKeepKind = "storage.keep"
	// StoragePurgeKind deletes a removed app's bucket without waiting.
	StoragePurgeKind = "storage.purge"
)

// BucketExpiry is how long the bucket of a removed app stays before the
// nightly sweep deletes it. A month is long enough to notice that an app
// was removed by mistake and bring it back from its backups, and short
// enough that a removed app stops costing anything by the second bill.
const BucketExpiry = 30 * 24 * time.Hour

// bucketWriteSlack is how long after a removal an upload still counts as
// the removed app's own. The removal is recorded when its last step ends,
// after anything of the app could write; an hour covers a clock that
// differs between this machine and the object store. Any upload later than
// that came from somewhere else, and the bucket is then in use. This only
// catches a writer that is still writing; whose the contents are is settled
// before it, by the snapshots.
const bucketWriteSlack = time.Hour

// snapshotRunKinds are the backup run kinds that write a snapshot into an
// app's repository on this machine: a backup, the capture a move takes, and
// a release checkpoint. A drill or a restore records the snapshot it read,
// which proves nothing about who made it.
var snapshotRunKinds = []string{state.BackupRunBackup, releaseCheckpointRun}

// StorageSampleWindow is how long samples are kept: the seven days growth
// is measured over, with four weeks behind them to see a trend in.
const StorageSampleWindow = 35 * 24 * time.Hour

// The sweep holds the machine's operation lock, so neither half of it may
// run away with the night. A bucket that is not read in time is recorded as
// not read; a deletion that is not finished continues the next night.
const (
	sweepSampleBudget = 20 * time.Minute
	sweepExpireBudget = 40 * time.Minute
)

// StorageWatch is what the three storage operations share.
type StorageWatch struct {
	Store   *state.Store
	Secrets *secrets.Store
	// Hostname names this machine's own bucket.
	Hostname func() string
	// Objects reaches the object store's own API; nil means objectstore.New.
	Objects func(objectstore.Config) (objectstore.Store, error)
	// Snapshots lists every snapshot in a bucket's repository, whoever made
	// it; nil means restic through Docker.
	Snapshots func(ctx context.Context, st *integration.Storage, bucket string) ([]restic.Snapshot, error)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func (w StorageWatch) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

// storageCredentials names the storage credentials without the network: a
// removal records it so that the first sweep can tell whether it still
// looks at the same store.
func storageCredentials(st *integration.Storage) string {
	sum := sha256.Sum256([]byte(st.Kind + "\x00" + strings.TrimSuffix(st.Endpoint, "/") + "\x00" + st.KeyID))
	return fmt.Sprintf("key:%x", sum[:8])
}

func (w StorageWatch) storage() (*integration.Storage, error) {
	st, err := integration.LoadStorage(w.Secrets)
	if err != nil {
		return nil, fmt.Errorf("the storage watch needs the storage integration: %w", err)
	}
	if st.BucketPrefix == "" {
		return nil, errors.New("the storage integration has no bucket prefix, so no bucket can be told apart as this machine's")
	}
	return st, nil
}

// storageSession is one look at the storage account.
type storageSession struct {
	w       StorageWatch
	st      *integration.Storage
	obj     objectstore.Store
	account string
	// listed is every bucket the credentials can see. A bucket missing from
	// a listing that succeeded does not exist.
	listed map[string]objectstore.Bucket
}

// open reads the account and its buckets. Every failure here stops the
// operation before it deletes anything.
func (w StorageWatch) open(ctx context.Context) (*storageSession, error) {
	st, err := w.storage()
	if err != nil {
		return nil, err
	}
	dial := w.Objects
	if dial == nil {
		dial = objectstore.New
	}
	obj, err := dial(objectstore.Config{Kind: st.Kind, Endpoint: st.Endpoint, KeyID: st.KeyID, Key: st.Key})
	if err != nil {
		return nil, err
	}
	account, err := obj.Account(ctx)
	if err != nil {
		return nil, fmt.Errorf("identify the storage account: %w", err)
	}
	if account == "" {
		return nil, errors.New("the storage account has no identity; nothing is deleted without one")
	}
	buckets, err := obj.Buckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the storage buckets: %w", err)
	}
	s := &storageSession{w: w, st: st, obj: obj, account: account, listed: map[string]objectstore.Bucket{}}
	for _, b := range buckets {
		s.listed[b.Name] = b
	}
	return s, nil
}

// ownedBucket is a bucket this machine answers for.
type ownedBucket struct {
	bucket, owner, kind string
}

// owned names the buckets this machine answers for: one for each app it
// holds, its own, and one for each app it removed whose bucket has not
// expired yet. An app that moved away is not among them.
func (w StorageWatch) owned(ctx context.Context, st *integration.Storage) ([]ownedBucket, error) {
	names, err := w.Store.AppNames(ctx)
	if err != nil {
		return nil, err
	}
	tombstones, err := w.Store.StorageTombstones(ctx)
	if err != nil {
		return nil, err
	}
	var out []ownedBucket
	seen := map[string]bool{}
	add := func(b ownedBucket) {
		if b.bucket != "" && !seen[b.bucket] {
			seen[b.bucket] = true
			out = append(out, b)
		}
	}
	for _, name := range names {
		if name != manifest.ReservedApp {
			add(ownedBucket{st.Bucket(name), name, state.StorageApp})
		}
	}
	if w.Hostname != nil {
		if target := MachineTarget(w.Hostname()); target != MachineTarget("") {
			add(ownedBucket{st.Bucket(target), target, state.StorageMachine})
		}
	}
	for _, t := range tombstones {
		if !t.Moved {
			add(ownedBucket{t.Bucket, t.App, state.StorageRemoved})
		}
	}
	return out, nil
}

// StorageSweep is the Definition for StorageSweepKind.
type StorageSweep struct{ StorageWatch }

// StorageSweepInput is empty: a sweep takes the whole machine.
type StorageSweepInput struct{}

// Kind implements kernel.Definition.
func (StorageSweep) Kind() string { return StorageSweepKind }

// Plan implements kernel.Definition.
func (w StorageSweep) Plan(ctx context.Context, _ json.RawMessage) (*kernel.Plan, error) {
	if _, err := w.storage(); err != nil {
		return nil, err
	}
	tombstones, err := w.Store.StorageTombstones(ctx)
	if err != nil {
		return nil, err
	}
	now := w.now()
	// The plan names the buckets that may go. The step deletes no other,
	// so a plan read with --plan is the whole of what its digest allows.
	var due, named []string
	for _, t := range tombstones {
		if bucketDue(t, now) {
			due = append(due, t.App)
			named = append(named, fmt.Sprintf("%s (%s, removed %s)", t.Bucket, t.App, t.RemovedAt.UTC().Format("2006-01-02")))
		}
	}
	change := "no removed app's bucket has reached its 30 days; delete nothing"
	if len(due) > 0 {
		change = "delete the buckets of apps removed more than 30 days ago, with every backup in them (no way back): " + strings.Join(named, ", ")
	}
	return &kernel.Plan{Target: "storage", Recovery: kernel.Resume, Steps: []kernel.Step{
		{Name: "sample", Change: "record the size and snapshots of every bucket this machine owns, and the size of the others under its prefix", Apply: w.sample},
		{Name: "expire", Change: change, Apply: func(ctx context.Context, out io.Writer) error { return w.expire(ctx, due, out) }},
	}}, nil
}

// bucketDue reports whether a tombstone's 30 days are up.
func bucketDue(t state.StorageTombstone, now time.Time) bool {
	return !t.Moved && !t.Kept() && !now.Before(t.RemovedAt.Add(BucketExpiry))
}

func unknownSample(b ownedBucket, at time.Time) state.StorageSample {
	return state.StorageSample{Bucket: b.bucket, TakenAt: at, Owner: b.owner, Kind: b.kind,
		StoredBytes: state.StorageUnknown, Files: state.StorageUnknown, UsedBytes: state.StorageUnknown,
		Snapshots: state.StorageUnknown, NewestSnapshotBytes: state.StorageUnknown}
}

// sample records one reading of every bucket under this machine's prefix.
// A figure that cannot be read is recorded as unknown with the reason; it
// is never guessed, and one unreadable bucket does not cost the others
// their sample.
func (w StorageWatch) sample(ctx context.Context, out io.Writer) error {
	s, err := w.open(ctx)
	if err != nil {
		return err
	}
	owned, err := w.owned(ctx, s.st)
	if err != nil {
		return err
	}
	now := w.now()
	e, dockerErr := docker.Connect(ctx)
	if dockerErr == nil {
		defer e.Close()
	}
	budget, cancel := context.WithTimeout(ctx, sweepSampleBudget)
	defer cancel()
	var samples []state.StorageSample
	mine := map[string]bool{}
	for _, b := range owned {
		mine[b.bucket] = true
		if _, exists := s.listed[b.bucket]; !exists {
			continue // nothing was ever backed up into it
		}
		sample := unknownSample(b, now)
		var notes []string
		notes = s.readUsage(budget, &sample, notes)
		switch {
		case dockerErr != nil:
			notes = append(notes, "snapshots not read: "+firstLine(dockerErr.Error()))
		default:
			notes = s.readRepository(budget, e, b, &sample, notes)
		}
		sample.Note = strings.Join(notes, "; ")
		samples = append(samples, sample)
	}
	// What else carries the prefix is another machine's, or nobody's. This
	// machine cannot tell which, so it only says how large each one is.
	prefix := s.st.BucketPrefix + "-"
	for _, name := range sortedKeys(s.listed) {
		if !strings.HasPrefix(name, prefix) || mine[name] {
			continue
		}
		sample := unknownSample(ownedBucket{bucket: name, kind: state.StorageForeign}, now)
		sample.Note = strings.Join(s.readUsage(budget, &sample, nil), "; ")
		samples = append(samples, sample)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.Store.AddStorageSamples(ctx, samples, now.Add(-StorageSampleWindow)); err != nil {
		return fmt.Errorf("record the storage samples: %w", err)
	}
	for _, sample := range samples {
		line := fmt.Sprintf("%s: %s", sample.Bucket, knownBytes(sample.StoredBytes))
		if sample.Snapshots >= 0 {
			line += fmt.Sprintf(", %d snapshot(s)", sample.Snapshots)
		}
		if sample.Kind == state.StorageForeign {
			line += ", not this machine's"
		}
		if sample.Note != "" {
			line += " (" + sample.Note + ")"
		}
		fmt.Fprintln(out, line)
	}
	if len(samples) == 0 {
		fmt.Fprintln(out, "no bucket carries this machine's prefix yet")
	}
	return nil
}

func knownBytes(n int64) string {
	if n < 0 {
		return "size unknown"
	}
	return HumanBytes(n)
}

// readUsage adds up what the bucket stores, which is what is billed.
func (s *storageSession) readUsage(ctx context.Context, sample *state.StorageSample, notes []string) []string {
	if ctx.Err() != nil {
		return append(notes, "size not read: the sweep ran out of time")
	}
	usage, err := s.obj.Usage(ctx, s.listed[sample.Bucket])
	if err != nil {
		return append(notes, "size not read: "+firstLine(err.Error()))
	}
	sample.StoredBytes, sample.Files, sample.LastWriteAt = usage.Bytes, usage.Files, usage.LastWrite
	return notes
}

// readRepository asks restic what the repository holds. Both commands read
// without a lock, so they neither wait for nor hold up anything else.
func (s *storageSession) readRepository(ctx context.Context, e *docker.Engine, b ownedBucket, sample *state.StorageSample, notes []string) []string {
	if ctx.Err() != nil {
		return append(notes, "snapshots not read: the sweep ran out of time")
	}
	// The helper container carries the machine's label, not a removed
	// app's, so nothing mistakes it for something that app left behind.
	owner := b.owner
	if b.kind != state.StorageApp {
		owner = manifest.ReservedApp
	}
	r := restic.Runner{Engine: e, Owner: owner, Repo: restic.Repo{Repository: s.st.Repository(b.bucket), Password: s.st.Password, Env: s.st.Env()}}
	snapshots, err := r.AllSnapshots(ctx)
	if err != nil {
		return append(notes, "snapshots not read: "+firstLine(err.Error()))
	}
	sample.Snapshots = int64(len(snapshots))
	if len(snapshots) > 0 {
		newest := snapshots[0]
		sample.NewestSnapshotAt, sample.OldestSnapshotAt = newest.Time.UTC(), snapshots[len(snapshots)-1].Time.UTC()
		if newest.Summary != nil {
			sample.NewestSnapshotBytes = newest.Summary.TotalBytes
		}
	}
	used, err := r.UsedBytes(ctx)
	if err != nil {
		return append(notes, "dead data not read: "+firstLine(err.Error()))
	}
	sample.UsedBytes = used
	return notes
}

// A tombstone's verdict.
const (
	// bucketWait: nothing to do yet.
	bucketWait = iota
	// bucketHold: something is not as the removal left it. Nothing is
	// deleted, and the reason is recorded and raised.
	bucketHold
	// bucketGone: the bucket no longer exists, so the tombstone is spent.
	bucketGone
	// bucketDelete: every check holds and the bucket may go.
	bucketDelete
)

// tombstoneFacts is what a verdict is reached from.
type tombstoneFacts struct {
	// bucket is what the app's bucket is called under today's prefix.
	bucket string
	// credentials and account identify the store today's integration
	// reaches: without the network, and as the store names itself.
	credentials, account string
	// listed says the bucket is in a listing that succeeded.
	listed bool
	// revisions is how many revisions of the app this machine holds.
	revisions int
	now       time.Time
	// byHand is helios storage purge: the operator said now, so neither the
	// 30 days nor a keep stands in the way. Every other check still does.
	byHand bool
}

// tombstoneVerdict decides what becomes of a removed app's bucket. It is
// the only place that can say "delete", and every doubt says "hold":
//
//  1. The app left through a move: the bucket is the other machine's.
//  2. The app has revisions here again: the bucket is in use. (Recording a
//     revision clears the tombstone, so this only catches an interrupted
//     removal.)
//  3. The bucket is not what this app's bucket is called today: the prefix
//     changed, and the name may now mean something else.
//  4. The storage integration reaches another account than the one the app
//     was removed from: a bucket of the same name there is not this one.
//  5. The 30 days are not up, or the expiry was cancelled.
//
// Two more checks need the bucket's contents and are made on the way to the
// deletion: every snapshot in it must be one this machine made (strangers),
// and nothing may have been uploaded after the removal, which the deletion
// itself refuses.
func tombstoneVerdict(t state.StorageTombstone, f tombstoneFacts) (int, string) {
	switch {
	case t.Moved:
		return bucketHold, fmt.Sprintf("%s left this machine through a move, so bucket %s belongs to the machine it moved to", t.App, t.Bucket)
	case f.revisions > 0:
		return bucketHold, fmt.Sprintf("%s is on this machine again, so bucket %s is in use", t.App, t.Bucket)
	case t.Bucket == "" || t.Bucket != f.bucket:
		return bucketHold, fmt.Sprintf("the storage prefix changed since %s was removed: its bucket would now be called %s, not %s", t.App, f.bucket, t.Bucket)
	case t.Account == "" || f.account == "" || f.credentials == "":
		return bucketHold, fmt.Sprintf("it is not recorded which storage account bucket %s was in", t.Bucket)
	case strings.HasPrefix(t.Account, "key:") && t.Account != f.credentials:
		return bucketHold, fmt.Sprintf("the storage credentials changed before bucket %s was first checked, so it cannot be told whether this is the same account", t.Bucket)
	case !strings.HasPrefix(t.Account, "key:") && t.Account != f.account:
		return bucketHold, fmt.Sprintf("the storage integration reaches another account than the one %s was removed from; bucket %s there is left alone", t.App, t.Bucket)
	case !f.listed:
		return bucketGone, ""
	case f.byHand:
		return bucketDelete, ""
	case t.Kept() || f.now.Before(t.RemovedAt.Add(BucketExpiry)):
		return bucketWait, ""
	}
	return bucketDelete, ""
}

// settle reaches one tombstone's verdict and acts on it. mayDelete is
// false for a bucket the reviewed plan did not name. It returns why a
// bucket was held, and an error only when state could not be read or
// written, which stops the whole pass.
func (s *storageSession) settle(ctx context.Context, t state.StorageTombstone, mayDelete, byHand bool, out io.Writer) (string, error) {
	store := s.w.Store
	revs, err := store.Revisions(ctx, t.App)
	if err != nil {
		return "", err
	}
	_, listed := s.listed[t.Bucket]
	verdict, why := tombstoneVerdict(t, tombstoneFacts{
		bucket: s.st.Bucket(t.App), credentials: storageCredentials(s.st), account: s.account,
		listed: listed, revisions: len(revs), now: s.w.now(), byHand: byHand,
	})
	hold := func(why string) (string, error) {
		fmt.Fprintf(out, "bucket %s stays: %s\n", t.Bucket, why)
		return why, store.SetStorageTombstoneProblem(ctx, t.App, why)
	}
	if verdict == bucketHold {
		if t.Moved {
			return why, nil // not a problem: it is how the row is meant to be
		}
		return hold(why)
	}
	// The account checked out. From here on the tombstone is held to the
	// account itself, which a rotated key does not change.
	if strings.HasPrefix(t.Account, "key:") {
		if err := store.BindStorageTombstone(ctx, t.App, t.Account, s.account); err != nil {
			return "", err
		}
	}
	switch verdict {
	case bucketGone:
		fmt.Fprintf(out, "bucket %s no longer exists; nothing of %s is left to expire\n", t.Bucket, t.App)
		return "", s.forget(ctx, t)
	case bucketDelete:
		if !mayDelete {
			fmt.Fprintf(out, "bucket %s is due, but the plan that was reviewed does not name it; the next sweep takes it\n", t.Bucket)
			return "", nil
		}
	default:
		if t.Problem != "" {
			return "", store.SetStorageTombstoneProblem(ctx, t.App, "")
		}
		return "", nil
	}
	// The tombstone says this machine gave the app up. It does not say the
	// bucket's contents are this machine's: another machine may run an app
	// of the same name against the same account and prefix, and its
	// backups are then in this very bucket.
	why, err = s.strangers(ctx, t)
	if err != nil {
		return "", err
	}
	if why != "" {
		return hold(why)
	}
	fmt.Fprintf(out, "deleting bucket %s, the backups of %s removed on %s\n", t.Bucket, t.App, t.RemovedAt.UTC().Format("2006-01-02"))
	done, err := s.obj.DeleteBucket(ctx, s.listed[t.Bucket], t.RemovedAt.Add(bucketWriteSlack))
	switch {
	case errors.Is(err, objectstore.ErrWrittenSince):
		return hold(fmt.Sprintf("something was uploaded to it after %s was removed, so it is still in use, perhaps by another machine; nothing was deleted (%s)", t.App, firstLine(err.Error())))
	case err != nil:
		return hold(fmt.Sprintf("deleting it did not finish after %d file(s): %s; the next sweep carries on", done.Files, firstLine(err.Error())))
	}
	fmt.Fprintf(out, "deleted bucket %s: %d file(s), %s\n", t.Bucket, done.Files, HumanBytes(done.Bytes))
	return "", s.forget(ctx, t)
}

// strangers says why a bucket is not this machine's to delete, or "" when
// every snapshot in it is one this machine recorded making. The runs of a
// removed app are kept, so the record outlives the app. A repository that
// cannot be read, and a machine with no record of a snapshot for the app,
// both hold: the proof has to be there, not merely not contradicted. An
// error is returned only when this machine's own state could not be read.
func (s *storageSession) strangers(ctx context.Context, t state.StorageTombstone) (string, error) {
	made, err := s.w.Store.SnapshotsMade(ctx, t.App, snapshotRunKinds...)
	if err != nil {
		return "", err
	}
	if len(made) == 0 {
		return fmt.Sprintf("this machine has no record of a backup of %s, so the backups in it are not this machine's to delete", t.App), nil
	}
	list := s.w.Snapshots
	if list == nil {
		list = resticSnapshots
	}
	snapshots, err := list(ctx, s.st, t.Bucket)
	if err != nil {
		return fmt.Sprintf("its snapshots could not be read, so it cannot be told whose backups it holds (%s)", firstLine(err.Error())), nil
	}
	var unknown []string
	for _, snapshot := range snapshots {
		if !made[snapshot.ID] {
			unknown = append(unknown, snapshot.ID)
		}
	}
	if len(unknown) == 0 {
		return "", nil
	}
	first := unknown[0]
	if len(first) > 8 {
		first = first[:8]
	}
	return fmt.Sprintf("%d of its %d snapshot(s) were not made by this machine (the first is %s), so another machine backs up to it or did; it is left for that machine, or for whoever deletes it at the storage provider", len(unknown), len(snapshots), first), nil
}

// resticSnapshots asks restic for every snapshot in a bucket's repository.
// It takes no lock, so it reads a repository another machine is writing to.
func resticSnapshots(ctx context.Context, st *integration.Storage, bucket string) ([]restic.Snapshot, error) {
	e, err := docker.Connect(ctx)
	if err != nil {
		return nil, err
	}
	defer e.Close()
	// The helper container carries the machine's label, not the removed
	// app's, so nothing mistakes it for something that app left behind.
	r := restic.Runner{Engine: e, Owner: manifest.ReservedApp, Repo: restic.Repo{Repository: st.Repository(bucket), Password: st.Password, Env: st.Env()}}
	return r.AllSnapshots(ctx)
}

// forget drops what was recorded about a bucket that is gone.
func (s *storageSession) forget(ctx context.Context, t state.StorageTombstone) error {
	if err := s.w.Store.DeleteStorageSamples(ctx, t.Bucket); err != nil {
		return err
	}
	return s.w.Store.DeleteStorageTombstone(ctx, t.App)
}

// expire deletes the buckets the plan named, and checks every other
// tombstone so that one that can never expire says so before its day.
func (w StorageWatch) expire(ctx context.Context, due []string, out io.Writer) error {
	tombstones, err := w.Store.StorageTombstones(ctx)
	if err != nil {
		return err
	}
	pending := tombstones[:0:0]
	for _, t := range tombstones {
		if !t.Moved {
			pending = append(pending, t)
		}
	}
	if len(pending) == 0 {
		fmt.Fprintln(out, "no removed app's bucket is waiting to expire")
		return nil
	}
	s, err := w.open(ctx)
	if err != nil {
		return err
	}
	budget, cancel := context.WithTimeout(ctx, sweepExpireBudget)
	defer cancel()
	for _, t := range pending {
		if _, err := s.settle(budget, t, slices.Contains(due, t.App), false, out); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// StorageAppInput names the removed app whose bucket is meant.
type StorageAppInput struct {
	App string `json:"app"`
}

// tombstoneOf finds the tombstone a keep or a purge is about. Neither
// accepts anything else: a bucket this machine did not give up through
// helios remove is not this machine's to decide on.
func (w StorageWatch) tombstoneOf(ctx context.Context, raw json.RawMessage, verb string) (*state.StorageTombstone, error) {
	var in StorageAppInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("storage %s input: %w", verb, err)
	}
	if in.App == "" {
		return nil, errors.New("which app?")
	}
	t, err := w.Store.StorageTombstone(ctx, in.App)
	if errors.Is(err, state.ErrNotFound) {
		return nil, fmt.Errorf("this machine has no bucket of a removed app named %s; helios storage %s only takes an app that helios remove took off this machine (helios storage lists them)", in.App, verb)
	}
	if err != nil {
		return nil, err
	}
	if t.Moved {
		return nil, fmt.Errorf("%s left this machine through a move, so bucket %s belongs to the machine it moved to and is decided there", t.App, t.Bucket)
	}
	return t, nil
}

// StorageKeep is the Definition for StorageKeepKind.
type StorageKeep struct{ StorageWatch }

// Kind implements kernel.Definition.
func (StorageKeep) Kind() string { return StorageKeepKind }

// Plan implements kernel.Definition.
func (w StorageKeep) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	t, err := w.tombstoneOf(ctx, raw, "keep")
	if err != nil {
		return nil, err
	}
	if t.Kept() {
		return nil, fmt.Errorf("bucket %s is kept already, since %s", t.Bucket, t.KeptAt.UTC().Format("2006-01-02"))
	}
	app := t.App
	return &kernel.Plan{Target: app, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name:   "keep",
		Change: fmt.Sprintf("cancel the expiry of bucket %s, the backups of %s removed on %s; it stays until helios storage purge %s", t.Bucket, app, t.RemovedAt.UTC().Format("2006-01-02"), app),
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := w.Store.KeepStorageTombstone(ctx, app, w.now()); err != nil {
				return err
			}
			fmt.Fprintf(out, "bucket %s is kept\n", t.Bucket)
			return nil
		},
	}}}, nil
}

// StoragePurge is the Definition for StoragePurgeKind.
type StoragePurge struct{ StorageWatch }

// Kind implements kernel.Definition.
func (StoragePurge) Kind() string { return StoragePurgeKind }

// Plan implements kernel.Definition.
func (w StoragePurge) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	t, err := w.tombstoneOf(ctx, raw, "purge")
	if err != nil {
		return nil, err
	}
	if _, err := w.storage(); err != nil {
		return nil, err
	}
	app, removed := t.App, t.RemovedAt
	return &kernel.Plan{Target: app, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name:   "purge",
		Change: fmt.Sprintf("delete bucket %s and every backup in it, the backups of %s removed on %s (no way back)", t.Bucket, app, removed.UTC().Format("2006-01-02")),
		Apply: func(ctx context.Context, out io.Writer) error {
			// The tombstone is read again: it must be the removal the plan
			// described, not a later one of an app that came and went.
			current, err := w.Store.StorageTombstone(ctx, app)
			if errors.Is(err, state.ErrNotFound) {
				fmt.Fprintf(out, "bucket %s is no longer waiting to expire\n", t.Bucket)
				return nil
			}
			if err != nil {
				return err
			}
			if current.Moved || current.Bucket != t.Bucket || !current.RemovedAt.Equal(removed) {
				return fmt.Errorf("%s was removed again or moved since this purge was reviewed; review it again", app)
			}
			s, err := w.open(ctx)
			if err != nil {
				return err
			}
			held, err := s.settle(ctx, *current, true, true, out)
			if err != nil {
				return err
			}
			if held != "" {
				return fmt.Errorf("bucket %s was not deleted: %s", t.Bucket, held)
			}
			return nil
		},
	}}}, nil
}

// bucketFate is what a removal does about the app's backup bucket.
type bucketFate struct {
	// bucket is empty when the app has no bucket to speak of.
	bucket      string
	credentials string
	// moved means a move is on record for the app, so the bucket may be in
	// use by the machine at the other end and never expires here.
	moved bool
}

// bucketFate decides, when a removal is planned, whether the app's bucket
// starts to expire. It needs no network, and it errs towards keeping: only
// an app with storage set, a snapshot this machine recorded making, and no
// move on record gets a tombstone. That the app keeps data is not enough:
// an app of the same name on another machine may be what fills the bucket,
// and this machine never wrote to it.
func (r Remove) bucketFate(ctx context.Context, app string) (bucketFate, error) {
	if r.Secrets == nil {
		return bucketFate{}, nil
	}
	st, err := integration.LoadStorage(r.Secrets)
	if errors.Is(err, integration.ErrNotSet) {
		return bucketFate{}, nil
	}
	if err != nil {
		return bucketFate{}, err
	}
	if st.BucketPrefix == "" {
		return bucketFate{}, nil
	}
	fate := bucketFate{bucket: st.Bucket(app), credentials: storageCredentials(st)}
	// An interrupted removal of a moved app left its mark before it forgot
	// the move; a retry finds the mark and not the move.
	earlier, err := r.Store.StorageTombstone(ctx, app)
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return bucketFate{}, err
	}
	// A move's record that cannot be read is still a move's record. It
	// does not stop the removal, which is how such a record is cleared; it
	// only means the bucket stays.
	record, err := readMigration(r.Store.Path(), app)
	if err != nil || record != nil || (earlier != nil && earlier.Moved) {
		fate.moved = true
		return fate, nil
	}
	made, err := r.Store.SnapshotsMade(ctx, app, snapshotRunKinds...)
	if err != nil {
		return bucketFate{}, err
	}
	if len(made) > 0 {
		return fate, nil
	}
	return bucketFate{}, nil
}

// change is what the removal's last step says about the bucket.
func (f bucketFate) change(app string) string {
	switch {
	case f.bucket == "":
		return ""
	case f.moved:
		return fmt.Sprintf("; its backups in bucket %s stay, because a move is on record for it and the machine at the other end may use the bucket", f.bucket)
	}
	return fmt.Sprintf("; its backups in bucket %s are deleted after %d days unless helios storage keep %s cancels that", f.bucket, int(BucketExpiry/(24*time.Hour)), app)
}

// afterData is what the data step says about the backups.
func (f bucketFate) afterData() string {
	if f.bucket != "" && !f.moved {
		return fmt.Sprintf("its backups in the storage bucket stay for %d more days", int(BucketExpiry/(24*time.Hour)))
	}
	return "its backups in the storage bucket stay"
}

// record makes the fate durable as the app is forgotten. It returns the
// tombstone to record with the removal, or nil when the bucket stays.
func (f bucketFate) record(ctx context.Context, store *state.Store, app string, at time.Time) (*state.StorageTombstone, error) {
	if f.bucket == "" {
		return nil, nil
	}
	if f.moved {
		// Before the move's record is forgotten, so a retry cannot find the
		// app without its move and start the bucket's clock.
		return nil, store.MarkStorageMoved(ctx, app, f.bucket, at)
	}
	if record, err := readMigration(store.Path(), app); err != nil || record != nil {
		return nil, fmt.Errorf("a move was recorded for %s after its removal was reviewed; review the removal again", app)
	}
	return &state.StorageTombstone{App: app, Bucket: f.bucket, Account: f.credentials, RemovedAt: at}, nil
}
