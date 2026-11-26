# Helios 0.7.29

This patch adds the storage watch: what every backup bucket costs, an alert
when one grows in a way its backups do not explain, and an end to paying for
the buckets of removed apps and for space that forgotten snapshots still
hold. It also gives a release checkpoint an age limit.

- `helios storage` lists every bucket this machine owns with its size, its
  snapshots, a week's growth and how much of it no snapshot uses. A nightly
  `storage.sweep` at 05:00 UTC takes the measurements. `helios storage sweep`
  measures now.
- A bucket that grows by half in a week (and by at least 1 GB), one over 5 GB
  that is more than 20 times its newest snapshot, or one over 5 GB that is
  more than half dead data raises a warning. A new repository's first week
  raises nothing.
- `helios remove <app>` now records the app's bucket, and the sweep deletes it
  30 days later. `helios storage keep <app>` cancels that and `helios storage
  purge <app>` does it now. A bucket is deleted only when this machine
  removed its app, every snapshot in it is one this machine recorded making,
  and nothing was written to it after the removal. A bucket that carries the
  machine's prefix and belongs to no app here is reported and never touched.
- Each repository is pruned in full once a week, so the space of forgotten
  snapshots comes back. The nightly prune stays the quick one.
- A run records every snapshot restic returned to it at once, so a backup
  that failed after its capture no longer leaves a snapshot nobody recorded,
  which held a removed app's bucket for good.
- On an S3 store, a listing that trails its deletions for a moment no longer
  stops a deletion at one page a night, and a store that answers a listing of
  versions or of unfinished uploads with the plain listing is read as a store
  without them and no longer passes for an empty bucket. A listing that
  repeats itself or never ends stops with an error.
- **A completed release's checkpoint is kept for a rollback for 30 days.**
  Before, a checkpoint was kept until it was restored, so an app that ships
  data-changing releases kept one per release for good. From 30 days after a
  release began, once its jobs finished, `helios rollback --restore-data`
  refuses its checkpoint. A day later ordinary retention decides about the
  snapshot, and garbage collection stops holding the revision it returns to.
  A release whose jobs failed, or that is still under way or being restored,
  keeps its checkpoint at any age.
- `helios rollback` refuses a checkpoint that an earlier restoration already
  discarded: the data is older than that checkpoint, and a rollback does not
  move it forward.

**Read this before upgrading if you rely on old checkpoints.** A release
declared `restore-required`, or with no declared data compatibility, cannot
be rolled back by code alone. Until now it could be rolled back by restoring
its checkpoint at any age. From this version that works for 30 days. After
that the data from before the release is out of a rollback's reach:
`helios rollback` says so, names a later release's checkpoint when one is
still inside the 30 days, and otherwise points at an ordinary backup. The
first backup after the upgrade lets retention decide about every such
checkpoint older than 31 days.

No `--json` shape of an existing command, production dependency, data
relocation or application redeployment changes. The state store gains tables
and three columns for the storage watch when it is first opened; the state
version is unchanged, and an older binary opens the same store and ignores
them. The first weekly full prune of a large repository takes longer than a
nightly one and runs inside the backup's own step.

## Upgrade

0.7.28 to 0.7.29 crosses no lock-path boundary. On each live target,
**personal-vps** and **braintreelabs**, capture
`helios upgrade --version 0.7.29 --plan`, inspect it, then apply its exact
`--digest`. The storage key needs to list all buckets and delete files and
buckets for the watch to measure and expire; see
`docs/features/storage-watch.md`.

## Verification

The source passes `make check` with a short `TMPDIR`. The deletion rule, the
listings and the checkpoint horizon each have tests that fail when the line
they guard is removed, and an independent review of the follow-ups found
five defects that are fixed here. The object store code runs against
in-process fakes of B2 and S3.

Not run against a live S3 store other than Backblaze's, and no bucket has yet
been deleted by the sweep on a live machine: the first tombstone made after
the upgrade expires 30 days later.
