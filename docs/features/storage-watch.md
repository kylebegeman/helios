# Storage watch

Backups cost money for as long as they are stored, and nothing in a backup
tool's ordinary work says how much. Helios measures every bucket it owns each
night, raises an alert when one grows in a way its backups do not explain,
deletes the bucket of an app removed 30 days ago, and reclaims the space of
forgotten snapshots in full once a week.

## The report

```sh
helios storage
helios storage --json
```

One row for each bucket this machine owns: every app that is backed up, the
machine's own repository, and every removed app whose bucket has not expired.

| Column | What it is |
|---|---|
| `SIZE` | every version of every file in the bucket, which is what is billed |
| `SNAPSHOTS` | how many snapshots the repository holds |
| `NEWEST` | when the newest of them was taken |
| `7D GROWTH` | `SIZE` now against `SIZE` seven days ago. In a bucket's first week of samples it compares with the first sample and says how many days that covers |
| `DEAD` | `SIZE` less what `restic stats --mode raw-data` counts |
| `STATE` | for a removed app: when it was removed and when its bucket is deleted, or that it is kept |

`DEAD` is the cheapest honest measure restic offers. `restic stats --mode
raw-data` adds up the stored size of every blob a snapshot still uses, from
the repository's index, without downloading any data. What the bucket holds
beyond that is data no snapshot uses, waiting for a prune. The figure includes
the repository's own indexes and keys, a few megabytes, so a healthy
repository never reads exactly zero.

A `?` is a figure the last sweep could not read, and a line under the table
says why. The report reads no storage itself: it shows the account as of the
time it names. `helios storage sweep` measures again now.

A second list holds the buckets that carry this machine's bucket prefix and
that it does not own. They belong to another machine that shares the storage
account, or to nobody. **They are reported and never touched**, whatever their
age: from one machine, another machine's buckets look unused, so "no app here
uses it" is never a reason to delete. The bucket of an app that left through
`helios move` is listed there too.

## The nightly sweep

The daemon runs `storage.sweep` at 05:00 UTC, after the night's backups
(03:00 by default), the machine backup (03:30) and garbage collection
(04:00). It is an operation like any other, with a plan, a receipt and a
place in `helios history`. It has two steps.

1. **Sample.** List the account's buckets. For each owned bucket, add up every
   file version and read the repository's snapshots and used bytes. For the
   other buckets under the prefix, add up the files only. The samples go to
   the state store and are kept for 35 days.
2. **Expire.** Delete the bucket of each app removed more than 30 days ago.
   The plan names every bucket this step deletes, and the step deletes no
   other.

The sample has 20 minutes and the deletions 40, because the sweep holds the
machine's operation lock. A bucket not read in time is recorded as not read,
and a deletion that does not finish in time is recorded as unfinished and
continues the next night.

## The growth alert

The daemon's watch reads the samples every minute and raises a warning for a
bucket, `storage:<bucket>`, in three cases. A bucket's alert is its own: one
that recovers does not hide another.

| Case | Rule | Why |
|---|---|---|
| Unusual growth | half as large again as seven days before, and at least 1 GB larger | Retention keeps a steady repository level, so a week of daily backups adds little. Half as much again is far outside that. The 1 GB floor keeps a small bucket that doubles from 100 MB quiet |
| Bloat | over 5 GB, and more than 20 times its newest snapshot | Seven daily, four weekly and six monthly snapshots of slowly changing data share most of their blocks. Twenty times one snapshot means they share nothing, or that forgotten data is not being reclaimed |
| Dead data | over 5 GB, and more than half of it used by no snapshot | A prune that keeps up leaves a few percent |

**A new repository's first week raises nothing.** Its first week is all
growth. The growth rule compares with the sample of a week before only when
that sample was itself taken from a repository at least a week old, judged by
its oldest snapshot or, when retention keeps the oldest snapshot younger than
that, by a week of samples. So a new app stays quiet for its first week and
for the week after, when the only week-old samples are from the days it was
filling up.

The watch raises four more conditions:

- `storage:<bucket>` also when the bucket's weekly full prune started three
  times in a row without finishing.
- `host:storage-expiry` when the sweep refuses to delete a removed app's
  bucket. The message names the bucket and the reason.
- `host:storage-sweep` when the last sweep failed, or when storage is set and
  no bucket has been measured for 48 hours.

When the state store cannot be read, the storage alerts that are open stay
open: no reading is not a recovery.

## Buckets of removed apps

`helios remove <app>` records a tombstone in the state store: the app, its
bucket and the time. The removal's plan says so in its last step, so the plan
digest covers it. The bucket and every backup in it stay for 30 days, which is
long enough to notice a mistake and restore, and are then deleted by the
nightly sweep, every file version and then the bucket.

```sh
helios storage              # shows the bucket with its expiry date
helios storage keep <app>   # cancel the expiry; the bucket stays
helios storage purge <app>  # delete it now
```

`purge` shows its plan and digest like every destructive command, and takes
`--plan`, `--yes` and `--digest`. Deploying an app of the same name again
clears its tombstone: the bucket is in use.

**Only a bucket this machine tombstoned through `helios remove` is ever
deleted**, by the sweep or by `purge`. `helios storage keep` and `helios
storage purge` refuse any other name.

A tombstone only says this machine gave the app up. Two machines can share
one account and prefix and each run an app of the same name, and the bucket
then holds the other machine's backups. So before a bucket is deleted every
file in it is listed, and **every snapshot in it must be one this machine
recorded making**: a backup, the capture a move takes, or a release
checkpoint. The record of an app's backup runs is kept after the app is
removed. A drill or a restore does not count, because it reads a snapshot
that anyone may have made.

Nor does the history a machine recovery brings with it. `helios recover`
copies the source machine's backup runs into this machine's state, and they
stay that machine's record. Until the source's snapshots have aged
out of a repository, the bucket of an app removed on the recovered machine is
held, and deleting it is done at the storage provider. A machine that
imported a recovery before this rule existed cannot tell which of its runs
came with the import, so it counts none from before its last import.

The snapshots are read from the bucket's own listing, not through restic. A
repository sits at the root of its bucket and keeps one file for each
snapshot under `snapshots/`, named by the snapshot's id, so the listing
cannot leave one out. It also still answers for a bucket whose deletion
stopped part way: unfinished uploads are cancelled first and the files are
then deleted in the order of their names, which takes the repository's
`config` first and its snapshots last, so the next attempt finds the same
snapshots and carries on. Every file is checked a second time as it is
deleted, and a snapshot that turns up in between stops the deletion there. A
backup that recorded its snapshot by a short id, as some releases did, owns
the snapshot that id begins.

The sweep makes the same check every night while a bucket waits, so one that
will not pass says so on the first night and not on the thirtieth.

A deletion that stops part way is carried on by the next sweep when the
bucket's 30 days are up. A `purge` ahead of them that stops is not: the sweep
has no say over a bucket that is not due, so it reports that the repository's
`config` is gone and what is left can no longer be restored, every night,
until `helios storage purge <app>` is run again or the 30 days end.

Neither the sweep nor `purge` deletes anything, and the sweep raises
`host:storage-expiry`, when any of these holds:

- the bucket holds a snapshot this machine has no record of making, it holds
  files but no snapshot at all, or this machine has no record of a backup of
  the app. A backup here that failed after it wrote its snapshot leaves such
  a snapshot too, until retention forgets it;
- something was uploaded to the bucket more than an hour after the app was
  removed, so another machine or tool is using it;
- the app is deployed on this machine again;
- the storage integration now reaches a different account, or a different
  bucket prefix, than the one the app was removed from;
- the storage answered a deletion with an error, such as a key that may not
  delete buckets, or the deletion ran out of time.

When the account's buckets cannot be listed, or the state store cannot be
read, the sweep fails before anything is deleted, and that raises
`host:storage-sweep`. When the files of a bucket that is still waiting cannot
be listed, the bucket is left as it was recorded and read again the next
night. A bucket that is due and cannot be listed is held like any other
deletion that failed.

No tombstone is recorded when:

- storage is not set, or this machine never recorded a snapshot of the app.
  That the app keeps data is not enough: a machine that never backed the app
  up has nothing in the bucket;
- the removal only clears what an already removed app left behind
  (`helios remove <app> --data` for an app that is no longer on the machine);
- the app has a move on record. A moved app's bucket is the one its new
  machine backs up to, so it is listed with the buckets this machine does not
  own and can be neither purged nor expired from here. Deploying the app on
  this machine again clears that mark like any other tombstone; a later
  removal then expires the bucket only if every snapshot in it is this
  machine's, as above.

## The weekly full prune

Every backup forgets old snapshots and then prunes. That prune rewrites at
most 2 GB, so a backup stays short. A repository with more than that to
reclaim never caught up.

Once a week per repository, the prune after a backup runs without that cap.
The state store records when it was last attempted, so a week in which no
backup ran catches up at the next backup, and a repository that has never had
one gets it at its next backup. Attempts count, not completions: a full prune
that runs out of time is not tried again the same night.

The full prune has the same one hour limit as the capped one. One that is
stopped at its limit leaves the snapshot in place and the backup counted as
good, with "retention deferred" in `helios backups`, and `restic unlock`
before the next backup clears the lock it left once restic considers it stale.
Three full prunes in a row that start and do not finish raise an alert for the
bucket: that repository needs a prune run by hand with more time.

## Release checkpoints

A release checkpoint is exempt from retention only while a rollback could
still restore it. See
[release safety](release-safety.md#when-a-checkpoint-expires) for the rule.

## What the storage key must be allowed to do

The sweep uses the storage integration's own credentials, and needs more of
them than backups do.

| Store | Needed |
|---|---|
| Backblaze B2 | `listBuckets`, `listFiles`, `deleteFiles`, `deleteBuckets`, on a key not restricted to one bucket |
| S3 | list all buckets, list object versions and multipart uploads, delete object versions, abort multipart uploads, delete bucket |

A key that may list but not delete still gives the report and the growth
alert. The sweep then holds each expired bucket and says so in
`host:storage-expiry`.
