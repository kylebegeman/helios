# Release rehearsal and data-safe rollback

A release workload can write to a database or volume before a deployment fails.
Stopping its container does not undo those writes. Helios records that boundary,
tests candidates against isolated restored data, and refuses to run older code
against data whose compatibility is unknown.

## Rehearse a candidate

```sh
helios rehearse ./candidate --snapshot <snapshot-id> --plan
helios rehearse ./candidate --snapshot <snapshot-id> --yes
```

The app must already be deployed and have backed-up data. Omitting `--snapshot`
selects the latest backup when the rehearsal begins. An explicit ID can be an
unambiguous hexadecimal prefix of at least eight characters. The proof records
the full identity actually restored.

Helios captures the candidate's source bytes and permission modes. The source
hash is part of the approved plan digest, and a source change after planning
refuses execution. Source trees must contain plain files and directories;
symlinks and devices are refused.

The rehearsal uses a separate encrypted secret store with the active revision's
pinned credentials. Generated and derived candidate secrets stay in that store.
It restores data to uniquely named scratch volumes, builds or pulls the candidate
images, pins image digests, runs release workloads in declared order, starts
long-running workloads and runs direct application checks. The scratch network
is internal, direct checks refuse redirects outside the container's origin, and
no host ports, public routes or cron schedules are activated. Privileged workloads
are refused because they could escape those constraints.

All scratch containers, volumes, networks, copied source, keys and secrets are
removed on success or failure. Interrupted operations compensate by removing the
same resources. A cleanup failure makes the proof fail.

A credential-free JSON proof lives at
`<state-dir>/rehearsals/<app>/<candidate-revision>.json`. It records source and
manifest hashes, the active revision, exact snapshot, workload image digests,
completed release jobs, outcome and times. Read it locally or through a named target with
`helios rehearse report <app> <candidate-revision>`; `--json` returns the full proof.
A successful result proves that
combination. Public edge checks are deferred until real deployment, and a later
snapshot or rebuild can differ from what was tested.

## Declare the data compatibility contract

```yaml
release:
  data_compatibility: backward-compatible
workloads:
  migrate:
    kind: release
    image: ghcr.io/example/app:2
    command: [app, migrate]
```

Use `backward-compatible` only when the release's data changes allow the older
revision to keep reading and writing safely. An additive migration that retains
the old columns is one common example.

Use `restore-required` when running older code requires reverting the app's data.
Omitting the policy means `unknown`, which has the same conservative rollback
behavior. Helios does not infer reverse SQL or assume failed release jobs made
no changes.

Before an unknown or restore-required release against an existing data app,
Helios captures a quiesced checkpoint of the active revision. Storage must be
configured and capture must succeed before any release job runs. The checkpoint
is tagged `bedrock-release-checkpoint` and backup retention leaves it alone
for as long as a rollback could restore it; see
[when a checkpoint expires](#when-a-checkpoint-expires). Garbage collection
also keeps the prior revision record and its workload images while a
checkpoint has not been restored, even beyond the ordinary five retired
revisions. This preserves the code needed for an explicit data rollback after
later deployments. Once restoration completes, ordinary active and previous
revision retention applies again.

The exact checkpoint and prior revision are persisted before release execution.
The release boundary then transitions from prepared to started to completed or
failed. Failed candidates are included even when they never became active. If
execution is interrupted, jobs are not replayed automatically: inspect the
recorded jobs and create a new candidate or restore the retained checkpoint.
A completed release step is safely skipped on operation recovery.

## Roll back with the matching data

Declared backward-compatible transitions permit ordinary code rollback:

```sh
helios rollback my-app --to <older-revision> --plan
helios rollback my-app --to <older-revision> --yes
```

Unknown or restore-required transitions refuse code-only rollback. The error
names the attempted release and its exact checkpoint. This applies to automatic
failure recovery too: Helios does not restart stopped singletons or switch the
edge back to incompatible older code.

To explicitly replace live data with the retained pre-release checkpoint:

```sh
helios rollback my-app --restore-data <full-64-character-checkpoint> --plan
helios rollback my-app --restore-data <full-64-character-checkpoint> --yes
```

The checkpoint pins its previous revision, so `--to` is optional. If
supplied, it must name that same revision. The snapshot's manifest is checked
against the target before live data is touched.

A checkpoint can be named for 30 days after its release began, once the
release has completed; see [the rollback horizon](#the-rollback-horizon).

**Restoring discards database and volume writes made since that checkpoint.**
Helios persists a writer fence, removes the app's containers, replaces its data,
restores its original current secrets as a new secret version, and only then
starts and checks the older code. Revision history, retained images and all
prior secret versions survive. Older release workloads are never rerun.

Jobs and interactive commands for the app remain blocked while restoration is
incomplete. Integration changes also wait, preserving shared recovery credentials.
Read-only reports remain available.
After a daemon or host restart, surviving container restart policies cannot
revive the app. Retrying the same rollback restores the same checkpoint and
clears any partially restored data before retrying. A completed restoration is
idempotent while no later unsafe data release has occurred. If a later release
changes data incompatibly, the previously restored checkpoint cannot be reused
to skip restoration; Helios names the newer checkpoint to review. Restoring a
checkpoint also discards every later release's data changes, so the
checkpoints of those later releases are marked restored without having been
restored. A rollback that names one of them is refused: the data is now older
than that checkpoint, and a rollback does not move it forward. Other apps
remain active.
Releases predating boundary recording with unknown data compatibility are also
refused for code-only rollback; recover through a separately verified backup
when no retained pre-release checkpoint exists.

## When a checkpoint expires

One thing reads a release checkpoint: `helios rollback --restore-data`. A
rollback accepts a checkpoint only when a release boundary of the app records
exactly that snapshot together with the revision to return to, and it restores
the snapshot only while that boundary is not yet marked restored. Retention
follows the same test. **A checkpoint is exempt from retention for as long as
a rollback could still restore it.**

A checkpoint loses the exemption in exactly three cases:

1. Every boundary that records it is restored. The data was put back to that
   checkpoint or an earlier one. A rollback that names it again is refused
   when a later release changed data again or when it was an earlier
   checkpoint that was restored, and otherwise succeeds without reading the
   snapshot.
2. No boundary records it and this machine's backup history shows that this
   machine took it. That is the checkpoint of an app that was removed:
   removal deletes the app's boundaries, and a rollback finds a checkpoint
   only through a boundary. It is also the checkpoint of a release that
   failed before its boundary could be written, once that attempt has ended.
3. Its release's jobs finished and the release began more than 30 days
   ago, plus a day. See [the rollback horizon](#the-rollback-horizon).

Everything else stays exempt, and when in doubt a checkpoint is kept:

- The checkpoint of a release whose jobs failed, or that is prepared,
  started or being restored, stays however old it is. Only a release whose
  jobs finished ages. That is the status `completed`, which a release has
  from then on even when its new code went on to fail its start.
- A checkpoint that a later data-changing release makes a rollback refuse
  today stays, because the refusal lifts once the later release is restored.
- A checkpoint this machine has no record of stays, because another machine
  backing up to the same bucket may hold its boundary.
- When the boundaries or the backup history cannot be read, every checkpoint
  stays, and `helios backups` shows retention deferred with that reason.

Losing the exemption deletes nothing by itself. The checkpoint becomes an
ordinary snapshot: the app's `backup.keep` policy holds it while it is the
newest of its day, week or month, and forgets it when it is not. Its space
comes back with the prune that follows.

### The rollback horizon

A release whose jobs finished can be undone by restoring data for 30 days,
counted from when the release began. After that `helios rollback
--restore-data` refuses its checkpoint: restoring it would discard a month or
more of writes, which is a recovery from a backup and not a rollback.
Retention goes on protecting the checkpoint for one more day, so a rollback
planned just inside the horizon never reads a snapshot that retention is free
to drop. Garbage collection holds the revision the checkpoint returns to for
exactly as long.

Without the horizon an app that ships data-changing releases and never
restores one keeps one checkpoint per release for good.

What the horizon means for a rollback depends on the release:

- A release declared `backward-compatible` takes no checkpoint and is rolled
  back by code alone, at any age.
- A `restore-required` or `unknown` release cannot be rolled back by code
  alone at any age. `unknown` is what a manifest without the policy gets.
  Inside the horizon the rollback names the checkpoint to restore. Past it,
  the data from before that release is out of a rollback's reach, and
  `helios rollback` says so. When a later release still has a checkpoint
  inside the horizon it names that one and the revision it returns to, which
  is as far back as a rollback goes. Further back is a recovery from a
  separately verified backup.

The horizon is fixed. It is not a setting.
