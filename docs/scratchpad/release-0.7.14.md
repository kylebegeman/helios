# Helios 0.7.14

This patch makes a restore drill refuse a snapshot that can't fit, lets an
operator skip a drill or hold a cron without SSH timing, finishes cron jobs that
outlive their timeout, and lets a data volume stay out of an app's backups.

- **Drill preflight** ([PR #11](https://github.com/kylebegeman/helios/pull/11)).
  Before restoring, a drill checks that the snapshot fits with 5 GB to spare on
  every disk it writes to, counting a 4 KB block per file. After restoring, it
  runs SQLite's integrity check on up to 64 restored databases.
- **Operator holds** ([PR #12](https://github.com/kylebegeman/helios/pull/12)).
  `helios drill <app> --skip-next --reason <text>` skips the next scheduled
  drill, and `helios cron hold` holds a cron workload for at most 14 days.
  A cron container that outlives its timeout now ends its run as timed out even
  when Docker refuses the first removal.
- **Volume backup opt-out** ([PR #13](https://github.com/kylebegeman/helios/pull/13)).
  A data volume marked `backup: false` is left out of the app's snapshots.
  Restore, drill and move create it empty and record that. Decoding is strict,
  so no manifest may use the key until every host that reads it runs 0.7.14.

## Release verification

PR #13 merged at `47768c35d3f8984a803d7deb3217dee5f9c49fc5`, after PRs #11
(`4ca5548`) and #12 (`515f0cf`). Each PR's CI and the
[merged-commit CI](https://github.com/kylebegeman/helios/actions/runs/39379546480)
passed the code/build checks and the disposable Linux daemon-recovery proof.

The standard build script produced static Linux and macOS AMD64/ARM64 binaries
from that clean merge. The Linux binaries carry `vcs.revision` 47768c3 with
`vcs.modified=false`, and the macOS ARM64 build prints
`helios 0.7.14 (47768c35d3f8, go1.27.1 darwin/arm64)`. All four legacy copies
are byte-identical. All nine draft assets were downloaded and matched against
local SHA-256 values and GitHub asset digests before
[v0.7.14](https://github.com/kylebegeman/helios/releases/tag/v0.7.14) was
published. The published tag resolves to the merge commit, and the asset
digests were verified again after publication.

| Asset | SHA-256 |
|---|---|
| `helios_0.7.14_linux_amd64` | `223a1a37ff6f4cca28ff1e31a6161dc513ff8c70f45928132bcb95ec95c7cd9d` |
| `helios_0.7.14_linux_arm64` | `c701509a61d38b2c2ece3428ac19dd635e916449f69aa57a05da7079151a7042` |
| `helios_0.7.14_darwin_amd64` | `f5d6ca8d5673000cfa98b3c4b88e7e7d9723d2fcfe44afbe182b99213f29994e` |
| `helios_0.7.14_darwin_arm64` | `f177901179e6de6bde4c91b62e60045f38d0e564139f76f2202fad42261c7d31` |

## Rollout

Pending. Kyle upgrades the hosts; personal-vps must run 0.7.14 before the
Library drill at 06:10 UTC on 25 October 2026. Each host uses the published
platform checksum and a fresh inspected plan:

```sh
helios upgrade --version 0.7.14 --sha256 <platform-checksum> --plan
helios upgrade --version 0.7.14 --sha256 <platform-checksum> --digest <plan-digest>
helios version
```

No state/schema or upgrade-plan migration is included. Skips and holds are
rows in the existing job and backup run tables. Release any cron hold before
downgrading, because 0.7.13 would read it as a job run. A downgrade needs a new
inspected upgrade plan using the published 0.7.13 checksum. See
[compatibility and upgrades](../features/compatibility.md).
