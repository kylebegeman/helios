# Helios 0.7.13

This patch reduces recurring metrics processing and deployment planning costs.
The [performance guide](../technical/performance.md) documents 71 benchmark
cases, and the [results](../technical/performance/results/2026-10-17/report.md)
retain the baseline, two optimization sweeps, alternating comparisons, profiles
and measurement limits. Eight representative targets meet the documented
runtime or allocation threshold. Generated SMTP fallback and Message-ID text
also use Helios; the saved email integration continues to control the sender.

## Release verification

[PR #10](https://github.com/kylebegeman/helios/pull/10) merged at
`ed83229ba3dea8a05d92b373df87c40d242c806c`. Both PR CI and the
[merged-commit CI](https://github.com/kylebegeman/helios/actions/runs/39065015011)
passed the code/build checks, all 71 benchmark fixtures and the disposable Linux
daemon-recovery proof.

The standard build script produced static Linux and macOS AMD64/ARM64 binaries
from that clean merge, with the exact VCS revision and release version. All
four legacy copies are byte-identical. All nine draft assets were downloaded
and matched against local SHA-256 values and GitHub asset digests before
[v0.7.13](https://github.com/kylebegeman/helios/releases/tag/v0.7.13) was published.
The published tag and asset digests were verified again after publication.

## Rollout

Both live hosts upgraded sequentially from checksum-verified 0.7.12 binaries.
Each upgrade used the published platform checksum and a fresh inspected plan
with an exact digest. Both saved receipts resumed after the daemon restart and
completed all four steps. CLI and daemon API versions match the release commit;
state checkpoints and previous binaries are retained, staged markers are gone,
and operation locks are free.

All current apps remain healthy with their original revisions and running
container identities. Both live edge configurations have the same canonical
hash as before the upgrade, HTTPS probes retain their prior responses, and a
subsequent sampling round advanced for every app. No new alerts appeared. One
host's pre-existing critical disk-capacity alert remains an operator followup;
its available space was checked before staging. Private host snapshots,
receipts, hashes and journals are retained in the ignored rollout evidence
folder rather than committed.

No state/schema or upgrade-plan migration is included. The existing upgrade
workflow retains a consistent state checkpoint and previous binary. After
successful verification, a later downgrade requires a new inspected upgrade
plan using the published 0.7.12 checksum; the checkpoint is not automatically
restored. See [compatibility and upgrades](../features/compatibility.md).

These rollout checks establish operational health. They do not add production
latency, peak RSS or Linux performance measurements to the local benchmark
results.
