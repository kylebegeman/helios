# Helios 0.7.17

Helios 0.7.17 forecasts when a disk fills, lets the machines that run Helios
watch each other, and opens a Loom thread with the evidence for each critical
incident.

- **Disk forecast** ([PR #26](https://github.com/kylebegeman/helios/pull/26)).
  `helios watch` keeps the hourly use of the root filesystem for 90 days and
  each minute of the last 6 hours, and forecasts when it fills.
  `host:disk-forecast` warns when the 7 day trend fills the disk within 14 days
  and is critical within 48 hours. It is also critical when the 6 hour trend
  fills it within 6 hours while usage still climbs, as a runaway log does. A
  cleanup, a one-off download or a passing temp file is set aside. The alert
  says how fast the disk fills and which app's data grew most. **Behaviour
  change:** a disk with under 10% free is critical until there are 2 days of
  hourly samples, then a warning while the 7 day trend lasts beyond 14 days or
  isn't growing. The 5 GB floor stays critical.
- **Peer watch** ([PR #27](https://github.com/kylebegeman/helios/pull/27)).
  `helios peer init|add|rm|ls|key|observe`. Every minute each server looks at
  each peer three ways: a signed summary over the mesh, its edge over the mesh,
  and its public URLs. One healthy machine pages for the rest. A peer that
  answers none of the three is critical once most of the machines watching it
  agree. A Mac can add its own view with `helios peer observe --install`; it
  never pages. See `docs/features/peer-watch.md`. Nothing changes until `helios
  peer init` is run.
- **Incident evidence and Loom threads** ([PR
  #28](https://github.com/kylebegeman/helios/pull/28)). `helios host setup`
  keeps two weeks of app and job logs in the journal, so `helios logs
  --revision` reads a retired revision's logs and `helios logs --job` a finished
  run's. Each critical incident's evidence is collected and redacted: logs,
  history, the change before it and its checks. `helios alerts show <id>
  --evidence` shows it, and `helios alerts review <id>` prints a blameless
  timeline. With `helios integration set loom_webhook`, the first critical
  notice of each incident opens a Loom thread through a signed scheduled-task
  webhook. The target advertises `incidents.evidence.v1`. Running containers
  move to the journal on their next deploy after `helios host setup`.

No state migration, production dependency, data relocation or application
redeployment is required.

Upgrade from 0.7.16 with `helios upgrade --version 0.7.17 --plan`, inspect the
plan, and apply its exact `--digest`. The 0.7.16 upgrader checks
`SHA256SUMS.sig` itself. A downgrade to 0.7.16 needs a new inspected plan.

## Release verification

PR #28 merged at `e7fc16b540a1daf3e065d1b63a4581115ea66dc9`, after PRs #26
(`f789a5a`) and #27 (`d68a75d`). Each PR's CI and the
[merged-commit
CI](https://github.com/kylebegeman/helios/actions/runs/39524509051)
passed the code/build checks and the disposable Linux daemon-recovery proof.
`make check` and lane proofs `m2`, `peer` and `journald` on a disposable
Ubuntu 24.04 ARM64 lane VM passed at `97efe5e`, whose tree is identical to
the merge commit's.

The standard build script produced static Linux and macOS AMD64/ARM64 binaries
from that clean merge. They carry `vcs.revision` e7fc16b with
`vcs.modified=false`, and the macOS ARM64 build prints
`helios 0.7.17 (e7fc16b540a1, go1.27.1 darwin/arm64)`. All four legacy copies
are byte-identical. `SHA256SUMS.sig` is an SSH signature in the
`helios-release` namespace by the pinned release key
(`SHA256:/63CRHxNsgYsxKBVy3TSHuIVNnY4y+y/Rx9w3bH0xnY`), checked with
`ssh-keygen -Y verify` against `release/allowed_signers`. All ten draft assets
were downloaded and matched against local SHA-256 values and GitHub asset
digests before
[v0.7.17](https://github.com/kylebegeman/helios/releases/tag/v0.7.17)
was published on 21 October 2026 at 01:47 UTC. The published tag resolves to
the merge commit, and the asset digests and the signature were verified again
after publication.

| Asset | SHA-256 |
|---|---|
| `helios_0.7.17_linux_amd64` | `5c7ef446539fe8995e7f3d77249cc323d3140e745509d9522f97fd38f4ee66fb` |
| `helios_0.7.17_linux_arm64` | `395d4535df306f9fbe6e356fd5cd3ac13ca2e995e5e0aa016b8f3362e2fce143` |
| `helios_0.7.17_darwin_amd64` | `b06d533cc2e8853f5f5ad658cf79252aaeb2550db24f78b7c490a97c9c26733d` |
| `helios_0.7.17_darwin_arm64` | `89d496a8db1c6ee5f29e222aa4cd1adc4ad16e68f9fd77a6ad9b4e16989a11da` |
