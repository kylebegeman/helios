# Helios 0.7.15

This patch sends every alert every way at once and reaches a phone, and lets an
app deploy only commits signed by a key the machine allows.

- **Fan-out alerts** ([PR #15](https://github.com/kylebegeman/helios/pull/15)).
  A notice goes to every configured leg in parallel. Email goes through `email`,
  and through `email2` only when the first mail server fails. Pushover or ntfy
  reaches a phone, and a critical incident rings through Pushover every minute
  until acknowledged, for up to an hour. A leg that missed is retried alone, with
  the wait growing from 1 minute to 15. `helios alerts test` reports each leg and
  takes `--leg`. The daemon runs it every Monday at 09:15 UTC, and a failed leg
  opens a `host:alerts` warning that the other legs deliver. A writer paused for
  a backup is a critical incident once the pause passes 35 minutes.
- **Signed deploys** ([PR #17](https://github.com/kylebegeman/helios/pull/17)).
  `helios git signers add|remove|list` keeps an OpenSSH allowed signers file in
  `/etc/bedrock/git`, and `helios git require-signed <app>` holds that app's
  pushed and webhook-fetched tips to it. The machine's own git and OpenSSH check
  the tip before anything is exported. Unsigned commits, unknown keys, GPG and
  X.509 signatures, other namespaces, keys outside their valid dates, pushed
  replace refs and uploaded trees are refused. The receipt names the signer. The
  daemon and `helios host reconcile` give `/etc/bedrock` the group bedrock with
  group bits `--x`, and make `/etc/bedrock/git` 750 root:bedrock. The target
  advertises `git.signed.v1`.
- **`helios ls --json`** lists a machine with no apps as `"apps": []` instead of
  `null` (also PR #17).

[PR #18](https://github.com/kylebegeman/helios/pull/18) changed only the lane
tooling: each lane VM gets its own Docker network, so SSH survives host setup.

## Release verification

PR #17 merged at `9373ce4645b4d856d905d3873387c93033d6ff5e`, after PRs #15
(`19e9220`) and #18 (`d842bf5`). Each PR's CI and the
[merged-commit CI](https://github.com/kylebegeman/helios/actions/runs/39408774220)
passed the code/build checks and the disposable Linux daemon-recovery proof. On
a disposable Ubuntu 24.04.5 ARM64 lane VM (git 2.43.0, OpenSSH 9.6p1), lane
proofs `m2` and `signed` passed.

The standard build script produced static Linux and macOS AMD64/ARM64 binaries
from that clean merge. The Linux binaries carry `vcs.revision` 9373ce4 with
`vcs.modified=false`, and the macOS ARM64 build prints
`helios 0.7.15 (9373ce4645b4, go1.27.1 darwin/arm64)`. All four legacy copies
are byte-identical. All nine draft assets were downloaded and matched against
local SHA-256 values and GitHub asset digests before
[v0.7.15](https://github.com/kylebegeman/helios/releases/tag/v0.7.15) was
published. The published tag resolves to the merge commit, and the asset
digests were verified again after publication.

| Asset | SHA-256 |
|---|---|
| `helios_0.7.15_linux_amd64` | `9d9673a9a674818f89335bd65bf38726527efbd958873078d36f8e5bd779ec6c` |
| `helios_0.7.15_linux_arm64` | `25c80561b7b9041ff3a1c59b24c4976fd2ed2d9623ac9635760c983db53ff8f3` |
| `helios_0.7.15_darwin_amd64` | `38fb5ae1cbba02b6135f63e0a6b1e4248d477dee33d53b5d2577678cc05a94e7` |
| `helios_0.7.15_darwin_arm64` | `b98f86ab154f4f4bdd9b877973a1a823ee6b503df41876ff664064f3c4f48d33` |

`SHA256SUMS` is not signed. Release signing (IA-10) waits for its key and ships
in 0.7.16.

## Rollout

Pending. Kyle upgrades the hosts. personal-vps goes straight to the newest
release before the Library drill at 06:10 UTC on 25 October 2026. Each host uses
the published platform checksum and a fresh inspected plan:

```sh
helios upgrade --version 0.7.15 --sha256 <platform-checksum> --plan
helios upgrade --version 0.7.15 --sha256 <platform-checksum> --digest <plan-digest>
helios version
stat -c "%a %U:%G %n" /etc/bedrock /etc/bedrock/git
```

The restarted daemon makes `/etc/bedrock` root:bedrock with a group digit of 1,
and `/etc/bedrock/git` 750 root:bedrock. Then, per host:

- set `pushover` or `ntfy`, and `email2` if wanted, then run `helios alerts test`
- remove IA-02's `helios-alert-canary.timer` and `.service` if they were
  installed, because the daemon now runs the weekly test
- turn signed deploys on per app with `helios git signers add <name> <key>` and
  `helios git require-signed <app>`, packrat first

No state/schema or upgrade-plan migration is included. Per-leg alert state is
kept in memory, so a daemon restart resends to every leg. `helios recover` and
`helios move` don't carry `/etc/bedrock/git` yet, so the signing commands are
re-run on a new machine after either one. Turn `require-signed` off before
downgrading, because 0.7.14 ignores the policy and would deploy unsigned
commits. A downgrade needs a new inspected upgrade plan using the published
0.7.14 checksum. See [compatibility and upgrades](../features/compatibility.md).
