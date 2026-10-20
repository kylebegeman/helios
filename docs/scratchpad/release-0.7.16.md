# Helios 0.7.16

This patch is the first signed release. It also lets a Cloudflare-proxied host
take only Cloudflare's connections, and makes a machine backup check its space
before it copies anything.

- **Signed releases** ([PR #16](https://github.com/kylebegeman/helios/pull/16)).
  `helios upgrade --version`, host bootstrap's download and
  `scripts/install-release.sh` trust a release's `SHA256SUMS` only when
  `SHA256SUMS.sig` is an SSH signature for the `helios-release` namespace, made by
  the Ed25519 release key pinned in the build
  (`SHA256:/63CRHxNsgYsxKBVy3TSHuIVNnY4y+y/Rx9w3bH0xnY`). A checksum pinned from
  reviewed source (`--sha256`, `HELIOS_SHA256`, a bootstrap profile) still
  vouches for a build alone, so 0.7.15 and earlier still install. The upgrade
  plan, its digest and the receipt name the signer. The target advertises
  `release.signed.v1`.
- **Cloudflare origin pull** ([PR #22](https://github.com/kylebegeman/helios/pull/22)).
  `origin_pull: optional|required` on a proxied route, with
  `helios edge origin-pull mint|trust|list|forget`. A required host refuses at
  the TLS handshake any connection without a certificate from a CA the machine
  trusts for it. Deploys, checks, rollbacks, moves and recovery cutovers refuse to
  leave a required host without one. The watch warns 30 days before a trusted CA
  runs out. Needs Caddy 2.8.0 or later; both hosts run 2.11.4. The target
  advertises `edge.origin-pull.v1`.
- **Escalation is told once it holds** ([PR #20](https://github.com/kylebegeman/helios/pull/20),
  [PR #21](https://github.com/kylebegeman/helios/pull/21)). An open warning that
  becomes an outage is told in the round it has held for three rounds, not at
  the next daily repeat. Easing back has to hold as long as a recovery, so a
  flapping outage stays one outage.
- **Host papercuts** ([PR #23](https://github.com/kylebegeman/helios/pull/23)).
  - The daemon gives `/etc/bedrock` the bedrock group with a group digit of 1 at
    start, as `helios host reconcile` does.
  - `helios upgrade` follows its operation across the daemon restart, for up to
    3 minutes, instead of exiting 1 on `canceled`.
  - `helios psql app < dump.sql` asks docker for a terminal only when stdin is
    one.
  - **Behaviour change:** `helios exec` attaches stdin only with
    `-i/--interactive` or when stdin is a terminal. Piped input now needs `-i`,
    for example
    `helios exec site -i -- sh -c 'cat > /data/import.csv' < import.csv`. The target
    advertises `exec.interactive.v1`. A client older than 0.7.16 that runs
    `exec` through `--target` on a 0.7.16 host sends no stdin.
- **Machine backup checks its space first** ([PR #24](https://github.com/kylebegeman/helios/pull/24)).
  Before it copies any app data, a machine backup adds up the pinned snapshots
  and the room saving the workload images takes, and refuses with the shortfall
  unless the total fits with the reserve `helios watch` keeps: 5 GB or a tenth
  of the disk, whichever is larger. Drills, rehearsals and restores keep the
  same tenth. Images count as the compressed content the containerd image store
  saves, not the unpacked size `docker image ls` shows; a graph driver store
  counts twice the reported size, for the copy it makes under Docker's data
  directory. A backup that fails removes what it staged unless it will resume,
  after stopping any restic helper still reading it. A backup's or a move
  capture's run now ends with the operation that began it, including when
  Recover ends that operation instead of resuming it. `helios watch` warns
  `host:machine-backup` when the last good machine backup is 36 hours old.

## Release verification

PR #24 merged at `24c031520190197eac9cccf6c6adbbfbc58da659`, after PRs #20
(`f25d0b3`), #16 (`2c9eea4`), #21 (`09281a7`), #22 (`f5378d1`) and #23
(`0816ff0`). Each PR's CI and the
[merged-commit CI](https://github.com/kylebegeman/helios/actions/runs/39488385929)
passed the code/build checks and the disposable Linux daemon-recovery proof. On
a disposable Ubuntu 24.04.5 ARM64 lane VM (git 2.43.0, OpenSSH 9.6p1), lane
proofs `m2`, `signed` and `originpull` passed at that commit.

The standard build script produced static Linux and macOS AMD64/ARM64 binaries
from that clean merge. The Linux binaries carry `vcs.revision` 24c0315 with
`vcs.modified=false`, and the macOS ARM64 build prints
`helios 0.7.16 (24c031520190, go1.27.1 darwin/arm64)`. All four legacy copies
are byte-identical. `SHA256SUMS.sig` is an SSH signature in the
`helios-release` namespace by the pinned release key
(`SHA256:/63CRHxNsgYsxKBVy3TSHuIVNnY4y+y/Rx9w3bH0xnY`), checked with
`ssh-keygen -Y verify` against `release/allowed_signers`. All ten draft assets
were downloaded and matched against local SHA-256 values and GitHub asset
digests before [v0.7.16](https://github.com/kylebegeman/helios/releases/tag/v0.7.16)
was published. The published tag resolves to the merge commit, and the asset
digests and the signature were verified again after publication.

| Asset | SHA-256 |
|---|---|
| `helios_0.7.16_linux_amd64` | `30692ac513c398a5d207f99ee346c6a5cbce92c6f43aedf92b91776507e20f87` |
| `helios_0.7.16_linux_arm64` | `e8e413eedb7f58069615ea73ad89226c4ed112cb401da1b8bedd989c31175522` |
| `helios_0.7.16_darwin_amd64` | `a99b16240d5fdd8367567d81ae121fd59380bc34de0a5ecc0f3ba201779efd84` |
| `helios_0.7.16_darwin_arm64` | `d05f1d1ddb49263fdb5f6af69bf3cdf92da74c8005ffa401ecde22aaae1e43ae` |

## Rollout

Pending. Kyle upgrades the hosts. personal-vps is upgraded on 21 October
outside 02:55 to 05:00 UTC, once no operation is in flight. This is
the last upgrade that leans on the pinned checksum alone: the running 0.7.15
upgrader doesn't check `SHA256SUMS.sig`. Each host uses the published platform
checksum and a fresh inspected plan:

```sh
helios upgrade --version 0.7.16 --sha256 <platform-checksum> --plan
helios upgrade --version 0.7.16 --sha256 <platform-checksum> --digest <plan-digest>
helios version
stat -c "%a %U:%G %n" /etc/bedrock /etc/bedrock/git
```

The host's 0.7.15 client can still exit 1 with `canceled` as the daemon
restarts, since following the operation across the restart is new in the
0.7.16 client. Check `helios version` and the operation's receipt rather than
re-running it. The restarted daemon makes `/etc/bedrock` root:bedrock with a
group digit of 1.

- Machine backup now keeps 10% of the disk free, as drills and rehearsals do,
  and checks pins plus images before copying. On personal-vps that is 19.27 GiB
  of 192.69 GiB. Library rollout 73 (op-20261020-172822-2lodu) left
  library-backups out of backups with IA-09 step 2's `backup: false`. Counting
  every image at its full reported size, the 22 October machine backup needs at
  most 36.0 GiB (pins 9.46, images 7.2 and 0.1, and 19.27 for the tenth)
  against 42.8 GiB free on 20 October after that rollout. A refusal names the
  shortfall and leaves nothing staged.
- `host:machine-backup` starts warning 36 hours after the last good machine
  backup.
- `origin_pull` stays off until a route sets it. Before setting `required`,
  run `helios edge origin-pull trust` for the zone's CA and turn on
  Authenticated Origin Pulls in Cloudflare.
- Piped `helios exec` input needs `-i` from now on.

No state/schema or upgrade-plan migration is included. A downgrade needs a new
inspected upgrade plan using the published 0.7.15 checksum. It refuses while
an app's active revision sets `origin_pull`, since 0.7.15 would read it as
nothing and stop checking Cloudflare's certificate, so deploy those apps
without it first. See
[compatibility and upgrades](../features/compatibility.md).

Credit op-20261020-033043-qo3q4 (personal-vps, 20 October) for the machine
backup preflight.
