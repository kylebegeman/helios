# Helios 0.7.20

This patch lets the machine backup run when an app with data has `backup.off`.
Since 0.7.19, the machine recovery catalog refused every such machine, because
it required a pinned data backup from any app with data, including one whose
backups are intentionally off. On personal-vps, loom-vault has `backup.off`, so
no machine backup has succeeded since 21 October 2026.

- The machine backup pins no data for an app whose backups are off, leaves it
  out of the free-space precheck and says so in its output. When such an app's
  database has first-run scripts, they are copied into the snapshot and listed
  in the new optional catalog field `app_init`, since an empty database still
  needs them.
- Recovery checks accept such an app without a pin or provenance. Apps whose
  backups are on are checked exactly as before.
- Recovery creates every volume of such an app empty and gives it to its
  workload, restores only its first-run scripts when the snapshot kept them,
  and starts its database empty with no dump restore or verify query.

No new production dependency, database schema migration, data relocation,
application redeployment or replacement storage image is included. Plan step
text is unchanged, so plan digests and resumed operations still match.

## Upgrade preparation

0.7.19 to 0.7.20 does not cross a lock-path boundary. `LockOperations` and
`operationLockPath` are byte-identical to 0.7.19, and `internal/api`,
`internal/cli` and `internal/version` are unchanged, so `--json version` and
`--json ps` keep their shapes. Older builds already refuse a machine snapshot
catalog made by a newer version.

The coordinated live target is **personal-vps only**. Capture
`helios upgrade --version 0.7.20 --plan`, inspect its candidate identity and all
steps, then apply only that plan's exact `--digest`. Afterwards, run
`helios backup helios --plan` and apply its digest. The output should say that
loom-vault's backups are off and the machine backup keeps none of its data.

## Verification and publication

New regression tests cover a machine backup with one backed-up app and one app
with backups off, the first-run scripts of a database with backups off, empty
recovery of such an app, and its volume ownership. Against 0.7.19's code the
backup tests fail with the production error and the recovery tests fail with
"no pinned successful data backup". The merged source passes `make check`
locally. The path that starts an empty Postgres for an app with backups off has
no unit coverage, since the Docker fake has no exec support; it needs a lane
proof or a recovery rehearsal before anyone relies on it.

Artifacts come from `scripts/build-release.sh` on the clean tagged commit, and
`SHA256SUMS.sig` is signed by the pinned release key. The exact assets are
uploaded and verified before the release is published.
