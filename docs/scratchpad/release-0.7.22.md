# Helios 0.7.22

This patch keeps the nightly machine backup from failing after an app deploy.
Since 0.7.19 the machine backup refuses an app whose newest data backup
predates its active revision. An app deployed after its own backup hour
therefore failed that night's machine backup. Office backs up at 04:00, after
the 03:30 machine backup, and its release flow backs up before it deploys, so
every day with an office release failed. On personal-vps no machine backup
succeeded from 27 October to 3 November 2026.

- When the machine backup is due, the scheduler first backs up each app that
  has no backup started since its active revision, then runs the machine
  backup as before.
- A catch-up backup that fails counts as that app's attempt. It is not retried
  on every tick; the machine backup then reports the app as before, and the
  app's own schedule runs as usual.
- A manual `helios backup helios` still refuses such an app and says which
  backup to run.

Plan step text is unchanged, so plan digests and resumed operations still
match. No new production dependency, database schema migration, data
relocation or application redeployment is included.

## Upgrade preparation

0.7.21 to 0.7.22 does not cross a lock-path boundary. Only `internal/daemon`'s
scheduler changed. `internal/api`, `internal/cli`, `internal/version`,
`internal/state` and `internal/kernel` are unchanged.

The coordinated live target is **personal-vps**. Capture
`helios upgrade --version 0.7.22 --plan`, inspect its candidate identity and all
steps, then apply only that plan's exact `--digest`. The next 03:30 UTC machine
backup should succeed even when an app was deployed that day.

## Verification and publication

A new scheduler test fails against 0.7.21's code. It covers three checks:

- With a machine backup due, an app deployed after its last backup is backed
  up first.
- With no machine backup due, the app waits for its own hour.
- A failed catch-up is not retried on the next tick.

A mutation check that drops the attempt guard fails the retry assertion. The
merged source passes `make check`. On macOS that needs a short `TMPDIR`,
because the socket test's lane temp path exceeds the Unix socket path limit.

Artifacts come from `scripts/build-release.sh` on the clean tagged commit, and
`SHA256SUMS.sig` is signed by the pinned release key. The exact assets are
uploaded and verified before the release is published.
