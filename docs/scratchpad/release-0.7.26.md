# Helios 0.7.26

This patch stops a quiet machine from looking broken to the machines that
watch it.

- A peer judges each of a machine's alert legs by when it last worked, and
  warns once that is more than eight days ago. The summary counted only real
  alert deliveries, so a machine with nothing to report for eight days read as
  having a dead Loom leg, even though the weekly alert test reached Loom every
  Monday. braintreelabs raised this warning (#67) from 2026-11-10. The summary
  now also counts the leg's last passing test, a probe included. A failed test
  never counts.
- The summary no longer lists the frozen source of a finished move among the
  apps owed a backup. The machine's own watch already skipped it; the peer
  view kept reporting its last backup as overdue until the source was removed.
- 0.7.26 also carries per-workload DNS resolvers (`f1a3076`), which personal-vps
  ran as an unreleased 0.7.25 build from 2026-11-12. No 0.7.25 release exists.

No `--json` shape, production dependency, database schema migration, data
relocation or application redeployment changes.

## Upgrade

0.7.24 and the 0.7.25 build to 0.7.26 cross no lock-path boundary. On each live
target, **personal-vps** and **braintreelabs**, capture
`helios upgrade --version 0.7.26 --plan`, inspect it, then apply its exact
`--digest`.

## Verification

The extended `TestSummaryReports` fails against 0.7.24's `internal/peer/summary.go`
on both changes: Pushover's passing test is missing from its legs, and the
fenced `moved` app is listed as owed a backup. The merged source passes
`make check` with a short `TMPDIR`.
