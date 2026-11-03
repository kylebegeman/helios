# Helios 0.7.21

This patch makes the daily collection (`app.gc`) reclaim what it was leaving
behind. On personal-vps the root disk reached 9% free on 3 November 2026
(incident 58), although every nightly collection had reported success.

- **Build cache.** Both prune passes now take `--all`. Without it BuildKit skips
  every record whose layers an image also holds. On the containerd image store
  that was 56 of 62.5 GB, and the previous night's collection freed 224 MB. The
  ceiling pass uses `--max-used-space`, because `--reserved-space` is a floor.
  A daemon too old for that flag still answers to `--keep-storage`.
- **Images.** Forgetting a revision now removes the images it records, including
  ones Helios pulled or that were deployed by digest without Helios building
  them. An image stays when a revision that remains on record records it, when
  any container (running or stopped, Helios's or not) uses it, or when it is
  kept for rollback. Images go before their revision is forgotten, so a resumed
  run retries them. Removal is never forced.
- **Local registry.** A new `registry` step after `forget` deletes tags in
  Helios's `<app>/<workload>` repositories that meet both conditions: the tag's
  revision is no longer on record, and no revision on record records its digest.
  It then runs `registry garbage-collect` and restarts the registry.
  - It does not pass `--delete-untagged`, because that flag destroyed an image
    that was pushed by hand and deployed by digest.
  - The restart is required. Without it, the registry's in-memory blob cache
    lets the next push skip layers that were just deleted, and the stored image
    can no longer be pulled.

Plan step text changed for `app.gc` only. The forget step describes image
removal and the plan gains the registry step, so GC plan digests differ from
0.7.20's. No other plan changes. No new production dependency, database schema
migration, data relocation or application redeployment is included.

## What still leaks

- Images that revisions forgotten before this release recorded have no record
  left, so this release does not collect them. On personal-vps they were removed
  by hand on 3 November 2026. Registry tags of those revisions are collected,
  because the registry step checks every revision-shaped tag.
- Release rehearsal tags (`rehearse-<rev>`), repositories of removed apps, and
  images of removed apps that Helios did not build. App removal still removes
  only the images Helios built.
- A completed release boundary keeps its previous revision indefinitely.

## Upgrade preparation

0.7.20 to 0.7.21 does not cross a lock-path boundary. `internal/api`,
`internal/cli`, `internal/version`, `internal/state` and `internal/kernel` are
unchanged since 0.7.20.

The coordinated live target is **personal-vps**. Capture
`helios upgrade --version 0.7.21 --plan`, inspect its candidate identity and all
steps, then apply only that plan's exact `--digest`. Afterwards, run
`helios gc --plan` and apply its digest. Expect the first run to print
`deleted <repo>:<tag>` for registry tags of forgotten revisions, then the
storage it reclaimed.

## Verification and publication

Each fix has a regression test that fails against 0.7.20's code for the leak's
own reason:

- The build cache test fails on a prune without `--all`.
- The image tests fail because a forgotten revision's pulled image is left
  behind.
- The registry tests fail because forgotten revisions' tags remain.

Mutation checks show that the image guard depends on both the remaining
revisions and the container check.

Two probes ran against real software on a Mac:

- **Docker Desktop 29.8, containerd store.** A removal stops with a conflict
  while a container uses the image, and the recorded reference still resolves.
  Repeating a removal is safe.
- **registry:3.1.1.** Images were pushed with the attestation manifests
  production has. The probe confirmed the delete semantics and the
  garbage-collect variants, and showed that the restart is needed.

The merged source passes `make check`. On macOS that needs a short `TMPDIR`,
because the socket test's lane temp path exceeds the Unix socket path limit.

Artifacts come from `scripts/build-release.sh` on the clean tagged commit, and
`SHA256SUMS.sig` is signed by the pinned release key. The exact assets are
uploaded and verified before the release is published.
