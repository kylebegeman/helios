# Helios 0.7.19

This patch repairs approval, source, ownership, recovery and credential boundaries
across the CLI, daemon and app lifecycle. It retains 0.7.18's alert sender names
while validating and normalizing SMTP envelope addresses.

- Approval digests bind exact one-off argv, revision and extra secret names;
  upgrade approval binds the candidate executable's bytes. Already-switched
  0.7.18 upgrade journals finish restart and verification under their original
  approval; unfinished legacy switches remain refused.
- App cleanup preserves foreign resources and scratch data whose writers could
  not be stopped. Move and recovery retries retain reservations and fences and
  revalidate cutover. Cron admission checks holds atomically.
- Archives remain inside their source root and obey complete decompressed-stream
  limits. Manifest/schema validation rejects unsupported or malformed inputs
  before mutation. Source-root PostgreSQL initialization remains supported.
- Encrypted configuration updates serialize correctly. Cloudflare settings are
  validated before verification and verification errors omit credentials.
- API startup preserves existing files and shared parent permissions; remote
  commands consume stdin only when required. Bootstrap cache writes are atomic.
- Incomplete journal fragments are excluded from incident evidence. Traffic
  batches and sampler baselines commit together, preserving failed intervals
  for retry. Health failures remain unknown; accepted SMTP DATA stays delivered.
- Systemd preserves literal executable paths and renews startup deadlines during
  healthy synchronous recovery. Host timezones validate before setup mutations.
  The selected Go toolchain includes the security patches described in the
  [improvement record](improvement-2026-10-21.md).

No new production dependency, database schema migration, data relocation,
application redeployment or replacement storage image is included. The existing
MinIO production image availability issue remains a separate
[dependency handoff](../technical/minio-image-availability.md).

## Upgrade preparation

Before crossing the secret-lock-path boundary, finish active secret/integration
changes, imports, copies and app removals. Keep those commands idle through the
daemon restart and prevent retained older binaries from writing afterward. A
restart alone does not drain direct CLI writers. See
[compatibility and upgrades](../features/compatibility.md).

The coordinated live target is **personal-vps only**. Other hosts are excluded.
Use the published signed checksums and exact reviewed platform bytes. Capture
`helios upgrade --version 0.7.19 --plan`, inspect its candidate identity and all
steps, then apply only that plan's exact `--digest`. Bind the readback to the
admitted upgrade operation ID; verify its successful receipt, installed binary,
answering daemon and absence of a staged marker. Record pre/post doctor, app and
alert state so existing failures remain distinguishable from regressions.

## Verification and publication

The prior improvement pass's complete evidence and limits are retained in the
[improvement record](improvement-2026-10-21.md). The merge regression first
demonstrated a lost sender display name; integration, mail and CLI tests, the
real SMTP watch regression, and affected vet checks pass with both contracts
preserved. The merged source passes `make check`: all 107 lane safeguard tests,
formatting, full vet and the complete Go test suite. Release artifacts, signed
publication and the personal-vps upgrade remain pending their separate gates.
The cross-version regression reproduced a rejected 0.7.18 journal after its
binary switch. Recovery now retains only that completed legacy switch
description, with generic semantic and original-digest checks intact. Host and
kernel race suites, focused recovery/approval regressions and vet pass. New
approvals retain checksum binding through recovery. No production host has been
contacted in this release preparation.

There is no tag-triggered release workflow. The existing
`scripts/build-release.sh` produces four static platform builds, identical legacy
copies and `SHA256SUMS` from a clean exact commit. `SHA256SUMS.sig` must be signed
by the existing pinned release key without exporting it. Those exact assets
must be uploaded and verified before the release is published. A tag alone is
not a binary release.
