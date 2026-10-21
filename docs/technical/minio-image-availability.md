# Open dependency issue: MinIO image availability

Status: open. Owner: Bedrock data-service maintainer (Kyle).
Observed during the 2026-10-10 implementation session; anonymously rechecked
on 2026-10-21 with the same result.

Fresh pulls of the production object-service image currently fail with HTTP
401. The pin is defined by `ObjectsImage` in
[internal/app/data.go](../../internal/app/data.go):

```text
quay.io/minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e
```

This affects provisioning an object service when its image must be fetched.
The selected implementation's volume-based backup, release and recovery
proofs use an independent storage fixture and do not verify this image.

## Evidence

- The 2026-10-21 recheck received HTTP 200 from Quay's anonymous token
  service and HTTP 401 for the exact pinned digest manifest. No image was
  pulled and no production configuration changed.
- Quay's anonymous token request succeeded; the exact digest manifest request
  with that token and OCI/Docker manifest headers returned HTTP 401.
- Docker Hub authentication for the official `minio/minio` repository returned
  no pull scope. The same digest returned HTTP 401; public repository metadata
  and tags returned HTTP 404. An identical official mirror was not established.
- Commit `5e16709` introduced the pin on September 19, 2026, without an exact
  release tag or source provenance mapping.
- The [official MinIO README](https://github.com/minio/minio/blob/master/README.md)
  describes the community repository as unmaintained with source-only
  distribution. Historical release binaries remain publicly available.

## Required resolution

Recover an authenticated, reproducible source of the exact pinned image, or
establish the provenance and compatibility of a replacement production build.
Verify both Linux architectures and object-service creation, representative
existing-data startup, backup, restore and recovery before changing the pin.
Existing data-format compatibility has not been established for a substitute.

The disposable lane builds its own scratch storage fixture from official
`RELEASE.2025-04-22T22-12-26Z` binaries, verified against hardcoded published
SHA-256 checksums for both architectures. That fixture is a backup repository;
its release has not been mapped to the production image digest. The production
pin remains unchanged, and the fixture is not a production replacement.
