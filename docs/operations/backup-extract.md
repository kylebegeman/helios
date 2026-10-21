# Private backup extraction operator

`helios backup extract` retrieves exact regular files from one explicit app
snapshot without changing app data. This separately built operator is based on
v0.7.17; it is not a daemon upgrade. Run it directly on the Linux host with its
existing state and sealed storage integration. No storage credential arguments,
exports or additional credential files are needed.

Use an **explicit empty `--socket=`**. The command refuses a daemon socket,
SSH `--target`, and remote Docker endpoints. An existing v0.7.17 daemon remains
installed and running. The local kernel uses the existing machine operation
lock and schema. Planning reads local metadata only and does not contact storage.

Create a private, operator-owned parent directory with mode 0700 outside Helios
state and Docker volumes. Its ancestors must not be symlinks. Select the full
64-character lowercase snapshot ID from the successful backup's JSON history.
Use the independently retained publication generation and digests, rather than
following the passive app's mutable `current` link.

```sh
/path/to/helios-backup-extract-linux-amd64 --socket= \
  --state-dir /var/lib/bedrock backup extract loom-vault-backup \
  --snapshot FULL_64_HEX_SNAPSHOT_ID \
  --path /data/volumes/snapshots/generations/GENERATION/snapshot.snap \
  --path /data/volumes/snapshots/generations/GENERATION/completion.json \
  --path /data/volumes/snapshots/generations/GENERATION/receipt \
  --destination /root/private/vault-drill/NEW_DIRECTORY --plan
```

Review that plan. Repeat the exact command, replacing `--plan` with
`--digest REVIEWED_DIGEST`. The digest binds every input. The app must match the
snapshot's hostname and Helios tag; `latest` and abbreviated IDs are refused.
The operation reads the configured repository through the existing restic runner.
It does not initialize, unlock, prune or change retention in that repository.

The destination must not already exist. Before restoring, the operation counts
the whole snapshot conservatively and preserves the existing free-space reserve.
The operation has a two-hour deadline; the existing runner adds bounded helper
cleanup time after cancellation. Restic mounts only a newly created private
payload directory plus its existing cache and temporary credential mount.
No application volume is mounted or restored and no application workload is
stopped or started.

Output layout:

```text
NEW_DIRECTORY/
  incomplete.json
  extraction.json
  payload/volumes/snapshots/generations/GENERATION/
    snapshot.snap
    completion.json
    receipt
```

An archive path `/data/PATH` maps to `NEW_DIRECTORY/payload/PATH`. The immutable
`incomplete.json` records the attempt. Only a valid `extraction.json` marks a
verified result. Its bounded metadata contract is:

```json
{
  "schema_version": 1,
  "state": "extracted",
  "app": "loom-vault-backup",
  "snapshot": "FULL_64_HEX_SNAPSHOT_ID",
  "verified": true,
  "files": [{"path": "/data/PATH", "size": 123, "sha256": "SHA256_HEX"}]
}
```

The success receipt is written after restic verification, complete topology
verification, hashing and syncing the retrieved files. Selected files become
mode 0600, directories mode 0700. The verifier accepts 1 to 16 distinct regular
files, paths at most 512 bytes and 16 components beneath `/data`, and at most
8 GiB total file data. It rejects missing files, extra entries, directories
selected as files, symlinks, hardlinks and special files. It does not trust
restic progress counters as evidence of completeness.

Every existing destination is refused, including a completed result. Failed or
interrupted attempts remain privately fenced and are not automatically cleaned
or retried. Inspect locally before any new attempt. If helper cleanup could not
be confirmed, a helper may still be using staging; do not remove or reuse it.
An old daemon cannot resume this new operation. Keep the operator artifact for
inspection; do not invoke generic restore or drill as a recovery shortcut.

This receipt proves exact file retrieval, not native Bao recovery. The separate
owner-run adapter must compare publication digests, validate the native archive,
and perform the isolated restore, custody-share unseal, canary decryption and
revocation reconciliation. Root, issuer and share credentials never belong in
this extraction command, its receipts or its maintenance configuration.
