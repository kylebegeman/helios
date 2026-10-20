# Whole-machine recovery

`helios backup bedrock` now preserves a self-contained recovery point: the
SQLite state, sealed secret histories, host profile, active workload images and
the exact last successful data backup for each active app. App data is embedded
inside the machine snapshot, so later app retention cannot delete the recovery
point. Run a fresh data backup for every app that keeps data after its current
deployment and before making the machine backup. Each app snapshot records its
exact revision, secret version, manifest digest and capture time. Machine backup
refuses missing provenance, older revisions and changed secret versions, even
when the volume layout and service versions are identical. The recorded app
recovery points can be older than the machine snapshot;
inspect the app backup history when choosing how much data loss is acceptable.
Before losing the source, record its machine snapshot IDs with
`helios backups bedrock --json` on that source machine and keep the inventory
with your recovery materials. This command reads local backup history.

The backup omits the machine's private identity. Keep the source recovery
identity and storage backup password separately. Workload images are archived
by their immutable image IDs, including images built in the source machine's
local registry. Recovery does not need the source registry or source checkout.

## Prepare a clean target

Initialize the target with its own identity and configure storage to read the
source machine's repository. Use the source storage bucket prefix and backup
encryption password. Never replace the target private identity with the source
identity. Real recovery requires a different target identity, a compatible
Helios version and matching operating system and architecture. It refuses
existing app history, app secrets and app resources rather than overwriting them.

Choose an explicit source hostname and machine snapshot ID:

```sh
helios recover old-host --snapshot <machine-snapshot-id> \
  --identity-file ./source-recovery.key --plan
helios recover old-host --snapshot <machine-snapshot-id> \
  --identity-file ./source-recovery.key --yes
```

The identity file must be a plain file readable only by its owner, usually mode
`0600`. `--identity-stdin --yes` accepts a protected stream instead. Identity
contents never enter command arguments, operation input, receipts or report
JSON. The source identity is sealed with the target identity before journaling,
checked against its artifact digest on resume and removed after completion.
`--plan` neither reads the source identity nor creates a recovery workspace.

An ID is derived from source hostname, requested snapshot and mode. `--id`
allows an explicit stable ID. Use a new ID to run a fresh rehearsal of the same
snapshot; a completed ID remains an idempotent proof. Retry the same selection
and ID after an ordinary failure; the kernel resumes interrupted operations and saved markers keep the
same full machine snapshot, app data and secret version numbers. Ambiguous
snapshot prefixes and `latest` are refused. Snapshots made before recovery
catalogs and image archives were introduced require a new machine backup.

## Private readiness and live cutover

Recovery restores app data into volumes claimed on the clean target and starts
long-running workloads on internal networks. It publishes no ports, installs
no live app routes, changes no DNS records and runs no release or cron jobs.
Restored file contents are verified against their snapshot before private
health probes verify the restored runtime. The source host profile is
applied; missing non-storage integrations and operational keys, among them
the CAs the edge trusts for origin pull, are recovered while target storage
and already configured target values remain authoritative.

The source state is imported additively. The target operation journal, identity
and configured integrations stay in place. Original source revisions remain
inactive history; new recovered revisions record their new containers and
archive-loaded image IDs. The immutable source state snapshot retains the
source operation journal. Imported app secret version numbers remain unchanged.

Real recovery reserves the target against unrelated app and host operations,
operator data commands and jobs. The reservation survives reboot and remains
until cutover or explicit abandonment. Reports stay available:

```sh
helios recover report <recovery-id>
helios recover report <recovery-id> --json
helios recover cutover <recovery-id> --plan
helios recover cutover <recovery-id> --yes
```

Cutover brings services onto their normal app networks, restores normal
workload port publishing and rechecks every long-running workload. Only after
readiness does it activate recovered revisions, load edge routes and explicitly
point managed DNS records at the target. Cron jobs become eligible after
cutover completes and releases the reservation. DNS modes configured as manual
remain manual.
Cutover durably records its start before changing the target runtime. A failed
or interrupted cutover reports `cutover-incomplete` and is retried with the same
recovery ID; it cannot be abandoned after that start marker.

## Disposable rehearsal

```sh
helios recover old-host --snapshot <machine-snapshot-id> \
  --identity-file ./source-recovery.key --rehearsal --yes
helios recover report <rehearsal-id> --json
```

Rehearsal can run beside existing apps, including on the source machine with
its own recovery identity. It uses distinct names, internal networks and scratch
volumes. It reseals secrets into a private temporary store without installing
them into the target store. It skips host profile application, integration
recovery, state import and all live routing. Successful rehearsal removes its
containers, networks, volumes, staged data and staged secrets. Failure cleanup
removes only resources the rehearsal claimed. A rehearsal cannot be cut over.

## Abandon a private recovery

```sh
helios recover abandon <recovery-id> --plan
helios recover abandon <recovery-id> --yes
```

Abandonment removes only ownership-labeled private recovery containers and
networks, deletes the sealed source identity, records an `abandoned` report and
releases the target reservation. Restored volumes, secret histories and state
history are preserved for inspection and later operator decisions. It refuses
active target apps and a cutover that has already begun. Complete the same
cutover in that case. An abandoned ID cannot be reused for a new recovery.
