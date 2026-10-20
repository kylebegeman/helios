# Compatibility and upgrades

`helios capabilities --json` describes the invoked binary's API, manifest and
state contracts, supported state reader range, optional capability names,
build and stable machine identity. It reads existing identity/state metadata
without creating a secret key or database. The daemon's
`GET /v1/capabilities` describes the running daemon and its persisted schema.

Historical unversioned state is migrated transactionally. The journal,
saved output and app history survive. A binary refuses a newer unsupported
schema through a read-only inspection before opening the file for writes or
WAL changes. Schema changes live in the migration sequence; generated manifest
schema stays aligned with the Go validator.

An upgrade probes the actual candidate binary before switching. It checks
contract versions, required capabilities and the state reader range, then
writes a private consistent SQLite checkpoint before staging the binary.
Checkpoint metadata is bound to the kernel operation ID so an interrupted
upgrade cannot adopt a checkpoint from a different attempt.

The daemon restarts itself partway through an upgrade, which ends the
command's event stream before the outcome. The command then follows the
journaled operation: it says so, reads the receipt until the operation ends,
shows it and exits as it says. It waits up to three minutes for a daemon that
doesn't answer, long enough for systemd to stop the old daemon, try the new
build and put the previous one back; past that, or on Ctrl-C, it names
`helios history <id> --output` and leaves the operation to the daemon. Any
operation a daemon restart cuts off is followed the same way. The command
running the upgrade is the build being replaced, so an upgrade run by a build
before 0.7.16 still ends with `context canceled`, even when it succeeded;
`helios history` shows how it ended.

When an app's active revision sets `origin_pull` for a host, the candidate
must also report `edge.origin-pull.v1`: an older build reads the stored
`origin_pull` as nothing, and its edge would stop checking Cloudflare's
client certificate on that host. The upgrade names those hosts and stops
before the journal or binary changes; upgrade to a build that has it, or
deploy those apps without `origin_pull` first.

Automatic binary rollback requires both binaries to read the resulting state.
A candidate that migrates beyond the running binary's reader is refused with
instructions for a coordinated migration. A state checkpoint is evidence and
a recovery artifact; it is not an automatic destructive database replacement.

API errors retain the existing human message and add stable `code`,
`retryable` and `api_version` fields. Existing receipt and history JSON stay
compatible. Daemon and direct local fallback execution share the same machine
operation lock, so choosing another socket cannot create a second concurrent
writer authority.

## Helios source rename

The primary command is now `helios`, with a `bedrock` compatibility entrypoint.
New manifests use `helios.yaml`. An existing sole `bedrock.yaml` still loads;
when both files exist, select one explicitly using `--manifest` or remove the
duplicate. A source filename change requires a new reviewed deploy digest.

Named-target `deploy` and `check` forward the selected filename explicitly,
so a supported older daemon does not choose its own default. The legacy
`deploy --to` transport retains its existing wire request: deploying a new
`helios.yaml` through that transport requires a daemon that understands the
new filename. Until then, keep `bedrock.yaml` for that workflow. Older hosts
without named-target capabilities must follow their existing deployment path.

Both entrypoints still use the Bedrock state directory, socket, services,
Docker identities and stored formats. `HELIOS_*` configuration names accept
the corresponding `BEDROCK_*` fallback. Different nonempty values are refused;
an explicit corresponding flag overrides its environment settings. Machine
identity, encrypted integration state and existing backup repositories retain
their original identities. The physical migration and live rollout are
separate work described in the [rename plan](../operations/helios-rename-plan.md).
