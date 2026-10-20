# Manifest editor schema

`helios.schema.json` is generated. Regenerate it from the repository root:

```sh
go generate ./internal/manifest
```

The generator is `cmd/helios-schema`. `internal/manifest/schema.go` reflects
all YAML-tagged manifest types and adds workload-kind and field constraints
from the authoritative validation rules in `internal/manifest/manifest.go`.
`x-helios-schema-version` identifies this editor contract. Existing manifests
do not need a version field.

For a YAML editor that supports the YAML Language Server, put this directive
at the top of a manifest:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/kylebegeman/helios/next/schema/helios.schema.json
```

Use a reviewed release tag instead of `next` to pin the schema, or point the
directive at a local copy. The schema uses JSON Schema draft 2020-12 and
rejects unknown fields on manifest objects. Maps such as workload names,
volume names, environment variables and build arguments retain their declared
key/value types.

The schema is editor guidance. `helios check [source-dir]` uses the deploy
parser and validator, then checks local build contexts, Dockerfiles, static
directories and PostgreSQL init inputs. It also validates references, route
and port collisions, one `dns` and `origin_pull` per host across its routes,
cron expressions and durations that JSON Schema cannot fully express. Use
`--manifest helios.worker.yaml` for another manifest at the source root and
`--json` for structured field/line diagnostics.

An offline pass does not prove that Docker can build the source, a container
can answer its HTTP health path, DNS points at a target, certificates are
ready, secret values exist, images can be pulled or the machine has capacity.
Run `helios check <source-dir> --host` on the target to apply the deploy
planner's read-only preflight after the offline check passes. This checks
required integrations, exact host/path ownership, shared-host DNS modes and
published-port ownership against the target's existing apps, that the
target's edge trusts a CA for every host that would require origin pull,
whether this app or another app sharing the host requires it, and named
secrets (including generated, derived and inherited names), then returns
the plan without applying or journaling an operation. It does not establish
runtime readiness, DNS resolution or certificate issuance. `--json` includes
`host_preflight.valid` and the plan when successful.

When adding manifest fields, update the authoritative types and validation,
add any editor constraints in `schema.go`, then regenerate the checked-in
schema. The artifact freshness test catches missing regeneration.

To verify the schema itself and its editor semantics with an independent
standards implementation, run:

```sh
uv run --with jsonschema --with PyYAML schema/test_schema.py
```

Those Python packages are development-only verification dependencies installed
in uv's isolated environment. Helios and its Go tests need neither package.

## Rename compatibility

The generator also writes `bedrock.schema.json` with its historical schema ID.
Both files validate the same manifest contract and retain the legacy
`x-bedrock-schema-version` extension alongside `x-helios-schema-version`.
Existing editor annotations keep working through the repository redirect. Current
annotations can use the canonical Helios repository URL.
