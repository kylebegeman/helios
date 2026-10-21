# Helios improvement pass, 2026-10-21

Status: implementation, final local gates and selected Linux acceptance complete. Combined M2 remains failed on its unchanged maintenance budget; provider/access limits are recorded below.

Human-facing companion: [improvement report](improvement-2026-10-21.html).

## Scope and working assumptions

The scope is the complete current Go codebase, CLI, daemon, generated editor
schemas, shell/Python operational lane, CI and current product documentation.
The starting checkout was clean at `b7f0e37` on `next`. Work uses
`improve/codebase-2026-10-21` in the existing checkout; no worktree was created.
The current feature documents and executable source take precedence over the
historical milestone plan and older idea inventory. The retained Bedrock
runtime paths, labels, service names and compatibility command are intentional.

This pass repairs established behavior. It does not authorize a release,
production changes, external messages, a replacement object-storage image or
new product capabilities. No new production dependency or database schema
migration is part of the implementation.

## System and coverage record

Helios is one statically buildable Go binary. Cobra commands either run local
read-only inspection, submit journaled operations to a Unix-socket daemon, or
transport the same commands over pinned SSH. The kernel persists plans, steps,
leases and receipts in SQLite. App operations coordinate Docker, the Caddy edge,
Cloudflare and restic; secrets and integrations are age-encrypted on disk.
Daemon loops handle jobs, maintenance, sampling, health, incidents and peers.

All 33 packages from `go list ./...` were included in package-level inspection
and the repository check plan. This is breadth coverage with deeper tracing of
mutation, cleanup, restart and external-input paths, not a claim that every
line or provider/environment combination was dynamically exercised.

| Area | Workflows inspected | Verification approach |
| --- | --- | --- |
| `cmd/helios`, `cmd/bedrock`, `internal/cli`, `internal/ui`, `internal/version` | Canonical/compatibility entrypoints, read and mutation commands, JSON/human output, source upload, remote dispatch, operation following, historical logs | CLI/renderer regressions; full package gate; supported builds |
| `internal/api`, `internal/daemon`, `internal/kernel`, `internal/state` | Socket startup, request lifetime, journal apply/compensate/recovery, persisted scheduling, activation, checkpoints, integrity checks, additive recovery import | Focused failure/restart tests; full gate; concurrency and Linux proof checks |
| `internal/app` | Deploy/release/rollback, previews, route ownership, jobs/holds/adoption, backup/drill/restore, machine recovery and cutover, staged host moves/fencing, remove/GC | Docker/provider fixtures, durable state regressions, cancellation/retry/cleanup tests; operational proofs where available |
| `internal/docker`, `internal/docker/dockertest` | Image account resolution, root defaults, ownership/adoption, volume/network/container lifecycle, exec, builds, logs/journald | Root/account and volume ownership regressions; existing runtime tests |
| `internal/edge`, `internal/dns`, `internal/cloudflare`, `internal/cloudflare/cloudflaretest` | Route/auth/TLS/origin-pull configuration, readiness, multi-record DNS status, managed-record retention/removal and takeover | Package tests and deterministic provider fixtures; no live DNS mutation |
| `internal/host`, `internal/release`, `internal/compat` | Host setup/reconcile, maintenance, firewall/web guard, doctor/facts, release signatures/downloads, candidate switch and rollback, machine identity | Candidate mutation and compatibility regressions; existing host/release tests; static builds; disposable setup/upgrade proof |
| `internal/restic` | Snapshot identity, helper ownership, archive/restore and failure cleanup boundaries | Package tests and app-level fixtures; live storage acceptance explicitly separate |
| `internal/manifest`, `cmd/helios-schema`, `schema` | YAML boundaries, workloads/routes/checks/durations, build-context containment, scaffolding and generated JSON Schema parity | Parse/validation regressions, generator freshness and independent JSON Schema validation |
| `internal/secrets`, `internal/integration` | Encrypted versions, concurrent updates/removal, transfer/copy/import, integration conflict policy, mailbox/endpoint normalization | Concurrent/idempotent update and validation regressions; no real credentials/providers |
| `internal/gitdeploy` | SSH push/signatures, hooks, archive extraction/capture retention, webhook authentication, body limits, queue/fetch cleanup | Git/archive/webhook regressions using local fixtures |
| `internal/remote`, `internal/bootstrap` | Target validation/save/load, pinned transport, stdin use, profiles, capability compatibility, bootstrap defaults | Transport/profile/compatibility regressions and supported builds |
| `internal/watch`, `internal/peer`, `internal/signals`, `internal/mail`, `internal/incident` | Observation/unknown states, alert scheduling/retry, peer authentication/summary/privacy, traffic ownership, SMTP completion, evidence redaction and incident timelines | HTTP/SMTP/state fixtures, panic/lifetime/concurrency tests and exact-boundary regressions |
| `lane`, `lane/fixtures/fakeflare`, `scripts`, `.github/workflows` | Disposable-target ownership/refusal, provisioner, proof runner, installer/release/benchmark tooling, CI gates | Lane safeguard suite, shell/Python syntax, benchmark smoke, Linux guest proofs where available |
| Documentation | README, CONTRIBUTING, SECURITY, feature/operations guides, direction/ideas/plan, performance evidence, latest release notes and MinIO handoff | Commands and claims checked against source/manifests; this coverage report |

## Completed root runtime fixes

### Image users and volumes

Default image users resolving to UID zero now receive the existing non-root
fallback even when they specify another group or spell zero with leading zeros.
A named account alias resolving to root receives the same treatment. Explicit
manifest root overrides preserve their requested group. `EnsureVolume` refuses
an existing volume explicitly labelled for another owner, while preserving the
supported legacy unlabeled case.

Evidence: `internal/docker/users.go`, `users_safety_test.go`, `adoption_test.go`.
Failing-first tests demonstrated the previous root-group bypass and foreign
volume adoption. These are isolation/ownership corrections; they do not prove a
hard security boundary against a privileged Docker operator.

### Upgrade approval binds executable bytes

An upgrade plan now includes the candidate executable SHA-256 and checks it
before rollback state is staged. Installation streams into a private temporary
file and verifies the copied bytes before atomic replacement. Two executables
reporting identical version metadata no longer share an approval when their
bytes differ, and mutation after approval is refused.

Evidence: `internal/host/upgrade.go` and `upgrade_source_test.go`;
`docs/features/compatibility.md` documents the contract.

### Patched toolchain and accurate runtime guidance

`go.mod` selects Go 1.27.3 with a supported patched minimum of Go 1.26.10.
The installed Go 1.27.1 initially yielded 11 reachable standard-library advisory
reports from `govulncheck`; reachability is not a claim that all are exploitable
in Helios. Official release/advisory data confirmed the patched versions. The
patched Darwin build-context scan reports no reachable or imported-package
vulnerabilities. Three module-only reports concern unused SSH/OpenPGP packages
in the existing indirect `golang.org/x/crypto` module. No dependency update was
needed to remove reachable findings.

Existing release binaries need a separately authorized rebuild and rollout to
receive these patches. SECURITY now names the actual retained socket and group,
`/run/bedrock/bedrock.sock` and `bedrock`.

### Split DNS destinations stay visible

DNS status examines the complete exact or wildcard A/AAAA destination set and
prefers a conflicting/non-local destination over a local one. Record ordering
can no longer make a split destination appear healthy.

Evidence: `internal/dns/dns.go` and table-driven multi-record status regressions.

## Integration results

### Lifecycle, data ownership and approvals

- One-off approvals bind canonical argv boundaries, selected revision and extra
  secret names. Previously `echo "a b"` and `echo a b` could share the same
  digest; note-only revision/name changes were also unbound. Failing-first
  approval tests cover each distinction (`internal/app/jobs.go`).
- Cron preparation rechecks holds; final admission checks the latest hold and
  inserts the run in one SQLite transaction. Tests include held/expired/released
  scheduled occurrences and 64 concurrent races through separate connections.
  One-off admission remains unchanged. Startup deadlines record a timeout;
  ambiguous legacy containers retain their durable overlap guard.
- Shared-host DNS cleanup preserves surviving apps. Ownership transfer only
  claims an existing local managed record, without creating DNS or changing its
  address/proxy policy. Preview hostname collisions fail explicitly.
- Drills, rehearsals, removal and move cleanup check container/image/volume
  ownership. Failed writer removal preserves scratch data; explicitly foreign
  volumes and image tags survive cleanup.
- Machine recovery retries reacquire reservations, recheck cleanliness and
  revalidate cutover containers. Fresh excluded volumes have workload ownership.
  Move retries preserve their reserved revision, image/secret pins and source
  fence, reject unrelated history, and recheck current web policy at cutover.
- Restore rejects unsafe app names and closes failed runs. PostgreSQL init at
  source root (`.`) now passes the same containment contract as nested init
  directories. GC also trims failed-only deployment histories.

Evidence is in `internal/app/*_test.go`, including approval, admission, cleanup,
move/recovery and source-root init regressions. The full app suite passed after
these changes; providers were exercised with fixtures, not production data.

### Source, manifest and encrypted configuration boundaries

- Offline Dockerfile checks confine symlinks to the declared build context.
  Route duplicate detection uses normalized hosts/paths; host total/label lengths,
  positive cron/release timeouts and HTTP status ranges are validated.
  Scaffold directories are YAML-quoted. Empty `origin_pull` acceptance matches
  the generated schema. Both schemas were regenerated through their source.
- App removal no longer unlinks a secret lock another writer already opened.
  Locks persist beside the store. Transfers compare under the lock; partial
  edits, password generation and import/recovery conflict choices preserve
  concurrent updates. The cross-version writer-drain requirement is recorded
  in [compatibility guidance](../features/compatibility.md).
- Integration mailboxes normalize to envelope addresses. Base URLs reject
  credentials, inappropriate schemes, query strings and fragments under each
  integration's existing policy. CLI Cloudflare setup merges effective current
  and patch values, validates before verification, and emits credential-safe
  errors. Regressions reproduced URL credential disclosure, premature requests
  and token echo before the repair.
- Source extraction verifies gzip trailers and applies an uncompressed-stream
  budget to headers and skipped metadata, as well as file bodies. Legitimate
  `pax_global_header` files remain supported. Deploy captures owned by durable
  operations survive generic pruning; oversized webhook bodies fail; failed
  exports are cleaned; null signing policies fail closed; hook replacement uses
  unique temporary files.

Evidence: `internal/manifest`, `internal/secrets`, `internal/integration`,
`internal/gitdeploy` and their regression tests; `schema/test_schema.py` passed
13 independent JSON Schema tests. Archive limits were reproduced with compressed
header/skipped-payload fixtures, not merely length checks of ordinary files.

### CLI, API, transport and persisted recovery

- API startup preserves non-socket paths and shared parent permissions. Only a
  confirmed stale Unix socket is removed. Remote commands forward stdin only
  when the actual workflow consumes it.
- CLI archives stay inside their source root. Git listing failures fail closed
  rather than switching to an unfiltered source walk. Empty DNS JSON is `[]`;
  JSON exposure failures return failure; following a silent daemon is bounded;
  saved job output without a live container does not require Docker.
- Bootstrap cache publication uses a private temporary file, sync and rename.
  Partial-copy and checksum-path symlink regressions proved the old cache could
  be corrupted before the fix. Target/profile size limits agree on save/load;
  saved profiles are private and atomic; known-hosts paths and bare IPv6
  destinations are rendered correctly.
- Bootstrap checks persisted state compatibility, restores execute permission
  on an already matching binary and applies the default empty web policy.
  Shared host timezone validation rejects invalid locations and `Local` before
  packages or hostname can change. Systemd uses a fixed `/bin/sh` launcher with
  `exec "$@"`, passing the
  executable and arguments separately. Each argument is C-quoted with doubled
  `%`, and systemd `$` expansion is disabled. This preserves literal filenames
  and the main PID for notify/watchdog/signals.
- Activation replay preserves rollback history. Integrity checks do not create
  missing databases. Recovery maps and journal indices are validated;
  compensation preserves operation identity; historical notifications remain
  historical; checkpoints stay private. Plan field encoding prevents digest
  ambiguity while semantic comparison permits unchanged legacy recovery.
  Malformed age-recipient errors omit the rejected value.

Evidence: failing-first regressions in API/CLI/remote/bootstrap/state/kernel/
compat/host/daemon packages. State, kernel and compat passed race checks. The
CLI incident golden changed only to reflect the intended redaction rule:
revision/commit/signer come from redacted evidence, so an uncollected later
rollback no longer displays its raw revision.

### Monitoring, incident privacy and delivery

- A panic in the local watch joins the peer observation. Maintenance, backup,
  GC and weekly canary scheduling retain persisted restart anchors.
- Peer stop closes a listener even before serving starts. Summary decoding is
  bounded and complete; sealed peer-name errors and summaries keep private
  addresses/credentials out. A notifier panic clears its sending marker.
- Container health redirects stay on their origin. Failed or invalid disk and
  memory measurements remain unknown and cannot certify recovery. Loom response
  codes cannot echo webhook credentials.
- Incident collection respects exact time/query windows. Redaction runs before
  truncation, recognizes quoted credentials, and supplies timeline details.
  Incomplete/headless journald fragments are excluded from evidence; full
  adjacent lines remain available. Human streaming still exposes partial logs.
  EOF, skipped chunks, new IDs, legacy chunks and limits have regression tests.
- Traffic attribution handles shared hosts, owner changes, ownerless intervals
  and incomplete scrapes. `state.AddSignals` writes a whole rollup batch in one
  transaction, then the sampler commits its baselines and eviction. First-write,
  partial-write and overflow failures preserve the interval for a nonduplicating
  retry. No schema change was required.
- SMTP DATA acknowledgement establishes delivery even if QUIT then fails.
  Human terminal output escapes controls/table injection; JSON preserves original
  structured values.

Evidence: daemon, peer, watch, incident, signals, state, mail and UI regressions;
focused panic/lifecycle tests and full/targeted race checks. The independent
fallback reviewer examined committed and working changes against `b7f0e37`,
including signal transactions, and reported no confirmed unresolved correctness
finding. Focused kernel/app/CLI/signals/state/Docker regressions passed there.
The pinned Reviewer bot failed after 2m 9s with only “The run ended as failed.”;
it supplied no verdict or finding and is not counted as a passing review.

### Documentation and intentional behavior

The direction inventory now recognizes shipped schema/offline checks,
targets/bootstrap and sealed transfer, safe moves and machine recovery. The old
idea page identifies itself as historical exploration. Encrypted recovery
histories and the MinIO dependency limitation are described accurately.

Dismissed concerns after checking counterevidence:

- Empty `git allow` arguments cannot reach remote-dispatch slicing: installed
  Cobra validates `MinimumNArgs(1)` before `PersistentPreRunE`.
- Checkpoint completion already atomically retires active code; quiesce recovery
  already retains failed restart journals.
- Retained Bedrock service/path/label names are an explicit compatibility
  decision, not disconnected Helios wiring.
- No measured performance gain is claimed. Benchmark smoke checks fixtures;
  provider, concurrency and ownership corrections were prioritized over
  speculative hot-path refactoring.

### Operational-proof correctness

The live m2 run exposed a proof-harness defect: fixed sleeps followed by
`history --limit 1` could accept an earlier successful receipt while the new
command was still planning. The transcript said maintenance succeeded but
printed the old setup receipt and began the broken-upgrade phase while the
actual maintenance operation was applying. The reboot phase also did not
assert a changed boot ID. This is not accepted as m2 success. The parent stopped
only the identified proof process group and its queued broken-upgrade client;
the runner preserved the failure transcript and diagnostics. Maintenance was
left to settle and succeeded in 4m9s; its reboot step correctly said “no reboot
needed.” `maintain --reboot` intentionally reboots only when requested by the
host, so the test needs a disposable reboot-required fixture. Commit `e7ef02b` binds phase admission and completion to each command's fresh
JSON event stream, exact operation ID, kind and plan digest. M2 requires a changed
boot ID and recovery of the reboot step; its broken upgrade must prove stage,
switch and failed resumed restart before accepting the restored binary. The good
upgrade must complete its own receipt and run the candidate bytes. M1 uses a
bounded guest-local watcher to recheck its exact running third step immediately
before SIGKILL, then verifies one interruption and all six timestamp markers.
A fresh pinned SSH `true` took 9.14s while the in-guest receipt read took 0.66s;
local crash timing avoids depending on that host transport latency. Eighteen
focused executable regressions and all 107 lane safeguards pass; twelve cases
failed against the original scripts. No production Go source changed in this
late proof repair. Existing phase and runner time limits were retained.

### Healthy startup can finish recovery before readiness

Live Linux acceptance established another root cause: initial recovery and edge
preparation run before API readiness, so systemd's default 90-second startup
limit could terminate valid work and trigger the rollback handler. Commit
`f68d616` sends an immediate `EXTEND_TIMEOUT_USEC=30000000`, then renews every
10 seconds while the state store responds. The loop covers initialization from
store opening through recovery and edge preparation, and is canceled and joined
before API readiness or startup exit. Cancellation at that handoff does not send
`READY=1`. Notify writes have a one-second deadline.

Readiness still requires the API listener; the runtime watchdog, unit timeouts
and rollback configuration remain in place. A deliberately broken candidate
still exits without extending startup. Health means database responsiveness,
matching the existing runtime watchdog; semantic progress of arbitrary external
work is not independently measured. Initialization stalled behind an external
command can keep extending startup if the database remains responsive. Explicit
startup errors still exit and trigger systemd failure handling.

Failing-first tests cover silent plan rebuilding, recovery application, edge
startup, immediate renewal and canceled readiness. Full daemon race tests passed
in 32.506s, vet passed, and the deliberately broken build's startup failure check
passed. The same controlled Linux regression passed against this commit;
its exact before/after evidence is recorded below. The pinned Fixer and
Reviewer bots failed in 5s and 6s without output or a verdict; implementation and
review used explicit fallback work rather than treating those failures as passes.
The narrow fallback review found no unresolved correctness finding; it was static
inspection, not independent live or blocked-socket verification.

## Verification record

| Check | Result |
| --- | --- |
| Runtime/host/provider packages on patched toolchain | Passed: `go test ./internal/docker ./internal/host ./internal/edge ./internal/restic ./internal/dns ./internal/cloudflare ./internal/release` |
| Benchmark smoke | Passed: `make bench-smoke BENCH_OUT=bin/benchmarks/improvement-20261021`, 71 cases, one iteration/sample; fixture validation only, no measured speedup claim |
| Supported static builds | Passed again at `f68d616`: `CGO_ENABLED=0 go build -trimpath` for Linux AMD64, Linux ARM64 and Darwin ARM64 |
| Final repository gate | Passed again at `f68d616`: `make check`; 107 lane safeguards, gofmt, `go vet ./...`, full `go test ./...` across all 33 packages. Log `/tmp/helios-improve-check-startup-final.log`. The `e7ef02b` proof-repair gate also passed in `/tmp/helios-improve-check-with-proof-fix.log`. Earlier final Go-source gate: `/tmp/helios-improve-check-final.log`; earlier uncached app 43.594s, CLI 30.969s, watch 134.935s in `/tmp/helios-improve-check-complete.log` |
| Final proof-harness gate | Passed for `e7ef02b`: `make lane-check`, all 107 safeguards including 18 focused operation/reboot/crash regressions |
| Final daemon race and startup checks | Passed at `f68d616`: `go test -race ./internal/daemon -count=1 -timeout=120s` (32.506s); `go vet ./internal/daemon`; focused startup/cancellation tests and the `0.7.0-broken` startup-refusal test |
| Final app/state race gate | Passed: `go test -race ./internal/app ./internal/state -count=1`; app 80.651s, state 8.854s. Log `/tmp/helios-improve-app-state-race.log` |
| Report quality | Passed: 83 local references including 58 fragment links; all eight proposal labels match. Desktop/mobile preview and filter/details interactions pass; muted text contrast is at least 5.84:1 in tested light/dark themes, with no horizontal overflow |
| Schema acceptance | Passed: `uv run --with jsonschema --with PyYAML schema/test_schema.py`, 13 cases |
| Scoped race checks | Passed: secrets/integration/gitdeploy, state/kernel/compat, signals/mail/UI, peer, daemon/watch panic/lifecycle and health/schedule regressions; exact scopes below |
| Linux systemd argument boundary | Passed: `systemd-analyze verify` plus execution of six disposable oneshot units using the emitted command format, covering literal spaces, quotes, `%`, `$` and backslash paths. Local regression executes the actual rendered command and checks argument boundaries and PID preservation. Log `/tmp/helios-improve-systemd-execution.log` |
| Disposable Linux daemon recovery | Passed again with corrected assertions from `e7ef02b`: `lane/prove.sh --config "$PWD/bin/improvement-lane-20261021/lane.env" --artifacts "$PWD/bin/improvement-proof-m1-m2-bound-20261021" m1 m2`; m1 binds `op-20261021-201003-baga7`, interrupts its third step, resumes once and verifies six timestamp markers. Operation duration 32.8s; m2 result recorded separately |
| Peer authorization and privacy acceptance | Passed on final source `f68d616`: unauthenticated/unknown-key 401, registered summary/view responses, no daemon API, Mac-style observer stop/restart recovery and no address/key leakage in checked output. Scenario 225.0s; final runner passed. Transcript `bin/improvement-proof-peer-journald-20261021/peer.log` |
| Journald retention acceptance | Passed on `f68d616`: 1G/14-day host policy, retired revision logs after container removal, all 60 finished-job lines beyond the saved 40-line tail, and live Engine logs. Scenario 764.1s within its unchanged 900s budget. Final runner and diagnostics passed; `bin/improvement-proof-peer-journald-20261021/report.md` |
| Final startup and upgrade acceptance | Passed at `f68d616`: identical 10s startup-deadline exercise that failed before the repair; separate broken/good upgrade phases with exact receipts, binary SHA and answering daemon. Artifacts `bin/improvement-proof-startup-deadline-20261021` and `bin/improvement-proof-upgrades-20261021` |
| Disposable host setup/reboot/upgrade | Corrected `e7ef02b` run: setup, doctor and reconciliation-plan inspection passed. Maintenance exceeded its unchanged 180s phase budget, so m2 failed and upgrade phases were not reached in that run. Report: `bin/improvement-proof-m1-m2-bound-20261021/report.md`; post-deadline recovery evidence recorded below |

The signals and cron-admission gate passed at `be0660c`. A subsequent Linux
parser check rejected quotes/backslashes in systemd's executable field despite
C-quoting; the initial string-only regressions had not established runtime
acceptance. Commit `114c9eb` repairs that with a fixed shell launcher and a
literal filename/argument/PID execution regression. The repository gate and
static builds passed again for that source. Documentation and proof repairs
followed, then live reboot acceptance found the startup timeout repaired in
`f68d616`. Its final checks are recorded separately.

Additional focused race commands (all passed):

```sh
go test -race ./internal/daemon -run '^TestAPanickingLocalWatchWaitsForItsPeerObservation$' -count=1
go test -race ./internal/peer -run '^(TestStopClosesAListenerBeforeServingStarts|TestTheSummaryPathReadsWhatHeliosAnswers|TestInvalidSealedPeerNamesAreNotRepeated|TestSummaryKeepsWatchedURLsPrivate|TestTwoObserversPageOnce|TestSidecarSurvivesRestartAndPrunes)$' -count=1
go test -race ./internal/peer -run 'TestAPanickingSenderNoLongerReadsAsSending|TestInFlightSenderIsNotDoubled' -count=1
go test -race ./internal/watch -skip '^TestDiskForecastScenarios$' -count=1
go test -race ./internal/watch -run '^(TestHealthProbe|TestPublicWatchesRequire200AndMayFollowPublicRedirects|TestUnavailable(Memory|Disk)MeasurementsCannotCertifyRecovery|TestARestartDoesNotPostponeAnOverdueAlertTest|TestLoomResponseCodesCannotEchoWebhookCredentials)' -count=1
go test -race ./internal/signals ./internal/mail ./internal/ui -count=1
go test -race ./internal/state ./internal/signals -run '^(TestSignalBatchesRollBackEveryEarlierWriteOnFailure|TestFailedTrafficWritesKeepTheWholeIntervalForRetry)$' -count=1
```

The disk forecast scenarios excluded from the watch race command use the existing
long scenario simulation; they passed the full repository suite. This exclusion
does not weaken the required gate. Worker package race checks and focused
consumer tests were completed before integration; final app/state race covers
the late transaction changes.

An early integration `make check` observed newly added failing-first Docker
tests before their implementation landed. That run is not a pristine baseline
or final verification. Root runtime regressions passed after the implementation. A subsequent full
integration run found the expected CLI incident-redaction golden mismatch. It
was regenerated with the existing `-update` workflow; full CLI reruns and the
final repository gate passed. No check was disabled to obtain the final result. An extra schema invocation with the system Python failed to import the isolated development-only `jsonschema` dependency; the documented uv command supplies that environment. This is an environment/setup failure, not a schema assertion failure.

## Remaining provider limitation

The existing production MinIO image digest remains unavailable on anonymous
fresh pulls: a 2026-10-21 read-only recheck received HTTP 200 from Quay's token
service, followed by HTTP 401 for the exact manifest. It was not replaced: provenance and existing-data compatibility of a
substitute are not established. See
[the owned dependency handoff](../technical/minio-image-availability.md).
The disposable lane's independent storage fixture is not evidence that a
production replacement is compatible.

Required resolution is an authenticated reproducible source for the exact image,
or a selected replacement validated on both Linux architectures, representative
existing data, creation, backup, restore and recovery. This is the existing
material product/dependency decision, not an approval gate for this pass's local
repairs.

## Opportunities

These remain unimplemented proposals. Existing schema, targets/bootstrap,
previews, rehearsals, safe moves and machine recovery were verified as existing
capabilities. A fleet dashboard remains tabled for the current two-machine
estate. The cron-admission proposal was implemented and is not a backlog item.

### Minor Features & Improvements

| Label and proposal | Evidence and product experience | Complexity / impact | Dependencies, tradeoffs and unlocked work |
| --- | --- | --- | --- |
| **O-MAN-01: Shared acceptance corpus** | Parser/schema mismatches repaired in this pass show the value of one case corpus exercised by both Go validation and independent JSON Schema tests. Editors and `helios check` would agree on the same accepted/rejected examples. | Medium / Medium | Existing schema generator and Python schema checker; define which source/host checks are outside editor validation. High return for keeping future manifest additions coherent. |
| **CORE-O1: Reference-aware artifact retention** | `_remote-artifact` saves content-addressed source/binary/data artifacts under `remote-artifacts`; no retention owner was found. A status/cleanup command could explain disk use and prune only objects unreferenced by active operations and recovery. | Medium / Medium | Durable operation/recovery references and a grace-period policy. Aggressive deletion can break resume, so age-only cleanup is insufficient. Unlocks predictable remote disk use. |
| **OBS-02: Capture local evidence when incidents open** | Loom automatically collects evidence on its first critical notice; warning/notice incidents and installations without Loom rely on `alerts review` or `alerts show --evidence`. A later collection can miss output already removed by journal retention. Optional bounded local capture would preserve the opening context and show collection failures in review. | Medium / High | Reuse current redaction, budgets and private evidence files; choose retention and retries. Storage/privacy tradeoff. Highest-return observability improvement, without requiring an external relay. |

### Major Features, Systems & Refactors

| Label and proposal | Evidence and product experience | Complexity / impact | Dependencies, tradeoffs and unlocked work |
| --- | --- | --- | --- |
| **BOOT-O1: Verify staged bootstrap candidates** | Fresh bootstrap installs the pinned binary, then asks for capabilities/version. A mismatch fails safely before host setup but leaves the candidate installed. Verify a temporary executable first, then publish; a failed candidate would leave a fresh target ready for retry. Existing differing installations already require upgrade. | Medium / High | Explicit staging, cancellation, cleanup and retry lifecycle; preserve checksum/machine/state binding. Highest-return setup hardening. |
| **APP-SOURCE-CAPTURE: Immutable local move builds** | Ordinary `helios rehearse` already hashes, copies and verifies source; named-target moves upload a snapshot. Local `move stage` and `move test` still build from supplied paths. Extend the existing capture contract there so later edits cannot change the selected build. Operators would review and execute one reproducible snapshot. | Medium / High | Existing deployment capture/upload contracts and recovery ownership. Extra disk/copy cost; unlocks reusable build provenance across workflows. |
| **APP-RESTORE-PROGRESS: Durable ordinary-restore retries** | Ordinary restore already pins its snapshot, uses `kernel.Resume` and skips completed journal steps. The gap is replaying an unfinished step that already wrote data, or starting another restore against partial data. Operation-owned per-volume progress could explain and safely resume those cases. | Large / High | Ownership markers, compatibility design and real PostgreSQL/storage proof. Must distinguish prior user data from this operation's partial data. Strong long-term reliability investment. |
| **GD-O04: Durable webhook delivery identity** | Per-app running/pending state is in memory; no delivery ID is tracked. Pushes coalesce and execution fetches the newest branch commit. Link authenticated delivery IDs durably to existing deployment receipts so restarts/redelivery can report the attempt, while preserving that coalescing policy. | Medium / High | Schema authorization, dedupe-retention and retry policy. Must preserve explicit retry after genuine failure. Unlocks clearer delivery diagnostics. |
| **OPS-RECOVERY: Scheduled whole-machine recovery proof** | Recovery, private rehearsal and disposable targets already exist but production-provider acceptance remains separate. An opt-in isolated proof could restore a selected snapshot, run checks, retain a receipt and tear down the target. The operator would know the age of the last successful recovery, not only the last backup. | Large / High | Explicit infrastructure/cost/credential policy and representative storage/images. Strongest long-term operational investment; connects existing capabilities without a fleet dashboard. |

Remaining quick wins are acceptance-corpus additions as new manifest options
land. Keeping the existing recovery path proven has greater immediate return
than expanding the set of managed data engines.

## Operational evidence and continuation

The owned target is a Docker-backed QEMU Ubuntu 24.04.5 ARM64 guest with about
3 GiB of reported memory. It is an explicitly identified disposable machine;
no historical or production host was used. Guest image SHA-256 is
`50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e`.

- Initial daemon recovery: the operation resumed once and completed all six
  markers. The runner then timed out collecting final diagnostics after 45s,
  so its overall report failed. Artifacts:
  `bin/improvement-proof-m1-20261021/report.md` and `m1.log`.
- Initial setup/reboot/upgrade proof: failed in the first `packages` step at
  `apt-get update` (exit 100, index download failure). Hostname, Docker, firewall,
  reboot and upgrade steps were not reached. Artifact:
  `bin/improvement-proof-m2-20261021/report.md`. Both HTTP and HTTPS probes to
  the official Ubuntu ports InRelease endpoint subsequently returned HTTP 200;
  this does not establish that all package indices can be fetched.
- Those initial runners began during source integration; their source hashes
  and installed binary commits differ as recorded in their reports. They are
  not final-source acceptance. The first final m1 retry used executable source commit `114c9eb`.
  Production Go source stayed frozen through `b4b1783` (documentation) and
  `e7ef02b` (operational proofs); the later startup repair is `f68d616`.
- Earlier final-source daemon recovery passed, including runner metadata and diagnostics:
  `bin/improvement-proof-m1-final-20261021/report.md`. Installed binary SHA-256:
  `72ff82a2a2e24ce425ba24d22d3ae5e139c515eadb2597d10db4c27553244d26`.
  Source tree hash:
  `282d395da951bcbe39bc523657faa5de94b460a9f7c0a424773ed9eff4663956`.
  The scenario took 158.0s; the whole runner took about four minutes.
- A bounded package-index retry with zero acquisition retries and 20s HTTP/HTTPS
  acquisition timeouts completed successfully. It fetched 1,563 kB in 40s;
  package-list processing and guarded transport added wall time. A fresh m2
  retry from source `114c9eb` completed host setup, doctor and reconciliation
  without changing mirrors or host setup source. It was then stopped after
  the receipt synchronization defect above was reproduced. Its failed report
  remains at `bin/improvement-proof-m2-final-20261021/report.md` (exit -15).
- Corrected m1 at `e7ef02b` passed with exact operation and plan-digest binding:
  `op-20261021-201003-baga7`, interrupted during step 3, one interruption,
  step-3 attempts 2, and six valid timestamp marker files. The operation took
  32.8s. Transcript: `bin/improvement-proof-m1-m2-bound-20261021/m1.log`.
  Independent read-only review found no discrepancy in this completed evidence.
- Corrected m2 at `e7ef02b` completed setup operation
  `op-20261021-201436-ezafj` in 265.2s. Doctor had no failures; resource
  warnings and the existing Docker/UFW UDP exposure warning remained visible.
  Reconciliation-plan inspection succeeded and described the already configured
  services; it is not asserted as an empty plan. Maintenance operation
  `op-20261021-202133-jzphb` exceeded its unchanged 180s phase budget.
  The scenario failed after 738.5s; the transcript and metadata remain at
  `bin/improvement-proof-m1-m2-bound-20261021/report.md` and `m2.log`.
  SSH closed during final diagnostics; the QEMU console subsequently showed
  a fresh Linux boot. A later exact receipt confirms completion in 409.3s,
  changed boot ID `c4baf8eb-6221-4739-bad3-9c2e99b173c9` to
  `401c4b45-f8ac-4425-8bff-f803337e1221`, and reboot-step attempts 2.
  The operation recorded two interruptions: the reboot and an unexpected
  systemd startup timeout. The journal confirms the default 90s limit killed
  PID 705 while rebuilding recovery; PID 1864 eventually completed it. This is
  a confirmed startup/recovery defect, not merely a slow proof. Read-only
  follow-up evidence is preserved beside the failed report as
  `maintenance-after-deadline.txt` and `startup-timeout.txt`. The failed timed
  acceptance remains failed despite eventual completion.
- A controlled Linux startup regression uses only a runtime drop-in on the
  owned guest: startup timeout 10s and restart delay 20s, exceeding the 15s
  operation lease. Existing 90s exercise proof assertions remain unchanged.
  Before repair, `op-20261021-203148-xumw7` finished in 64.9s but acquired
  two interruptions and repeated step 5; the proof failed as required.
  `bin/improvement-proof-startup-deadline-20261021/before.log` and
  `before-state.txt` preserve the exact receipt and systemd timeout. The
  runtime drop-in was removed, restoring startup 90s and restart 2s.
  A preliminary case with the normal 2s restart passed because the live lease
  delayed recovery until the background sweep; it did not reproduce startup
  recovery and is not counted as failing-first evidence.
- The identical controlled startup regression passed on `f68d616`:
  `op-20261021-203842-fre5r`, duration 40.4s, interruptions 1, only step 3
  attempts 2, six valid timestamp marker files and an active daemon. Recovery
  exceeded the imposed 10s startup deadline without another interruption.
  Evidence: `bin/improvement-proof-startup-deadline-20261021/after.log` and
  `install.log`; the runtime drop-in was removed after the proof.
- Separate upgrade-phase acceptance passed at `f68d616` using the unchanged
  120s helper budgets. Broken candidate `op-20261021-204128-m3ef4` staged and
  switched, then failed resumed restart and reported systemd restoring
  `0.7.0-dev`; previous binary bytes and daemon were verified. Operation duration
  34.9s. Good candidate `op-20261021-204237-k4ema` completed all four steps,
  with matching `0.7.0-lane` candidate bytes and answering daemon, in 25.3s.
  Evidence: `bin/improvement-proof-upgrades-20261021/phases.log` and
  `phases.sh`. These phase successes do not change the earlier m2 timing failure.
- Peer and journald acceptance both passed on `f68d616`; the runner exited 0
  after final binary metadata and diagnostics. Peer took 225.0s; journald took
  764.1s, within each unchanged 900s scenario budget. Journald verified the
  1G/14-day policy, retired revision logs after removal, a finished job's first
  and sixtieth lines after its container was gone, and live Engine output.
  Report: `bin/improvement-proof-peer-journald-20261021/report.md`, with
  `peer.log`, `journald.log` and `diagnostics.txt`. Installed binary SHA-256:
  `1bf9ee891b98bc69cee3eae034273c4e64f5193106102642008a0111e06d97b3`.
  Source tree SHA-256 at admission:
  `0e0cf3f1de3750d95b5eeed18ac648b3b26f37a16fbac062ea6dfa3a91e972d9`.
  The report records a modified working tree because these two report drafts
  were untracked; production source matched committed `f68d616`.
- The live systemd check uses six disposable units, verifies them with the
  Linux parser and executes filenames with the same quoting contract as the
  Go renderer. Each received its literal filename plus `daemon`, `run`.
  The units and temporary executables were removed after the check. The Go
  execution regression separately verifies the actual rendered command and
  that `exec` preserves PID. This is stronger evidence than string comparison.

After the runner and final diagnostics exited, `LANE_VM_STATE="$PWD/bin/improvement-lane-20261021" lane/vm.sh down` passed its ownership/disposable checks and removed only
`bedrock-lane-d6e99884a72827f9c2108bb6bd4c523b`, its network and generated
SSH/config files. Cleanup log: `/tmp/helios-improve-cleanup.log`. Proof reports,
transcripts and image checksums remain in ignored `bin` artifacts. A future
proof needs a fresh guarded target/config; the deleted guest config is no
longer usable.

For a passing combined m2 result, rerun the committed proof on a guarded,
owned disposable Ubuntu/Debian target with functioning official package/image
access and enough execution speed to meet its existing phase budgets. The
software-emulated guest used here did not meet the 180s maintenance budget;
raising that limit is not counted as acceptance. Use the new target's pinned lane config:

```sh
lane/prove.sh --config /path/to/disposable/lane.env \
  --artifacts "$PWD/bin/improvement-followup-proof" m1 m2
```

Completion criteria are each exact setup/maintenance/upgrade receipt, actual
reboot with recovered step, rollback to the verified previous binary, then the
verified good candidate. Preserve prior failed reports and source hashes.
Public-DNS/provider/private-fixture, non-root sudo bootstrap and two-host
transfer/recovery proofs need their declared access and representative inputs;
passing local fixtures does not replace them.

## Handoff and branch state

All implementation batches are committed on `improve/codebase-2026-10-21`;
final production Go source is `f68d616`, following operational-proof repairs
in `e7ef02b`. The branch remains local and unmerged into
`next`, awaiting Kyle's review/landing. No additional worktree, release,
production rollout or pull request was created. The disposable guest, its
network and generated SSH/config files were removed after final diagnostics.
Both report formats accompany this handoff in a documentation commit.

Final Git inventory contains one checkout, on this improvement branch. The
branch is intentionally waiting for Kyle's review into `next`. The existing
unmerged `feat/vault-backup-extract-20261021` branch belongs to separate work and
was left untouched. There are no other worktrees or development processes
created by this pass waiting for cleanup.
