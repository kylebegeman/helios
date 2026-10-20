# Disposable operational proofs

The lane runs operational proofs on a dedicated Linux machine, separately
from provisioning it. A proof uses the checkout being tested, checks the
result, and writes a report with commit, dirty-tree status, source-diff hash,
a source-tree fingerprint including untracked inputs (excluding ignored build
output and Python caches), OS, architecture, selected results, transcripts
and failure diagnostics.
A preflight failure is **blocked**, never a passing proof.

The historical Hostinger machine became production. `hostinger.env` is no
longer read by proofs or reset. `BEDROCK_LANE_DESTROY` cannot override a
safety refusal. No command here buys a VPS or contacts that historical target.

## Local Linux VM

Requirements: Docker running Linux containers, Go from `go.mod`, Python 3,
OpenSSH client, and outbound access to Ubuntu packages/cloud images. On a
Mac, Docker Desktop's Linux backend is sufficient. No Lima, privileged
container, Docker-socket mount or host-directory mount is needed.

```sh
make lane-up                  # provision a disposable Ubuntu 24.04 QEMU VM
lane/prove.sh --list           # show each proof and its fixture prerequisites
lane/prove.sh --check m1       # pinned SSH, identity, architecture, Linux/systemd
lane/prove.sh m1               # run and write report.md/report.json
lane/prove.sh m2               # host setup, a real guest reboot, upgrade rollback
make lane-status              # inspect only the VM owned by this lane
make lane-down                # remove only that VM and its generated keys
```

The provisioner builds a QEMU image with a pinned Ubuntu container base,
checks the Ubuntu guest image against Canonical's published SHA256SUMS,
records the exact guest checksum and provider image ID, generates guest/deploy
SSH keys, and boots a separate guest kernel. SSH is
forwarded only on localhost. QEMU uses software virtualization, so boot and
package upgrades take longer than on a VPS. A 24 GiB sparse guest disk and
3 GiB guest memory are configured by default. New provider images cap QEMU's
TCG translated-code cache at 128 MiB. Guest RAM is only part of provider
memory use: budget the TCG cache, QEMU overhead, Docker's Linux backend and
any other running containers as well. The guest supports systemd and reboot;
it is not a container pretending to be a host.

Set `LANE_VM_MEMORY_MIB` when creating a new VM to select an ASCII decimal
integer from 512 through 65536 MiB, without leading zeros. The chosen RAM and
cache size are recorded in
`machine.json` and `lane.env`. Running `up` on an existing VM preserves its
container settings, disk and SSH identity; an explicit differing RAM request
is refused. Use a fresh state directory to create a VM with different RAM.
The accepted range validates provisioning configuration, not proof capacity.
`m2`, product bootstrap and the transfer destination require at least 2 GiB
reported by the guest's `/proc/meminfo` `MemTotal`; swap does not count.
Configured RAM includes reserved guest memory, so 2048 MiB can report less
than 2 GiB. Keep the 3072 MiB default for fresh setup and bootstrap proofs.
The proof runner checks this requirement before running those workflows.

To reproduce an earlier guest image exactly, retain its Docker image and run
`LANE_VM_PROVIDER_IMAGE=sha256:<provider-image-id> lane/vm.sh up` with a fresh
state directory. The image must carry the lane provider label. A retained
image with an older boot policy remains unchanged and cannot accept an
explicit RAM override; its RAM and cache metadata are left unknown because
the current defaults do not describe it. Unknown resource keys are omitted
from `lane.env`, so exporting that config cannot create an empty RAM override.
Rebuild the current provider image
for configurable RAM and the cache cap. Existing providers also retain their
boot policy and keep unrecorded resource fields unknown. The report records
the immutable provider ID and guest checksum. The default build
checks Canonical's current Ubuntu 24.04 release; it does not claim all future
Ubuntu point releases have already been tested.

Local state lives in `${TMPDIR:-/tmp}/bedrock-lane-$UID`, outside the repo.
`LANE_VM_STATE` selects another state directory; pass its `lane.env` to
`lane/prove.sh --config` when using that override. Use a fresh state directory
for another independent VM. `make lane-reset` deletes and recreates the
managed VM only, after verifying its saved name and Docker ownership label.
To inspect an unsuccessful boot, use the exact container name printed by
`lane/vm.sh up` with `docker logs`. The VM remains available after a failed
proof for inspection. Remove it with `make lane-down` when finished.

Each VM runs on a Docker network of its own, labelled with its identity, in
`10.213.0.0/16`. On Docker's default bridge the guest sees SSH arrive from
172.17.0.1, the address its own Docker later gives `docker0`, and it stops
answering SSH as soon as `m2`'s host setup installs Docker. A VM created
before this keeps the default bridge; `lane/vm.sh up` says so, and
`make lane-reset` replaces it.

The local loopback VM proves `m1`, `m2`, `product`, `signed`, `originpull`,
and `peer`. Public certificate, external DNS and public webhook proofs
require the dedicated externally reachable SSH machine described below.
The runner refuses those scopes on the loopback VM and names the missing
prerequisite.

## Existing dedicated SSH machine

A disposable VPS or independently provisioned VM works without any provider
API or Hostinger CLI. Copy [ssh.env.example](ssh.env.example) outside the
repo and supply the address, SSH key and independently verified/pinned host
key file. Set `LANE_DISPOSABLE=true` and generate a new identity:

```sh
openssl rand -hex 16
```

On the **already identified disposable machine**, its owner installs that
same identity as a root-owned, mode-600 `/etc/bedrock-lane-id`. The runner
never writes this marker automatically to an arbitrary SSH target. A
`/etc/bedrock-production` or `/etc/helios-production` marker always refuses the target. A missing,
changed, symlinked or incorrectly permissioned disposable identity refuses
it. SSH failure, a changed host key, malformed app registry, non-fixture
apps and unmanaged non-fixture containers also refuse it. The allowed app
names are the lane fixtures, not a wildcard prefix.

`helios ls --json` reports `unmanaged_known: true` only after a successful
Docker inventory, including an empty inventory. Its app listing remains useful
when Docker is unavailable, with `unmanaged_known: false`; unknown inventory
cannot authorize lane work. The guard checks the command exit separately from
JSON parsing, validates inventory shapes, and requires this explicit evidence.
Older installed builds without the field are refused. Update them through a
separately verified disposable-target binary transition before using these guards.
Remote `DOCKER_HOST` and `DOCKER_CONTEXT` overrides are refused because they
could make inventory describe another machine.

Fresh provisioning and the `m1` to `m2` sequence remain supported before Docker
is installed. That exception requires no deployed apps or unmanaged names and
explicit absence of `docker` and `dockerd` commands, `/var/lib/docker`, Docker
sockets at `/run/docker.sock`, `/var/run/docker.sock`, and `/run/user/*/docker.sock`,
and `docker.service` and `docker.socket` units under `/etc/systemd/system`,
`/lib/systemd/system`, and `/usr/lib/systemd/system`. Existing paths and broken
symlinks both count as installation evidence. A Docker footprint without Helios
is also refused until its inventory can be verified. A stopped, broken, or
partially installed Docker engine cannot take the fresh-machine exception.

```sh
lane/prove.sh --config /absolute/path/to/lane.env --check m1 m2
lane/prove.sh --config /absolute/path/to/lane.env m1 m2
```

Reprovision that target separately using its existing provider workflow.
Proof commands never reinstall its OS. `lane/reset.sh` controls only the
locally created QEMU machine.

## Proof scopes and dependencies

| Proof | Behavior | Required fixtures/setup |
| --- | --- | --- |
| `transfer` | Two-host rehearsal/final/stage/cutover, durable source fence, clean encrypted machine recovery/private readiness/cutover, retained destination key/journal, deliberate source resume | Prepared disposable source plus `--target-config` for a separate clean Linux guest of the same architecture |
| `product` | Pinned profile bootstrap, sealed integration transfer, connection/machine/source-bound approvals, preview retention, authenticated HTTPS checks, scratch release rehearsal, data-aware rollback, machine recovery rehearsal, source move fence/resume | Ubuntu/Debian and package/image downloads; provisions loopback fixtures; no public DNS |
| `m1` | Daemon killed during a journaled operation; systemd restarts and resumes it | Fresh root SSH Linux/systemd machine |
| `m2` | Host setup, doctor, reconcile, maintenance reboot, failed/good upgrade | Ubuntu/Debian and package downloads; runs independently of `m1` |
| `m3` | Static/web deploys, certificates, revisions, rollback, failed check, DNS diagnosis | `m2`; public wildcard DNS to target, ports 80/443 reachable |
| `m4` | Revision-pinned secrets, cron, one-offs, restore private-shaped apps | `m3`; `--staging`, `LANE_SITE_URL`, expected `LANE_DW_CHAPTERS` |
| `m5` | Backups, drills, restoration, email outage signals | `m4`'s apps and expected chapter count |
| `m6` | Git push, app isolation, DNS stand-in, webhook, remote deploy | `m5`'s apps; explicit `LANE_BEGAMIN_REPO`, `LANE_SITE_URL` |
| `signed` | The daemon on its own and reconcile on its own, each from a stock 755 root:root `/etc/bedrock`, make it 715 root:bedrock, so the push user passes through to the signing policy without listing it; a signed pushed tip deploys and names its signer; unsigned, unknown-key, GPG and other-namespace tips and uploaded trees are refused with nothing built; an app without the policy deploys as before; the gitdeploy signing and webhook tests on the guest's git and OpenSSH | `m2`; no public DNS |
| `originpull` | Required origin pull refused until a CA is trusted; the minted leaf is a year's client certificate in a new file; optional checks a presented certificate and logs its name; required takes only the minted leaf, redirects port 80 and answers a mismatched name with 421; a `dns: direct` host beside it unchanged; `forget` keeps a required host's last CA; rotation without a gap; the edge restored without `origin_pull` | `m2`; no public DNS |
| `peer` | The daemon's peer listener on loopback answers only a registered key, with 401 and `Helios-Peer` otherwise, serves the summary with every field, takes a pushed view with 204 and serves none of the daemon's API; a Mac-style observer in a second state directory reads it and pushes its view, and finds its summary refused with the daemon stopped; `peer ls` shows names and public URLs only; neither the journal nor `helios alerts --json` names the port or the listen address | `m2`; no public DNS |
| `m7` | Generated/derived secrets, release order, singleton recovery, pgvector, object store, backup/restore | Prepared host; storage integration; public wildcard DNS |
| `cloudflare` | Records made, retained, pruned and removed against Cloudflare itself | `m6`; real integration token already on target; explicit `--real-cloudflare` |

Select proofs in dependency order. Dependencies are explicit; selecting
`m7` does not silently execute private-app proofs or real Cloudflare calls.
Independent storage/email fixture setup uses MinIO/Mailpit on guest loopback,
with throwaway credentials retained on the guest.

The storage fixture builds a scratch image from the official historical MinIO
release binary, with published SHA-256 values pinned for each architecture.
The image build needs no base-image registry or network. Downloads are verified
before building; the fixture binds only to guest loopback.

To prepare fixtures independently:

```sh
lane/prove.sh --config /absolute/path/to/lane.env --setup storage m7
lane/setup-fixtures.sh storage email    # requires LANE_CONFIG when not the local VM
```

`m4` staging contains `src/begamin`, `src/dragon-writer`, and `archives/` with
`begamin-data.tar.gz`, exactly one `dragon_writer_*.dump` and exactly one
`uploads_*.tar.gz`. Use sanitized, dedicated fixture data and sources without
`.env` files. These historical private-shaped proofs are optional and their
absence is reported distinctly; ordinary local checks and `m1` do not need
them. `m6` clones its explicitly supplied repository into a temporary folder
and pushes only to the disposable target.

Historical scripts can still be run directly with `LANE_CONFIG=...`; each
uses the same refusal checks and target-specific arm64/amd64 builds.
Prefer the runner for prerequisite checks, bounded proof timeouts and reports.

## Reports and CI

```sh
lane/prove.sh --artifacts /tmp/bedrock-proof-review m1
make lane-check               # shell syntax, safeguards, Python syntax
```

Artifact directories must be new and have mode 700. Reports contain no SSH
key, provider token, integration credential file or database contents.
Credential-shaped transcript values are masked; diagnostics collect daemon
service state and operation receipts. Do not use production data in fixtures.
Only selected completed scopes count as proven. Preflight-only reports say
`ready` and `not run`; missing prerequisites say `blocked`; an assertion or
timeout says `failed`. A failed proof leaves the machine for inspection.

CI runs safeguard tests alongside normal checks. Its separate operational
job boots a fresh QEMU guest, runs `m1`, uploads the proof report even on
failure, and removes its owned VM. This checks daemon recovery on a real
Linux kernel without external secrets, DNS, private repositories or a VPS.

## Product workflow proof

```sh
lane/prove.sh --config /absolute/path/to/lane.env product
```

This proof builds private client and Linux binaries from the checkout. An
existing installation is upgraded through the journaled compatibility and
checkpoint workflow. A checksum-pinned profile then bootstraps the target and
transfers a selected email integration encrypted to its own identity. The
proof exercises remote source upload, read-only host preflight, stale source
and wrong connection/machine approval refusals, preview pinning and pruning,
and authenticated HTTPS checks against a guest-loopback fixture. A temporary
fixture certificate is trusted only inside the disposable guest and removed
when the proof exits.

A loopback MinIO fixture holds actual restic backups. A candidate release
changes a scratch-restored marker and passes its health check while live data
and the active revision stay unchanged. A live incompatible release then
proves that ordinary rollback is refused and an explicit retained checkpoint
restores the original data. Exact machine recovery rehearses recorded images
and volume data without changing live app state and checks scratch cleanup.
Finally, an app handoff proves the persistent source write fence and deliberate
resume after confirming destination writers have stopped.

The fixture apps are `hello`, `notes`, and `lane-preview`; their state is
deliberately changed by this proof. It requires no private app sources,
production credentials, public DNS, certificate authority or paid provider.
It does not prove public route/certificate behavior or a clean cross-host
recovery and move cutover. Those require a separate second-target proof.

## Two-host transfer proof

```sh
lane/prove.sh --config /path/to/source/lane.env \
  --target-config /path/to/clean-target/lane.env transfer
```

Create the second guest in a separate `LANE_VM_STATE` directory. This baseline
uses the default 3072 MiB for each new guest and prepares the source before
starting the destination:

```sh
LANE_VM_STATE=/absolute/path/to/source lane/vm.sh up
lane/prove.sh --config /absolute/path/to/source/lane.env m2
LANE_VM_STATE=/absolute/path/to/clean-target lane/vm.sh up
lane/prove.sh --config /absolute/path/to/source/lane.env \
  --target-config /absolute/path/to/clean-target/lane.env transfer
```

Use fresh state directories and leave `LANE_VM_MEMORY_MIB` unset for the default.
Budget 6 GiB of guest RAM plus two 128 MiB TCG caches, QEMU overhead, the Docker
backend and other running work. Check available backend memory before starting
the second guest. Legal smaller allocations are useful for selected lightweight
workflows, but do not establish that setup, bootstrap or a complete proof will
pass. The actual destination `MemTotal` check also applies to retained guests.

Both connections pass the same pinned-host-key and disposable-identity guards;
the runner refuses identical identities or different architectures. The
source must already have working host setup. The target is bootstrapped
from a pinned binary and keeps its own encryption identity.

The proof opens guest-loopback MinIO access through two pinned SSH tunnels,
transfers the storage integration encrypted to the destination recipient,
and stops only tunnel processes it started. It exercises actual destination
rehearsal, exact final snapshot staging, explicit writer cutover, durable
source fencing across a daemon restart, and deliberate resume after removing
destination writers. It then recovers an exact machine snapshot onto the
clean target, checks inactive imported state, retained target journal and
identity, private readiness without published ports, and explicit cutover.
The source identity streams directly between pinned SSH connections and is
never printed or stored on the client. Fixture destination apps are removed
before source writers are deliberately resumed.

Worker fixtures and real volume markers prove data and write-authority
behavior. Public DNS, traffic routing and certificate issuance remain
outside this proof. Both guests remain available for inspection afterward.

## Origin pull proof

```sh
lane/prove.sh --config /absolute/path/to/lane.env originpull
```

The guest has no public address, record or certificate, so the proof brings
its own for the run: the documentation address 192.0.2.10 on a dummy
interface, the Cloudflare stand-in serving `lane.test` on guest loopback, an
`/etc/hosts` line so the `dns: direct` host resolves, and a throwaway CA
trusted only inside the guest, whose server certificates are seeded into
the edge's storage. Every request is made on the guest against 127.0.0.1,
playing Cloudflare with the leaf `helios edge origin-pull mint` wrote. It
records the edge's Caddy version and image, refusing one older than 2.8 or
without the inline CA pool, and the CA names the edge asks for, and checks
HTTP/3 too when the guest's curl speaks it.

It needs the lane after `m2` (the runner refuses an unprepared host),
without a `site` app, a `cloudflare` integration or a `lane-cloudflare`
container; it names the command that removes each. It removes everything it
added when it exits, and a run that was killed is cleaned up by the next one.

Cloudflare itself presenting the leaf, the dashboard upload, the zone's
SSL/TLS mode and public certificate issuance stay outside this proof.
[Authenticated origin pulls](../README.md#authenticated-origin-pulls) covers
those steps.

## Peer watch proof

```sh
lane/prove.sh --config /absolute/path/to/lane.env peer
```

The guest has no mesh, so the daemon's peer listener answers on guest
loopback, at a port no edge uses. A second state directory on the guest,
with no daemon of its own, plays the Mac: its key is registered with the
daemon, and `helios peer observe` reads the summary and pushes its view
the way launchd runs it on a Mac. curl presents a second registered key,
made on the guest and never printed, to check the listener's answers
directly. The proof stops the daemon to show the observer finds its
summary refused, and starts it again.

It needs the lane after `m2` (the runner refuses an unprepared host),
without peer watch set up and with nothing listening on its port; it
names what is in the way. It removes the peer configuration and the
observer's state directory when it exits, and a run that was killed is
cleaned up by the next one.

Two servers watching each other, paging once and needing a majority stay
outside this proof: a second daemon on the guest would share the first's
hooks socket. `TestTwoObserversPageOnce` and
`TestThreeObserversNeedAMajority` in `internal/peer` run them on real
listeners instead, and `TestNoMeshAddressLeaves` in `internal/daemon`
checks what a daemon says over many failed rounds.
