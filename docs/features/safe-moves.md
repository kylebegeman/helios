# Safe app moves across machines

A staged move transfers one app to another machine through a rehearsal, a final
capture that freezes the source, private target validation, and an explicit
production cutover. The source stays stopped after the final capture, including
across daemon and host restarts. Plan downtime from that capture until the
target is ready and traffic reaches it.

| Phase | Source | Target |
| --- | --- | --- |
| Rehearsal capture | Paused briefly for consistent data, then resumed | No change |
| Rehearsal test | Continues serving | Scratch restore and private checks |
| Final capture | Writers stopped behind a durable fence | No change |
| Stage | Remains frozen | Restored data, private web and static checks |
| Cutover | Remains frozen | Normal writers, production routes and managed DNS |

## Prepare the target

Initialize the target with its own machine identity and install a compatible
Helios version. `--to` on the capture names the target's exact hostname, not a
local SSH target alias. Place the app's source on the target with the same
manifest and captured Git commit. Remote `--target` commands upload local source
and preserve its Git commit for validation.

For an app with data, both machines must read the same storage repository: the
same provider or S3 endpoint, bucket prefix and backup encryption password. The
handoff names the exact app bucket and full 64-character snapshot ID. A target
with different storage refuses the handoff. Stateless apps need no storage or
snapshot.

Import the original app secrets before testing or staging. A restored database
still contains the passwords and roles from the source. Newly generated target
passwords cannot replace them. The target keeps its own private machine key:

```sh
# On the target, obtain its public age recipient.
helios secret recipient

# On the source, seal the app's secrets to that recipient.
helios move secrets my-app --to age1... > secrets.age

# Transfer the ciphertext to the target and accept it within ten minutes.
helios move secrets my-app --accept < secrets.age
```

Configure the target integrations used by the app, including Cloudflare for
managed DNS and Loom for guarded routes. A target app must not already be
active. Restoration refuses existing data, and staging refuses running orphan
containers for the app. Moves and ordinary app restores also refuse an
unfinished release-checkpoint restore. Finish that selected rollback, or
explicitly remove the app, before changing recovery paths.

A host the app requires origin pull for (`origin_pull: required`) needs the
CA the source trusts for it on the target too, since Cloudflare keeps
presenting the certificate minted on the source. `helios edge origin-pull
list --json` shows each CA's PEM as `ca_pem`:

```sh
# On the source, save the host's CA.
helios edge origin-pull list --json \
  | jq -r '.[] | select(.host == "shop.example.com") | .cas[0].ca_pem' > ca.pem

# Copy ca.pem to the target and trust it there.
helios edge origin-pull trust shop.example.com ca.pem
```

A host in the middle of a rotation trusts two CAs; trust the one whose
certificate Cloudflare presents (`.cas[1]` is the second). Trust takes the
CA, never the certificate uploaded to Cloudflare.

`helios move stage` refuses the app until the target trusts a CA for each
such host, and `helios move cutover` refuses it again if that CA was
forgotten since. Machine recovery brings the source's trust along with its
other operational keys.

## Rehearse before downtime

Capture a consistent rehearsal snapshot on the source. Workloads resume after
this capture. Only handoff JSON goes to standard output; the plan and progress
go to standard error.

```sh
# On the source, review first, then capture.
helios move rehearse my-app --to target-hostname --plan
helios move rehearse my-app --to target-hostname --yes > rehearsal.json

# Copy rehearsal.json to the target, then test the source there.
helios move test ./my-app --handoff rehearsal.json --plan
helios move test ./my-app --handoff rehearsal.json --yes
```

The target restores scratch volumes and a scratch database, builds the source,
and starts web and static workloads on an internal network. Readiness and
application checks run directly against those workloads. Workers, cron and
release jobs stay excluded. Public routes, published ports and DNS stay out of
the rehearsal. Successful tests remove their scratch containers, networks,
volumes, staging files and temporary revision.

The internal scratch network blocks external network egress. External services
are not emulated, so readiness checks that depend on public network access may
fail in a rehearsal. Failed or interrupted tests compensate by removing their
owned scratch resources and temporary revision, using the captured manifest
even when an uploaded checkout is no longer available.

## Capture the final source and stage the target

Start the maintenance window with a final capture:

```sh
# On the source.
helios move final my-app --to target-hostname --plan
helios move final my-app --to target-hostname --yes > final.json

# Copy final.json to the target.
helios move stage ./my-app --handoff final.json --plan
helios move stage ./my-app --handoff final.json --yes
```

Final capture drains operator commands and jobs, records every source writer's
identity and original restart policy, disables automatic restart and cleanly
stops web, worker, cron, one-off jobs and object storage. Postgres remains up
for the dump. An unclean writer stop fails the capture while retaining the
fence. Helios never automatically resumes this source after a failed capture.
Daemon startup keeps these writers stopped while allowing explicit recovery;
retrying final capture still refuses their unclean stop.

The final handoff binds the source machine, target machine, app, source
revision, manifest digest, captured Git commit, bucket and exact snapshot. A
retry reuses the recorded capture. Changed storage or source identity requires
reviewing a new move after a deliberate source resume.

Staging reserves the target against operator and job writes, restores only the
final snapshot, and records restore progress durably. Web and static workloads
start without public ports or automatic restart. Background workers, cron and
release jobs wait. Direct readiness and application checks must pass before
the target is marked staged. Production routes and DNS remain on the source
until cutover, while source workloads remain stopped. Garbage collection keeps
the unfinished target revision, containers and images until cutover or explicit
app removal.

Staged workloads use the normal destination network and can call configured
external services. They run on the restored destination data and may change it.
Resuming the old source does not recover those changes. A Git commit and
manifest digest also do not prove identical dirty source files: revisions made
from a dirty checkout do not retain a content digest of those original bytes.
Use matching clean source when exact code provenance matters.

## Cut over explicitly

```sh
# On the target.
helios move cutover my-app --plan
helios move cutover my-app --yes
```

Cutover rechecks the staged application, records that destination write
authority is beginning, recreates web and static containers with their normal
live configuration, and starts workers. It activates production edge routes,
points only manifest-managed DNS records at the target, waits for certificates,
and verifies edge content and anonymous guard denial. Normal jobs become
eligible after cutover completes. Release jobs do not rerun during a move.

Routes with manual DNS remain under operator control. Move those records to
the target at cutover; certificate and public checks may need a retry once DNS
propagates. There is no automatic DNS rollback to the source.

A failure after target writers begin leaves the target intact and the source
frozen. Repair the cause and retry the same cutover. The target may already
hold new writes, so pointing back at the old source could lose data.

## Resume or retire the source deliberately

If abandoning the destination and returning to the source, stop all target
writers first. Explicit app removal on the target can stop its containers and
clear the migration metadata while preserving its data for inspection:

```sh
# On the target, review the resource and DNS removal plan.
helios remove my-app --plan
helios remove my-app --yes

# On the source, explicitly assert that target writers have stopped.
helios move resume my-app --target-stopped --plan
helios move resume my-app --target-stopped --yes
```

Resume restores the original restart policies and only writers that were
running before the fence. It changes no DNS records. Review traffic routing
separately before returning users to the source. The source cannot verify the
remote assertion and contains none of the destination's later writes. A
reverse move is required to preserve those writes before returning service.
A completed destination can be the source of that new move; Helios archives
its previous cutover record before installing the new source fence. The old
source must first become a clean destination, with any retained data handled
explicitly rather than overwritten.

After a successful cutover and the chosen source retention window, remove the
frozen source explicitly. Review its plan: removal takes down its containers
and edge routes, attempts removal of DNS records it owns, and clears its move
records and fence. App data and secrets remain unless requested otherwise;
`--data` removes them too. Backups in shared storage remain.

The older `move out` and `move in` commands remain manual copy workflows.
Their source can keep accepting writes after capture. Use the staged workflow
when transferring final write authority.
