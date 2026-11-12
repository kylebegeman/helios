# Helios 0.7.24

This patch gives Docker room for more than 31 networks, so drills, machine
recovery, release rehearsals and new apps stop failing on a machine with many
apps.

- Docker's default address pools hold 31 networks, and every app takes two:
  its own network and its edge network. personal-vps runs eighteen apps, so
  every pool was in use. Since then, a drill, a machine recovery or a release
  rehearsal could not make its network, and failed with "all predefined
  address pools have been fully subnetted". The scheduled begamin drill
  failed this way, and so did a loom-library rehearsal.
- Host setup now writes `default-address-pools` into `/etc/docker/daemon.json`.
  Docker's own pools come first and unchanged, so each existing network keeps
  its subnet. 10.200.0.0/16, split into 256 /24s, follows them. It overlaps
  none of Docker's pools and no subnet personal-vps routes.
- When `daemon.json` differs, the docker step's plan note now says Docker
  restarts and live restore keeps containers running. Before this patch the
  note said "already" even when the step would restart Docker.

No `--json` shape, production dependency, database schema migration, data
relocation or application redeployment changes.

## Upgrade preparation

0.7.23 to 0.7.24 does not cross a lock-path boundary. Only `internal/host`'s
setup step and the README changed. `internal/api`, `internal/cli`,
`internal/version`, `internal/state` and `internal/kernel` are unchanged.

The live targets are **personal-vps** and **braintreelabs**. On each, capture
`helios upgrade --version 0.7.24 --plan`, inspect its candidate identity and
all steps, then apply only that plan's exact `--digest`.

The upgrade alone leaves `daemon.json` alone. On personal-vps, capture
`helios host reconcile --plan`, check that only the docker step changes
anything, and apply it outside the backup windows with no operation running.
Docker restarts once and live restore keeps containers running. Afterwards,
run a real `helios drill` without an explicit subnet. braintreelabs takes the
pools at its next reconcile.

## Verification and publication

Two new setup tests fail against 0.7.23's `internal/host/setup.go`:

- The daemon settings keep Docker's seven default pools first and in order,
  add 10.200.0.0/16 by /24, and hold 31 + 256 networks with live restore.
- A machine with the older `daemon.json` gets a plan note that Docker
  restarts, gets the new file, restarts Docker once, and then plans "already".

The merged source passes `make check`. On macOS that needs a short `TMPDIR`,
because the socket test's lane temp path exceeds the Unix socket path limit.
