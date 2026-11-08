# Helios 0.7.23

This patch stops `helios doctor` from warning about published ports that the
internet can't reach, and checks a published port range one port at a time.

- A port published on a private address is no longer reported as open to
  anyone past ufw. Private addresses are loopback, private ranges, link-local
  and carrier-grade NAT, including a tailnet address in 100.64.0.0/10. On
  personal-vps, Loom Vault's port 8200 is published only on the machine's
  tailnet address, and every `helios doctor` run warned about it and asked
  for a ufw rule. 0.0.0.0, :: and public addresses still count.
- Docker prints consecutive published ports as one range, such as
  `0.0.0.0:3478-3479->3478-3479/udp`. Before this patch the doctor read the
  range as a single port that no ufw rule matches. It warned even when ufw
  allowed both ports, and suggested `ufw allow 3478-3479/udp`, which is not
  ufw's range syntax. Each port in a range is now checked by itself.

In `--json`, `facts.published` leaves out ports published on private
addresses and lists a range port by port. Its shape is unchanged. The README
now names a tailnet address as one way to keep a port off the internet. No new
production dependency, database schema migration, data relocation or
application redeployment is included.

## Upgrade preparation

0.7.22 to 0.7.23 does not cross a lock-path boundary. Only `internal/host`'s
published-port probe and the README changed. `internal/api`, `internal/cli`,
`internal/version`, `internal/state` and `internal/kernel` are unchanged.

The live targets are **personal-vps** and **braintreelabs**. On each, capture
`helios upgrade --version 0.7.23 --plan`, inspect its candidate identity and
all steps, then apply only that plan's exact `--digest`. Afterwards,
`helios doctor` on personal-vps should report no warning for port 8200.

## Verification and publication

Two new probe tests fail against 0.7.22's `internal/host/facts.go`:

- Bindings on loopback, private, link-local and carrier-grade NAT addresses
  are left out, in IPv4 and in both IPv6 forms Docker prints. 0.0.0.0, ::
  and public addresses are listed.
- A range of published ports is listed port by port.

The merged source passes `make check`. On macOS that needs a short `TMPDIR`,
because the socket test's lane temp path exceeds the Unix socket path limit.
