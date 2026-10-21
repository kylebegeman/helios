# Security Policy

## Supported versions

Helios is pre-1.0. Fixes land on the default branch, `next`, and ship as
the next 0.7.x patch release; there are no backports.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting on the repository; if it is not enabled,
open a minimal public issue asking for it to be, with no details.

Please include the version or commit, the command or component, the impact
and likely path, reproduction steps using fixture data, and whether any
secret, token, hostname or production data may have been exposed.

Secret exposure, command injection, a restore that could replace the keys
data was written with, a deploy that runs without the plan that was
approved, a guarded route served open, and DNS or edge changes that reach
another machine's traffic are treated as high priority.

## What to know about the design

- Secrets are sealed with age to a key the machine holds at
  `/etc/bedrock/secrets.key`, mode 0600. Values never appear in arguments,
  logs, receipts or backups; only names do. The recovery identity is shown
  once, when the key is made.
- Releases are static binaries published with `SHA256SUMS` and
  `SHA256SUMS.sig`, an SSH signature by a release key every build pins.
  `helios upgrade --version` and `scripts/install-release.sh` refuse a
  release whose sums that key didn't sign. `--sha256` pins a checksum from
  reviewed source instead, which also installs a release from before 0.7.16.
- The daemon listens on `/run/bedrock/bedrock.sock`, mode 0660, owned by
  root and the `bedrock` group that receives pushes. The edge's admin API is
  a Unix socket only the machine reaches.
- A machine's address is not treated as a secret. `helios host setup
  --web-from cloudflare` lets only Cloudflare's proxy reach 80 and 443, so
  the address serves nothing on the web to anyone who finds it; every route
  must then be `dns: proxied`. Docker forwards published ports past ufw,
  so the rule that holds is a guard in Docker's `DOCKER-USER` chain, which
  `helios doctor` checks. SSH stays reachable, keys only, behind fail2ban.
- Letting only Cloudflare reach the machine still lets in any Cloudflare
  zone pointed at its address. A proxied host with `origin_pull: required`
  takes only connections presenting the client certificate `helios edge
  origin-pull mint` made for it, checked against a CA trusted for that host
  alone. The CA's key is thrown away once it has signed, and the
  certificate's key exists only in the file uploaded to Cloudflare. The CA
  of Cloudflare's global origin-pull certificate, which every Cloudflare
  account presents, must never be given to `helios edge origin-pull trust`.
- A backup runs restic in a container. The repository password and the
  storage credentials reach it in a file only root reads, mounted read-only
  for the length of the run and removed with it, never in the container's
  environment, which Docker would keep on disk and show to anyone who can
  inspect the container.

## Secret handling in contributions

Never submit real secrets, `.env` values, private keys, provider tokens,
host addresses, personal paths or production payloads. Use secret names,
fixture values and `example.com` domains.
