# Helios 0.7.28

This patch stops a first certificate that stalls at the issuer from failing
the deploy of a new host.

- On 0.7.27 the first deploy of a new proxied host could fail at
  `certificates` after three minutes with `remote error: tls: internal error`,
  and the next deploy of the same source passed within seconds. The edge log
  showed the issuer answering "order pending" once and "Certificate not found"
  on the edge's own retry. After that second error the edge ends the job and
  doesn't try again, so the deploy waited for a certificate that was no longer
  on its way.
- While it waits, a host still without a real certificate after 90 seconds now
  has the edge asked to start over: the configuration it already runs is loaded
  again with `Cache-Control: must-revalidate`, which the edge doesn't treat as
  unchanged, so certificate management begins again for the host. That happens
  at most twice per host, and never once a real certificate is served.
- The wait goes from three to five minutes, so the second fresh start has the
  room the first had. The step prints a line each time it asks, and a wait
  that still runs out says how often it asked.
- The certificate step of a move's cutover shares the wait.
- The README describes the wait, and the bypass a host behind a Cloudflare
  Access gate needs for `/.well-known/acme-challenge/*`. Without that bypass
  the issuer's challenge never reaches the edge, and no number of fresh starts
  helps.

No `--json` shape, production dependency, database schema migration, data
relocation or application redeployment changes. A deploy whose host never gets
a certificate now takes five minutes to fail instead of three, and loads the
edge's configuration up to two extra times on the way; each of those loads
starts every app's routes again, as a deploy's own load does.

## Upgrade

0.7.27 to 0.7.28 crosses no lock-path boundary. On each live target,
**personal-vps** and **braintreelabs**, capture
`helios upgrade --version 0.7.28 --plan`, inspect it, then apply its exact
`--digest`.

## Verification

`internal/edge/wait_certificate_test.go` runs the wait with neither an edge
nor a clock: a certificate that arrives leaves the edge alone, one issued only
after a fresh start passes, a host that never gets one costs two fresh starts
and fails at the limit, and a cancelled wait returns within its sleep. On a
throwaway Caddy 2.11.9 an identical plain load answered "config is unchanged"
and the forced one provisioned again. The source passes `make check` with a
short `TMPDIR`.

Not run against a real stalled issuance: the stall depends on the issuer's
timing and couldn't be produced on demand.
