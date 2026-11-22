# Helios 0.7.27

This patch stops one lossy public resolver from failing a machine's checks.

- Checks, the deploy DNS step and certificate probes look names up through a
  public resolver, so a stale answer cached on the machine can't hide a record.
  That lookup asked 1.1.1.1 over UDP and meant to fall back to 8.8.8.8 when
  1.1.1.1 couldn't be reached. A UDP dial never fails, so the fallback never
  ran, and every unanswered query cost five seconds of a check's ten-second
  budget. On 2026-11-21 personal-vps lost about one query in eight to 1.1.1.1
  (1.0.0.1 answered none), and `app:kylebegeman` opened incidents 80, 81 and
  82 with `lookup kylebegeman.com: i/o timeout` and redirect timeouts while the
  site itself was serving normally.
- The lookup now reaches the resolvers over TCP, trying 1.1.1.1 and then
  8.8.8.8 with up to two seconds for each connection, and never more than an
  equal share of the query's time left. TCP resends what the path drops, and a
  resolver that can't be reached fails its connection, so the next one is asked
  within the same query.

On personal-vps, 120 lookups of kylebegeman.com and boop.at through each path:

| Path | Failed | Over 2 s | Median | p95 | Max |
| --- | --- | --- | --- | --- | --- |
| 0.7.26, UDP to 1.1.1.1 | 1 | 30 | 61 ms | 5.07 s | 10.0 s |
| 0.7.27, TCP with fallback | 0 | 0 | 121 ms | 1.14 s | 1.38 s |

No `--json` shape, production dependency, database schema migration, data
relocation or application redeployment changes. A host that blocks outbound
TCP on port 53 while allowing UDP would now fail these lookups; Helios's own
host setup installs no outbound firewall rules.

## Upgrade

0.7.26 to 0.7.27 crosses no lock-path boundary. On each live target,
**personal-vps** and **braintreelabs**, capture
`helios upgrade --version 0.7.27 --plan`, inspect it, then apply its exact
`--digest`.

## Verification

`TestPublicResolverMovesOnFromAnUnreachableResolver` fails against 0.7.26's
dialing (the UDP dial to a closed port succeeds, so the working resolver is
never asked) and passes with the fix. The source passes `make check` with a
short `TMPDIR`.
