# Peer watch

A machine that is down sends no alerts: its watcher stops with it. Peer watch
has the machines that run Helios watch each other, so a healthy one tells you
when another goes quiet. Every minute each server looks at each of its peers
three ways, decides what the answers mean, and one machine pages for all of
them. A Mac can add a third view every minute; it never pages.

The machines reach each other over the mesh, a private network between them
such as a Tailscale tailnet. Each server answers its peers on its mesh IP
address, at a port of its own beside the edge.

## Setup

For two servers, `web1` and `web2`, and a Mac:

```
web1$ helios peer init --name web1 --listen <web1 mesh ip>:7700 --public https://web1.example.test
web2$ helios peer init --name web2 --listen <web2 mesh ip>:7700 --public https://web2.example.test
web1$ helios peer add web2 --mesh web2.mesh.example.test:7700 --public https://web2.example.test --key sha256:<web2>
web2$ helios peer add web1 --mesh web1.mesh.example.test:7700 --public https://web1.example.test --key sha256:<web1>
mac$  helios peer init --name mac
mac$  helios peer add web1 --mesh web1.mesh.example.test:7700 --public https://web1.example.test
mac$  helios peer add web2 --mesh web2.mesh.example.test:7700 --public https://web2.example.test
web1$ helios peer add mac --key sha256:<mac>      # and on web2
mac$  helios peer observe --install
```

`helios peer init` names the machine to its peers and makes its peer key. It
prints the key's fingerprint, the `sha256:` value each peer registers, and
`helios peer key` prints it again later. The key itself never leaves the
machine. A server also gives:

- `--listen`: where it answers its peers, as its mesh IP address and a port.
  Loopback works for a test. A name, an address off the mesh, and ports 80
  and 443, which the edge serves, are refused.
- `--public`: its own public URL, repeatable. Each round it checks this first,
  so a server whose own way out is broken doesn't blame its peers.

`helios peer add <name>` does one or both of two things:

- With `--mesh` and `--public`, this machine watches the peer. `--mesh` is
  where the peer answers on the mesh: its mesh name or mesh IP address, and
  the port it listens on.
- With `--key`, the peer may read this machine. A server pair needs both
  directions; the Mac only reads, so each server registers its key and the
  Mac watches without `--key`.

Adding a name again updates it. `helios peer rm <name>` stops watching a peer
and stops letting it read this machine; an alert open about it resolves
without a page. `helios peer ls` lists each peer by name, what it is to this
machine, and its public URLs. It never shows a mesh address or a key, and
neither does any alert, log or summary.

The daemon follows these changes on its own: it starts answering within 30
seconds and watches a new peer from its next round. Nothing needs a restart.

On a machine with no Helios secrets yet, such as the Mac, `helios peer init`
first makes the secrets key and prints its recovery identity once. Keep it
with the machine's other recovery material.

### The firewall

If ufw filters the mesh interface, each server must let its peers reach the
port it listens on. Helios does not add this rule:

```sh
ufw allow in on tailscale0 to any port 7700 proto tcp
```

The edge check uses port 443, which needs no rule: Docker forwards the edge's
port past ufw, and the guard `helios host setup --web-from cloudflare` puts
in front of it lets private networks, the mesh among them, through.

### Keys

`helios peer key --rotate` replaces this machine's key and prints the new
fingerprint. Register it on every peer with `helios peer add <name> --key
sha256:<new>`; until then they refuse this machine and report it as not
trusted.

A machine recovered from a backup or set up again starts without peer watch.
Run `helios peer init` there, add its peers again, and register its new key
on each of them.

## What each server checks

| Path | What it asks |
|---|---|
| Summary | The peer's Helios, over the mesh, for a short summary of the machine, presenting this machine's key. |
| Edge on the mesh | The peer's edge, over the mesh, for its certificate for the peer's first public URL. |
| Public | Each of the peer's public URLs, from the outside, as `helios watch` checks a URL. |

Each path ends in one word: `ok`, `timeout`, `refused`, `reset`, `dns`,
`tls`, `status 502` and the like, `unreachable` or `failed`. A summary can
also be `stale` (its last round is over 5 minutes old), `untrusted` (the peer
refuses this machine's key) or `mismatch` (another machine answered). Nothing
else from an error is kept, which is how an address stays out of every alert.

## What the answers mean

| What answers | What it means | Severity |
|---|---|---|
| The summary, its edge and a public URL | Healthy. | None, unless its summary shows something quietly wrong (below). |
| The summary, but not its edge, or not its public URLs | Edge degraded: Helios runs, but the edge, or the way in from the internet, does not. | Warning. |
| Its edge on the mesh, but not the summary; or a stale summary | Peer watcher down: the machine is up but its Helios is stopped or stuck, so it cannot send its own alerts. | Warning, critical after 15 minutes. |
| Only its public URLs | Mesh degraded: the mesh can't reach it, but it serves. | Warning, always. |
| Nothing | Host down. | Critical when the observers agree, otherwise a warning. |
| A summary that refuses this machine's key, or names another machine | Not trusted: register the keys, or fix the mesh address. | Warning. |
| No summary, ever, since the peer was added | Never seen: check the mesh address it was added with, and that it listens there. | Warning, never critical. |

A broken mesh alone never pages: a failing tailnet makes warnings, not
outages. A peer that has never answered stays a warning too, so a mistyped
address can't page.

Two rules look at the whole round first:

- **This machine cut off.** When this machine can't reach its own public URL
  or any peer, and no Mac view arrived in the last 3 minutes, it raises one
  warning about itself and holds every peer finding as it is: it pages
  nothing about its peers and resolves nothing.
- **The edge provider.** When every peer's public URL fails while the mesh
  reaches them, and there are at least two peers or this machine's own public
  check fails too, it raises one warning that the edge provider or this
  machine's internet is degraded, in place of one per peer.

## What the summary shows

A peer's summary also shows what is quietly wrong there, the things a machine
that can't send alerts would never tell you:

- **A stale backup**: an app's last good backup is over 36 hours old, or it
  was deployed over 36 hours ago and never backed up. The machine's own state
  backup counts.
- **An overdue drill**: an app's restore drill is more than a day past due,
  by the peer's own clock.
- **Silent alerts**: one of the peer's ways of sending alerts has delivered
  nothing in 8 days, or never has. The weekly test alert keeps a working way
  inside that. The alert then names what the peer has open, since nobody may
  have heard about it.

These are warnings, and join the peer's one alert:

```
web1: web2 has a problem
its last good backup of shop is 3 days old; its pushover alerts have not worked in 9 days; open there: shop (warning)
```

## When it pages

A peer's finding is an alert like any other: it must hold three rounds to
open, and two good rounds to recover. A host down pages about 3 minutes after
the first round that found it. A peer watcher down warns at about 3 minutes,
and is told again as critical at about 17.

**Agreement.** Host down is critical only when most of the machines watching
the peer, not counting the peer itself, see all three paths fail. These
machines count:

- this machine, when its own public check passed;
- each other server whose summary arrived this round, when its own public
  check passed and its view of the peer is under 3 minutes old;
- the Mac, when it sent a view of the peer in the last 3 minutes and reached
  something on that run.

With two servers and no Mac, the watching server alone decides, since its
mesh and public paths are two independent answers that agree. With the Mac's
view fresh, the Mac must agree too. A peer watcher down goes critical the
same way, once 15 minutes have passed since its last good summary, or since
this daemon started if that is later.

**Who sends.** Every server that finds a problem opens its own alert, but one
machine sends it: of the servers that see the problem at least as gravely,
whose own public check passes and whose ways of sending alerts have each
delivered something in 8 days, the one with the lowest name. Never the peer
the alert is about, and never the Mac. If no server qualifies on its alerts,
that rule is dropped; if none qualifies still, each server sends its own.

The others wait, and once the sender has told it, they record who did. If
the sender hasn't told it within 5 minutes, or every way it sends alerts
failed, a waiting server sends it through its own ways; while the sender is
still sending it, they wait up to 5 minutes more. A server that can't be
reached is never elected, so then the page goes out at once. Every machine's
alert about one peer carries the same Pushover tag, so a recovery from any of
them stops the ringing any of them started. The recovery goes once, from the
machine that first sent the alert at its worst severity.

On the server that sent it, `helios alerts` says when it told you, as for any
alert. Another server says who it waits for, then who sent it. With three
servers and `web2` down, `web3` shows while `web1` sends:

```
OPEN  web2 (critical) since 2026-10-20 15:01: no answer over the mesh, from its edge on the mesh, or at its public URLs (summary: timeout, edge: timeout, public: timeout)
      web1 is to send this (waiting since 15:04)
```

and once `web1` has told it:

```
OPEN  web2 (critical) since 2026-10-20 15:01: no answer over the mesh, from its edge on the mesh, or at its public URLs (summary: timeout, edge: timeout, public: timeout)
      sent by web1 at 15:04
```

## The Mac

`helios peer observe` looks at every server once, the same three ways, tells
each server what it saw, and prints a line per server:

```
web1: summary ok, edge ok, public ok; view sent
web2: summary timeout, edge timeout, public timeout; view not sent (timeout)
```

It exits 0 even when a server can't be reached, since the servers judge
silence. `--json` prints an object per server.

`helios peer observe --install` has launchd run it every minute on macOS with
`--changes`, which prints the lines, each with the time, only when they
differ from the last run. Its log at `~/Library/Logs/helios-peer-observe.log`
then grows only when something changes. `--uninstall` stops it and removes
the launch agent. Elsewhere, run `helios peer observe --changes` from cron.

Each server counts the Mac's view for 3 minutes. Once the Mac has sent one, a
server warns when none has come for 10 minutes, as `mac has sent no views for
25 min`. A Mac that sleeps warns while it sleeps; `helios peer rm mac` on the
servers stops counting it.

## What it does not cover

- **Everything down at once.** When every server is down, none is left to
  page, and the Mac never sends. An uptime service outside your machines,
  such as UptimeRobot checking each public URL, covers that.
- **A peer's own alerts.** A peer's app, disk and backup alerts are its own to
  send. Peer watch names them only when the peer's ways of sending alerts are
  silent, since then nobody may have heard about them.
- **A machine Helios doesn't run.** `helios watch add` still checks a public
  URL anywhere. For a machine that runs Helios, peer watch checks its URLs too
  and knows whether the machine behind them is up.

The listener speaks plain HTTP and relies on the mesh's encryption. It
answers only requests from the mesh or loopback, only with a registered key,
and only its two routes: the summary and the views a Mac or a peer sends.
[The lane proof](../../lane/README.md#peer-watch-proof) checks it on a
disposable machine.
