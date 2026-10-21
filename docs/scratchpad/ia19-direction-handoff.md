# IA-19 direction handoff

For the owner of `loom-platform/docs/direction.md`. Kyle routes this note;
nothing in helios edits that file.

## What changed

IA-19 is delivered in helios as peer watch, the Slice 1 external heartbeat.
Servers that run Helios watch each other every minute three ways: a summary
from the peer's Helios over the mesh, the peer's edge over the mesh, and its
public URLs from the outside. A machine that is down, or whose Helios has
stopped, is paged once, by one healthy machine, when the machines watching it
agree. A Mac adds its own view and never pages. The summary also carries the
peer's dead-man signals: stale backups, overdue restore drills and alert legs
that have delivered nothing in 8 days.

Peer watch can't cover everything down at once: when every server is down,
none is left to page, and the Mac never sends. IA-02's UptimeRobot covers
that case.

## Replacement text

Where `direction.md` describes the external heartbeat as open or planned,
replace it with:

> IA-19 is Slice 1's external heartbeat. Servers that run Helios watch each
> other over the mesh, their edges and their public URLs, and one healthy
> machine pages when another is down or its Helios has stopped. A Mac adds a
> view and never pages. IA-02's UptimeRobot covers everything down at once.

Where it assigns "everything down" to IA-19, assign it to IA-02's UptimeRobot.

## Where

The design cites `docs/direction.md` lines 438, 935 and 943. Those lines were
not checked: `loom-platform` is not part of this checkout. Confirm each one
says what the replacement assumes before editing.

## In helios

- [docs/features/peer-watch.md](../features/peer-watch.md): setup, what each
  finding means, and who pages.
- [lane/README.md](../../lane/README.md#peer-watch-proof): the lane proof.
- The release ships as a patch, with no schema change.
