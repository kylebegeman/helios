#!/usr/bin/env bash
# Peer watch on the lane. The daemon answers its peers on loopback, at a
# port no edge uses: a request without a registered key gets 401 and the
# Helios-Peer header, a registered key gets this machine's summary, a view
# pushed with it is taken with 204, and the daemon's own API isn't there. A
# second state directory on the guest, with no daemon of its own, plays the
# Mac: its key is registered with the daemon, and helios peer observe reads
# the summary and pushes what it saw, the way launchd runs it. peer ls shows
# names and public URLs, never an address or a key. With the daemon stopped
# the Mac finds its summary refused, and answered again once it starts.
# Through all of it, neither the daemon's journal nor helios alerts --json
# holds the port or the listen address.
#
# A second daemon on the guest would share the first's hooks socket, so two
# servers paging once is proven by TestTwoObserversPageOnce instead, and
# what a daemon says over many failed rounds by TestNoMeshAddressLeaves.
#
# Needs the lane after prove-m2.sh, without peer watch set up.
set -euo pipefail
umask 077
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lane/common.sh
. "$here/common.sh"
run() { ssh "${ssh_opts[@]}" "$box" "$@"; }
put() { scp -q "${scp_opts[@]}" "$1" "$box:$2"; }
fail() { echo "PEER NOT proven: $*" >&2; exit 1; }

port=47731 # where the daemon answers its peers: not 80, 443 or another edge port
listen="127.0.0.1:$port"
# The port as a number on its own; the listen address holds it too.
port_re="(^|[^0-9])$port([^0-9]|\$)"
remote_work="/var/lib/bedrock/lane-peer/$LANE_ID"
observer="$remote_work/mac" # the Mac's state directory
work=$(mktemp -d "${TMPDIR:-/tmp}/bedrock-peer.XXXXXX")
started=false

# undo puts the guest back as the proof found it: the daemon running and
# peer watch not set up. A step with nothing to do is skipped, so it also
# clears what a run that was killed left behind.
undo() {
  run "sh -s -- '$remote_work'" <<'UNDO' || true
systemctl start bedrock >/dev/null 2>&1 || true
for key in PEER_LIST PEER_OBSERVERS PEER_TOKEN; do
  bedrock secret remove bedrock "$key" >/dev/null 2>&1 || true
done
rm -rf "$1"
UNDO
}
cleanup() {
  if [[ "$started" == true ]]; then undo; fi
  rm -rf "$work"
}
trap cleanup EXIT

# expect <what> <want> <got> shows what a step got, and fails unless it is
# what was wanted.
expect() {
  echo "-- $1: $3"
  [[ "$3" == "$2" ]] || fail "$1 gave $3, not $2"
}
# ask <path> [curl args] prints the status the guest's request to the peer
# listener got, then " peer" when the answer carries Helios-Peer; 000 when
# nothing answered.
ask() {
  local path=$1
  shift
  run ": >'$remote_work/headers'; curl -s -o /dev/null -D '$remote_work/headers' -w '%{http_code}' --max-time 10 $* 'http://$listen$path'; grep -qi '^helios-peer: ' '$remote_work/headers' && printf ' peer'; true"
}
# probe is the curl arguments that present the probe's key, which stays on
# the guest.
probe="-H @'$remote_work/probe.header'"
# mac runs helios as the Mac does: from its own state directory, with no
# daemon to ask.
mac() { run "bedrock --state-dir '$observer' --socket '$observer/no.sock' $*"; }
# clean <what> <file> fails if the file holds the port, and so where the
# daemon listens, or a key.
clean() {
  if grep -nE "$port_re|hp1_" "$2" >&2; then fail "$1 names where web1 listens, or holds a key"; fi
  echo "-- $1: no port, listen address or key in $(wc -l <"$2" | tr -d ' ') lines"
}

echo "== build and install"
(cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go build -trimpath -o "bin/bedrock-linux-$LANE_ARCH" ./cmd/helios)
put "$here/../bin/bedrock-linux-$LANE_ARCH" /usr/local/bin/bedrock.new
run 'chmod 755 /usr/local/bin/bedrock.new && mv -f /usr/local/bin/bedrock.new /usr/local/bin/bedrock && bedrock daemon install >/dev/null && bedrock version'

echo "== the guest has no peer watch of its own, and nothing on port $port"
if run "test -e '$remote_work/started'"; then
  echo "-- a run that was stopped left $remote_work behind; putting the guest back first"
  undo
fi
names=$(run 'bedrock secret list bedrock --json' | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["names"] or []))')
[[ " $names " != *" PEER_LIST "* ]] || fail "peer watch is set up here, and the proof sets up its own; remove it with bedrock secret remove bedrock PEER_LIST (and PEER_OBSERVERS, PEER_TOKEN), then run the proof again"
if run "ss -ltn | awk '{print \$4}' | grep -qE ':$port\$'"; then fail "something listens on port $port"; fi
since=$(run 'date +%s')
run "install -d -m 700 '$remote_work' && touch '$remote_work/started'"
started=true

echo "== web1 answers its peers on loopback; the Mac watches it and may read it"
# web1 only answers here and watches no peer, so its self-check, which fails
# for want of a public name, judges nothing.
run "bedrock peer init --name web1 --listen $listen --public https://web1.example.test"
# As root on the guest, helios keeps its secrets key at the guest's own key
# path whatever the state directory, so the Mac seals its peer setup with
# the guest's key and only that setup is new: no key is made, and no
# recovery identity is shown. The Mac's first run, which makes a key, isn't
# proven here. The sed is a guard: should a run ever make a key, the
# identity it shows stays out of the proof's output.
mac peer init --name mac 2>&1 | sed 's/AGE-SECRET-KEY-1[A-Z0-9]*/AGE-SECRET-KEY-1.../'
mac peer add web1 --mesh "$listen" --public https://web1.example.test
mac_key=$(mac peer key)
[[ "$mac_key" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "helios peer key printed $mac_key, not a fingerprint"
run "bedrock peer add mac --key $mac_key"
# curl's key is made and kept on the guest; only its fingerprint comes back.
probe_key=$(run "sh -s -- '$remote_work'" <<'PROBE'
set -eu
umask 077
token="hp1_$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf 'Authorization: Bearer %s\n' "$token" >"$1/probe.header"
printf '{"self_check":true,"sends":false,"views":[]}' >"$1/view.json"
printf 'sha256:%s\n' "$(printf %s "$token" | sha256sum | cut -d' ' -f1)"
PROBE
)
run "bedrock peer add probe --key $probe_key"

echo "== the listener answers only a registered key, and only peer watch's two routes"
for _ in $(seq 1 24); do
  [[ "$(ask /peer/v1/summary)" == "401 peer" ]] && break
  sleep 5
done
expect "the summary, with no key" "401 peer" "$(ask /peer/v1/summary)"
expect "the summary, with a key nobody registered" "401 peer" "$(ask /peer/v1/summary "-H 'Authorization: Bearer hp1_nobody'")"
expect "the summary, with the probe's key" "200 peer" "$(ask /peer/v1/summary "$probe")"
expect "the daemon's API, with the probe's key" "404 peer" "$(ask /v1/apps "$probe")"
expect "a view pushed with the probe's key" "204 peer" "$(ask /peer/v1/view "$probe -H 'Content-Type: application/json' --data-binary @'$remote_work/view.json'")"
run "curl -sf --max-time 10 $probe http://$listen/peer/v1/summary" >"$work/summary.json" || fail "the probe's key didn't get the summary"
python3 - "$work/summary.json" <<'PY' || fail "the summary isn't web1's, with every field"
import json, sys
summary = json.load(open(sys.argv[1]))
missing = [k for k in ("name", "version", "last_round_age_s", "self_check", "incidents", "sending", "backups", "legs", "findings", "views") if k not in summary]
assert not missing, f"missing {missing}"
assert summary["name"] == "web1" and summary["version"], summary
for k in ("incidents", "backups", "findings", "views"):
    assert isinstance(summary[k], list), f"{k} is {summary[k]!r}"
print(f"-- the summary: web1 at {summary['version']}, last round {summary['last_round_age_s']}s ago, "
      f"{len(summary['incidents'])} open, {len(summary['backups'])} apps, disk {'reported' if 'disk' in summary else 'left out'}")
PY

echo "== the Mac reads web1 and pushes what it saw"
line=$(mac peer observe) || fail "helios peer observe failed"
echo "-- the Mac: $line"
[[ "$line" == "web1: summary ok, "*"; view sent" ]] || fail "the Mac didn't read web1 and push its view"

echo "== peer ls shows names and public URLs, never an address or a key"
{ run 'bedrock peer ls; bedrock peer ls --json'; mac peer ls; mac peer ls --json; } | tee "$work/ls.txt"
expect "web1's readers" "mac probe" "$(run 'bedrock peer ls --json' | python3 -c 'import json,sys; print(" ".join(r["name"] for r in json.load(sys.stdin) if r["reads_this_machine"] and not r["watched"]))')"
expect "the Mac's watched peers" "web1 https://web1.example.test" "$(mac peer ls --json | python3 -c 'import json,sys; print(" ".join(r["name"] + " " + " ".join(r["public"]) for r in json.load(sys.stdin) if r["watched"]))')"
if grep -nE '127\.0\.0\.1|sha256:' "$work/ls.txt" >&2; then fail "peer ls shows an address or a key"; fi
clean "peer ls" "$work/ls.txt"
clean "the summary" "$work/summary.json"

echo "== with the daemon stopped, the Mac finds web1's summary refused"
run 'systemctl stop bedrock'
line=$(mac peer observe) || fail "helios peer observe failed"
echo "-- the Mac: $line"
[[ "$line" == "web1: summary refused, "* ]] || fail "the Mac didn't find web1's summary refused"
run 'systemctl start bedrock'
for _ in $(seq 1 12); do
  line=$(mac peer observe) || fail "helios peer observe failed"
  [[ "$line" == "web1: summary ok, "* ]] && break
  sleep 5
done
echo "-- the Mac, with the daemon started: $line"
[[ "$line" == "web1: summary ok, "*"; view sent" ]] || fail "the Mac didn't read web1 again once its daemon started"

echo "== neither the daemon's journal for the run nor helios alerts --json names where it listens"
run "journalctl -u bedrock --since @$since --no-pager -o cat" >"$work/journal.txt"
grep 'peer listener' "$work/journal.txt" || true
grep -q '^peer listener: listening for peers$' "$work/journal.txt" || fail "the journal doesn't say the listener started"
clean "the daemon's journal" "$work/journal.txt"
run 'bedrock alerts --json' >"$work/alerts.json"
clean "helios alerts --json" "$work/alerts.json"

echo "Peer watch proven: the listener on loopback answers only a registered key, with 401 and Helios-Peer otherwise, serves the summary with every field, takes a pushed view with 204 and serves none of the daemon's API; a Mac-style observer reads it and pushes its view; peer ls shows names and public URLs only; with the daemon stopped the Mac finds its summary refused, and answered once it starts; and neither the journal nor helios alerts --json names the port or the listen address"
