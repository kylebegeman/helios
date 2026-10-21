#!/usr/bin/env bash
# Journald logs on the lane: host setup keeps the journal for two weeks in
# at most 1G, an app's workload logs to it, and its output outlives the
# container: a retired revision's logs read back by revision, and a
# finished one-off command's by job, beyond the 40 lines kept with the run.
# The Engine still serves the live container's logs from the journal.
#
# Needs the lane after prove-m2.sh: Docker, the daemon and journald. No
# public DNS: the fixture is a worker with no route.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lane/common.sh
. "$here/common.sh"
run() { ssh "${ssh_opts[@]}" "$box" "$@"; }
put() { scp -q "${scp_opts[@]}" "$1" "$box:$2"; }
quiet() { grep -v '^  \.\.\.  ' || true; }
fail() { echo "JOURNALD NOT proven: $*" >&2; exit 1; }
# gone <container> fails unless Docker has no container of that name.
gone() {
  local names
  names=$(run "docker ps -a --format '{{.Names}}'")
  ! grep -qx -- "$1" <<<"$names" || fail "$1 is still there"
}
# worker <field> prints the running hello worker's revision or container.
worker() { run 'bedrock ps --json' | python3 -c 'import json,sys; print(next((r[sys.argv[1]] for r in json.load(sys.stdin) or [] if r["app"]=="hello" and r["workload"]=="worker"), ""))' "$1"; }
# worker_manifest <mark> has the worker print the mark once, then wait for
# Docker to stop it.
worker_manifest() {
  run 'mkdir -p /srv/lane/journald && cat >/srv/lane/journald/helios.yaml' <<YAML
app: hello
workloads:
  worker:
    kind: worker
    image: busybox:1.37
    command: [sh, -c, 'echo $1; trap "exit 0" TERM INT; while :; do sleep 10 & wait "\$!"; done']
YAML
}
# shows <line> <command...> waits up to 30 seconds for the command to print
# exactly that line, the time the journal may take to have it.
shows() {
  local line=$1 out
  shift
  for _ in $(seq 1 15); do
    out=$("$@" 2>&1) || true
    grep -qx -- "$line" <<<"$out" && return 0
    sleep 2
  done
  printf '%s\n' "$out" | tail -5 >&2
  return 1
}

echo "== build and install; reconcile writes the journald drop-in"
(cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go build -trimpath -o "bin/bedrock-linux-$LANE_ARCH" ./cmd/helios)
put "$here/../bin/bedrock-linux-$LANE_ARCH" /usr/local/bin/bedrock.new
run 'chmod 755 /usr/local/bin/bedrock.new && mv -f /usr/local/bin/bedrock.new /usr/local/bin/bedrock && bedrock daemon install >/dev/null && bedrock version'
run 'bedrock host reconcile --yes' | quiet | grep -E "journal|succeeded|failed"
dropin=$(run 'cat /etc/systemd/journald.conf.d/bedrock.conf')
grep -qx 'SystemMaxUse=1G' <<<"$dropin" && grep -qx 'MaxRetentionSec=14day' <<<"$dropin" \
  || fail "the journald drop-in doesn't keep 1G for 14 days: $dropin"
doctor=$(run 'bedrock doctor' 2>&1) || true
grep -F 'journal capped' <<<"$doctor" || true
grep -qF 'journal capped at 1G for 14day' <<<"$doctor" || fail "doctor doesn't say the journal is capped at 1G for 14day"

echo "== deploy a worker that prints mark-A"
worker_manifest mark-A
run 'bedrock deploy /srv/lane/journald --yes' | quiet | tail -3
rev1=$(worker revision)
container1=$(worker container)
[[ -n "$rev1" && -n "$container1" ]] || fail "hello's worker isn't running"
driver=$(run "docker inspect -f '{{.HostConfig.LogConfig.Type}}' $container1")
echo "-- $container1 logs to $driver"
[[ "$driver" == journald ]] || fail "$container1 logs to $driver, not journald"
shows mark-A run "docker logs $container1" || fail "docker logs doesn't show mark-A from $container1"

echo "== a second revision prints mark-B and retires the first"
worker_manifest mark-B
run 'bedrock deploy /srv/lane/journald --yes' | quiet | tail -3
rev2=$(worker revision)
container2=$(worker container)
[[ -n "$rev2" && "$rev2" != "$rev1" ]] || fail "the second deploy didn't replace revision $rev1"
gone "$container1"
echo "-- $container1 is gone; $rev2 runs in $container2"

echo "== the retired revision's logs, from the journal"
past=$(run "bedrock logs hello --revision $rev1")
printf '%s\n' "$past"
grep -qx mark-A <<<"$past" || fail "bedrock logs --revision $rev1 doesn't show mark-A"
grep -qx mark-B <<<"$past" && fail "bedrock logs --revision $rev1 shows the next revision's mark-B"
# Evidence and a revision gc forgot are read by these fields, not by name.
labelled=$(run "journalctl --no-pager --output=cat BEDROCK_APP=hello BEDROCK_WORKLOAD=worker BEDROCK_REVISION=$rev1")
grep -qx mark-A <<<"$labelled" || fail "the journal doesn't carry hello's app, workload and revision on $container1's lines"

echo "== the running revision's logs, through the Engine"
shows mark-B run 'bedrock logs hello worker' || fail "bedrock logs hello worker doesn't show mark-B"
shows mark-B run "docker logs $container2" || fail "docker logs doesn't show mark-B from $container2"

echo "== a one-off command's 60 lines outlive its container"
run "bedrock run hello worker -- sh -c 'for i in \$(seq 1 60); do echo job-line-\$i; done'" | quiet | tail -2
run 'bedrock jobs hello --limit 1'
job=$(run 'bedrock jobs hello --json --limit 1' | python3 -c 'import json,sys; r=(json.load(sys.stdin) or [{}])[0]; print(r.get("id",""), r.get("container",""))')
read -r job_id job_container <<<"$job"
[[ -n "$job_id" && -n "$job_container" ]] || fail "bedrock jobs hello doesn't list the run"
gone "$job_container"
output=$(run "bedrock logs hello --job $job_id --tail all")
printf '%s\n' "$output" | sed -n '1p;$p'
grep -qx job-line-1 <<<"$output" && grep -qx job-line-60 <<<"$output" \
  || fail "bedrock logs --job $job_id doesn't show all 60 lines from the journal"

echo "== clean up"
run 'bedrock remove hello --yes' | quiet | tail -1
run 'rm -rf /srv/lane/journald'

echo "Journald logs proven: the journal keeps 1G for 14 days; a retired revision's logs read back by revision and a finished job's by id, past the 40 lines kept with the run; the Engine still serves the live container's logs"
