#!/usr/bin/env bash
# M2 on the lane: set the box up, pass the doctor, reconcile as a no-op,
# maintain with a reboot, survive a broken upgrade (systemd rolls it back),
# then take a good one.
#
# Runs against the box as prove-m1 left it (daemon installed) or fresh.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lane/common.sh
. "$here/common.sh"
run() { ssh "${ssh_opts[@]}" "$box" "$@"; }
put() { scp -q "${scp_opts[@]}" "$1" "$box:$2"; }
build() { # build <output> <version>
  (cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go build -trimpath -ldflags "-X github.com/kylebegeman/helios/internal/version.number=$2" -o "$1" ./cmd/helios)
}
phase() { # phase <name> <seconds> [extra proof arguments]
  local name=$1 budget=$2
  shift 2
  python3 "$here/proof_operation.py" --phase "$name" --directory "$proof_dir" --timeout "$budget" "$@" -- ssh "${ssh_opts[@]}" "$box"
}

echo "== build and install"
build "$here/../bin/bedrock-linux-$LANE_ARCH" "0.7.0-dev"
put "$here/../bin/bedrock-linux-$LANE_ARCH" /usr/local/bin/bedrock.new
run 'chmod 755 /usr/local/bin/bedrock.new && mv -f /usr/local/bin/bedrock.new /usr/local/bin/bedrock && bedrock daemon install'

echo "== doctor before setup (failures expected)"
run 'bedrock doctor' || true

echo "== host setup"
# Fresh paths prevent a previous proof's command output from being evidence.
proof_dir=$(run 'mktemp -d /var/lib/bedrock/m2-proof.XXXXXX')
[[ "$proof_dir" =~ ^/var/lib/bedrock/m2-proof\.[a-zA-Z0-9]+$ ]] || { echo "M2 NOT proven: invalid proof directory" >&2; exit 1; }
echo "phase evidence: $proof_dir"
# Preserve the runner's existing 1800-second proof bound for fresh setup.
phase setup 1800

echo "== doctor after setup (must pass)"
run 'bedrock doctor'

echo "== reconcile plan (everything already fine)"
run 'bedrock host reconcile --plan'

echo "== maintain with reboot"
boot_before=$(run 'cat /proc/sys/kernel/random/boot_id')
# /var/run is cleared by a real reboot. Seed the supported reboot-needed
# contract on this guarded disposable guest so an up-to-date image still boots.
run 'touch /var/run/reboot-required'
phase maintain 180 --boot-before "$boot_before"
run 'bedrock doctor'

echo "== broken upgrade (must roll back)"
build "$here/../bin/bedrock-broken" "0.7.0-broken"
put "$here/../bin/bedrock-broken" /tmp/bedrock-broken
phase broken-upgrade 120

echo "== good upgrade (must succeed)"
build "$here/../bin/bedrock-lane" "0.7.0-lane"
put "$here/../bin/bedrock-lane" /tmp/bedrock-lane
phase good-upgrade 120
echo "M2 proven: setup, doctor, reconcile, maintain with reboot, a rolled-back upgrade and a good one"
