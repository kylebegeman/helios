#!/usr/bin/env bash
# M1 on the lane: install the daemon, run an operation through it, kill the
# daemon halfway, and show that systemd brings it back and the operation
# finishes with the interruption on its receipt.
#
# Run after lane/reset.sh: the box is fresh, the binary goes over by scp.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lane/common.sh
. "$here/common.sh"
run() { ssh "${ssh_opts[@]}" "$box" "$@"; }

echo "== build and copy"
(cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go build -trimpath -o bin/bedrock-linux-$LANE_ARCH ./cmd/helios)
# A running daemon keeps the old binary busy, so copy beside it and rename
# over it: the running process keeps its inode, the next start gets the new one.
scp -q "${scp_opts[@]}" "$here/../bin/bedrock-linux-$LANE_ARCH" "$box:/usr/local/bin/bedrock.new"
run 'chmod 755 /usr/local/bin/bedrock.new && mv -f /usr/local/bin/bedrock.new /usr/local/bin/bedrock && bedrock version'

echo "== install the daemon"
run 'bedrock daemon install && bedrock daemon status'

echo "== run and interrupt an admitted exercise during its third step"
proof_dir=$(run 'mktemp -d /var/lib/bedrock/m1-proof.XXXXXX')
[[ "$proof_dir" =~ ^/var/lib/bedrock/m1-proof\.[a-zA-Z0-9]+$ ]] || { echo "M1 NOT proven: invalid proof directory" >&2; exit 1; }
echo "phase evidence: $proof_dir"
python3 "$here/proof_operation.py" --phase exercise --directory "$proof_dir" --timeout 90 -- ssh "${ssh_opts[@]}" "$box"
echo "M1 proven: the killed daemon's operation was resumed and finished (interrupted once), with six markers"
