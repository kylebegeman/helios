#!/usr/bin/env bash
# Signed deploys on the lane: an app that requires signed commits deploys a
# pushed tip an allowed SSH key signed, and refuses an unsigned tip, a key
# nobody allowed, a GPG signature, an SSH signature made for another
# namespace, a replace ref and an uploaded tree, building nothing of them. An app that
# doesn't require signatures deploys as before. A webhook delivery needs a
# routed app and public DNS (m6 covers it on a dedicated machine), so the
# webhook's check runs here through the gitdeploy tests, on the box's own
# git and OpenSSH, as root the way the daemon runs it. First the daemon on
# its own, then reconcile, let the push user through /etc/bedrock to the
# policy without listing it.
set -euo pipefail
umask 077
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lane/common.sh
. "$here/common.sh"
run() { ssh "${ssh_opts[@]}" "$box" "$@"; }
put() { scp -q "${scp_opts[@]}" "$1" "$box:$2"; }
quiet() { grep -v '^  \.\.\.  ' | grep -v '^remote:   \.\.\.  ' || true; }
fail() { echo "SIGNED NOT proven: $*" >&2; exit 1; }
field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
# This Mac's own git configuration, which may sign with an agent, stays out.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
unset SSH_AUTH_SOCK

work=$(mktemp -d "${TMPDIR:-/tmp}/bedrock-signed.XXXXXX")
for key in push sign stranger; do
  ssh-keygen -q -t ed25519 -N "" -C "lane $key key" -f "$work/$key-key"
done
cleanup() {
  run "bedrock git require-signed hello --off --yes; bedrock git signers remove lane@example.test --yes; for app in hello notes; do bedrock git deny \$app '$(cat "$work/push-key.pub")'; done" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
push_ssh=$(printf '%q ' ssh -i "$work/push-key" -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -p "$PORT" -o "UserKnownHostsFile=$KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
# expect_refusal <regex> <cmd...> fails unless the command fails saying so.
expect_refusal() {
  local message=$1
  shift
  if "$@" >"$work/refusal.log" 2>&1; then
    cat "$work/refusal.log" >&2
    fail "expected a refusal ($message)"
  fi
  grep -E "refused|$message" "$work/refusal.log" | quiet | head -3 || true
  grep -qE "$message" "$work/refusal.log" || { cat "$work/refusal.log" >&2; fail "the refusal didn't say $message"; }
}
running_commit() { run 'bedrock ls --json' | python3 -c 'import json,sys; print(next((a.get("commit","") for a in json.load(sys.stdin)["apps"] or [] if a["name"]==sys.argv[1]), ""))' "$1"; }
hello_builds() { run 'ls -A /var/lib/bedrock-git/builds/hello 2>/dev/null || true'; }
# nothing_built fails if hello runs another commit, or has another source
# tree, than it had before the refusals began.
nothing_built() {
  [[ "$(running_commit hello)" == "$hello_before" ]] || fail "hello deployed from $(running_commit hello)"
  [[ "$(hello_builds)" == "$builds_before" ]] || fail "a refused commit was exported"
}
g() { git -C "$work/hello" -c user.name=lane -c user.email=lane@example.test "$@"; }
# deploys <repo> pushes HEAD with the push key, and shows what the box said.
deploys() {
  GIT_SSH_COMMAND="$push_ssh" git -C "$1" push bedrock HEAD:main >"$work/push.log" 2>&1 || { cat "$work/push.log" >&2; fail "the push of $1 was refused"; }
  grep -E "is signed by|succeeded|failed" "$work/push.log" | quiet | head -4 || true
}
# signed_with <commit> <armor file> writes a copy of a commit carrying that
# signature, and prints the copy.
signed_with() {
  g cat-file commit "$1" | python3 -c '
import sys
raw = sys.stdin.read()
header, body = raw.split("\n\n", 1)
sig = open(sys.argv[1]).read().rstrip("\n").replace("\n", "\n ")
sys.stdout.write(header + "\ngpgsig " + sig + "\n\n" + body)' "$2" | g hash-object -t commit -w --stdin
}

echo "== build and install; the daemon alone gives a stock /etc/bedrock to the bedrock group"
(cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go build -trimpath -o "bin/bedrock-linux-$LANE_ARCH" ./cmd/helios \
  && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go test -c -trimpath -o "bin/gitdeploy-linux-$LANE_ARCH.test" ./internal/gitdeploy \
  && go build -trimpath -o bin/bedrock ./cmd/helios)
put "$here/../bin/bedrock-linux-$LANE_ARCH" /usr/local/bin/bedrock.new
# /etc/bedrock goes back to a stock 755 root:root, as 0.7.15 left both hosts,
# and only the daemon restarts: as it starts it makes it 715 root:bedrock,
# as reconcile does, so the push user passes through and lists nothing.
run 'mkdir -p /etc/bedrock && chown root:root /etc/bedrock && chmod 755 /etc/bedrock'
run 'chmod 755 /usr/local/bin/bedrock.new && mv -f /usr/local/bin/bedrock.new /usr/local/bin/bedrock && bedrock daemon install >/dev/null && bedrock version'
run 'stat -c "%a %U:%G %n" /etc/bedrock /etc/bedrock/git'
run '[ "$(stat -c "%a %U:%G" /etc/bedrock)" = "715 root:bedrock" ] && sudo -u bedrock test -x /etc/bedrock/git && ! sudo -u bedrock ls /etc/bedrock >/dev/null 2>&1' \
  || fail "the daemon left a stock /etc/bedrock other than 715 root:bedrock, or the push user can list it"

echo "== reconcile lets the push user read the policy"
run 'bedrock host reconcile --yes' | quiet | grep -E "pushes|succeeded|failed"
run 'git --version; ssh -V 2>&1; stat -c "%a %U:%G %n" /etc/bedrock /etc/bedrock/git; ls -l /etc/bedrock'
# /etc/bedrock keeps whatever others had (755 on a stock box); only its
# group becomes bedrock, and the group may pass through and list nothing.
run '[ "$(stat -c "%U:%G" /etc/bedrock)" = "root:bedrock" ] && [ "$(stat -c "%a" /etc/bedrock | cut -c2)" = 1 ] && [ "$(stat -c "%a %U:%G" /etc/bedrock/git)" = "750 root:bedrock" ] && sudo -u bedrock test -x /etc/bedrock/git && ! sudo -u bedrock ls /etc/bedrock >/dev/null 2>&1' \
  || fail "the push user can't reach /etc/bedrock/git, or can list /etc/bedrock"

echo "== two apps the push key may deploy; hello will require signed commits"
run 'rm -rf /var/lib/bedrock-git/hello.git /var/lib/bedrock-git/notes.git'
for app in hello notes; do run "bedrock git allow $app '$(cat "$work/push-key.pub")'" | head -1; done
for app in hello notes; do
  mkdir "$work/$app"
  cat >"$work/$app/helios.yaml" <<YAML
app: $app
workloads:
  worker:
    kind: worker
    image: busybox:1.37
    command: [sh, -c, 'trap "exit 0" TERM INT; while :; do sleep 10 & wait "\$!"; done']
YAML
  git -C "$work/$app" init -q --initial-branch=main
  git -C "$work/$app" remote add bedrock "bedrock@$HOST:$app.git"
done

echo "== requiring signatures before anyone may sign is refused"
expect_refusal "no signer is allowed yet" run 'bedrock git require-signed hello --yes'

echo "== allow a signer, and require signed commits, each from a read plan"
run "bedrock git signers add lane@example.test '$(cat "$work/sign-key.pub")' --plan --json" >"$work/add.json"
run "bedrock git signers add lane@example.test '$(cat "$work/sign-key.pub")' --digest $(field digest <"$work/add.json")" | tail -2
run 'bedrock git require-signed hello --plan --json' >"$work/require.json"
python3 -c 'import json,sys; s=json.load(sys.stdin)["steps"][0]; print(s["change"]); print(s.get("note",""))' <"$work/require.json"
run "bedrock git require-signed hello --digest $(field digest <"$work/require.json")" | tail -2
run 'bedrock git signers list; bedrock git keys'
run 'stat -c "%a %U:%G %n" /etc/bedrock/git/allowed_signers /etc/bedrock/git/signing.json'
for file in allowed_signers signing.json; do
  [[ "$(run "stat -c '%a %U:%G' /etc/bedrock/git/$file")" == "640 root:bedrock" ]] || fail "$file isn't 640 root:bedrock"
done
fingerprint=$(ssh-keygen -lf "$work/sign-key.pub" | awk '{print $2}')

hello_before=$(running_commit hello)
builds_before=$(hello_builds)

echo "== an unsigned tip is refused, and nothing is built"
g add helios.yaml
g -c commit.gpgsign=false commit -q -m "lane: unsigned"
unsigned=$(g rev-parse HEAD)
expect_refusal "commit ${unsigned:0:12} isn't signed; the push is refused" env GIT_SSH_COMMAND="$push_ssh" git -C "$work/hello" push bedrock HEAD:main
nothing_built

echo "== a tip signed by a key nobody allowed is refused"
g -c gpg.format=ssh -c user.signingkey="$work/stranger-key" commit -q -S --allow-empty -m "lane: a stranger signs"
expect_refusal "which isn't an allowed signer" env GIT_SSH_COMMAND="$push_ssh" git -C "$work/hello" push bedrock HEAD:main
nothing_built

echo "== a GPG signature is refused; only SSH signatures count"
printf '%s\n' '-----BEGIN PGP SIGNATURE-----' '' 'iHUEABYKAB0WIQQlane' '=lane' '-----END PGP SIGNATURE-----' >"$work/pgp.sig"
gpg_tip=$(signed_with "$unsigned" "$work/pgp.sig")
expect_refusal "has a GPG signature, and only SSH signatures count" env GIT_SSH_COMMAND="$push_ssh" git -C "$work/hello" push bedrock "$gpg_tip:refs/heads/main"
nothing_built

echo "== an allowed key's signature made for files, not git, is refused"
g cat-file commit "$unsigned" | ssh-keygen -q -Y sign -f "$work/sign-key" -n file >"$work/file.sig"
file_tip=$(signed_with "$unsigned" "$work/file.sig")
expect_refusal "doesn't verify" env GIT_SSH_COMMAND="$push_ssh" git -C "$work/hello" push bedrock "$file_tip:refs/heads/main"
nothing_built

echo "== a replace ref, which would make git read one object as another, is refused"
g replace "$unsigned" "$(g rev-parse HEAD)"
expect_refusal "replace refs aren't kept here, and the push is refused" env GIT_SSH_COMMAND="$push_ssh" git -C "$work/hello" push bedrock "refs/replace/$unsigned"
g replace -d "$unsigned" >/dev/null
nothing_built

echo "== a tree uploaded with deploy --to is refused: it has no commit to check"
expect_refusal "an uploaded tree has no commit to check" env BEDROCK_SSH="$push_ssh" "$here/../bin/bedrock" deploy "$work/hello" --to "bedrock@$HOST"
nothing_built

echo "== a tip the allowed key signed deploys, and its receipt says who signed"
g -c gpg.format=ssh -c user.signingkey="$work/sign-key" commit -q -S --allow-empty -m "lane: signed"
signed=$(g rev-parse HEAD)
deploys "$work/hello"
grep -q "${signed:0:12} is signed by lane@example.test" "$work/push.log" || fail "the push didn't say who signed it"
[[ "$(running_commit hello)" == "${signed:0:12}" ]] || fail "hello runs $(running_commit hello), not ${signed:0:12}"
operation=$(run 'bedrock history --json --app hello --limit 1' | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
run "bedrock history $operation --json" | grep -o "signed by lane@example.test ($fingerprint)" | head -1 \
  || fail "the receipt doesn't name the signer and $fingerprint"

echo "== an app that doesn't require signatures deploys as before"
git -C "$work/notes" add helios.yaml
git -C "$work/notes" -c user.name=lane -c user.email=lane@example.test -c commit.gpgsign=false commit -q -m "lane: unsigned notes"
deploys "$work/notes"
[[ "$(running_commit notes)" == "$(git -C "$work/notes" rev-parse --short=12 HEAD)" ]] || fail "an unsigned push of notes didn't deploy"
BEDROCK_SSH="$push_ssh" "$here/../bin/bedrock" deploy "$work/notes" --to "bedrock@$HOST" 2>&1 | quiet | tail -2

echo "== the webhook's check and the verifier, on the box's own git and OpenSSH, as root"
put "$here/../bin/gitdeploy-linux-$LANE_ARCH.test" /root/gitdeploy.test
run 'chmod 700 /root/gitdeploy.test && cd /root && ./gitdeploy.test -test.count=1 -test.v -test.run "SSHKey|AnotherKind|NobodyCanRead|WrittenWhole|UploadedTree|UnsignedTip|PlannedChanges|Webhook|ReplaceRef|ValidDates|HandWritten|SharesItsKey|StoppedAfterWriting" 2>&1 | grep -E "^(--- |PASS|FAIL|ok)"; status=${PIPESTATUS[0]}; rm -f /root/gitdeploy.test; exit $status' \
  || fail "the gitdeploy signing tests failed on the box"

echo "== --off deploys any commit again"
run 'bedrock git require-signed hello --off --yes' | tail -1
g -c commit.gpgsign=false commit -q --allow-empty -m "lane: unsigned again"
deploys "$work/hello"
[[ "$(running_commit hello)" == "$(g rev-parse --short=12 HEAD)" ]] || fail "with --off an unsigned push of hello didn't deploy"

echo "Signed deploys proven: a signed tip deploys and names its signer; unsigned, unknown-key, GPG and other-namespace tips, replace refs and uploaded trees are refused with nothing built; an app without the policy deploys as before"
