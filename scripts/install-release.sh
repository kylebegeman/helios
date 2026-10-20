#!/bin/sh
# Put a published Helios release on one or more machines with the compatibility layout,
# or one too old to upgrade itself.
#
# The bytes come from the GitHub release and are checked against the
# SHA256SUMS published beside them, once here and again on the machine after
# transfer. A machine is only ever given a binary whose checksum matched.
# The published sums count only when SHA256SUMS.sig is a signature by a key in
# release/allowed_signers, checked with ssh-keygen before any checksum is read.
# HELIOS_SHA256 (or BEDROCK_SHA256) pins the checksum from reviewed source
# instead, for the hosts' architecture (run once per architecture when they
# differ); that also installs a release from before releases were signed.
#
# The binary already there is kept as the previous one, with the marker
# bedrock's own upgrade leaves, so a daemon that fails to start on the new
# build is put back by systemd the same way.
#
# Usage: install-release.sh VERSION HOST [HOST...]
set -eu

version=${1:?usage: install-release.sh VERSION HOST [HOST...]}
shift
[ $# -gt 0 ] || { echo 'At least one host is required' >&2; exit 1; }
printf '%s' "$version" | grep -Eq '^[0-9]+(\.[0-9]+)*$' || { echo "A release version such as 0.7.8 is required, not '$version'" >&2; exit 1; }

# The release channel and installed paths stay compatible until host migration.
if [ -n "${HELIOS_SHA256:-}" ] && [ -n "${BEDROCK_SHA256:-}" ] && [ "$HELIOS_SHA256" != "$BEDROCK_SHA256" ]; then
  echo 'HELIOS_SHA256 and BEDROCK_SHA256 conflict' >&2
  exit 1
fi
release_pin=${HELIOS_SHA256:-${BEDROCK_SHA256:-}}
signers=$(cd "$(dirname "$0")/.." && pwd)/release/allowed_signers
base="https://github.com/kylebegeman/helios/releases/download/v$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# sum prints a file's SHA-256, with whichever tool this machine has.
sum() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}

curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS"
if [ -z "$release_pin" ]; then
  curl -fsSL "$base/SHA256SUMS.sig" -o "$work/SHA256SUMS.sig" || {
    echo "No SHA256SUMS.sig for v$version (releases before 0.7.16 publish none); set HELIOS_SHA256 to install it unsigned" >&2
    exit 1
  }
  ssh-keygen -Y verify -f "$signers" -I helios-release -n helios-release -s "$work/SHA256SUMS.sig" < "$work/SHA256SUMS" >&2 || {
    echo "SHA256SUMS for v$version is not signed by a Helios release key; refusing it" >&2
    exit 1
  }
fi

# Fetch one asset and verify it against the pinned or published sum.
fetch() {
  asset="helios_${version}_linux_$1"
  if ! grep -q " $asset\$" "$work/SHA256SUMS"; then asset="bedrock_${version}_linux_$1"; fi
  [ -f "$work/$asset" ] && return 0
  curl -fsSL "$base/$asset" -o "$work/$asset"
  want=${release_pin:-$(grep " $asset\$" "$work/SHA256SUMS" | awk '{print $1}')}
  [ -n "$want" ] || { echo "No published checksum for $asset" >&2; exit 1; }
  got=$(sum "$work/$asset")
  [ "$want" = "$got" ] || { echo "$asset does not match its checksum" >&2; exit 1; }
}

for host in "$@"; do
  machine=$(ssh "$host" 'uname -m')
  case "$machine" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "$host: unsupported architecture $machine" >&2; exit 1 ;;
  esac
  fetch "$arch"
  asset="helios_${version}_linux_$arch"
  if ! grep -q " $asset\$" "$work/SHA256SUMS"; then asset="bedrock_${version}_linux_$arch"; fi
  want=${release_pin:-$(grep " $asset\$" "$work/SHA256SUMS" | awk '{print $1}')}

  scp -q "$work/$asset" "$host:/tmp/$asset"
  # Rename rather than write in place: overwriting a running executable is
  # ETXTBSY, and rename is atomic, so no one ever sees a partial binary.
  ssh "$host" "set -eu
    got=\$(sha256sum '/tmp/$asset' | awk '{print \$1}')
    [ \"\$got\" = '$want' ] || { rm -f '/tmp/$asset'; echo 'transfer corrupted' >&2; exit 1; }
    if [ -e /usr/local/bin/helios ] || [ -L /usr/local/bin/helios ]; then
      [ -L /usr/local/bin/helios ] && [ \"\$(readlink /usr/local/bin/helios)\" = bedrock ] || { echo 'helios path already exists; inspect it before installing' >&2; exit 1; }
    fi
    chmod 0755 '/tmp/$asset'
    lib=/usr/local/lib/bedrock
    mkdir -p \"\$lib\"
    if [ -f /usr/local/bin/bedrock ]; then
      cp /usr/local/bin/bedrock \"\$lib/previous\"
      echo 'install-release $version' > \"\$lib/staged\"
    fi
    mv '/tmp/$asset' /usr/local/bin/bedrock
    if [ ! -L /usr/local/bin/helios ]; then ln -s bedrock /usr/local/bin/helios; fi
    if systemctl cat bedrock.service >/dev/null 2>&1; then systemctl restart bedrock.service; fi"
  printf '%s: %s\n' "$host" "$(ssh "$host" 'bedrock version')"
done
