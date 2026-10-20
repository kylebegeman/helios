#!/bin/sh
# Build reviewed, clean source, and sign its SHA256SUMS with the Helios release
# key. Upload these exact bytes, the sums and SHA256SUMS.sig.
#
# HELIOS_RELEASE_SIGNING_KEY names the release key's public half; the private
# half stays in the key holder's SSH agent. Without it the build stops before
# signing and prints the command that signs it.
set -eu
version=${1:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}
out=${2:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}
# The same rule helios upgrade --version applies.
printf '%s' "$version" | grep -Eq '^[0-9]+(\.[0-9]+)*$' || { echo "A release version such as 0.7.8 is required, not '$version'" >&2; exit 1; }
signers=$(cd "$(dirname "$0")/.." && pwd)/release/allowed_signers
if [ -n "$(git status --porcelain)" ]; then
  echo 'Commit the reviewed changes before building a release.' >&2
  exit 1
fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=true \
    -ldflags "-s -w -X github.com/kylebegeman/helios/internal/version.number=$version" \
    -o "$out/helios_${version}_${os}_${arch}" ./cmd/helios
  # Older installed upgraders request this filename. Both names are the same bytes.
  cp "$out/helios_${version}_${os}_${arch}" "$out/bedrock_${version}_${os}_${arch}"
done
# Whichever the machine has; the two print the same first field.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$out" && sha256sum helios_* bedrock_* > SHA256SUMS)
else
  (cd "$out" && shasum -a 256 helios_* bedrock_* > SHA256SUMS)
fi
printf 'Built %s at %s into %s\n' "$version" "$(git rev-parse HEAD)" "$out"
# A signature left from an earlier build would no longer match, and
# ssh-keygen asks before overwriting one.
rm -f "$out/SHA256SUMS.sig"
if [ -z "${HELIOS_RELEASE_SIGNING_KEY:-}" ]; then
  printf 'SHA256SUMS is not signed yet, so the release must not be published. The release key holder signs it with\n' >&2
  printf '  ssh-keygen -Y sign -f <release key .pub> -n helios-release %s/SHA256SUMS\n' "$out" >&2
  printf 'and checks it with\n  ssh-keygen -Y verify -f %s -I helios-release -n helios-release -s %s/SHA256SUMS.sig < %s/SHA256SUMS\n' "$signers" "$out" "$out" >&2
  exit 0
fi
ssh-keygen -Y sign -f "$HELIOS_RELEASE_SIGNING_KEY" -n helios-release "$out/SHA256SUMS"
# Only a key in release/allowed_signers counts, so check against that list
# rather than trusting the key that was handed in.
ssh-keygen -Y verify -f "$signers" -I helios-release -n helios-release -s "$out/SHA256SUMS.sig" < "$out/SHA256SUMS"
