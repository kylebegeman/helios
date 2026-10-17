#!/usr/bin/env bash
# Compare committed sources in alternating order to reduce machine-state drift.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
export GOWORK=off
if [[ $# -ne 3 ]]; then
  printf 'usage: %s baseline-ref candidate-ref new-output-directory\n' "$0" >&2
  exit 2
fi
baseline=$(git rev-parse --verify "$1^{commit}")
candidate=$(git rev-parse --verify "$2^{commit}")
out=$3
count=${BENCH_COUNT:-10}
benchtime=${BENCH_TIME:-250ms}
pattern=${BENCH_PATTERN:-.}
if [[ ! "$count" =~ ^[1-9][0-9]*$ ]]; then
  printf 'BENCH_COUNT must be a positive integer\n' >&2
  exit 2
fi
if [[ -e "$out" ]]; then
  printf 'Refusing to overwrite existing benchmark output: %s\n' "$out" >&2
  exit 1
fi
mkdir -p "$root/bin/benchmarks" "$(dirname "$out")"
lock="$root/bin/benchmarks/.measurement-lock"
if ! mkdir "$lock" 2>/dev/null; then
  printf 'Another benchmark runner holds %s; wait for it to finish.\n' "$lock" >&2
  exit 1
fi
scratch=""
cleanup() {
  if [[ -n "$scratch" ]]; then rm -rf "$scratch"; fi
  rmdir "$lock"
}
trap cleanup EXIT
mkdir "$out"
out=$(cd "$out" && pwd)
scratch=$(mktemp -d "$root/bin/benchmarks/compare.XXXXXX")
packages=(signals edge state manifest app daemon)
{
  printf 'utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'baseline: %s\ncandidate: %s\n' "$baseline" "$candidate"
  go version
  go env -json GOOS GOARCH CGO_ENABLED GOEXPERIMENT GOFLAGS GOWORK GOTOOLCHAIN
  printf 'GOGC: %s\nGOMEMLIMIT: %s\n' "${GOGC:-default}" "${GOMEMLIMIT:-default}"
  printf 'benchmark: -test.run=^$ -test.bench=%s -test.benchmem -test.count=1 -test.benchtime=%s -test.cpu=1\n' "$pattern" "$benchtime"
  printf 'samples-per-case: %s\norder: baseline/candidate, then candidate/baseline, alternating per package\n' "$count"
} > "$out/environment.txt"

# Build both versions before any timing. Archives are temporary source copies,
# not worktrees, and never include uncommitted edits or change the live checkout.
for label in baseline candidate; do
  if [[ "$label" == baseline ]]; then revision=$baseline; else revision=$candidate; fi
  mkdir -p "$scratch/$label/source" "$scratch/$label/tests"
  git archive "$revision" | tar -x -C "$scratch/$label/source"
  for pkg in "${packages[@]}"; do
    (cd "$scratch/$label/source" && go test -c -p=1 -o "$scratch/$label/tests/$pkg.test" "./internal/$pkg")
  done
done

for pkg in "${packages[@]}"; do
  for ((sample=1; sample<=count; sample++)); do
    if (( sample % 2 )); then order=(baseline candidate); else order=(candidate baseline); fi
    for label in "${order[@]}"; do
      printf '%s %s %s\n' "$pkg" "$sample" "$label" >> "$out/order.txt"
      # Relative fixture paths resolve in that revision's source snapshot.
      (cd "$scratch/$label/source/internal/$pkg" && \
        "$scratch/$label/tests/$pkg.test" -test.run='^$' -test.bench="$pattern" \
          -test.benchmem -test.count=1 -test.benchtime="$benchtime" -test.cpu=1 \
          -test.timeout=15m) >> "$out/$label.txt"
    done
  done
  printf 'Completed %s paired samples for %s\n' "$count" "$pkg"
done

python3 scripts/check-benchmark-results.py --count "$count" "$out/baseline.txt" "$out/candidate.txt"
