#!/usr/bin/env bash
# Run serially on an otherwise idle machine; retain raw Go output for benchstat.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -gt 1 ]]; then
  printf 'usage: %s [new-output-directory]\n' "$0" >&2
  exit 2
fi
out=${1:-"bin/benchmarks/$(date -u +%Y%m%dT%H%M%SZ)"}
count=${BENCH_COUNT:-10}
benchtime=${BENCH_TIME:-250ms}
pattern=${BENCH_PATTERN:-.}
if [[ -e "$out" ]]; then
  printf 'Refusing to overwrite existing benchmark output: %s\n' "$out" >&2
  exit 1
fi
mkdir -p "$out"
{
  printf 'utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'commit: %s\n' "$(git rev-parse HEAD)"
  printf 'tree: %s\n' "$(git rev-parse 'HEAD^{tree}')"
  printf 'tracked-diff-sha256: '
  git diff HEAD -- . ':!docs/technical/performance/results' | shasum -a 256
  printf 'tracked-worktree-status:\n'
  git status --short --untracked-files=no
  go version
  go env GOOS GOARCH CGO_ENABLED
  printf 'benchmark: -run=^$ -bench=%s -benchmem -count=%s -benchtime=%s -cpu=1 -p=1\n' "$pattern" "$count" "$benchtime"
} > "$out/environment.txt"
go test -run='^$' -bench="$pattern" -benchmem -count="$count" \
  -benchtime="$benchtime" -cpu=1 -p=1 \
  ./internal/signals ./internal/edge ./internal/state ./internal/manifest ./internal/app ./internal/daemon \
  | tee "$out/bench.txt"
