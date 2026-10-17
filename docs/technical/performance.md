# Performance measurements

Helios should spend little CPU and memory managing a machine. This suite measures
its own recurring work and deployment planning using synthetic, reproducible
fixtures. It does not contact a live daemon, Docker, Caddy, a backup repository
or a remote machine. SQLite benchmarks use real WAL databases in temporary
directories. Results describe local Go code and local database access, not total
production deploy time or application request latency.

## Measurement opportunities

| Path | Why measure it | Metrics and dimensions |
| --- | --- | --- |
| Edge metrics parsing and traffic rollup | Runs every minute; scrape cardinality grows with hosts, methods, status codes and histograms | ns/op, B/op, allocs/op, scrape MB/s; small and large scrapes, unchanged and advancing counters |
| Signal summaries | Status reads hourly rollups retained for 90 days | ns/op, B/op, allocs/op; 24-hour, 7-day and 90-day windows |
| Edge configuration generation | Every deploy and daemon start rebuilds the entire configuration | ns/op, B/op, allocs/op, output MB/s; 10/100/1000 apps, shared hosts, guarded routes and proxies |
| State reads | Status, health, scheduling and reconciliation share the state store | ns/op, B/op, allocs/op; fleet count, deployment history and backup history |
| Manifest parsing and validation | Source checks and deploys should remain responsive for multi-service apps | ns/op, B/op, allocs/op, input MB/s; 1/8/32 workloads with realistic data, routes, environment and checks |
| Manifest route lookup | Post-deploy and ongoing health checks resolve a host/path to a workload | ns/op, B/op, allocs/op; successful lookup, unknown host, unmatched path |
| Route ownership preflight | Each deploy must reject conflicting route and DNS ownership | ns/op, B/op, allocs/op; 1/25/100 active apps with 2/8/32 candidate workloads |
| First deployment timestamp | Backup scheduling and stale-backup alerts need one timestamp from retained history | ns/op, B/op, allocs/op; 1/100/1000 retained revisions |

The initial optimization targets are metrics ingestion, edge generation, route
preflight and history-sensitive timestamp lookup. Keep the other measurements as
controls and as a baseline for future work. A worthwhile local change reduces
median runtime by at least 20% or allocated bytes by at least 30% on a representative
workload. Check smaller workloads and adjacent paths for regressions. A runtime
regression above 5% requires investigation; do not assume a noisy timing difference
is real. Require passing behavioral tests and unchanged external contracts.

## Reproduce and compare

Use the same Go version, CPU, power mode, workload and benchmark settings for
both revisions. Stop competing builds, tests and benchmarks. The runner uses
`-cpu=1 -p=1`, runs packages serially and collects ten samples per case with a
250 ms measurement interval. It excludes test execution and fixture setup from
timed iterations. These are single-worker operation measurements, not concurrent
service tail latencies. Go's reported ranges describe uncertainty in repeated
measurements, not a production request p95.

```sh
make bench BENCH_OUT=bin/benchmarks/baseline
# Make a focused change, test its behavior, then rerun the identical workloads.
make bench BENCH_OUT=bin/benchmarks/candidate

go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e \
  bin/benchmarks/baseline/bench.txt bin/benchmarks/candidate/bench.txt
```

The comparison tool is pinned developer tooling and adds no production dependency.
Both runners reserve output directories atomically and share a per-checkout lock
to prevent overlapping measurements. They reject empty, incomplete or mismatched
benchmark inventories rather than treating a successful process exit as sufficient.
The runner refuses to overwrite an existing output directory. Each run records
UTC time, source commit/tree, tracked-diff hash/status, Go version, target platform,
cgo configuration, Go build flags, workspace mode, GC/memory settings and benchmark
flags beside the raw Go output. New runs set `GOWORK=off` to use the archived module. Commit benchmark
fixtures before a baseline; untracked source is not covered by the tracked-diff
hash. Keep raw results and metadata when reporting a gain. `BENCH_COUNT`,
`BENCH_TIME` and `BENCH_PATTERN` allow shorter smoke runs or focused sweeps; compare
only matching settings and workloads.

## Check machine drift with paired samples

When unchanged controls move or a large case looks slower despite reduced work,
compare committed versions in alternating order. The paired runner builds test
binaries for both commits before timing, from temporary source archives under
`bin/benchmarks/`. It leaves the checkout untouched and removes its source copies
and binaries on exit. Each package alternates baseline/candidate then
candidate/baseline for ten rounds. Raw samples, immutable source IDs, flags and
execution order are retained. The same `BENCH_COUNT`, `BENCH_TIME` and
`BENCH_PATTERN` overrides apply.

```sh
scripts/benchmark-compare.sh BASELINE_COMMIT CANDIDATE_COMMIT bin/benchmarks/paired
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e \
  bin/benchmarks/paired/baseline.txt bin/benchmarks/paired/candidate.txt
```

Paired order reduces drift; it does not make a shared workstation a controlled
performance lab. Inspect unchanged controls, sample spread and allocation counts.
Recheck suspected runtime regressions rather than discarding inconvenient samples.

## Profile before changing code

Run profiles separately from accepted timing samples. For example:

```sh
go test ./internal/signals -run='^$' -bench=ParseMetrics \
  -benchtime=3s -cpu=1 -cpuprofile=bin/signals.cpu -memprofile=bin/signals.mem
go tool pprof -top bin/signals.cpu
go tool pprof -sample_index=alloc_space -top bin/signals.mem
```

Change one cause at a time. Rerun its correctness tests, collect repeated samples,
and retain or reject the change from the evidence. Finish with a full sweep to
expose interactions. Avoid hardware-specific hard timing gates in ordinary CI;
CI runs `make bench-smoke` to exercise each fixture once, alongside behavioral
tests. Compare timing on the same idle machine.

## Operational measurements still needed

A disposable Linux proof can measure end-to-end deployment phase durations,
Caddy reload acknowledgement, Docker stats/probe concurrency, backup and retention
wall time, daemon sampling duty cycle, SQLite contention and peak RSS. Measure
those with realistic network/disk limits and record timeouts and failures as
outcomes. They depend on external services and data volume, so local microbenchmark
gains alone cannot establish improvements there. Live measurements or deployment
are separate from this local optimization work.

The dated results directory contains the baseline, each retained sweep, statistical
comparisons and the final report for this work.
