# Helios performance baseline and optimization results

Eight representative targets meet the predefined threshold of at least 20% less runtime or 30% fewer allocated bytes. Two optimization sweeps reduce recurring daemon work and deployment planning costs while preserving behavior.

These are local Go and SQLite measurements on an Apple M5 Pro using Go 1.27.1. Each case has ten alternating baseline/candidate samples at 250 ms with one worker. Values are medians of per-operation means reported by Go, rather than production request percentiles.

Baseline source: 6d2398eaea873909dfbdf08048e7882680e11429. Optimized source: 56f1ffc2efbf59049c79920a646f725f8024c0e4. All 71 cases have ten samples in both versions; benchmark fixtures and flags match.

[Interactive report](report.html) · [Raw comparison](paired-final/comparison.txt) · [CSV](paired-final/comparison.csv) · [Environment](paired-final/environment.txt) · [Execution order](paired-final/order.txt) · [Data](summary.json)

| Target | Before runtime | After runtime | Runtime change | Allocated bytes change | Allocation count change |
| --- | ---: | ---: | ---: | ---: | ---: |
| Metrics parsing: 10 hosts, 1,095 series | 2.488 ms | 925.86 µs | -62.8% | -69.6% | -83.8% |
| Counter bookkeeping: 100 hosts, unchanged scrape | 28.005 ms | 9.784 ms | -65.1% | -79.7% | -94.9% |
| Durable traffic rollups: 10 hosts, 120 rollups | 12.392 ms | 6.769 ms | -45.4% (inconclusive) | -69.4% | -80.0% |
| Edge configuration: 100 apps, 400 routes | 9.973 ms | 2.912 ms | -70.8% | -55.0% | -90.3% |
| Route lookup: 32 workloads, nested path hit | 2.15 µs | 667.2 ns | -68.9% | -100.0% | -100.0% |
| Route preflight: 100 apps, 32 candidate workloads | 5.101 ms | 1.929 ms | -62.2% | -42.3% | -60.2% |
| Backup schedule anchor: 1,000 retained revisions | 3.193 ms | 224.15 µs | -93.0% | -99.96% | -99.9% |
| Active revision read: 25 apps, 32 retained revisions each | 295.11 µs | 206.19 µs | -30.1% | 0.0% | 0.0% |

## Changes retained

1. Parse scrapes with a 4 KiB initial scanner buffer and the existing 1 MiB line limit. Slice label fields and extract whitespace fields without temporary per-label builders or field slices.
2. Encode every counter label in canonical sorted order using length-prefixed fields. Filter metric families and nonfinite histogram bounds that never produce rollups before building counter identities. Preserve priming, resets, new series and eviction.
3. Build edge JSON with concrete Go types and shared immutable forwarding headers. Goldens and equivalence tests preserve exact bytes, guards, proxies, escaping and route order.
4. Read the first deployment timestamp with a scalar SQLite query. Scheduling and stale-backup alerts avoid decoding retained revision history.
5. Resolve routes without sorting workload names per lookup; explicit lexical ties and live manifest mutations preserve prior selection.
6. Index conflicting routes by host once per active app, keep diagnostic order, and reserve compact candidate records.
7. Scan the revision table and sort only active results, avoiding historical app-index lookups. EXPLAIN confirms the plan; filtering, errors and app/id ordering remain covered.

## Controls and limits

Initial grouped sweeps suffered major machine drift. Their raw results remain in [baseline](baseline/bench.txt) and [sweep 1](sweep-1/bench.txt); final runtime claims use alternating committed-source measurements. The first sweep's Go processes passed, but its outer shell failed after timing because its active script was edited. All 710 samples were independently validated; see [run status](sweep-1/run-status.txt). The paired runner remained unchanged throughout its complete run.

Timing spread remains wide on this shared workstation. Benchstat p-values are exploratory per-case comparisons without adjustment for multiple comparisons. Allocated byte and object counts provide the strongest repeatable evidence. Traffic-rollup runtime changes are inconclusive; their allocation reductions meet the target.

The active-read improvement was observed at 25 apps with 32 revisions each (p=0.043). Other active-read sizes are inconclusive, including the largest stress case. Reads still scale with retained history; no schema/index migration was added.

The smallest route preflight has indistinguishable runtime (p=1.000 n=10) and +5.2% allocated bytes (11.74 KiB to 12.35 KiB). The large preflight reduces both runtime and allocations substantially.

An unchanged control, fleet backup-kind history at 100 apps and 512 history entries, reported +65.36% runtime (p=0.043). Its query and benchmark are unchanged. This is evidence of residual host variability; the result is retained rather than hidden or treated as a source-code regression.

End-to-end Linux operations, live Caddy reloads, actual request latency, Docker/backup service time, peak RSS and production performance remain unmeasured. Repeat on a quiet Linux host before making claims about those environments.

## Verification and reproduction

Both optimization sweeps passed make check: all 80 lane target-safety tests, formatting, vet and all Go tests. All 71 fixtures pass the smoke check. Static Linux AMD64 and macOS ARM64 builds pass. Go 1.26.0 tests pass for edge, manifest, signals, state and mail, including exact edge JSON compatibility.

[Verification record](verification.txt) · [Profile evidence](profiles/) · [Benchmark guide](../../../performance.md)

    scripts/benchmark-compare.sh 6d2398e 56f1ffc bin/benchmarks/reproduction
    go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e \
      bin/benchmarks/reproduction/baseline.txt bin/benchmarks/reproduction/candidate.txt

## All case medians

| Case | Before runtime | After runtime | Runtime change | Before bytes/op | After bytes/op | Allocs change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ParseMetrics/Hosts1 | 658.85 µs | 101.27 µs | -84.6% | 1.10 MiB | 68.23 KiB | -81.5% |
| ParseMetrics/Hosts10 | 2.488 ms | 925.86 µs | -62.8% | 2.01 MiB | 625.73 KiB | -83.8% |
| ParseMetrics/Hosts100 | 32.504 ms | 14.260 ms | -56.1% | 11.33 MiB | 6.29 MiB | -84.1% |
| TrafficUnchanged/Hosts1 | 166.81 µs | 71.00 µs | -57.4% | 57.92 KiB | 14.41 KiB | -94.3% |
| TrafficUnchanged/Hosts10 | 2.707 ms | 783.28 µs | -71.1% | 620.05 KiB | 131.63 KiB | -94.8% |
| TrafficUnchanged/Hosts100 | 28.005 ms | 9.784 ms | -65.1% | 5.85 MiB | 1.19 MiB | -94.9% |
| TrafficRollups/Hosts1 | 1.633 ms | 827.74 µs | -49.3% (inconclusive) | 66.26 KiB | 22.75 KiB | -79.6% |
| TrafficRollups/Hosts10 | 12.392 ms | 6.769 ms | -45.4% (inconclusive) | 703.87 KiB | 215.44 KiB | -80.0% |
| Summarize/Hours24 | 23.14 µs | 57.39 µs | +148.0% (inconclusive) | 1.07 KiB | 1.07 KiB | 0.0% |
| Summarize/Hours168 | 148.48 µs | 309.78 µs | +108.6% (inconclusive) | 9.29 KiB | 9.29 KiB | 0.0% |
| Summarize/Hours2160 | 2.768 ms | 2.406 ms | -13.1% (inconclusive) | 144.84 KiB | 144.84 KiB | 0.0% |
| ConfigBehind/apps=10 | 1.015 ms | 247.97 µs | -75.6% | 321.58 KiB | 148.17 KiB | -90.0% |
| ConfigBehind/apps=100 | 9.973 ms | 2.912 ms | -70.8% | 2.98 MiB | 1.34 MiB | -90.3% |
| ConfigBehind/apps=1000 | 113.241 ms | 22.019 ms | -80.6% | 42.18 MiB | 13.36 MiB | -90.3% |
| StateRevisionReads/apps=1/history=32/ActiveRevisions | 25.40 µs | 21.57 µs | -15.1% (inconclusive) | 3.94 KiB | 3.94 KiB | 0.0% |
| StateRevisionReads/apps=1/history=32/RevisionWithStatus/active | 28.76 µs | 30.69 µs | +6.7% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=1/history=32/RevisionWithStatus/previous | 26.86 µs | 30.79 µs | +14.7% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=1/history=32/Revisions | 192.56 µs | 189.91 µs | -1.4% (inconclusive) | 99.62 KiB | 99.62 KiB | 0.0% |
| StateRevisionReads/apps=25/history=32/ActiveRevisions | 295.11 µs | 206.19 µs | -30.1% | 80.04 KiB | 80.04 KiB | 0.0% |
| StateRevisionReads/apps=25/history=32/RevisionWithStatus/active | 29.17 µs | 28.97 µs | -0.7% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=25/history=32/RevisionWithStatus/previous | 29.72 µs | 27.81 µs | -6.4% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=25/history=32/Revisions | 233.48 µs | 162.23 µs | -30.5% (inconclusive) | 99.62 KiB | 99.62 KiB | 0.0% |
| StateRevisionReads/apps=25/history=512/ActiveRevisions | 8.118 ms | 6.048 ms | -25.5% (inconclusive) | 80.53 KiB | 80.49 KiB | 0.0% |
| StateRevisionReads/apps=25/history=512/RevisionWithStatus/active | 133.91 µs | 121.33 µs | -9.4% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=25/history=512/RevisionWithStatus/previous | 119.86 µs | 117.62 µs | -1.9% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=25/history=512/Revisions | 2.772 ms | 2.453 ms | -11.5% (inconclusive) | 1.56 MiB | 1.56 MiB | 0.0% |
| StateRevisionReads/apps=100/history=512/ActiveRevisions | 31.750 ms | 35.171 ms | +10.8% (inconclusive) | 321.45 KiB | 321.18 KiB | 0.0% |
| StateRevisionReads/apps=100/history=512/RevisionWithStatus/active | 132.63 µs | 117.40 µs | -11.5% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=100/history=512/RevisionWithStatus/previous | 148.77 µs | 121.72 µs | -18.2% (inconclusive) | 3.90 KiB | 3.90 KiB | 0.0% |
| StateRevisionReads/apps=100/history=512/Revisions | 2.883 ms | 2.329 ms | -19.2% (inconclusive) | 1.56 MiB | 1.56 MiB | 0.0% |
| StateBackupReads/apps=1/history=32/LatestForApp | 39.35 µs | 36.04 µs | -8.4% (inconclusive) | 2.52 KiB | 2.52 KiB | 0.0% |
| StateBackupReads/apps=1/history=32/AppHistory | 95.65 µs | 85.95 µs | -10.1% (inconclusive) | 21.74 KiB | 21.74 KiB | 0.0% |
| StateBackupReads/apps=1/history=32/FleetHistory | 94.06 µs | 83.94 µs | -10.8% (inconclusive) | 21.54 KiB | 21.54 KiB | 0.0% |
| StateBackupReads/apps=1/history=32/FleetBackupHistory | 97.48 µs | 81.66 µs | -16.2% (inconclusive) | 21.79 KiB | 21.79 KiB | 0.0% |
| StateBackupReads/apps=1/history=32/LastGoodBackupRun | 25.89 µs | 22.84 µs | -11.8% (inconclusive) | 1.66 KiB | 1.66 KiB | 0.0% |
| StateBackupReads/apps=25/history=32/LatestForApp | 45.48 µs | 37.60 µs | -17.3% (inconclusive) | 2.53 KiB | 2.53 KiB | 0.0% |
| StateBackupReads/apps=25/history=32/AppHistory | 100.70 µs | 88.81 µs | -11.8% (inconclusive) | 21.90 KiB | 21.90 KiB | 0.0% |
| StateBackupReads/apps=25/history=32/FleetHistory | 265.53 µs | 299.79 µs | +12.9% (inconclusive) | 22.54 KiB | 22.54 KiB | 0.0% |
| StateBackupReads/apps=25/history=32/FleetBackupHistory | 322.78 µs | 290.16 µs | -10.1% (inconclusive) | 22.79 KiB | 22.79 KiB | 0.0% |
| StateBackupReads/apps=25/history=32/LastGoodBackupRun | 28.26 µs | 22.35 µs | -20.9% (inconclusive) | 1.67 KiB | 1.67 KiB | 0.0% |
| StateBackupReads/apps=25/history=512/LatestForApp | 37.29 µs | 37.90 µs | +1.6% (inconclusive) | 2.53 KiB | 2.53 KiB | 0.0% |
| StateBackupReads/apps=25/history=512/AppHistory | 218.73 µs | 203.90 µs | -6.8% (inconclusive) | 21.99 KiB | 21.99 KiB | 0.0% |
| StateBackupReads/apps=25/history=512/FleetHistory | 6.647 ms | 3.630 ms | -45.4% (inconclusive) | 22.54 KiB | 22.54 KiB | 0.0% |
| StateBackupReads/apps=25/history=512/FleetBackupHistory | 3.885 ms | 4.468 ms | +15.0% (inconclusive) | 22.79 KiB | 22.79 KiB | 0.0% |
| StateBackupReads/apps=25/history=512/LastGoodBackupRun | 23.85 µs | 21.57 µs | -9.6% (inconclusive) | 1.67 KiB | 1.67 KiB | 0.0% |
| StateBackupReads/apps=100/history=512/LatestForApp | 40.21 µs | 38.17 µs | -5.1% (inconclusive) | 2.53 KiB | 2.53 KiB | 0.0% |
| StateBackupReads/apps=100/history=512/AppHistory | 215.11 µs | 211.03 µs | -1.9% (inconclusive) | 21.99 KiB | 21.99 KiB | 0.0% |
| StateBackupReads/apps=100/history=512/FleetHistory | 15.981 ms | 21.109 ms | +32.1% (inconclusive) | 22.54 KiB | 22.54 KiB | 0.0% |
| StateBackupReads/apps=100/history=512/FleetBackupHistory | 15.348 ms | 25.379 ms | +65.4% | 22.79 KiB | 22.79 KiB | 0.0% |
| StateBackupReads/apps=100/history=512/LastGoodBackupRun | 23.13 µs | 23.88 µs | +3.2% (inconclusive) | 1.67 KiB | 1.67 KiB | 0.0% |
| Parse/Workloads1 | 101.37 µs | 103.74 µs | +2.3% (inconclusive) | 48.95 KiB | 48.95 KiB | 0.0% |
| Parse/Workloads8 | 407.27 µs | 412.90 µs | +1.4% (inconclusive) | 183.40 KiB | 183.40 KiB | 0.0% |
| Parse/Workloads32 | 1.458 ms | 1.560 ms | +7.0% (inconclusive) | 658.03 KiB | 658.03 KiB | 0.0% |
| Validate/Workloads1 | 6.63 µs | 7.66 µs | +15.6% (inconclusive) | 2.13 KiB | 2.13 KiB | 0.0% |
| Validate/Workloads8 | 26.90 µs | 29.39 µs | +9.3% (inconclusive) | 7.34 KiB | 7.34 KiB | 0.0% |
| Validate/Workloads32 | 104.97 µs | 115.76 µs | +10.3% (inconclusive) | 32.23 KiB | 32.23 KiB | 0.0% |
| RouteFor/Workloads1/Hit | 137.4 ns | 102.0 ns | -25.8% | 16 B | 0 B | -100.0% |
| RouteFor/Workloads1/MissHost | 115.0 ns | 55.0 ns | -52.2% | 16 B | 0 B | -100.0% |
| RouteFor/Workloads1/MissPath | 118.2 ns | 81.7 ns | -30.9% | 16 B | 0 B | -100.0% |
| RouteFor/Workloads8/Hit | 462.5 ns | 194.6 ns | -57.9% | 128 B | 0 B | -100.0% |
| RouteFor/Workloads8/MissHost | 432.1 ns | 90.3 ns | -79.1% | 128 B | 0 B | -100.0% |
| RouteFor/Workloads8/MissPath | 422.2 ns | 163.8 ns | -61.2% | 128 B | 0 B | -100.0% |
| RouteFor/Workloads32/Hit | 2.15 µs | 667.2 ns | -68.9% | 512 B | 0 B | -100.0% |
| RouteFor/Workloads32/MissHost | 2.11 µs | 318.1 ns | -84.9% | 512 B | 0 B | -100.0% |
| RouteFor/Workloads32/MissPath | 2.07 µs | 604.8 ns | -70.8% | 512 B | 0 B | -100.0% |
| CheckRouteConflicts/Apps1/Workloads2 | 36.13 µs | 34.64 µs | -4.1% (inconclusive) | 11.74 KiB | 12.35 KiB | +4.2% |
| CheckRouteConflicts/Apps25/Workloads8 | 641.22 µs | 444.19 µs | -30.7% | 301.36 KiB | 265.84 KiB | -22.8% |
| CheckRouteConflicts/Apps100/Workloads32 | 5.101 ms | 1.929 ms | -62.2% | 1.80 MiB | 1.04 MiB | -60.2% |
| SchedulerFirstDeploy/Revisions1 | 19.56 µs | 10.29 µs | -47.4% | 3.19 KiB | 1.02 KiB | -64.8% |
| SchedulerFirstDeploy/Revisions100 | 356.41 µs | 31.09 µs | -91.3% | 195.48 KiB | 935 B | -99.2% |
| SchedulerFirstDeploy/Revisions1000 | 3.193 ms | 224.15 µs | -93.0% | 1.99 MiB | 934 B | -99.9% |
