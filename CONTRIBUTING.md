# Contributing To Helios

Helios is one Go program (Go 1.26, no cgo) that runs a machine. Changes
are small, proven where they can be, and written in plain prose: an error
says what to do next, a plan says what will change.

## Development

```sh
make check   # gofmt, go vet, go test ./...
make build   # bin/helios for this Mac
make linux   # bin/helios-linux-amd64 for the machines
```

CI runs `make check` and cross-builds for linux/amd64 and darwin/arm64 on
every push and pull request. The tests use the standard library only, real
SQLite stores in temporary directories, and fakes for the machine, Docker's
API and Cloudflare's; `go test ./...` touches no network and no real
Docker. Operational behavior is proven on a disposable Linux machine. Provisioning
is separate from running proofs, and no proof assumes the historical
Hostinger target is disposable. See [lane/README.md](lane/README.md).

```sh
make lane-up                 # dedicated local QEMU guest through Docker
lane/prove.sh --check m1      # preflight only
lane/prove.sh m1              # daemon recovery, with reproducible reports
make lane-down               # remove only that managed VM
```

`make check` also runs the lane's fail-closed target-safety tests. CI boots a
fresh Linux guest for the daemon proof and retains its report/failure
artifacts. Other proofs declare public DNS, storage or sanitized private
fixture requirements; missing prerequisites are reported as blocked, rather
than passing. Select proof scopes appropriate to the changed behavior.

## Performance measurements

Run `make bench` on an otherwise idle machine for ten serial samples of the
metrics, edge, state, manifest, route-preflight and scheduler benchmarks. Raw
results and environment metadata are saved under `bin/benchmarks/`. Use
`BENCH_OUT`, `BENCH_COUNT`, `BENCH_TIME` and `BENCH_PATTERN` to select the output
and measurement budget. See [the performance guide](docs/technical/performance.md)
for workloads, profiling, comparison and acceptance criteria.

## What a change looks like

- Fixture apps and `example.com` hostnames in tests and docs; never a real
  hostname, address, path, credential or production value.
- Anything that changes a machine is an operation: planned as steps,
  journaled, finished with a receipt. It takes `--plan` and `--digest`, and
  its plan must not depend on the moment it was made.
- Secret values never reach an argument, a log, a receipt or a message;
  only their names do.
- A `--json` output shape is a contract: change one deliberately and say so
  in the commit.
- Tests are sentences that name the behaviour, such as
  `TestAPlannedPreviewCopiesNoSecrets`.
- Commit subjects are sentences too, and the body says why.

## Pull requests

Run `make check`, say what changes for a person using helios and how it
was verified, and keep a pull request to one subject. Helios is licensed
under the Apache License 2.0; a contribution is licensed the same way.
