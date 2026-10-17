.PHONY: build test check bench bench-smoke linux lane-check lane-up lane-down lane-proof lane-reset lane-status

build:
	CGO_ENABLED=0 go build -trimpath -o bin/helios ./cmd/helios
	cp bin/helios bin/bedrock

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/helios-linux-amd64 ./cmd/helios
	cp bin/helios-linux-amd64 bin/bedrock-linux-amd64

test:
	go test ./...

# Repeated serial performance samples; see docs/technical/performance.md.
bench:
	scripts/benchmark.sh $(BENCH_OUT)

bench-smoke:
	BENCH_COUNT=1 BENCH_TIME=1x scripts/benchmark.sh $(BENCH_OUT)

check: lane-check
	test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go vet ./...
	go test ./...

# Disposable Linux proofs. Provisioning is separate from proof execution.
lane-check:
	lane/check.sh

lane-up:
	lane/vm.sh up

lane-down:
	lane/vm.sh down

lane-proof:
	lane/prove.sh m1

lane-reset:
	lane/reset.sh

lane-status:
	lane/reset.sh --status
