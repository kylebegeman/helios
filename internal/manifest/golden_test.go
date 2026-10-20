package manifest

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files from what the code does now")

// Validation says every problem at once, in an order a person can follow;
// that order is part of what it says.
func TestValidationSaysEveryProblemInTheSameOrder(t *testing.T) {
	input := `app: Bad
workloads:
  web:
    kind: web
    image: x
    build: {}
    dir: public
    port: 0
    routes:
      - {host: not a host, path: nope, dns: sideways, auth: magic, origin_pull: strict, port: 70000}
      - {host: a.com}
      - {host: a.com, dns: direct, origin_pull: required}
    env: {bad: 1, KEY: 2}
    secrets: [KEY, lower]
    resources: {memory: lots, cpus: 99, pids: 3}
    health: {path: nope, command: [""], timeout: soon}
    mounts: [{volume: nowhere, path: relative}]
    user: "Nope!"
    capabilities: ["bad cap"]
    tmpfs: [relative]
    aliases: [web, Bad]
    grace: 20m
    order: 2
    singleton: false
    ports: [{port: 0, protocol: sctp, host_port: 70000, address: nowhere}, {port: 443}, {port: 3478}]
  job:
    kind: cron
    image: x
    schedule: never
    timeout: forever
    routes: [{host: b.com}]
    ports: [{port: 3478}]
  rel:
    kind: release
    image: x
    port: 80
  site:
    kind: static
    image: x
    routes: [{host: c.com, port: 81}]
  what:
    kind: blob
data:
  volumes:
    postgres: {}
    Bad: {}
  postgres: {version: "9", user: "Bad User", init: ../x, env: {bad: 1}, secrets: [lower]}
secrets:
  generate: {lower: hex:1, BOTH: nope}
  derive: {BOTH: "{x", lower2: "{nope nope}"}
backup:
  schedule: never
  drill: never
  keep: {daily: -1}
  verify: {sql: ""}
preview: {of: Bad, branch: ""}
checks:
  - {url: ftp://x, status: 700, within: soon}
`
	_, err := Parse([]byte(input))
	if err == nil {
		t.Fatal("a manifest this broken parsed")
	}
	got := err.Error() + "\n"
	path := filepath.Join("testdata", "validation.golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to write it)", err)
	}
	if got != string(want) {
		t.Fatalf("validation changed:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// The scaffold teaches the schema by its comments, so its text is what it
// says, word for word.
func TestEveryScaffoldStaysWhatItWas(t *testing.T) {
	var all []byte
	for _, s := range []Scaffold{
		{App: "acme", Kind: Web, Host: "acme.example.com"},
		{App: "acme", Kind: Web, Host: "acme.example.com", Port: 3000, Postgres: true},
		{App: "acme", Kind: Static, Host: "acme.example.com"},
		{App: "acme", Kind: Static, Host: "acme.example.com", Dir: "dist", Postgres: true},
		{App: "acme", Kind: Worker},
		{App: "acme", Kind: Worker, Postgres: true},
		{App: "acme", Kind: Cron},
		{App: "acme", Kind: Cron, Schedule: "*/15 * * * *", Postgres: true},
	} {
		out, err := s.Render()
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, fmt.Sprintf("=== %+v\n", s)...)
		all = append(all, out...)
	}
	path := filepath.Join("testdata", "scaffolds.golden")
	if *update {
		if err := os.WriteFile(path, all, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(all) != string(want) {
		t.Fatalf("a scaffold changed:\n%s", all)
	}
}
