package docker

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Docker reports what a prune reclaimed in whatever unit suits the number,
// and gc turns that into the line a person reads. A unit it cannot read
// must count as nothing rather than as a bare number of bytes, which would
// report a gigabyte reclaim as "1.2 B".
func TestParseReclaimed(t *testing.T) {
	for _, c := range []struct {
		line string
		want int64
	}{
		{"Total:\t0B", 0},
		{"Total:\t49.25GB", 49_250_000_000},
		{"Total reclaimed space: 0B", 0},
		{"Total reclaimed space: 512KB", 512_000},
		{"Total reclaimed space: 1.5MB", 1_500_000},
		{"Total reclaimed space: 49.25GB", 49_250_000_000},
		{"Total reclaimed space: 2TB", 2_000_000_000_000},
		{"Deleted build cache objects:", 0},
		{"", 0},
	} {
		if got := parseReclaimed(c.line); got != c.want {
			t.Errorf("parseReclaimed(%q) = %d, want %d", c.line, got, c.want)
		}
	}
}

// On the containerd image store BuildKit counts a cache record whose layers an
// image also holds as shared, and a prune without --all skips every one of
// them. That was most of a machine's cache, so neither the age rule nor the
// ceiling reached it and the disk filled.
func TestPruneBuildCacheReachesSharedCacheAndCapsIt(t *testing.T) {
	const age = "builder prune --force --all --filter until=24h"
	const ceiling = "builder prune --force --all --max-used-space 8589934592"
	for _, c := range []struct {
		name, script string
		want         []string
	}{
		{"current daemon", "", []string{age, ceiling}},
		{"daemon before max-used-space", "case \"$*\" in *--max-used-space*) echo 'unknown flag: --max-used-space' >&2; exit 125 ;; esac\n",
			[]string{age, ceiling, "builder prune --force --all --keep-storage 8589934592"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			script := "echo \"$*\" >> " + calls + "\n" + c.script + "echo 'Total:\t1.5GB'\n"
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":/bin:/usr/bin")
			freed, err := PruneBuildCache(context.Background(), 24*time.Hour, 8<<30)
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Split(strings.TrimSpace(string(body)), "\n"); !slices.Equal(got, c.want) {
				t.Fatalf("pruned with %q, want %q", got, c.want)
			}
			if freed != 3_000_000_000 {
				t.Fatalf("freed %d, want both passes counted", freed)
			}
		})
	}
}
