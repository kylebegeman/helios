package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/cloudflare/cloudflaretest"
	"github.com/kylebegeman/helios/internal/dns"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// The production machine after loom was removed by hand: its records
// still point here, and helios dns audit says nothing answers for them.
func TestDroppingARecordNoRouteHereKeeps(t *testing.T) {
	ctx := context.Background()
	const here = "187.127.249.208"
	fake := cloudflaretest.New("t0ken", "begam.in")
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "loom.begam.in", Content: here})
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "runner.loom.begam.in", Content: here})
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "*.loom.begam.in", Content: here})
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "*.pr.begam.in", Content: here})
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "hello.begam.in", Content: here})
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "old.begam.in", Content: here})
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "site.begam.in", Content: "198.51.100.20", Comment: "helios: site on " + here})

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedManifest(t, store, "hello", `{"app":"hello","workloads":{"web":{"kind":"web","image":"x","port":80,"routes":[{"host":"hello.begam.in"}]}}}`)
	// A previous revision routes old.begam.in: a rollback would want it.
	old := state.Revision{App: "hello", ID: "r0", Status: state.RevisionPrevious, CreatedAt: time.Now().Add(-time.Hour).UTC(),
		Manifest: json.RawMessage(`{"app":"hello","workloads":{"web":{"kind":"web","image":"x","port":80,"routes":[{"host":"old.begam.in"},{"host":"a.pr.begam.in"}]}}}`)}
	if err := store.SaveRevision(ctx, old); err != nil {
		t.Fatal(err)
	}
	sec := newSecrets(t)
	d := Drop{Store: store, Secrets: sec, Addresses: func(context.Context) []string { return []string{here} }}
	plan := func(host string) error {
		_, err := d.Plan(ctx, json.RawMessage(`{"host":"`+host+`"}`))
		return err
	}
	if err := plan("loom.begam.in"); err == nil || !strings.Contains(err.Error(), "needs the cloudflare integration") {
		t.Fatalf("without the integration: %v", err)
	}
	if _, _, err := integration.Set(sec, integration.CloudflareName, map[string]string{"token": "t0ken", "api": srv.URL + "/client/v4"}); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"hello.begam.in":  "hello routes hello.begam.in on this machine",
		"old.begam.in":    "hello routes old.begam.in on this machine",
		"*.pr.begam.in":   "*.pr.begam.in covers a.pr.begam.in, which hello routes",
		"site.begam.in":   "names 198.51.100.20, not this machine",
		"gone.begam.in":   "has no A or AAAA record",
		"not a host":      "isn't a hostname",
		"*.*.begam.in":    "isn't a hostname",
		"loom.example.io": "no zone",
	} {
		if err := plan(host); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", host, err, want)
		}
	}

	p, err := d.Plan(ctx, json.RawMessage(`{"host":"Loom.Begam.in."}`))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "plan-dns-drop", planText(p))
	var out strings.Builder
	for _, st := range p.Steps {
		if err := st.Apply(ctx, &out); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "loom.begam.in's A 187.127.249.208 record deleted") {
		t.Fatalf("output: %q", out.String())
	}
	var left []string
	for _, r := range fake.Records() {
		left = append(left, r.Name)
	}
	// The wildcard over it and the name below it stay: each goes by its
	// own name only.
	if got := strings.Join(left, " "); got != "*.loom.begam.in *.pr.begam.in hello.begam.in old.begam.in runner.loom.begam.in site.begam.in" {
		t.Fatalf("left: %s", got)
	}
	if err := plan("*.loom.begam.in"); err != nil {
		t.Fatalf("a wildcard no route falls under, named: %v", err)
	}
}

func TestDNSCleanupPreservesSharedHostsUntilTheLastAppLeaves(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(map[bool]string{false: "remove", true: "retire-route"}[retire], func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			owner := routeFixture(t, "owner", "/", manifest.DNSProxied)
			survivor := routeFixture(t, "survivor", "/api", manifest.DNSProxied)
			saveActive(t, store, owner)
			saveActive(t, store, survivor)
			const here = "203.0.113.10"
			fake := cloudflaretest.New("fixture-token", "example.com")
			server := httptest.NewServer(fake)
			defer server.Close()
			hostname, _ := os.Hostname()
			fake.Seed(cloudflaretest.Record{Type: "A", Name: "shared.example.com", Content: here, Proxied: true, Comment: dns.Comment("owner", hostname)})
			sec := newSecrets(t)
			if _, _, err := integration.Set(sec, integration.CloudflareName, map[string]string{"token": "fixture-token", "api": server.URL + "/client/v4"}); err != nil {
				t.Fatal(err)
			}
			removeRecords := func(app string) error {
				return (&removal{r: Remove{Store: store, Secrets: sec, Addresses: func(context.Context) []string { return []string{here} }}, in: RemoveInput{App: app}, m: *owner}).dnsStep().Apply(ctx, io.Discard)
			}
			var err error
			if retire {
				err = store.SetRevisionStatus(ctx, "owner", "20260920-120000", state.RevisionRetired)
				if err == nil {
					err = pruneRecords(ctx, store, sec, "owner", []string{here}, io.Discard)
				}
			} else {
				err = removeRecords("owner")
			}
			if err != nil {
				t.Fatal(err)
			}
			if records := fake.Records(); len(records) != 1 || records[0].Content != here || records[0].Comment != dns.Comment("survivor", hostname) {
				t.Fatalf("cleanup removed or orphaned a host still routed by another app: %+v", records)
			}
			if err := store.SetRevisionStatus(ctx, "owner", "20260920-120000", state.RevisionRetired); err != nil {
				t.Fatal(err)
			}
			if err := removeRecords("survivor"); err != nil {
				t.Fatal(err)
			}
			if records := fake.Records(); len(records) != 0 {
				t.Fatalf("the final app's DNS record survived cleanup: %+v", records)
			}
		})
	}
}

func TestDNSCleanupTransfersExistingOwnershipToAManagedSurvivor(t *testing.T) {
	for _, record := range []string{"owned", "absent", "foreign"} {
		t.Run(record, func(t *testing.T) {
			ctx := context.Background()
			store := releaseTestStore(t)
			for _, route := range []struct {
				app, path string
				mode      manifest.DNSMode
			}{{"owner", "/", manifest.DNSProxied}, {"amanual", "/manual", manifest.DNSManual}, {"zmanaged", "/api", manifest.DNSProxied}} {
				if record == "absent" && route.app == "amanual" {
					continue
				}
				saveActive(t, store, routeFixture(t, route.app, route.path, route.mode))
			}
			const here = "203.0.113.10"
			fake := cloudflaretest.New("fixture-token", "example.com")
			server := httptest.NewServer(fake)
			defer server.Close()
			hostname, _ := os.Hostname()
			comment := dns.Comment("owner", hostname)
			if record == "foreign" {
				comment = "managed by another system"
			}
			if record != "absent" {
				fake.Seed(cloudflaretest.Record{Type: "A", Name: "shared.example.com", Content: here, Proxied: true, Comment: comment})
			}
			sec := newSecrets(t)
			if _, _, err := integration.Set(sec, integration.CloudflareName, map[string]string{"token": "fixture-token", "api": server.URL + "/client/v4"}); err != nil {
				t.Fatal(err)
			}
			mgr, err := DNSManager(sec, []string{here})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := removeUnroutedRecords(ctx, store, mgr, "owner", []string{"shared.example.com"}, io.Discard); err != nil {
				t.Fatal(err)
			}
			records := fake.Records()
			if record == "absent" {
				if len(records) != 0 {
					t.Fatalf("cleanup created DNS: %+v", records)
				}
				return
			}
			want := comment
			if record == "owned" {
				want = dns.Comment("zmanaged", hostname)
			}
			if len(records) != 1 || records[0].Comment != want || records[0].Content != here || !records[0].Proxied {
				t.Fatalf("cleanup changed or orphaned DNS: %+v, want comment %q", records, want)
			}
		})
	}
}
