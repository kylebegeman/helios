package dns

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/cloudflare"
	"github.com/kylebegeman/helios/internal/cloudflare/cloudflaretest"
	"github.com/kylebegeman/helios/internal/manifest"
)

func TestZoneCacheAlwaysChoosesTheMostSpecificVisibleZone(t *testing.T) {
	fake := cloudflaretest.New("test", "example.com", "apps.example.com")
	server := httptest.NewServer(fake)
	defer server.Close()
	cf := cloudflare.New("test")
	cf.Base = server.URL + "/client/v4"
	m := &Manager{CF: cf}
	for host, want := range map[string]string{"example.com": "example.com", "site.apps.example.com": "apps.example.com"} {
		// Prime the parent before every child lookup, which used to hide
		// child zones after an unrelated app had populated the cache.
		if _, err := m.zone(context.Background(), "www.example.com"); err != nil {
			t.Fatal(err)
		}
		if z, err := m.zone(context.Background(), host); err != nil || z.Name != want {
			t.Fatalf("zone for %s = %+v, %v", host, z, err)
		}
	}
}

func TestEnsureRefusesSplitAddressRecordsUntilExplicitTakeover(t *testing.T) {
	m, fake := setup(t)
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "site.example.com", Content: here})
	fake.Seed(cloudflaretest.Record{Type: "A", Name: "site.example.com", Content: "198.51.100.7"})
	if _, err := m.Ensure(context.Background(), "site", "site.example.com", manifest.DNSDirect, false); !errors.Is(err, ErrElsewhere) {
		t.Fatalf("ignored a second destination: %v", err)
	}
	if len(fake.Records()) != 2 {
		t.Fatal("changed records before takeover")
	}
	if _, err := m.Ensure(context.Background(), "site", "site.example.com", manifest.DNSDirect, true); err != nil {
		t.Fatal(err)
	}
	if records := fake.Records(); len(records) != 1 || records[0].Content != here {
		t.Fatalf("takeover left split traffic: %+v", records)
	}
}

func TestLookReportsEveryDestinationForExactAndWildcardRecords(t *testing.T) {
	for _, wildcard := range []bool{false, true} {
		for _, remoteFirst := range []bool{false, true} {
			m, fake := setup(t)
			host := "site.example.com"
			name := host
			if wildcard {
				name = "*.example.com"
			}
			records := []cloudflaretest.Record{
				{Type: "A", Name: name, Content: here, Comment: Comment("site", m.Hostname)},
				{Type: "AAAA", Name: name, Content: "2001:db8::2"},
			}
			if remoteFirst {
				records[0], records[1] = records[1], records[0]
			}
			for _, r := range records {
				fake.Seed(r)
			}
			statuses, err := m.Look(context.Background(), []Route{{App: "site", Host: host}})
			if err != nil || len(statuses) != 1 {
				t.Fatalf("statuses = %+v, %v", statuses, err)
			}
			if !strings.Contains(statuses[0].Verdict, "elsewhere") {
				t.Fatalf("wildcard=%t remoteFirst=%t: a split destination appeared healthy: %+v", wildcard, remoteFirst, statuses[0])
			}
		}
	}
}
