package signals

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

func TestFailedTrafficWritesKeepTheWholeIntervalForRetry(t *testing.T) {
	for _, failure := range []struct{ name, condition string }{
		{"first write", "1"},
		{"later write", "EXISTS (SELECT 1 FROM signals)"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			ctx := context.Background()
			store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			db, err := sql.Open("sqlite", store.Path())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			sampler := &Sampler{Store: store}
			hosts := map[string]string{"app.example.com": "site", "other.example.com": "site"}
			series := func(requests, bytes float64, other bool) []Series {
				out := []Series{
					{Name: "caddy_http_requests_total", Labels: map[string]string{"handler": "subroute", "host": "app.example.com"}, Value: requests},
					{Name: "caddy_http_response_size_bytes_sum", Labels: map[string]string{"handler": "subroute", "host": "app.example.com"}, Value: bytes},
				}
				if other {
					out = append(out, Series{Name: "caddy_http_requests_total", Labels: map[string]string{"handler": "subroute", "host": "other.example.com"}, Value: 20})
				}
				return out
			}
			if err := sampler.traffic(ctx, now, series(10, 100, true), hosts); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `CREATE TRIGGER refuse_traffic BEFORE INSERT ON signals WHEN `+failure.condition+` BEGIN SELECT RAISE(ABORT, 'fixture traffic write failure'); END`); err != nil {
				t.Fatal(err)
			}
			// This complete scrape would also evict the other host. A failed
			// write must preserve that host's baseline along with the deltas.
			failed := series(15, 160, false)
			if err := sampler.traffic(ctx, now.Add(time.Minute), failed, hosts); err == nil || !strings.Contains(err.Error(), "fixture traffic write failure") {
				t.Fatalf("expected the injected write failure, got %v", err)
			}
			rows, err := store.Signals(ctx, "site", now)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Errorf("failed traffic batch partially persisted: %+v", rows)
			}
			if _, err := db.ExecContext(ctx, "DROP TRIGGER refuse_traffic"); err != nil {
				t.Fatal(err)
			}
			// Retry the same counters, then observe more traffic. The other
			// host comes back at 22, so only its two new requests count.
			retry := series(15, 160, false)
			retry = append(retry, Series{Name: "caddy_http_requests_total", Labels: map[string]string{"handler": "subroute", "host": "other.example.com"}, Value: 22})
			for _, sample := range [][]Series{retry, retry, series(17, 180, false)} {
				if err := sampler.traffic(ctx, now.Add(2*time.Minute), sample, hosts); err != nil {
					t.Fatal(err)
				}
			}
			rows, err = store.Signals(ctx, "site", now)
			if err != nil {
				t.Fatal(err)
			}
			if got := Summarize(rows); got.Requests != 9 || got.Bytes != 80 {
				t.Fatalf("failed interval lost or recounted on retry: %+v; want 9 requests and 80 bytes", got)
			}
		})
	}
}
