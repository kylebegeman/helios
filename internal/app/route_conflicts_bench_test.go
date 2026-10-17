package app

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// Check the whole preflight, including SQLite reads and manifest decoding.
// Each app has four web workloads with four routes each. The candidate grows
// from a small app to a larger multi-service app on a populated machine.
func BenchmarkCheckRouteConflicts(b *testing.B) {
	for _, size := range []struct{ apps, workloads int }{{1, 2}, {25, 8}, {100, 32}} {
		b.Run(fmt.Sprintf("Apps%d/Workloads%d", size.apps, size.workloads), func(b *testing.B) {
			store, err := state.Open(filepath.Join(b.TempDir(), "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { store.Close() })
			ctx := b.Context()
			for i := 0; i < size.apps; i++ {
				m := benchmarkRouteManifest(fmt.Sprintf("app-%03d", i), 4)
				body, err := json.Marshal(m)
				if err != nil {
					b.Fatal(err)
				}
				r := state.Revision{App: m.App, ID: "rev-001", Status: state.RevisionActive, Manifest: body,
					Images: map[string]string{"web": "example/app:1"}, Containers: map[string]string{"web": "fixture"},
					CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
				if err := store.SaveRevision(ctx, r); err != nil {
					b.Fatal(err)
				}
			}
			candidate := benchmarkRouteManifest("candidate", size.workloads)
			if err := candidate.Validate(); err != nil {
				b.Fatal(err)
			}
			if err := CheckRouteConflicts(ctx, store, candidate); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := CheckRouteConflicts(ctx, store, candidate); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkRouteManifest(appName string, workloads int) *manifest.Manifest {
	m := &manifest.Manifest{App: appName, Workloads: make(map[string]manifest.Workload, workloads)}
	for w := 0; w < workloads; w++ {
		routes := []manifest.Route{
			{Host: appName + ".example.com", Path: fmt.Sprintf("/service-%02d", w), DNS: manifest.DNSDirect},
			{Host: "shared.example.com", Path: fmt.Sprintf("/%s/service-%02d", appName, w), DNS: manifest.DNSDirect},
			{Host: appName + ".example.com", Path: fmt.Sprintf("/service-%02d/admin", w), DNS: manifest.DNSDirect, Auth: manifest.AuthLoom},
			{Host: "api." + appName + ".example.com", Path: fmt.Sprintf("/v1/service-%02d", w), DNS: manifest.DNSDirect},
		}
		m.Workloads[fmt.Sprintf("web-%02d", w)] = manifest.Workload{Kind: manifest.Web, Image: "example/app:1", Port: 8080, Routes: routes}
	}
	return m
}
