package daemon

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

// The scheduler needs one timestamp, regardless of retained deploy history.
func BenchmarkSchedulerFirstDeploy(b *testing.B) {
	for _, history := range []int{1, 100, 1000} {
		b.Run(fmt.Sprintf("Revisions%d", history), func(b *testing.B) {
			store, err := state.Open(filepath.Join(b.TempDir(), "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { store.Close() })
			ctx := b.Context()
			first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			for i := 0; i < history; i++ {
				r := state.Revision{App: "fixture", ID: fmt.Sprintf("rev-%04d", i), Status: state.RevisionRetired,
					Manifest: []byte(`{"app":"fixture","workloads":{"web":{"kind":"web","image":"example/app:1","port":8080,"routes":[{"host":"fixture.example.com"}]}}}`),
					Images:   map[string]string{"web": "example/app:1"}, Containers: map[string]string{"web": "fixture-web"},
					CreatedAt: first.Add(time.Duration(i) * time.Hour)}
				if err := store.SaveRevision(ctx, r); err != nil {
					b.Fatal(err)
				}
			}
			s := Scheduler{Store: store}
			if got := s.firstDeploy(ctx, "fixture"); !got.Equal(first) {
				b.Fatalf("first deployment: got %s, want %s", got, first)
			}
			b.ReportAllocs()
			for b.Loop() {
				if got := s.firstDeploy(ctx, "fixture"); !got.Equal(first) {
					b.Fatal("first deployment changed")
				}
			}
		})
	}
}
