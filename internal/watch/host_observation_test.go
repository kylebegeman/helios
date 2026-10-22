package watch

import (
	"context"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/state"
)

func TestUnavailableDiskMeasurementsCannotCertifyRecovery(t *testing.T) {
	for _, tc := range []struct {
		name        string
		free, total uint64
		ok          bool
	}{
		{name: "statfs failed"},
		{name: "no capacity", ok: true},
		{name: "inconsistent capacity", free: 2, total: 1, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			notifier := &fakeNotifier{}
			w, now := newWatcher(t, notifier)
			w.OpenAfter = 1
			keys := []string{"host:disk", "host:disk-forecast"}
			var failing []Condition
			for _, key := range keys {
				failing = append(failing, Condition{Key: key, Subject: key, Severity: state.SeverityCritical, Message: "disk space is exhausted"})
			}
			if err := w.Round(ctx, failing); err != nil {
				t.Fatal(err)
			}
			p := NewProber(w.Store)
			p.Now = func() time.Time { return *now }
			p.Disk = func(string) (uint64, uint64, bool) { return tc.free, tc.total, tc.ok }
			for range DefaultResolveAfter + 1 {
				*now = now.Add(time.Minute)
				if err := w.Round(ctx, p.host(ctx)); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range keys {
				inc, err := w.Store.OpenIncidentByKey(ctx, key)
				if err != nil || inc == nil || toldResolved(notifier, key) {
					t.Fatalf("unobserved %s was reported recovered: %+v, %v", key, inc, err)
				}
			}
			p.Disk = func(string) (uint64, uint64, bool) { return 50 << 30, 100 << 30, true }
			for range DefaultResolveAfter {
				*now = now.Add(time.Minute)
				if err := w.Round(ctx, p.host(ctx)); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range keys {
				inc, err := w.Store.OpenIncidentByKey(ctx, key)
				if err != nil || inc != nil || !toldResolved(notifier, key) {
					t.Fatalf("a fresh healthy observation did not resolve %s: %+v, %v", key, inc, err)
				}
			}
		})
	}
}

func TestUnavailableMemoryMeasurementsCannotCertifyRecovery(t *testing.T) {
	for _, tc := range []struct {
		name             string
		available, total uint64
		ok               bool
	}{
		{name: "memory read failed"},
		{name: "no capacity", ok: true},
		{name: "inconsistent capacity", available: 2, total: 1, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			notifier := &fakeNotifier{}
			w, now := newWatcher(t, notifier)
			w.OpenAfter = 1
			const key = "host:memory"
			if err := w.Round(ctx, []Condition{{Key: key, Subject: "memory", Severity: state.SeverityWarning, Message: "memory is exhausted"}}); err != nil {
				t.Fatal(err)
			}
			p := NewProber(w.Store)
			p.Now = func() time.Time { return *now }
			p.Disk = func(string) (uint64, uint64, bool) { return 50 << 30, 100 << 30, true }
			p.Memory = func() (uint64, uint64, bool) { return tc.available, tc.total, tc.ok }
			for range DefaultResolveAfter + 1 {
				*now = now.Add(time.Minute)
				if err := w.Round(ctx, p.host(ctx)); err != nil {
					t.Fatal(err)
				}
			}
			inc, err := w.Store.OpenIncidentByKey(ctx, key)
			if err != nil || inc == nil || toldResolved(notifier, key) {
				t.Fatalf("unobserved memory was reported recovered: %+v, %v", inc, err)
			}
			p.Memory = func() (uint64, uint64, bool) { return 50, 100, true }
			for range DefaultResolveAfter {
				*now = now.Add(time.Minute)
				if err := w.Round(ctx, p.host(ctx)); err != nil {
					t.Fatal(err)
				}
			}
			inc, err = w.Store.OpenIncidentByKey(ctx, key)
			if err != nil || inc != nil || !toldResolved(notifier, key) {
				t.Fatalf("a fresh healthy observation did not resolve memory: %+v, %v", inc, err)
			}
			p.Memory = func() (uint64, uint64, bool) { return 0, 100, true }
			*now = now.Add(time.Minute)
			if err := w.Round(ctx, p.host(ctx)); err != nil {
				t.Fatal(err)
			}
			inc, err = w.Store.OpenIncidentByKey(ctx, key)
			if err != nil || inc == nil || inc.Severity != state.SeverityWarning {
				t.Fatalf("zero available memory was not reported exhausted: %+v, %v", inc, err)
			}
		})
	}
}
