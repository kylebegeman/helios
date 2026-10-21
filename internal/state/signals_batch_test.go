package state

import (
	"context"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestSignalBatchesRollBackEveryEarlierWriteOnFailure(t *testing.T) {
	for _, failure := range []string{"database", "nonfinite", "overflow"} {
		t.Run(failure, func(t *testing.T) {
			store := open(t)
			ctx := context.Background()
			now := time.Date(2026, 10, 21, 12, 30, 0, 0, time.UTC)
			signal := func(metric string, value float64) Signal {
				return Signal{Hour: now, App: "site", Key: "app.example.com", Metric: metric, Value: value, Samples: 1}
			}
			if err := store.AddSignal(ctx, signal(SignalRequests, 5)); err != nil {
				t.Fatal(err)
			}
			batch := []Signal{signal(SignalRequests, 3), signal(SignalBytes, 10), signal(SignalErrors, 2)}
			switch failure {
			case "database":
				if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER refuse_signal BEFORE INSERT ON signals WHEN NEW.metric='errors' BEGIN SELECT RAISE(ABORT, 'fixture signal write failure'); END`); err != nil {
					t.Fatal(err)
				}
			case "nonfinite":
				batch[2].Value = math.NaN()
			case "overflow":
				batch[2].Value = math.MaxFloat64
				if err := store.AddSignal(ctx, batch[2]); err != nil {
					t.Fatal(err)
				}
			}
			before, err := store.Signals(ctx, "site", now.Truncate(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.AddSignals(ctx, batch); err == nil {
				t.Fatal("failed signal batch was accepted")
			}
			after, err := store.Signals(ctx, "site", now.Truncate(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after, before) {
				t.Errorf("failed batch changed hourly rollups: got %+v, want %+v", after, before)
			}
			if failure == "database" {
				if _, err := store.db.ExecContext(ctx, "DROP TRIGGER refuse_signal"); err != nil {
					t.Fatal(err)
				}
				if err := store.AddSignals(ctx, batch); err != nil {
					t.Fatal(err)
				}
				rows, err := store.Signals(ctx, "site", now.Truncate(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]float64{SignalRequests: 8, SignalBytes: 10, SignalErrors: 2}
				if len(rows) != len(want) {
					t.Fatalf("retried signal batch: %+v", rows)
				}
				for _, row := range rows {
					samples := 1
					if row.Metric == SignalRequests {
						samples = 2
					}
					if row.Value != want[row.Metric] || row.Samples != samples {
						t.Errorf("retried signal counted incorrectly: %+v", row)
					}
				}
			}
		})
	}
}
