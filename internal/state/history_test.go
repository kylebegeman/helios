package state

import (
	"context"
	"testing"
	"time"
)

func TestOperationFiltersRunBeforeTheLimitAndIncludeCompensatedFailures(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	for i, row := range []struct {
		id, target, kind string
		status           OperationStatus
	}{
		{"old", "api", "app.deploy", Failed},
		{"failed", "api", "app.deploy", Failed},
		{"compensated", "api", "app.deploy", Compensated},
		{"success", "api", "app.deploy", Succeeded},
		{"backup", "api", "app.backup", Failed},
		{"other-app", "site", "app.deploy", Failed},
	} {
		op := newOp(row.id, start.Add(time.Duration(i)*time.Minute))
		op.Target, op.Kind = row.target, row.kind
		if err := s.CreateOperation(ctx, op); err != nil {
			t.Fatal(err)
		}
		if err := s.Finish(ctx, row.id, row.status, "", nil, op.CreatedAt.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListFiltered(ctx, OperationFilter{Target: "api", Kind: "app.deploy", Failed: true, Since: start.Add(time.Minute), Limit: 1})
	if err != nil || len(rows) != 1 || rows[0].ID != "compensated" {
		t.Fatalf("combined filter before limit: %v %+v", err, rows)
	}
	rows, err = s.ListFiltered(ctx, OperationFilter{Target: "api", Kind: "app.deploy", Failed: true, Since: start.Add(time.Minute)})
	if err != nil || len(rows) != 2 || rows[1].ID != "failed" {
		t.Fatalf("since includes the boundary: %v %+v", err, rows)
	}
	rows, err = s.ListFiltered(ctx, OperationFilter{Target: "api", Since: start.Add(time.Minute), Until: start.Add(2 * time.Minute)})
	if err != nil || len(rows) != 2 || rows[0].ID != "compensated" || rows[1].ID != "failed" {
		t.Fatalf("until includes the boundary: %v %+v", err, rows)
	}
	rows, err = s.ListFiltered(ctx, OperationFilter{Target: "api' OR 1=1 --"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("filter values must be bound: %v %+v", err, rows)
	}
}
