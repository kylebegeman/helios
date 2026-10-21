package state

import (
	"context"
	"testing"
	"time"
)

func TestMachineRecoveryDoesNotRetryTheSourceMachinesIncidentNotices(t *testing.T) {
	ctx := context.Background()
	source, target := open(t), open(t)
	at := time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC)
	for _, resolved := range []bool{false, true} {
		incident := Incident{Key: "host:disk", Subject: "source disk", Severity: SeverityCritical, Message: "source disk is full", OpenedAt: at}
		id, err := source.OpenIncident(ctx, incident)
		if err != nil {
			t.Fatal(err)
		}
		incident.ID, incident.NotifyError = id, "source delivery failed"
		if resolved {
			incident.ResolvedAt = at.Add(time.Minute)
		}
		if err := source.UpdateIncident(ctx, incident); err != nil {
			t.Fatal(err)
		}
	}
	local := Incident{Key: "host:backup", Subject: "target backup", OpenedAt: at}
	id, err := target.OpenIncident(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	local.ID, local.ResolvedAt, local.NotifyError = id, at.Add(time.Minute), "target delivery failed"
	if err := target.UpdateIncident(ctx, local); err != nil {
		t.Fatal(err)
	}
	if err := target.ImportMachineRecovery(ctx, source.Path(), "source-notifications", nil, nil); err != nil {
		t.Fatal(err)
	}
	pending, err := target.PendingResolvedIncidentNotices(ctx)
	if err != nil || len(pending) != 1 || pending[0].ID != local.ID {
		t.Fatalf("source history became target notification work: %+v, %v", pending, err)
	}
	history, err := target.Incidents(ctx, 10)
	if err != nil || len(history) != 3 {
		t.Fatalf("source incident history was lost: %+v, %v", history, err)
	}
	for _, incident := range history {
		if incident.Key == "host:disk" && (incident.Open() || incident.Message != "source disk is full") {
			t.Fatalf("source incident was not retained as history: %+v", incident)
		}
	}
	originals, err := source.Incidents(ctx, 10)
	if err != nil || len(originals) != 2 {
		t.Fatalf("source incidents: %+v, %v", originals, err)
	}
	for _, incident := range originals {
		if incident.NotifyError != "source delivery failed" {
			t.Fatalf("source notification queue changed: %+v", incident)
		}
	}
}
