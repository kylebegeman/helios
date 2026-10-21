package state

import (
	"context"
	"testing"
	"time"
)

func TestRepeatingActivationKeepsThePreviousRevisionAvailableForRollback(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for i, id := range []string{"old", "new"} {
		if err := s.CreateRevision(ctx, Revision{App: "site", ID: id, Status: RevisionFailed, CreatedAt: at.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := s.Activate(ctx, "site", id, at.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// The switch step can be retried after activation but before its edge
	// configuration or journal entry finished.
	if err := s.Activate(ctx, "site", "new", at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	previous, err := s.RevisionWithStatus(ctx, "site", RevisionPrevious)
	if err != nil || previous == nil || previous.ID != "old" {
		t.Fatalf("retry lost the rollback revision: %+v, %v", previous, err)
	}
	if err := s.Activate(ctx, "site", previous.ID, at.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	active, err := s.RevisionWithStatus(ctx, "site", RevisionActive)
	if err != nil || active == nil || active.ID != "old" {
		t.Fatalf("rollback after retry: %+v, %v", active, err)
	}
	previous, err = s.RevisionWithStatus(ctx, "site", RevisionPrevious)
	if err != nil || previous == nil || previous.ID != "new" {
		t.Fatalf("rollback lost its own previous revision: %+v, %v", previous, err)
	}
}
