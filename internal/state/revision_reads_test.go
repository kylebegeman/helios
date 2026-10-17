package state

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFirstRevisionCreatedAtReadsOnlyTimestampAcrossAllStatuses(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	first := time.Date(2026, 1, 1, 12, 0, 0, 123000000, time.UTC)
	for _, r := range []Revision{
		{App: "site", ID: "active", Status: RevisionActive, CreatedAt: first.Add(3 * time.Hour)},
		{App: "site", ID: "previous", Status: RevisionPrevious, CreatedAt: first.Add(2 * time.Hour)},
		{App: "site", ID: "failed", Status: RevisionFailed, CreatedAt: first},
		{App: "site", ID: "retired", Status: RevisionRetired, CreatedAt: first},
		{App: "other", ID: "older", Status: RevisionRetired, CreatedAt: first.Add(-time.Hour)},
	} {
		if err := s.SaveRevision(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// Corrupted payloads must not prevent a timestamp-only read. In particular,
	// old failed revisions need not be decoded to schedule a current app.
	if _, err := s.db.ExecContext(ctx, `UPDATE revisions SET images = 'invalid json', containers = 'invalid json' WHERE app = ? AND id = ?`, "site", "failed"); err != nil {
		t.Fatal(err)
	}
	got, err := s.FirstRevisionCreatedAt(ctx, "site")
	if err != nil || !got.Equal(first) {
		t.Fatalf("first revision timestamp = %v, %v; want %v", got, err, first)
	}
}

func TestFirstRevisionCreatedAtDistinguishesMissingFromZeroTimestamp(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if got, err := s.FirstRevisionCreatedAt(ctx, "missing"); !errors.Is(err, ErrNotFound) || !got.IsZero() {
		t.Fatalf("missing app = %v, %v; want zero, ErrNotFound", got, err)
	}
	for _, r := range []Revision{
		{App: "site", ID: "zero", Status: RevisionFailed},
		{App: "site", ID: "later", Status: RevisionActive, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if err := s.SaveRevision(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.FirstRevisionCreatedAt(ctx, "site"); err != nil || !got.IsZero() {
		t.Fatalf("zero creation time = %v, %v; want zero, nil", got, err)
	}
}

func TestFirstRevisionCreatedAtSupportsReadOnlyAndCancellation(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	first := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := s.SaveRevision(ctx, Revision{App: "site", ID: "first", Status: RevisionRetired, CreatedAt: first}); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if got, err := ro.FirstRevisionCreatedAt(ctx, "site"); err != nil || !got.Equal(first) {
		t.Fatalf("read-only timestamp = %v, %v; want %v", got, err, first)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.FirstRevisionCreatedAt(canceled, "site"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled timestamp read = %v; want context.Canceled", err)
	}
}

func TestActiveRevisionsOrdersAppsAndIDsAndExcludesHistoricalPayloads(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	// Insert in a different order from both app and ID order. Multiple active
	// rows for an app retain the existing app/id index traversal tie order.
	for _, r := range []Revision{
		{App: "zeta", ID: "r2", Status: RevisionActive},
		{App: "alpha", ID: "r2", Status: RevisionActive},
		{App: "alpha", ID: "r1", Status: RevisionActive},
		{App: "alpha", ID: "old", Status: RevisionRetired},
		{App: "beta", ID: "failed", Status: RevisionFailed},
	} {
		if err := s.SaveRevision(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE revisions SET images = 'invalid json' WHERE status <> ?`, string(RevisionActive)); err != nil {
		t.Fatal(err)
	}
	got, err := s.ActiveRevisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range got {
		keys = append(keys, r.App+"/"+r.ID)
	}
	if want := []string{"alpha/r1", "alpha/r2", "zeta/r2"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("active revisions = %v; want %v", keys, want)
	}
}

func TestActiveRevisionsPreservesPayloadAndContextErrors(t *testing.T) {
	for _, column := range []string{"images", "containers"} {
		t.Run(column, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()
			if err := s.SaveRevision(ctx, Revision{App: "site", ID: "live", Status: RevisionActive}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, `UPDATE revisions SET `+column+` = 'invalid json'`); err != nil {
				t.Fatal(err)
			}
			if got, err := s.ActiveRevisions(ctx); got != nil || err == nil || !strings.Contains(err.Error(), "revision site/live "+column) {
				t.Fatalf("malformed %s = %+v, %v; want revision payload error", column, got, err)
			}
		})
	}
	s := open(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ActiveRevisions(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled active revision read = %v; want context.Canceled", err)
	}
}
