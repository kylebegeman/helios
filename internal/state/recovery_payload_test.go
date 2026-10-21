package state

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMachineRecoveryRefusesUnreadableRevisionMapsBeforeImport(t *testing.T) {
	for _, fixture := range []struct{ column, value string }{
		{"images", `[]`},
		{"images", `{"web":42}`},
		{"containers", `"not a map"`},
		{"containers", `{"web":false}`},
	} {
		t.Run(fixture.column+fixture.value, func(t *testing.T) {
			ctx := context.Background()
			source, target := open(t), open(t)
			if err := source.SaveRevision(ctx, Revision{App: "site", ID: "old", Status: RevisionRetired, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if _, err := source.db.ExecContext(ctx, "UPDATE revisions SET "+fixture.column+"=?", fixture.value); err != nil {
				t.Fatal(err)
			}
			if err := target.ImportMachineRecovery(ctx, source.Path(), "malformed-revision", nil, nil); err == nil || !strings.Contains(err.Error(), "revisions."+fixture.column) {
				t.Fatalf("unreadable revision payload imported: %v", err)
			}
			if imported, err := target.MachineRecoveryImported(ctx, "malformed-revision"); err != nil || imported {
				t.Fatalf("invalid snapshot recorded as imported: %v, %v", imported, err)
			}
			if apps, err := target.AppNames(ctx); err != nil || len(apps) != 0 {
				t.Fatalf("invalid snapshot left app state behind: %v, %v", apps, err)
			}
		})
	}
}
