package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/state"
)

var update = flag.Bool("update", false, "rewrite the golden files from what the code does now")

// The doc a person reads before an incident is the review helios alerts
// review fills in, rendered blank.
func TestTheReviewDocIsTheBlankReview(t *testing.T) {
	var got bytes.Buffer
	if err := WriteBlankReview(&got); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "operations", "incident-review.md")
	if *update {
		if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to write it)", err)
	}
	if got.String() != string(want) {
		t.Fatalf("the review template changed; diff %s against:\n%s", path, got.String())
	}
}

func TestReviewKeepsRedactedChangeDetailsWhenItsOperationFinishes(t *testing.T) {
	store := openStore(t)
	saveChange(t, store, "op-before", apps.DeployKind, "web", apps.DeployInput{Revision: "r1", Signer: apiToken}, opened.Add(-time.Minute))
	inc := openIncident(t, store, "app:web", "failing", opened)
	e, err := Collect(context.Background(), inc, Sources{Store: store, Secrets: fakeSecrets{versions: map[string]map[int]map[string]string{"web": {1: {"API_TOKEN": apiToken}}}}})
	if err != nil {
		t.Fatal(err)
	}
	// Evidence can be collected before the operation finishes. Later live
	// state supplies its outcome without replacing the redacted details.
	e.LastChange.FinishedAt = time.Time{}
	e.LastChange.Outcome = string(state.Applying)
	ops, err := OperationsAround(context.Background(), store, inc, opened.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	review := Review{Incident: inc, Evidence: e, Operations: ops}
	var out bytes.Buffer
	if err := review.Write(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), apiToken) {
		t.Fatal("the review restored a redacted secret from live operation state")
	}
	if !strings.Contains(out.String(), "signed by [redacted API_TOKEN]") || !strings.Contains(out.String(), "finished: succeeded") {
		t.Fatal("the review lost safe change details or the current outcome")
	}
}

func TestReviewWithoutEvidenceLeavesUnredactedMessagesOut(t *testing.T) {
	target := "https://user:synthetic-password@example.test/api?token=synthetic-token"
	review := Review{Incident: state.Incident{ID: 42, Key: "watch:" + target, Subject: target, Severity: state.SeverityCritical, Message: "health output: " + apiToken, OpenedAt: opened}, Host: "10.0.0.1"}
	var out bytes.Buffer
	if err := review.Write(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), apiToken) {
		t.Fatal("a review without evidence printed an unredacted incident message")
	}
	if strings.Contains(out.String(), "synthetic-") || strings.Contains(out.String(), "10.0.0.1") {
		t.Fatal("a review without evidence printed credentials or a private host")
	}
	if !strings.Contains(out.String(), messageOmitted) {
		t.Fatal("the review did not explain that its message was omitted")
	}
}

func TestReviewLeavesRawLaterChangeDetailsOut(t *testing.T) {
	input, err := json.Marshal(apps.DeployInput{Revision: apiToken, Commit: backupKey, Signer: "ops@node.example.ts.net"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		evidence *Evidence
	}{{"without evidence", nil}, {"with opening evidence", full()}} {
		t.Run(tc.name, func(t *testing.T) {
			review := Review{
				Incident: state.Incident{ID: 42, Key: "app:web", Subject: "web", Message: "failing", OpenedAt: opened}, Evidence: tc.evidence,
				Operations: []state.Operation{{ID: "op-later", Kind: apps.DeployKind, Target: "web", Input: input, StartedAt: opened.Add(time.Minute), FinishedAt: opened.Add(2 * time.Minute), Status: state.Succeeded}},
			}
			var out bytes.Buffer
			if err := review.Write(&out); err != nil {
				t.Fatal(err)
			}
			for _, value := range []string{apiToken, backupKey[:commitShown], "node.example.ts.net"} {
				if strings.Contains(out.String(), value) {
					t.Error("a later operation restored raw change details without redaction")
				}
			}
			if !strings.Contains(out.String(), "app.deploy of web started (op-later)") || !strings.Contains(out.String(), "app.deploy of web finished: succeeded (op-later)") {
				t.Fatal("the later operation's lifecycle was lost")
			}
		})
	}
}
