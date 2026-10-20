package incident

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
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
