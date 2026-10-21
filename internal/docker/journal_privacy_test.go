package docker

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// Incident redaction knows complete secret values. A fragment ending inside a
// value cannot be safely redacted, regardless of why its last chunk is absent.
func TestJournalEvidenceExcludesUnfinishedSecretFragments(t *testing.T) {
	entry := func(message, id string, ordinal int, partial bool) string {
		fields := map[string]string{"__REALTIME_TIMESTAMP": at(1), "CONTAINER_ID_FULL": "aaa", "PRIORITY": "6", "MESSAGE": message}
		if id != "" {
			fields["CONTAINER_PARTIAL_ID"] = id
			fields["CONTAINER_PARTIAL_ORDINAL"] = strconv.Itoa(ordinal)
		}
		if partial {
			fields["CONTAINER_PARTIAL_MESSAGE"] = "true"
		}
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw) + "\n"
	}
	const prefix = "synthetic-secret-prefix"
	for _, tc := range []struct {
		name, output string
		limit        int64
	}{
		{"end of window", entry(prefix, "p1", 1, true), 0},
		{"missing chunk", entry(prefix, "p1", 1, true) + entry("secret-tail", "p1", 3, false), 0},
		{"new partial id", entry(prefix, "p1", 1, true) + entry("complete next line", "p2", 1, false), 0},
		{"legacy unnumbered tail", entry(prefix, "", 0, true), 0},
		{"read budget", entry(prefix, "p1", 1, true) + entry(strings.Repeat("x", 1000), "p1", 2, false), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeJournal{out: entry("complete adjacent line", "", 0, false) + tc.output}
			var kept []string
			_, err := fake.journal().read(context.Background(), JournalQuery{App: "hello"}, tc.limit, false, func(line JournalLine) error { kept = append(kept, line.Text); return nil })
			if err != nil {
				t.Fatal(err)
			}
			if len(kept) == 0 || kept[0] != "complete adjacent line" {
				t.Fatalf("lost complete evidence: %q", kept)
			}
			if strings.Contains(strings.Join(kept, "\n"), prefix) {
				t.Fatal("evidence retained a secret fragment that cannot match its complete value")
			}
		})
	}
}
