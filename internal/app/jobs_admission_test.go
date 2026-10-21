package app

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/state"
)

func TestCronAdmissionSkipsAHeldOccurrenceAfterItsHoldExpires(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	m := releaseTestManifest()
	at := time.Now().UTC().Add(-2 * time.Hour)
	rev := releaseTestRevision(t, store, m, "active-revision", state.RevisionActive, at.Add(-time.Hour))
	until := at.Add(time.Hour)
	if _, err := store.HoldJob(ctx, m.App, "web", rev.ID, at, until, "maintenance"); err != nil {
		t.Fatal(err)
	}
	fake := dockertest.New(t)
	code, err := NewJobs(store, newSecrets(t)).RunWith(ctx, rev, "web", nil, JobCron, JobOptions{scheduledAt: at}, io.Discard)
	if code != -1 || err == nil || !strings.Contains(err.Error(), "held until "+OperatorTime(until)) || !strings.Contains(err.Error(), "queued run was skipped") {
		t.Fatalf("expired hold lost its scheduled-occurrence feedback: exit=%d, error=%v", code, err)
	}
	if open := mustOpen(t, store); len(open) != 0 {
		t.Fatalf("held occurrence left a durable run: %+v", open)
	}
	for _, call := range fake.Calls() {
		if strings.HasPrefix(call, "POST /containers/create") {
			t.Fatalf("held occurrence started a container: %s", call)
		}
	}
}
