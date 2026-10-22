package app

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

func TestRunApprovalBindsArgumentsRevisionAndExtraSecretNames(t *testing.T) {
	for _, change := range []string{"arguments", "revision", "extra-secrets"} {
		t.Run(change, func(t *testing.T) {
			dockertest.New(t)
			ctx := context.Background()
			store := releaseTestStore(t)
			m := releaseTestManifest()
			releaseTestRevision(t, store, m, "approved-revision", state.RevisionActive, time.Now())
			registry := kernel.Registry{}
			registry.Add(RunDefinition{Jobs: NewJobs(store, newSecrets(t))})
			engine := kernel.New(store, registry, "test")
			input := RunInput{App: m.App, Workload: "web", Command: []string{"echo", "a b"}, Secrets: []string{"APPROVED_TOKEN"}}
			raw, _ := json.Marshal(input)
			approved, err := engine.PlanOnly(ctx, RunKind, raw)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "arguments":
				input.Command = []string{"echo", "a", "b"}
			case "revision":
				if err := store.SetRevisionStatus(ctx, m.App, "approved-revision", state.RevisionRetired); err != nil {
					t.Fatal(err)
				}
				releaseTestRevision(t, store, m, "new-revision", state.RevisionActive, time.Now())
			case "extra-secrets":
				input.Secrets = []string{"DIFFERENT_TOKEN"}
			}
			raw, _ = json.Marshal(input)
			current, err := engine.PlanOnly(ctx, RunKind, raw)
			if err != nil {
				t.Fatal(err)
			}
			if current.Digest == approved.Digest {
				t.Errorf("changed %s retained the approved plan digest", change)
			}
			if _, err := engine.RunExpecting(ctx, RunKind, raw, approved.Digest, func(kernel.Event) {}); !errors.Is(err, kernel.ErrPlanChanged) {
				t.Fatalf("changed %s entered execution with old approval: %v", change, err)
			}
			operations, err := store.List(ctx, 10)
			if err != nil || len(operations) != 0 {
				t.Fatalf("stale approval journaled an operation: %+v, %v", operations, err)
			}
		})
	}
}
