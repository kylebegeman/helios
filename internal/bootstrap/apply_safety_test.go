package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/kernel"
)

func bootstrapPlan(t *testing.T, def Definition, in Input) *kernel.Plan {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := def.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func bootstrapStep(t *testing.T, plan *kernel.Plan, name string) kernel.Step {
	t.Helper()
	for _, step := range plan.Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("missing %s step", name)
	return kernel.Step{}
}

func TestBootstrapRepairsMatchingBinaryWithoutExecutePermission(t *testing.T) {
	def, in, _ := bootstrapFixture(t)
	candidate, err := os.ReadFile(in.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(in.Target.Binary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.Target.Binary, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	plan := bootstrapPlan(t, def, in)
	if err := bootstrapStep(t, plan, "install").Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapStep(t, plan, "capabilities").Apply(context.Background(), io.Discard); err != nil {
		t.Fatalf("matching binary remained unusable after bootstrap installation: %v", err)
	}
	installed, err := os.ReadFile(in.Target.Binary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(candidate, installed) {
		t.Fatal("repair changed the pinned binary bytes")
	}
}

func TestBootstrapChecksPersistedStateCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, capabilities string
		wantError          bool
	}{
		{"current", `{"api_version":1,"manifest_version":1,"machine_id":"linux:fixture","state_version":1,"min_state_version":0,"max_state_version":1,"persisted_state_version":1}`, false},
		{"fresh", `{"api_version":1,"manifest_version":1,"machine_id":"linux:fixture","state_version":1,"min_state_version":0,"max_state_version":1}`, false},
		{"fresh without legacy support", `{"api_version":1,"manifest_version":1,"machine_id":"linux:fixture","state_version":1,"min_state_version":1,"max_state_version":1}`, false},
		{"supported existing unversioned state", `{"api_version":1,"manifest_version":1,"machine_id":"linux:fixture","state_version":1,"min_state_version":0,"max_state_version":1,"persisted_state_version":0}`, false},
		{"unsupported existing unversioned state", `{"api_version":1,"manifest_version":1,"machine_id":"linux:fixture","state_version":1,"min_state_version":1,"max_state_version":1,"persisted_state_version":0}`, true},
		{"newer persisted state", `{"api_version":1,"manifest_version":1,"machine_id":"linux:fixture","state_version":1,"min_state_version":0,"max_state_version":1,"persisted_state_version":2}`, true},
		{"invalid range", `{"api_version":1,"manifest_version":1,"machine_id":"linux:fixture","state_version":1,"min_state_version":2,"max_state_version":1,"persisted_state_version":1}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			def, in, _ := bootstrapFixture(t)
			t.Setenv("BOOTSTRAP_TEST_CAPABILITIES", tc.capabilities)
			wrapper := filepath.Join(t.TempDir(), "ssh")
			script := `#!/bin/sh
for last do :; done
case "$last" in
 *"'capabilities'"*) printf '%s\n' "$BOOTSTRAP_TEST_CAPABILITIES" ;;
 *"'version'"*) printf '%s\n' '{"version":"fixture-dev","os":"linux","arch":"arm64"}' ;;
 *) exit 99 ;;
esac
`
			if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			def.Transport.Program = []string{wrapper}
			plan := bootstrapPlan(t, def, in)
			err := bootstrapStep(t, plan, "capabilities").Apply(context.Background(), io.Discard)
			if (err != nil) != tc.wantError {
				t.Fatalf("capabilities error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}

func TestBootstrapAppliesEmptyWebPolicyAsAnyone(t *testing.T) {
	def, in, record := bootstrapFixture(t)
	plan := bootstrapPlan(t, def, in)
	if err := bootstrapStep(t, plan, "install").Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapStep(t, plan, "host").Apply(context.Background(), io.Discard); err != nil {
		t.Fatal(err)
	}
	commands, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "--web-from=anyone") {
		t.Fatalf("empty profile web policy would retain a target's existing restriction: %s", commands)
	}
}
