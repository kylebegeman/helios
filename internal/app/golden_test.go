package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

var update = flag.Bool("update", false, "rewrite the golden files from what the code does now")

// golden compares text with testdata/<name>.golden, or writes it there
// with -update. Plans are what a person approves and a digest pins, so a
// change to any of them should be one somebody meant.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to write it)", err)
	}
	if got != string(want) {
		t.Fatalf("%s changed:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// planText is a plan as a person reads it, every word that goes into the
// digest and every note.
func planText(p *kernel.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "target %s, %s\n", p.Target, p.Recovery)
	for i, st := range p.Steps {
		fmt.Fprintf(&b, "%2d %s: %s", i+1, st.Name, st.Change)
		if st.Note != "" {
			fmt.Fprintf(&b, " (%s)", st.Note)
		}
		undo := ""
		if st.Undo != nil {
			undo = " [undo]"
		}
		fmt.Fprintf(&b, "%s\n", undo)
	}
	return b.String()
}

func goldenStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestThePlansStayWhatTheyWere(t *testing.T) {
	ctx := context.Background()
	m, dir := loadCore(t)
	raw, _ := json.Marshal(m)
	images := map[string]string{}
	for _, name := range m.WorkloadNames() {
		images[name] = "img-" + name
	}
	nobody := func(context.Context) []string { return nil }

	t.Run("deploy", func(t *testing.T) {
		d := Deploy{Secrets: newSecrets(t), StateDir: t.TempDir(), Addresses: nobody}
		plan, err := d.rollout(ctx, m, "20260922-120000", &buildFrom{source: dir, commit: "0123456789ab", signer: "kyle@example.com (SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg)",
			restore: Restore{Postgres: "/restore/pg.dump", Volumes: map[string]string{"files": "/restore/files.tar.gz"}}, secretsFrom: "parent"})
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "plan-deploy", planText(plan))
	})
	t.Run("rollback", func(t *testing.T) {
		store := goldenStore(t)
		if err := store.SaveRevision(ctx, state.Revision{App: "loom", ID: "20260918-120000", Status: state.RevisionPrevious, Manifest: raw, Images: images, Containers: map[string]string{}, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		d := Deploy{Store: store, StateDir: t.TempDir(), Addresses: nobody}
		plan, err := d.rollout(ctx, m, "20260918-120000", nil)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "plan-rollback", planText(plan))
	})
	t.Run("drill", func(t *testing.T) {
		// A privileged workload is refused a drill, so this one isn't.
		drillable := *m
		drillable.Workloads = maps.Clone(m.Workloads)
		runner := drillable.Workloads["runner"]
		runner.Privileged = false
		drillable.Workloads["runner"] = runner
		drillRaw, _ := json.Marshal(&drillable)
		store := goldenStore(t)
		if err := store.SaveRevision(ctx, state.Revision{App: "loom", ID: "r1", Status: state.RevisionActive, Manifest: drillRaw, Images: images, Containers: map[string]string{}, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		plan, err := Drill{Store: store, Secrets: newSecrets(t), StateDir: t.TempDir()}.Plan(ctx, json.RawMessage(`{"app":"loom"}`))
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "plan-drill", planText(plan))
	})
	t.Run("restore", func(t *testing.T) {
		plan, err := RestoreDef{Store: goldenStore(t), Secrets: newSecrets(t), StateDir: t.TempDir()}.Plan(ctx, json.RawMessage(`{"app":"loom","snapshot":"abc12345"}`))
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "plan-restore", planText(plan))
	})
	t.Run("remove", func(t *testing.T) {
		store := goldenStore(t)
		if err := store.SaveRevision(ctx, state.Revision{App: "loom", ID: "r1", Status: state.RevisionActive, Manifest: raw, Images: images, Containers: map[string]string{}, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		var all strings.Builder
		for _, in := range []string{`{"app":"loom"}`, `{"app":"loom","data":true}`, `{"app":"loom","data":true,"secrets":true}`} {
			plan, err := Remove{Store: store, Secrets: newSecrets(t), StateDir: t.TempDir()}.Plan(ctx, json.RawMessage(in))
			if err != nil {
				t.Fatal(err)
			}
			all.WriteString(in + "\n" + planText(plan))
		}
		golden(t, "plan-remove", all.String())
	})
}

func TestTheBackupAndCollectionPlansStayWhatTheyWere(t *testing.T) {
	ctx := context.Background()
	m, _ := loadCore(t)
	raw, _ := json.Marshal(m)
	sec := newSecrets(t)
	if _, _, err := integration.Set(sec, integration.StorageName, map[string]string{"kind": "s3", "endpoint": "http://127.0.0.1:9000", "key_id": "id", "key": "k", "bucket_prefix": "lane"}); err != nil {
		t.Fatal(err)
	}
	store := goldenStore(t)
	if err := store.SaveRevision(ctx, state.Revision{App: "loom", ID: "r1", Status: state.RevisionActive, Manifest: raw, Images: map[string]string{}, Containers: map[string]string{}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(ctx, "loom", "r1", time.Now()); err != nil {
		t.Fatal(err)
	}
	b := Backup{Store: store, Secrets: sec, StateDir: t.TempDir(), Hostname: func() string { return "box" }, Profile: "/etc/bedrock/host.json"}
	var all strings.Builder
	for _, app := range []string{"loom", "bedrock"} {
		plan, err := b.Plan(ctx, json.RawMessage(`{"app":"`+app+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		all.WriteString(app + "\n" + planText(plan))
	}
	golden(t, "plan-backup", all.String())

	fake := dockertest.New(t)
	fake.Add(dockertest.Container{Name: "bedrock-loom-api-r0", Labels: map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: "loom", docker.LabelRevision: "r0"}})
	fake.Add(dockertest.Container{Name: "bedrock-loom-api-r1", Running: true, Labels: map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: "loom", docker.LabelRevision: "r1"}})
	all.Reset()
	for _, in := range []string{`{}`, `{"keep_build_cache":true}`, `{"build_cache_max":-1}`} {
		plan, err := GC{Store: store}.Plan(ctx, json.RawMessage(in))
		if err != nil {
			t.Fatal(err)
		}
		all.WriteString(in + "\n" + planText(plan))
	}
	golden(t, "plan-gc", all.String())
}
