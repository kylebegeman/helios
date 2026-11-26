package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

func seedApp(t *testing.T, store *state.Store, app string) {
	t.Helper()
	seedManifest(t, store, app, `{"app":"`+app+`","workloads":{"web":{"kind":"web","image":"x","port":80,"routes":[{"host":"`+app+`.example.com"}]}}}`)
}

// seedPreview records a preview the way preview up derives one: the name
// alone doesn't make it one, its preview block does.
func seedPreview(t *testing.T, store *state.Store, app, of string) {
	t.Helper()
	seedManifest(t, store, app, `{"app":"`+app+`","preview":{"of":"`+of+`","branch":"nav"},"workloads":{"web":{"kind":"web","image":"x","port":80,"routes":[{"host":"`+app+`.example.com","auth":"loom"}]}}}`)
}

func seedManifest(t *testing.T, store *state.Store, app, manifest string) {
	t.Helper()
	rev := state.Revision{App: app, ID: "r1", Status: state.RevisionActive, Manifest: json.RawMessage(manifest), CreatedAt: time.Now().UTC()}
	if err := store.SaveRevision(context.Background(), rev); err != nil {
		t.Fatal(err)
	}
}

func TestRemovingWithDataForgetsTheSecrets(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedApp(t, store, "site")
	seedPreview(t, store, "site-pr-nav", "site")
	// Named like a preview, but not one.
	seedApp(t, store, "api-pr-tools")
	r := Remove{Store: store, Secrets: newSecrets(t), StateDir: t.TempDir()}
	forget := func(in RemoveInput) string {
		t.Helper()
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := r.Plan(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		return plan.Steps[len(plan.Steps)-1].Change
	}
	if c := forget(RemoveInput{App: "site-pr-nav", Data: true}); !strings.Contains(c, "the secrets it was given as a preview") {
		t.Fatalf("a preview removed with its data keeps its secrets: %q", c)
	}
	if c := forget(RemoveInput{App: "site-pr-nav"}); strings.Contains(c, "secrets") {
		t.Fatalf("a preview kept for its data lost its secrets: %q", c)
	}
	if c := forget(RemoveInput{App: "api-pr-tools", Data: true}); strings.Contains(c, "as a preview") {
		t.Fatalf("an app named like a preview was taken for one: %q", c)
	}
	if c := forget(RemoveInput{App: "site", Data: true}); !strings.Contains(c, ", and its sealed secrets") {
		t.Fatalf("an app removed with its data kept the secrets that opened it: %q", c)
	}
	if c := forget(RemoveInput{App: "site"}); strings.Contains(c, "secrets") {
		t.Fatalf("an app removed without its data lost its secrets: %q", c)
	}
	if c := forget(RemoveInput{App: "site", Secrets: true}); !strings.Contains(c, ", and its sealed secrets") {
		t.Fatalf("--secrets was not honoured: %q", c)
	}
}

func TestForgettingAnAppClearsWhatTheMachineKeptForIt(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	seedApp(t, store, "hello")
	if err := store.SaveGitHook(ctx, state.GitHook{App: "hello", Repo: "r", Branch: "main", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	sec := newSecrets(t)
	hook, key, storage := "hook", "key", "storage"
	if _, err := sec.SetAll(integration.App, map[string]*string{integration.WebhookSecretName("hello"): &hook, integration.DeployKeyName("hello"): &key, "STORAGE_KEY": &storage}); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.Set("hello", "API_KEY", "v"); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	for _, d := range []string{"backups/hello", "restore/hello", "drills/hello", "builds/hello", "backups/other"} {
		if err := os.MkdirAll(filepath.Join(stateDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var out strings.Builder
	if err := forgetApp(ctx, store, sec, stateDir, "hello", false, nil, &out); err != nil {
		t.Fatal(err)
	}
	if revs, _ := store.Revisions(ctx, "hello"); len(revs) != 0 {
		t.Fatalf("revisions survived: %+v", revs)
	}
	if h, _ := store.GitHookFor(ctx, "hello"); h != nil {
		t.Fatalf("the webhook survived: %+v", h)
	}
	for _, d := range []string{"backups/hello", "restore/hello", "drills/hello", "builds/hello"} {
		if _, err := os.Stat(filepath.Join(stateDir, d)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived: %v", d, err)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, "backups/other")); err != nil {
		t.Fatalf("another app's directory went: %v", err)
	}
	own, _, err := sec.LoadCurrent(integration.App)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := own[integration.WebhookSecretName("hello")]; ok {
		t.Fatal("the webhook secret survived")
	}
	if own["STORAGE_KEY"] != "storage" {
		t.Fatal("an integration credential went with the app")
	}
	if v, _, _ := sec.LoadCurrent("hello"); v["API_KEY"] != "v" {
		t.Fatalf("the app's secrets went unasked: %v", v)
	}
	if !strings.Contains(out.String(), "webhook secret and deploy key") {
		t.Fatalf("output: %q", out.String())
	}
	if err := forgetApp(ctx, store, sec, stateDir, "hello", true, nil, &out); err != nil {
		t.Fatal(err)
	}
	if current, _ := sec.Current("hello"); current != 0 {
		t.Fatalf("the app's secrets survived --secrets: version %d", current)
	}
}

// The machine as it was once loom and loom-runner had been removed without
// their data, and some of their volumes cleared by hand: secrets, a volume
// or two, networks and a staging directory, and no revision of either.
func TestWhatARemovedAppLeftCanGoWithItsData(t *testing.T) {
	ctx := context.Background()
	fake := dockertest.New(t)
	owned := map[string]string{docker.LabelOwner: docker.OwnerValue}
	for _, v := range []string{"bedrock-loom-postgres", "bedrock-loom-files", "bedrock-loom.drill.files", "bedrock-loom-runner-state", "bedrock-loomy-files", "bedrock-edge-data", "bedrock-hello-postgres"} {
		fake.AddVolume(v, owned)
	}
	for _, n := range []string{"bedrock-loom", "bedrock.edge.loom", "bedrock-loom-runner", "bedrock-hello"} {
		fake.AddNetwork(n, owned)
	}
	fake.AddNetwork("bedrock-loom.drill", nil) // not bedrock's: no label
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedApp(t, store, "hello")
	sec := newSecrets(t)
	a, b := "a", "b"
	if _, err := sec.SetAll("loom", map[string]*string{"API_KEY": &a, "BEDROCK_POSTGRES_PASSWORD": &b}); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.Set("loom-runner", "TOKEN", "t"); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	for _, d := range []string{"apps/loom/postgres-init", "builds/loom", "apps/loom-runner"} {
		if err := os.MkdirAll(filepath.Join(stateDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r := Remove{Store: store, Secrets: sec, StateDir: stateDir}
	plan := func(in string) (*kernel.Plan, error) {
		return r.Plan(ctx, json.RawMessage(in))
	}

	if _, err := plan(`{"app":"loom"}`); err == nil || !strings.Contains(err.Error(), "sealed secrets (2 names)") || !strings.Contains(err.Error(), "helios remove loom --data") {
		t.Fatalf("without --data: %v", err)
	}
	if _, err := plan(`{"app":"loom","secrets":true}`); err == nil || !strings.Contains(err.Error(), "--data") {
		t.Fatalf("--secrets alone: %v", err)
	}
	if _, err := plan(`{"app":"gone","data":true}`); err == nil || !strings.Contains(err.Error(), "nothing of it is left") {
		t.Fatalf("an app that left nothing: %v", err)
	}
	for _, reserved := range []string{"edge", "bedrock", "../loom"} {
		if _, err := plan(`{"app":"` + reserved + `","data":true}`); err == nil || !strings.Contains(err.Error(), "isn't the name of an app") {
			t.Fatalf("%s: %v", reserved, err)
		}
	}
	// hello is still deployed, so its remove is the ordinary one.
	if p, err := plan(`{"app":"hello","data":true}`); err != nil || p.Steps[0].Name != "unroute" {
		t.Fatalf("a deployed app took the leftovers path: %v", err)
	}

	p, err := plan(`{"app":"loom","data":true}`)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "plan-remove-leftovers", strings.ReplaceAll(planText(p), stateDir, "<state>"))
	var out strings.Builder
	for _, st := range p.Steps {
		if err := st.Apply(ctx, &out); err != nil {
			t.Fatalf("%s: %v", st.Name, err)
		}
	}
	if got := strings.Join(fake.VolumeNames(), " "); got != "bedrock-edge-data bedrock-hello-postgres bedrock-loom-runner-state bedrock-loomy-files" {
		t.Fatalf("volumes left: %s", got)
	}
	if got := strings.Join(fake.NetworkNames(), " "); got != "bedrock-hello bedrock-loom-runner bedrock-loom.drill" {
		t.Fatalf("networks left: %s", got)
	}
	if v, _ := sec.Current("loom"); v != 0 {
		t.Fatalf("loom's secrets survived: version %d", v)
	}
	if v, _ := sec.Current("loom-runner"); v == 0 {
		t.Fatal("loom-runner's secrets went with loom's")
	}
	for _, d := range []string{"apps/loom", "builds/loom"} {
		if _, err := os.Stat(filepath.Join(stateDir, d)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived: %v", d, err)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, "apps/loom-runner")); err != nil {
		t.Fatalf("loom-runner's directory went: %v", err)
	}
	if _, err := plan(`{"app":"loom","data":true}`); err == nil || !strings.Contains(err.Error(), "nothing of it is left") {
		t.Fatalf("a second purge found something: %v", err)
	}
}

func TestRemovingDataIncludesVolumesFromRetiredAndFailedRevisions(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	for i, rev := range []state.Revision{
		{App: "site", ID: "retired-revision", Status: state.RevisionRetired, Manifest: json.RawMessage(`{"app":"site","data":{"volumes":{"old-files":{}}}}`)},
		{App: "site", ID: "failed-revision", Status: state.RevisionFailed, Manifest: json.RawMessage(`{"app":"site","data":{"volumes":{"failed-files":{}}}}`)},
		{App: "site", ID: "active-revision", Status: state.RevisionActive, Manifest: json.RawMessage(`{"app":"site","data":{"volumes":{"files":{}}}}`)},
	} {
		rev.CreatedAt = time.Now().Add(time.Duration(i) * time.Minute)
		if err := store.SaveRevision(ctx, rev); err != nil {
			t.Fatal(err)
		}
	}
	fake := dockertest.New(t)
	owned := map[string]string{docker.LabelOwner: docker.OwnerValue}
	for _, name := range []string{"bedrock-site-files", "bedrock-site-old-files", "bedrock-site-failed-files", "bedrock-other-files"} {
		fake.AddVolume(name, owned)
	}
	plan, err := (Remove{Store: store, StateDir: t.TempDir()}).Plan(ctx, json.RawMessage(`{"app":"site","data":true}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Name == "data" {
			if err := step.Apply(ctx, io.Discard); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := strings.Join(fake.VolumeNames(), " "); got != "bedrock-other-files" {
		t.Fatalf("data removal left historical volumes or touched another app: %s", got)
	}
}

func TestRemovingDataRefusesUnreadableHistoricalManifests(t *testing.T) {
	ctx := context.Background()
	store := releaseTestStore(t)
	seedApp(t, store, "site")
	if err := store.SaveRevision(ctx, state.Revision{App: "site", ID: "old-revision", Status: state.RevisionRetired, Manifest: json.RawMessage(`{"broken":`), CreatedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := (Remove{Store: store, StateDir: t.TempDir()}).Plan(ctx, json.RawMessage(`{"app":"site","data":true}`)); err == nil {
		t.Fatal("removal cannot identify historical data safely from a malformed manifest")
	}
}
