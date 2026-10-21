package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOfflineCheckNamesMissingInputsWithoutCreatingThem(t *testing.T) {
	dir := checkFixture(t, "app: api\nworkloads:\n  web:\n    kind: web\n    build: {}\n    port: 8080\n    routes: [{host: api.example.com}]\n")
	got := CheckSource(dir, FileName)
	if got.Valid || got.App != "api" || len(got.Diagnostics) != 1 {
		t.Fatalf("%+v", got)
	}
	d := got.Diagnostics[0]
	if d.Code != "source.missing" || d.Path != "workloads.web.build.dockerfile" || d.Line != 5 || !strings.Contains(d.Message, "Dockerfile") {
		t.Fatalf("%+v", d)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != FileName {
		t.Fatalf("the offline check changed the source: %v %v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if report := CheckSource(dir, FileName); !report.Valid || len(report.Diagnostics) != 0 {
		t.Fatalf("%+v", report)
	}
}

func TestOfflineCheckUsesTheDeployValidatorAndLocatesUnknownFields(t *testing.T) {
	cases := []struct {
		body, path string
		line       int
	}{
		{"app: api\nworkloads:\n  web:\n    kind: web\n    image: alpine\n    port: 0\n    routes: [{host: api.example.com}]\n", "workloads.web", 3},
		{"app: api\nworkloads:\n  worker: {kind: worker, image: alpine, colour: blue}\n", "workloads.worker.colour", 3},
		{"app: api\nworkloads:\n  worker:\n    kind: worker\n    image: alpine\n    resources: {cpus: -1}\n", "workloads.worker.resources.cpus", 6},
	}
	for _, tt := range cases {
		t.Run(tt.path, func(t *testing.T) {
			if _, err := Parse([]byte(tt.body)); err == nil {
				t.Fatal("the fixture must fail the authoritative validator")
			}
			got := CheckSource(checkFixture(t, tt.body), FileName)
			if got.Valid || len(got.Diagnostics) == 0 {
				t.Fatalf("%+v", got)
			}
			if d := got.Diagnostics[0]; d.Path != tt.path || d.Line != tt.line || d.Column == 0 {
				t.Fatalf("%+v", d)
			}
		})
	}
}

func TestOfflineCheckReadsAnAlternateManifestAndRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	name := "helios.worker.yaml"
	body := []byte("app: mailer\nworkloads: {worker: {kind: worker, image: alpine}}\n")
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if report := CheckSource(dir, name); !report.Valid || report.Manifest != name {
		t.Fatalf("%+v", report)
	}
	if err := os.Symlink(name, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if report := CheckSource(dir, FileName); report.Valid || report.Diagnostics[0].Code != "manifest.file" {
		t.Fatalf("%+v", report)
	}
	if report := CheckSource(dir, "../helios.worker.yaml"); report.Valid || report.Diagnostics[0].Code != "manifest.filename" {
		t.Fatalf("%+v", report)
	}
}

func TestOfflineCheckRejectsSourcePathsThatLeadOutsideTheRepository(t *testing.T) {
	dir := checkFixture(t, "app: site\nworkloads:\n  site:\n    kind: static\n    dir: public\n    routes: [{host: site.example.com}]\n")
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "public")); err != nil {
		t.Fatal(err)
	}
	got := CheckSource(dir, FileName)
	if got.Valid || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "source.outside" || got.Diagnostics[0].Line != 5 {
		t.Fatalf("%+v", got)
	}
}

func TestOfflineCheckChecksBuildInputsRelativeToTheirContext(t *testing.T) {
	dir := checkFixture(t, "app: api\nworkloads:\n  worker:\n    kind: worker\n    build: {context: server, dockerfile: deploy/Dockerfile}\n")
	if err := os.MkdirAll(filepath.Join(dir, "server", "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server", "deploy", "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := CheckSource(dir, FileName); !got.Valid {
		t.Fatalf("%+v", got)
	}
}

func TestOfflineCheckFindsEmptyPostgresInitDirectories(t *testing.T) {
	dir := checkFixture(t, "app: notes\nworkloads: {worker: {kind: worker, image: alpine}}\ndata:\n  postgres: {init: init}\n")
	if err := os.Mkdir(filepath.Join(dir, "init"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := CheckSource(dir, FileName)
	if got.Valid || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "source.init_empty" {
		t.Fatalf("%+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "init", "roles.sql.gz"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := CheckSource(dir, FileName); !got.Valid {
		t.Fatalf("%+v", got)
	}
}

func TestOfflineCheckRejectsAdditionalYAMLDocuments(t *testing.T) {
	body := "app: api\nworkloads: {worker: {kind: worker, image: alpine}}\n---\nworkloads: {bad: {kind: worker}}\n"
	got := CheckSource(checkFixture(t, body), FileName)
	if got.Valid || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "manifest.documents" {
		t.Fatalf("%+v", got)
	}
}

func TestOfflineCheckKeepsDockerfileLinksInsideTheirBuildContext(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		valid        bool
	}{
		{"sibling outside context", "../Dockerfile", false},
		{"relative inside context", "deploy/Dockerfile", true},
		{"absolute inside context", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := checkFixture(t, "app: api\nworkloads:\n  worker:\n    kind: worker\n    build: {context: server}\n")
			inside := filepath.Join(dir, "server", "deploy", "Dockerfile")
			if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{inside, filepath.Join(dir, "Dockerfile")} {
				if err := os.WriteFile(path, []byte("FROM scratch\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			target := tc.target
			if target == "" {
				target = inside
			}
			if err := os.Symlink(target, filepath.Join(dir, "server", "Dockerfile")); err != nil {
				t.Fatal(err)
			}
			got := CheckSource(dir, FileName)
			if got.Valid != tc.valid {
				t.Fatalf("%+v", got)
			}
			if !tc.valid && (len(got.Diagnostics) != 1 || got.Diagnostics[0].Path != "workloads.worker.build.dockerfile" || got.Diagnostics[0].Code != "source.outside") {
				t.Fatalf("%+v", got)
			}
		})
	}
}
