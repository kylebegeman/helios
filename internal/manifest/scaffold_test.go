package manifest

import (
	"strings"
	"testing"
)

// Every shape the command can be asked for has to produce a manifest that
// loads. Render checks this itself and refuses to return an invalid file,
// so this walks the whole matrix to prove no combination trips that check.
func TestEveryScaffoldParsesAndValidates(t *testing.T) {
	for _, kind := range []Kind{Web, Static, Worker, Cron} {
		for _, postgres := range []bool{false, true} {
			s := Scaffold{App: "acme", Kind: kind, Postgres: postgres}
			if kind == Web || kind == Static {
				s.Host = "acme.example.com"
			}
			out, err := s.Render()
			if err != nil {
				t.Fatalf("%s postgres=%v: %v", kind, postgres, err)
			}
			m, err := Parse(out)
			if err != nil {
				t.Fatalf("%s postgres=%v: %v", kind, postgres, err)
			}
			if m.App != "acme" {
				t.Fatalf("%s: app is %q", kind, m.App)
			}
			if got := m.HasData(); got != postgres {
				t.Fatalf("%s: HasData is %v, want %v", kind, got, postgres)
			}
			if len(m.Workloads) != 1 {
				t.Fatalf("%s: %d workloads, want the one", kind, len(m.Workloads))
			}
			for name, w := range m.Workloads {
				if w.Kind != kind {
					t.Fatalf("workload %s is %q, want %q", name, w.Kind, kind)
				}
			}
		}
	}
}

// A scaffolded app with a database gets DATABASE_URL without declaring
// anything, which is the reason the data block can be two lines long.
func TestScaffoldedDatabaseIsInjectedWithoutDeclaringIt(t *testing.T) {
	out, err := Scaffold{App: "acme", Kind: Worker, Postgres: true}.Render()
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !m.InjectsDatabaseURL() {
		t.Fatal("a scaffolded database must reach the workloads on its own")
	}
	if m.PostgresVersion() == "" {
		t.Fatal("no postgres version")
	}
}

// The commented-out blocks are the parts a person has to finish. They are
// comments precisely so that a half-finished manifest is never deployed, so
// they must not become live YAML by accident.
func TestTheUnfinishedPartsStayComments(t *testing.T) {
	out, err := Scaffold{App: "acme", Kind: Web, Host: "acme.example.com", Postgres: true}.Render()
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, live := m.Workloads["migrate"]; live {
		t.Fatal("the migrate example must stay commented out")
	}
	if m.Backup != nil && m.Backup.Verify != nil {
		t.Fatal("the verify example must stay commented out")
	}
	if !strings.Contains(string(out), "# migrate:") {
		t.Fatal("the migrate example should still be there to uncomment")
	}
}

func TestScaffoldRefusesWhatItCannotRender(t *testing.T) {
	for name, s := range map[string]Scaffold{
		"no name":              {Kind: Web, Host: "a.example.com"},
		"bad name":             {App: "Acme Corp", Kind: Web, Host: "a.example.com"},
		"reserved name":        {App: "edge", Kind: Web, Host: "a.example.com"},
		"no kind":              {App: "acme", Host: "a.example.com"},
		"unknown kind":         {App: "acme", Kind: "service", Host: "a.example.com"},
		"web without host":     {App: "acme", Kind: Web},
		"static without host":  {App: "acme", Kind: Static},
		"host that is not":     {App: "acme", Kind: Web, Host: "not a host"},
		"worker with host":     {App: "acme", Kind: Worker, Host: "a.example.com"},
		"port on a worker":     {App: "acme", Kind: Worker, Port: 8000},
		"port out of range":    {App: "acme", Kind: Web, Host: "a.example.com", Port: 70000},
		"schedule on web":      {App: "acme", Kind: Web, Host: "a.example.com", Schedule: "0 3 * * *"},
		"schedule that is not": {App: "acme", Kind: Cron, Schedule: "nightly"},
	} {
		if _, err := s.Render(); err == nil {
			t.Fatalf("%s: must be refused", name)
		}
	}
}

// The port and schedule a person passes have to reach the file; a scaffold
// that quietly ignores a flag is worse than one that refuses it.
func TestScaffoldUsesWhatItIsGiven(t *testing.T) {
	out, err := Scaffold{App: "acme", Kind: Web, Host: "acme.example.com", Port: 3000}.Render()
	if err != nil {
		t.Fatal(err)
	}
	m, _ := Parse(out)
	if got := m.Workloads["web"].Port; got != 3000 {
		t.Fatalf("port is %d, want 3000", got)
	}
	if got := m.Workloads["web"].Routes[0].Host; got != "acme.example.com" {
		t.Fatalf("host is %q", got)
	}

	out, err = Scaffold{App: "acme", Kind: Cron, Schedule: "*/15 * * * *"}.Render()
	if err != nil {
		t.Fatal(err)
	}
	m, _ = Parse(out)
	if got := m.Workloads["job"].Schedule; got != "*/15 * * * *" {
		t.Fatalf("schedule is %q", got)
	}

	out, _ = Scaffold{App: "acme", Kind: Web, Host: "acme.example.com"}.Render()
	m, _ = Parse(out)
	if got := m.Workloads["web"].Port; got != DefaultPort {
		t.Fatalf("default port is %d, want %d", got, DefaultPort)
	}
}

func TestNextNamesWhatIsStillMissing(t *testing.T) {
	next := Scaffold{App: "acme", Kind: Web, Host: "acme.example.com", Postgres: true}.Next()
	joined := strings.Join(next, "\n")
	for _, want := range []string{"Dockerfile", "/healthz", "DATABASE_URL", "acme.example.com"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("next steps never mention %q: %v", want, next)
		}
	}
	static := Scaffold{App: "acme", Kind: Static, Host: "acme.example.com"}.Next()
	if !strings.Contains(strings.Join(static, "\n"), "./public") {
		t.Fatalf("a static app must be told where its files go: %v", static)
	}
}

func TestStaticScaffoldPreservesTheDirectoryAsOneYAMLString(t *testing.T) {
	for _, dir := range []string{"public # site", "public: files", "[public]", "null", "public\n    env: {UNEXPECTED: injected}"} {
		t.Run(dir, func(t *testing.T) {
			out, err := (Scaffold{App: "site", Kind: Static, Host: "site.example.com", Dir: dir}).Render()
			if err != nil {
				t.Fatal(err)
			}
			m, err := Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			w := m.Workloads["pages"]
			if w.Dir != dir || len(w.Env) != 0 {
				t.Fatalf("directory changed or became YAML fields: %+v", w)
			}
		})
	}
}
