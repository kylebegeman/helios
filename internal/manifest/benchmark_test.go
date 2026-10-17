package manifest

import (
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

// These benchmarks cover the CPU and allocation cost of accepting an app's
// configuration, independently of disk, Docker, DNS, and network latency. One
// workload is a small web app; larger fixtures mix web, worker, and cron roles.
func BenchmarkParse(b *testing.B) {
	for _, workloads := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("Workloads%d", workloads), func(b *testing.B) {
			_, data := benchmarkManifest(b, workloads)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				if _, err := Parse(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkValidate(b *testing.B) {
	for _, workloads := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("Workloads%d", workloads), func(b *testing.B) {
			m, _ := benchmarkManifest(b, workloads)
			b.ReportAllocs()
			for b.Loop() {
				if err := m.Validate(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRouteFor(b *testing.B) {
	for _, workloads := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("Workloads%d", workloads), func(b *testing.B) {
			m, _ := benchmarkManifest(b, workloads)
			// Every third workload is web. Match the last one, including its
			// longer admin prefix, so the fixture exercises prefix selection.
			lastWeb := (workloads - 1) / 3 * 3
			for _, tc := range []struct {
				name, host, path, workload, routePath string
				found                                 bool
			}{
				{"Hit", "bench.example.com", fmt.Sprintf("/service-%03d/admin/users", lastWeb), fmt.Sprintf("service-%03d", lastWeb), fmt.Sprintf("/service-%03d/admin", lastWeb), true},
				{"MissHost", "unrouted.example.com", "/", "", "", false},
				{"MissPath", "bench.example.com", "/unrouted", "", "", false},
			} {
				b.Run(tc.name, func(b *testing.B) {
					name, _, route, found := m.RouteFor(tc.host, tc.path)
					if name != tc.workload || route.Path != tc.routePath || found != tc.found {
						b.Fatalf("fixture route: got %q %q %v, want %q %q %v", name, route.Path, found, tc.workload, tc.routePath, tc.found)
					}
					b.ReportAllocs()
					for b.Loop() {
						if _, _, _, found := m.RouteFor(tc.host, tc.path); found != tc.found {
							b.Fatal("route result changed")
						}
					}
				})
			}
		})
	}
}

// benchmarkManifest returns an already validated fixture and its YAML encoding.
// Construction, YAML marshaling, and the initial Parse are outside b.Loop.
func benchmarkManifest(b *testing.B, workloads int) (*Manifest, []byte) {
	b.Helper()
	m := &Manifest{
		App:         "benchmark-app",
		Description: "Synthetic performance fixture",
		Owner:       "benchmark",
		Repo:        "https://example.com/benchmark/app.git",
		Workloads:   make(map[string]Workload, workloads),
		Data: &Data{
			Postgres: &Postgres{Version: "17", User: "benchmark", Database: "benchmark", Init: "deploy/postgres/init"},
			Volumes:  map[string]Volume{"uploads": {Description: "User uploads"}},
		},
		Backup: &Backup{
			Schedule: "0 3 * * *",
			Drill:    "0 4 * * 0",
			Keep:     &Keep{Daily: 7, Weekly: 4, Monthly: 6},
			Verify:   &Verify{SQL: "SELECT count(*) FROM records", AtLeast: 1},
		},
		Secrets: &Secrets{
			Generate: map[string]string{"SESSION_SECRET": "hex:32", "API_TOKEN": "base64url:32"},
		},
	}
	for i := range workloads {
		name := fmt.Sprintf("service-%03d", i)
		w := Workload{
			Image: "example.com/benchmark/app:1",
			Env: map[string]string{
				"APP_ENV": "production", "LOG_LEVEL": "info", "TZ": "UTC",
				"QUEUE_NAME": name, "OBJECTS_BUCKET": "uploads", "PUBLIC_URL": "https://bench.example.com",
			},
			Secrets:   []string{"SESSION_SECRET", "API_TOKEN"},
			Resources: Resources{Memory: "512m", CPUs: 0.5, Pids: 256},
			Mounts:    []Mount{{Volume: "uploads", Path: "/app/uploads"}},
			User:      "1000:1000",
		}
		switch i % 3 {
		case 0:
			w.Kind, w.Port = Web, 8080
			w.Health = &Health{Path: "/health", Timeout: "30s"}
			w.Routes = []Route{
				{Host: "bench.example.com", Path: "/" + name, DNS: DNSDirect},
				{Host: "bench.example.com", Path: "/" + name + "/admin", DNS: DNSDirect},
				{Host: name + ".example.com", DNS: DNSDirect},
			}
			m.Checks = append(m.Checks, Check{URL: "https://bench.example.com/" + name + "/health", Status: 200, Contains: "ok", Within: "2s"})
		case 1:
			w.Kind = Worker
			w.Command = []string{"app", "worker", "--queue", name}
			w.Health = &Health{Command: []string{"app", "worker-health"}, Timeout: "30s"}
			w.Grace = "30s"
		case 2:
			w.Kind = Cron
			w.Command = []string{"app", "cleanup", "--batch", "1000"}
			w.Schedule, w.Timeout = "15 * * * *", "10m"
		}
		m.Workloads[name] = w
	}
	if err := m.Validate(); err != nil {
		b.Fatalf("invalid benchmark fixture: %v", err)
	}
	data, err := yaml.Marshal(m)
	if err != nil {
		b.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		b.Fatalf("benchmark fixture does not parse: %v", err)
	}
	if len(parsed.Workloads) != workloads {
		b.Fatalf("parsed %d workloads, want %d", len(parsed.Workloads), workloads)
	}
	return parsed, data
}
