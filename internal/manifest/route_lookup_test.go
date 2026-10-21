package manifest

import "testing"

func TestRouteForNormalizesPathsAndKeepsPrefixBoundaries(t *testing.T) {
	m := &Manifest{Workloads: map[string]Workload{
		"root": {Image: "root-image", Routes: []Route{{Host: "app.example.com", Port: 8000}}},
		"api": {Image: "api-image", Routes: []Route{
			{Host: "app.example.com", Path: "/api", Port: 8001},
			{Host: "app.example.com", Path: "/api/admin/", Port: 8002},
		}},
		"isolated": {Image: "isolated-image", Routes: []Route{{Host: "isolated.example.com", Path: "/private/", Port: 8003}}},
	}}
	for _, tc := range []struct {
		host, path, name string
		port             int
	}{
		{"app.example.com", "", "root", 8000},
		{"app.example.com", "/", "root", 8000},
		{"app.example.com", "/about", "root", 8000},
		{"app.example.com", "/api", "api", 8001},
		{"app.example.com", "/api/", "api", 8001},
		{"app.example.com", "/api/users", "api", 8001},
		{"app.example.com", "/api/admin", "api", 8002},
		{"app.example.com", "/api/admin/", "api", 8002},
		{"app.example.com", "/api/admin/users", "api", 8002},
		{"app.example.com", "/api/administrator", "api", 8001},
		{"app.example.com", "/apiary", "root", 8000},
		{"isolated.example.com", "/private", "isolated", 8003},
		{"isolated.example.com", "/private/users", "isolated", 8003},
		{"isolated.example.com", "/private-other", "", 0},
		{"isolated.example.com", "", "", 0},
		{"missing.example.com", "/api", "", 0},
		{"APP.EXAMPLE.COM", "/api", "", 0},
	} {
		t.Run(tc.host+tc.path, func(t *testing.T) {
			name, workload, route, found := m.RouteFor(tc.host, tc.path)
			if found != (tc.name != "") || name != tc.name || route.Port != tc.port {
				t.Fatalf("got %q port %d found %v, want %q port %d", name, route.Port, found, tc.name, tc.port)
			}
			if found && workload.Image != m.Workloads[tc.name].Image {
				t.Fatalf("returned workload %q, want %q", workload.Image, m.Workloads[tc.name].Image)
			}
			if !found && (workload.Image != "" || route != (Route{})) {
				t.Fatalf("miss returned a workload or route: %+v %+v", workload, route)
			}
		})
	}
}

func TestRouteForBreaksTiesByWorkloadNameThenRouteOrder(t *testing.T) {
	// Direct construction deliberately bypasses validation: callers can edit
	// the public workload map, and lookup must stay deterministic even when
	// duplicate or differently spelled routes normalize to the same prefix.
	for _, path := range []string{"", "/api"} {
		normalized := path + "/"
		m := &Manifest{Workloads: map[string]Workload{
			"z-last": {Routes: []Route{{Host: "app.example.com", Path: path, Port: 9000}}},
			"a-first": {Routes: []Route{
				{Host: "other.example.com", Path: path, Port: 9001},
				{Host: "app.example.com", Path: normalized, Port: 9002},
				{Host: "app.example.com", Path: path, Port: 9003},
			}},
			"m-middle": {Routes: []Route{{Host: "app.example.com", Path: normalized, Port: 9004}}},
		}}
		t.Run(normalized, func(t *testing.T) {
			// Repeating the lookup catches dependence on Go's randomized map
			// iteration while retaining the first tied route within a workload.
			for range 64 {
				name, _, route, found := m.RouteFor("app.example.com", normalized+"users")
				if !found || name != "a-first" || route.Port != 9002 {
					t.Fatalf("got %q port %d found %v, want a-first port 9002", name, route.Port, found)
				}
			}
		})
	}
}

func TestRouteForReflectsWorkloadAndRouteMutations(t *testing.T) {
	m := &Manifest{Workloads: map[string]Workload{
		"web": {Image: "original", Routes: []Route{{Host: "app.example.com", Path: "/api"}}},
	}}
	assertRoute := func(path, wantName, wantImage string) {
		t.Helper()
		name, workload, _, found := m.RouteFor("app.example.com", path)
		if found != (wantName != "") || name != wantName || workload.Image != wantImage {
			t.Fatalf("%s: got %q image %q found %v, want %q image %q", path, name, workload.Image, found, wantName, wantImage)
		}
	}
	assertRoute("/api/users", "web", "original")
	m.Workloads["api"] = Workload{Image: "added", Routes: []Route{{Host: "app.example.com", Path: "/api"}}}
	assertRoute("/api/users", "api", "added")
	delete(m.Workloads, "api")
	assertRoute("/api/users", "web", "original")
	m.Workloads["web"] = Workload{Image: "replacement", Routes: []Route{{Host: "app.example.com", Path: "/changed"}}}
	assertRoute("/api/users", "", "")
	assertRoute("/changed/users", "web", "replacement")
	m.Workloads["web"].Routes[0].Path = "/latest"
	assertRoute("/changed/users", "", "")
	assertRoute("/latest/users", "web", "replacement")
	delete(m.Workloads, "web")
	assertRoute("/latest/users", "", "")
}

func TestValidationRefusesRoutesWithTheSameNormalizedPrefix(t *testing.T) {
	for _, sameWorkload := range []bool{false, true} {
		for _, paths := range [][2]string{{"/api", "/api/"}, {"", "/"}} {
			m := &Manifest{App: "site", Workloads: map[string]Workload{
				"first": {Kind: Web, Image: "image", Port: 8000, Routes: []Route{{Host: "site.example.com", Path: paths[0]}}},
			}}
			second := Route{Host: "site.example.com", Path: paths[1], Auth: AuthLoom}
			if sameWorkload {
				w := m.Workloads["first"]
				w.Routes = append(w.Routes, second)
				m.Workloads["first"] = w
			} else {
				m.Workloads["second"] = Workload{Kind: Web, Image: "image", Port: 8001, Routes: []Route{second}}
			}
			if err := m.Validate(); err == nil {
				t.Errorf("accepted duplicate prefixes %q in one workload: %v", paths, sameWorkload)
			}
		}
	}
}
