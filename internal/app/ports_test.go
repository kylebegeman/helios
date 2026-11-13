package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

const headscaleYAML = `app: headscale
workloads:
  server:
    kind: web
    image: headscale/headscale:0.26
    port: 8080
    singleton: true
    dns_servers: [192.0.2.53, "2001:db8::53"]
    routes: [{host: hs.example.com}]
    ports:
      - port: 3478
        protocol: udp
      - port: 9090
        host_port: 19090
        address: "::1"
    mounts: [{volume: state, path: /var/lib/headscale}]
data:
  volumes:
    state: {}
`

func headscale(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(headscaleYAML))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAWorkloadsContainerPublishesItsPorts(t *testing.T) {
	m := headscale(t)
	spec, err := containerSpec(m, "server", m.Workloads["server"], "r1", "img", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"3478:3478/udp", "[::1]:19090:9090/tcp"}
	if !slices.Equal(spec.Publish, want) {
		t.Fatalf("publish %v, want %v", spec.Publish, want)
	}
	if !slices.Equal(spec.DNSServers, m.Workloads["server"].DNSServers) {
		t.Fatalf("DNS servers %v", spec.DNSServers)
	}
}

// A job or a drill runs beside the workload's own container, which already
// holds its ports; one that asked for them too would fail to start.
func TestJobsAndDrillsPublishNothing(t *testing.T) {
	m := headscale(t)
	job, err := jobSpec(m, "r1", "server", m.Workloads["server"], "img", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Publish) > 0 || job.Restart || len(job.Aliases) > 0 {
		t.Fatalf("a job is published %v, restarts %v, answers to %v", job.Publish, job.Restart, job.Aliases)
	}
	if !slices.Equal(job.Networks, []string{docker.AppNetwork("headscale")}) {
		t.Fatalf("a job's networks: %v", job.Networks)
	}
	if !slices.Equal(job.DNSServers, m.Workloads["server"].DNSServers) {
		t.Fatalf("a job's DNS servers: %v", job.DNSServers)
	}
	names := newDrillNames(t.TempDir(), m)
	drill, err := drillSpec(m, "r1", "server", "img", nil, names)
	if err != nil {
		t.Fatal(err)
	}
	if len(drill.Publish) > 0 || drill.Restart {
		t.Fatalf("a drill is published %v, restarts %v", drill.Publish, drill.Restart)
	}
	if drill.Name != names.containers["server"] || !slices.Equal(drill.Networks, []string{names.network}) {
		t.Fatalf("a drill's container %s on %v", drill.Name, drill.Networks)
	}
	if !slices.Equal(drill.DNSServers, m.Workloads["server"].DNSServers) {
		t.Fatalf("a drill's DNS servers: %v", drill.DNSServers)
	}
	if len(drill.Mounts) != 1 || !strings.HasPrefix(drill.Mounts[0], names.volumes["state"]+":") {
		t.Fatalf("a drill mounts %v, want its own copy of state", drill.Mounts)
	}
}

func TestAPreviewPublishesNothingOnTheMachine(t *testing.T) {
	preview, err := PreviewOf(headscale(t), "new-derp", "preview.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ports := preview.PublishedPorts(); len(ports) > 0 {
		t.Fatalf("a preview publishes %v, which its parent holds", ports)
	}
}

func saveActive(t *testing.T, store *state.Store, m *manifest.Manifest) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRevision(context.Background(), state.Revision{App: m.App, ID: "20260920-120000", Status: state.RevisionActive, Manifest: raw, Containers: map[string]string{}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestADeployIsRefusedAPortAnotherAppHolds(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	d := Deploy{Store: store, StateDir: t.TempDir(), Addresses: func(context.Context) []string { return nil }}
	m := headscale(t)

	// Its own running revision is not in the way: the singleton stops first.
	saveActive(t, store, m)
	plan, err := d.rollout(ctx, m, "20260921-120000", &buildFrom{source: t.TempDir()})
	if err != nil {
		t.Fatalf("redeploying the app that holds the port: %v", err)
	}
	var start string
	for _, s := range plan.Steps {
		if s.Name == "start" {
			start = s.Change
		}
	}
	if !strings.Contains(start, "publishing 3478/udp for server, [::1]:19090/tcp for server on the machine") {
		t.Fatalf("the plan doesn't say what it publishes: %q", start)
	}

	// Another app on the same port and protocol is.
	other := headscale(t)
	other.App = "stun"
	otherWorkload := other.Workloads["server"]
	otherWorkload.Routes[0].Host = "stun.example.com"
	other.Workloads["server"] = otherWorkload
	_, err = d.rollout(ctx, other, "20260921-120000", &buildFrom{source: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "3478/udp (for server) is already published by headscale's server") {
		t.Fatalf("a clash on 3478/udp: %v", err)
	}

	// The same number over the other protocol, or another loopback port, is not.
	w := other.Workloads["server"]
	w.Ports = []manifest.PublishedPort{{Port: 3478}, {Port: 9090, HostPort: 19090, Address: "127.0.0.1"}}
	other.Workloads["server"] = w
	if _, err := d.rollout(ctx, other, "20260921-120000", &buildFrom{source: t.TempDir()}); err != nil {
		t.Fatalf("3478/tcp and 127.0.0.1:19090 beside 3478/udp and [::1]:19090: %v", err)
	}
}

// The manifest can't import the docker package, so it names the registry's
// port itself; this keeps the two from drifting apart.
func TestTheRegistrysPortCannotBePublished(t *testing.T) {
	_, port, _ := strings.Cut(docker.Registry, ":")
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	yaml := strings.Replace(headscaleYAML, "host_port: 19090", "host_port: "+port, 1)
	if _, err := manifest.Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), strconv.Itoa(n)+" on the machine belongs to") {
		t.Fatalf("publishing the registry's port %d: %v", n, err)
	}
}
