package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// originPullSite is an app with a host that requires origin pull, one
// where it is optional and one without it. Its first host, the one its
// webhook arrives on, is the required one.
func originPullSite(app string) *manifest.Manifest {
	return &manifest.Manifest{App: app, Workloads: map[string]manifest.Workload{"web": {
		Kind: manifest.Web, Image: "example/site:1", Port: 8080,
		Routes: []manifest.Route{
			{Host: "a-required.example.com", DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullRequired},
			{Host: "a-required.example.com", Path: "/api", DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullRequired},
			{Host: "b-optional.example.com", DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullOptional},
			{Host: "c-plain.example.com", DNS: manifest.DNSProxied},
		},
	}}}
}

// saveRunning makes m an active revision with containers, and a webhook
// when hooked, the way a deploy leaves it.
func saveRunning(t *testing.T, store *state.Store, m *manifest.Manifest, hooked bool) {
	t.Helper()
	ctx := context.Background()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	containers := map[string]string{}
	for _, name := range m.WorkloadNames() {
		containers[name] = "bedrock-" + m.App + "-" + name + "-r1"
	}
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: "r1", Status: state.RevisionActive, Manifest: raw, Images: map[string]string{}, Containers: containers, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if hooked {
		if err := store.SaveGitHook(ctx, state.GitHook{App: m.App, Repo: "git@example.com:site.git", Branch: "main", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
}

// mintCA is a CA for host, as helios edge origin-pull mint keeps it.
func mintCA(t *testing.T, host string, now time.Time) edge.OriginPullCA {
	t.Helper()
	minted, err := edge.MintOriginPull(host, now)
	if err != nil {
		t.Fatal(err)
	}
	return minted.CA
}

func caDER(t *testing.T, ca edge.OriginPullCA) string {
	t.Helper()
	cert, err := edge.ParseOriginPullCA(ca.PEM)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

func writeManifestFile(t *testing.T, dir string, m *manifest.Manifest) {
	t.Helper()
	data, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// quietEdge keeps what edgeConfig says about the trust for the test.
func quietEdge(t *testing.T) *bytes.Buffer {
	t.Helper()
	var notes bytes.Buffer
	saved := edgeNotes
	edgeNotes = &notes
	t.Cleanup(func() { edgeNotes = saved })
	return &notes
}

// edgeServer is what these tests read of the edge's configuration.
type edgeServer struct {
	Routes []struct {
		Match []struct {
			Host     []string `json:"host"`
			Protocol string   `json:"protocol"`
		} `json:"match"`
	} `json:"routes"`
	StrictSNIHost *bool `json:"strict_sni_host"`
	Policies      []struct {
		ClientAuthentication *struct {
			CA struct {
				Provider       string   `json:"provider"`
				TrustedCACerts []string `json:"trusted_ca_certs"`
			} `json:"ca"`
			Mode string `json:"mode"`
		} `json:"client_authentication"`
		Drop  bool `json:"drop"`
		Match *struct {
			SNI []string `json:"sni"`
		} `json:"match"`
	} `json:"tls_connection_policies"`
}

func readEdge(t *testing.T, cfg []byte) edgeServer {
	t.Helper()
	var c struct {
		Apps struct {
			HTTP struct {
				Servers struct {
					Bedrock edgeServer `json:"bedrock"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		t.Fatal(err)
	}
	return c.Apps.HTTP.Servers.Bedrock
}

// protocolOf is what the edge's outer route for host asks of a request's
// protocol, and whether it has one.
func (s edgeServer) protocolOf(host string) (string, bool) {
	for _, r := range s.Routes {
		for _, m := range r.Match {
			if slices.Contains(m.Host, host) {
				return m.Protocol, true
			}
		}
	}
	return "", false
}

func TestEveryRouteOfAnOriginPullHostTakesItsStrictestModeAndItsCAs(t *testing.T) {
	ctx := context.Background()
	quietEdge(t)
	now := time.Now()
	store := goldenStore(t)
	sec := newSecrets(t)
	saveRunning(t, store, originPullSite("site"), true)
	required, optional := mintCA(t, "a-required.example.com", now), mintCA(t, "b-optional.example.com", now)
	trust := edge.OriginPullTrust{}
	trust.Trust("a-required.example.com", required)
	trust.Trust("b-optional.example.com", optional)
	if err := saveOriginPullTrust(sec, trust); err != nil {
		t.Fatal(err)
	}
	routes, err := edgeRoutes(ctx, store, sec, now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		mode string
		cas  []string
	}{
		"a-required.example.com": {edge.OriginPullRequired, []string{caDER(t, required)}},
		"b-optional.example.com": {edge.OriginPullOptional, []string{caDER(t, optional)}},
		"c-plain.example.com":    {"", nil},
	}
	hook := false
	for _, r := range routes {
		w := want[r.Host]
		if r.OriginPull != w.mode || !slices.Equal(r.ClientCAs, w.cas) {
			t.Errorf("%s%s: origin pull %q with %d CAs, want %q with %d", r.Host, r.Path, r.OriginPull, len(r.ClientCAs), w.mode, len(w.cas))
		}
		if r.Path == HookRoute {
			// The webhook route has no manifest route of its own; served
			// in plain, it would let anyone past the host's origin pull.
			hook = r.Host == "a-required.example.com"
		}
	}
	if !hook {
		t.Fatalf("the webhook route isn't on the required host: %+v", routes)
	}

	cfg, err := EdgeConfig(ctx, store, sec)
	if err != nil {
		t.Fatal(err)
	}
	s := readEdge(t, cfg)
	if s.StrictSNIHost == nil || !*s.StrictSNIHost {
		t.Fatalf("an origin-pull host without strict SNI can be reached through another host's name:\n%s", cfg)
	}
	modes := map[string]string{}
	for i, p := range s.Policies {
		if p.Match == nil {
			if i != len(s.Policies)-1 || p.ClientAuthentication != nil || p.Drop {
				t.Fatalf("the catch-all policy isn't the last, or checks something:\n%s", cfg)
			}
			continue
		}
		if p.ClientAuthentication == nil || p.ClientAuthentication.CA.Provider != "inline" || len(p.ClientAuthentication.CA.TrustedCACerts) != 1 {
			t.Fatalf("%v is checked against no CA of its own:\n%s", p.Match.SNI, cfg)
		}
		modes[strings.Join(p.Match.SNI, ",")] = p.ClientAuthentication.Mode
	}
	if len(s.Policies) == 0 || s.Policies[len(s.Policies)-1].Match != nil {
		t.Fatalf("every other host needs the catch-all policy last:\n%s", cfg)
	}
	if !maps.Equal(modes, map[string]string{"a-required.example.com": "require_and_verify", "b-optional.example.com": "verify_if_given"}) {
		t.Fatalf("client checks by host: %v", modes)
	}
	for host, want := range map[string]string{"a-required.example.com": "https", "b-optional.example.com": "https", "c-plain.example.com": ""} {
		if got, ok := s.protocolOf(host); !ok || got != want {
			t.Errorf("%s matches protocol %q, want %q", host, got, want)
		}
	}
}

// A machine where no app sets origin pull never reads the trust, so even
// one that doesn't load changes nothing and says nothing.
func TestAnEdgeWithoutOriginPullNeverReadsTheTrust(t *testing.T) {
	ctx := context.Background()
	notes := quietEdge(t)
	store := goldenStore(t)
	sec := newSecrets(t)
	plain := &manifest.Manifest{App: "plain", Workloads: map[string]manifest.Workload{"web": {
		Kind: manifest.Web, Image: "example/plain:1", Port: 8080,
		Routes: []manifest.Route{{Host: "plain.example.com", DNS: manifest.DNSDirect}},
	}}}
	saveRunning(t, store, plain, true)
	before, err := EdgeConfig(ctx, store, sec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sec.Set(integration.App, integration.OriginPullName, "{"); err != nil {
		t.Fatal(err)
	}
	after, err := EdgeConfig(ctx, store, sec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || notes.Len() != 0 {
		t.Fatalf("an unused trust changed the edge or said %q", notes)
	}
	s := readEdge(t, after)
	if s.StrictSNIHost != nil || len(s.Policies) != 0 {
		t.Fatalf("a host without origin pull got TLS policies:\n%s", after)
	}
	if got, _ := s.protocolOf("plain.example.com"); got != "" {
		t.Fatalf("a host without origin pull redirects plain HTTP: %q", got)
	}
}

// The trust failing to load takes no CA from any host, so the required
// one refuses every connection, but every app keeps its routes, and the
// reason is told rather than swallowed.
func TestTrustThatDoesNotLoadClosesOnlyTheHostsThatRequireIt(t *testing.T) {
	ctx := context.Background()
	notes := quietEdge(t)
	store := goldenStore(t)
	sec := newSecrets(t)
	saveRunning(t, store, originPullSite("site"), false)
	other := &manifest.Manifest{App: "other", Workloads: map[string]manifest.Workload{"web": {
		Kind: manifest.Web, Image: "example/other:1", Port: 8080,
		Routes: []manifest.Route{{Host: "other.example.com", DNS: manifest.DNSDirect}},
	}}}
	saveRunning(t, store, other, false)
	if _, err := sec.Set(integration.App, integration.OriginPullName, "{not json"); err != nil {
		t.Fatal(err)
	}
	cfg, err := EdgeConfig(ctx, store, sec)
	if err != nil {
		t.Fatalf("one unreadable value took every app's edge down: %v", err)
	}
	if !strings.Contains(notes.String(), "origin-pull trust doesn't parse") || !strings.Contains(notes.String(), "refuses every connection") {
		t.Fatalf("the edge didn't say why a host is refused: %q", notes)
	}
	s := readEdge(t, cfg)
	var dropped []string
	for _, p := range s.Policies {
		if p.ClientAuthentication != nil {
			t.Fatalf("a client is checked with no CA loaded:\n%s", cfg)
		}
		if p.Drop && p.Match != nil {
			dropped = append(dropped, p.Match.SNI...)
		}
	}
	if !slices.Equal(dropped, []string{"a-required.example.com"}) {
		t.Fatalf("refused %v, want only the required host", dropped)
	}
	for _, host := range []string{"a-required.example.com", "b-optional.example.com", "c-plain.example.com", "other.example.com"} {
		if _, ok := s.protocolOf(host); !ok {
			t.Errorf("%s lost its route", host)
		}
	}
}

// A mode a newer helios wrote counts as required here: closed, not open.
func TestAnOriginPullModeThisHeliosDoesNotKnowCountsAsRequired(t *testing.T) {
	ctx := context.Background()
	quietEdge(t)
	store := goldenStore(t)
	sec := newSecrets(t)
	m := originPullSite("site")
	w := m.Workloads["web"]
	w.Routes = []manifest.Route{{Host: "new.example.com", DNS: manifest.DNSProxied, OriginPull: "pinned"}, {Host: "new.example.com", Path: "/b"}}
	m.Workloads["web"] = w
	saveRunning(t, store, m, false)
	routes, err := edgeRoutes(ctx, store, sec, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.OriginPull != edge.OriginPullRequired {
			t.Fatalf("%s%s takes origin pull %q", r.Host, r.Path, r.OriginPull)
		}
	}
	modes, err := OriginPullModes(ctx, store)
	if err != nil || modes["new.example.com"] != manifest.OriginPullRequired {
		t.Fatalf("modes %v, %v", modes, err)
	}
}

// Cloudflare holds no certificate for a preview's hostname.
func TestAPreviewTakesNoOriginPull(t *testing.T) {
	p, err := PreviewOf(originPullSite("site"), "feature/x", "preview.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range p.Workloads {
		for _, r := range w.Routes {
			if r.OriginPull != manifest.OriginPullOff {
				t.Fatalf("preview route %s kept origin_pull %q", r.Host, r.OriginPull)
			}
		}
	}
}

// Apps on different paths of one host switch it to origin pull one deploy
// at a time, in either order, and back. The edge checks the host by the
// strictest mode any of them asks for, so an app asking less of it, or
// nothing, leaves it as strict as the other and is held to the same CA.
func TestAppsSharingAHostTakeItsStrictestOriginPull(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	host := "shared.example.com"
	paths := map[string]string{"site": "/", "api": "/api"}
	shared := func(app string, mode manifest.OriginPullMode) *manifest.Manifest {
		m := routeFixture(t, app, paths[app], manifest.DNSProxied)
		w := m.Workloads["web"]
		w.Routes[0].OriginPull = mode
		m.Workloads["web"] = w
		return m
	}
	for _, order := range [][]string{{"site", "api"}, {"api", "site"}} {
		store := goldenStore(t)
		sec := newSecrets(t)
		d := Deploy{Store: store, Secrets: sec, StateDir: t.TempDir()}
		for _, app := range order {
			saveActive(t, store, shared(app, manifest.OriginPullOff))
		}
		if _, err := TrustOriginPull(ctx, store, sec, host, mintCA(t, host, now).PEM, now); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []manifest.OriginPullMode{manifest.OriginPullOptional, manifest.OriginPullRequired, manifest.OriginPullOptional, manifest.OriginPullOff} {
			for _, app := range order {
				m := shared(app, mode)
				if _, err := d.rollout(ctx, m, "r2", &buildFrom{source: t.TempDir()}); err != nil {
					t.Fatalf("%s first: %s switching %s to origin_pull %q was refused: %v", order[0], app, host, mode, err)
				}
				saveActive(t, store, m)
			}
		}
	}

	// site requires the host and the edge has no CA for it, as when the
	// one it trusted ran out: api asking less of the host doesn't open it.
	store := goldenStore(t)
	sec := newSecrets(t)
	d := Deploy{Store: store, Secrets: sec, StateDir: t.TempDir()}
	saveActive(t, store, shared("site", manifest.OriginPullRequired))
	for _, mode := range []manifest.OriginPullMode{manifest.OriginPullOptional, manifest.OriginPullOff} {
		_, err := d.rollout(ctx, shared("api", mode), "r2", &buildFrom{source: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "site requires origin pull on shared.example.com, but the edge trusts no CA for it") {
			t.Fatalf("api with origin_pull %q was planned onto a host site requires and the edge would refuse: %v", mode, err)
		}
	}
	_, err := d.rollout(ctx, shared("api", manifest.OriginPullRequired), "r2", &buildFrom{source: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "api and site require origin pull on shared.example.com") {
		t.Fatalf("both apps requiring the host weren't named: %v", err)
	}
	if _, err := TrustOriginPull(ctx, store, sec, host, mintCA(t, host, now).PEM, now); err != nil {
		t.Fatal(err)
	}
	relaxed := shared("api", manifest.OriginPullOptional)
	if _, err := d.rollout(ctx, relaxed, "r2", &buildFrom{source: t.TempDir()}); err != nil {
		t.Fatalf("api relaxing a host site still requires was refused: %v", err)
	}
	saveActive(t, store, relaxed)
	routes, err := edgeRoutes(ctx, store, sec, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.Host == host && (r.OriginPull != edge.OriginPullRequired || len(r.ClientCAs) != 1) {
			t.Fatalf("%s%s takes origin pull %q with %d CAs, want required with the host's CA", r.Host, r.Path, r.OriginPull, len(r.ClientCAs))
		}
	}
	modes, err := OriginPullModes(ctx, store)
	if err != nil || modes[host] != manifest.OriginPullRequired {
		t.Fatalf("the host reads as %q, %v", modes[host], err)
	}
}

func TestADeployRequiringOriginPullWithoutACAIsRefusedBeforeAnythingChanges(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := goldenStore(t)
	sec := newSecrets(t)
	d := Deploy{Store: store, Secrets: sec, StateDir: t.TempDir()}
	m := originPullSite("site")
	_, err := d.rollout(ctx, m, "r2", &buildFrom{source: t.TempDir()})
	for _, want := range []string{"site requires origin pull on a-required.example.com", "helios edge origin-pull mint a-required.example.com --out FILE", "origin_pull: optional first"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("a deploy whose host would refuse every connection was planned: %v", err)
		}
	}
	if ops, err := store.List(ctx, 20); err != nil || len(ops) != 0 {
		t.Fatalf("planning changed the operation journal: %v %v", ops, err)
	}
	// A CA that ran out is no CA.
	expired := mintCA(t, "a-required.example.com", now.Add(-2*edge.OriginPullLifetime))
	if err := saveOriginPullTrust(sec, edge.OriginPullTrust{"a-required.example.com": {expired}}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.rollout(ctx, m, "r2", &buildFrom{source: t.TempDir()}); err == nil {
		t.Fatal("a CA that ran out was taken for one the edge checks against")
	}
	// Only the required host needs one: an optional host is how a first
	// CA gets tried before anything depends on it.
	if _, err := TrustOriginPull(ctx, store, sec, "a-required.example.com", mintCA(t, "a-required.example.com", now).PEM, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.rollout(ctx, m, "r2", &buildFrom{source: t.TempDir()}); err != nil {
		t.Fatalf("a deploy with a trusted CA was refused: %v", err)
	}
}

// A move's target has to trust the CA the source does: minting another
// would mean a new leaf at Cloudflare that the source would refuse.
func TestAMoveIsNotStagedOntoAnEdgeThatTrustsNoCAForARequiredHost(t *testing.T) {
	ctx := context.Background()
	store, m, h, dir := safeMoveFixture(t)
	w := m.Workloads["web"]
	w.Routes = []manifest.Route{{Host: "site.example.com", DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullRequired}}
	m.Workloads["web"] = w
	writeManifestFile(t, dir, m)
	h.ManifestDigest = manifestDigest(m)
	sec := newSecrets(t)
	stage := MoveStage{Deploy: Deploy{Store: store, Secrets: sec}, Hostname: func() string { return "target" }}
	raw, _ := json.Marshal(MoveStageInput{Source: dir, Revision: MoveTargetRevision(h), Handoff: h})
	_, err := stage.Plan(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "site requires origin pull on site.example.com") || !strings.Contains(err.Error(), "helios edge origin-pull trust") {
		t.Fatalf("a move was staged onto an edge that would refuse its host: %v", err)
	}
	if _, err := TrustOriginPull(ctx, store, sec, "site.example.com", mintCA(t, "site.example.com", time.Now()).PEM, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Plan(ctx, raw); err != nil {
		t.Fatalf("a target trusting the CA was refused: %v", err)
	}
}

func TestAMoveIsNotCutOverOntoAnEdgeThatForgotTheCA(t *testing.T) {
	ctx := context.Background()
	store, m, h, _ := safeMoveFixture(t)
	w := m.Workloads["web"]
	w.Routes = []manifest.Route{{Host: "site.example.com", DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullRequired}}
	m.Workloads["web"] = w
	h.ManifestDigest = manifestDigest(m)
	revision := MoveTargetRevision(h)
	data, _ := json.Marshal(m)
	if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: revision, Status: revisionStaged, Manifest: data, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := saveMigration(store.Path(), &migrationRecord{Handoff: h, Role: "target", Phase: "staged", TargetRevision: revision}); err != nil {
		t.Fatal(err)
	}
	sec := newSecrets(t)
	if _, _, err := integration.Set(sec, integration.CloudflareName, map[string]string{"token": "token"}); err != nil {
		t.Fatal(err)
	}
	c := MoveCutover{Deploy: Deploy{Store: store, Secrets: sec}}
	raw, _ := json.Marshal(MoveCutoverInput{App: m.App, Migration: h.Migration, Revision: revision})
	_, err := c.Plan(ctx, raw)
	if err == nil || !strings.Contains(err.Error(), "helios edge origin-pull trust") || !strings.Contains(err.Error(), "cut over again") {
		t.Fatalf("a move was cut over onto an edge that would refuse its host: %v", err)
	}
	if _, err := TrustOriginPull(ctx, store, sec, "site.example.com", mintCA(t, "site.example.com", time.Now()).PEM, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Plan(ctx, raw); err != nil {
		t.Fatalf("a target trusting the CA was refused: %v", err)
	}
}

// A recovery brings back the trust the source had when it was backed up,
// which can lack a host's CA, or hold one that ran out since. Cutover
// would load the edge refusing that host and then point its name here.
func TestARecoveryIsNotCutOverOntoAnEdgeThatTrustsNoCAForARequiredHost(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	r, _ := recoveryFixture(t)
	in := recoveryInput(false)
	x := &machineRecovering{r: r, in: in, dir: RecoveryDirectory(r.StateDir, in.ID)}
	m := recoveryManifest()
	host := "hello.example.test"
	w := m.Workloads["web"]
	w.Routes = []manifest.Route{{Host: host, DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullRequired}}
	m.Workloads["web"] = w
	body, _ := json.Marshal(m)
	rec := &machineRecoveryRecord{Input: in, FinishedAt: now, StateInstalled: true,
		Catalog: machineRecoveryCatalog{Revisions: []state.Revision{{App: m.App, Manifest: body, Images: map[string]string{"web": "sha256:" + strings.Repeat("b", 64)}}}}, Ready: map[string]bool{m.App: true}}
	if err := x.save(rec); err != nil {
		t.Fatal(err)
	}
	c := RecoverCutover{Recovery: r}
	raw, _ := json.Marshal(RecoverCutoverInput{ID: in.ID})
	_, err := c.Plan(ctx, raw)
	for _, want := range []string{"hello requires origin pull on hello.example.test", "helios edge origin-pull trust <host>", "helios recover cutover " + in.ID + " again"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("a recovery was cut over onto an edge that would refuse its host: %v", err)
		}
	}
	if err := saveOriginPullTrust(r.Secrets, edge.OriginPullTrust{host: {mintCA(t, host, now.Add(-2*edge.OriginPullLifetime))}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Plan(ctx, raw); err == nil {
		t.Fatal("a recovered CA that ran out was taken for one the edge checks against")
	}
	if _, err := TrustOriginPull(ctx, r.Store, r.Secrets, host, mintCA(t, host, now).PEM, now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Plan(ctx, raw); err != nil {
		t.Fatalf("a target trusting the CA was refused: %v", err)
	}
}

// Rollback plans the revision it goes back to as a deploy would. A host's
// CAs can be forgotten while a later revision has it optional, and going
// back to one that requires it would then leave the edge refusing it.
func TestARollbackToARevisionRequiringOriginPullWithoutACAIsRefused(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := goldenStore(t)
	sec := newSecrets(t)
	host := "a-required.example.com"
	save := func(m *manifest.Manifest, id string, status state.RevisionStatus) {
		t.Helper()
		raw, _ := json.Marshal(m)
		if err := store.SaveRevision(ctx, state.Revision{App: m.App, ID: id, Status: status, Manifest: raw, Images: map[string]string{}, Containers: map[string]string{}, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	required := originPullSite("site")
	save(required, "r1", state.RevisionActive)
	if _, err := TrustOriginPull(ctx, store, sec, host, mintCA(t, host, now).PEM, now); err != nil {
		t.Fatal(err)
	}
	optional := originPullSite("site")
	w := optional.Workloads["web"]
	for i := range w.Routes {
		if w.Routes[i].Host == host {
			w.Routes[i].OriginPull = manifest.OriginPullOptional
		}
	}
	optional.Workloads["web"] = w
	save(required, "r1", state.RevisionPrevious)
	save(optional, "r2", state.RevisionActive)
	if n, err := ForgetOriginPull(ctx, store, sec, host, "", now); err != nil || n != 1 {
		t.Fatalf("forgetting the CA of a host now optional: %d %v", n, err)
	}
	rollback := Rollback{Deploy: Deploy{Store: store, Secrets: sec, StateDir: t.TempDir()}}
	_, err := rollback.Plan(ctx, json.RawMessage(`{"app":"site"}`))
	if err == nil || !strings.Contains(err.Error(), "site requires origin pull on a-required.example.com, but the edge trusts no CA for it") {
		t.Fatalf("a rollback onto a host the edge would refuse was planned: %v", err)
	}
	if ops, err := store.List(ctx, 20); err != nil || len(ops) != 0 {
		t.Fatalf("planning changed the operation journal: %v %v", ops, err)
	}
	if _, err := TrustOriginPull(ctx, store, sec, host, mintCA(t, host, now).PEM, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rollback.Plan(ctx, json.RawMessage(`{"app":"site"}`)); err != nil {
		t.Fatalf("a rollback with a trusted CA was refused: %v", err)
	}
}

// The edge checks against no CA that ran out, so one kept beside the last
// usable CA of a required host doesn't make that CA safe to forget.
func TestTheLastUsableCAOfARequiredHostIsKeptBesideOneThatRanOut(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := goldenStore(t)
	sec := newSecrets(t)
	saveRunning(t, store, originPullSite("site"), false)
	host := "a-required.example.com"
	expired, usable := mintCA(t, host, now.Add(-2*edge.OriginPullLifetime)), mintCA(t, host, now)
	trust := edge.OriginPullTrust{}
	trust.Trust(host, expired)
	trust.Trust(host, usable)
	if err := saveOriginPullTrust(sec, trust); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := OriginPullFingerprint(usable.PEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ForgetOriginPull(ctx, store, sec, host, fingerprint, now); err == nil || !strings.Contains(err.Error(), "refuse every connection") {
		t.Fatalf("the required host's last usable CA was forgotten: %v", err)
	}
	kept, err := LoadOriginPullTrust(sec)
	if err != nil || len(kept[host]) != 2 {
		t.Fatalf("a refused forget changed the trust: %v, %v", kept[host], err)
	}
}

// helios can't see which certificate Cloudflare presents, so a CA that
// ran out beside a newer one stays in the trust, where the watch keeps
// saying so, until forget takes it out. Trusting another CA, for its host
// or any other, must not quietly drop it; the edge checks against it no
// more either way.
func TestACAThatRanOutStaysTrustedUntilItIsForgotten(t *testing.T) {
	ctx := context.Background()
	quietEdge(t)
	now := time.Now()
	store := goldenStore(t)
	sec := newSecrets(t)
	saveRunning(t, store, originPullSite("site"), false)
	host := "a-required.example.com"
	old, newer := mintCA(t, host, now.Add(time.Hour-edge.OriginPullLifetime)), mintCA(t, host, now)
	for _, ca := range []edge.OriginPullCA{old, newer} {
		if _, err := TrustOriginPull(ctx, store, sec, host, ca.PEM, now); err != nil {
			t.Fatal(err)
		}
	}
	later := now.Add(2 * time.Hour)
	other := mintCA(t, "b-optional.example.com", later)
	if _, err := TrustOriginPull(ctx, store, sec, "b-optional.example.com", other.PEM, later); err != nil {
		t.Fatal(err)
	}
	newest := mintCA(t, host, later)
	if _, err := TrustOriginPull(ctx, store, sec, host, newest.PEM, later); err != nil {
		t.Fatal(err)
	}
	trust, err := LoadOriginPullTrust(sec)
	if err != nil {
		t.Fatal(err)
	}
	if cas := trust[host]; len(cas) != 3 || cas[0].PEM != old.PEM {
		t.Fatalf("%s trusts %d CAs, and the one that ran out isn't the first: trusting another CA dropped it", host, len(cas))
	}
	routes, err := edgeRoutes(ctx, store, sec, later)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.Host == host && !slices.Equal(r.ClientCAs, []string{caDER(t, newer), caDER(t, newest)}) {
			t.Fatalf("%s%s checks against %d CAs, want the two that haven't run out", r.Host, r.Path, len(r.ClientCAs))
		}
	}
	fingerprint, err := OriginPullFingerprint(old.PEM)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := ForgetOriginPull(ctx, store, sec, host, fingerprint, later); err != nil || n != 1 {
		t.Fatalf("forget the CA that ran out: %d %v", n, err)
	}
}

func TestTrustingAndForgettingOriginPullCAs(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := goldenStore(t)
	sec := newSecrets(t)
	saveRunning(t, store, originPullSite("site"), false)
	host := "a-required.example.com"
	minted, err := edge.MintOriginPull(host, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, pem := range map[string]string{"the leaf": string(minted.LeafPEM), "the key": string(minted.KeyPEM), "nothing": ""} {
		if _, err := TrustOriginPull(ctx, store, sec, host, pem, now); err == nil {
			t.Fatalf("%s was trusted as a CA", name)
		}
	}
	if _, err := TrustOriginPull(ctx, store, sec, "not a host", minted.CA.PEM, now); err == nil {
		t.Fatal("a CA was trusted for something that isn't a host name")
	}
	if _, err := TrustOriginPull(ctx, store, sec, host, minted.CA.PEM, now.Add(2*edge.OriginPullLifetime)); err == nil || !strings.Contains(err.Error(), "ran out") {
		t.Fatalf("a CA that ran out was trusted: %v", err)
	}
	first := minted.CA
	if added, err := TrustOriginPull(ctx, store, sec, strings.ToUpper(host), first.PEM, now); err != nil || !added {
		t.Fatalf("trust: %v %v", added, err)
	}
	if added, err := TrustOriginPull(ctx, store, sec, host, first.PEM, now); err != nil || added {
		t.Fatalf("the same CA trusted twice: %v %v", added, err)
	}
	// Rotation: the new CA joins the old, which stays until it is forgotten.
	second := mintCA(t, host, now.Add(time.Hour))
	if added, err := TrustOriginPull(ctx, store, sec, host, second.PEM, now); err != nil || !added {
		t.Fatalf("a second CA: %v %v", added, err)
	}
	trust, err := LoadOriginPullTrust(sec)
	if err != nil || len(trust[host]) != 2 {
		t.Fatalf("the host trusts %v, %v", trust[host], err)
	}

	firstPrint, err := OriginPullFingerprint(first.PEM)
	if err != nil || !strings.HasPrefix(firstPrint, "sha256:") || len(firstPrint) != len("sha256:")+64 {
		t.Fatalf("fingerprint %q, %v", firstPrint, err)
	}
	if _, err := ForgetOriginPull(ctx, store, sec, host, "sha256:00", now); err == nil {
		t.Fatal("forgot a CA the host doesn't trust")
	}
	if n, err := ForgetOriginPull(ctx, store, sec, host, strings.ToUpper(firstPrint), now); err != nil || n != 1 {
		t.Fatalf("forget the old CA: %d %v", n, err)
	}
	// The last CA of a host an app requires origin pull for stays.
	if _, err := ForgetOriginPull(ctx, store, sec, host, "", now); err == nil || !strings.Contains(err.Error(), "refuse every connection") {
		t.Fatalf("the required host was left with nothing to check against: %v", err)
	}
	// Once it ran out, forgetting it changes nothing the edge does.
	if n, err := ForgetOriginPull(ctx, store, sec, host, "", now.Add(2*edge.OriginPullLifetime)); err != nil || n != 1 {
		t.Fatalf("forget a CA that ran out: %d %v", n, err)
	}
	optional := mintCA(t, "b-optional.example.com", now)
	if _, err := TrustOriginPull(ctx, store, sec, "b-optional.example.com", optional.PEM, now); err != nil {
		t.Fatal(err)
	}
	if n, err := ForgetOriginPull(ctx, store, sec, "b-optional.example.com", "", now); err != nil || n != 1 {
		t.Fatalf("forget the optional host's CA: %d %v", n, err)
	}
	if _, err := ForgetOriginPull(ctx, store, sec, "b-optional.example.com", "", now); err == nil {
		t.Fatal("forgot CAs a host no longer has")
	}
	values, _, err := sec.LoadCurrent(integration.App)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := values[integration.OriginPullName]; kept {
		t.Fatalf("no trust left, but the value stays: %q", values[integration.OriginPullName])
	}
}

func TestOriginPullStatusListsEveryHostThatSetsItOrTrustsACA(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := goldenStore(t)
	sec := newSecrets(t)
	saveRunning(t, store, originPullSite("site"), false)
	// Another app asks more of a host the first has optional, on a path of
	// its own: the host takes the stricter mode.
	stricter := &manifest.Manifest{App: "docs", Workloads: map[string]manifest.Workload{"web": {
		Kind: manifest.Web, Image: "example/docs:1", Port: 8080,
		Routes: []manifest.Route{{Host: "b-optional.example.com", Path: "/docs", DNS: manifest.DNSProxied, OriginPull: manifest.OriginPullRequired}},
	}}}
	saveRunning(t, store, stricter, false)
	modes, err := OriginPullModes(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]manifest.OriginPullMode{"a-required.example.com": manifest.OriginPullRequired, "b-optional.example.com": manifest.OriginPullRequired}; len(modes) != len(want) || modes["a-required.example.com"] != want["a-required.example.com"] || modes["b-optional.example.com"] != want["b-optional.example.com"] {
		t.Fatalf("modes %v, want %v", modes, want)
	}
	required := mintCA(t, "a-required.example.com", now)
	leftover := mintCA(t, "gone.example.com", now)
	trust := edge.OriginPullTrust{}
	trust.Trust("a-required.example.com", required)
	trust.Trust("gone.example.com", leftover)
	if err := saveOriginPullTrust(sec, trust); err != nil {
		t.Fatal(err)
	}
	hosts, err := OriginPullStatus(ctx, store, sec)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, h := range hosts {
		names = append(names, h.Host)
	}
	if !slices.Equal(names, []string{"a-required.example.com", "b-optional.example.com", "gone.example.com"}) {
		t.Fatalf("hosts %v", names)
	}
	fp, _ := OriginPullFingerprint(required.PEM)
	if a := hosts[0]; a.Mode != manifest.OriginPullRequired || len(a.CAs) != 1 || a.CAs[0].Fingerprint != fp || !a.CAs[0].NotAfter.Equal(required.NotAfter) {
		t.Fatalf("a-required: %+v", a)
	}
	// A host that requires origin pull and trusts nothing is listed, with
	// an empty list rather than none, so it reads as the problem it is.
	if b := hosts[1]; b.CAs == nil || len(b.CAs) != 0 {
		t.Fatalf("b-optional: %+v", b)
	}
	if g := hosts[2]; g.Mode != manifest.OriginPullOff || len(g.CAs) != 1 {
		t.Fatalf("a CA no app uses: %+v", g)
	}
	if _, err := sec.Set(integration.App, integration.OriginPullName, "["); err != nil {
		t.Fatal(err)
	}
	if _, err := OriginPullStatus(ctx, store, sec); err == nil {
		t.Fatal("a trust that doesn't parse was listed as none")
	}
}
