// Package app deploys and rolls back apps: builds their images, starts a
// new revision beside the old, waits for it to be ready, switches the
// edge, checks it, and retires what it replaced.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/kylebegeman/helios/internal/cloudflare"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// DeployKind deploys a source directory as a new revision of its app.
const DeployKind = "app.deploy"

// RollbackKind makes an earlier revision active again.
const RollbackKind = "app.rollback"

// Deploy is the Definition for DeployKind.
type Deploy struct {
	Store   *state.Store
	Secrets *secrets.Store
	// Addresses are this machine's public addresses, for the DNS check.
	Addresses func(ctx context.Context) []string
	// StateDir is helios's state directory; empty means /var/lib/bedrock.
	StateDir string
	// CloudflareOnly refuses routes that would not go through Cloudflare's
	// proxy on a machine that answers only Cloudflare.
	CloudflareOnly CloudflareOnly
}

// DeployInput says what to deploy.
type DeployInput struct {
	// Source is the directory holding helios.yaml and the code.
	Source string `json:"source"`
	// Revision names the new revision; the CLI makes one from the clock.
	Revision string `json:"revision"`
	// Restore loads data before the first start.
	Restore Restore `json:"restore,omitempty"`
	// Commit is the source's commit when the caller knows it, as a push
	// does; otherwise it is read from the source when it is a checkout.
	Commit string `json:"commit,omitempty"`
	// Signer is who signed Commit, as a push or webhook checked it for an
	// app that deploys only signed commits: the principal and key
	// fingerprint. Empty means the commit wasn't checked.
	Signer string `json:"signer,omitempty"`
	// Manifest names the manifest at the source's root; empty is helios.yaml.
	Manifest string `json:"manifest,omitempty"`
	// SecretsFrom names an app whose current secrets are copied to this one
	// before its own are made: a preview inherits the values its parent was
	// given by hand. Empty means none.
	SecretsFrom string `json:"secrets_from,omitempty"`
}

var revisionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{3,40}$`)

// NewRevision names a revision by the moment it was made, to the second, so
// revisions sort by time and read as dates. It is the one place a revision
// is minted, and nothing that goes into a plan's digest carries it: the
// same source planned twice yields the same plan, whenever it was planned.
func NewRevision(now time.Time) string { return now.UTC().Format("20060102-150405") }

// Kind implements kernel.Definition.
func (Deploy) Kind() string { return DeployKind }

// Plan implements kernel.Definition.
func (d Deploy) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in DeployInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("deploy input: %w", err)
	}
	if !filepath.IsAbs(in.Source) {
		return nil, errors.New("deploy needs the absolute path of the source directory")
	}
	if !revisionPattern.MatchString(in.Revision) {
		return nil, fmt.Errorf("revision %q must be lowercase letters, digits and hyphens", in.Revision)
	}
	if len(in.Signer) > 200 || strings.ContainsFunc(in.Signer, unicode.IsControl) {
		return nil, errors.New("the commit's signer must be one line of at most 200 characters")
	}
	// The manifest is read as root: LoadFile takes only a plain file of
	// the source's own, never a link out of it.
	name := in.Manifest
	stateDir := d.StateDir
	if stateDir == "" {
		stateDir = defaultStateDir
	}
	if err := refuseRecursiveDeployCapture(in.Source, stateDir); err != nil {
		return nil, err
	}
	cached, err := readDeploySourceReservation(stateDir, in)
	if err != nil {
		return nil, err
	}
	var m *manifest.Manifest
	if cached != nil {
		m = &cached.Manifest
	} else {
		m, err = manifest.LoadFile(in.Source, name)
		if err != nil {
			return nil, err
		}
	}
	if d.Store != nil {
		if err := CheckMigrationAccess(d.Store.Path(), m.App); err != nil {
			return nil, err
		}
		if err := checkReleaseStoreAccess(ctx, d.Store, m.App); err != nil {
			return nil, err
		}
	}
	if len(m.ManagedHosts()) > 0 {
		if _, err := integration.LoadCloudflare(d.Secrets); err != nil {
			return nil, errNoCloudflare(m.App, err)
		}
	}
	// A route that asks for a sign-in and cannot get one would be served
	// open. Refuse here rather than part way through, once containers are
	// already running and the edge is about to be pointed at them.
	if guarded := m.GuardedRoutes(); len(guarded) > 0 {
		g, err := loomGuard(d.Secrets)
		if err != nil {
			return nil, err
		}
		if g == nil {
			return nil, fmt.Errorf("%s puts a sign-in on %s, and this machine has no loom integration to ask: helios integration set loom",
				m.App, strings.Join(guarded, ", "))
		}
	}
	if in.SecretsFrom == m.App {
		return nil, fmt.Errorf("%s would copy its secrets onto itself", m.App)
	}
	if err := CheckDeploySecretsFrom(m, d.Secrets, in.SecretsFrom); err != nil {
		return nil, err
	}
	commit := in.Commit
	var sourceHash string
	if cached != nil {
		commit, sourceHash = cached.Commit, cached.Hash
		if !cached.Discarded {
			captured := filepath.Join(deploySourceDir(stateDir, m.App, in.Revision), "source")
			if _, err := os.Lstat(captured); err == nil {
				got, err := deploySourceHash(ctx, captured)
				if err != nil {
					return nil, err
				}
				if got != sourceHash {
					return nil, errors.New("captured deploy source changed; refusing operation recovery")
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	} else {
		if commit == "" {
			commit = sourceCommit(ctx, in.Source)
		}
		sourceHash, err = deploySourceHash(ctx, in.Source)
		if err != nil {
			return nil, err
		}
	}
	return deployCapturePlan(ctx, d, in, m, commit, sourceHash)
}

// buildFrom says images come from a source directory; nil means they are
// already recorded (a rollback).
type buildFrom struct {
	source      string
	commit      string
	signer      string
	restore     Restore
	secretsFrom string
}

// defaultStateDir is helios's state on a machine, where a Deploy that
// doesn't say otherwise keeps what it copies.
const defaultStateDir = "/var/lib/bedrock"

// buildGroups lists the images a deploy makes, each with the workloads
// that share it: workloads built from the same context, Dockerfile,
// target and arguments, or pulled from the same reference, share one.
// Groups keep manifest order, by their first workload.
func buildGroups(m *manifest.Manifest) [][]string {
	var groups [][]string
	index := map[string]int{}
	for _, name := range m.WorkloadNames() {
		w := m.Workloads[name]
		key := ""
		switch {
		case w.Kind == manifest.Static:
			key = "static\x00" + name
		case w.Build != nil:
			var args []string
			for _, k := range sortedKeys(w.Build.Args) {
				args = append(args, k+"="+w.Build.Args[k])
			}
			key = strings.Join([]string{"build", orDot(w.Build.Context), w.Build.Dockerfile, w.Build.Target, strings.Join(args, "\x01")}, "\x00")
		default:
			key = "image\x00" + w.Image
		}
		if i, ok := index[key]; ok {
			groups[i] = append(groups[i], name)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, []string{name})
	}
	return groups
}

// graceOf is how long a revision's workload gets to stop, as its own
// manifest says.
func graceOf(rev *state.Revision, workload string) time.Duration {
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err == nil {
		if w, ok := m.Workloads[workload]; ok {
			return w.GraceOr(10 * time.Second)
		}
	}
	return 10 * time.Second
}

// restartStoppedWorkloads starts again stopped long-running containers of the active
// revision that a deploy of another revision stopped, once that deploy
// has taken its own containers down.
func restartStoppedWorkloads(ctx context.Context, e *docker.Engine, store *state.Store, app, except string, out io.Writer) error {
	current, err := store.RevisionWithStatus(ctx, app, state.RevisionActive)
	if err != nil {
		return err
	}
	if current == nil || current.ID == except {
		return nil
	}
	var m manifest.Manifest
	if err := json.Unmarshal(current.Manifest, &m); err != nil {
		return err
	}
	var failures []error
	for _, name := range m.WorkloadNames() {
		if !m.Workloads[name].LongRunning() {
			continue
		}
		c := current.Containers[name]
		info, err := e.Inspect(ctx, c)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if info.Running {
			continue
		}
		if err := e.Start(ctx, c); err != nil {
			failures = append(failures, err)
			fmt.Fprintf(out, "starting %s again failed: %v\n", c, err)
			continue
		}
		fmt.Fprintf(out, "%s started again\n", c)
	}
	return errors.Join(failures...)
}

func noteCommit(commit string) string {
	if commit == "" {
		return ""
	}
	return "commit " + commit
}

func noteSigner(signer string) string {
	if signer == "" {
		return ""
	}
	return "signed by " + signer
}

// notes joins the parts of a step's note that are there.
func notes(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "; ")
}

func orDot(s string) string {
	if s == "" {
		return "."
	}
	return s
}

func imageLabels(app, workload, revision string) map[string]string {
	return map[string]string{docker.LabelOwner: docker.OwnerValue, docker.LabelApp: app, docker.LabelWorkload: workload, docker.LabelRevision: revision}
}

// recordImage stores the digest reference of a built image on the
// revision, for every workload that shares it.
func recordImage(ctx context.Context, store *state.Store, connect func(context.Context) (*docker.Engine, error), app, revision string, workloads []string, ref string, images map[string]string, out io.Writer) error {
	e, err := connect(ctx)
	if err != nil {
		return err
	}
	digest, err := e.Digest(ctx, ref)
	if err != nil {
		return err
	}
	for _, w := range workloads {
		images[w] = digest
	}
	fmt.Fprintf(out, "%s\n", digest)
	return saveImageReferences(ctx, store, app, revision, workloads, digest)
}

// Merge into the durable record: after a daemon restart, earlier build steps
// are skipped and their images exist only in the store.
func saveImageReferences(ctx context.Context, store *state.Store, app, revision string, workloads []string, image string) error {
	rev, err := store.GetRevision(ctx, app, revision)
	if err != nil {
		return err
	}
	if rev.Images == nil {
		rev.Images = map[string]string{}
	}
	for _, name := range workloads {
		rev.Images[name] = image
	}
	return store.SaveRevision(ctx, *rev)
}

// filtered keeps a build's useful lines and drops the progress noise.
func filtered(out io.Writer) io.Writer { return &lineFilter{out: out} }

type lineFilter struct {
	out     io.Writer
	partial strings.Builder
}

func (f *lineFilter) Write(p []byte) (int, error) {
	for _, c := range p {
		if c != '\n' {
			f.partial.WriteByte(c)
			continue
		}
		if line, ok := docker.TrimBuildLine(f.partial.String()); ok {
			fmt.Fprintln(f.out, line)
		}
		f.partial.Reset()
	}
	return len(p), nil
}

func containerSpec(m *manifest.Manifest, name string, w manifest.Workload, revision, image string, values map[string]string) (docker.Spec, error) {
	spec := docker.Spec{
		Name:     docker.ContainerName(m.App, name, revision),
		Image:    image,
		Cmd:      w.Command,
		Labels:   imageLabels(m.App, name, revision),
		Networks: []string{docker.AppNetwork(m.App)},
		// The app's other workloads reach it by its name and its aliases.
		Aliases:   append([]string{name}, w.Aliases...),
		Restart:   true,
		PidsLimit: w.Resources.Pids,
		// The manifest's health is the one that counts; an image's own
		// HEALTHCHECK, written for another role of it, would only mislead.
		NoHealthcheck: w.Health != nil,
	}
	if w.Serves() {
		// The one network it shares with the edge, and with no other app.
		spec.Networks = append(spec.Networks, edge.AppNetwork(m.App))
	}
	spec.Env = []string{
		"HELIOS_APP=" + m.App, "HELIOS_WORKLOAD=" + name, "HELIOS_REVISION=" + revision,
		"BEDROCK_APP=" + m.App, "BEDROCK_WORKLOAD=" + name, "BEDROCK_REVISION=" + revision,
	}
	for _, k := range sortedKeys(w.Env) {
		spec.Env = append(spec.Env, k+"="+w.Env[k])
	}
	for _, k := range w.Secrets {
		spec.Env = append(spec.Env, k+"="+values[k])
	}
	if m.InjectsDatabaseURL() && !slices.Contains(w.Secrets, DatabaseURLName) {
		spec.Env = append(spec.Env, DatabaseURLName+"="+values[DatabaseURLName])
	}
	for _, mt := range w.Mounts {
		spec.Mounts = append(spec.Mounts, docker.VolumeName(m.App, mt.Volume)+":"+mt.Path)
	}
	for _, p := range w.Ports {
		spec.Publish = append(spec.Publish, publishSpec(p))
	}
	if w.Resources.Memory != "" {
		bytes, err := parseSize(w.Resources.Memory)
		if err != nil {
			return spec, err
		}
		spec.MemoryBytes = bytes
	}
	if w.Resources.CPUs > 0 {
		spec.NanoCPUs = int64(w.Resources.CPUs * 1e9)
	}
	return spec, nil
}

// publishSpec writes a published port the way docker.Spec takes it, such as
// 3478:3478/udp or [::1]:8443:443/tcp.
func publishSpec(p manifest.PublishedPort) string {
	host := strconv.Itoa(p.OnHost())
	if p.Address != "" {
		host = net.JoinHostPort(p.Address, host)
	}
	return fmt.Sprintf("%s:%d/%s", host, p.Port, p.Proto())
}

// ParseSize reads a size written the way a manifest writes one: 512k, 256m,
// 8g. Exported so the CLI parses sizes exactly as the manifest does.
func ParseSize(s string) (int64, error) {
	return parseSize(s)
}

func parseSize(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("size %q", s)
	}
	return manifest.ParseMemory(s)
}

// waitReady waits until a workload's container is ready: its health
// command succeeds or its health path answers, or else its port accepts
// connections. A worker with neither only has to stay up.
func waitReady(ctx context.Context, e *docker.Engine, container string, w manifest.Workload) error {
	timeout := 60 * time.Second
	if w.Health != nil && w.Health.Timeout != "" {
		if d, err := time.ParseDuration(w.Health.Timeout); err == nil {
			timeout = d
		}
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last string
	expired := func() error {
		if err := parent.Err(); err != nil {
			return err
		}
		return fmt.Errorf("not ready after %s: %s", timeout, last)
	}
	for {
		info, err := e.Inspect(ctx, container)
		switch {
		case err != nil:
			last = err.Error()
		case !info.Running || info.Restarts > 0:
			// Its last words say why, isolation included (a binary that
			// wants a capability, a write to a read-only path).
			words := lastWords(e.LogTail(ctx, container, 30))
			return fmt.Errorf("the container exited (exit code %d, restarted %d times): %s", info.ExitCode, info.Restarts, words)
		default:
			ok, why := probeReady(ctx, e, container, info, w)
			if ok {
				return nil
			}
			last = why
		}
		if ctx.Err() != nil {
			return expired()
		}
		select {
		case <-ctx.Done():
			return expired()
		case <-time.After(2 * time.Second):
		}
	}
}

// probeReady asks a running container once whether it is ready.
func probeReady(ctx context.Context, e *docker.Engine, container string, info *docker.Info, w manifest.Workload) (bool, string) {
	if w.Health != nil && len(w.Health.Command) > 0 {
		if err := HealthCommand(ctx, e, container, w.Health.Command); err != nil {
			return false, err.Error()
		}
		return true, ""
	}
	port := servePort(w, nil)
	if port == 0 {
		// A worker that says nothing about its health: running is ready.
		return true, ""
	}
	ip := containerIP(info)
	if ip == "" {
		return false, "no network address yet"
	}
	if w.Health != nil && w.Health.Path != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(ip, strconv.Itoa(port))+w.Health.Path, nil)
		if err != nil {
			return false, err.Error()
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: directCheckRedirect}).Do(req)
		if err != nil {
			return false, err.Error()
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			return true, ""
		}
		return false, fmt.Sprintf("%s answered %s", w.Health.Path, resp.Status)
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false, err.Error()
	}
	conn.Close()
	return true, ""
}

// HealthCommand runs a workload's health command inside its container;
// it is healthy when the command exits 0 within 30 seconds.
func HealthCommand(ctx context.Context, e *docker.Engine, container string, command []string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := e.Exec(ctx, container, nil, command...)
	if err != nil {
		if ctx.Err() != nil {
			return errors.New("the health command took longer than 30s")
		}
		if words := lastWords(out); words != "it wrote nothing; see helios logs" {
			return fmt.Errorf("the health command failed: %s", words)
		}
		return errors.New("the health command failed")
	}
	return nil
}

// servePort is the port a route reaches, or with no route the port the
// workload listens on: static workloads serve on helios's own.
func servePort(w manifest.Workload, r *manifest.Route) int {
	if w.Kind == manifest.Static {
		port, _ := strconv.Atoi(docker.StaticPort)
		return port
	}
	if r != nil {
		return w.RoutePort(*r)
	}
	return w.Port
}

// ReloadEdge gives the edge the configuration the active revisions call
// for, when it is up. The daemon does this at start, so a helios that
// changed how it configures the edge takes effect without a deploy.
func ReloadEdge(ctx context.Context, store *state.Store, sec *secrets.Store) error {
	_, err := LoadEdge(ctx, store, sec)
	return err
}

// LoadEdge is ReloadEdge, and also reports whether the edge took the
// configuration: one whose admin API doesn't answer takes none, and keeps
// running whatever it last took.
func LoadEdge(ctx context.Context, store *state.Store, sec *secrets.Store) (bool, error) {
	return loadEdge(ctx, edge.NewAdmin(), store, sec)
}

// edgeAdmin is what loading the edge needs of its admin API.
type edgeAdmin interface {
	Answers(context.Context) bool
	Load(context.Context, []byte) error
}

func loadEdge(ctx context.Context, admin edgeAdmin, store *state.Store, sec *secrets.Store) (bool, error) {
	if !admin.Answers(ctx) {
		return false, nil
	}
	cfg, err := EdgeConfig(ctx, store, sec)
	if err != nil {
		return false, err
	}
	if err := admin.Load(ctx, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// UpgradeEdge replaces an edge an older helios made, keeping its routes,
// and then gives it the current configuration, reporting as LoadEdge does
// whether it took it. A machine without an edge yet is left for host
// setup.
func UpgradeEdge(ctx context.Context, store *state.Store, sec *secrets.Store, out io.Writer) (bool, error) {
	e, err := docker.Connect(ctx)
	if err != nil {
		return false, err
	}
	defer e.Close()
	info, err := e.Inspect(ctx, edge.Container)
	if err != nil {
		return false, nil
	}
	if info.Labels[edge.LayoutLabel] != edge.Layout {
		boot, err := EdgeConfig(ctx, store, sec)
		if err != nil {
			return false, err
		}
		if err := edge.Ensure(ctx, e, boot, out); err != nil {
			return false, err
		}
	}
	return LoadEdge(ctx, store, sec)
}

// servesAny reports whether any of an app's workloads takes traffic from
// the edge.
func servesAny(m *manifest.Manifest) bool {
	for _, name := range m.WorkloadNames() {
		if m.Workloads[name].Serves() {
			return true
		}
	}
	return false
}

// isolationWord says in a few words when a workload asked to be less
// isolated than the default.
func isolationWord(w manifest.Workload) string {
	switch {
	case w.Privileged:
		return ", privileged as its manifest says"
	case w.WritableRoot:
		return ", root filesystem writable as its manifest says"
	}
	return ""
}

// EdgeConfig builds the edge's whole configuration from every active revision.
func EdgeConfig(ctx context.Context, store *state.Store, sec *secrets.Store) ([]byte, error) {
	return edgeConfig(ctx, store, sec)
}

// HookRoute is the path webhooks arrive on, as the edge routes it: a
// prefix, as every route's path is.
const HookRoute = edge.HookPath + "/"

// lastWords picks the line of a container's output that best says why it
// stopped, for an error message: the last one that names an error, or else
// the last one with words in it, not a stack trace's closing brace.
func lastWords(logs string) string {
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); errorLine.MatchString(l) {
			return l
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); wordy.MatchString(l) {
			return l
		}
	}
	return "it wrote nothing; see helios logs"
}

var (
	errorLine = regexp.MustCompile(`(?i)\b(error|exception|fatal|panic)\b.*[a-z]{3}`)
	wordy     = regexp.MustCompile(`[A-Za-z]{3}`)
)

// showLastLines writes a container's last lines to a step's output, so the
// record says why it failed after the container is gone.
func showLastLines(ctx context.Context, e *docker.Engine, container, name string, out io.Writer) {
	tail := strings.TrimSpace(e.LogTail(ctx, container, 30))
	if tail == "" {
		return
	}
	fmt.Fprintf(out, "%s's last lines:\n", name)
	for _, line := range strings.Split(tail, "\n") {
		fmt.Fprintf(out, "  %s\n", line)
	}
}

// edgeConfig builds the edge's whole configuration from every active revision.
func edgeConfig(ctx context.Context, store *state.Store, sec *secrets.Store) ([]byte, error) {
	routes, err := edgeRoutes(ctx, store, sec, time.Now())
	if err != nil {
		return nil, err
	}
	return edge.ConfigBehind(routes, cloudflareProxies())
}

// edgeNotes hears what edgeConfig leaves out of the configuration rather
// than refuse all of it: the daemon's log, or the terminal of whoever ran
// the command. Tests replace it.
var edgeNotes io.Writer = os.Stderr

// edgeRoutes are the routes every active revision asks the edge for.
func edgeRoutes(ctx context.Context, store *state.Store, sec *secrets.Store, now time.Time) ([]edge.Route, error) {
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return nil, err
	}
	hooks, err := store.GitHooks(ctx)
	if err != nil {
		return nil, err
	}
	hooked := map[string]bool{}
	for _, h := range hooks {
		hooked[h.App] = true
	}
	guard, err := loomGuard(sec)
	if err != nil {
		return nil, err
	}
	var routes []edge.Route
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return nil, fmt.Errorf("revision %s/%s manifest: %w", rev.App, rev.ID, err)
		}
		if hosts := m.Hosts(); hooked[rev.App] && len(hosts) > 0 {
			// Webhooks for the app arrive on its first host and go to
			// helios, not to the app.
			routes = append(routes, edge.Route{Host: hosts[0], Path: HookRoute, Dial: edge.HooksDial})
		}
		for _, name := range m.WorkloadNames() {
			w := m.Workloads[name]
			for _, r := range w.Routes {
				route := edge.Route{Host: r.Host, Path: r.NormalizedPath(), Dial: fmt.Sprintf("%s:%d", rev.Containers[name], servePort(w, &r)), OriginPull: string(r.OriginPull)}
				if r.Auth.Guarded() {
					// Serving a route that asked for a sign-in without one
					// would put the app on the open internet, so the whole
					// configuration is refused instead.
					if guard == nil {
						return nil, fmt.Errorf("%s routes %s with auth: %s, and this machine has no loom integration: helios integration set loom", rev.App, r.Host, r.Auth)
					}
					route.Guard = guard
				}
				routes = append(routes, route)
			}
		}
	}
	if asksOriginPull(routes) {
		trust, err := LoadOriginPullTrust(sec)
		if err != nil {
			// One unreadable value must not take every app's edge down
			// with it, so no host gets a CA: one that requires origin pull
			// refuses every connection and every other host keeps
			// working. helios watch reports the same trouble.
			fmt.Fprintf(edgeNotes, "edge: %v; until it loads, a host that requires origin pull refuses every connection and one where it is optional checks no certificate\n", err)
			trust = edge.OriginPullTrust{}
		}
		settleOriginPull(routes, trust, now)
	}
	return routes, nil
}

// cloudflareProxies are the ranges the edge trusts to say who a visitor
// behind Cloudflare's proxy is: the list host setup keeps. Without one, or
// with one that does not parse, nothing is trusted and apps see the
// connecting address, which is the safe way to be wrong. Tests replace it.
var cloudflareProxies = func() []string { return keptProxies(cloudflare.RangesFile) }

func keptProxies(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	r, err := cloudflare.ParseRanges(b)
	if err != nil {
		return nil
	}
	return r.All()
}

func checkTimeout(c manifest.Check) time.Duration {
	if c.Within != "" {
		if d, err := time.ParseDuration(c.Within); err == nil {
			return d
		}
	}
	return 10 * time.Second
}

// RunCheck performs one manifest check against the live URL, through the
// edge, the way the watcher does between deploys.
func RunCheck(ctx context.Context, c manifest.Check) error { return runCheck(ctx, c) }

// runCheck performs one manifest check against the live URL, through the
// edge, resolving the name the way the world does.
func runCheck(ctx context.Context, c manifest.Check) error {
	within := checkTimeout(c)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	transport := publicTransport()
	defer transport.CloseIdleConnections()
	return evaluateCheck(c, &http.Client{Timeout: within, Transport: transport}, req, within)
}

// runCheckDirect performs a check against the new container that would
// serve the URL, before the edge routes anything to it.
func runCheckDirect(ctx context.Context, e checkInspector, m *manifest.Manifest, containers map[string]string, c manifest.Check) error {
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("check %s: %w", c.URL, err)
	}
	name, w, route, ok := m.RouteFor(u.Hostname(), u.Path)
	if !ok {
		return fmt.Errorf("check %s: no workload routes %s%s", c.URL, u.Hostname(), u.Path)
	}
	info, err := e.Inspect(ctx, containers[name])
	if err != nil {
		return fmt.Errorf("check %s: %w", c.URL, err)
	}
	ip := containerIP(info)
	if ip == "" {
		return fmt.Errorf("check %s: %s has no address", c.URL, containers[name])
	}
	within := checkTimeout(c)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(ip, strconv.Itoa(servePort(w, &route)))+u.RequestURI(), nil)
	if err != nil {
		return err
	}
	req.Host = u.Host
	return evaluateCheck(c, &http.Client{Timeout: within, CheckRedirect: directCheckRedirect}, req, within)
}

func directCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("direct check stopped after 10 redirects")
	}
	if len(via) == 0 || req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host {
		return errors.New("direct check refused a redirect outside the checked container")
	}
	return nil
}

func evaluateCheck(c manifest.Check, client *http.Client, req *http.Request, within time.Duration) error {
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("check %s: %w", c.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("check %s: read response: %w", c.URL, err)
	}
	took := time.Since(started)
	want := c.Status
	if want == 0 {
		want = http.StatusOK
	}
	if resp.StatusCode != want {
		return fmt.Errorf("check %s: answered %s, want %d", c.URL, resp.Status, want)
	}
	if c.Contains != "" && !strings.Contains(string(body), c.Contains) {
		return fmt.Errorf("check %s: the page doesn't contain %q", c.URL, c.Contains)
	}
	if took > within {
		return fmt.Errorf("check %s: took %s, longer than %s", c.URL, took.Round(time.Millisecond), within)
	}
	return nil
}

func containerIP(info *docker.Info) string {
	if ip := info.IPs[docker.EdgeNetwork]; ip != "" {
		return ip
	}
	for _, ip := range info.IPs {
		return ip
	}
	return ""
}

// revertSwitch puts the previous revision back on the edge after a live
// verification failed, or routes nothing to the app when there is none,
// and takes the failed revision's containers down.
func revertSwitch(ctx context.Context, store *state.Store, sec *secrets.Store, connect func(context.Context) (*docker.Engine, error), app, failed string, containers map[string]string) (string, error) {
	prev, err := store.RevisionWithStatus(ctx, app, state.RevisionPrevious)
	if err != nil {
		return "", err
	}
	if prev != nil {
		if err := store.Activate(ctx, app, prev.ID, time.Now().UTC()); err != nil {
			return "", err
		}
	}
	if err := store.SetRevisionStatus(ctx, app, failed, state.RevisionFailed); err != nil {
		return "", err
	}
	cfg, err := edgeConfig(ctx, store, sec)
	if err != nil {
		return "", err
	}
	e, err := connect(ctx)
	if err != nil {
		return "", err
	}
	var failures []error
	for _, c := range containers {
		if err := e.Remove(ctx, c, 5*time.Second); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 {
		// Restore stopped workloads even when the edge itself is unavailable.
		if err := restartStoppedWorkloads(ctx, e, store, app, failed, io.Discard); err != nil {
			failures = append(failures, err)
		}
	} else {
		// Never start a singleton again while its failed replacement may
		// still be running.
		failures = append(failures, errors.New("the previous revision's stopped workloads were not started again while the failed containers remain"))
	}
	// The edge goes back whatever happened above: what still runs of the
	// previous revision should be reached, and the failed revision should not.
	if err := edge.NewAdmin().Load(ctx, cfg); err != nil {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		return "", errors.Join(failures...)
	}
	if prev == nil {
		return "the edge routes nothing to " + app + " now", nil
	}
	return "the edge is back on " + prev.ID, nil
}

// sourceCommit reads the source's git commit, when it is a checkout.
func sourceCommit(ctx context.Context, source string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", source, "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Rollback is the Definition for RollbackKind.
type Rollback struct {
	Deploy Deploy
}

// RollbackInput says which revision to make active again.
type RollbackInput struct {
	App string `json:"app"`
	// Revision is the one to return to; empty means the previous one.
	Revision string `json:"revision,omitempty"`
	// RestoreData is an exact retained release checkpoint. It explicitly replaces data.
	RestoreData string `json:"restore_data,omitempty"`
}

// Kind implements kernel.Definition.
func (Rollback) Kind() string { return RollbackKind }

// Plan implements kernel.Definition.
func (r Rollback) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in RollbackInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("rollback input: %w", err)
	}
	store := r.Deploy.Store
	if in.App == "" {
		return nil, errors.New("which app?")
	}
	if store != nil {
		if err := CheckMigrationAccess(store.Path(), in.App); err != nil {
			return nil, err
		}
	}
	var rev *state.Revision
	var err error
	// The checkpoint pins the target even when "previous" changes after an
	// interrupted activation. A retry must restore and start the same revision.
	if in.RestoreData != "" {
		if !fullSnapshotID.MatchString(in.RestoreData) {
			return nil, errors.New("--restore-data requires the full 64-character checkpoint identity")
		}
		boundaries, err := store.ReleaseBoundaries(ctx, in.App)
		if err != nil {
			return nil, err
		}
		for _, b := range boundaries {
			if b.Snapshot == in.RestoreData && b.PreviousRevision != "" {
				if in.Revision != "" && in.Revision != b.PreviousRevision {
					return nil, errors.New("checkpoint belongs to a different rollback revision")
				}
				in.Revision = b.PreviousRevision
				break
			}
		}
	}
	if in.Revision == "" {
		rev, err = store.RevisionWithStatus(ctx, in.App, state.RevisionPrevious)
		if err != nil {
			return nil, err
		}
		if rev == nil {
			return nil, fmt.Errorf("%s has no previous revision to roll back to", in.App)
		}
	} else {
		rev, err = store.GetRevision(ctx, in.App, in.Revision)
		if err != nil {
			return nil, fmt.Errorf("revision %s of %s: %w", in.Revision, in.App, err)
		}
	}
	if rev.Status == state.RevisionActive && in.RestoreData == "" {
		return nil, fmt.Errorf("%s is already the active revision of %s", rev.ID, in.App)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return nil, err
	}
	unsafe, err := unsafeReleaseBoundaries(ctx, store, rev)
	if err != nil {
		return nil, err
	}
	var checkpoint *state.ReleaseBoundary
	if in.RestoreData != "" {
		if !fullSnapshotID.MatchString(in.RestoreData) {
			return nil, errors.New("--restore-data requires the full 64-character checkpoint identity")
		}
		boundaries, err := store.ReleaseBoundaries(ctx, in.App)
		if err != nil {
			return nil, err
		}
		for i := range boundaries {
			b := &boundaries[i]
			if b.Snapshot == in.RestoreData && b.PreviousRevision == rev.ID {
				checkpoint = b
				break
			}
		}
		if checkpoint == nil {
			return nil, errors.New("checkpoint is not the retained pre-release data for the requested revision")
		}
		if checkpoint.Status == state.ReleaseRestored && len(unsafe) > 0 {
			later := unsafe[0]
			for _, boundary := range unsafe[1:] {
				if boundary.StartedAt.Before(later.StartedAt) {
					later = boundary
				}
			}
			if later.Snapshot != "" {
				return nil, fmt.Errorf("checkpoint %s was already restored; release %s changed data again; review the newer matching checkpoint %s before retrying --restore-data", checkpoint.Snapshot, later.Revision, later.Snapshot)
			}
			return nil, fmt.Errorf("checkpoint %s was already restored; release %s changed data again without a retained checkpoint; recover through a separately verified backup", checkpoint.Snapshot, later.Revision)
		}
		for _, boundary := range unsafe {
			if boundary.StartedAt.Before(checkpoint.StartedAt) {
				return nil, fmt.Errorf("checkpoint %s was captured after unsafe data release %s; choose the checkpoint before the first incompatible transition", checkpoint.Snapshot, boundary.Revision)
			}
		}
	} else {
		if err := checkReleaseStoreAccess(ctx, store, in.App); err != nil {
			return nil, err
		}
		if len(unsafe) > 0 {
			return nil, unsafeRollbackError(in.App, unsafe)
		}
	}
	plan, err := r.Deploy.rollout(ctx, &m, rev.ID, nil)
	if err != nil {
		return nil, err
	}
	if checkpoint != nil {
		plan.Steps = append([]kernel.Step{rollbackCheckpointStep(r.Deploy, rev, *checkpoint)}, plan.Steps...)
	}
	return plan, nil
}

// publicTransport resolves names the way the world does, through a public
// resolver, so a check isn't fooled by the machine's own cache.
func publicTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: edge.PublicResolver}
	return &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 10 * time.Second}
}

// secretsFor returns the values a revision runs with: the current version
// for a deploy, the pinned one for a rollback.
func (d Deploy) secretsFor(rev *state.Revision, pinned bool) (map[string]string, int, error) {
	if pinned {
		values, err := d.Secrets.Load(rev.App, rev.SecretsVersion)
		return values, rev.SecretsVersion, err
	}
	return d.Secrets.LoadCurrent(rev.App)
}

// checkSecrets fails before anything starts when a workload's secrets
// aren't all set.
func checkSecrets(m *manifest.Manifest, values map[string]string) error {
	var missing []string
	for _, name := range m.WorkloadNames() {
		for _, n := range secrets.Missing(values, m.Workloads[name].Secrets) {
			missing = append(missing, fmt.Sprintf("%s (for %s)", n, name))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("secrets not set: %s; set each with helios secret set %s NAME", strings.Join(missing, ", "), m.App)
	}
	return nil
}

func secretsNote(m *manifest.Manifest) string {
	var names []string
	for _, name := range m.WorkloadNames() {
		names = append(names, m.Workloads[name].Secrets...)
	}
	if m.InjectsDatabaseURL() {
		names = append(names, DatabaseURLName)
	}
	if len(names) == 0 {
		return ""
	}
	slices.Sort(names)
	return "secrets: " + strings.Join(slices.Compact(names), ", ")
}

// publishedSummary names the ports a deploy publishes on the machine, for
// the plan: they are reached past the edge, and past ufw, so a plan that
// opens one says so.
func publishedSummary(m *manifest.Manifest) string {
	var parts []string
	for _, p := range m.PublishedPorts() {
		parts = append(parts, fmt.Sprintf("%s for %s", p, p.Workload))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", publishing " + strings.Join(parts, ", ") + " on the machine, past the edge and the firewall (helios doctor lists them)"
}

// checkPublishedPorts refuses a port on the machine that another app's
// running revision already publishes. The app's own active revision is
// not in the way: only singletons publish, and they stop first.
func checkPublishedPorts(ctx context.Context, store *state.Store, m *manifest.Manifest) error {
	mine := m.PublishedPorts()
	if len(mine) == 0 {
		return nil
	}
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return err
	}
	var clashes []string
	for _, rev := range active {
		if rev.App == m.App {
			continue
		}
		var other manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &other); err != nil {
			return fmt.Errorf("revision %s/%s manifest: %w", rev.App, rev.ID, err)
		}
		for _, theirs := range other.PublishedPorts() {
			for _, p := range mine {
				if p.Overlaps(theirs.PublishedPort) {
					clashes = append(clashes, fmt.Sprintf("%s (for %s) is already published by %s's %s", p, p.Workload, rev.App, theirs.Workload))
				}
			}
		}
	}
	if len(clashes) > 0 {
		return fmt.Errorf("%s can't publish what another app on this machine holds: %s", m.App, strings.Join(clashes, "; "))
	}
	return nil
}

func secretsSummary(m *manifest.Manifest) string {
	var parts []string
	if m.PostgresVersion() != "" {
		parts = append(parts, "the database's password")
	}
	if m.HasObjects() {
		parts = append(parts, "the object store's root user")
	}
	if m.Secrets != nil {
		if n := len(m.Secrets.Generate); n > 0 {
			parts = append(parts, fmt.Sprintf("%d generated", n))
		}
		if n := len(m.Secrets.Derive); n > 0 {
			parts = append(parts, fmt.Sprintf("%d derived", n))
		}
	}
	return ": " + strings.Join(parts, ", ")
}

func dataSummary(m *manifest.Manifest) string {
	var parts []string
	if v := m.PostgresVersion(); v != "" {
		parts = append(parts, "postgres "+v)
	}
	if m.HasObjects() {
		parts = append(parts, "object store")
	}
	for _, v := range sortedKeys(m.Data.Volumes) {
		parts = append(parts, "volume "+v)
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, ", ")
}

func restoreNote(r Restore) string {
	var parts []string
	if r.Postgres != "" {
		parts = append(parts, "database from "+r.Postgres)
	}
	for _, v := range sortedKeys(r.Volumes) {
		parts = append(parts, v+" from "+r.Volumes[v])
	}
	if len(parts) == 0 {
		return ""
	}
	return "restore " + strings.Join(parts, "; ")
}

// sortedKeys is a map's keys in order, for output that reads the same way
// every time.
func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

// loomGuard turns the loom integration into the endpoint the edge asks. A
// machine with no such integration gets nil, which is not an error: most
// machines run no Core and have no guarded routes.
func loomGuard(sec *secrets.Store) (*edge.Guard, error) {
	if sec == nil {
		return nil, nil
	}
	l, err := integration.LoadLoom(sec)
	if err != nil || l == nil {
		return nil, nil
	}
	v, err := integration.ParseVerifyURL(l.VerifyURL)
	if err != nil {
		return nil, fmt.Errorf("the loom integration's verify_url: %w", err)
	}
	g := &edge.Guard{
		Dial: v.Dial, Path: v.Path, TLS: v.TLS,
		HeaderName: integration.LoomVerifiedHeader, HeaderValue: integration.LoomVerifiedValue,
	}
	if v.TLS {
		g.ServerName = v.Host
	}
	return g, nil
}
