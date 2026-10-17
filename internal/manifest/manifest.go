// Package manifest is the one file an app needs: what it runs, where it is
// reached, how it is checked, and what it may use. helios.yaml lives in the
// app's repository.
package manifest

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

// FileName is the manifest's name in an app's repository.
const FileName = "helios.yaml"

// LegacyFileName remains readable while consuming repositories migrate.
const LegacyFileName = "bedrock.yaml"

// Manifest describes one app.
type Manifest struct {
	// App is the app's name: lowercase letters, digits and hyphens.
	App string `yaml:"app" json:"app"`
	// Description is one line about what the app is for.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Owner is who the app belongs to, such as personal or braintreelabs.
	Owner string `yaml:"owner,omitempty" json:"owner,omitempty"`
	// Repo is where the source lives.
	Repo string `yaml:"repo,omitempty" json:"repo,omitempty"`
	// Workloads are the containers the app runs, by name.
	Workloads map[string]Workload `yaml:"workloads" json:"workloads"`
	// Checks run after every deploy and again as health.
	Checks []Check `yaml:"checks,omitempty" json:"checks,omitempty"`
	// Data is what the app keeps: a database and named volumes.
	Data *Data `yaml:"data,omitempty" json:"data,omitempty"`
	// Backup says when the data is backed up and drilled. An app with data
	// is backed up nightly and drilled weekly unless this says otherwise.
	Backup *Backup `yaml:"backup,omitempty" json:"backup,omitempty"`
	// Release states whether older code may use data changed by release jobs.
	Release *ReleasePolicy `yaml:"release,omitempty" json:"release,omitempty"`
	// Secrets are the ones helios makes for the app, so nobody has to type
	// them in: generated once and kept, or derived from others at every
	// deploy.
	Secrets *Secrets `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	// Preview marks the app as a branch's preview of another app. helios
	// preview up writes it into the manifest it derives; nobody writes it
	// by hand. It is how a preview is known, whatever its name.
	Preview *Preview `yaml:"preview,omitempty" json:"preview,omitempty"`
}

// ReleasePolicy declares a data contract, not an automatic SQL rollback.
type ReleasePolicy struct {
	DataCompatibility string `yaml:"data_compatibility" json:"data_compatibility"`
}

const (
	DataBackwardCompatible   = "backward-compatible"
	DataRestoreRequired      = "restore-required"
	DataCompatibilityUnknown = "unknown"
)

// ReleaseCompatibility is conservative when an app has not declared a policy.
func (m *Manifest) ReleaseCompatibility() string {
	if m.Release == nil {
		return DataCompatibilityUnknown
	}
	return m.Release.DataCompatibility
}

// Preview says which app, and which branch of it, an app previews.
type Preview struct {
	Of     string `yaml:"of" json:"of"`
	Branch string `yaml:"branch" json:"branch"`
	// Pinned previews are retained by preview prune until explicitly unpinned.
	Pinned bool `yaml:"pinned,omitempty" json:"pinned,omitempty"`
}

// Secrets helios makes for an app.
type Secrets struct {
	// Generate makes each named secret once, when it doesn't exist yet,
	// in a format: hex:N or base64:N or base64url:N for N random bytes,
	// or value:TEXT for a fixed value such as a user name.
	Generate map[string]string `yaml:"generate,omitempty" json:"generate,omitempty"`
	// Derive computes each named secret from a template at every deploy:
	// {NAME} is another secret, {sha256:NAME} its SHA-256 in hex, and
	// {postgres} and {objects} the hosts of the app's data services.
	Derive map[string]string `yaml:"derive,omitempty" json:"derive,omitempty"`
}

// Backup is an app's backup policy.
type Backup struct {
	// Schedule is a five-field cron schedule, in UTC. Default "0 3 * * *".
	Schedule string `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	// Drill is when the latest backup is restored beside the app and
	// verified. Default "0 4 * * 0", Sunday.
	Drill string `yaml:"drill,omitempty" json:"drill,omitempty"`
	// Keep is how many daily, weekly and monthly backups stay. Default 7,
	// 4 and 6.
	Keep *Keep `yaml:"keep,omitempty" json:"keep,omitempty"`
	// Verify is a query the drill runs on the restored database.
	Verify *Verify `yaml:"verify,omitempty" json:"verify,omitempty"`
	// Off turns backups off for an app whose data isn't worth keeping.
	Off bool `yaml:"off,omitempty" json:"off,omitempty"`
}

// Keep is a retention policy.
type Keep struct {
	Daily   int `yaml:"daily,omitempty" json:"daily,omitempty"`
	Weekly  int `yaml:"weekly,omitempty" json:"weekly,omitempty"`
	Monthly int `yaml:"monthly,omitempty" json:"monthly,omitempty"`
}

// Verify is what a drill checks in the restored database.
type Verify struct {
	// SQL must return one number.
	SQL string `yaml:"sql" json:"sql"`
	// AtLeast is the smallest acceptable result. Default 1.
	AtLeast int `yaml:"at_least,omitempty" json:"at_least,omitempty"`
}

// Defaults for backups.
const (
	DefaultBackupSchedule = "0 3 * * *"
	DefaultDrillSchedule  = "0 4 * * 0"
)

// DefaultKeep is the retention an app gets unless it says otherwise.
var DefaultKeep = Keep{Daily: 7, Weekly: 4, Monthly: 6}

// ReservedApp is the name the machine's own things use, such as the
// integration credentials. No app may take it.
const ReservedApp = "bedrock"

// reservedApps are names whose containers, networks or volumes would
// collide with helios's own: bedrock-edge, bedrock-registry, bedrock-restic-cache.
var reservedApps = map[string]bool{ReservedApp: true, "helios": true, "edge": true, "registry": true, "restic": true}

// DatabaseVolume and ObjectsVolume are the volumes that hold an app's
// database and object store; no declared volume may take their names.
const (
	DatabaseVolume = "postgres"
	ObjectsVolume  = "objects"
)

// Data is an app's state, kept across revisions.
type Data struct {
	// Postgres gives the app its own database. Its URL reaches every
	// workload as DATABASE_URL.
	Postgres *Postgres `yaml:"postgres,omitempty" json:"postgres,omitempty"`
	// Volumes are named directories workloads mount.
	Volumes map[string]Volume `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	// Objects gives the app its own S3-compatible object store (MinIO),
	// reachable at {objects}:9000 with the MINIO_ROOT_USER and
	// MINIO_ROOT_PASSWORD secrets helios makes.
	Objects *Objects `yaml:"objects,omitempty" json:"objects,omitempty"`
}

// Objects configures the app's object store.
type Objects struct {
	// Image replaces helios's pinned MinIO image.
	Image string `yaml:"image,omitempty" json:"image,omitempty"`
}

// Postgres configures the app's database.
type Postgres struct {
	// Version is the major version. Default 16.
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	// Image replaces postgres:<version>-alpine, for an image with
	// extensions such as pgvector. Pin it by digest.
	Image string `yaml:"image,omitempty" json:"image,omitempty"`
	// User is the first superuser; Database the database made with it.
	// Both default to the app's name with underscores.
	User     string `yaml:"user,omitempty" json:"user,omitempty"`
	Database string `yaml:"database,omitempty" json:"database,omitempty"`
	// Init is a file or directory in the source whose .sql and .sh files
	// run once, when the database is first made.
	Init string `yaml:"init,omitempty" json:"init,omitempty"`
	// Env and Secrets reach the database container, for init scripts.
	Env     map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets []string          `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	// DatabaseURL false keeps helios from giving every workload
	// DATABASE_URL, the superuser's address: for an app whose workloads
	// each get a role of their own through derived secrets.
	DatabaseURL *bool `yaml:"database_url,omitempty" json:"database_url,omitempty"`
}

// Volume is a named directory an app keeps.
type Volume struct {
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Mount puts a volume in a workload.
type Mount struct {
	Volume string `yaml:"volume" json:"volume"`
	Path   string `yaml:"path" json:"path"`
}

// Kind is what a workload is.
type Kind string

const (
	// Web serves HTTP on a port and gets routes.
	Web Kind = "web"
	// Static serves files from a directory in the source, and gets routes.
	Static Kind = "static"
	// Worker runs without listening.
	Worker Kind = "worker"
	// Cron runs its command on a schedule and exits.
	Cron Kind = "cron"
	// Release runs its command once at every deploy, after the data is
	// up and before the new revision starts, such as a migration. A
	// failure stops the deploy.
	Release Kind = "release"
)

// Workload is one container the app runs.
type Workload struct {
	Kind Kind `yaml:"kind" json:"kind"`
	// Image is a pulled image reference, when the workload isn't built here.
	Image string `yaml:"image,omitempty" json:"image,omitempty"`
	// Build says how to build the image from the source.
	Build *Build `yaml:"build,omitempty" json:"build,omitempty"`
	// Dir is the directory to serve, for a static workload.
	Dir string `yaml:"dir,omitempty" json:"dir,omitempty"`
	// Port is the container port a web workload listens on.
	Port int `yaml:"port,omitempty" json:"port,omitempty"`
	// Routes are the hostnames and paths that reach this workload.
	Routes []Route `yaml:"routes,omitempty" json:"routes,omitempty"`
	// Env is plain configuration. Secrets are named in Secrets instead.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	// Secrets are the names of secrets the workload needs.
	Secrets []string `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	// Command replaces the image's command.
	Command []string `yaml:"command,omitempty" json:"command,omitempty"`
	// Health is how helios knows the workload is ready.
	Health *Health `yaml:"health,omitempty" json:"health,omitempty"`
	// Resources bound what the workload may use.
	Resources Resources `yaml:"resources,omitempty" json:"resources,omitempty"`
	// Mounts put the app's volumes in this workload.
	Mounts []Mount `yaml:"mounts,omitempty" json:"mounts,omitempty"`
	// Schedule is a cron workload's five-field schedule, in UTC.
	Schedule string `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	// Timeout is how long a cron run may take. Default 1h.
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// User runs the container as this user (uid, name or uid:gid) instead
	// of the image's own.
	User string `yaml:"user,omitempty" json:"user,omitempty"`
	// Privileged keeps every capability and lets the container gain
	// privileges: for a workload that runs other containers, such as
	// Loom's Runner. Everything else runs with no capabilities and can't
	// gain any.
	Privileged bool `yaml:"privileged,omitempty" json:"privileged,omitempty"`
	// Capabilities are the kernel capabilities to keep, such as
	// NET_BIND_SERVICE, when an image needs a few. Every other one is
	// dropped.
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	// WritableRoot lets the workload write to its root filesystem. By
	// default it is read-only, with /tmp in memory.
	WritableRoot bool `yaml:"writable_root,omitempty" json:"writable_root,omitempty"`
	// Tmpfs are more paths the workload may write to, kept in memory, such
	// as a framework's cache directory.
	Tmpfs []string `yaml:"tmpfs,omitempty" json:"tmpfs,omitempty"`
	// Aliases are more names the workload answers to on the app's own
	// network; its workload name always is one.
	Aliases []string `yaml:"aliases,omitempty" json:"aliases,omitempty"`
	// Order sorts release workloads; lower runs first, then by name.
	Order int `yaml:"order,omitempty" json:"order,omitempty"`
	// Grace is how long the workload gets to stop before it is killed.
	// Default 10s.
	Grace string `yaml:"grace,omitempty" json:"grace,omitempty"`
	// Singleton workloads never run twice at once: a deploy stops the old
	// container before it starts the new one, and starts the old one
	// again if the deploy fails. For a workload that owns state no second
	// copy may share, such as a lock-holding worker or a SQLite file.
	Singleton bool `yaml:"singleton,omitempty" json:"singleton,omitempty"`
	// Ports are published on the machine itself, past the edge, for
	// traffic that isn't HTTP on a hostname, such as STUN on 3478/udp. A
	// workload that publishes one must be a singleton.
	Ports []PublishedPort `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// PublishedPort is one of a workload's ports reached directly on the
// machine's own address rather than through the edge.
type PublishedPort struct {
	// Port is the container port.
	Port int `yaml:"port" json:"port"`
	// Protocol is tcp (the default) or udp.
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	// HostPort is the machine's port. Default the container port.
	HostPort int `yaml:"host_port,omitempty" json:"host_port,omitempty"`
	// Address is the machine address to listen on. Default every one.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
}

// Proto is the port's protocol with its default applied.
func (p PublishedPort) Proto() string {
	if p.Protocol == "" {
		return "tcp"
	}
	return p.Protocol
}

// OnHost is the machine's port with its default applied.
func (p PublishedPort) OnHost() int {
	if p.HostPort == 0 {
		return p.Port
	}
	return p.HostPort
}

// String is the port as the machine sees it, such as 3478/udp or
// 127.0.0.1:8443/tcp.
func (p PublishedPort) String() string {
	port := fmt.Sprintf("%d/%s", p.OnHost(), p.Proto())
	if p.Address == "" {
		return port
	}
	return net.JoinHostPort(p.Address, port)
}

// Overlaps reports whether two ports would claim the same socket on the
// machine: the same port and protocol, on the same address or where
// either listens on every address.
func (p PublishedPort) Overlaps(o PublishedPort) bool {
	if p.OnHost() != o.OnHost() || p.Proto() != o.Proto() {
		return false
	}
	if p.Address == "" || o.Address == "" {
		return true
	}
	a, errA := netip.ParseAddr(p.Address)
	b, errB := netip.ParseAddr(o.Address)
	if errA != nil || errB != nil {
		return true
	}
	return a == b || a.IsUnspecified() || b.IsUnspecified()
}

// reservedHostPorts are the machine's own: ssh, the edge on 80 and 443
// (443 over UDP too, for HTTP/3), and the image registry on 5000, which
// is docker.Registry.
var reservedHostPorts = map[int]string{22: "ssh", 80: "the edge", 443: "the edge", 5000: "helios's image registry"}

// Build says how to build a workload's image.
type Build struct {
	// Context is the build directory, relative to the source. Default ".".
	Context string `yaml:"context,omitempty" json:"context,omitempty"`
	// Dockerfile is relative to the context. Default "Dockerfile".
	Dockerfile string `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	// Target is a stage in a multi-stage Dockerfile.
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
	// Args are build arguments.
	Args map[string]string `yaml:"args,omitempty" json:"args,omitempty"`
}

// Route is one way in from the edge.
type Route struct {
	Host string `yaml:"host" json:"host"`
	// Path is a prefix; "/" (the default) takes everything not claimed by
	// a longer prefix on the same host.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Port sends the route to another port of the workload than its own,
	// for a workload that listens on two.
	Port int `yaml:"port,omitempty" json:"port,omitempty"`
	// DNS says whether helios keeps the host's record in Cloudflare:
	// "direct" makes a record that names this machine, "proxied" one
	// behind Cloudflare's proxy. Empty leaves the record alone and only
	// checks that it points here.
	DNS DNSMode `yaml:"dns,omitempty" json:"dns,omitempty"`
	// Auth puts a sign-in in front of the route, so the app behind it never
	// sees a request from someone who is not signed in and needs no auth
	// code of its own. Empty leaves the route open.
	Auth AuthMode `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// AuthMode is who may reach a route.
type AuthMode string

const (
	// AuthNone is a route anyone can reach, which is the default.
	AuthNone AuthMode = ""
	// AuthLoom asks a Loom Core whether the request carries a signed-in
	// session, and passes it through only when it does. The edge asks on
	// every request, so signing out takes effect at once.
	AuthLoom AuthMode = "loom"
)

// Guarded reports whether a route is behind a sign-in.
func (a AuthMode) Guarded() bool { return a == AuthLoom }

// DNSMode is how a route's record is kept.
type DNSMode string

const (
	// DNSManual leaves the record to the person; the deploy checks it.
	DNSManual DNSMode = ""
	// DNSDirect keeps a record that points straight at the machine.
	DNSDirect DNSMode = "direct"
	// DNSProxied keeps a record behind Cloudflare's proxy.
	DNSProxied DNSMode = "proxied"
)

// Managed reports whether helios keeps the record.
func (m DNSMode) Managed() bool { return m == DNSDirect || m == DNSProxied }

// Health is how a workload says it is ready.
type Health struct {
	// Path is an HTTP path that must answer 2xx or 3xx. Empty means the
	// port only has to accept a connection.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Timeout is how long to wait for readiness, as a Go duration. Default 60s.
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// Command is run inside the container instead; exit 0 means ready.
	// It is how a worker, which has no port, says it is ready.
	Command []string `yaml:"command,omitempty" json:"command,omitempty"`
}

// Resources bound a workload.
type Resources struct {
	// Memory is a limit such as 512m or 2g.
	Memory string `yaml:"memory,omitempty" json:"memory,omitempty"`
	// CPUs is a limit such as 1 or 0.5.
	CPUs float64 `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	// Pids bounds the processes. Default 4096.
	Pids int64 `yaml:"pids,omitempty" json:"pids,omitempty"`
}

// Check is a URL that must answer a certain way after a deploy.
type Check struct {
	URL string `yaml:"url" json:"url"`
	// Context limits this check to the application before activation or the
	// public edge afterwards. Empty checks both; guarded routes check the
	// application directly and verify anonymous denial separately.
	Context CheckContext `yaml:"context,omitempty" json:"context,omitempty"`
	// HeadersFromSecrets maps request headers to app secret names. Values
	// are resolved only when an explicit edge check runs, never recorded.
	HeadersFromSecrets map[string]string `yaml:"headers_from_secrets,omitempty" json:"headers_from_secrets,omitempty"`
	// Status is the expected code. Default 200.
	Status int `yaml:"status,omitempty" json:"status,omitempty"`
	// Contains is text the body must include.
	Contains string `yaml:"contains,omitempty" json:"contains,omitempty"`
	// Within is the longest acceptable response time, as a Go duration.
	Within string `yaml:"within,omitempty" json:"within,omitempty"`
}

// CheckContext is where a verification assertion runs.
type CheckContext string

const (
	CheckApplication CheckContext = "application"
	CheckEdge        CheckContext = "edge"
)

// ValidCheckHeader excludes HTTP routing and proxy-control headers.
func ValidCheckHeader(name string) bool {
	if name == "" {
		return false
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", ch)) {
			return false
		}
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "proxy-authenticate", "keep-alive", "te", "trailer", "upgrade", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-for", "x-forwarded-uri", "x-forwarded-method", "x-real-ip":
		return false
	}
	return true
}

var (
	namePattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
	hostPattern    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	envPattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	sizePattern    = regexp.MustCompile(`^[0-9]+[kmg]$`)
	capPattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	pgIdentPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	userPattern    = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]*(:[a-z0-9_][a-z0-9_-]*)?$`)
)

// Parse reads a manifest from YAML and validates it.
func Parse(data []byte) (*Manifest, error) {
	return parseNamed(data, FileName)
}

func parseNamed(data []byte, name string) (*Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s must contain exactly one YAML document", name)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Load reads dir/helios.yaml.
func Load(dir string) (*Manifest, error) {
	return LoadFile(dir, "")
}

// LoadFile reads a manifest by name from a source directory, for a source
// that holds several apps, such as a product and the worker it runs apart.
// The name is a plain YAML file at the source's root; it is read as root, so
// it must be the source's own file, never a link out of it.
func LoadFile(dir, name string) (*Manifest, error) {
	var err error
	name, err = ResolveFileName(dir, name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a plain file, not a link", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseNamed(data, name)
}

// ResolveFileName selects the sole default manifest, or preserves an explicit
// filename. Lstat counts links and directories as present so an unsafe default
// cannot be silently bypassed in favor of the other name. The reader validates
// the selected file before reading it. An empty source selects the new name.
func ResolveFileName(dir, name string) (string, error) {
	if name != "" {
		return name, CheckFileName(name)
	}
	var found string
	for _, candidate := range []string{FileName, LegacyFileName} {
		if _, err := os.Lstat(filepath.Join(dir, candidate)); err == nil {
			if found != "" {
				return "", fmt.Errorf("both %s and %s exist; select one explicitly with --manifest", FileName, LegacyFileName)
			}
			found = candidate
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	if found == "" {
		found = FileName
	}
	return found, nil
}

// CheckFileName refuses a manifest name that isn't a plain .yaml or .yml
// file at a source's root.
func CheckFileName(name string) error {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") ||
		!(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
		return fmt.Errorf("%q must name a .yaml file at the source's root, such as helios.worker.yaml", name)
	}
	return nil
}

// Validate checks a manifest. The errors name the field in the person's
// own terms.
func (m *Manifest) Validate() error {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if !namePattern.MatchString(m.App) {
		fail("app: %q must be lowercase letters, digits and hyphens, up to 40 characters", m.App)
	} else if reservedApps[m.App] {
		fail("app: %q is a name helios uses for itself", m.App)
	}
	if len(m.Workloads) == 0 {
		fail("workloads: an app needs at least one")
	}
	claimed := map[string]string{}   // host+path -> workload
	names := map[string]string{}     // workload names and aliases -> workload
	published := map[string]string{} // host port/protocol -> workload
	for name := range m.Workloads {
		names[name] = name
	}
	for _, name := range m.WorkloadNames() {
		m.validateWorkload(name, claimed, names, published, fail)
	}
	m.validateDNSModes(fail)
	m.validateData(fail)
	m.validateSecrets(fail)
	m.validateBackup(fail)
	if m.Release != nil {
		switch m.Release.DataCompatibility {
		case DataBackwardCompatible, DataRestoreRequired:
		default:
			fail("release.data_compatibility: use backward-compatible or restore-required")
		}
		if len(m.ReleaseWorkloads()) == 0 {
			fail("release: requires at least one release workload")
		}
	}
	m.validatePreview(fail)
	m.validateChecks(fail)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// validateWorkload checks one workload. claimed maps each host and path
// to the workload routing it, names each name and alias to its workload,
// and published each port and protocol on the machine to its workload.
func (m *Manifest) validateWorkload(name string, claimed, names, published map[string]string, fail func(format string, args ...any)) {
	w := m.Workloads[name]
	at := "workloads." + name
	validateShape(at, name, w, fail)
	validatePorts(at, name, w, published, fail)
	m.validateNames(at, name, w, names, fail)
	validateRoutes(at, name, w, claimed, fail)
	validateIsolation(at, w, fail)
}

// validateShape checks what a workload is: its kind and what the kind
// allows, its schedule, timeouts, grace and bounds.
func validateShape(at, name string, w Workload, fail func(format string, args ...any)) {
	if !namePattern.MatchString(name) {
		fail("%s: the name must be lowercase letters, digits and hyphens", at)
	}
	switch w.Kind {
	case Web, Worker, Cron, Release:
		if (w.Image == "") == (w.Build == nil) {
			fail("%s: give either image or build", at)
		}
		if w.Dir != "" {
			fail("%s: dir is for static workloads", at)
		}
	case Static:
		if w.Dir == "" {
			fail("%s: a static workload needs dir, the directory to serve", at)
		}
		if w.Image != "" || w.Build != nil || w.Port != 0 {
			fail("%s: a static workload has dir only, no image, build or port", at)
		}
	case "":
		fail("%s: kind is required: web, static, worker, cron or release", at)
	default:
		fail("%s: kind %q isn't one of web, static, worker, cron, release", at, w.Kind)
	}
	if w.Kind == Release {
		if len(w.Routes) > 0 || w.Port != 0 || w.Schedule != "" {
			fail("%s: a release workload runs once per deploy; it has no routes, port or schedule", at)
		}
	} else if w.Order != 0 {
		fail("%s: order is for release workloads", at)
	}
	if w.Kind == Cron {
		if w.Schedule == "" {
			fail("%s: a cron workload needs schedule, five fields such as \"0 3 * * *\"", at)
		} else if _, err := ParseSchedule(w.Schedule); err != nil {
			fail("%s.schedule: %v", at, err)
		}
		if len(w.Routes) > 0 || w.Port != 0 {
			fail("%s: a cron workload has no routes or port", at)
		}
		if w.Timeout != "" {
			if _, err := time.ParseDuration(w.Timeout); err != nil {
				fail("%s.timeout: %q isn't a duration such as 30m", at, w.Timeout)
			}
		}
	} else if w.Schedule != "" {
		fail("%s: schedule is for cron workloads", at)
	} else if w.Timeout != "" && w.Kind != Release {
		fail("%s: timeout is for cron and release workloads", at)
	} else if w.Timeout != "" {
		if _, err := time.ParseDuration(w.Timeout); err != nil {
			fail("%s.timeout: %q isn't a duration such as 10m", at, w.Timeout)
		}
	}
	if w.Singleton && w.Kind != Web && w.Kind != Worker {
		fail("%s: singleton is for web and worker workloads", at)
	}
	if w.Grace != "" {
		if d, err := time.ParseDuration(w.Grace); err != nil || d < time.Second || d > 10*time.Minute {
			fail("%s.grace: %q must be a duration from 1s to 10m", at, w.Grace)
		}
	}
	if w.Resources.Pids != 0 && (w.Resources.Pids < 16 || w.Resources.Pids > 1<<20) {
		fail("%s.resources.pids: must be 16 or more", at)
	}
}

// validatePorts checks the ports a workload publishes on the machine.
// published maps each port and protocol already published in the app,
// by the workloads before this one, to the workload publishing it.
func validatePorts(at, name string, w Workload, published map[string]string, fail func(format string, args ...any)) {
	if len(w.Ports) > 0 {
		if w.Kind != Web && w.Kind != Worker {
			fail("%s.ports: only web and worker workloads publish ports", at)
		} else if !w.Singleton {
			// A deploy starts the new revision beside the old, and two
			// containers cannot hold one port on the machine.
			fail("%s.ports: a workload that publishes a port must be singleton: true, so the old container lets go of the port before the new one takes it", at)
		}
	}
	for i, p := range w.Ports {
		pa := fmt.Sprintf("%s.ports[%d]", at, i)
		if p.Port < 1 || p.Port > 65535 {
			fail("%s.port: must be a port number, 1 to 65535", pa)
		}
		if p.HostPort != 0 && (p.HostPort < 1 || p.HostPort > 65535) {
			fail("%s.host_port: must be a port number, 1 to 65535", pa)
		}
		if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			fail("%s.protocol: %q isn't tcp or udp", pa, p.Protocol)
		}
		if p.Address != "" {
			if _, err := netip.ParseAddr(p.Address); err != nil {
				fail("%s.address: %q isn't an IP address; leave it out to listen on every one", pa, p.Address)
			}
		}
		if owner, taken := reservedHostPorts[p.OnHost()]; taken {
			fail("%s: %d on the machine belongs to %s", pa, p.OnHost(), owner)
		}
		key := fmt.Sprintf("%d/%s", p.OnHost(), p.Proto())
		if other, taken := published[key]; taken {
			fail("%s: %s is already published by %s", pa, key, other)
		}
		published[key] = name
	}
}

// validateNames checks a workload's aliases, health command and mounts,
// and that its routes suit its kind.
func (m *Manifest) validateNames(at, name string, w Workload, names map[string]string, fail func(format string, args ...any)) {
	for _, a := range w.Aliases {
		if !namePattern.MatchString(a) {
			fail("%s.aliases: %q must be lowercase letters, digits and hyphens", at, a)
		}
		if other, taken := names[a]; taken && other != name {
			fail("%s.aliases: %q is already %s's name", at, a, other)
		}
		names[a] = name
	}
	if h := w.Health; h != nil && len(h.Command) > 0 {
		if h.Path != "" {
			fail("%s.health: give a path or a command, not both", at)
		}
		for _, c := range h.Command {
			if c == "" {
				fail("%s.health.command: an argument is empty", at)
			}
		}
	}
	if h := w.Health; h != nil && h.Timeout != "" {
		if d, err := time.ParseDuration(h.Timeout); err != nil || d <= 0 {
			fail("%s.health.timeout: %q isn't a duration such as 90s", at, h.Timeout)
		}
	}
	for i, mt := range w.Mounts {
		ma := fmt.Sprintf("%s.mounts[%d]", at, i)
		if m.Data == nil || m.Data.Volumes == nil {
			fail("%s: volume %q isn't declared under data.volumes", ma, mt.Volume)
		} else if _, ok := m.Data.Volumes[mt.Volume]; !ok {
			fail("%s: volume %q isn't declared under data.volumes", ma, mt.Volume)
		}
		if !strings.HasPrefix(mt.Path, "/") {
			fail("%s: path must be absolute", ma)
		}
	}
	if w.Kind == Web {
		if w.Port < 1 || w.Port > 65535 {
			fail("%s: a web workload needs port, the container port it listens on", at)
		}
		if len(w.Routes) == 0 {
			fail("%s: a web workload needs at least one route", at)
		}
	}
	if w.Kind == Static && len(w.Routes) == 0 {
		fail("%s: a static workload needs at least one route", at)
	}
	if w.Kind == Worker && len(w.Routes) > 0 {
		fail("%s: a worker has no routes", at)
	}
}

// validateRoutes checks a workload's routes, and that no host and path
// is routed twice.
func validateRoutes(at, name string, w Workload, claimed map[string]string, fail func(format string, args ...any)) {
	for i, r := range w.Routes {
		ra := fmt.Sprintf("%s.routes[%d]", at, i)
		if !hostPattern.MatchString(r.Host) {
			fail("%s: host %q isn't a hostname", ra, r.Host)
		}
		path := r.Path
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "*") {
			fail("%s: path %q must start with / and is a prefix, without wildcards", ra, r.Path)
		}
		key := r.Host + " " + path
		if other, taken := claimed[key]; taken {
			fail("%s: %s %s is already routed to %s", ra, r.Host, path, other)
		}
		claimed[key] = name
		switch r.DNS {
		case DNSManual, DNSDirect, DNSProxied:
		default:
			fail("%s.dns: %q isn't direct or proxied", ra, r.DNS)
		}
		switch r.Auth {
		case AuthNone, AuthLoom:
		default:
			fail("%s.auth: %q isn't loom", ra, r.Auth)
		}
		if r.Port != 0 && (r.Port < 1 || r.Port > 65535) {
			fail("%s.port: must be a port number", ra)
		}
		if r.Port != 0 && w.Kind == Static {
			fail("%s.port: a static workload serves on its own port only", ra)
		}
	}
}

// validateIsolation checks what a workload may do and what it is given:
// its user, capabilities, writable paths, environment, secrets and
// resources, and that what it builds or serves is inside the source.
func validateIsolation(at string, w Workload, fail func(format string, args ...any)) {
	if w.User != "" && !userPattern.MatchString(w.User) {
		fail("%s.user: %q must be a user, uid, or user:group", at, w.User)
	}
	for _, c := range w.Capabilities {
		if !capPattern.MatchString(strings.TrimPrefix(strings.ToUpper(c), "CAP_")) {
			fail("%s.capabilities: %q isn't a capability name such as NET_BIND_SERVICE", at, c)
		}
	}
	if w.Privileged && len(w.Capabilities) > 0 {
		fail("%s: a privileged workload keeps every capability already; drop capabilities", at)
	}
	for _, t := range w.Tmpfs {
		if !strings.HasPrefix(t, "/") {
			fail("%s.tmpfs: %q must be an absolute path", at, t)
		}
	}
	for _, k := range sortedKeys(w.Env) {
		if !envPattern.MatchString(k) {
			fail("%s.env: %q must be an UPPER_CASE name", at, k)
		}
	}
	for _, s := range w.Secrets {
		if !envPattern.MatchString(s) {
			fail("%s.secrets: %q must be an UPPER_CASE name", at, s)
		}
		if _, both := w.Env[s]; both {
			fail("%s: %s is both a secret and a plain env value", at, s)
		}
	}
	if _, err := ParseMemory(w.Resources.Memory); err != nil {
		fail("%s.resources.memory: %v", at, err)
	}
	if math.IsNaN(w.Resources.CPUs) || math.IsInf(w.Resources.CPUs, 0) || w.Resources.CPUs < 0 || w.Resources.CPUs > 64 {
		fail("%s.resources.cpus: must be 0 to 64", at)
	}
	if w.Health != nil && w.Health.Path != "" && !strings.HasPrefix(w.Health.Path, "/") {
		fail("%s.health.path: must start with /", at)
	}
	if w.Build != nil && (strings.HasPrefix(w.Build.Context, "/") || strings.Contains(w.Build.Context, "..")) {
		fail("%s.build.context: must be inside the source", at)
	}
	if w.Build != nil && w.Build.Dockerfile != "" && (!filepath.IsLocal(w.Build.Dockerfile) || strings.ContainsRune(w.Build.Dockerfile, '\x00')) {
		fail("%s.build.dockerfile: must be relative to its build context and stay inside it", at)
	}
	if w.Dir != "" && (strings.HasPrefix(w.Dir, "/") || strings.Contains(w.Dir, "..")) {
		fail("%s.dir: must be inside the source", at)
	}
}

// validateDNSModes checks that every route to a host keeps its record
// the same way.
func (m *Manifest) validateDNSModes(fail func(format string, args ...any)) {
	modes := map[string]DNSMode{}
	for _, name := range m.WorkloadNames() {
		for _, r := range m.Workloads[name].Routes {
			if prev, seen := modes[r.Host]; seen && prev != r.DNS {
				fail("routes: %s has dns %q on one route and %q on another; use one", r.Host, prev, r.DNS)
			}
			modes[r.Host] = r.DNS
		}
	}
}

// validateData checks the app's volumes and database.
func (m *Manifest) validateData(fail func(format string, args ...any)) {
	if m.Data != nil {
		for _, name := range sortedKeys(m.Data.Volumes) {
			if !namePattern.MatchString(name) {
				fail("data.volumes: %q must be lowercase letters, digits and hyphens", name)
			}
			if name == DatabaseVolume || name == ObjectsVolume {
				fail("data.volumes: %q is helios's own volume for the %s; pick another name", name, map[string]string{DatabaseVolume: "database", ObjectsVolume: "object store"}[name])
			}
		}
		if pg := m.Data.Postgres; pg != nil {
			switch pg.Version {
			case "", "15", "16", "17", "18":
			default:
				fail("data.postgres.version: %q isn't a supported major version (15 to 18)", pg.Version)
			}
			for _, f := range []struct{ field, v string }{{"user", pg.User}, {"database", pg.Database}} {
				if f.v != "" && !pgIdentPattern.MatchString(f.v) {
					fail("data.postgres.%s: %q must be lowercase letters, digits and underscores", f.field, f.v)
				}
			}
			if pg.Init != "" && (strings.HasPrefix(pg.Init, "/") || strings.Contains(pg.Init, "..")) {
				fail("data.postgres.init: must be inside the source")
			}
			for _, k := range sortedKeys(pg.Env) {
				if !envPattern.MatchString(k) {
					fail("data.postgres.env: %q must be an UPPER_CASE name", k)
				}
			}
			for _, n := range pg.Secrets {
				if !envPattern.MatchString(n) {
					fail("data.postgres.secrets: %q must be an UPPER_CASE name", n)
				}
			}
		}
	}
}

// validateSecrets checks the secrets helios makes and derives.
func (m *Manifest) validateSecrets(fail func(format string, args ...any)) {
	if sec := m.Secrets; sec != nil {
		for _, name := range sortedKeys(sec.Generate) {
			format := sec.Generate[name]
			if !envPattern.MatchString(name) {
				fail("secrets.generate: %q must be an UPPER_CASE name", name)
			}
			if _, err := ParseSecretFormat(format); err != nil {
				fail("secrets.generate.%s: %v", name, err)
			}
			if _, both := sec.Derive[name]; both {
				fail("secrets: %s is both generated and derived", name)
			}
		}
		for _, name := range sortedKeys(sec.Derive) {
			tmpl := sec.Derive[name]
			if !envPattern.MatchString(name) {
				fail("secrets.derive: %q must be an UPPER_CASE name", name)
			}
			if err := checkTemplate(tmpl); err != nil {
				fail("secrets.derive.%s: %v", name, err)
			}
		}
	}
}

// validateBackup checks the backup policy.
func (m *Manifest) validateBackup(fail func(format string, args ...any)) {
	if b := m.Backup; b != nil {
		if !m.HasData() && !b.Off {
			fail("backup: the app keeps no data to back up; declare data first")
		}
		if b.Schedule != "" {
			if _, err := ParseSchedule(b.Schedule); err != nil {
				fail("backup.schedule: %v", err)
			}
		}
		if b.Drill != "" {
			if _, err := ParseSchedule(b.Drill); err != nil {
				fail("backup.drill: %v", err)
			}
		}
		if k := b.Keep; k != nil {
			if k.Daily < 0 || k.Weekly < 0 || k.Monthly < 0 {
				fail("backup.keep: counts can't be negative")
			}
			if k.Daily+k.Weekly+k.Monthly == 0 {
				fail("backup.keep: keep at least one daily, weekly or monthly backup")
			}
		}
		if v := b.Verify; v != nil {
			if strings.TrimSpace(v.SQL) == "" {
				fail("backup.verify: sql is required")
			}
			if m.PostgresVersion() == "" {
				fail("backup.verify: a query needs a database; the app declares none")
			}
			if v.AtLeast < 0 {
				fail("backup.verify.at_least: can't be negative")
			}
		}
	}
}

// validatePreview checks a preview's mark, and that none of its routes
// is open.
func (m *Manifest) validatePreview(fail func(format string, args ...any)) {
	if p := m.Preview; p != nil {
		if !namePattern.MatchString(p.Of) || p.Of == m.App {
			fail("preview.of: %q must name the app this previews", p.Of)
		}
		if strings.TrimSpace(p.Branch) == "" || strings.ContainsAny(p.Branch, "\r\n") {
			fail("preview.branch: must name the branch, on one line")
		}
		// A preview runs its parent's secrets at a hostname anyone can work
		// out from a branch name; one route left open would serve that to
		// everybody.
		for _, name := range m.WorkloadNames() {
			for i, r := range m.Workloads[name].Routes {
				if !r.Auth.Guarded() {
					fail("workloads.%s.routes[%d]: a preview's routes are all behind a sign-in (auth: loom)", name, i)
				}
			}
			// Its parent already holds them, and a branch has no business
			// answering on the machine's own address.
			if len(m.Workloads[name].Ports) > 0 {
				fail("workloads.%s.ports: a preview publishes nothing on the machine; its parent holds the ports", name)
			}
		}
	}
}

// validateChecks checks the checks run after a deploy.
func (m *Manifest) validateChecks(fail func(format string, args ...any)) {
	for i, c := range m.Checks {
		switch c.Context {
		case "", CheckApplication, CheckEdge:
		default:
			fail("checks[%d].context: %q isn't application or edge", i, c.Context)
		}
		u, err := url.Parse(c.URL)
		if err != nil || u.Hostname() == "" {
			fail("checks[%d]: url must name a host", i)
		} else if u.User != nil {
			fail("checks[%d]: credentials belong in headers_from_secrets, not the url", i)
		}
		if len(c.HeadersFromSecrets) > 0 {
			if c.Context != CheckEdge {
				fail("checks[%d].headers_from_secrets: credentials require context: edge", i)
			}
			if u == nil || u.Scheme != "https" {
				fail("checks[%d].headers_from_secrets: credentials require an https url", i)
			}
			seen := map[string]bool{}
			for _, header := range sortedKeys(c.HeadersFromSecrets) {
				if !ValidCheckHeader(header) {
					fail("checks[%d].headers_from_secrets: %q isn't an allowed request header", i, header)
				}
				if seen[strings.ToLower(header)] {
					fail("checks[%d].headers_from_secrets: %q repeats a header with different case", i, header)
				}
				seen[strings.ToLower(header)] = true
				if name := c.HeadersFromSecrets[header]; !envPattern.MatchString(name) {
					fail("checks[%d].headers_from_secrets.%s: %q must be an UPPER_CASE secret name", i, header, name)
				}
			}
		}
		if !strings.HasPrefix(c.URL, "https://") && !strings.HasPrefix(c.URL, "http://") {
			fail("checks[%d]: url must start with https:// or http://", i)
		}
		if c.Status < 0 || c.Status > 599 {
			fail("checks[%d]: status must be an HTTP status", i)
		}
		if c.Within != "" {
			if d, err := time.ParseDuration(c.Within); err != nil || d <= 0 {
				fail("checks[%d].within: %q isn't a duration such as 5s", i, c.Within)
			}
		}
	}
}

// sortedKeys is a map's keys in order, so validation reports problems in
// the same order every time.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// WorkloadNames returns the workload names in a stable order.
func (m *Manifest) WorkloadNames() []string {
	names := make([]string, 0, len(m.Workloads))
	for name := range m.Workloads {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Hosts returns every hostname the app is reached at, in order.
func (m *Manifest) Hosts() []string {
	seen := map[string]bool{}
	var hosts []string
	for _, name := range m.WorkloadNames() {
		for _, r := range m.Workloads[name].Routes {
			if !seen[r.Host] {
				seen[r.Host] = true
				hosts = append(hosts, r.Host)
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}

// NormalizedPath returns a route's path prefix with its default applied
// and a trailing slash, the form routes are matched in.
func (r Route) NormalizedPath() string {
	if r.Path == "" {
		return "/"
	}
	return strings.TrimSuffix(r.Path, "/") + "/"
}

// RouteFor finds the workload that serves a host and path, and the route
// that matched, whose port the request reaches: the route with the
// longest matching prefix wins, as it does at the edge.
func (m *Manifest) RouteFor(host, path string) (string, Workload, Route, bool) {
	if path == "" {
		path = "/"
	}
	probe := strings.TrimSuffix(path, "/") + "/"
	var (
		bestName  string
		bestRoute Route
		bestLen   = -1
	)
	for name, w := range m.Workloads {
		for _, r := range w.Routes {
			if r.Host != host {
				continue
			}
			prefix := r.NormalizedPath()
			if !strings.HasPrefix(probe, prefix) {
				continue
			}
			// Equal prefixes keep the lexical workload order used by the
			// sorted traversal, and the first route within that workload.
			if len(prefix) > bestLen || len(prefix) == bestLen && name < bestName {
				bestName, bestRoute, bestLen = name, r, len(prefix)
			}
		}
	}
	if bestLen < 0 {
		return "", Workload{}, Route{}, false
	}
	return bestName, m.Workloads[bestName], bestRoute, true
}

// ParseSchedule parses a five-field cron schedule.
func ParseSchedule(spec string) (cron.Schedule, error) {
	return cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(spec)
}

// PostgresVersion returns the app's database major version, or "" when it
// has no database.
func (m *Manifest) PostgresVersion() string {
	if m.Data == nil || m.Data.Postgres == nil {
		return ""
	}
	if m.Data.Postgres.Version == "" {
		return "16"
	}
	return m.Data.Postgres.Version
}

// Serves reports whether a workload listens for the edge.
func (w Workload) Serves() bool { return w.Kind == Web || w.Kind == Static }

// LongRunning reports whether a workload stays up between deploys.
func (w Workload) LongRunning() bool { return w.Kind != Cron && w.Kind != Release }

// RoutePort is the container port a route reaches.
func (w Workload) RoutePort(r Route) int {
	if r.Port != 0 {
		return r.Port
	}
	return w.Port
}

// GraceOr returns how long the workload gets to stop.
func (w Workload) GraceOr(fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(w.Grace); err == nil && d > 0 {
		return d
	}
	return fallback
}

// ReleaseWorkloads returns the release workloads in the order they run.
func (m *Manifest) ReleaseWorkloads() []string {
	var names []string
	for _, n := range m.WorkloadNames() {
		if m.Workloads[n].Kind == Release {
			names = append(names, n)
		}
	}
	sort.SliceStable(names, func(i, j int) bool {
		return m.Workloads[names[i]].Order < m.Workloads[names[j]].Order
	})
	return names
}

// PostgresIdentity returns the database's first superuser and database.
func (m *Manifest) PostgresIdentity() (user, database string) {
	base := strings.ReplaceAll(m.App, "-", "_")
	user, database = base, base
	if m.Data != nil && m.Data.Postgres != nil {
		if m.Data.Postgres.User != "" {
			user = m.Data.Postgres.User
		}
		if m.Data.Postgres.Database != "" {
			database = m.Data.Postgres.Database
		}
	}
	return user, database
}

// InjectsDatabaseURL reports whether workloads get DATABASE_URL.
func (m *Manifest) InjectsDatabaseURL() bool {
	if m.PostgresVersion() == "" {
		return false
	}
	pg := m.Data.Postgres
	return pg.DatabaseURL == nil || *pg.DatabaseURL
}

// HasObjects reports whether the app has an object store.
func (m *Manifest) HasObjects() bool { return m.Data != nil && m.Data.Objects != nil }

// HasData reports whether the app keeps a database, an object store or
// volumes.
func (m *Manifest) HasData() bool {
	return m.Data != nil && (m.Data.Postgres != nil || m.Data.Objects != nil || len(m.Data.Volumes) > 0)
}

// DataVolumes names every volume that holds the app's files, sorted: the
// declared ones, and the object store's.
func (m *Manifest) DataVolumes() []string {
	if m.Data == nil {
		return nil
	}
	var names []string
	for name := range m.Data.Volumes {
		names = append(names, name)
	}
	if m.Data.Objects != nil {
		names = append(names, ObjectsVolume)
	}
	sort.Strings(names)
	return names
}

// BackedUp reports whether the app's data gets backed up.
func (m *Manifest) BackedUp() bool {
	return m.HasData() && (m.Backup == nil || !m.Backup.Off)
}

// BackupSchedule returns when backups run, with the default applied.
func (m *Manifest) BackupSchedule() string {
	if m.Backup != nil && m.Backup.Schedule != "" {
		return m.Backup.Schedule
	}
	return DefaultBackupSchedule
}

// DrillSchedule returns when drills run, with the default applied.
func (m *Manifest) DrillSchedule() string {
	if m.Backup != nil && m.Backup.Drill != "" {
		return m.Backup.Drill
	}
	return DefaultDrillSchedule
}

// KeepPolicy returns the retention, with the default applied.
func (m *Manifest) KeepPolicy() Keep {
	if m.Backup != nil && m.Backup.Keep != nil {
		return *m.Backup.Keep
	}
	return DefaultKeep
}

// VerifyQuery returns the drill's query and its threshold, or "" when
// the app declares none.
func (m *Manifest) VerifyQuery() (string, int) {
	if m.Backup == nil || m.Backup.Verify == nil {
		return "", 0
	}
	atLeast := m.Backup.Verify.AtLeast
	if atLeast == 0 {
		atLeast = 1
	}
	return m.Backup.Verify.SQL, atLeast
}

// ManagedHosts returns the hosts whose records helios keeps, with their
// mode, in host order. A host routed twice with different modes is an
// error at validation time, so the first wins here.
func (m *Manifest) ManagedHosts() map[string]DNSMode {
	out := map[string]DNSMode{}
	for _, name := range m.WorkloadNames() {
		for _, r := range m.Workloads[name].Routes {
			if r.DNS.Managed() {
				if _, seen := out[r.Host]; !seen {
					out[r.Host] = r.DNS
				}
			}
		}
	}
	return out
}

// ValidApp reports whether a string could name an app: the manifest's
// rule for a name, and not one helios keeps for itself.
func ValidApp(name string) bool { return namePattern.MatchString(name) && !reservedApps[name] }

// ValidHost reports whether a string is a hostname a route can use, by the
// same rule a manifest is validated against.
func ValidHost(host string) bool { return hostPattern.MatchString(host) }

// GuardedRoutes lists the host and path prefix of every route that asks
// for a sign-in, in the order the workloads are named.
func (m *Manifest) GuardedRoutes() []string {
	var out []string
	for _, name := range m.WorkloadNames() {
		for _, r := range m.Workloads[name].Routes {
			if r.Auth.Guarded() {
				out = append(out, r.Host+r.NormalizedPath())
			}
		}
	}
	return out
}

// Published is one port an app publishes on the machine, and the workload
// that publishes it.
type Published struct {
	Workload string
	PublishedPort
}

// PublishedPorts lists every port the app publishes on the machine, in
// the order the workloads are named.
func (m *Manifest) PublishedPorts() []Published {
	var out []Published
	for _, name := range m.WorkloadNames() {
		for _, p := range m.Workloads[name].Ports {
			out = append(out, Published{Workload: name, PublishedPort: p})
		}
	}
	return out
}

// CapabilityNames returns the capability names to keep, with CAP_ stripped.
func (w Workload) CapabilityNames() []string {
	var out []string
	for _, c := range w.Capabilities {
		out = append(out, strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
	}
	return out
}

// ParseMemory reads a container memory ceiling in binary k, m or g units.
// Empty leaves the default to the caller; explicit limits must be positive
// and fit the signed byte count Docker accepts.
func ParseMemory(size string) (int64, error) {
	if size == "" {
		return 0, nil
	}
	if !sizePattern.MatchString(size) {
		return 0, fmt.Errorf("%q must look like 512m or 2g", size)
	}
	shift := map[byte]uint{'k': 10, 'm': 20, 'g': 30}[size[len(size)-1]]
	n, err := strconv.ParseUint(size[:len(size)-1], 10, 64)
	if err != nil || n == 0 || n > uint64(math.MaxInt64)>>shift {
		return 0, fmt.Errorf("%q must be a positive memory limit within 9223372036854775807 bytes", size)
	}
	return int64(n << shift), nil
}
