package manifest

import (
	"fmt"
	"strings"
)

// Scaffold describes an app to write a starting manifest for.
//
// The rendered file is commented, because the point of a scaffold is to
// teach the schema to whoever reads it next. That rules out marshalling a
// Manifest, which would drop every comment, so the YAML is assembled as
// text and then parsed back through Parse before it is returned. A template
// that cannot produce a valid manifest is a bug here, not a mistake by the
// person who ran the command, and it is reported that way.
type Scaffold struct {
	// App is the app's name, and the default for its route's first label.
	App string
	// Kind is the shape of the first workload: web, static, worker or cron.
	Kind Kind
	// Host is the hostname to route to, for web and static.
	Host string
	// Port is the container port a web workload listens on.
	Port int
	// Schedule is when a cron workload runs.
	Schedule string
	// Postgres adds a database. Every workload of an app with one is given
	// DATABASE_URL, so nothing else has to be declared to use it.
	Postgres bool
	// Dir is the directory a static site is served from. Default public.
	Dir string
	// Existing says the source already holds what the kind runs from, a
	// Dockerfile or the site's files, so Next needn't ask for it.
	Existing bool
}

// DefaultPort is what a web workload is assumed to listen on.
const DefaultPort = 8000

// DefaultSchedule runs a cron workload nightly, at an hour when nothing
// else is happening.
const DefaultSchedule = "0 3 * * *"

// Check reports whether the scaffold can be rendered, naming the flag to
// fix rather than the field.
func (s Scaffold) Check() error {
	if !namePattern.MatchString(s.App) {
		return fmt.Errorf("the app name %q must be lowercase letters, digits and hyphens, up to 40 characters", s.App)
	}
	if reservedApps[s.App] {
		return fmt.Errorf("%q is a name helios uses for itself; pick another", s.App)
	}
	switch s.Kind {
	case Web, Static:
		if s.Host == "" {
			return fmt.Errorf("a %s app is reached by a hostname: pass --host, such as --host %s.example.com", s.Kind, s.App)
		}
		if !ValidHost(s.Host) {
			return fmt.Errorf("--host %q isn't a hostname such as %s.example.com", s.Host, s.App)
		}
	case Worker, Cron:
		if s.Host != "" {
			return fmt.Errorf("a %s workload serves no traffic, so it takes no --host", s.Kind)
		}
	case "":
		return fmt.Errorf("--kind is required: web, static, worker or cron")
	default:
		return fmt.Errorf("--kind %q isn't one of web, static, worker, cron", s.Kind)
	}
	if s.Kind == Web && s.Port != 0 && (s.Port < 1 || s.Port > 65535) {
		return fmt.Errorf("--port %d isn't a port number", s.Port)
	}
	if s.Kind != Web && s.Port != 0 {
		return fmt.Errorf("--port is for a web workload; a %s workload listens on nothing", s.Kind)
	}
	if s.Kind != Cron && s.Schedule != "" {
		return fmt.Errorf("--schedule is for a cron workload")
	}
	if s.Dir != "" && (s.Kind != Static || strings.HasPrefix(s.Dir, "/") || strings.Contains(s.Dir, "..")) {
		return fmt.Errorf("--dir %q must be a directory inside a static site's source", s.Dir)
	}
	if s.Schedule != "" {
		if _, err := ParseSchedule(s.Schedule); err != nil {
			return fmt.Errorf("--schedule: %w", err)
		}
	}
	return nil
}

// Render writes the manifest. The result is guaranteed to parse and
// validate; see the note on Scaffold.
func (s Scaffold) Render() ([]byte, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	r := &rendering{s: s}
	r.header()
	switch s.Kind {
	case Static:
		r.static()
	case Web:
		r.web()
	case Worker:
		r.worker()
	case Cron:
		r.cron()
	}
	if s.Postgres {
		r.release()
		r.data()
	}
	if s.Host != "" {
		r.checks()
	}
	out := []byte(r.b.String())
	if _, err := Parse(out); err != nil {
		return nil, fmt.Errorf("the generated manifest is not valid, which is a bug in helios: %w", err)
	}
	return out, nil
}

// rendering is a scaffold being written, one section per method.
type rendering struct {
	s Scaffold
	b strings.Builder
}

func (r *rendering) w(format string, args ...any) { fmt.Fprintf(&r.b, format, args...) }

func (r *rendering) header() {
	r.w("# %s, as helios deploys it.\n", r.s.App)
	r.w("#\n")
	r.w("# Anything left out takes its default, and the defaults are the safe\n")
	r.w("# ones: a read-only root, no capabilities, a non-root user. Run\n")
	r.w("# `helios deploy` from the directory holding this file.\n")
	r.w("app: %s\n", r.s.App)
	r.w("description: What this app is\n")
	r.w("owner: personal\n")
	r.w("\n")
	r.w("workloads:\n")
}

func (r *rendering) static() {
	dir := r.s.Dir
	if dir == "" {
		dir = "public"
	}
	r.w("  # A static workload serves files straight from the source. It has\n")
	r.w("  # no image and no port; the edge serves the directory itself.\n")
	r.w("  pages:\n")
	r.w("    kind: static\n")
	r.w("    dir: %q\n", dir)
	r.w("    routes:\n")
	r.w("      - host: %s\n", r.s.Host)
}

func (r *rendering) web() {
	port := r.s.Port
	if port == 0 {
		port = DefaultPort
	}
	r.w("  web:\n")
	r.w("    kind: web\n")
	r.w("    # Built from ./Dockerfile. To deploy an image that is already\n")
	r.w("    # published, drop `build` and give `image: registry/name:tag`.\n")
	r.w("    build:\n")
	r.w("      context: .\n")
	r.w("    # The port the process listens on inside the container.\n")
	r.w("    port: %d\n", port)
	r.w("    routes:\n")
	r.w("      - host: %s\n", r.s.Host)
	r.w("    # Until this answers 200 the new revision is never given traffic,\n")
	r.w("    # and a deploy that cannot pass it rolls back on its own.\n")
	r.w("    health:\n")
	r.w("      path: /healthz\n")
	r.w("    resources:\n")
	r.w("      memory: 512m\n")
}

func (r *rendering) worker() {
	r.w("  # A worker runs without listening, so it has no port and no routes.\n")
	r.w("  worker:\n")
	r.w("    kind: worker\n")
	r.w("    build:\n")
	r.w("      context: .\n")
	r.w("    # Without a command the image's own CMD runs.\n")
	r.w("    # command: [./app, worker]\n")
	r.w("    #\n")
	r.w("    # singleton keeps the old copy from overlapping the new one\n")
	r.w("    # during a deploy, for work that must not run twice at once.\n")
	r.w("    # singleton: true\n")
	r.w("    resources:\n")
	r.w("      memory: 512m\n")
}

func (r *rendering) cron() {
	schedule := r.s.Schedule
	if schedule == "" {
		schedule = DefaultSchedule
	}
	r.w("  # A cron workload runs its command on a schedule and exits. It is\n")
	r.w("  # never given traffic, so it has no port and no routes.\n")
	r.w("  job:\n")
	r.w("    kind: cron\n")
	r.w("    build:\n")
	r.w("      context: .\n")
	r.w("    schedule: %q\n", schedule)
	r.w("    # A run that outlives its timeout is stopped and recorded failed.\n")
	r.w("    timeout: 30m\n")
	r.w("    # command: [./app, nightly]\n")
	r.w("    resources:\n")
	r.w("      memory: 512m\n")
}

func (r *rendering) release() {
	r.w("\n")
	r.w("  # A release workload runs once per deploy, after the database is up\n")
	r.w("  # and before the new revision starts. This is where migrations go.\n")
	r.w("  # It is commented out because only you know the command; a release\n")
	r.w("  # step that runs the wrong thing runs it on every single deploy.\n")
	r.w("  #\n")
	r.w("  # migrate:\n")
	r.w("  #   kind: release\n")
	r.w("  #   order: 1\n")
	r.w("  #   build:\n")
	r.w("  #     context: .\n")
	r.w("  #   command: [./app, migrate]\n")
	r.w("  #   timeout: 5m\n")
}

func (r *rendering) data() {
	r.w("\n")
	r.w("data:\n")
	r.w("  # Every workload above is given DATABASE_URL pointing here, so\n")
	r.w("  # nothing else needs declaring to use it. helios generates the\n")
	r.w("  # password, seals it, and never writes it to a log or a receipt.\n")
	r.w("  postgres:\n")
	r.w("    version: \"17\"\n")
	r.w("\n")
	r.w("backup:\n")
	r.w("  # An app with data is backed up nightly by default, with a weekly\n")
	r.w("  # drill that restores it somewhere safe to prove it opens.\n")
	r.w("  #\n")
	r.w("  # A verify query makes a backup prove it holds real rows before it\n")
	r.w("  # counts. Point it at a table that is never legitimately empty.\n")
	r.w("  #\n")
	r.w("  # verify:\n")
	r.w("  #   sql: select count(*) from users\n")
	r.w("  #   at_least: 1\n")
}

func (r *rendering) checks() {
	r.w("\n")
	r.w("# Checked after the deploy. A failure here rolls the deploy back.\n")
	r.w("checks:\n")
	r.w("  - url: https://%s/\n", r.s.Host)
}

// Next says what the person still has to supply, in the order they will
// need it. An empty result means the app is ready to deploy as written.
func (s Scaffold) Next() []string {
	var next []string
	switch {
	case s.Existing:
	case s.Kind == Static:
		dir := s.Dir
		if dir == "" {
			dir = "public"
		}
		next = append(next, "put the site's files in ./"+dir)
	default:
		next = append(next, "write a ./Dockerfile that builds the app")
	}
	if s.Kind == Web {
		next = append(next, fmt.Sprintf("serve /healthz, or drop the health block from %s", FileName))
	}
	if s.Postgres {
		next = append(next, "read DATABASE_URL from the environment; helios sets it")
	}
	if s.Host != "" {
		next = append(next, fmt.Sprintf("point %s at this machine, or let helios write the DNS record", s.Host))
	}
	return next
}
