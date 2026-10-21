package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/url"
	"strings"

	"github.com/kylebegeman/helios/internal/manifest"
)

// previewSuffix separates a parent app's name from its branch in a
// preview's name. The name is only a name: the manifest's preview block is
// what says an app is a preview.
const previewSuffix = "-pr-"

// maxAppName is what a manifest accepts for an app's name.
const maxAppName = 40

// PreviewOf derives a throwaway copy of an app for one branch.
//
// A preview is an ordinary app in every way that matters: it has its own
// name, its own containers, its own database and its own secrets, and it is
// deployed, backed up against and removed by the same code as anything
// else. What makes it a preview is what this function changes.
//
// Every route is put behind a sign-in, and there is no flag to turn it off.
// A preview is unreleased work at a hostname anyone can work out from a
// branch name, and it runs with the parent's hand-set secrets so it can
// start at all. Either is reason enough; together they make an open
// preview indefensible.
//
// Its database starts empty and is built by whatever the app runs to
// migrate itself, rather than copied from production. A preview is for
// seeing a branch work, and most branches need a schema rather than
// somebody's real rows.
//
// Checks for the parent's own routes keep their assertions at the preview's
// hostname. Application checks and anonymous guard probes are independent,
// so a sign-in never replaces a useful content assertion. Checks for an
// external host or nonstandard public port are reported individually.
//
// Backups are turned off: the database starts empty, and a preview exists
// to be thrown away.
//
// Ports published on the machine are dropped. The parent already holds
// them, so a preview that kept them could never start, and a branch has no
// business answering on the machine's own address anyway.
func PreviewOf(parent *manifest.Manifest, branch, domain string) (*manifest.Manifest, error) {
	preview, _, err := PreviewOfWithReport(parent, branch, domain)
	return preview, err
}

// PreviewCheckSkip explains one assertion that cannot be carried to a preview.
type PreviewCheckSkip struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
}

// PreviewOfWithReport derives a preview and explains unsupported checks.
func PreviewOfWithReport(parent *manifest.Manifest, branch, domain string) (*manifest.Manifest, []PreviewCheckSkip, error) {
	label := DNSLabel(branch)
	if label == "" {
		return nil, nil, fmt.Errorf("%q has nothing in it a hostname can use", branch)
	}
	if !manifest.ValidHost(domain) {
		return nil, nil, fmt.Errorf("%q isn't a domain to put previews under, such as preview.example.com", domain)
	}

	// Nothing is shared with the parent: its manifest is still in use, and
	// nothing here may be rewritten underneath it.
	preview := *parent
	preview.App = previewName(parent.App, branch)
	preview.Description = fmt.Sprintf("Preview of %s at %s", parent.App, branch)
	preview.Preview = &manifest.Preview{Of: parent.App, Branch: branch}
	preview.Checks = nil
	preview.Backup = &manifest.Backup{Off: true}
	if parent.Backup != nil && parent.Backup.Keep != nil {
		keep := *parent.Backup.Keep
		preview.Backup.Keep = &keep
	}
	if parent.Data != nil {
		data := *parent.Data
		if data.Postgres != nil {
			pg := *data.Postgres
			pg.Env, pg.Secrets = maps.Clone(pg.Env), append([]string(nil), pg.Secrets...)
			data.Postgres = &pg
		}
		if data.Objects != nil {
			objects := *data.Objects
			data.Objects = &objects
		}
		data.Volumes = maps.Clone(data.Volumes)
		preview.Data = &data
	}
	if parent.Secrets != nil {
		secrets := *parent.Secrets
		secrets.Generate, secrets.Derive = maps.Clone(secrets.Generate), maps.Clone(secrets.Derive)
		preview.Secrets = &secrets
	}
	preview.Workloads = make(map[string]manifest.Workload, len(parent.Workloads))
	type previewRoute struct {
		workload string
		route    manifest.Route
	}
	claimed := map[string]previewRoute{}
	for _, name := range parent.WorkloadNames() {
		w := parent.Workloads[name]
		copied := w
		copied.Routes = nil
		copied.Ports = nil
		for _, r := range w.Routes {
			host := previewHost(r.Host, branch, domain)
			if !manifest.ValidHost(host) {
				return nil, nil, fmt.Errorf("%s would become %q, which isn't a hostname; use a shorter branch name", r.Host, host)
			}
			route := r
			route.Host = host
			route.Auth = manifest.AuthLoom
			// Cloudflare holds no client certificate for a preview's
			// hostname, so the edge would refuse every connection to it.
			route.OriginPull = manifest.OriginPullOff
			key := host + " " + r.NormalizedPath()
			identity := route
			identity.Path, identity.Port = route.NormalizedPath(), w.RoutePort(route)
			if owner, ok := claimed[key]; ok {
				if owner.workload != name || owner.route != identity {
					return nil, nil, fmt.Errorf("preview routes for workloads %s and %s collide at %s%s; give their original hosts different first labels", owner.workload, name, host, r.NormalizedPath())
				}
				// Equivalent aliases of one workload may share a preview route.
				continue
			}
			claimed[key] = previewRoute{workload: name, route: identity}
			copied.Routes = append(copied.Routes, route)
		}
		preview.Workloads[name] = copied
	}
	var skipped []PreviewCheckSkip
	for _, check := range parent.Checks {
		u, err := url.Parse(check.URL)
		if err != nil || u.Hostname() == "" || u.User != nil {
			skipped = append(skipped, PreviewCheckSkip{URL: check.URL, Reason: "URL is not a supported application URL"})
			continue
		}
		if _, _, _, ok := parent.RouteFor(u.Hostname(), u.Path); !ok {
			skipped = append(skipped, PreviewCheckSkip{URL: check.URL, Reason: "URL does not belong to a route in this app"})
			continue
		}
		if port := u.Port(); port != "" && !(u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80") {
			skipped = append(skipped, PreviewCheckSkip{URL: check.URL, Reason: "nonstandard public port has no preview route"})
			continue
		}
		u.Host = previewHost(u.Hostname(), branch, domain)
		check.URL = u.String()
		check.HeadersFromSecrets = maps.Clone(check.HeadersFromSecrets)
		preview.Checks = append(preview.Checks, check)
	}
	if err := preview.Validate(); err != nil {
		return nil, nil, fmt.Errorf("the preview derived from %s is not a valid app, which is a bug in helios: %w", parent.App, err)
	}
	return &preview, skipped, nil
}

// SetRouteDNS makes every route of an app keep its record one way, for a
// preview whose parent's routes say another: a parent whose records are
// kept by hand has none for a preview's hostnames.
func SetRouteDNS(m *manifest.Manifest, mode manifest.DNSMode) {
	for name, w := range m.Workloads {
		routes := make([]manifest.Route, len(w.Routes))
		for i, r := range w.Routes {
			r.DNS = mode
			routes[i] = r
		}
		w.Routes = routes
		m.Workloads[name] = w
	}
}

// previewName is what a branch's preview of an app is called. It is
// derived rather than chosen so that the same branch always maps to the
// same app, and deploying a branch twice updates it instead of making a
// second one.
func previewName(app, branch string) string {
	name := app + previewSuffix + DNSLabel(branch)
	if len(name) <= maxAppName {
		return name
	}
	// Too long to keep whole. Keep as much as will fit and end with a
	// digest of the full name, so two long branches of the same app cannot
	// land on one preview.
	sum := sha256.Sum256([]byte(name))
	tail := "-" + hex.EncodeToString(sum[:])[:6]
	return strings.TrimRight(name[:maxAppName-len(tail)], "-") + tail
}

// previewHost is where a branch's copy of one of an app's hostnames
// answers: the branch, the first label of the original hostname, and the
// domain previews live under.
//
// The original's first label is kept so that an app serving several
// hostnames keeps them apart. Collapsing loom.example.com and
// runner.loom.example.com onto one preview hostname would put two
// workloads on the same route.
func previewHost(host, branch, domain string) string {
	first, _, _ := strings.Cut(host, ".")
	return DNSLabel(branch) + "." + DNSLabel(first) + "." + domain
}

// DNSLabel turns a branch name into something that can be one label of a
// hostname: lowercase, digits and hyphens, never starting or ending with
// one. A slash is as common in a branch name as a letter, so this is not a
// validation but a conversion.
func DNSLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	// A label is at most 63 octets, and one that long in a branch name is
	// a description rather than a name.
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	return out
}
