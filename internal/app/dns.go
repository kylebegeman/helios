package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/cloudflare"
	"github.com/kylebegeman/helios/internal/dns"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// DNSManager opens the Cloudflare integration for this machine, or says
// why it can't.
func DNSManager(sec *secrets.Store, addresses []string) (*dns.Manager, error) {
	cf, err := integration.LoadCloudflare(sec)
	if err != nil {
		return nil, err
	}
	client := cloudflare.New(cf.Token)
	if cf.API != "" {
		client.Base = cf.API
	}
	hostname, _ := os.Hostname()
	return &dns.Manager{CF: client, Hostname: hostname, Addresses: addresses}, nil
}

// errNoCloudflare says what to do when a manifest asks for records and
// the machine can't keep them.
func errNoCloudflare(app string, err error) error {
	return fmt.Errorf("%s's routes ask helios to keep their DNS records (dns: direct or proxied), but %w", app, err)
}

// managedHostsOf reads a revision's managed hosts.
func managedHostsOf(rev state.Revision) map[string]manifest.DNSMode {
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return nil
	}
	return m.ManagedHosts()
}

// keepRecords makes the records a manifest asks for and waits until every
// host points here. A record that points at another machine stops the
// deploy: moving a name is `helios dns point`, never a side effect.
func keepRecords(ctx context.Context, sec *secrets.Store, m *manifest.Manifest, addrs []string, out io.Writer) error {
	managed := m.ManagedHosts()
	if len(managed) > 0 {
		mgr, err := DNSManager(sec, addrs)
		if err != nil {
			return errNoCloudflare(m.App, err)
		}
		for _, host := range sortedKeys(managed) {
			outcome, err := mgr.Ensure(ctx, m.App, host, managed[host], false)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, outcome)
			if outcome.Proxied && outcome.Depth() > 1 {
				fmt.Fprintf(out, "note: Cloudflare's free certificate covers names one level below %s, so HTTPS to %s through the proxy fails unless the zone has Advanced Certificate Manager; dns: direct avoids it\n", outcome.Zone, host)
			}
		}
	}
	for _, host := range m.Hosts() {
		if managed[host] == manifest.DNSProxied {
			fmt.Fprintf(out, "%s is behind Cloudflare's proxy; its record names this machine\n", host)
			continue
		}
		if err := waitResolves(ctx, host, addrs, managed[host].Managed()); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s points here\n", host)
	}
	return nil
}

// waitResolves checks a host's public DNS, waiting up to two minutes for a
// record helios just made to reach the resolvers.
func waitResolves(ctx context.Context, host string, addrs []string, patient bool) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		ok, pointsAt, err := edge.Resolves(ctx, host, addrs)
		if ok {
			return nil
		}
		if !patient || time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return errors.New(edge.DNSProblem(host, pointsAt, addrs))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// pruneRecords removes the records helios keeps for an app's hosts that
// its active revision no longer routes. It needs the integration only
// when there is something to remove.
func pruneRecords(ctx context.Context, store *state.Store, sec *secrets.Store, app string, addrs []string, out io.Writer) error {
	revs, err := store.Revisions(ctx, app)
	if err != nil {
		return err
	}
	keep := map[string]manifest.DNSMode{}
	dropped := map[string]bool{}
	for _, r := range revs {
		if r.Status == state.RevisionActive {
			keep = managedHostsOf(r)
		}
	}
	for _, r := range revs {
		if r.Status == state.RevisionActive {
			continue
		}
		for host := range managedHostsOf(r) {
			if _, still := keep[host]; !still {
				dropped[host] = true
			}
		}
	}
	if len(dropped) == 0 {
		return nil
	}
	mgr, err := DNSManager(sec, addrs)
	if err != nil {
		fmt.Fprintf(out, "records for %v stay: %v\n", sortedKeys(dropped), err)
		return nil
	}
	removed, err := removeUnroutedRecords(ctx, store, mgr, app, sortedKeys(dropped), out)
	if err != nil {
		return err
	}
	for _, host := range removed {
		fmt.Fprintf(out, "%s's record removed; %s no longer routes it\n", host, app)
	}
	return nil
}

// A hostname can serve several apps at different paths. Transfer a shared
// managed record to a remaining app instead of deleting its route out from
// under it; the final app can then remove the record by its ownership marker.
func removeUnroutedRecords(ctx context.Context, store *state.Store, mgr *dns.Manager, app string, hosts []string, out io.Writer) ([]string, error) {
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return nil, err
	}
	type owner struct {
		app  string
		mode manifest.DNSMode
	}
	shared := map[string]owner{}
	for _, rev := range active {
		if rev.App == app {
			continue
		}
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			return nil, fmt.Errorf("revision %s/%s manifest: %w", rev.App, rev.ID, err)
		}
		managed := m.ManagedHosts()
		for _, host := range m.Hosts() {
			if previous, ok := shared[host]; !ok || managed[host].Managed() && !previous.mode.Managed() || managed[host].Managed() == previous.mode.Managed() && rev.App < previous.app {
				shared[host] = owner{app: rev.App, mode: managed[host]}
			}
		}
	}
	var dropped []string
	for _, host := range hosts {
		remaining, ok := shared[host]
		if !ok {
			dropped = append(dropped, host)
			continue
		}
		if remaining.mode.Managed() {
			if err := transferSharedRecordOwnership(ctx, mgr, host, app, remaining.app); err != nil {
				return nil, err
			}
		}
		fmt.Fprintf(out, "%s's record stays: %s still routes it\n", host, remaining.app)
	}
	return mgr.Remove(ctx, app, dropped)
}

// Cleanup only changes the ownership marker of existing records it could
// otherwise delete. It never creates DNS, changes routing/proxy policy, or
// adopts a record maintained by another owner.
func transferSharedRecordOwnership(ctx context.Context, mgr *dns.Manager, host, from, to string) error {
	zones, err := mgr.CF.Zones(ctx)
	if err != nil {
		return err
	}
	var zone cloudflare.Zone
	for _, candidate := range zones {
		if (host == candidate.Name || strings.HasSuffix(host, "."+candidate.Name)) && len(candidate.Name) > len(zone.Name) {
			zone = candidate
		}
	}
	if zone.ID == "" {
		return nil
	}
	records, err := mgr.CF.Records(ctx, zone.ID, host)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Name != host || record.Comment != dns.Comment(from, mgr.Hostname) {
			continue
		}
		local := false
		for _, address := range mgr.Addresses {
			local = local || record.Content == address
		}
		if !local {
			continue
		}
		record.Comment = dns.Comment(to, mgr.Hostname)
		if err := mgr.CF.Update(ctx, zone.ID, record); err != nil {
			return err
		}
	}
	return nil
}

// PointKind moves a host's record to this machine: the step of moving
// day when a name leaves one machine for another.
const PointKind = "dns.point"

// Point is the Definition for PointKind.
type Point struct {
	// AllowMigration is internal authority for a validated cutover plan.
	// Standalone DNS operations leave it empty and obey the writer fence.
	AllowMigration string
	Store          *state.Store
	Secrets        *secrets.Store
	Addresses      func(ctx context.Context) []string
	// CloudflareOnly refuses to point a name straight at a machine that
	// answers only Cloudflare.
	CloudflareOnly CloudflareOnly
}

// PointInput says which host, and whether it goes behind the proxy.
type PointInput struct {
	Host    string `json:"host"`
	Proxied bool   `json:"proxied,omitempty"`
}

// Kind implements kernel.Definition.
func (Point) Kind() string { return PointKind }

// Plan implements kernel.Definition.
func (p Point) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in PointInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("point input: %w", err)
	}
	// The app that routes the host: an active one, or else the newest
	// revision that asked for it, such as a first deploy that stopped
	// because the name still pointed at the old machine.
	app, mode, err := routedBy(ctx, p.Store, in.Host)
	if err != nil {
		return nil, err
	}
	if app == "" {
		return nil, fmt.Errorf("no app on this machine routes %s; deploy the app with it first, then point its name here", in.Host)
	}
	if err := CheckMigrationAccess(p.Store.Path(), app); err != nil {
		record, readErr := readMigration(p.Store.Path(), app)
		if readErr != nil {
			return nil, readErr
		}
		if p.AllowMigration == "" || record == nil || record.Role != "target" || record.Handoff.Migration != p.AllowMigration || (record.Phase != "staged" && record.Phase != "cutting-over") {
			return nil, err
		}
	}
	if in.Proxied {
		mode = manifest.DNSProxied
	}
	if direct, err := p.CloudflareOnly.bypassing(map[string]manifest.DNSMode{in.Host: mode}); err != nil {
		return nil, err
	} else if len(direct) > 0 {
		return nil, fmt.Errorf("%s, so a record naming it straight would reach nothing: point %s with --proxied", onlyCloudflare, in.Host)
	}
	if _, err := integration.LoadCloudflare(p.Secrets); err != nil {
		return nil, fmt.Errorf("pointing a record needs the cloudflare integration: %w", err)
	}
	return &kernel.Plan{Target: in.Host, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name: "point", Change: fmt.Sprintf("make %s's record name this machine (%s), for %s", in.Host, mode, app),
		Apply: func(ctx context.Context, out io.Writer) error {
			addrs := p.Addresses(ctx)
			mgr, err := DNSManager(p.Secrets, addrs)
			if err != nil {
				return err
			}
			outcome, err := mgr.Ensure(ctx, app, in.Host, mode, true)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, outcome)
			if mode == manifest.DNSProxied {
				return nil
			}
			if err := waitResolves(ctx, in.Host, addrs, true); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s points here for the world\n", in.Host)
			return nil
		},
	}}}, nil
}

// DropKind deletes a record that points at this machine for a host no
// app here routes: what helios dns audit finds and nothing else removes,
// such as an app's name after the app was removed by hand.
const DropKind = "dns.drop"

// Drop is the Definition for DropKind.
type Drop struct {
	Store     *state.Store
	Secrets   *secrets.Store
	Addresses func(ctx context.Context) []string
}

// DropInput names the host whose record goes.
type DropInput struct {
	Host string `json:"host"`
}

// Kind implements kernel.Definition.
func (Drop) Kind() string { return DropKind }

// Plan implements kernel.Definition. It reads the records when it plans,
// so the plan names each one it deletes and its digest pins them.
func (d Drop) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in DropInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("drop input: %w", err)
	}
	host := strings.TrimSuffix(strings.ToLower(in.Host), ".")
	under, wildcard := strings.CutPrefix(host, "*.")
	if !manifest.ValidHost(under) {
		return nil, fmt.Errorf("%q isn't a hostname, or a wildcard such as *.example.com", in.Host)
	}
	// Any revision counts, not only the active one: a rollback would
	// bring the route back to a name with no record.
	routed, err := routedHosts(ctx, d.Store)
	if err != nil {
		return nil, err
	}
	for _, h := range sortedKeys(routed) {
		if h == host {
			return nil, fmt.Errorf("%s routes %s on this machine; its record goes when the route is retired or the app is removed", routed[h], host)
		}
		if wildcard && dns.Covers(host, h) {
			return nil, fmt.Errorf("%s covers %s, which %s routes on this machine; helios drops a wildcard only when no route here falls under it", host, h, routed[h])
		}
	}
	if _, err := integration.LoadCloudflare(d.Secrets); err != nil {
		return nil, fmt.Errorf("dropping a record needs the cloudflare integration: %w", err)
	}
	mgr, err := DNSManager(d.Secrets, d.Addresses(ctx))
	if err != nil {
		return nil, err
	}
	drop, err := mgr.Droppable(ctx, host)
	if err != nil {
		return nil, err
	}
	return &kernel.Plan{Target: host, Recovery: kernel.Resume, Steps: []kernel.Step{{
		Name:   "drop",
		Change: dropChange(drop),
		Apply: func(ctx context.Context, out io.Writer) error {
			mgr, err := DNSManager(d.Secrets, d.Addresses(ctx))
			if err != nil {
				return err
			}
			dropped, err := mgr.DropRecords(ctx, drop)
			for _, r := range dropped {
				fmt.Fprintf(out, "%s's %s record deleted\n", host, r)
			}
			return err
		},
	}}}, nil
}

// dropChange says what a drop deletes, record by record.
func dropChange(d dns.Drop) string {
	what, points := "record", "points"
	if len(d.Records) > 1 {
		what, points = fmt.Sprintf("%d records", len(d.Records)), "point"
	}
	return fmt.Sprintf("delete %s's %s in %s (%s), which %s at this machine; no app here routes %s", d.Host, what, d.Zone, d, points, d.Host)
}

// routedHosts maps every host any revision on the machine routes to the
// app that routes it.
func routedHosts(ctx context.Context, store *state.Store) (map[string]string, error) {
	apps, err := store.AppNames(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, name := range apps {
		revs, err := store.Revisions(ctx, name)
		if err != nil {
			return nil, err
		}
		for _, rev := range revs {
			var m manifest.Manifest
			if err := json.Unmarshal(rev.Manifest, &m); err != nil {
				return nil, fmt.Errorf("revision %s of %s: its manifest doesn't parse, so what it routes is unknown: %w", rev.ID, name, err)
			}
			for _, h := range m.Hosts() {
				out[h] = name
			}
		}
	}
	return out, nil
}

// Routes lists every host the active revisions route, with its mode.
func Routes(ctx context.Context, store *state.Store) ([]dns.Route, error) {
	active, err := store.ActiveRevisions(ctx)
	if err != nil {
		return nil, err
	}
	var out []dns.Route
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			continue
		}
		managed := m.ManagedHosts()
		for _, h := range m.Hosts() {
			out = append(out, dns.Route{App: rev.App, Host: h, Mode: managed[h]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

// routedBy finds the app whose revisions route a host, preferring an
// active revision, and the record mode it asks for.
func routedBy(ctx context.Context, store *state.Store, host string) (string, manifest.DNSMode, error) {
	apps, err := store.AppNames(ctx)
	if err != nil {
		return "", "", err
	}
	type found struct {
		app    string
		mode   manifest.DNSMode
		active bool
		at     time.Time
	}
	var best *found
	for _, name := range apps {
		revs, err := store.Revisions(ctx, name)
		if err != nil {
			return "", "", err
		}
		for _, rev := range revs {
			var m manifest.Manifest
			if err := json.Unmarshal(rev.Manifest, &m); err != nil {
				continue
			}
			for _, h := range m.Hosts() {
				if h != host {
					continue
				}
				mode := m.ManagedHosts()[h]
				if mode == manifest.DNSManual {
					mode = manifest.DNSDirect
				}
				f := found{rev.App, mode, rev.Status == state.RevisionActive, rev.CreatedAt}
				if best == nil || (f.active && !best.active) || (f.active == best.active && f.at.After(best.at)) {
					best = &f
				}
			}
		}
	}
	if best == nil {
		return "", "", nil
	}
	return best.app, best.mode, nil
}
