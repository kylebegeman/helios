package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// CheckRouteConflicts refuses exact host/path ownership conflicts before a
// deploy builds or runs releases. Different prefixes may share one host, but
// that host's DNS mode must agree. The app may replace its own active routes.
func CheckRouteConflicts(ctx context.Context, store *state.Store, m *manifest.Manifest) error {
	if store == nil {
		return nil
	}
	type ownedRoute struct {
		workload string
		route    manifest.Route
		path     string
	}
	// Keep candidate and existing routes in workload order so diagnostics stay
	// stable. Index existing routes by host once per app, instead of sorting
	// and visiting every existing workload for every candidate route.
	var mine []ownedRoute
	hosts := map[string]bool{}
	for _, name := range m.WorkloadNames() {
		for _, r := range m.Workloads[name].Routes {
			mine = append(mine, ownedRoute{name, r, r.NormalizedPath()})
			hosts[r.Host] = true
		}
	}
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
		byHost := map[string][]ownedRoute{}
		for _, name := range other.WorkloadNames() {
			for _, r := range other.Workloads[name].Routes {
				if hosts[r.Host] {
					byHost[r.Host] = append(byHost[r.Host], ownedRoute{name, r, r.NormalizedPath()})
				}
			}
		}
		for _, candidate := range mine {
			for _, existing := range byHost[candidate.route.Host] {
				if candidate.path == existing.path {
					clashes = append(clashes, fmt.Sprintf("%s%s for %s is already routed to %s's %s", candidate.route.Host, candidate.path, candidate.workload, other.App, existing.workload))
				} else if candidate.route.DNS != existing.route.DNS {
					clashes = append(clashes, fmt.Sprintf("%s uses dns %q here and %q in %s; routes sharing a host must use one DNS mode", candidate.route.Host, candidate.route.DNS, existing.route.DNS, other.App))
				}
			}
		}
	}
	if len(clashes) > 0 {
		return fmt.Errorf("%s can't route what conflicts with another app on this machine: %s", m.App, strings.Join(clashes, "; "))
	}
	return nil
}
