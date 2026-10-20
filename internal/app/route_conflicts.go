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
// that host's DNS mode must agree. Its origin-pull modes need not: the edge
// takes the strictest any app asks for (settleOriginPull), which is how
// apps sharing a host switch it one at a time, and the trust check holds
// each of them to that mode. The app may replace its own active routes.
func CheckRouteConflicts(ctx context.Context, store *state.Store, m *manifest.Manifest) error {
	if store == nil {
		return nil
	}
	type ownedRoute struct {
		workload string
		host     string
		path     string
		dns      manifest.DNSMode
	}
	// Keep candidate and existing routes in workload order so diagnostics stay
	// stable. Index existing routes by host once per app, instead of sorting
	// and visiting every existing workload for every candidate route.
	names := m.WorkloadNames()
	count := 0
	for _, name := range names {
		count += len(m.Workloads[name].Routes)
	}
	mine := make([]ownedRoute, 0, count)
	hosts := map[string]bool{}
	for _, name := range names {
		for _, r := range m.Workloads[name].Routes {
			mine = append(mine, ownedRoute{name, r.Host, r.NormalizedPath(), r.DNS})
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
					byHost[r.Host] = append(byHost[r.Host], ownedRoute{name, r.Host, r.NormalizedPath(), r.DNS})
				}
			}
		}
		for _, candidate := range mine {
			for _, existing := range byHost[candidate.host] {
				if candidate.path == existing.path {
					clashes = append(clashes, fmt.Sprintf("%s%s for %s is already routed to %s's %s", candidate.host, candidate.path, candidate.workload, other.App, existing.workload))
				} else if candidate.dns != existing.dns {
					clashes = append(clashes, fmt.Sprintf("%s uses dns %q here and %q in %s; routes sharing a host must use one DNS mode", candidate.host, candidate.dns, existing.dns, other.App))
				}
			}
		}
	}
	if len(clashes) > 0 {
		return fmt.Errorf("%s can't route what conflicts with another app on this machine: %s", m.App, strings.Join(clashes, "; "))
	}
	return nil
}
