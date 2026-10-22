package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/dns"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/host"
)

func newDNS(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "The records behind every host this machine routes, as Cloudflare and the world see them.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.showDNS(cmd.Context())
		},
	}
	cmd.AddCommand(newDNSAudit(a), newDNSPoint(a), newDNSDrop(a))
	return cmd
}

// showDNS explains every routed host: what Cloudflare keeps for it when
// the integration is set, what public DNS answers when it is not.
func (a *app) showDNS(ctx context.Context) error {
	store, err := a.openState()
	if err != nil {
		return err
	}
	defer store.Close()
	routes, err := apps.Routes(ctx, store)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		if a.json {
			return json.NewEncoder(a.stdout).Encode([]dns.Status{})
		}
		fmt.Fprintln(a.stdout, "no hosts routed yet")
		return nil
	}
	addrs := host.Addresses(ctx, host.RealEnv())
	mgr, cfErr := apps.DNSManager(a.secretsStore(), addrs)
	var statuses []dns.Status
	if cfErr == nil {
		if statuses, err = mgr.Look(ctx, routes); err != nil {
			return err
		}
	} else {
		statuses = resolvedStatuses(ctx, routes, addrs)
	}
	if a.json {
		return json.NewEncoder(a.stdout).Encode(statuses)
	}
	w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tAPP\tRECORD KEPT BY\tPOINTS AT\tVERDICT")
	for _, st := range statuses {
		kept := "you (manual)"
		switch st.Mode {
		case "direct":
			kept = "helios, direct"
		case "proxied":
			kept = "helios, proxied"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", st.Host, st.App, kept, orDash(st.Record), st.Verdict)
	}
	w.Flush()
	if cfErr != nil {
		fmt.Fprintf(a.stdout, "(what public DNS answers; set the cloudflare integration to see and keep the records themselves)\n")
	}
	return nil
}

// resolvedStatuses is what the world resolves for each route, for a
// machine without the cloudflare integration.
func resolvedStatuses(ctx context.Context, routes []dns.Route, addrs []string) []dns.Status {
	var statuses []dns.Status
	for _, r := range routes {
		st := dns.Status{Host: r.Host, App: r.App, Mode: string(r.Mode)}
		if st.Mode == "" {
			st.Mode = "manual"
		}
		ok, pointsAt, err := edge.Resolves(ctx, r.Host, addrs)
		switch {
		case err != nil:
			st.Verdict = err.Error()
		case ok:
			st.Verdict, st.Record = "resolves here", strings.Join(pointsAt, " ")
		default:
			st.Verdict, st.Record = "resolves elsewhere", strings.Join(pointsAt, " ")
		}
		statuses = append(statuses, st)
	}
	return statuses
}

func newDNSAudit(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Records that point here without a route, records helios left behind, routes whose records point elsewhere.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			routes, err := apps.Routes(ctx, store)
			if err != nil {
				return err
			}
			mgr, err := apps.DNSManager(a.secretsStore(), host.Addresses(ctx, host.RealEnv()))
			if err != nil {
				return fmt.Errorf("an audit reads the zones through the cloudflare integration: %w", err)
			}
			findings, err := mgr.Audit(ctx, routes)
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(findings)
			}
			if len(findings) == 0 {
				fmt.Fprintln(a.stdout, "every record that points here has a route, and every route has a record")
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "HOST\tRECORD\tFINDING")
			for _, f := range findings {
				record := "-"
				if f.Type != "" {
					record = f.Type + " " + f.Content
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", f.Host, record, f.What)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			for _, f := range findings {
				if f.Droppable {
					fmt.Fprintln(a.stdout, "helios dns drop <host> deletes a record that points here with no route here, once you are sure nothing needs it")
					break
				}
			}
			return nil
		},
	}
}

func newDNSPoint(a *app) *cobra.Command {
	var (
		planOnly bool
		proxied  bool
	)
	point := &cobra.Command{
		Use:   "point <host>",
		Short: "Make a host's record name this machine, taking it from wherever it points now (moving day).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.PointKind, apps.PointInput{Host: args[0], Proxied: proxied}, planOnly)
		},
	}
	point.Flags().BoolVar(&proxied, "proxied", false, "put the host behind Cloudflare's proxy")
	a.mutatingFlags(point, &planOnly)
	return point
}

func newDNSDrop(a *app) *cobra.Command {
	var planOnly bool
	drop := &cobra.Command{
		Use:   "drop <host>",
		Short: "Delete a record that points here for a host no app on this machine routes.",
		Long: `Delete a record that points here for a host no app on this machine routes,
such as one helios dns audit finds after an app was removed.

Only the A and AAAA records at exactly that name go, and only when every
record there points at this machine: a record that names another machine,
or a CNAME, refuses the drop. A wildcard that covers the host is never
touched; name the wildcard itself, such as '*.example.com', to drop it,
and only when no route here falls under it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.DropKind, apps.DropInput{Host: args[0]}, planOnly)
		},
	}
	a.mutatingFlags(drop, &planOnly)
	return drop
}
