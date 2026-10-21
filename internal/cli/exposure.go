package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/host"
)

// exposureReport is what helios exposure prints.
type exposureReport struct {
	Containers []exposureRow `json:"containers"`
	// Shared lists networks more than one app is on, besides the edge.
	Shared []string `json:"shared_networks"`
	// Findings are the lines worth a look: privileges, root, writable
	// roots, published ports, containers helios doesn't manage.
	Findings []string `json:"findings"`
}

type exposureRow struct {
	docker.Exposure
	Role     string   `json:"role"`
	Workload string   `json:"workload,omitempty"`
	Nets     []string `json:"network_roles"`
}

// roleOf says what a container is: an app's workload, its database, one
// of helios's own, or something helios doesn't manage.
func roleOf(x docker.Exposure) (role, workload string) {
	switch {
	case x.Labels[docker.LabelOwner] != docker.OwnerValue:
		return "not managed by helios", ""
	case x.Name == edge.Container:
		return "the edge", ""
	case x.Name == host.RegistryContainer:
		return "the image registry", ""
	case x.Labels[docker.LabelWorkload] == "postgres":
		return "database", "postgres"
	case x.Labels[docker.LabelWorkload] == "objects":
		return "object store", "objects"
	case x.Labels[docker.LabelWorkload] == "drill":
		return "restore drill", "drill"
	case x.Labels[docker.LabelWorkload] != "":
		return "workload", x.Labels[docker.LabelWorkload]
	}
	return "helios's", ""
}

// networkRole names a network the way the report reads.
func networkRole(app, name string) string {
	switch {
	case name == docker.AppNetwork(app):
		return "own"
	case name == edge.AppNetwork(app):
		return "edge"
	case name == docker.EdgeNetwork:
		return "shared edge (from before isolation)"
	}
	return name
}

func buildExposure(xs []docker.Exposure) exposureReport {
	var r exposureReport
	members := map[string]map[string]bool{} // network -> apps on it
	for _, x := range xs {
		role, workload := roleOf(x)
		row := exposureRow{Exposure: x, Role: role, Workload: workload}
		for _, n := range x.Networks {
			row.Nets = append(row.Nets, networkRole(x.App, n))
			if role == "workload" || role == "database" || role == "object store" || role == "restore drill" {
				if members[n] == nil {
					members[n] = map[string]bool{}
				}
				members[n][x.App] = true
			}
		}
		r.Containers = append(r.Containers, row)
		if !x.Running {
			continue
		}
		switch role {
		case "not managed by helios":
			if len(x.Ports) > 0 {
				r.Findings = append(r.Findings, fmt.Sprintf("%s isn't managed by helios and publishes %s", x.Name, strings.Join(x.Ports, ", ")))
			} else {
				r.Findings = append(r.Findings, fmt.Sprintf("%s isn't managed by helios", x.Name))
			}
		case "workload":
			who := x.Name
			if x.Privileged {
				r.Findings = append(r.Findings, fmt.Sprintf("%s is privileged (its manifest declares it)", who))
				continue
			}
			if x.AllCapabilities || !x.NoNewPrivileges {
				r.Findings = append(r.Findings, fmt.Sprintf("%s runs with Docker's default privileges: started before isolation; redeploy %s", who, x.App))
			}
			if isRoot(x.User) {
				r.Findings = append(r.Findings, fmt.Sprintf("%s runs as root (its manifest says user: root)", who))
			}
			if !x.ReadOnlyRoot {
				r.Findings = append(r.Findings, fmt.Sprintf("%s can write its root filesystem", who))
			}
			if len(x.Capabilities) > 0 {
				r.Findings = append(r.Findings, fmt.Sprintf("%s keeps %s", who, strings.Join(x.Capabilities, ", ")))
			}
			if len(x.Ports) > 0 {
				r.Findings = append(r.Findings, fmt.Sprintf("%s publishes %s", who, strings.Join(x.Ports, ", ")))
			}
			for _, n := range x.Networks {
				if n == docker.EdgeNetwork {
					r.Findings = append(r.Findings, fmt.Sprintf("%s is on the shared edge network: started before isolation; redeploy %s", who, x.App))
				}
			}
			for _, m := range x.Mounts {
				if strings.HasPrefix(m, "/") {
					r.Findings = append(r.Findings, fmt.Sprintf("%s mounts a path from the machine: %s", who, m))
				}
			}
		}
	}
	nets := make([]string, 0, len(members))
	for n := range members {
		nets = append(nets, n)
	}
	sort.Strings(nets)
	for _, n := range nets {
		if len(members[n]) > 1 {
			apps := make([]string, 0, len(members[n]))
			for a := range members[n] {
				apps = append(apps, a)
			}
			sort.Strings(apps)
			r.Shared = append(r.Shared, fmt.Sprintf("%s: %s", n, strings.Join(apps, ", ")))
		}
	}
	return r
}

func isRoot(user string) bool {
	u, _, _ := strings.Cut(user, ":")
	return u == "" || u == "0" || u == "root"
}

func newExposure(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "exposure [app]",
		Short: "What each container may do and what reaches it: user, capabilities, root filesystem, networks, ports, mounts.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := docker.Connect(cmd.Context())
			if err != nil {
				return err
			}
			defer engine.Close()
			all, err := engine.Exposures(cmd.Context())
			if err != nil {
				return err
			}
			report := buildExposure(all)
			if len(args) == 1 {
				var mine []exposureRow
				for _, row := range report.Containers {
					if row.App == args[0] {
						mine = append(mine, row)
					}
				}
				if len(mine) == 0 {
					return fmt.Errorf("no containers for %s", args[0])
				}
				report.Containers = mine
			}
			if a.json {
				if err := json.NewEncoder(a.stdout).Encode(report); err != nil {
					return err
				}
				if len(report.Shared) > 0 {
					return quietError{code: 1}
				}
				return nil
			}
			w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CONTAINER\tROLE\tUSER\tPRIVILEGES\tROOT FS\tNETWORKS\tPORTS\tMOUNTS\tLIMITS")
			for _, row := range report.Containers {
				if !row.Running {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", row.Name, roleWord(row), userWord(row.User), privilegeWord(row.Exposure), rootWord(row.Exposure), orDash(strings.Join(row.Nets, ", ")), orDash(strings.Join(row.Ports, ", ")), orDash(strings.Join(row.Mounts, ", ")), limitWord(row.Exposure))
			}
			w.Flush()
			if len(report.Shared) == 0 {
				fmt.Fprintln(a.stdout, "no two apps share a network; each reaches the others only through the edge, as the world does")
			} else {
				for _, s := range report.Shared {
					fmt.Fprintf(a.stdout, "SHARED NETWORK %s\n", s)
				}
			}
			fmt.Fprintf(a.stdout, "the edge's admin API is the socket %s, which no container reaches over a network\n", edge.AdminSocket)
			for _, f := range report.Findings {
				fmt.Fprintf(a.stdout, "  %s\n", f)
			}
			if len(report.Shared) > 0 {
				return errors.New("apps share a network; redeploy them with this helios")
			}
			return nil
		},
	}
}

func roleWord(row exposureRow) string {
	if row.Role == "workload" {
		return row.App + " " + row.Workload
	}
	if row.Role == "database" || row.Role == "object store" || row.Role == "restore drill" {
		return row.App + " " + row.Role
	}
	return row.Role
}

func userWord(u string) string {
	if u == "" {
		return "image's"
	}
	return u
}

func privilegeWord(x docker.Exposure) string {
	switch {
	case x.Privileged:
		return "PRIVILEGED"
	case x.AllCapabilities && !x.NoNewPrivileges:
		return "docker defaults"
	case x.AllCapabilities:
		return "docker defaults, no new"
	case len(x.Capabilities) == 0:
		return "none"
	}
	return strings.Join(x.Capabilities, "+")
}

func rootWord(x docker.Exposure) string {
	if x.ReadOnlyRoot {
		return "read-only"
	}
	return "writable"
}

func limitWord(x docker.Exposure) string {
	var parts []string
	if x.MemoryBytes > 0 {
		parts = append(parts, bytesWord(x.MemoryBytes))
	}
	if x.PidsLimit > 0 {
		parts = append(parts, fmt.Sprintf("%d pids", x.PidsLimit))
	}
	return orDash(strings.Join(parts, ", "))
}
