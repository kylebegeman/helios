package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
)

// RecoverCutover is deliberately separate from restoration and rehearsal.
// It checks readiness again before routing any host to the recovered apps.
type RecoverCutover struct {
	Recovery       RecoverMachine
	Addresses      func(context.Context) []string
	CloudflareOnly CloudflareOnly
}

type RecoverCutoverInput struct {
	ID string `json:"id"`
}

func (RecoverCutover) Kind() string { return RecoverCutoverKind }

func (c RecoverCutover) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in RecoverCutoverInput
	if json.Unmarshal(raw, &in) != nil || !recoveryIDPattern.MatchString(in.ID) {
		return nil, errors.New("cutover needs a valid recovery ID")
	}
	// Load the immutable source selection from the recovery record. The
	// caller cannot change snapshots or turn a rehearsal into recovery.
	dir := RecoveryDirectory(c.Recovery.StateDir, in.ID)
	path := dir + "/recovery-record.json"
	if err := recoveryPlainFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var original machineRecoveryRecord
	if json.Unmarshal(data, &original) != nil {
		return nil, errors.New("invalid recovery record")
	}
	x := &machineRecovering{r: c.Recovery, in: original.Input, dir: dir}
	rec, err := x.load()
	if err != nil {
		return nil, err
	}
	if !rec.AbandonedAt.IsZero() {
		return nil, errors.New("an abandoned recovery cannot be cut over")
	}
	if err := validateRecoveryCatalog(rec.Catalog); err != nil {
		return nil, err
	}
	if rec.Input.Rehearsal {
		return nil, errors.New("a disposable rehearsal cannot be cut over; recover onto a clean target first")
	}
	if rec.FinishedAt.IsZero() || !rec.StateInstalled {
		return nil, errors.New("recovery has not completed its private readiness and state import")
	}
	for _, rev := range rec.Catalog.Revisions {
		if !rec.Ready[rev.App] {
			return nil, fmt.Errorf("%s has not passed private readiness", rev.App)
		}
		var m manifest.Manifest
		_ = json.Unmarshal(rev.Manifest, &m)
		if rec.Cutover {
			continue
		}
		if err := c.CloudflareOnly.checkRoutes(&m); err != nil {
			return nil, err
		}
		if err := CheckRouteConflicts(ctx, c.Recovery.Store, &m); err != nil {
			return nil, err
		}
		// Activation loads the edge, which would refuse every connection
		// to a host that requires origin pull and has no CA here, and then
		// DNS points the host at this machine.
		if err := checkRecoveredOriginPullTrust(ctx, c.Recovery.Store, &m, c.Recovery.Secrets, time.Now(), in.ID); err != nil {
			return nil, err
		}
	}
	plan := &kernel.Plan{Target: "recovery " + in.ID, Recovery: kernel.Resume, Steps: []kernel.Step{
		{Name: "begin", Change: "record the start of reviewed cutover before changing target runtime", Apply: func(ctx context.Context, out io.Writer) error {
			rec, err := x.load()
			if err != nil {
				return err
			}
			if rec.CutoverStarted || rec.Cutover {
				return nil
			}
			rec.CutoverStarted = true
			return x.save(rec)
		}},
		{Name: "edge", Change: "ensure the target edge before routing recovered apps", Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			boot, err := EdgeConfig(ctx, c.Recovery.Store, c.Recovery.Secrets)
			if err != nil {
				return err
			}
			return edge.Ensure(ctx, e, boot, out)
		}},
		{Name: "runtime", Change: "bring recovered services onto their normal networks and enable normal workload ports", Apply: func(ctx context.Context, out io.Writer) error {
			rec, err := x.load()
			if err != nil {
				return err
			}
			if rec.Cutover {
				return nil
			}
			e, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			for _, rev := range rec.Catalog.Revisions {
				var m manifest.Manifest
				_ = json.Unmarshal(rev.Manifest, &m)
				n := x.names(&m)
				values, err := c.Recovery.Secrets.Load(rev.App, rev.SecretsVersion)
				if err != nil {
					return err
				}
				if err := e.EnsureNetwork(ctx, docker.AppNetwork(rev.App)); err != nil {
					return err
				}
				if err := e.EnsureNetwork(ctx, docker.EdgeNetwork); err != nil {
					return err
				}
				if !rec.CutoverReady[rev.App] {
					if err := x.checkRecoveryContainers(ctx, e, &m, n, true); err != nil {
						return err
					}
					// These are recovery-owned containers on restored volumes,
					// never original-source or unrelated target workloads.
					for _, name := range n.containers {
						if err := e.Remove(ctx, name, 5*time.Second); err != nil {
							return err
						}
					}
					if m.PostgresVersion() != "" {
						if err := e.Remove(ctx, n.postgres, 5*time.Second); err != nil {
							return err
						}
					}
					if m.HasObjects() {
						if err := e.Remove(ctx, n.objects, 5*time.Second); err != nil {
							return err
						}
					}
				}
				if m.PostgresVersion() != "" {
					svc, err := postgresService(&m, values, "")
					if err != nil {
						return err
					}
					if err := svc.start(ctx, e, out); err != nil {
						return err
					}
				}
				if m.HasObjects() {
					o := objectsServiceFor(&m, values)
					if err := o.start(ctx, e, out); err != nil {
						return err
					}
				}
				for _, name := range sortedKeys(n.containers) {
					w := m.Workloads[name]
					spec, err := containerSpec(&m, name, w, recoveryRevisionID(in.ID), rev.Images[name], values)
					if err != nil {
						return err
					}
					if _, err := isolate(ctx, e, &spec, w, rev.Images[name]); err != nil {
						return err
					}
					if err := e.Run(ctx, spec); err != nil {
						return err
					}
				}
				for _, name := range sortedKeys(n.containers) {
					if err := waitReady(ctx, e, n.containers[name], m.Workloads[name]); err != nil {
						return fmt.Errorf("%s/%s cutover readiness: %w", rev.App, name, err)
					}
				}
				rec.CutoverReady[rev.App] = true
				if err := x.save(rec); err != nil {
					return err
				}
			}
			return nil
		}},
		{Name: "ready", Change: "recheck all restored long-running workloads before changing any live route or DNS record", Apply: func(ctx context.Context, out io.Writer) error {
			rec, err := x.load()
			if err != nil {
				return err
			}
			e, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			for _, rev := range rec.Catalog.Revisions {
				if !rec.CutoverReady[rev.App] {
					return fmt.Errorf("%s runtime is not ready for cutover", rev.App)
				}
				var m manifest.Manifest
				_ = json.Unmarshal(rev.Manifest, &m)
				n := x.names(&m)
				for _, name := range sortedKeys(n.containers) {
					if err := waitReady(ctx, e, n.containers[name], m.Workloads[name]); err != nil {
						return err
					}
				}
			}
			fmt.Fprintln(out, "all recovered workloads passed readiness before route or DNS cutover")
			return nil
		}},
		{Name: "activate", Change: "activate the new recovered revisions and load their edge routes", Apply: func(ctx context.Context, out io.Writer) error {
			rec, err := x.load()
			if err != nil {
				return err
			}
			for _, rev := range rec.Catalog.Revisions {
				if err := c.Recovery.Store.Activate(ctx, rev.App, recoveryRevisionID(in.ID), time.Now().UTC()); err != nil {
					return err
				}
			}
			if err := ReloadEdge(ctx, c.Recovery.Store, c.Recovery.Secrets); err != nil {
				return err
			}
			fmt.Fprintln(out, "target edge routes to recovered revisions")
			return nil
		}},
		{Name: "dns", Change: "explicitly point managed app hosts to this target after readiness", Apply: func(ctx context.Context, out io.Writer) error {
			rec, err := x.load()
			if err != nil {
				return err
			}
			for _, rev := range rec.Catalog.Revisions {
				var m manifest.Manifest
				_ = json.Unmarshal(rev.Manifest, &m)
				if len(m.ManagedHosts()) == 0 {
					continue
				}
				if c.Addresses == nil {
					return errors.New("cutover cannot discover the target public addresses")
				}
				mgr, err := DNSManager(c.Recovery.Secrets, c.Addresses(ctx))
				if err != nil {
					return err
				}
				for _, h := range sortedKeys(m.ManagedHosts()) {
					outcome, err := mgr.Ensure(ctx, m.App, h, m.ManagedHosts()[h], true)
					if err != nil {
						return err
					}
					fmt.Fprintln(out, outcome)
				}
			}
			return nil
		}},
		{Name: "finish", Change: "record the live cutover and retire private recovery networks", Apply: func(ctx context.Context, out io.Writer) error {
			rec, err := x.load()
			if err != nil {
				return err
			}
			e, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			for _, rev := range rec.Catalog.Revisions {
				var m manifest.Manifest
				_ = json.Unmarshal(rev.Manifest, &m)
				if err := e.RemoveNetwork(ctx, x.names(&m).network); err != nil {
					return err
				}
			}
			rec.Cutover = true
			if err := x.save(rec); err != nil {
				return err
			}
			if err := x.releaseReservation(); err != nil {
				return err
			}
			fmt.Fprintln(out, "machine recovery cutover complete")
			return nil
		}},
	}}
	for i := range plan.Steps {
		apply := plan.Steps[i].Apply
		finish := plan.Steps[i].Name == "finish"
		plan.Steps[i].Apply = func(ctx context.Context, out io.Writer) error {
			rec, err := x.load()
			if err != nil {
				return err
			}
			if rec.Cutover {
				// A completed recovery ID remains a historical proof even
				// after later deployments. Only a reservation left behind
				// between its completion marker and release needs repair.
				if finish {
					return x.releaseReservation()
				}
				return nil
			}
			return apply(ctx, out)
		}
	}
	return plan, nil
}
