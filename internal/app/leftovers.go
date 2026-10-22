package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
)

// leftovers is what an app that is no longer on the machine left behind:
// removed without --data, or with parts of it cleared by hand since. Each
// field is found when the plan is made and named in it, and a step removes
// exactly what its plan named.
type leftovers struct {
	app string
	// secretNames and secretVersion describe its sealed secrets.
	secretNames   []string
	secretVersion int
	containers    []string
	images        []string
	volumes       []string
	networks      []string
	// dirs are what the machine keeps for it under the state directory.
	dirs []string
	// migrationFence is retained until the remaining app writers are removed.
	migrationFence string
	// credentials says whether the webhook secret or deploy key helios
	// made for it are still among the integration credentials.
	credentials bool
}

func (l *leftovers) empty() bool {
	return len(l.secretNames) == 0 && l.secretVersion == 0 && len(l.containers) == 0 && len(l.images) == 0 &&
		len(l.volumes) == 0 && len(l.networks) == 0 && len(l.dirs) == 0 && l.migrationFence == "" && !l.credentials
}

// summary names what was found, for a refusal.
func (l *leftovers) summary() string {
	var parts []string
	if l.secretVersion > 0 {
		parts = append(parts, fmt.Sprintf("its sealed secrets (%s)", plural(len(l.secretNames), "name")))
	}
	if len(l.containers) > 0 {
		parts = append(parts, plural(len(l.containers), "container"))
	}
	if len(l.images) > 0 {
		parts = append(parts, plural(len(l.images), "image"))
	}
	if len(l.volumes) > 0 {
		parts = append(parts, plural(len(l.volumes), "volume"))
	}
	if len(l.networks) > 0 {
		parts = append(parts, plural(len(l.networks), "network"))
	}
	if len(l.dirs) > 0 || l.migrationFence != "" || l.credentials {
		parts = append(parts, "files the machine kept for it")
	}
	return strings.Join(parts, ", ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// planLeftovers plans the removal of what an app that is no longer on the
// machine left behind. Only --data asks for it: nothing of the app runs,
// so what is left is its data and the secrets that open it.
func (r Remove) planLeftovers(ctx context.Context, in RemoveInput, stateDir string) (*kernel.Plan, error) {
	if !manifest.ValidApp(in.App) {
		return nil, fmt.Errorf("%q isn't the name of an app", in.App)
	}
	l, err := r.findLeftovers(ctx, in.App, stateDir)
	if err != nil {
		return nil, err
	}
	if l.empty() {
		return nil, fmt.Errorf("%s isn't on this machine, and nothing of it is left here", in.App)
	}
	if !in.Data {
		return nil, fmt.Errorf("%s isn't on this machine, but it left %s behind; helios remove %s --data removes what is left (only a backup brings it back)", in.App, l.summary(), in.App)
	}
	plan := &kernel.Plan{Target: in.App, Recovery: kernel.Resume}
	if len(l.containers) > 0 || len(l.images) > 0 {
		plan.Steps = append(plan.Steps, l.containersStep())
	}
	if len(l.volumes) > 0 {
		plan.Steps = append(plan.Steps, l.volumesStep())
	}
	if len(l.networks) > 0 {
		plan.Steps = append(plan.Steps, l.networksStep())
	}
	if l.secretVersion > 0 {
		plan.Steps = append(plan.Steps, l.secretsStep(r))
	}
	plan.Steps = append(plan.Steps, l.forgetStep(r, stateDir))
	return plan, nil
}

// findLeftovers looks for everything of an app on the machine. A volume
// is the app's by helios's naming, bedrock-<app>-<volume>; a hyphen can
// sit in an app's name too, so one that fits another app still known
// here (loom-runner's, looking for loom's) is left to that app.
func (r Remove) findLeftovers(ctx context.Context, app, stateDir string) (*leftovers, error) {
	l := &leftovers{app: app}
	if r.Secrets != nil {
		names, version, err := r.Secrets.Names(app)
		if err != nil {
			return nil, err
		}
		l.secretNames, l.secretVersion = names, version
		own, _, err := r.Secrets.Names(integration.App)
		if err != nil {
			return nil, err
		}
		l.credentials = slices.Contains(own, integration.WebhookSecretName(app)) || slices.Contains(own, integration.DeployKeyName(app))
	}
	others, err := r.otherApps(ctx, app)
	if err != nil {
		return nil, err
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("looking for what %s left behind: %w", app, err)
	}
	defer e.Close()
	owned, err := e.Owned(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range owned {
		if c.Labels[docker.LabelApp] == app {
			l.containers = append(l.containers, c.Name)
		}
	}
	images, err := e.OwnedImages(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		if img.Labels[docker.LabelApp] == app {
			l.images = append(l.images, img.ID)
		}
	}
	slices.Sort(l.containers)
	slices.Sort(l.images)
	volumes, err := e.Volumes(ctx, "bedrock-"+app)
	if err != nil {
		return nil, err
	}
	for _, v := range volumes {
		if volumeOf(v, app, others) {
			l.volumes = append(l.volumes, v)
		}
	}
	// Its own network, a drill's, and the one it shared with the edge.
	for _, want := range []string{docker.AppNetwork(app), drillPrefix(app), edge.AppNetwork(app)} {
		found, err := e.Networks(ctx, want)
		if err != nil {
			return nil, err
		}
		if slices.Contains(found, want) {
			l.networks = append(l.networks, want)
		}
	}
	for _, dir := range appDirs(stateDir, app) {
		if _, err := os.Stat(dir); err == nil {
			l.dirs = append(l.dirs, dir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	fence := migrationFile(r.Store.Path(), app)
	if _, err := os.Stat(fence); err == nil {
		l.migrationFence = fence
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return l, nil
}

// otherApps are the apps this machine still knows besides app: deployed,
// or holding secrets they left behind.
func (r Remove) otherApps(ctx context.Context, app string) ([]string, error) {
	known, err := r.Store.AppNames(ctx)
	if err != nil {
		return nil, err
	}
	if r.Secrets != nil {
		sealed, err := r.Secrets.Apps()
		if err != nil {
			return nil, err
		}
		known = append(known, sealed...)
	}
	return slices.DeleteFunc(known, func(name string) bool { return name == app }), nil
}

// volumeOf reports whether a volume is one of app's by name: one of its
// own, bedrock-<app>-<volume>, that no other known app's name fits
// better, or one a drill of it made, bedrock-<app>.drill.<volume>.
func volumeOf(volume, app string, others []string) bool {
	if strings.HasPrefix(volume, drillPrefix(app)+".") {
		return true
	}
	if !strings.HasPrefix(volume, docker.VolumeName(app, "")) {
		return false
	}
	for _, other := range others {
		if len(other) > len(app) && strings.HasPrefix(volume, docker.VolumeName(other, "")) {
			return false
		}
	}
	return true
}

// drillPrefix starts the names of what a drill of app makes.
func drillPrefix(app string) string { return "bedrock-" + app + ".drill" }

// appDirs are the directories the machine keeps for an app under its
// state directory: its database's first-run scripts, and the staging
// directories of backups, restores, drills, builds and moves.
func appDirs(stateDir, app string) []string {
	dirs := []string{filepath.Dir(InitDir(stateDir, app))}
	for _, d := range []string{"backups", "restore", "drills", "builds", "moves"} {
		dirs = append(dirs, filepath.Join(stateDir, d, app))
	}
	return dirs
}

func (l *leftovers) containersStep() kernel.Step {
	change := fmt.Sprintf("remove the containers and images %s left", l.app)
	var what []string
	if len(l.containers) > 0 {
		what = append(what, strings.Join(l.containers, ", "))
	}
	if len(l.images) > 0 {
		what = append(what, plural(len(l.images), "image"))
	}
	change += ": " + strings.Join(what, "; ")
	return kernel.Step{
		Name: "containers", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			for _, name := range l.containers {
				if err := e.Remove(ctx, name, 60*time.Second); err != nil {
					return err
				}
				fmt.Fprintf(out, "%s removed\n", name)
			}
			for _, id := range l.images {
				if err := e.RemoveImage(ctx, id); err != nil {
					fmt.Fprintf(out, "image %s stays: %v\n", id, err)
				}
			}
			return nil
		},
	}
}

func (l *leftovers) volumesStep() kernel.Step {
	named := make([]string, len(l.volumes))
	for i, v := range l.volumes {
		named[i] = v
		if v == docker.VolumeName(l.app, postgresWorkload) {
			named[i] += " (its database)"
		}
	}
	return kernel.Step{
		Name:   "volumes",
		Change: fmt.Sprintf("remove %s's volumes: %s (no way back except a backup)", l.app, strings.Join(named, ", ")),
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			if err := checkVolumeRemoval(ctx, e, l.volumes); err != nil {
				return err
			}
			for _, v := range l.volumes {
				removed, err := e.RemoveVolume(ctx, v)
				if err != nil {
					return err
				}
				if removed {
					fmt.Fprintf(out, "volume %s removed\n", v)
				}
			}
			return nil
		},
	}
}

func (l *leftovers) networksStep() kernel.Step {
	return kernel.Step{
		Name:   "networks",
		Change: fmt.Sprintf("remove %s's networks: %s", l.app, strings.Join(l.networks, ", ")),
		Apply: func(ctx context.Context, out io.Writer) error {
			e, err := docker.Connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			for _, n := range l.networks {
				if n == edge.AppNetwork(l.app) {
					err = edge.Leave(ctx, e, l.app)
				} else {
					err = e.RemoveNetwork(ctx, n)
				}
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "network %s removed\n", n)
			}
			return nil
		},
	}
}

func (l *leftovers) secretsStep(r Remove) kernel.Step {
	return kernel.Step{
		Name: "secrets",
		Change: fmt.Sprintf("forget %s's sealed secrets: %s at version %d (only a machine backup made before now, helios backup helios, keeps them)",
			l.app, plural(len(l.secretNames), "name"), l.secretVersion),
		Apply: func(ctx context.Context, out io.Writer) error {
			if err := r.Secrets.RemoveApp(l.app); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s's secrets forgotten\n", l.app)
			return nil
		},
	}
}

func (l *leftovers) forgetStep(r Remove, stateDir string) kernel.Step {
	change := fmt.Sprintf("forget whatever else the machine keeps about %s", l.app)
	var kept []string
	if len(l.dirs) > 0 {
		kept = append(kept, strings.Join(l.dirs, ", "))
	}
	if l.migrationFence != "" {
		kept = append(kept, l.migrationFence)
	}
	if l.credentials {
		kept = append(kept, "the webhook secret and deploy key made for it")
	}
	if len(kept) > 0 {
		change += ": " + strings.Join(kept, "; ")
	}
	change += "; its backups in the storage bucket stay, and are the only way to bring its data back"
	return kernel.Step{
		Name: "forget", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			// The secrets have their own step, named in the plan.
			if err := forgetApp(ctx, r.Store, r.Secrets, stateDir, l.app, false, out); err != nil {
				return err
			}
			for _, dir := range l.dirs {
				if err := os.RemoveAll(dir); err != nil {
					return err
				}
			}
			fmt.Fprintf(out, "what %s left is gone\n", l.app)
			return nil
		},
	}
}
