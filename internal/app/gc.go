package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

// GCKind removes what helios created and no longer needs: containers and
// images of revisions that are neither active nor kept for rollback, and
// the build cache. It never touches anything without helios's label.
const GCKind = "app.gc"

// DefaultBuildCacheMax is how much build cache a machine keeps.
//
// Build cache is a speed optimisation, not data: losing it costs one slow
// build and nothing else. A machine iterating on a large source tree can
// produce tens of gigabytes of it in a day, so the ceiling is deliberately
// far below what an unbounded cache reaches. Raise it with --keep-cache on
// a machine that rebuilds something huge and has the disk to spare.
const DefaultBuildCacheMax = 8 << 30 // 8 GiB

// GC is the Definition for GCKind.
type GC struct {
	Store *state.Store
}

// GCInput configures a collection.
type GCInput struct {
	// KeepBuildCache leaves Docker's build cache alone.
	KeepBuildCache bool `json:"keep_build_cache,omitempty"`

	// BuildCacheMax is how many bytes of build cache to keep. Zero means
	// DefaultBuildCacheMax; a negative value keeps no ceiling at all.
	BuildCacheMax int64 `json:"build_cache_max,omitempty"`
}

// Kind implements kernel.Definition.
func (GC) Kind() string { return GCKind }

// Plan implements kernel.Definition.
func (g GC) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	var in GCInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("gc input: %w", err)
		}
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return nil, err
	}
	defer e.Close()
	keep, err := gcResourcesToKeep(ctx, g.Store)
	if err != nil {
		return nil, err
	}
	containersNow, err := staleContainers(ctx, e, keep)
	if err != nil {
		return nil, err
	}
	imagesNow, err := staleImages(ctx, e, keep)
	if err != nil {
		return nil, err
	}

	plan := &kernel.Plan{Target: "this machine", Recovery: kernel.Resume}
	plan.Steps = append(plan.Steps, g.containersStep(len(containersNow)), g.imagesStep(len(imagesNow)))
	if !in.KeepBuildCache {
		plan.Steps = append(plan.Steps, buildCacheStep(in.BuildCacheMax))
	}
	plan.Steps = append(plan.Steps, g.forgetStep())
	return plan, nil
}

// connect opens Docker and works out, at apply time, which revisions stay:
// a deploy may have finished between the plan and this step.
func (g GC) connect(ctx context.Context) (*docker.Engine, *gcRetention, error) {
	e, err := docker.Connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	keep, err := gcResourcesToKeep(ctx, g.Store)
	if err != nil {
		e.Close()
		return nil, nil, err
	}
	return e, keep, nil
}

func (g GC) containersStep(now int) kernel.Step {
	return kernel.Step{
		Name: "containers", Change: "remove containers of revisions that are neither active nor kept for rollback",
		Note: countNote(now, "container"),
		Apply: func(ctx context.Context, out io.Writer) error {
			e, keep, err := g.connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			stale, err := staleContainers(ctx, e, keep)
			if err != nil {
				return err
			}
			for _, c := range stale {
				if err := e.Remove(ctx, c.Name, 5*time.Second); err != nil {
					return err
				}
				fmt.Fprintf(out, "removed %s\n", c.Name)
			}
			return nil
		},
	}
}

func (g GC) imagesStep(now int) kernel.Step {
	return kernel.Step{
		Name: "images", Change: "remove images of revisions that are neither active nor kept for rollback",
		Note: countNote(now, "image"),
		Apply: func(ctx context.Context, out io.Writer) error {
			e, keep, err := g.connect(ctx)
			if err != nil {
				return err
			}
			defer e.Close()
			stale, err := staleImages(ctx, e, keep)
			if err != nil {
				return err
			}
			var freed int64
			for _, img := range stale {
				if err := e.RemoveImage(ctx, img.ID); err != nil {
					return err
				}
				freed += img.Size
				fmt.Fprintf(out, "removed %s\n", img.Describe())
			}
			if freed > 0 {
				fmt.Fprintf(out, "freed %s\n", megabytes(freed))
			}
			return nil
		},
	}
}

// buildCacheStep prunes Docker's build cache. max is GCInput.BuildCacheMax.
func buildCacheStep(max int64) kernel.Step {
	keep := max
	if keep == 0 {
		keep = DefaultBuildCacheMax
	}
	if keep < 0 {
		keep = 0
	}
	change := "drop build cache older than a day"
	if keep > 0 {
		change += ", then keep at most " + megabytes(keep)
	}
	return kernel.Step{
		Name: "build-cache", Change: change,
		Apply: func(ctx context.Context, out io.Writer) error {
			freed, err := docker.PruneBuildCache(ctx, 24*time.Hour, keep)
			if freed > 0 {
				fmt.Fprintf(out, "reclaimed %s of build cache\n", megabytes(freed))
			}
			return err
		},
	}
}

// retiredKept is how many retired or failed revisions an app keeps on
// record after a collection.
const retiredKept = 5

func (g GC) forgetStep() kernel.Step {
	return kernel.Step{
		Name: "forget", Change: "forget retired revisions older than the last five and discard source captures of finished deployments",
		Apply: func(ctx context.Context, out io.Writer) error {
			keep, err := gcResourcesToKeep(ctx, g.Store)
			if err != nil {
				return err
			}
			// Failed first deployments have revision history without an app row.
			apps, err := g.Store.AppNames(ctx)
			if err != nil {
				return err
			}
			for _, app := range apps {
				revs, err := g.Store.Revisions(ctx, app)
				if err != nil {
					return err
				}
				var old []state.Revision
				for _, r := range revs {
					if (r.Status == state.RevisionRetired || r.Status == state.RevisionFailed) && !keep.revisions[r.App+"/"+r.ID] {
						old = append(old, r)
					}
				}
				for _, r := range old[min(retiredKept, len(old)):] {
					if err := g.Store.ForgetRevision(ctx, r.App, r.ID); err != nil {
						return err
					}
					fmt.Fprintf(out, "forgot %s %s\n", r.App, r.ID)
				}
			}
			removed, err := collectDeploySources(ctx, g.Store, filepath.Dir(g.Store.Path()))
			if err != nil {
				return err
			}
			if removed > 0 {
				fmt.Fprintf(out, "removed source captures for %d finished deployment(s)\n", removed)
			}
			return nil
		},
	}
}

// gcRetention keeps both revision authority and image references. Restored
// images can retain their original source labels while a new target revision
// records their immutable image IDs.
type gcRetention struct {
	revisions map[string]bool
	images    map[string]bool
}

// gcResourcesToKeep protects live rollback choices, unfinished target
// migrations, and the code paired with each unconsumed data checkpoint.
func gcResourcesToKeep(ctx context.Context, store *state.Store) (*gcRetention, error) {
	keep := &gcRetention{revisions: map[string]bool{}, images: map[string]bool{}}
	openJobs, err := store.OpenJobRuns(ctx)
	if err != nil {
		return nil, err
	}
	for _, run := range openJobs {
		keep.revisions[run.App+"/"+run.Revision] = true
	}
	boundaries, err := store.ReleaseBoundaries(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, b := range boundaries {
		if !fullSnapshotID.MatchString(b.Snapshot) || b.PreviousRevision == "" {
			continue
		}
		switch b.Status {
		case state.ReleasePrepared, state.ReleaseStarted, state.ReleaseCompleted, state.ReleaseFailed, state.ReleaseRestoring:
			keep.revisions[b.App+"/"+b.PreviousRevision] = true
		}
	}
	// A destination that has only staged revisions has no active app row yet.
	apps, err := store.AppNames(ctx)
	if err != nil {
		return nil, err
	}
	for _, app := range apps {
		record, err := readMigration(store.Path(), app)
		if err != nil {
			return nil, err
		}
		if record != nil && record.Role == "target" && record.Phase != "cutover" {
			keep.revisions[app+"/"+record.TargetRevision] = true
		}
		revs, err := store.Revisions(ctx, app)
		if err != nil {
			return nil, err
		}
		for _, r := range revs {
			key := r.App + "/" + r.ID
			if r.Status == state.RevisionActive || r.Status == state.RevisionPrevious {
				keep.revisions[key] = true
			}
			if keep.revisions[key] {
				for _, ref := range r.Images {
					keep.images[ref] = true
				}
			}
		}
	}
	return keep, nil
}

// staleContainers are helios's containers that belong to a revision nobody
// keeps. Containers without a revision label (the edge, the registry) stay.
func staleContainers(ctx context.Context, e *docker.Engine, keep *gcRetention) ([]docker.Info, error) {
	owned, err := e.Owned(ctx)
	if err != nil {
		return nil, err
	}
	var stale []docker.Info
	for _, c := range owned {
		rev := c.Labels[docker.LabelRevision]
		if rev == "" || keep.revisions[c.Labels[docker.LabelApp]+"/"+rev] {
			continue
		}
		stale = append(stale, c)
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].Name < stale[j].Name })
	return stale, nil
}

// staleImages are images helios built for revisions nobody keeps.
func staleImages(ctx context.Context, e *docker.Engine, keep *gcRetention) ([]docker.Image, error) {
	images, err := e.OwnedImages(ctx)
	if err != nil {
		return nil, err
	}
	var stale []docker.Image
	for _, img := range images {
		rev := img.Labels[docker.LabelRevision]
		if rev == "" || keep.revisions[img.Labels[docker.LabelApp]+"/"+rev] || keep.images[img.ID] {
			continue
		}
		referenced := false
		for _, ref := range append(img.Tags, img.Digests...) {
			if keep.images[ref] {
				referenced = true
				break
			}
		}
		if !referenced {
			stale = append(stale, img)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].Describe() < stale[j].Describe() })
	return stale, nil
}

func countNote(n int, what string) string {
	switch n {
	case 0:
		return "nothing to remove"
	case 1:
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

func megabytes(b int64) string {
	if b >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	}
	return fmt.Sprintf("%d MB", b>>20)
}
