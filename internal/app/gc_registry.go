package app

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/state"
)

// registryStep deletes the images builds pushed to the local registry for
// revisions helios no longer has on record, then reclaims their storage.
func (g GC) registryStep() kernel.Step {
	return kernel.Step{
		Name: "registry", Change: "delete local registry images of revisions helios no longer has on record, then reclaim their storage",
		Apply: func(ctx context.Context, out io.Writer) error {
			sweep, err := newRegistrySweep(ctx, g.Store, docker.NewRegistryClient(cmp.Or(g.Registry, docker.Registry)))
			if err != nil {
				return err
			}
			deleted, err := sweep.run(ctx, out)
			if err != nil || deleted == 0 {
				return err
			}
			freed, err := docker.CollectRegistry(ctx)
			if freed > 0 {
				fmt.Fprintf(out, "reclaimed %s of registry storage\n", megabytes(freed))
			}
			return err
		},
	}
}

// registrySweep knows which revisions are on record and which images they
// use, for every app with revision history.
type registrySweep struct {
	reg       *docker.RegistryClient
	apps      map[string]bool
	revisions map[string]bool
	images    map[string]bool
}

func newRegistrySweep(ctx context.Context, store *state.Store, reg *docker.RegistryClient) (*registrySweep, error) {
	keep, err := gcResourcesToKeep(ctx, store)
	if err != nil {
		return nil, err
	}
	s := &registrySweep{reg: reg, apps: map[string]bool{}, revisions: keep.revisions, images: keep.images}
	apps, err := store.AppNames(ctx)
	if err != nil {
		return nil, err
	}
	for _, app := range apps {
		s.apps[app] = true
		revs, err := store.Revisions(ctx, app)
		if err != nil {
			return nil, err
		}
		for _, r := range revs {
			s.revisions[r.App+"/"+r.ID] = true
			for _, ref := range r.Images {
				s.images[ref] = true
			}
		}
	}
	return s, nil
}

// run deletes in the repositories builds push to, app/workload, and
// returns how many tags it deleted.
func (s *registrySweep) run(ctx context.Context, out io.Writer) (int, error) {
	repos, err := s.reg.Repositories(ctx)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, repo := range repos {
		app, workload, ok := strings.Cut(repo, "/")
		if !ok || strings.Contains(workload, "/") || !s.apps[app] {
			continue
		}
		n, err := s.repository(ctx, repo, app, out)
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// repository deletes the tags of revisions no longer on record whose image
// no revision on record uses.
func (s *registrySweep) repository(ctx context.Context, repo, app string, out io.Writer) (int, error) {
	tags, err := s.reg.Tags(ctx, repo)
	if err != nil {
		return 0, err
	}
	var stale []string
	for _, tag := range tags {
		if isRevisionID(tag) && !s.revisions[app+"/"+tag] {
			stale = append(stale, tag)
		}
	}
	if len(stale) == 0 {
		return 0, nil
	}
	manifests := map[string]docker.RegistryManifest{}
	for _, tag := range tags {
		if manifests[tag], err = s.reg.Manifest(ctx, repo, tag); err != nil {
			return 0, err
		}
	}
	var doomed []string
	for _, tag := range stale {
		if d := manifests[tag].Digest; !s.images[docker.Registry+"/"+repo+"@"+d] && !s.images[d] {
			doomed = append(doomed, tag)
		}
	}
	// Deleting by digest takes every tag on the manifest with it, and
	// deleting a listed manifest breaks every index that lists it.
	inUse := map[string]bool{}
	for _, tag := range tags {
		if m := manifests[tag]; m.Digest != "" && !slices.Contains(doomed, tag) {
			inUse[m.Digest] = true
			for _, d := range m.Manifests {
				inUse[d] = true
			}
		}
	}
	for i, tag := range doomed {
		refs := []string{tag}
		if m := manifests[tag]; m.Digest != "" && !inUse[m.Digest] {
			refs = []string{m.Digest}
			for _, d := range m.Manifests {
				if !inUse[d] {
					refs = append(refs, d)
				}
			}
		}
		for _, ref := range refs {
			if err := s.reg.Delete(ctx, repo, ref); err != nil {
				return i, err
			}
		}
		fmt.Fprintf(out, "deleted %s:%s\n", repo, tag)
	}
	return len(doomed), nil
}

// isRevisionID reports whether tag is a revision's ID as NewRevision makes it.
func isRevisionID(tag string) bool {
	at, err := time.Parse("20060102-150405", tag)
	return err == nil && NewRevision(at) == tag
}
