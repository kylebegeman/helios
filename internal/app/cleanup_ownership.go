package app

import (
	"context"
	"fmt"
	"slices"

	"github.com/kylebegeman/helios/internal/docker"
)

// checkVolumeRemoval preserves volumes another system explicitly owns. Older
// app volumes can be unlabeled, so use the same ownership policy as mounting
// them. Inspect existence first to avoid creating volumes just to remove them.
func checkVolumeRemoval(ctx context.Context, e *docker.Engine, names []string) error {
	existing, err := e.Volumes(ctx, "")
	if err != nil {
		return err
	}
	for _, name := range names {
		if slices.Contains(existing, name) {
			if err := e.EnsureVolume(ctx, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkScratchRemoval validates all expected resources before any writer or
// data is removed. Scratch names alone do not authorize adopting resources.
func checkScratchRemoval(ctx context.Context, e *docker.Engine, names drillNames, app string) error {
	roles := map[string]string{names.postgres: "drill", names.objects: "drill"}
	for workload, name := range names.containers {
		roles[name] = workload
	}
	for _, name := range sortedKeys(roles) {
		info, err := e.Inspect(ctx, name)
		if docker.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Labels[docker.LabelOwner] != docker.OwnerValue || info.Labels[docker.LabelApp] != app || info.Labels[docker.LabelWorkload] != roles[name] {
			return fmt.Errorf("scratch container %s belongs to another owner or workload; refusing cleanup", name)
		}
	}
	if found, err := e.NetworkExists(ctx, names.network); err != nil {
		return err
	} else if found {
		owned, err := e.Networks(ctx, names.network)
		if err != nil {
			return err
		}
		if !slices.Contains(owned, names.network) {
			return fmt.Errorf("scratch network %s belongs to another owner; refusing cleanup", names.network)
		}
	}
	volumes := []string{names.postgresVolume}
	for _, name := range sortedKeys(names.volumes) {
		volumes = append(volumes, names.volumes[name])
	}
	return checkVolumeRemoval(ctx, e, volumes)
}
