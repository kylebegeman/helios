package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// The reservation contains no secrets and survives uploaded source cleanup.
// Scratch names include the candidate revision, so compensation cannot collide
// with a later normal drill or another migration's rehearsal.
type moveTestReservation struct {
	Input    MoveStageInput    `json:"input"`
	Manifest manifest.Manifest `json:"manifest"`
	Commit   string            `json:"commit,omitempty"`
}

func readMoveTestReservation(path string, input MoveStageInput) (*moveTestReservation, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record moveTestReservation
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("read move test reservation: %w", err)
	}
	if record.Input.Source != input.Source || record.Input.Manifest != input.Manifest || record.Input.Commit != input.Commit || record.Input.Revision != input.Revision ||
		!sameMigration(record.Input.Handoff, input.Handoff) || record.Input.Handoff.Snapshot != input.Handoff.Snapshot {
		return nil, errors.New("interrupted move test reservation does not match this request")
	}
	if err := record.Manifest.Validate(); err != nil {
		return nil, err
	}
	return &record, nil
}

func checkMoveTestAdmission(ctx context.Context, store *state.Store, app string) error {
	if err := checkReleaseStoreAccess(ctx, store, app); err != nil {
		return err
	}
	if active, err := store.RevisionWithStatus(ctx, app, state.RevisionActive); err != nil {
		return err
	} else if active != nil {
		return errors.New("move test requires a clean destination; use a local drill for an app already active here")
	}
	return CheckMigrationAccess(store.Path(), app)
}

func cleanupMoveTest(ctx context.Context, r *rollout, names drillNames, workspace, reservation string) error {
	_, err := os.Stat(reservation)
	reserved := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	e, err := docker.Connect(ctx)
	if err != nil {
		return err
	}
	defer e.Close()
	containers := []string{names.postgres, names.objects}
	roles := map[string]string{names.postgres: "drill", names.objects: "drill"}
	for _, name := range sortedKeys(names.containers) {
		containers = append(containers, names.containers[name])
		roles[names.containers[name]] = name
	}
	// Even a reserved name cannot authorize deleting a foreign container.
	for _, name := range containers {
		info, err := e.Inspect(ctx, name)
		if docker.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !reserved {
			return fmt.Errorf("move test scratch container %s has no ownership reservation; refusing cleanup", name)
		}
		if info.Labels[docker.LabelOwner] != docker.OwnerValue || info.Labels[docker.LabelApp] != r.m.App || info.Labels[docker.LabelWorkload] != roles[name] {
			return fmt.Errorf("move test scratch name %s belongs to another container; refusing cleanup", name)
		}
	}
	if found, err := e.NetworkExists(ctx, names.network); err != nil {
		return err
	} else if found {
		if !reserved {
			return fmt.Errorf("move test scratch network %s has no ownership reservation; refusing cleanup", names.network)
		}
		owned, err := e.Networks(ctx, names.network)
		if err != nil {
			return err
		}
		if !slices.Contains(owned, names.network) {
			return fmt.Errorf("move test scratch network %s is not owned by helios", names.network)
		}
	}
	volumes := []string{names.postgresVolume}
	for _, name := range sortedKeys(names.volumes) {
		volumes = append(volumes, names.volumes[name])
	}
	existingVolumes, err := e.Volumes(ctx, names.network+".")
	if err != nil {
		return err
	}
	for _, name := range volumes {
		if !slices.Contains(existingVolumes, name) {
			continue
		}
		if !reserved {
			return fmt.Errorf("move test scratch volume %s has no ownership reservation; refusing cleanup", name)
		}
		// Creation of an existing volume leaves its labels unchanged and
		// checks the owner, so a replaced foreign volume is never deleted.
		if err := e.EnsureVolume(ctx, name); err != nil {
			return err
		}
	}
	var failures []error
	for _, name := range containers {
		failures = append(failures, e.Remove(ctx, name, 10*time.Second))
	}
	if err := errors.Join(failures...); err != nil {
		return err // Retain volumes if any scratch writer could still run.
	}
	failures = append(failures, e.RemoveNetwork(ctx, names.network))
	for _, name := range volumes {
		_, err := e.RemoveVolume(ctx, name)
		failures = append(failures, err)
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	if revision, err := r.store.GetRevision(ctx, r.m.App, r.revision); err == nil {
		if revision.Status != state.RevisionFailed || manifestDigestFromRaw(revision.Manifest) != manifestDigest(r.m) || revision.Source != r.from.commit {
			return errors.New("move test revision belongs to other app history; refusing cleanup")
		}
	} else if !errors.Is(err, state.ErrNotFound) {
		return err
	}
	if err := r.store.ForgetRevision(ctx, r.m.App, r.revision); err != nil {
		return err
	}
	if err := os.RemoveAll(workspace); err != nil {
		return err
	}
	if err := os.Remove(reservation); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncMigrationDir(filepath.Dir(reservation))
}
