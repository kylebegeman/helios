package app

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"testing"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
)

func TestRemovingAppDataRetainsExplicitlyForeignVolumes(t *testing.T) {
	for _, hasHistory := range []bool{false, true} {
		t.Run(map[bool]string{false: "leftovers", true: "recorded-app"}[hasHistory], func(t *testing.T) {
			store := releaseTestStore(t)
			if hasHistory {
				seedManifest(t, store, "site", `{"app":"site","data":{"volumes":{"files":{}}},"workloads":{"web":{"kind":"worker","image":"x"}}}`)
			}
			fake := dockertest.New(t)
			volume := docker.VolumeName("site", "files")
			fake.AddVolume(volume, map[string]string{docker.LabelOwner: "another-system"})
			raw, _ := json.Marshal(RemoveInput{App: "site", Data: true})
			plan, err := (Remove{Store: store, StateDir: t.TempDir()}).Plan(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range plan.Steps {
				if step.Name == "data" || step.Name == "volumes" {
					if err := step.Apply(context.Background(), io.Discard); err == nil {
						t.Fatal("cleanup accepted an explicitly foreign volume")
					}
					if !slices.Contains(fake.VolumeNames(), volume) {
						t.Fatal("cleanup deleted an explicitly foreign volume")
					}
					return
				}
			}
			t.Fatal("test did not reach data cleanup")
		})
	}
}
