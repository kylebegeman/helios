package integration

import (
	"fmt"
	"sync"
	"testing"
)

func TestConcurrentIntegrationEditsKeepEveryNamedChange(t *testing.T) {
	store := newStore(t)
	if _, _, err := Set(store, StorageName, map[string]string{"kind": "b2", "key_id": "old-id", "key": "old-key", "bucket_prefix": "old-prefix", "password": "old-password"}); err != nil {
		t.Fatal(err)
	}
	changes := map[string]string{"key_id": "new-id", "key": "new-key", "bucket_prefix": "new-prefix", "password": "new-password"}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for field, value := range changes {
		workers.Go(func() {
			<-start
			if _, _, err := Set(store, StorageName, map[string]string{field: value}); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	workers.Wait()
	got, err := Get(store, StorageName)
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range changes {
		if got[field] != want {
			t.Errorf("concurrent edit to %s was lost", field)
		}
	}
}

func TestConcurrentStorageSetupGeneratesOnlyOneBackupPassword(t *testing.T) {
	store := newStore(t)
	start := make(chan struct{})
	generated := make(chan bool, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			<-start
			_, made, err := Set(store, StorageName, map[string]string{"kind": "b2", "key_id": "fixture-id", "key": "fixture-key", "bucket_prefix": "fixture"})
			if err != nil {
				t.Error(err)
			}
			generated <- len(made) != 0
		})
	}
	close(start)
	workers.Wait()
	close(generated)
	count := 0
	for made := range generated {
		if made {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("generated %d backup passwords, want exactly one", count)
	}
}

func TestConcurrentImportsCannotReplaceDifferentCredentialsWithoutApproval(t *testing.T) {
	store := newStore(t)
	start := make(chan struct{})
	results := make(chan error, 8)
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Go(func() {
			<-start
			_, err := applyValues(store, map[string]map[string]string{CloudflareName: {"token": fmt.Sprintf("fixture-%d", i)}}, false, false)
			results <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d conflicting imports succeeded without --replace, want one", succeeded)
	}
}

func TestRecoveryPublishesIntegrationAndOperationalCredentialsTogether(t *testing.T) {
	source, target, _ := transferStores(t)
	if _, _, err := Set(source, CloudflareName, map[string]string{"token": "fixture-token"}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Set(App, "DEPLOY_KEY_API", "fixture-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverMissing(target, source); err != nil {
		t.Fatal(err)
	}
	versions, err := target.Versions(App)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions {
		values, err := target.Load(App, version.Version)
		if err != nil {
			t.Fatal(err)
		}
		if values["CLOUDFLARE_TOKEN"] != "fixture-token" || values["DEPLOY_KEY_API"] != "fixture-key" {
			t.Fatal("recovery committed a partial credential snapshot")
		}
	}
}
