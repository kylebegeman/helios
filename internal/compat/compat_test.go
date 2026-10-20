package compat

import (
	"errors"
	"filippo.io/age"
	"os"
	"testing"
)

func TestMachineIdentityUsesOnlyPublicRecipientAndFallbackIsStable(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	reads := []string{}
	read := func(path string) ([]byte, error) {
		reads = append(reads, path)
		return []byte(key.Recipient().String() + "\n"), nil
	}
	id, err := MachineIdentity("/private/key", read, func() (string, error) { t.Fatal("public key must win"); return "", nil })
	if err != nil || id != "age:"+key.Recipient().String() || len(reads) != 1 || reads[0] != "/private/key.pub" {
		t.Fatalf("%s %v %v", id, err, reads)
	}
	missing := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	first, err := MachineIdentity("/private/key", missing, func() (string, error) { return "machine-123\n", nil })
	second, _ := MachineIdentity("/private/key", missing, func() (string, error) { return "machine-123", nil })
	if err != nil || first == "" || first != second {
		t.Fatalf("%s %s %v", first, second, err)
	}
}

func TestMachineIdentityDoesNotHideInvalidOrUnreadablePublicKeys(t *testing.T) {
	for _, read := range []func(string) ([]byte, error){func(string) ([]byte, error) { return []byte("invalid"), nil }, func(string) ([]byte, error) { return nil, os.ErrPermission }} {
		_, err := MachineIdentity("key", read, func() (string, error) { t.Fatal("fallback hides key failure"); return "", nil })
		if err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	_, err := MachineIdentity("", nil, func() (string, error) { return "", errors.New("unavailable") })
	if err == nil {
		t.Fatal("missing OS identity accepted")
	}
}
func TestCandidateCompatibilityRejectsUnsupportedDowngradesAndUnsafeMigrations(t *testing.T) {
	base := Info{APIVersion: 1, ManifestVersion: 1, StateVersion: 1, MinStateVersion: 0, MaxStateVersion: 1}
	if err := base.AcceptsState(0); err != nil {
		t.Fatal(err)
	}
	if err := base.AcceptsState(1); err != nil {
		t.Fatal(err)
	}
	downgrade := base
	downgrade.StateVersion = 0
	downgrade.MaxStateVersion = 0
	if err := downgrade.AcceptsState(1); err == nil {
		t.Fatal("incompatible downgrade accepted")
	}
	future := base
	future.StateVersion = 2
	future.MaxStateVersion = 2
	if err := future.AcceptsState(1); err == nil {
		t.Fatal("automatic rollback would read a newer schema")
	}
}

// A client asks a target for a feature only when the target names it, so a
// feature this build has but doesn't name is never used remotely.
func TestCapabilitiesNameEachFeatureOnce(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range capabilities {
		if seen[name] {
			t.Fatalf("%s is named twice", name)
		}
		seen[name] = true
	}
	for _, want := range []string{"remote.source.v1", "git.signed.v1", "edge.origin-pull.v1", "exec.interactive.v1"} {
		if !seen[want] {
			t.Fatalf("capabilities lack %s: %v", want, capabilities)
		}
	}
}
