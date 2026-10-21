package compat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestMachineIdentityDoesNotEchoInvalidPublicRecipientContents(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		contents string
	}{
		{name: "private identity", contents: identity.String()},
		{name: "other sensitive text", contents: "fixture-sensitive-file-contents"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "secrets.key")
			if err := os.WriteFile(keyPath+".pub", []byte(tc.contents+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			id, err := MachineIdentity(keyPath, os.ReadFile, func() (string, error) {
				t.Fatal("invalid public recipient must not fall back to OS identity")
				return "", nil
			})
			if err == nil || id != "" {
				t.Fatal("invalid public recipient was accepted")
			}
			if strings.Contains(err.Error(), tc.contents) {
				t.Fatal("machine identity error exposes the public recipient file contents")
			}
			if !strings.Contains(err.Error(), "machine public recipient") {
				t.Fatal("machine identity error does not identify the invalid public recipient")
			}
		})
	}
}
