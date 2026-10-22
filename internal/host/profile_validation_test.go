package host

import (
	"context"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/kernel"
)

func TestProfileTimezoneMustNameAKnownLocation(t *testing.T) {
	for _, zone := range []string{"", "UTC", "Etc/UTC", "America/New_York"} {
		if err := (Profile{Hostname: "box", Timezone: zone}).Validate(); err != nil {
			t.Errorf("valid timezone %q: %v", zone, err)
		}
	}
	for _, zone := range []string{"Local", "not/a-timezone", "../UTC", "America/New_York\n"} {
		if err := (Profile{Hostname: "box", Timezone: zone}).Validate(); err == nil {
			t.Errorf("accepted invalid profile timezone %q", zone)
		}
	}
}

func TestSetupRefusesInvalidTimezoneBeforeInspectingOrChangingTheMachine(t *testing.T) {
	m := freshUbuntu(t)
	engine := kernel.New(openStore(t), registryWith(m), "test")
	_, err := engine.Run(context.Background(), SetupKind, profileJSON(t, Profile{Hostname: "box", Timezone: "not/a-timezone"}), func(kernel.Event) {})
	if err == nil || !strings.Contains(err.Error(), "timezone") {
		t.Fatalf("invalid timezone reached setup: %v", err)
	}
	if commands := m.commands(); len(commands) != 0 {
		t.Fatalf("invalid profile reached machine inspection or mutation: %v", commands)
	}
}
