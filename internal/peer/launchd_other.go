//go:build !darwin

package peer

import (
	"context"
	"errors"
)

// errNotMacOS is why there is no launch agent to install or remove here.
var errNotMacOS = errors.New("the launch agent is for macOS; run helios peer observe from cron instead")

// InstallLaunchAgent is for macOS; it refuses everywhere else.
func InstallLaunchAgent(context.Context, string, func(ctx context.Context, args ...string) error) (plist, log string, err error) {
	return "", "", errNotMacOS
}

// UninstallLaunchAgent is for macOS; it refuses everywhere else.
func UninstallLaunchAgent(context.Context, func(ctx context.Context, args ...string) error) (string, bool, error) {
	return "", false, errNotMacOS
}
