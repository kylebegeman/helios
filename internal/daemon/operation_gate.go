package daemon

import (
	"context"
	"encoding/json"

	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/kernel"
)

// The operation lock serializes execution; a persistent recovery reservation
// retains authority across restarts and between private restore and cutover.
type recoveryGuard struct {
	stateFile  string
	definition kernel.Definition
}

func (g recoveryGuard) Kind() string { return g.definition.Kind() }
func (g recoveryGuard) Plan(ctx context.Context, raw json.RawMessage) (*kernel.Plan, error) {
	if err := app.CheckMachineRecoveryAccess(g.stateFile, g.Kind(), raw); err != nil {
		return nil, err
	}
	return g.definition.Plan(ctx, raw)
}

// Abandon passes kernel.Abandoner on to the definition it guards, which
// Recover could not otherwise reach through the guard. It does so even
// while a recovery reserves the machine: Recover ends the operation all
// the same, and what the definition closes is that operation's own.
func (g recoveryGuard) Abandon(ctx context.Context, operation, reason string) {
	if a, ok := g.definition.(kernel.Abandoner); ok {
		a.Abandon(ctx, operation, reason)
	}
}
