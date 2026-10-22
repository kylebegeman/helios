package kernel

import "context"

type operationIDKey struct{}

// OperationID is the journaled operation running a step or being replanned
// during recovery. It is empty during initial planning and when a step is
// called directly, outside the engine.
func OperationID(ctx context.Context) string {
	id, _ := ctx.Value(operationIDKey{}).(string)
	return id
}
func withOperationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, operationIDKey{}, id)
}
