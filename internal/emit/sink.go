package emit

import "context"

// Sink is the interface for external event emission backends.
// Implementations must be safe for concurrent use.
type Sink interface {
	// Emit sends an event to the external system.
	// Implementations should filter by their configured minimum severity.
	Emit(ctx context.Context, event Event) error

	// Close flushes pending events and releases resources.
	Close() error
}
