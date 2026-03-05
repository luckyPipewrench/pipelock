package mcp

import (
	"encoding/json"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

// maxTrackedRequests caps the number of pending request IDs to prevent
// unbounded memory growth from a compromised client sending requests
// without consuming responses. Same cap pattern as tool baseline (10,000).
const maxTrackedRequests = 10000

// RequestTracker records outbound JSON-RPC request IDs and validates
// that inbound response IDs match a previously tracked request. This
// prevents confused deputy attacks where a malicious MCP server sends
// unsolicited responses with IDs the client never used.
//
// A nil tracker passes all IDs through (feature disabled).
type RequestTracker struct {
	mu      sync.Mutex
	pending map[string]struct{}
	// order preserves insertion order for FIFO eviction when cap is reached.
	order []string
	// seeded is true once at least one request ID has been tracked.
	// Validate only rejects unsolicited IDs after the tracker has been seeded,
	// so responses arriving before any request tracking (e.g., during MCP
	// server initialization) pass through instead of being blocked.
	seeded bool
}

// NewRequestTracker creates a tracker with an empty pending set.
func NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		pending: make(map[string]struct{}),
	}
}

// Track records a request ID as pending. Nil/null IDs are ignored
// (notifications don't expect responses). If the pending set exceeds
// maxTrackedRequests, the oldest entry is evicted.
func (t *RequestTracker) Track(id json.RawMessage) {
	if t == nil {
		return
	}
	key := canonicalID(id)
	if key == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.pending[key]; exists {
		return // already tracked
	}

	// Evict oldest if at capacity.
	if len(t.pending) >= maxTrackedRequests {
		oldest := t.order[0]
		delete(t.pending, oldest)
		t.order = t.order[1:]
	}

	t.pending[key] = struct{}{}
	t.order = append(t.order, key)
	t.seeded = true
}

// Validate checks whether id was previously tracked, consuming it on
// match (one-shot). Returns true if the ID is valid (was tracked or is
// nil/null). A nil tracker always returns true (feature disabled).
func (t *RequestTracker) Validate(id json.RawMessage) bool {
	if t == nil {
		return true
	}
	key := canonicalID(id)
	if key == "" {
		// Nil/null IDs: notifications and server-initiated requests.
		return true
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.pending[key]; !ok {
		return false
	}
	delete(t.pending, key)
	// Remove from order slice. Linear scan is acceptable because n
	// is bounded by maxTrackedRequests (10,000) and MCP message rates are low.
	for i, k := range t.order {
		if k == key {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
	return true
}

// Seeded reports whether at least one request ID has been tracked.
// Used by ForwardScanned to skip validation during server initialization
// (before any client request has been sent). A nil tracker returns false.
func (t *RequestTracker) Seeded() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seeded
}

// canonicalID normalizes a JSON-RPC ID to a canonical string for map
// lookup. Returns "" for nil, empty, or "null" IDs (notifications).
// The canonical form preserves the raw JSON representation so numeric
// IDs (1) and string IDs ("1") remain distinct.
func canonicalID(id json.RawMessage) string {
	if len(id) == 0 || string(id) == jsonrpc.Null {
		return ""
	}
	return string(id)
}
