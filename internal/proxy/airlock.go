// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Transport constants identify request origin for action classification.
const (
	TransportFetch   = "fetch"
	TransportForward = "forward"
	TransportConnect = "connect"
	TransportWS      = "websocket"
	TransportMCP     = "mcp"
	TransportScanAPI = "scan_api"
	TransportReverse = "reverse"
)

// Exemption reason constants for the response_scan_exempt_total metric.
const (
	ExemptReasonDomain   = "exempt_domain"
	ExemptReasonSuppress = "suppress"
)

// Airlock transition source and trigger labels emitted in explain output.
const (
	airlockSourceTriggers = "airlock_triggers"
	airlockSourceAdminAPI = "admin_api"
	airlockSourceTimers   = "airlock_timers"

	airlockTriggerOnElevated = "on_elevated"
	airlockTriggerOnHigh     = "on_high"
	airlockTriggerOnCritical = "on_critical"
	airlockTriggerManual     = "manual"
	airlockTriggerTimer      = "timer"
)

// AirlockTierOrder maps tier names to numeric order for comparison.
// Higher numbers represent more restrictive tiers.
var AirlockTierOrder = map[string]int{
	config.AirlockTierNone:  0,
	config.AirlockTierSoft:  1,
	config.AirlockTierHard:  2,
	config.AirlockTierDrain: 3,
}

// readOnlyMethods are HTTP methods considered read-only and allowed in hard tier.
var readOnlyMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// AirlockState tracks per-session quarantine state with graduated tiers.
// Embedded in SessionState to provide action-class restrictions (read vs write)
// between adaptive enforcement and kill switch.
type AirlockState struct {
	mu          sync.Mutex
	tier        string
	enteredAt   time.Time
	trigger     string
	source      string
	cancelFuncs []context.CancelFunc

	// inFlightCount tracks active requests for drain coordination.
	inFlightCount atomic.Int64
}

// NewAirlockState returns an AirlockState initialized at the none tier.
func NewAirlockState() *AirlockState {
	return &AirlockState{
		tier: config.AirlockTierNone,
	}
}

// Tier returns the current airlock tier (thread-safe).
func (a *AirlockState) Tier() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tier
}

// EnteredAt returns the wall-clock time the current tier was entered.
// Zero value when the session has been reset or never escalated. Callers
// use this to compute elapsed-in-tier for operator explain output and to
// estimate the next auto-deescalation instant.
func (a *AirlockState) EnteredAt() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enteredAt
}

// EntryProvenance returns the trigger/source pair that set the current tier.
// Empty strings mean the tier was entered without explicit provenance.
func (a *AirlockState) EntryProvenance() (trigger, source string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.trigger, a.source
}

// setEntryMetadataLocked records when and why the current tier was entered.
// Entering the none tier clears quarantine metadata entirely.
func (a *AirlockState) setEntryMetadataLocked(tier, trigger, source string) {
	if tier == config.AirlockTierNone {
		a.enteredAt = time.Time{}
		a.trigger = ""
		a.source = ""
		return
	}
	a.enteredAt = time.Now()
	a.trigger = trigger
	a.source = source
}

// SetTier transitions the airlock to a new tier. Upward transitions fast-forward
// through intermediate tiers atomically (none->hard skips soft). Downward
// transitions are rejected; use TryDeescalate for timer-based recovery.
// Returns whether the tier changed, and the previous/new tier for logging.
func (a *AirlockState) SetTier(newTier string) (changed bool, from, to string) {
	return a.SetTierWithProvenance(newTier, "", "")
}

// SetTierWithProvenance transitions the airlock to a new tier and records
// the trigger/source that caused the entry.
func (a *AirlockState) SetTierWithProvenance(newTier, trigger, source string) (changed bool, from, to string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	oldOrder, oldValid := AirlockTierOrder[a.tier]
	newOrder, newValid := AirlockTierOrder[newTier]

	// Reject invalid tiers.
	if !oldValid || !newValid {
		return false, a.tier, a.tier
	}

	// Reject downward transitions (use TryDeescalate instead).
	if newOrder <= oldOrder {
		return false, a.tier, a.tier
	}

	from = a.tier
	a.tier = newTier
	a.setEntryMetadataLocked(newTier, trigger, source)

	// On hard entry, half-close existing connections.
	if newTier == config.AirlockTierHard {
		a.callCancelFuncsLocked()
	}

	// On drain entry, full-close all connections.
	if newTier == config.AirlockTierDrain {
		a.callCancelFuncsLocked()
	}

	return true, from, newTier
}

// TryDeescalate checks whether the current tier's configured timer has expired
// and drops one tier if so. Returns whether a transition occurred and the
// previous/new tier. Zero-value timers disable auto-deescalation for that tier.
func (a *AirlockState) TryDeescalate(timers *config.AirlockTimers) (changed bool, from, to string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tier == config.AirlockTierNone {
		return false, a.tier, a.tier
	}

	var duration time.Duration
	var nextTier string

	switch a.tier {
	case config.AirlockTierSoft:
		if timers.SoftMinutes <= 0 {
			return false, a.tier, a.tier
		}
		duration = time.Duration(timers.SoftMinutes) * time.Minute
		nextTier = config.AirlockTierNone
	case config.AirlockTierHard:
		if timers.HardMinutes <= 0 {
			return false, a.tier, a.tier
		}
		duration = time.Duration(timers.HardMinutes) * time.Minute
		nextTier = config.AirlockTierSoft
	case config.AirlockTierDrain:
		if timers.DrainMinutes <= 0 && timers.DrainTimeoutSeconds <= 0 {
			return false, a.tier, a.tier
		}
		// Drain uses the shorter of DrainMinutes and DrainTimeoutSeconds.
		// DrainTimeoutSeconds is the hard ceiling for in-flight completion.
		duration = time.Duration(timers.DrainMinutes) * time.Minute
		if timers.DrainTimeoutSeconds > 0 {
			drainTimeout := time.Duration(timers.DrainTimeoutSeconds) * time.Second
			if duration <= 0 || drainTimeout < duration {
				duration = drainTimeout
			}
		}
		nextTier = config.AirlockTierHard
	default:
		return false, a.tier, a.tier
	}

	if time.Since(a.enteredAt) < duration {
		return false, a.tier, a.tier
	}

	from = a.tier
	a.tier = nextTier
	a.setEntryMetadataLocked(nextTier, airlockTriggerTimer, airlockSourceTimers)
	return true, from, nextTier
}

// RegisterCancel adds a cancel function for a long-lived connection.
// Called when new connections are established so they can be torn down
// on tier escalation. Stale entries (from normally-closed connections)
// are harmless: cancel/close functions are idempotent, and the slice
// is cleared on ForceSetTier to normal or on session reset.
func (a *AirlockState) RegisterCancel(cancel context.CancelFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// If already at hard/drain, cancel immediately — the escalation
	// that would have torn this down already fired before registration.
	if a.tier == config.AirlockTierHard || a.tier == config.AirlockTierDrain {
		cancel()
		return
	}
	a.cancelFuncs = append(a.cancelFuncs, cancel)
}

// HalfClose cancels all registered long-lived connections (client-to-server).
// Used on hard tier entry to terminate active write channels.
func (a *AirlockState) HalfClose() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.callCancelFuncsLocked()
}

// FullClose cancels all registered connections and marks the session for
// no new connections. Used on drain tier entry.
func (a *AirlockState) FullClose() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.callCancelFuncsLocked()
}

// callCancelFuncsLocked calls and clears all registered cancel functions.
// Must be called with mu held.
func (a *AirlockState) callCancelFuncsLocked() {
	for _, cancel := range a.cancelFuncs {
		cancel()
	}
	a.cancelFuncs = nil
}

// IncrementInFlight atomically increments the in-flight request counter.
func (a *AirlockState) IncrementInFlight() {
	a.inFlightCount.Add(1)
}

// DecrementInFlight atomically decrements the in-flight request counter.
func (a *AirlockState) DecrementInFlight() {
	a.inFlightCount.Add(-1)
}

// InFlight returns the current in-flight request count.
func (a *AirlockState) InFlight() int64 {
	return a.inFlightCount.Load()
}

// ClassifyAction returns whether a request is allowed under the given airlock
// tier. Returns (allowed, reason). Fail-closed: unknown tiers, unknown
// transports, and unclassifiable CONNECT tunnels are all blocked.
//
// Rules by tier:
//   - none/soft: always allowed (soft is observe-only, logging handled upstream)
//   - hard: read-only actions allowed, write actions blocked
//   - drain: everything blocked
func ClassifyAction(tier, method, transport string, isTLSIntercepted bool) (bool, string) {
	switch tier {
	case config.AirlockTierNone, config.AirlockTierSoft:
		return true, ""

	case config.AirlockTierHard:
		return classifyHard(method, transport, isTLSIntercepted)

	case config.AirlockTierDrain:
		return false, "airlock: drain tier blocks all traffic"

	default:
		// Fail-closed: unknown tier blocks.
		return false, "airlock: unknown tier"
	}
}

// classifyHard implements action classification for the hard tier.
func classifyHard(method, transport string, isTLSIntercepted bool) (bool, string) {
	switch transport {
	case TransportFetch:
		// Fetch is read-only by design.
		return true, ""

	case TransportScanAPI:
		// Scan API is evaluation-plane, always allowed.
		return true, ""

	case TransportForward:
		if readOnlyMethods[method] {
			return true, ""
		}
		return false, "airlock: hard tier blocks write methods on forward proxy"

	case TransportConnect:
		if !isTLSIntercepted {
			// Fail-closed: can't classify inner request without TLS interception.
			return false, "airlock: hard tier blocks CONNECT without TLS interception (unclassifiable)"
		}
		// With TLS interception, classify by inner request method.
		if readOnlyMethods[method] {
			return true, ""
		}
		return false, "airlock: hard tier blocks write methods on CONNECT tunnel"

	case TransportWS:
		// Server-to-client (reads) are allowed; client-to-server writes are blocked.
		// The caller distinguishes direction via method: GET = server-to-client,
		// POST = client-to-server with body.
		if method == http.MethodGet {
			return true, ""
		}
		return false, "airlock: hard tier blocks client-to-server WebSocket writes"

	case TransportMCP:
		// MCP classification is delegated to the frozen tool registry.
		// Return allowed here; callers check FrozenToolRegistry separately.
		return true, ""

	default:
		// Fail-closed: unknown transport blocks.
		return false, "airlock: hard tier blocks unknown transport"
	}
}

// FrozenToolRegistry maintains immutable tool inventories per MCP stable
// identity. When a session enters hard tier, the current tool set is frozen
// and only calls to those tools are permitted.
type FrozenToolRegistry struct {
	mu      sync.RWMutex
	entries map[string]frozenEntry
}

type frozenEntry struct {
	tools   map[string]struct{}
	created time.Time
}

// NewFrozenToolRegistry returns an initialized FrozenToolRegistry.
func NewFrozenToolRegistry() *FrozenToolRegistry {
	return &FrozenToolRegistry{
		entries: make(map[string]frozenEntry),
	}
}

// Freeze captures an immutable tool name set for the given MCP stable identity.
// If already frozen, this is a no-op (first freeze wins).
func (r *FrozenToolRegistry) Freeze(stableKey string, tools []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[stableKey]; exists {
		return // first freeze wins
	}

	toolSet := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		toolSet[t] = struct{}{}
	}
	r.entries[stableKey] = frozenEntry{
		tools:   toolSet,
		created: time.Now(),
	}
}

// IsFrozen reports whether a tool set has been frozen for the given key.
func (r *FrozenToolRegistry) IsFrozen(stableKey string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.entries[stableKey]
	return exists
}

// IsToolAllowed checks whether a tool call is permitted under the frozen
// inventory. Returns true if the key is not frozen (no restriction) or if
// the tool is in the frozen set.
func (r *FrozenToolRegistry) IsToolAllowed(stableKey, toolName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.entries[stableKey]
	if !exists {
		return true // not frozen, no restriction
	}
	_, allowed := entry.tools[toolName]
	return allowed
}

// ForceSetTier sets the airlock tier without transition restrictions.
// Used by the admin API for manual releases and de-escalation where
// operators need to move sessions to any tier including downward.
func (a *AirlockState) ForceSetTier(newTier string) (changed bool, from, to string) {
	return a.ForceSetTierWithProvenance(newTier, airlockTriggerManual, airlockSourceAdminAPI)
}

// ForceSetTierWithProvenance sets the airlock tier without transition
// restrictions and records the trigger/source that caused the entry.
func (a *AirlockState) ForceSetTierWithProvenance(newTier, trigger, source string) (changed bool, from, to string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, valid := AirlockTierOrder[newTier]; !valid {
		return false, a.tier, a.tier
	}
	if a.tier == newTier {
		return false, a.tier, a.tier
	}

	from = a.tier
	a.tier = newTier
	a.setEntryMetadataLocked(newTier, trigger, source)

	// Tear down connections on hard/drain, matching SetTier behavior.
	// ForceSetTier is used by the admin API; operators expect immediate effect.
	if newTier == config.AirlockTierHard || newTier == config.AirlockTierDrain {
		a.callCancelFuncsLocked()
	}

	// Clear cancel funcs when releasing to normal so stale connection
	// teardown callbacks don't fire on future escalations.
	if newTier == config.AirlockTierNone {
		a.cancelFuncs = nil
	}

	return true, from, newTier
}

// Unfreeze removes the frozen tool set for the given key.
// Called on deescalation out of hard tier.
func (r *FrozenToolRegistry) Unfreeze(stableKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, stableKey)
}

// ToolNames returns a sorted snapshot of the frozen tool names for the
// given key. Returns nil when the key is not frozen. Sorted to give the
// admin API a stable preview regardless of map iteration order.
func (r *FrozenToolRegistry) ToolNames(stableKey string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, exists := r.entries[stableKey]
	if !exists {
		return nil
	}
	names := make([]string, 0, len(entry.tools))
	for name := range entry.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
