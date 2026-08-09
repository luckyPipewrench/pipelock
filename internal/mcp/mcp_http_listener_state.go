// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const maxMCPListenerClients = 4096

// mcpListenerClientState holds the mutable MCP state that belongs to one
// listener client. Mcp-Session-Id establishes correlation only, not identity:
// a client that forges another client's value can select the same state. The
// listener cannot provide authenticated-client isolation without an
// authenticated credential bound to the client.
type mcpListenerClientState struct {
	key          string
	baseline     *tools.ToolBaseline
	recorder     session.Recorder
	lastAccessed uint64
}

// mcpListenerClientStates partitions listener state by an explicit
// Mcp-Session-Id. Headerless requests receive a new, unregistered state, so
// they cannot inherit another client's state. If an upstream later supplies a
// session ID, bindUpstreamSession retains that request's state under the new
// key for subsequent requests.
//
// The registry retains at most maxMCPListenerClients client states. Eviction
// loses only the evicted client's learned state; its next call starts with an
// empty baseline and therefore follows the configured no-baseline action.
type mcpListenerClientStates struct {
	mu        sync.Mutex
	clients   map[string]*mcpListenerClientState
	clock     uint64
	store     session.Store
	driftEdge tools.DetectDriftRisingEdge
}

func newMCPListenerClientStates(store session.Store) *mcpListenerClientStates {
	return &mcpListenerClientStates{
		clients: make(map[string]*mcpListenerClientState),
		store:   store,
	}
}

func (s *mcpListenerClientStates) stateForRequest(sessionID string) (*mcpListenerClientState, string) {
	if sessionID == "" {
		key := session.NextInvocationKey("mcp-http-listener-anonymous")
		return &mcpListenerClientState{
			key:      key,
			baseline: tools.NewToolBaseline(),
		}, key
	}

	key := mcpListenerStateKey(sessionID)
	created := &mcpListenerClientState{
		key:      key,
		baseline: tools.NewToolBaseline(),
	}
	if s.store != nil {
		created.recorder = s.store.GetOrCreate(key)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.clients[key]; existing != nil {
		s.touchLocked(existing)
		return existing, key
	}
	if len(s.clients) >= maxMCPListenerClients {
		s.evictOldestLocked()
	}
	s.touchLocked(created)
	s.clients[key] = created
	return created, key
}

func (s *mcpListenerClientStates) bindUpstreamSession(state *mcpListenerClientState, sessionID string) {
	if state == nil || sessionID == "" {
		return
	}
	key := mcpListenerStateKey(sessionID)
	if state.recorder == nil && s.store != nil {
		state.recorder = s.store.GetOrCreate(key)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if state.key != key && s.clients[state.key] == state {
		delete(s.clients, state.key)
	}
	if state.key != key && len(s.clients) >= maxMCPListenerClients {
		s.evictOldestLocked()
	}
	state.key = key
	s.touchLocked(state)
	s.clients[key] = state
}

func (s *mcpListenerClientStates) forget(sessionID string) {
	if sessionID == "" {
		return
	}
	key := mcpListenerStateKey(sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, key)
}

func (s *mcpListenerClientStates) toolConfig(state *mcpListenerClientState, cfg *tools.ToolScanConfig) *tools.ToolScanConfig {
	if state == nil || cfg == nil || cfg.Action == "" {
		return nil
	}
	if s.driftEdge.Observe(cfg.DetectDrift) {
		s.resetDriftState()
	}
	return &tools.ToolScanConfig{
		Baseline:                state.baseline,
		Action:                  cfg.Action,
		DetectDrift:             cfg.DetectDrift,
		BindingUnknownAction:    cfg.BindingUnknownAction,
		BindingNoBaselineAction: cfg.BindingNoBaselineAction,
		ExtraPoison:             cfg.ExtraPoison,
	}
}

func (s *mcpListenerClientStates) resetDriftState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, state := range s.clients {
		state.baseline.ResetDriftState()
	}
}

func (s *mcpListenerClientStates) touchLocked(state *mcpListenerClientState) {
	s.clock++
	state.lastAccessed = s.clock
}

func (s *mcpListenerClientStates) evictOldestLocked() {
	var oldestKey string
	var oldest uint64
	for key, state := range s.clients {
		if oldestKey == "" || state.lastAccessed < oldest {
			oldestKey = key
			oldest = state.lastAccessed
		}
	}
	if oldestKey != "" {
		delete(s.clients, oldestKey)
	}
}

func mcpListenerStateKey(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return fmt.Sprintf("mcp-http-listener:%x", sum)
}

func listenerAuditSessionKey(sessionID, stateKey string) string {
	if sanitized := sanitizeAuditSessionKey(sessionID); sanitized != "" {
		return sanitized
	}
	sum := sha256.Sum256([]byte(stateKey))
	return fmt.Sprintf("mcp-session:%x", sum[:8])
}
