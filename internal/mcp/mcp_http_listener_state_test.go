// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

type listenerStateBoundedStore struct {
	recorders map[string]session.Recorder
	deleted   map[string]struct{}
}

func (s *listenerStateBoundedStore) GetOrCreate(key string) session.Recorder {
	if s.recorders == nil {
		s.recorders = make(map[string]session.Recorder)
	}
	if s.recorders[key] == nil {
		s.recorders[key] = &listenerDiagnosisRecorder{}
	}
	return s.recorders[key]
}

func (s *listenerStateBoundedStore) Delete(key string) {
	delete(s.recorders, key)
	if s.deleted == nil {
		s.deleted = make(map[string]struct{})
	}
	s.deleted[key] = struct{}{}
}

func listenerSetupState(t *testing.T, states *mcpListenerClientStates, n int) *mcpListenerClientState {
	t.Helper()
	token := fmt.Sprintf("listener-state-test-%d", n)
	state := &mcpListenerClientState{
		token:    token,
		key:      mcpListenerStateKey(token),
		baseline: newMCPListenerTransientState().baseline,
	}
	if !states.admitSetup(state) {
		t.Fatalf("admitSetup(%d) = false", n)
	}
	return state
}

func TestMCPListenerClientStates_BoundedAdmissionDeletesEvictedRecorder(t *testing.T) {
	store := &listenerStateBoundedStore{}
	states := newMCPListenerClientStates(store)
	victim := listenerSetupState(t, states, 0)
	for i := 1; i < maxMCPListenerClients; i++ {
		listenerSetupState(t, states, i)
	}
	if got := len(states.clients); got != maxMCPListenerClients {
		t.Fatalf("client entries before overflow = %d, want %d", got, maxMCPListenerClients)
	}
	if got := len(store.recorders); got != maxMCPListenerClients {
		t.Fatalf("store entries before overflow = %d, want %d", got, maxMCPListenerClients)
	}

	listenerSetupState(t, states, maxMCPListenerClients)
	if got := len(states.clients); got != maxMCPListenerClients {
		t.Fatalf("client entries after overflow = %d, want %d", got, maxMCPListenerClients)
	}
	if got := len(store.recorders); got != maxMCPListenerClients {
		t.Fatalf("store entries after overflow = %d, want %d", got, maxMCPListenerClients)
	}
	if _, ok := store.deleted[victim.key]; !ok {
		t.Fatalf("evicted recorder %q was not deleted", victim.key)
	}
	if _, ok := states.stateForToken(victim.token); ok {
		t.Fatal("evicted token remained admitted")
	}
	if states.admitSetup(victim) {
		t.Fatal("delayed response re-admitted an evicted state")
	}
	if got := len(states.clients); got != maxMCPListenerClients {
		t.Fatalf("client entries after delayed response = %d, want %d", got, maxMCPListenerClients)
	}
	if got := len(store.recorders); got != maxMCPListenerClients {
		t.Fatalf("store entries after delayed response = %d, want %d", got, maxMCPListenerClients)
	}
}
