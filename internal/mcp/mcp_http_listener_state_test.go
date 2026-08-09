// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
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
	state := newMCPListenerClientState(token, mcpListenerStateKey(token))
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

func TestMCPListenerClientStates_DiscardUnboundState(t *testing.T) {
	store := &listenerStateBoundedStore{}
	states := newMCPListenerClientStates(store)
	unbound := states.newUnboundState()
	states.discardUnboundState(unbound)
	if _, ok := store.deleted[unbound.key]; !ok {
		t.Fatalf("unbound recorder %q was not deleted", unbound.key)
	}

	bound := listenerSetupState(t, states, 1)
	states.discardUnboundState(bound)
	if _, ok := states.stateForToken(bound.token); !ok {
		t.Fatal("token-bound state was discarded")
	}
}

func TestMCPListenerClientStates_Forget(t *testing.T) {
	store := &listenerStateBoundedStore{}
	states := newMCPListenerClientStates(store)
	states.forget("")
	states.forgetLegacySession("")

	bound := listenerSetupState(t, states, 1)
	states.forget(bound.token)
	if _, ok := states.stateForToken(bound.token); ok {
		t.Fatal("forgotten token remained admitted")
	}
	if _, ok := store.deleted[bound.key]; !ok {
		t.Fatalf("forgotten recorder %q was not deleted", bound.key)
	}

	legacy := states.stateForLegacySession("legacy")
	states.forgetLegacySession("legacy")
	if !legacy.revoked.Load() {
		t.Fatal("forgotten legacy state was not revoked")
	}
	if _, ok := store.deleted[legacy.key]; !ok {
		t.Fatalf("forgotten legacy recorder %q was not deleted", legacy.key)
	}
}

func TestMCPListenerClientStates_LegacySessionReuse(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	transient := states.stateForLegacySession("")
	if transient.token != "" || len(states.clients) != 0 {
		t.Fatal("empty legacy session was registered")
	}
	first := states.stateForLegacySession("legacy")
	second := states.stateForLegacySession("legacy")
	if first != second {
		t.Fatal("repeated legacy session did not reuse state")
	}
}

func TestListenerHasStatefulControls_ToolBindingFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *tools.ToolScanConfig
	}{
		{"unknown action", &tools.ToolScanConfig{BindingUnknownAction: "block"}},
		{"no-baseline action", &tools.ToolScanConfig{BindingNoBaselineAction: "warn"}},
		{"drift detection", &tools.ToolScanConfig{DetectDrift: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !listenerHasStatefulControls(MCPProxyOpts{ToolCfg: tc.cfg}) {
				t.Fatalf("tool config %+v was not treated as stateful", tc.cfg)
			}
		})
	}
}

func TestMCPListenerClientState_CommitLinearizesWithRevoke(t *testing.T) {
	t.Run("revocation wins", func(t *testing.T) {
		state := newMCPListenerClientState("token", "key")
		state.revoke()
		committed := false
		if state.commitIfActive(func() { committed = true }) {
			t.Fatal("commit succeeded after revocation")
		}
		if committed {
			t.Fatal("commit callback ran after revocation")
		}
	})

	t.Run("commit wins", func(t *testing.T) {
		state := newMCPListenerClientState("token", "key")
		commitStarted := make(chan struct{})
		releaseCommit := make(chan struct{})
		commitDone := make(chan bool, 1)
		go func() {
			commitDone <- state.commitIfActive(func() {
				close(commitStarted)
				<-releaseCommit
			})
		}()
		<-commitStarted

		revokeDone := make(chan struct{})
		go func() {
			state.revoke()
			close(revokeDone)
		}()
		select {
		case <-revokeDone:
			t.Fatal("revocation completed during an in-flight commit")
		default:
		}

		close(releaseCommit)
		if !<-commitDone {
			t.Fatal("active commit was rejected")
		}
		<-revokeDone
		if !state.revoked.Load() {
			t.Fatal("state was not revoked after commit completed")
		}
	})
}
