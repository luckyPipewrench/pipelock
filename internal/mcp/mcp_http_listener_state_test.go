// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type listenerStateBoundedStore struct {
	recorders map[string]session.Recorder
	deleted   map[string]struct{}
}

func TestMCPListenerClientStates_EdgeTransitions(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	if state, ok := states.stateForToken(""); ok || state != nil {
		t.Fatal("empty token selected state")
	}
	if state, ok := states.stateForToken("missing"); ok || state != nil {
		t.Fatal("unknown token selected state")
	}

	revoked := newMCPListenerClientState("revoked", mcpListenerStateKey("revoked"))
	states.clients[revoked.key] = revoked
	revoked.revoke()
	if state, ok := states.stateForToken(revoked.token); ok || state != nil {
		t.Fatal("revoked token selected state")
	}

	duplicate := newMCPListenerClientState("duplicate", mcpListenerStateKey("duplicate"))
	if !states.admitSetup(duplicate) {
		t.Fatal("initial setup admission failed")
	}
	if states.admitSetup(newMCPListenerClientState("duplicate", duplicate.key)) {
		t.Fatal("duplicate state key was admitted")
	}

	var nilState *mcpListenerClientState
	ctx := context.Background()
	gotCtx, cleanup := nilState.requestContext(ctx)
	cleanup()
	if gotCtx != ctx {
		t.Fatal("nil state replaced request context")
	}
	nilState.revoke()
	if nilState.commitIfActive(func() { t.Fatal("nil-state commit callback ran") }) {
		t.Fatal("nil state accepted commit")
	}

	if cfg := states.toolConfig(duplicate, &tools.ToolScanConfig{DetectDrift: true}); cfg == nil {
		t.Fatal("drift config was discarded")
	}
	states.resetDriftState()
	if got := listenerAuditSessionKey("", duplicate.key); got == "" {
		t.Fatal("state key did not produce audit fallback")
	}
}

func TestMCPListenerTokenHelpers_EdgeCases(t *testing.T) {
	valid := strings.Repeat("a", 43)
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "absent", want: true},
		{name: "duplicate", values: []string{valid, valid}, want: false},
		{name: "wrong length", values: []string{"short"}, want: false},
		{name: "bad character", values: []string{valid[:42] + "!"}, want: false},
		{name: "valid", values: []string{valid}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validMCPListenerSessionToken(tc.values); got != tc.want {
				t.Fatalf("validMCPListenerSessionToken() = %v, want %v", got, tc.want)
			}
		})
	}

	disabled := false
	if listenerRequiresStateToken(MCPProxyOpts{
		ToolCfg:                    &tools.ToolScanConfig{Action: "block"},
		listenerStateTokenRequired: &disabled,
	}) {
		t.Fatal("explicit compatibility mode required a listener token")
	}

	state := newMCPListenerClientState("token", "key")
	state.revoke()
	var out bytes.Buffer
	writer := &listenerStateMessageWriter{state: state, writer: &syncWriter{w: &out}}
	if err := writer.WriteMessage([]byte(`{"jsonrpc":"2.0"}`)); err == nil {
		t.Fatal("revoked state writer accepted a message")
	}
	if out.Len() != 0 {
		t.Fatalf("revoked state writer emitted %q", out.String())
	}

	writeErr := errors.New("delegated write failed")
	active := newMCPListenerClientState("active-token", "active-key")
	delegated := &sentinelMessageWriter{err: writeErr}
	writer = &listenerStateMessageWriter{state: active, writer: delegated}
	if err := writer.WriteMessage([]byte(`{"jsonrpc":"2.0"}`)); !errors.Is(err, writeErr) {
		t.Fatalf("delegated writer error = %v, want %v", err, writeErr)
	}
}

type sentinelMessageWriter struct{ err error }

func (w *sentinelMessageWriter) WriteMessage([]byte) error { return w.err }

type deadlineBlockingResponseWriter struct {
	header      http.Header
	deadlineSet chan struct{}
	release     chan struct{}
	once        sync.Once
}

func newDeadlineBlockingResponseWriter() *deadlineBlockingResponseWriter {
	return &deadlineBlockingResponseWriter{
		header:      make(http.Header),
		deadlineSet: make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (w *deadlineBlockingResponseWriter) Header() http.Header { return w.header }
func (w *deadlineBlockingResponseWriter) WriteHeader(int)     {}
func (w *deadlineBlockingResponseWriter) Write([]byte) (int, error) {
	<-w.release
	return 0, context.DeadlineExceeded
}

func (w *deadlineBlockingResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return nil
	}
	w.once.Do(func() {
		close(w.deadlineSet)
		time.AfterFunc(time.Until(deadline), func() { close(w.release) })
	})
	return nil
}

func TestListenerStateMessageWriter_BoundsBlockedWriteBeforeRevocation(t *testing.T) {
	state := newMCPListenerClientState("token", "key")
	blocked := newDeadlineBlockingResponseWriter()
	stream := &sseMessageWriter{
		w:              blocked,
		responseWriter: blocked,
		writeTimeout:   20 * time.Millisecond,
	}
	writer := &listenerStateMessageWriter{state: state, writer: stream}
	writeDone := make(chan error, 1)
	go func() { writeDone <- writer.WriteMessage([]byte(`{"jsonrpc":"2.0"}`)) }()
	<-blocked.deadlineSet

	revokeDone := make(chan struct{})
	go func() {
		state.revoke()
		close(revokeDone)
	}()
	select {
	case <-revokeDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("revocation remained blocked behind a downstream write deadline")
	}
	if err := <-writeDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked write error = %v, want deadline exceeded", err)
	}
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

func TestMCPListenerClientStates_LegacyAdmissionEvictsOldest(t *testing.T) {
	store := &listenerStateBoundedStore{}
	states := newMCPListenerClientStates(store)
	var oldest *mcpListenerClientState
	for i := range maxMCPListenerClients {
		state := newMCPListenerClientState("", fmt.Sprintf("legacy-key-%d", i))
		if i == 0 {
			oldest = state
		}
		state.lastAccessed = uint64(i + 1)
		states.clients[state.key] = state
		store.GetOrCreate(state.key)
	}

	admitted := states.stateForLegacySession("replacement")
	if admitted.recorder == nil {
		t.Fatal("legacy admission did not attach a recorder")
	}
	if got := len(states.clients); got != maxMCPListenerClients {
		t.Fatalf("legacy client entries = %d, want %d", got, maxMCPListenerClients)
	}
	if _, ok := store.deleted["legacy-key-0"]; !ok {
		t.Fatal("legacy admission did not delete the oldest recorder")
	}
	if !oldest.revoked.Load() {
		t.Fatal("legacy admission did not revoke the oldest state")
	}
}

func TestMCPListenerSessionTokenIsGenerated(t *testing.T) {
	token, err := newMCPListenerSessionToken()
	if err != nil {
		t.Fatalf("newMCPListenerSessionToken: %v", err)
	}
	if !validMCPListenerSessionToken([]string{token}) {
		t.Fatalf("generated invalid listener session token %q", token)
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
		revokeContended := make(chan struct{})
		go func() {
			state.revokeWithContentionSignal(revokeContended)
			close(revokeDone)
		}()
		<-revokeContended
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
