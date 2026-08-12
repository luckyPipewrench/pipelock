// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// principalControlRPC is intentionally unable to send the legacy initialize,
// MCP session, or Pipelock-session-token extensions. Each request is current
// Streamable HTTP and carries only a listener bearer credential.
func principalControlRPC(baseURL, bearer string, body []byte) (int, string, error) {
	frame := ParseMCPFrame(body)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(string(body)))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", currentMCPVersion)
	req.Header.Set("Mcp-Method", frame.Method)
	if frame.RoutingName != "" {
		req.Header.Set("Mcp-Name", frame.RoutingName)
	}
	if bearer != "" {
		req.Header.Set("Proxy-Authorization", "Bearer "+bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(payload), nil
}

func mustPrincipalControlRPC(t *testing.T, baseURL, bearer string, body []byte) (int, string) {
	t.Helper()
	status, payload, err := principalControlRPC(baseURL, bearer, body)
	if err != nil {
		t.Fatalf("current-spec listener request: %v", err)
	}
	return status, payload
}

func principalControlToolsList(id int) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, id, currentMCPVersion))
}

func principalControlToolCall(id int, tool, arguments string) []byte {
	if arguments == "" {
		arguments = "{}"
	}
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s,"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, id, tool, arguments, currentMCPVersion))
}

func principalControlCEEChunk(id int, chunk string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"integrity_checker","arguments":{"alpha":%q,"beta":"part %d/120"},"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, id, chunk, id, currentMCPVersion))
}

func principalControlOpts(t *testing.T) MCPProxyOpts {
	t.Helper()
	return MCPProxyOpts{
		ListenerBearerToken: principalStateTestBearer,
		Scanner:             testScannerForHTTP(t),
		InputCfg:            newHTTPInputCfg(config.ActionBlock),
	}
}

// principalControlAirlockStore gives every verified principal a real, separate
// recorder. Its records deliberately key off Pipelock's derived state key, not
// any client-provided header.
type principalControlAirlockStore struct {
	mu   sync.Mutex
	recs map[string]*airlockTestRecorder
}

func (s *principalControlAirlockStore) GetOrCreate(key string) session.Recorder {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recs == nil {
		s.recs = make(map[string]*airlockTestRecorder)
	}
	if s.recs[key] == nil {
		s.recs[key] = &airlockTestRecorder{tier: config.AirlockTierNone, level: 0, escalate: true}
	}
	return s.recs[key]
}

func (s *principalControlAirlockStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.recs, key)
}

// TestHTTPListener_PrincipalControls_BindingPersistsAndIsolatesVerifiedSubjects
// makes the verifier an out-of-band test fixture: the selected identity never
// comes from the HTTP request. It verifies both persistence for one principal
// and baseline isolation for another sharing the same listener bearer.
func TestHTTPListener_PrincipalControls_BindingPersistsAndIsolatesVerifiedSubjects(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		var frame struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if frame.Method == "tools/list" {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"Echo text","inputSchema":{"type":"object"}}]}}`, frame.ID)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, frame.ID)
	}))
	t.Cleanup(upstream.Close)

	var verifiedSubject atomic.Value
	verifiedSubject.Store("alice")
	opts := principalControlOpts(t)
	opts.ToolCfg = &tools.ToolScanConfig{
		Action:                  config.ActionBlock,
		BindingUnknownAction:    config.ActionBlock,
		BindingNoBaselineAction: config.ActionBlock,
	}
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		return ListenerPrincipal{Provider: "test", Subject: verifiedSubject.Load().(string)}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	request := func(subject string, body []byte) (int, string) {
		verifiedSubject.Store(subject)
		return mustPrincipalControlRPC(t, baseURL, principalStateTestBearer, body)
	}

	if status, body := request("alice", principalControlToolsList(1)); status != http.StatusOK || !strings.Contains(body, `"name":"echo"`) {
		t.Fatalf("alice tools/list = status %d body %s, want baseline seed", status, body)
	}
	if status, body := request("alice", principalControlToolCall(2, "echo", `{"text":"same principal"}`)); status != http.StatusOK || strings.Contains(body, `"error"`) {
		t.Fatalf("alice known tool = status %d body %s, want allowed", status, body)
	}
	if status, body := request("bob", principalControlToolCall(3, "echo", `{"text":"different principal"}`)); status != http.StatusOK || !strings.Contains(body, bindingReasonNoBaseline) {
		t.Fatalf("bob inherited alice baseline = status %d body %s", status, body)
	}
	if status, body := request("bob", principalControlToolsList(4)); status != http.StatusOK || !strings.Contains(body, `"name":"echo"`) {
		t.Fatalf("bob tools/list = status %d body %s, want independent baseline seed", status, body)
	}
	if status, body := request("bob", principalControlToolCall(5, "echo", `{"text":"own principal"}`)); status != http.StatusOK || strings.Contains(body, `"error"`) {
		t.Fatalf("bob known tool = status %d body %s, want allowed", status, body)
	}
	if got := upstreamCalls.Load(); got != 4 {
		t.Fatalf("upstream calls = %d, want 4; unbaselined bob call must not forward", got)
	}
}

// TestHTTPListener_PrincipalControls_TaintPersistsAndIsolatesVerifiedSubjects
// proves response-created taint is retained for the originating principal and
// cannot be inherited by another verified principal holding the same bearer.
func TestHTTPListener_PrincipalControls_TaintPersistsAndIsolatesVerifiedSubjects(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		var frame struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"external result"}]}}`, frame.ID)
	}))
	t.Cleanup(upstream.Close)

	var verifiedSubject atomic.Value
	verifiedSubject.Store("alice")
	opts := principalControlOpts(t)
	opts.Store = &listenerDiagnosisStore{}
	opts.TaintCfg = &config.TaintConfig{Enabled: true, Policy: config.ModeStrict}
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		return ListenerPrincipal{Provider: "test", Subject: verifiedSubject.Load().(string)}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	request := func(subject string, body []byte) (int, string) {
		verifiedSubject.Store(subject)
		return mustPrincipalControlRPC(t, baseURL, principalStateTestBearer, body)
	}

	if status, body := request("alice", principalControlToolsList(1)); status != http.StatusOK || strings.Contains(body, `"error"`) {
		t.Fatalf("alice external response = status %d body %s, want forwarded taint source", status, body)
	}
	if status, body := request("alice", principalControlToolCall(2, "execute_command", `{"command":"id"}`)); status != http.StatusOK || !strings.Contains(body, "mutating_exec_after_untrusted_external_exposure") {
		t.Fatalf("alice tainted write = status %d body %s, want taint block", status, body)
	}
	if status, body := request("bob", principalControlToolCall(3, "execute_command", `{"command":"id"}`)); status != http.StatusOK || strings.Contains(body, "mutating_exec_after_untrusted_external_exposure") {
		t.Fatalf("bob inherited alice taint = status %d body %s", status, body)
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2; alice taint block must not forward", got)
	}
}

// TestHTTPListener_PrincipalControls_CEEPersistsAndIsolatesVerifiedSubjects
// splits a credential-shaped value across requests. The same verified principal
// must reassemble and block it, while a different verified principal must not
// receive an invented cross-subject concatenation.
func TestHTTPListener_PrincipalControls_CEEPersistsAndIsolatesVerifiedSubjects(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		var frame struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, frame.ID)
	}))
	t.Cleanup(upstream.Close)

	var verifiedSubject atomic.Value
	verifiedSubject.Store("alice")
	opts := principalControlOpts(t)
	opts.CEE = testMCPCEEFragmentBlock(t)
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		return ListenerPrincipal{Provider: "test", Subject: verifiedSubject.Load().(string)}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	request := func(subject string, body []byte) (int, string) {
		verifiedSubject.Store(subject)
		return mustPrincipalControlRPC(t, baseURL, principalStateTestBearer, body)
	}

	if status, body := request("alice", principalControlCEEChunk(1, "AKI"+"A")); status != http.StatusOK || strings.Contains(body, "cross-request fragment DLP match") {
		t.Fatalf("alice first fragment = status %d body %s, want allowed", status, body)
	}
	if status, body := request("bob", principalControlCEEChunk(2, testMCPAWSKeySuffix)); status != http.StatusOK || strings.Contains(body, "cross-request fragment DLP match") {
		t.Fatalf("bob isolated suffix = status %d body %s, want allowed", status, body)
	}
	if status, body := request("alice", principalControlCEEChunk(3, testMCPAWSKeySuffix)); status != http.StatusOK || !strings.Contains(body, "cross-request fragment DLP match") {
		t.Fatalf("alice reassembled fragments = status %d body %s, want CEE block", status, body)
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2; same-principal CEE block must not forward", got)
	}
}

// TestHTTPListener_PrincipalControls_AdaptiveAirlockPersistsAndIsolatesVerifiedSubjects
// verifies an adaptive signal escalates only its principal's recorder and
// containment. The next call by that principal must fail locally; a different
// verified principal remains usable.
func TestHTTPListener_PrincipalControls_AdaptiveAirlockPersistsAndIsolatesVerifiedSubjects(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		var frame struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, frame.ID)
	}))
	t.Cleanup(upstream.Close)

	var verifiedSubject atomic.Value
	verifiedSubject.Store("alice")
	blockAll := true
	airlockCfg := config.Defaults().Airlock
	airlockCfg.Enabled = true
	airlockCfg.Triggers.OnElevated = config.AirlockTierHard
	opts := principalControlOpts(t)
	opts.Store = &principalControlAirlockStore{}
	opts.AdaptiveCfg = &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 1,
		Levels: config.EscalationLevels{
			Elevated: config.EscalationActions{BlockAll: &blockAll},
		},
	}
	opts.AirlockCfg = &airlockCfg
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		return ListenerPrincipal{Provider: "test", Subject: verifiedSubject.Load().(string)}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	request := func(subject string, body []byte) (int, string) {
		verifiedSubject.Store(subject)
		return mustPrincipalControlRPC(t, baseURL, principalStateTestBearer, body)
	}

	secret := "sk-ant-" + strings.Repeat("x", 25)
	if status, body := request("alice", principalControlToolCall(1, "echo", fmt.Sprintf(`{"value":%q}`, secret))); status != http.StatusOK || !strings.Contains(body, "MCP input scanning") {
		t.Fatalf("alice adaptive signal = status %d body %s, want input block", status, body)
	}
	if status, body := request("alice", principalControlToolCall(2, "read_file", `{"path":"/tmp/blocked"}`)); status != http.StatusOK || !strings.Contains(body, "airlock") {
		t.Fatalf("alice contained follow-up = status %d body %s, want airlock block", status, body)
	}
	if status, body := request("bob", principalControlToolCall(3, "read_file", `{"path":"/tmp/other"}`)); status != http.StatusOK || strings.Contains(body, "airlock") {
		t.Fatalf("bob inherited alice containment = status %d body %s", status, body)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1; input and airlock blocks must not forward", got)
	}
}

// TestHTTPListener_PrincipalControls_UnidentifiedStatefulControlsFailClosed
// covers every remaining stateful-control classifier branch without a bearer,
// initialize, MCP session id, or Pipelock session token. Each case must stop
// locally rather than silently selecting an unbound transient state.
func TestHTTPListener_PrincipalControls_UnidentifiedStatefulControlsFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testing.T, *MCPProxyOpts)
	}{
		{
			name: "tool baseline binding",
			configure: func(_ *testing.T, opts *MCPProxyOpts) {
				opts.ToolCfg = &tools.ToolScanConfig{BindingNoBaselineAction: config.ActionBlock}
			},
		},
		{
			name: "taint",
			configure: func(_ *testing.T, opts *MCPProxyOpts) {
				opts.TaintCfg = &config.TaintConfig{Enabled: true, Policy: config.ModeStrict}
			},
		},
		{
			name: "CEE",
			configure: func(t *testing.T, opts *MCPProxyOpts) {
				opts.CEE = testMCPCEEFragmentBlock(t)
			},
		},
		{
			name: "adaptive",
			configure: func(_ *testing.T, opts *MCPProxyOpts) {
				opts.AdaptiveCfg = adaptiveCfgEnabled()
			},
		},
		{
			name: "airlock",
			configure: func(_ *testing.T, opts *MCPProxyOpts) {
				airlockCfg := config.Defaults().Airlock
				airlockCfg.Enabled = true
				opts.AirlockCfg = &airlockCfg
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			}))
			t.Cleanup(upstream.Close)

			opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock), Store: &listenerDiagnosisStore{}}
			tc.configure(t, &opts)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			status, body := mustPrincipalControlRPC(t, baseURL, "", principalControlToolCall(1, "read_file", `{"path":"/tmp/no-principal"}`))
			if status >= http.StatusInternalServerError || !strings.Contains(body, `"error"`) {
				t.Fatalf("unidentified current-spec request = status %d body %s, want a local block", status, body)
			}
			if got := upstreamCalls.Load(); got != 0 {
				t.Fatalf("unidentified request reached upstream %d times, want 0", got)
			}
		})
	}
}

// TestHTTPListener_PrincipalControls_ConcurrentBearerRotationCannotResurrectOldState
// holds an old-credential request after it has reached the upstream, rotates
// to a new credential, and then releases it. The canceled old request must not
// commit its read history; rotating the old credential back creates a fresh
// epoch whose first exec is allowed.
func TestHTTPListener_PrincipalControls_ConcurrentBearerRotationCannotResurrectOldState(t *testing.T) {
	const oldBearer = "principal-control-old"
	const newBearer = "principal-control-new"
	var active atomic.Value
	active.Store(oldBearer)
	oldReachedUpstream := make(chan struct{})
	releaseOld := make(chan struct{})
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		var frame struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if string(frame.ID) == "1" {
			close(oldReachedUpstream)
			<-releaseOld
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, frame.ID)
	}))
	t.Cleanup(upstream.Close)

	opts := principalControlOpts(t)
	opts.ListenerBearerToken = ""
	opts.ChainMatcher = buildBlockChainMatcher()
	opts.ListenerBearerTokenFn = func() (string, error) { return active.Load().(string), nil }
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	type result struct {
		status int
		body   string
		err    error
	}
	oldResult := make(chan result, 1)
	go func() {
		status, body, err := principalControlRPC(baseURL, oldBearer, principalControlToolCall(1, "read_file", `{"path":"/tmp/old"}`))
		oldResult <- result{status: status, body: body, err: err}
	}()
	<-oldReachedUpstream

	active.Store(newBearer)
	if status, body := mustPrincipalControlRPC(t, baseURL, newBearer, principalControlToolCall(2, "bash_exec", `{"command":"id"}`)); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("new epoch exec = status %d body %s, want fresh allowed state", status, body)
	}
	close(releaseOld)
	got := <-oldResult
	if got.err != nil {
		t.Fatalf("old in-flight request did not complete after revocation: %v", got.err)
	}
	if got.status != http.StatusBadGateway || !strings.Contains(got.body, "upstream HTTP request failed") {
		t.Fatalf("revoked in-flight request = status %d body %s, want canceled-upstream response", got.status, got.body)
	}

	active.Store(oldBearer)
	if status, body := mustPrincipalControlRPC(t, baseURL, oldBearer, principalControlToolCall(3, "bash_exec", `{"command":"id"}`)); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("old bearer resurrected a canceled epoch = status %d body %s", status, body)
	}
	if got := upstreamCalls.Load(); got != 3 {
		t.Fatalf("upstream calls = %d, want 3: canceled old read, new fresh exec, reintroduced old fresh exec", got)
	}
}
