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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type listenerDiagnosisStore struct {
	mu   sync.Mutex
	recs map[string]*listenerDiagnosisRecorder
}

func (s *listenerDiagnosisStore) GetOrCreate(key string) session.Recorder {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recs == nil {
		s.recs = make(map[string]*listenerDiagnosisRecorder)
	}
	if s.recs[key] == nil {
		s.recs[key] = &listenerDiagnosisRecorder{}
	}
	return s.recs[key]
}

type listenerDiagnosisRecorder struct {
	mu    sync.Mutex
	score float64
	level int
	risk  session.SessionRisk
}

func (r *listenerDiagnosisRecorder) RecordSignal(sig session.SignalType, threshold float64) (bool, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.score += session.SignalPoints[sig]
	if r.score < threshold || r.level > 0 {
		return false, "", ""
	}
	r.level = 1
	return true, "normal", "elevated"
}

func (r *listenerDiagnosisRecorder) RecordClean(float64) {}

func (r *listenerDiagnosisRecorder) EscalationLevel() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.level
}

func (r *listenerDiagnosisRecorder) ThreatScore() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.score
}

func (r *listenerDiagnosisRecorder) RiskSnapshot() session.SessionRisk {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.risk.Snapshot()
}

func (r *listenerDiagnosisRecorder) ObserveRisk(observation session.RiskObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.risk.Observe(observation)
}

// TestHTTPListenerDiagnosis_ClientBaselineDoesNotCrossSessions proves a client
// that never received tools/list cannot inherit another client's inventory.
// Client B must stay on the configured no-baseline action after client A
// establishes echo, while client A's own baseline remains available for drift
// detection across reloads.
func TestHTTPListenerDiagnosis_ClientBaselineDoesNotCrossSessions(t *testing.T) {
	var listCalls atomic.Int32
	var toolCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll(upstream request): %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(string(body), `"method":"tools/list"`):
			listCalls.Add(1)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Echo text","inputSchema":{"type":"object"}}]}}`))
		case strings.Contains(string(body), `"name":"echo"`):
			toolCalls.Add(1)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}`))
		default:
			t.Errorf("unexpected request forwarded upstream: %s", body)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer upstream.Close()

	toolCfg := &tools.ToolScanConfig{
		Action:                  config.ActionBlock,
		BindingUnknownAction:    config.ActionBlock,
		BindingNoBaselineAction: config.ActionBlock,
	}
	baseURL, _, _ := startListenerProxy(t, upstream.URL, testScannerForHTTP(t), &InputScanConfig{
		Enabled:      true,
		Action:       config.ActionBlock,
		OnParseError: config.ActionBlock,
	}, toolCfg, nil)

	newClient := func() *http.Client {
		client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		t.Cleanup(client.CloseIdleConnections)
		return client
	}
	clientA := newClient()
	clientB := newClient()
	post := func(t *testing.T, client *http.Client, sessionID, body string) string {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Mcp-Session-Id", sessionID)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST listener: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll(listener response): %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("listener status = %d, want 200; payload=%s", resp.StatusCode, payload)
		}
		return string(payload)
	}

	// Client B has no tool inventory, so its first call proves that the
	// no-baseline control is active before any other session seeds the listener.
	preBaseline := post(t, clientB, "diagnostic-client-b", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	if !strings.Contains(preBaseline, bindingReasonNoBaseline) {
		t.Fatalf("pre-baseline response = %s, want %q", preBaseline, bindingReasonNoBaseline)
	}
	if got := toolCalls.Load(); got != 0 {
		t.Fatalf("upstream echo calls before baseline = %d, want 0", got)
	}

	listPayload := post(t, clientA, "diagnostic-client-a", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if !strings.Contains(listPayload, `"name":"echo"`) {
		t.Fatalf("tools/list response = %s, want echo inventory", listPayload)
	}
	if got := listCalls.Load(); got != 1 {
		t.Fatalf("upstream tools/list calls = %d, want 1", got)
	}

	// B still has no tools/list. Its own empty baseline must take precedence
	// over A's populated baseline, so the configured no-baseline action blocks
	// even an unlisted name.
	unknown := post(t, clientB, "diagnostic-client-b", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"not_listed","arguments":{}}}`)
	if !strings.Contains(unknown, bindingReasonNoBaseline) {
		t.Fatalf("unlisted client-B response = %s, want %q", unknown, bindingReasonNoBaseline)
	}
	if got := toolCalls.Load(); got != 0 {
		t.Fatalf("upstream echo calls after client-B block = %d, want 0", got)
	}

	// B never received tools/list. echo is known only to A and must stay
	// blocked for B.
	postBaseline := post(t, clientB, "diagnostic-client-b", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	if !strings.Contains(postBaseline, bindingReasonNoBaseline) {
		t.Fatalf("cross-session echo call = %s, want %q", postBaseline, bindingReasonNoBaseline)
	}
	if got := toolCalls.Load(); got != 0 {
		t.Fatalf("cross-session echo calls = %d, want 0", got)
	}

	// A repeated client-supplied value deliberately selects the same
	// correlation state even over a separate connection. This proves the
	// boundary is separate-unless-proven-same, not authenticated identity.
	sameDeclaredClient := post(t, clientB, "diagnostic-client-a", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	if strings.Contains(sameDeclaredClient, `"error"`) {
		t.Fatalf("same supplied session ID did not reuse its baseline: %s", sameDeclaredClient)
	}
	if got := toolCalls.Load(); got != 1 {
		t.Fatalf("same supplied session ID echo calls = %d, want 1", got)
	}
}

// TestHTTPListenerDiagnosis_ClientStateDoesNotCrossSessions proves adaptive,
// taint, and headerless chain state cannot cross between listener clients.
func TestHTTPListenerDiagnosis_ClientStateDoesNotCrossSessions(t *testing.T) {
	t.Run("adaptive", func(t *testing.T) {
		var upstreamCalls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`))
		}))
		defer upstream.Close()

		store := &listenerDiagnosisStore{}
		adaptiveCfg := &config.AdaptiveEnforcement{
			Enabled:             true,
			EscalationThreshold: session.SignalPoints[session.SignalBlock],
			Levels: config.EscalationLevels{
				Elevated: config.EscalationActions{BlockAll: boolPtr(true)},
			},
		}
		baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
			Scanner:        newAdaptiveTestScanner(),
			InputCfg:       newHTTPInputCfg(config.ActionBlock),
			Store:          store,
			AdaptiveCfg:    adaptiveCfg,
			RequestBodyCfg: &config.RequestBodyScanning{Enabled: true, ScanHeaders: true},
		})

		secret := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
		first, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		if err != nil {
			t.Fatalf("NewRequest(first): %v", err)
		}
		first.Header.Set("Content-Type", "application/json")
		first.Header.Set("Mcp-Session-Id", "adaptive-client-a")
		first.Header.Set("Authorization", "Bearer "+secret)
		firstResp, err := http.DefaultClient.Do(first) //nolint:gosec // listener integration test
		if err != nil {
			t.Fatalf("POST(first): %v", err)
		}
		_ = firstResp.Body.Close()

		second, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
		if err != nil {
			t.Fatalf("NewRequest(second): %v", err)
		}
		second.Header.Set("Content-Type", "application/json")
		second.Header.Set("Mcp-Session-Id", "adaptive-client-b")
		secondResp, err := http.DefaultClient.Do(second) //nolint:gosec // listener integration test
		if err != nil {
			t.Fatalf("POST(second): %v", err)
		}
		defer func() { _ = secondResp.Body.Close() }()
		secondBody, err := io.ReadAll(secondResp.Body)
		if err != nil {
			t.Fatalf("ReadAll(second): %v", err)
		}
		if strings.Contains(string(secondBody), adaptiveBlockedReason) {
			t.Fatalf("second client inherited first client escalation: %s", secondBody)
		}
		if got := upstreamCalls.Load(); got != 1 {
			t.Fatalf("upstream calls = %d, want 1 after isolated adaptive escalation", got)
		}
	})

	t.Run("taint", func(t *testing.T) {
		var upstreamCalls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				ID int `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("Decode(upstream request): %v", err)
				return
			}
			upstreamCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{}}`, request.ID)
		}))
		defer upstream.Close()

		baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
			Scanner:  testScannerForHTTP(t),
			InputCfg: newHTTPInputCfg(config.ActionBlock),
			Store:    &listenerDiagnosisStore{},
			TaintCfg: &config.TaintConfig{Enabled: true, Policy: config.ModeStrict},
		})
		post := func(t *testing.T, sessionID, body string) string {
			t.Helper()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Mcp-Session-Id", sessionID)
			resp, err := http.DefaultClient.Do(req) //nolint:gosec // listener integration test
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			payload, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			return string(payload)
		}

		post(t, "taint-client-a", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
		second := post(t, "taint-client-b", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"id"}}}`)
		if strings.Contains(second, "mutating_exec_after_untrusted_external_exposure") {
			t.Fatalf("second client inherited first client taint: %s", second)
		}
		if got := upstreamCalls.Load(); got != 2 {
			t.Fatalf("upstream calls = %d, want 2 after isolated taint state", got)
		}
	})

	t.Run("chain without session ID", func(t *testing.T) {
		var upstreamCalls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				ID int `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("Decode(upstream request): %v", err)
				return
			}
			upstreamCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{}}`, request.ID)
		}))
		defer upstream.Close()

		baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
			Scanner:      testScannerForHTTP(t),
			InputCfg:     newHTTPInputCfg(config.ActionBlock),
			ChainMatcher: buildBlockChainMatcher(),
		})
		post := func(t *testing.T, body string) string {
			t.Helper()
			resp, err := http.Post(baseURL+"/", "application/json", strings.NewReader(body)) //nolint:gosec,noctx // listener integration test
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			payload, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			return string(payload)
		}

		post(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`)
		second := post(t, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"id"}}}`)
		if strings.Contains(second, "chain pattern") {
			t.Fatalf("second headerless client inherited first client chain: %s", second)
		}
		if got := upstreamCalls.Load(); got != 2 {
			t.Fatalf("upstream calls = %d, want 2 after isolated chain state", got)
		}
	})
}

func TestHTTPListenerDiagnosis_BaselineSurvivesReloadAndAnonymousSetup(t *testing.T) {
	var changedDescription atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("Decode(upstream request): %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "tools/list":
			if request.ID == 4 {
				w.Header().Set("Mcp-Session-Id", "upstream-minted-session")
			}
			description := "Echo text"
			if changedDescription.Load() {
				description = "Echo text with changed schema guidance"
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"echo","description":%q,"inputSchema":{"type":"object"}}]}}`, request.ID, description)
		case "tools/call":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"ok"}]}}`, request.ID)
		default:
			t.Errorf("unexpected method %q", request.Method)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer upstream.Close()

	newToolCfg := func() *tools.ToolScanConfig {
		return &tools.ToolScanConfig{
			Action:                  config.ActionBlock,
			DetectDrift:             true,
			BindingUnknownAction:    config.ActionBlock,
			BindingNoBaselineAction: config.ActionBlock,
		}
	}
	var activeToolCfg atomic.Pointer[tools.ToolScanConfig]
	activeToolCfg.Store(newToolCfg())
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:   testScannerForHTTP(t),
		ToolCfgFn: activeToolCfg.Load,
	})
	// A hot-reload snapshot may arrive before any client establishes a
	// baseline. The first tools/list must still initialize normally.
	activeToolCfg.Store(newToolCfg())
	post := func(t *testing.T, client *http.Client, id int, sessionID, method string) (string, http.Header) {
		t.Helper()
		var body string
		if method == "tools/list" {
			body = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{}}`, id)
		} else {
			body = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, id)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		return string(payload), resp.Header
	}

	clientA := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	t.Cleanup(clientA.CloseIdleConnections)
	first, _ := post(t, clientA, 1, "reload-client", "tools/list")
	if strings.Contains(first, `"error"`) {
		t.Fatalf("first tools/list blocked: %s", first)
	}

	// A new config object models a hot reload. The connection is also new, so
	// this proves a legitimate reconnect keeps its prior inventory.
	activeToolCfg.Store(newToolCfg())
	reconnectedClient := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	t.Cleanup(reconnectedClient.CloseIdleConnections)
	reconnected, _ := post(t, reconnectedClient, 2, "reload-client", "tools/call")
	if strings.Contains(reconnected, `"error"`) {
		t.Fatalf("same client was refused after reload: %s", reconnected)
	}

	changedDescription.Store(true)
	drifted, _ := post(t, reconnectedClient, 3, "reload-client", "tools/list")
	if !strings.Contains(drifted, `"error"`) {
		t.Fatalf("tool drift after reload was not blocked: %s", drifted)
	}

	// A headerless setup request has no shared fallback state. The upstream's
	// session ID promotes this request's fresh baseline for later calls.
	changedDescription.Store(false)
	anonymousClient := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	t.Cleanup(anonymousClient.CloseIdleConnections)
	setup, headers := post(t, anonymousClient, 4, "", "tools/list")
	if strings.Contains(setup, `"error"`) {
		t.Fatalf("headerless tools/list blocked: %s", setup)
	}
	if got := headers.Get("Mcp-Session-Id"); got != "upstream-minted-session" {
		t.Fatalf("returned session ID = %q, want upstream-minted-session", got)
	}
	afterSetup, _ := post(t, anonymousClient, 5, "upstream-minted-session", "tools/call")
	if strings.Contains(afterSetup, `"error"`) {
		t.Fatalf("upstream-minted session lost its baseline: %s", afterSetup)
	}
}

// TestHTTPListenerDiagnosis_DeferredPolicyFailsClosed proves a defer-matched
// request cannot reach the listener's forwarding code. This matters because
// the handler currently handles Blocked but has no Deferred branch: the
// transport support validator must remain the fail-closed boundary until a
// portable HTTP deferred-response/resume protocol exists.
func TestHTTPListenerDiagnosis_DeferredPolicyFailsClosed(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	manager := deferred.NewManager(deferred.Config{
		Enabled:              true,
		Timeout:              time.Hour,
		MaxPending:           4,
		MaxPendingPerSession: 4,
		MaxPendingBytes:      4096,
	})
	policyCfg := &policy.Config{
		Action: config.ActionWarn,
		Rules: []*policy.CompiledRule{{
			Name:        "defer-dangerous",
			ToolPattern: regexp.MustCompile(`^dangerous_tool$`),
			Action:      config.ActionDefer,
		}},
	}
	baseURL, logBuf := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:      testScannerForHTTP(t),
		PolicyCfg:    policyCfg,
		DeferManager: manager,
	})

	resp, err := http.Post(baseURL+"/", "application/json", strings.NewReader(jsonToolsCallDangerous)) //nolint:gosec,noctx // listener integration test
	if err != nil {
		t.Fatalf("POST listener: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(listener response): %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listener status = %d, want 200; payload=%s", resp.StatusCode, payload)
	}
	var response struct {
		ID    int `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("Unmarshal(listener response): %v; payload=%s", err, payload)
	}
	if response.ID != 1 || response.Error.Code != -32002 {
		t.Fatalf("defer rejection = %+v, want id=1 code=-32002", response)
	}
	if !strings.Contains(response.Error.Message, "defer is not yet supported on mcp_http_listener") {
		t.Fatalf("defer rejection message = %q", response.Error.Message)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls after deferred listener request = %d, want 0", got)
	}
	if got := len(manager.Snapshot()); got != 0 {
		t.Fatalf("listener created deferred holds = %d, want 0", got)
	}
	if !strings.Contains(logBuf.String(), "policy:defer-dangerous") || !strings.Contains(logBuf.String(), "defer is not yet supported on mcp_http_listener") {
		t.Fatalf("listener log did not show the matched defer rejection: %s", logBuf.String())
	}
}
