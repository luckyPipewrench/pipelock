// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const principalStateTestBearer = "shared-listener-credential"

// principalStateUpstream records the requests that Pipelock actually forwards.
// A block must be visible here as an absent request, not merely as a JSON-RPC
// error generated after forwarding.
func principalStateUpstream(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var request struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, request.ID)
	}))
	t.Cleanup(upstream.Close)
	return upstream, &calls
}

// principalStateToolCall deliberately sends the current Streamable HTTP shape:
// no initialize request, no Mcp-Session-Id, and no Pipelock-Session-Token.
// The bearer proves one shared credential trust domain; it is not a claim that
// Pipelock can distinguish individual humans holding that credential.
func principalStateToolCallRequest(baseURL, bearer string, id int, tool string, extra http.Header) (int, string, error) {
	if extra != nil && (extra.Get("Mcp-Session-Id") != "" || extra.Get(listenerSessionTokenHeader) != "") {
		return 0, "", fmt.Errorf("current-spec principal-state request must not carry an MCP or Pipelock session token")
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, id, tool, currentMCPVersion)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
	if err != nil {
		return 0, "", fmt.Errorf("NewRequest: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	req.Header.Set("Mcp-Protocol-Version", currentMCPVersion)
	if bearer != "" {
		req.Header.Set("Proxy-Authorization", "Bearer "+bearer)
	}
	for name, values := range extra {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("POST listener: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("ReadAll(listener response): %w", err)
	}
	return resp.StatusCode, string(payload), nil
}

func principalStateToolCall(t *testing.T, baseURL, bearer string, id int, tool string, extra http.Header) (int, string) {
	t.Helper()
	status, payload, err := principalStateToolCallRequest(baseURL, bearer, id, tool, extra)
	if err != nil {
		t.Fatal(err)
	}
	return status, payload
}

func principalStateDelete(t *testing.T, baseURL, bearer string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, baseURL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest(DELETE): %v", err)
	}
	if bearer != "" {
		req.Header.Set("Proxy-Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE listener: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(DELETE response): %v", err)
	}
	return resp.StatusCode, string(payload)
}

func principalStateOpts(t *testing.T, bearer string) MCPProxyOpts {
	t.Helper()

	return MCPProxyOpts{
		ListenerBearerToken: bearer,
		Scanner:             testScannerForHTTP(t),
		InputCfg:            newHTTPInputCfg(config.ActionBlock),
		ChainMatcher:        buildBlockChainMatcher(),
	}
}

// TestHTTPListener_PrincipalState_CurrentSpecSharedBearerRejectsSpoofedPartitions
// is the core AF-326 customer path. A successfully verified listener bearer is
// one intentionally shared principal. Current-spec requests do not initialize
// an MCP session and never replay Pipelock's private extension token, so they
// must still retain state across a read -> exec chain. Client-supplied headers
// must not buy separate state partitions.
func TestHTTPListener_PrincipalState_CurrentSpecSharedBearerRejectsSpoofedPartitions(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, principalStateTestBearer)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	firstStatus, first := principalStateToolCall(t, baseURL, principalStateTestBearer, 1, "read_file", http.Header{
		"X-Pipelock-Agent": []string{"pretend-alpha"},
		"X-Forwarded-For":  []string{"198.51.100.10"},
	})
	if firstStatus != http.StatusOK || strings.Contains(first, "chain pattern") {
		t.Fatalf("first current-spec call = status %d body %s, want allowed", firstStatus, first)
	}

	secondStatus, second := principalStateToolCall(t, baseURL, principalStateTestBearer, 2, "bash_exec", http.Header{
		"X-Pipelock-Agent": []string{"pretend-beta"},
		"X-Forwarded-For":  []string{"203.0.113.77"},
	})
	if secondStatus != http.StatusOK || !strings.Contains(second, "chain pattern") {
		t.Fatalf("spoofed-header follow-up = status %d body %s, want current principal chain block", secondStatus, second)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1; blocked follow-up must not be forwarded", got)
	}
}

// TestHTTPListener_PrincipalState_BearerRotationStartsNewEpoch proves the
// listener bearer is one verified shared principal whose rotation revokes the
// old epoch. The new credential must not inherit the old chain, while its own
// later read -> exec sequence must still block without a private session token.
func TestHTTPListener_PrincipalState_BearerRotationStartsNewEpoch(t *testing.T) {
	const oldBearer = "shared-listener-credential-old"
	const newBearer = "shared-listener-credential-new"
	var active atomic.Value
	active.Store(oldBearer)

	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, "")
	opts.ListenerBearerTokenFn = func() (string, error) { return active.Load().(string), nil }
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	if status, body := principalStateToolCall(t, baseURL, oldBearer, 1, "read_file", nil); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("old credential read = status %d body %s, want allowed", status, body)
	}

	active.Store(newBearer)
	if status, body := principalStateToolCall(t, baseURL, oldBearer, 2, "read_file", nil); status != http.StatusProxyAuthRequired {
		t.Fatalf("rotated-out credential = status %d body %s, want 407", status, body)
	}
	if status, body := principalStateToolCall(t, baseURL, newBearer, 3, "bash_exec", nil); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("new credential inherited old epoch = status %d body %s", status, body)
	}
	if status, body := principalStateToolCall(t, baseURL, newBearer, 4, "read_file", nil); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("new credential read = status %d body %s, want allowed", status, body)
	}
	if status, body := principalStateToolCall(t, baseURL, newBearer, 5, "bash_exec", nil); status != http.StatusOK || !strings.Contains(body, "chain pattern") {
		t.Fatalf("new credential current-spec chain = status %d body %s, want block", status, body)
	}
	active.Store(oldBearer)
	if status, body := principalStateToolCall(t, baseURL, oldBearer, 6, "bash_exec", nil); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("reused old credential resurrected its first epoch = status %d body %s", status, body)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("upstream calls = %d, want 4: old read, new exec, new read, reused-old fresh exec", got)
	}
}

// TestHTTPListener_PrincipalState_RotatedBearerDoesNotSelectLegacySessionState
// holds a request after bearer authentication, rotates the bearer on another
// request, then resumes the original request in explicit compatibility mode.
// The original principal is still authenticated, but its retired epoch cannot
// be admitted. A client-supplied Mcp-Session-Id must not select the preexisting
// legacy chain state; the request proceeds with stateless controls instead.
func TestHTTPListener_PrincipalState_RotatedBearerDoesNotSelectLegacySessionState(t *testing.T) {
	const (
		oldBearer     = "legacy-fallback-rotation-old"
		newBearer     = "legacy-fallback-rotation-new"
		legacySession = "legacy-partition-that-must-not-bind"
	)

	var active atomic.Value
	active.Store(oldBearer)
	var holdOld atomic.Bool
	oldReachedConfig := make(chan struct{})
	releaseOld := make(chan struct{})
	var oldConfigOnce sync.Once

	upstream, calls := principalStateUpstream(t)
	auditPath := filepath.Join(t.TempDir(), "listener-audit.jsonl")
	auditLogger, err := audit.New("json", "file", auditPath, false, true)
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}
	defer auditLogger.Close()

	chainMatcher := buildBlockChainMatcher()
	legacyStateKey := mcpListenerStateKey(legacySession)
	if verdict := chainMatcher.Record(legacyStateKey, "read_file"); verdict.Matched {
		t.Fatalf("legacy chain seed unexpectedly matched: %+v", verdict)
	}

	compatibilityMode := false
	adaptiveCfg := adaptiveCfgEnabled()
	adaptiveCfg.EscalationThreshold = 1
	opts := principalStateOpts(t, "")
	opts.ListenerBearerTokenFn = func() (string, error) { return active.Load().(string), nil }
	opts.listenerStateTokenRequired = &compatibilityMode
	opts.ChainMatcher = chainMatcher
	opts.InputCfg = newHTTPInputCfg(config.ActionWarn)
	opts.AdaptiveCfgFn = func() *config.AdaptiveEnforcement {
		if holdOld.Load() {
			oldConfigOnce.Do(func() { close(oldReachedConfig) })
			<-releaseOld
		}
		return adaptiveCfg
	}
	opts.Store = &listenerDiagnosisStore{}
	opts.AuditLogger = auditLogger
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	holdOld.Store(true)
	type result struct {
		status int
		body   string
		err    error
	}
	oldResult := make(chan result, 1)
	go func() {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash_exec","arguments":{"token":%q},"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, "sk-ant-"+strings.Repeat("x", 25), currentMCPVersion)
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
		if reqErr != nil {
			oldResult <- result{err: fmt.Errorf("new old-bearer request: %w", reqErr)}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Protocol-Version", currentMCPVersion)
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "bash_exec")
		req.Header.Set("Mcp-Session-Id", legacySession)
		req.Header.Set("Proxy-Authorization", "Bearer "+oldBearer)
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			oldResult <- result{err: fmt.Errorf("old-bearer request: %w", doErr)}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		payload, readErr := io.ReadAll(resp.Body)
		oldResult <- result{status: resp.StatusCode, body: string(payload), err: readErr}
	}()

	<-oldReachedConfig
	active.Store(newBearer)
	holdOld.Store(false)
	if status, body := principalStateToolCall(t, baseURL, newBearer, 2, "read_file", nil); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("rotating bearer request = status %d body %s, want new state admission", status, body)
	}
	close(releaseOld)

	got := <-oldResult
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.status != http.StatusOK || strings.Contains(got.body, "chain pattern") {
		t.Fatalf("retired-but-authenticated request = status %d body %s, want stateless forward", got.status, got.body)
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls = %d, want 2; the retired request must not select the legacy chain partition", calls.Load())
	}

	auditLogger.Close()
	auditData, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditData), `"session":"`+legacySession+`"`) {
		t.Fatalf("unbound request audit key did not retain its compatibility session header: %s", auditData)
	}

	// Positive control. Every security assertion above is a negative one: the
	// retired request was not blocked. That proves the retired principal avoided
	// the legacy partition only if the matcher would have fired had it entered
	// that partition. Complete the chain on the legacy key directly and require
	// a match, so a matcher that silently stops recognising this pattern fails
	// here instead of leaving the test green while proving nothing. Run it after
	// the HTTP assertions so it cannot alter the state the listener observed.
	if verdict := chainMatcher.Record(legacyStateKey, "bash_exec"); !verdict.Matched {
		t.Fatalf("chain matcher did not match the completing step on the legacy partition, so the negative assertions above prove nothing: %+v", verdict)
	}
}

func TestHTTPListener_PrincipalState_VerifierSeparatesAuthenticatedSubjects(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, principalStateTestBearer)
	opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
		return ListenerPrincipal{Provider: "test", Subject: r.Header.Get("X-Test-Verified-Principal")}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	request := func(id int, tool, principal string) (int, string) {
		return principalStateToolCall(t, baseURL, principalStateTestBearer, id, tool, http.Header{
			"X-Test-Verified-Principal": []string{principal},
		})
	}
	if status, body := request(1, "read_file", "alice"); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("alice read = status %d body %s", status, body)
	}
	if status, body := request(2, "bash_exec", "bob"); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("bob inherited alice state = status %d body %s", status, body)
	}
	if status, body := request(3, "bash_exec", "alice"); status != http.StatusOK || !strings.Contains(body, "chain pattern") {
		t.Fatalf("alice follow-up = status %d body %s, want block", status, body)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want alice read and bob exec only", got)
	}
}

func TestHTTPListener_PrincipalState_ResolverCannotSeeConsumedListenerCredential(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, principalStateTestBearer)
	opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" {
			return ListenerPrincipal{}, fmt.Errorf("consumed listener credential reached principal verifier")
		}
		return ListenerPrincipal{Provider: "test", Subject: "verified-subject"}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	status, body := principalStateToolCall(t, baseURL, principalStateTestBearer, 1, "read_file", nil)
	if status != http.StatusOK || strings.Contains(body, "authentication unavailable") {
		t.Fatalf("resolver credential isolation = status %d body %s", status, body)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestHTTPListener_PrincipalState_ResolverFailuresFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolver ListenerPrincipalResolver
	}{
		{name: "resolver error", resolver: func(*http.Request) (ListenerPrincipal, error) {
			return ListenerPrincipal{}, errors.New("verifier unavailable")
		}},
		{name: "subject without provider", resolver: func(*http.Request) (ListenerPrincipal, error) {
			return ListenerPrincipal{Subject: "orphan"}, nil
		}},
		{name: "provider without subject", resolver: func(*http.Request) (ListenerPrincipal, error) {
			return ListenerPrincipal{Provider: "test"}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, calls := principalStateUpstream(t)
			opts := principalStateOpts(t, principalStateTestBearer)
			opts.ListenerPrincipalResolver = tc.resolver
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			status, body := principalStateToolCall(t, baseURL, principalStateTestBearer, 1, "read_file", nil)
			if status != http.StatusServiceUnavailable || !strings.Contains(body, "authentication unavailable") {
				t.Fatalf("status = %d body = %s, want 503 authentication unavailable", status, body)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("failed resolver reached upstream %d times", got)
			}
		})
	}
}

func TestHTTPListener_PrincipalState_VerifierAuthenticatesWithoutListenerBearer(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, principalStateTestBearer)
	opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
		if r.Header.Get("X-Verified-Subject") != "alice" {
			return ListenerPrincipal{}, nil
		}
		return ListenerPrincipal{Provider: "test", Subject: "alice"}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	status, body := principalStateToolCall(t, baseURL, "wrong-bearer", 1, "read_file", http.Header{"X-Verified-Subject": []string{"alice"}})
	if status != http.StatusOK {
		t.Fatalf("verifier-backed authentication = status %d body %s, want 200", status, body)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestHTTPListener_PrincipalState_SlowVerifierDoesNotSerializeRequests(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseVerifier := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseVerifier()
	opts := principalStateOpts(t, "")
	opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
		subject := r.Header.Get("X-Verified-Subject")
		if subject == "slow" {
			close(entered)
			<-release
		}
		return ListenerPrincipal{Provider: "test", Subject: subject}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	slowDone := make(chan struct{})
	slowResult := make(chan error, 1)
	go func() {
		defer close(slowDone)
		status, body, err := principalStateToolCallRequest(baseURL, "", 1, "read_file", http.Header{"X-Verified-Subject": []string{"slow"}})
		if err == nil && status != http.StatusOK {
			err = fmt.Errorf("slow verifier request = status %d body %s, want 200", status, body)
		}
		slowResult <- err
	}()
	<-entered
	status, body := principalStateToolCall(t, baseURL, "", 2, "read_file", http.Header{"X-Verified-Subject": []string{"fast"}})
	if status != http.StatusOK {
		t.Fatalf("fast verifier request = status %d body %s, want 200 while slow resolver is blocked", status, body)
	}
	releaseVerifier()
	<-slowDone
	if err := <-slowResult; err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2", got)
	}
}

func TestHTTPListener_PrincipalState_ResolverRotationScrubsBothBearerGenerations(t *testing.T) {
	oldBearer := strings.Join([]string{"resolver", "rotation", "old"}, "-")
	newBearer := strings.Join([]string{"resolver", "rotation", "new"}, "-")
	var active atomic.Value
	active.Store(oldBearer)
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	upstreamHeaders := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	t.Cleanup(upstream.Close)
	opts := principalStateOpts(t, "")
	opts.ListenerBearerTokenFn = func() (string, error) { return active.Load().(string), nil }
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		close(entered)
		<-release
		return ListenerPrincipal{Provider: "test", Subject: "resolver-subject"}, nil
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	result := make(chan error, 1)
	go func() {
		status, body, err := principalStateToolCallRequest(baseURL, "", 1, "read_file", http.Header{
			"X-Verified-Subject":       []string{"resolver-subject"},
			listenerProxyAuthorization: []string{"Bearer " + newBearer},
			listenerAuthorization:      []string{"Bearer " + oldBearer, "Bearer " + newBearer},
		})
		if err == nil && status != http.StatusOK {
			err = fmt.Errorf("rotated resolver request = status %d body %s, want 200", status, body)
		}
		result <- err
	}()
	<-entered
	active.Store(newBearer)
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case headers := <-upstreamHeaders:
		if headers.Get(listenerAuthorization) != "" || headers.Get(listenerProxyAuthorization) != "" {
			t.Fatalf("upstream received listener bearer headers: Authorization=%q Proxy-Authorization=%q", headers.Get(listenerAuthorization), headers.Get(listenerProxyAuthorization))
		}
	case <-time.After(time.Second):
		t.Fatal("rotated resolver request did not reach upstream")
	}
}

func TestRoutingHeaderMatchesFrame_RejectsNameForUnsupportedMethod(t *testing.T) {
	headers := http.Header{}
	headers.Set(listenerMCPMethod, "resources/subscribe")
	headers.Set(listenerMCPName, "unscanned-entity")
	if routingHeaderMatchesFrame(headers, MCPFrame{Method: "resources/subscribe"}) {
		t.Fatal("Mcp-Name on an unsupported routing method must be rejected")
	}
}

func TestMCPListenerPrincipalState_ExpiredIdleStateNeverResurrects(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	now := time.Unix(1_800_000_000, 0)
	states.now = func() time.Time { return now }
	principal, err := states.principal("test", "alice", 0)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	first, ok := states.stateForPrincipal(principal)
	if !ok {
		t.Fatal("first state admission failed")
	}
	for len(states.clients) < maxMCPListenerClients {
		key := fmt.Sprintf("filler-%d", len(states.clients))
		state := newMCPListenerClientState("legacy", key)
		states.touchLocked(state)
		states.clients[key] = state
	}
	now = now.Add(listenerPrincipalIdleTTL + time.Second)
	for _, state := range states.clients {
		if state != first {
			states.touchLocked(state)
		}
	}
	second, ok := states.stateForPrincipal(principal)
	if !ok {
		t.Fatal("expired principal was not recoverable at registry capacity")
	}
	if second == first || !first.revoked.Load() {
		t.Fatal("expired principal state was reused instead of revoked and recreated")
	}
}

func TestMCPListenerPrincipalState_DoWTrustMatchesIdentityStrength(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	bearer, err := states.bearerPrincipal("shared-secret")
	if err != nil {
		t.Fatalf("bearerPrincipal: %v", err)
	}
	if bearer.trust != config.DoWTrustAgent {
		t.Fatalf("shared bearer trust = %s, want agent", bearer.trust)
	}
	rotatedBearer, err := states.bearerPrincipal("rotated-secret")
	if err != nil {
		t.Fatalf("rotated bearer: %v", err)
	}
	if bearer.key == rotatedBearer.key || bearer.billingKey != rotatedBearer.billingKey {
		t.Fatal("bearer rotation must reset security state without resetting its DoW budget")
	}
	verified, err := states.principal("oauth", "subject-42", 0)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	if verified.trust != config.DoWTrustPrincipal {
		t.Fatalf("verified subject trust = %s, want principal", verified.trust)
	}
	verifiedNextEpoch, err := states.principal("oauth", "subject-42", 1)
	if err != nil {
		t.Fatalf("next verifier epoch: %v", err)
	}
	if verified.key == verifiedNextEpoch.key || verified.billingKey != verifiedNextEpoch.billingKey {
		t.Fatal("verifier epoch must reset security state without resetting its DoW budget")
	}
}

func TestMCPListenerPrincipalState_StaleAuthenticatedBearerCannotUndoRotation(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	oldPrincipal, err := states.bearerPrincipal("old-secret")
	if err != nil {
		t.Fatalf("old bearer: %v", err)
	}
	newPrincipal, err := states.bearerPrincipal("new-secret")
	if err != nil {
		t.Fatalf("new bearer: %v", err)
	}
	newState, ok := states.stateForPrincipal(newPrincipal)
	if !ok {
		t.Fatal("new bearer state admission failed")
	}
	if stale, ok := states.stateForPrincipal(oldPrincipal); ok || stale != nil {
		t.Fatal("stale pre-rotation authentication restored the retired epoch")
	}
	if got, ok := states.stateForPrincipal(newPrincipal); !ok || got != newState {
		t.Fatal("stale admission displaced the active bearer state")
	}
}

func TestMCPListenerPrincipalState_RotationWaitDoesNotHoldRegistryLock(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	oldPrincipal, err := states.bearerPrincipal("old-secret")
	if err != nil {
		t.Fatalf("old bearer: %v", err)
	}
	oldState, ok := states.stateForPrincipal(oldPrincipal)
	if !ok {
		t.Fatal("old state admission failed")
	}
	oldState.commitMu.Lock()
	contended := make(chan struct{})
	states.revokeContentionSignal = contended
	newPrincipal, err := states.bearerPrincipal("new-secret")
	if err != nil {
		oldState.commitMu.Unlock()
		t.Fatalf("new bearer: %v", err)
	}
	rotationDone := make(chan struct{})
	go func() {
		_, _ = states.stateForPrincipal(newPrincipal)
		close(rotationDone)
	}()
	select {
	case <-contended:
	case <-time.After(time.Second):
		oldState.commitMu.Unlock()
		t.Fatal("rotation never reached the retired in-flight response")
	}

	registryReadable := make(chan bool, 1)
	go func() {
		states.mu.Lock()
		_, admitted := states.clients[newPrincipal.key]
		states.mu.Unlock()
		registryReadable <- admitted
	}()
	select {
	case admitted := <-registryReadable:
		if !admitted {
			oldState.commitMu.Unlock()
			t.Fatal("new state was not admitted before retired response commit drained")
		}
	case <-time.After(time.Second):
		oldState.commitMu.Unlock()
		t.Fatal("rotation held the listener registry lock while waiting for a response commit")
	}
	select {
	case <-rotationDone:
		oldState.commitMu.Unlock()
		t.Fatal("rotation completed while retired response commit was still active")
	default:
	}
	oldState.commitMu.Unlock()
	select {
	case <-rotationDone:
	case <-time.After(time.Second):
		t.Fatal("rotation did not finish after retired response commit drained")
	}
}

func TestMCPListenerPrincipalState_PrincipalAdmissionEvictsLegacyFirst(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	for i := range maxMCPListenerClients {
		key := fmt.Sprintf("legacy-%d", i)
		state := newMCPListenerClientState("legacy", key)
		states.touchLocked(state)
		states.clients[key] = state
	}
	principal, err := states.principal("oauth", "subject-42", 0)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	state, ok := states.stateForPrincipal(principal)
	if !ok || state == nil {
		t.Fatal("authenticated principal was starved by evictable legacy states")
	}
	if len(states.clients) != maxMCPListenerClients {
		t.Fatalf("registry size = %d, want capped %d", len(states.clients), maxMCPListenerClients)
	}
}

func TestMCPListenerPrincipalState_RetriesSecretInitialization(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	states.principalSecretErr = errors.New("transient entropy failure")
	principal, err := states.principal("oauth", "subject-42", 0)
	if err != nil || principal.key == "" {
		t.Fatalf("transient entropy failure remained latched: principal=%#v err=%v", principal, err)
	}
}

// TestHTTPListener_PrincipalState_UnidentifiedStatefulCurrentSpecFailsClosed
// prevents the old unbound/transient fallback from turning a missing identity
// into a skipped stateful guard.
func TestHTTPListener_PrincipalState_UnidentifiedStatefulCurrentSpecFailsClosed(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, "")
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	status, body := principalStateToolCall(t, baseURL, "", 1, "read_file", nil)
	if status < http.StatusBadRequest || status >= http.StatusInternalServerError {
		t.Fatalf("unidentified stateful current-spec call = status %d body %s, want explicit client denial", status, body)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("unidentified stateful call reached upstream %d times, want 0", got)
	}
}

func TestHTTPListener_PrincipalState_UnidentifiedDenialDoesNotSpendDoWBudget(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, "")
	var budgetChecks atomic.Int32
	opts.DoWCheck = func(_, _, _ string) (bool, string, string, string) {
		budgetChecks.Add(1)
		return true, "", "", ""
	}
	opts.DoWEnabledFn = func() bool { return true }
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	status, body := principalStateToolCall(t, baseURL, "", 1, "read_file", nil)
	if status < http.StatusBadRequest || status >= http.StatusInternalServerError {
		t.Fatalf("unidentified call = status %d body %s, want identity denial", status, body)
	}
	if got := budgetChecks.Load(); got != 0 {
		t.Fatalf("unidentified request spent DoW budget %d times, want 0", got)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("unidentified call reached upstream %d times, want 0", got)
	}
}

// TestHTTPListener_PrincipalState_DeleteRetainsSecurityHistory verifies that a
// tokenless current-spec DELETE cannot prove ownership of a principal state and
// therefore must not clear it. It is forwarded to the upstream, while the later
// exec remains blocked by the preceding authenticated read.
func TestHTTPListener_PrincipalState_DeleteRetainsSecurityHistory(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	opts := principalStateOpts(t, principalStateTestBearer)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)

	if status, body := principalStateToolCall(t, baseURL, principalStateTestBearer, 1, "read_file", nil); status != http.StatusOK || strings.Contains(body, "chain pattern") {
		t.Fatalf("read before DELETE = status %d body %s, want allowed", status, body)
	}
	if status, body := principalStateDelete(t, baseURL, principalStateTestBearer); status != http.StatusNoContent || body != "" {
		t.Fatalf("current-spec DELETE = status %d body %q, want 204 and empty", status, body)
	}
	if status, body := principalStateToolCall(t, baseURL, principalStateTestBearer, 2, "bash_exec", nil); status != http.StatusOK || !strings.Contains(body, "chain pattern") {
		t.Fatalf("exec after tokenless DELETE = status %d body %s, want retained-principal-state block", status, body)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2: read and DELETE only", got)
	}
}
