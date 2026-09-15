// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Split AWS example access key (test fixture, not a live credential): the
// same split used by internal/scanner/fragment_buffer_test.go.
const (
	crossReqAWSPart1 = "AKI" + "A"
	crossReqAWSPart2 = "IOSF" + "ODNN7EXAMPLE"
)

// newCrossRequestTestHandler returns a Handler with cross-request fragment
// reassembly enabled and a small buffer, so tests can drive capacity
// exhaustion without huge inputs.
func newCrossRequestTestHandler(t *testing.T, maxBufferBytes, maxSessions int) *Handler {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ScanAPI.Auth.BearerTokens = []string{testToken}
	cfg.CrossRequestDetection = config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: maxBufferBytes,
			MaxSessions:    &maxSessions,
			WindowMinutes:  5,
		},
	}
	sc := scanner.MustNew(cfg)
	m := metrics.New()
	return NewHandler(cfg, sc, nil, m, "test-version")
}

func postScanAPI(t *testing.T, h *Handler, body string) (Response, int) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v (body=%s)", err, w.Body.String())
	}
	return resp, w.Code
}

func dlpScanBody(t *testing.T, text, sessionID string) string {
	t.Helper()
	req := Request{
		Kind:  KindDLP,
		Input: Input{Text: text},
	}
	if sessionID != "" {
		req.Context = &RequestContext{SessionID: sessionID}
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(b)
}

func TestCrossRequestFragment_SplitSecretAcrossTwoRequests(t *testing.T) {
	h := newCrossRequestTestHandler(t, 65536, 100)

	first, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart1, "sess-a"))
	if status != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d (%+v)", status, first)
	}
	if first.Decision != DecisionAllow {
		t.Fatalf("first request: expected allow, got %q findings=%+v", first.Decision, first.Findings)
	}
	firstScanID := first.ScanID
	if firstScanID == "" {
		t.Fatal("first request: expected a non-empty scan_id")
	}

	second, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart2, "sess-a"))
	if status != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d (%+v)", status, second)
	}
	if second.Decision != DecisionDeny {
		t.Fatalf("second request: expected deny (split secret completed), got %q findings=%+v", second.Decision, second.Findings)
	}
	if second.SessionID != "sess-a" {
		t.Errorf("second request: expected session_id echoed as %q, got %q", "sess-a", second.SessionID)
	}

	var fragFinding *Finding
	for i := range second.Findings {
		if second.Findings[i].Scanner == "cross_request_fragment" {
			fragFinding = &second.Findings[i]
			break
		}
	}
	if fragFinding == nil {
		t.Fatalf("second request: expected a cross_request_fragment finding, got %+v", second.Findings)
	}
	if len(fragFinding.Contributors) == 0 {
		t.Fatal("expected non-empty Contributors provenance on the completing finding")
	}
	found := false
	for _, c := range fragFinding.Contributors {
		if c == firstScanID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected contributors %v to include first request's scan_id %q", fragFinding.Contributors, firstScanID)
	}
}

func TestCrossRequestFragment_DifferentSessionIDsDoNotLeak(t *testing.T) {
	h := newCrossRequestTestHandler(t, 65536, 100)

	first, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart1, "sess-a"))
	if status != http.StatusOK || first.Decision != DecisionAllow {
		t.Fatalf("first request: expected 200/allow, got %d %q", status, first.Decision)
	}

	second, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart2, "sess-b"))
	if status != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", status)
	}
	if second.Decision != DecisionAllow {
		t.Fatalf("second request: expected allow (different session_id must not see sess-a's fragment), got %q findings=%+v", second.Decision, second.Findings)
	}
}

// TestCrossRequestFragment_NoSessionIDIsStatelessAndUnchanged is the golden
// no-session regression: the response for a request without context or
// session_id must be byte-for-byte identical to the response the same
// content produced before cross-request wiring existed. Cross-request
// detection introduced two new fields (Response.SessionID,
// Finding.Contributors), both `omitempty`, so an unaffected response
// marshals identically.
func TestCrossRequestFragment_NoSessionIDIsStatelessAndUnchanged(t *testing.T) {
	h := newCrossRequestTestHandler(t, 65536, 100)

	const wantJSONShape = `{"status":"completed","decision":"allow","kind":"dlp","scan_id":`

	first, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart1, ""))
	if status != http.StatusOK || first.Decision != DecisionAllow {
		t.Fatalf("first request: expected 200/allow, got %d %q", status, first.Decision)
	}
	second, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart2, ""))
	if status != http.StatusOK || second.Decision != DecisionAllow {
		t.Fatalf("second request (no session_id): expected allow even though the split secret would complete under a session, got %q findings=%+v", second.Decision, second.Findings)
	}
	if second.SessionID != "" {
		t.Errorf("expected no session_id echoed when the request omitted it, got %q", second.SessionID)
	}
	if len(second.Findings) != 0 {
		t.Errorf("expected zero findings on the stateless path, got %+v", second.Findings)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(dlpScanBody(t, "safe", "")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !strings.HasPrefix(w.Body.String(), wantJSONShape) {
		t.Errorf("golden shape check: expected prefix %q, got %q", wantJSONShape, w.Body.String())
	}
}

func TestValidateSessionID(t *testing.T) {
	longID := strings.Repeat("a", maxScanAPISessionIDBytes+1)
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"empty is valid (stateless)", "", false},
		{"simple ascii", "session-123", false},
		{"exactly at bound", strings.Repeat("a", maxScanAPISessionIDBytes), false},
		{"too long", longID, true},
		{"contains space", "session 123", true},
		{"contains tab", "session\t123", true},
		{"contains newline", "session\n123", true},
		{"contains control char", "session\x01123", true},
		{"non-ascii", "sessión", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSessionID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSessionID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestHandler_MalformedSessionIDRejected(t *testing.T) {
	h := newCrossRequestTestHandler(t, 65536, 100)
	resp, status := postScanAPI(t, h, dlpScanBody(t, "safe", strings.Repeat("x", maxScanAPISessionIDBytes+1)))
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%+v)", status, resp)
	}
	if len(resp.Errors) == 0 || resp.Errors[0].Code != "invalid_session_id" {
		t.Fatalf("expected invalid_session_id error, got %+v", resp.Errors)
	}
}

func TestHandler_MalformedSessionIDWhitespaceRejected(t *testing.T) {
	h := newCrossRequestTestHandler(t, 65536, 100)
	resp, status := postScanAPI(t, h, dlpScanBody(t, "safe", "has space"))
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%+v)", status, resp)
	}
	if len(resp.Errors) == 0 || resp.Errors[0].Code != "invalid_session_id" {
		t.Fatalf("expected invalid_session_id error, got %+v", resp.Errors)
	}
}

// TestCrossRequestFragment_CapacityExhaustionFailsClosed reproduces the
// documented failure direction: once the global session ledger is full, a
// NEW session cannot be admitted, and that request must be denied (fail
// closed) rather than silently allowed with no cross-request inspection.
func TestCrossRequestFragment_CapacityExhaustionFailsClosed(t *testing.T) {
	h := newCrossRequestTestHandler(t, 65536, 1) // exactly one session slot

	// Occupy the single slot.
	first, status := postScanAPI(t, h, dlpScanBody(t, "occupying content", "sess-full-a"))
	if status != http.StatusOK || first.Decision != DecisionAllow {
		t.Fatalf("first request: expected 200/allow, got %d %q", status, first.Decision)
	}

	// A second, distinct session cannot be admitted: capacity is exhausted.
	second, status := postScanAPI(t, h, dlpScanBody(t, "other content", "sess-full-b"))
	if status != http.StatusOK {
		t.Fatalf("second request: expected 200 (evaluation-only endpoint denies via decision, not transport error), got %d", status)
	}
	if second.Decision != DecisionDeny {
		t.Fatalf("second request: expected deny (fail-closed on capacity exhaustion), got %q findings=%+v", second.Decision, second.Findings)
	}
	found := false
	for _, f := range second.Findings {
		if f.RuleID == "CEE-capacity-exceeded" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a CEE-capacity-exceeded finding, got %+v", second.Findings)
	}
}

// TestCrossRequestFragment_CallerIsolation confirms that two different
// bearer tokens sharing the exact same session_id do not share fragment
// state: the caller identity is folded into the key
// (identitykey.NewScanAPIIdentity), so one integrator cannot see or
// contribute to another integrator's session merely by guessing its
// session_id.
func TestCrossRequestFragment_CallerIsolation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	const tokenA, tokenB = "caller-token-a", "caller-token-b"
	cfg.ScanAPI.Auth.BearerTokens = []string{tokenA, tokenB}
	maxSessions := 100
	cfg.CrossRequestDetection = config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			MaxSessions:    &maxSessions,
			WindowMinutes:  5,
		},
	}
	sc := scanner.MustNew(cfg)
	m := metrics.New()
	h := NewHandler(cfg, sc, nil, m, "test-version")

	post := func(token, body string) (Response, int) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var resp Response
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		return resp, w.Code
	}

	first, status := post(tokenA, dlpScanBody(t, crossReqAWSPart1, "shared-session-id"))
	if status != http.StatusOK || first.Decision != DecisionAllow {
		t.Fatalf("caller A first request: expected 200/allow, got %d %q", status, first.Decision)
	}
	// Caller B uses the SAME session_id but a different bearer token.
	second, status := post(tokenB, dlpScanBody(t, crossReqAWSPart2, "shared-session-id"))
	if status != http.StatusOK {
		t.Fatalf("caller B request: expected 200, got %d", status)
	}
	if second.Decision != DecisionAllow {
		t.Fatalf("caller B: expected allow (must not see caller A's fragment under a shared session_id), got %q findings=%+v", second.Decision, second.Findings)
	}
}

func TestCrossRequestFragment_ConcurrentRequestsSameSession(t *testing.T) {
	h := newCrossRequestTestHandler(t, 1<<20, 1000)
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := dlpScanBody(t, fmt.Sprintf("concurrent payload %d", i), "concurrent-session")
			_, status := postScanAPI(t, h, body)
			if status != http.StatusOK {
				t.Errorf("worker %d: expected 200, got %d", i, status)
			}
		}(i)
	}
	wg.Wait()
}

func TestCrossRequestFragment_PromptInjectionAndToolCallKindsParticipate(t *testing.T) {
	h := newCrossRequestTestHandler(t, 65536, 100)

	firstBody, err := json.Marshal(Request{
		Kind:    KindPromptInjection,
		Input:   Input{Content: crossReqAWSPart1},
		Context: &RequestContext{SessionID: "inj-session"},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, status := postScanAPI(t, h, string(firstBody))
	if status != http.StatusOK || first.Decision != DecisionAllow {
		t.Fatalf("first prompt_injection request: expected 200/allow, got %d %q findings=%+v", status, first.Decision, first.Findings)
	}

	secondBody, err := json.Marshal(Request{
		Kind:    KindToolCall,
		Input:   Input{ToolName: "tool", Arguments: RawJSON(`{"arg":"` + crossReqAWSPart2 + `"}`)},
		Context: &RequestContext{SessionID: "inj-session"},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, status := postScanAPI(t, h, string(secondBody))
	if status != http.StatusOK {
		t.Fatalf("second tool_call request: expected 200, got %d", status)
	}
	if second.Decision != DecisionDeny {
		t.Fatalf("second tool_call request: expected deny (split secret completed across kinds), got %q findings=%+v", second.Decision, second.Findings)
	}
}

// TestCrossRequestFragment_WarnActionEscalatesToWarnNotDeny reproduces the
// documented action-mode behavior: cross_request_detection.action=warn
// escalates a clean per-request result to "warn" (with a finding carrying
// provenance) rather than "deny", matching the MCP proxy's warn-mode
// (LogAnomaly, not block) precedent in internal/mcp/cee.go.
func TestCrossRequestFragment_WarnActionEscalatesToWarnNotDeny(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ScanAPI.Auth.BearerTokens = []string{testToken}
	maxSessions := 100
	cfg.CrossRequestDetection = config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionWarn,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			MaxSessions:    &maxSessions,
			WindowMinutes:  5,
		},
	}
	sc := scanner.MustNew(cfg)
	m := metrics.New()
	h := NewHandler(cfg, sc, nil, m, "test-version")

	first, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart1, "warn-session"))
	if status != http.StatusOK || first.Decision != DecisionAllow {
		t.Fatalf("first request: expected 200/allow, got %d %q", status, first.Decision)
	}
	second, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart2, "warn-session"))
	if status != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", status)
	}
	if second.Decision != DecisionWarn {
		t.Fatalf("second request: expected warn (action=warn must not deny), got %q findings=%+v", second.Decision, second.Findings)
	}
	found := false
	for _, f := range second.Findings {
		if f.Scanner == "cross_request_fragment" && len(f.Contributors) > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a cross_request_fragment finding with contributors even in warn mode, got %+v", second.Findings)
	}
}

// TestCrossRequestFragments_CurrentBuildsUpdatesAndTearsDown drives
// crossRequestFragments.current directly across disabled -> enabled ->
// reconfigured -> disabled, covering the rebuild-on-change and
// close-on-disable branches that an end-to-end HTTP test cannot reach
// deterministically (they depend on observing two DIFFERENT configs across
// two calls on the same Handler state, which hot reload would do live but a
// single-process test drives directly).
func TestCrossRequestFragments_CurrentBuildsUpdatesAndTearsDown(t *testing.T) {
	var c crossRequestFragments

	// Disabled: no buffer.
	if buf := c.current(config.CrossRequestDetection{Enabled: false}); buf != nil {
		t.Fatal("expected nil buffer when cross_request_detection is disabled")
	}

	maxSessionsA := 10
	cfgA := config.CrossRequestDetection{
		Enabled: true,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 4096,
			MaxSessions:    &maxSessionsA,
			WindowMinutes:  5,
		},
	}
	bufA := c.current(cfgA)
	if bufA == nil {
		t.Fatal("expected a non-nil buffer once fragment reassembly is enabled")
	}

	// Same config again: must return the SAME instance (no unnecessary
	// rebuild, which would silently drop any state already accumulated).
	bufSame := c.current(cfgA)
	if bufSame != bufA {
		t.Error("expected current() to return the same buffer instance for an unchanged config")
	}

	// Changed byte budget: must reconfigure the existing instance in place
	// (UpdateConfig), not silently keep serving the old limits.
	maxSessionsB := 20
	cfgB := cfgA
	cfgB.FragmentReassembly.MaxBufferBytes = 8192
	cfgB.FragmentReassembly.MaxSessions = &maxSessionsB
	bufB := c.current(cfgB)
	if bufB != bufA {
		t.Error("expected current() to reconfigure the existing instance, not allocate a new one, on a config change")
	}

	// Disabled again: buffer torn down.
	if buf := c.current(config.CrossRequestDetection{Enabled: false}); buf != nil {
		t.Fatal("expected nil buffer once cross_request_detection is disabled again")
	}

	// Re-enabling after a teardown must build a fresh instance.
	bufC := c.current(cfgA)
	if bufC == nil {
		t.Fatal("expected a fresh non-nil buffer after re-enabling")
	}
	if bufC == bufA {
		t.Error("expected a NEW buffer instance after teardown and re-enable, not the torn-down one")
	}
}

// TestCrossRequestFragment_DisabledConfigWithSessionIDIsANoOp covers the
// case where a caller supplies context.session_id but the operator has not
// enabled cross_request_detection (or its fragment_reassembly stage): the
// session_id is still validated and echoed, but no state is written and no
// cross-request finding can occur, matching "reserved metadata" semantics
// for a disabled deployment.
func TestCrossRequestFragment_DisabledConfigWithSessionIDIsANoOp(t *testing.T) {
	h := newTestHandler(t) // config.Defaults(): CrossRequestDetection.Enabled is false
	resp, status := postScanAPI(t, h, dlpScanBody(t, crossReqAWSPart1, "disabled-session"))
	if status != http.StatusOK || resp.Decision != DecisionAllow {
		t.Fatalf("expected 200/allow, got %d %q", status, resp.Decision)
	}
	if resp.SessionID != "disabled-session" {
		t.Errorf("expected session_id still echoed even when cross-request detection is disabled, got %q", resp.SessionID)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("expected zero findings, got %+v", resp.Findings)
	}
}
