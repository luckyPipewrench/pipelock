// Copyright 2026 Pipelock contributors
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
)

const (
	wireContractProtocolVersion = currentMCPVersion
	wireContractHeaderMismatch  = mcpHeaderMismatchCode
	wireContractProtocolHeader  = listenerProtocolVersion
	wireContractMethodHeader    = listenerMCPMethod
	wireContractNameHeader      = listenerMCPName
)

// wireContractUpstreamCapture records only requests that reached the real
// upstream. A rejected request must leave this capture empty: an error emitted
// after forwarding would not protect an upstream that routes on these headers.
type wireContractUpstreamCapture struct {
	calls   atomic.Int32
	mu      sync.Mutex
	headers http.Header
}

func (c *wireContractUpstreamCapture) headerValues(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.headers.Values(name)...)
}

func newWireContractUpstream(t *testing.T) (*httptest.Server, *wireContractUpstreamCapture) {
	t.Helper()

	capture := &wireContractUpstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.calls.Add(1)
		capture.mu.Lock()
		capture.headers = r.Header.Clone()
		capture.mu.Unlock()

		var request struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(request.ID) == 0 {
			request.ID = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, request.ID)
	}))
	t.Cleanup(upstream.Close)
	return upstream, capture
}

func currentWireHeaders(method, name string) http.Header {
	headers := http.Header{}
	headers.Set(wireContractProtocolHeader, wireContractProtocolVersion)
	headers.Set(wireContractMethodHeader, method)
	if name != "" {
		headers.Set(wireContractNameHeader, name)
	}
	return headers
}

func currentWireBody(id int, method, routedParams string) string {
	meta := fmt.Sprintf(`"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}`, currentMCPVersion)
	if routedParams != "" {
		meta = routedParams + "," + meta
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":{%s}}`, id, method, meta)
}

func postWireContractRequest(t *testing.T, baseURL, body string, headers http.Header) (int, http.Header, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST listener: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(listener response): %v", err)
	}
	return resp.StatusCode, resp.Header.Clone(), string(payload)
}

func requireWireHeaderMismatch(t *testing.T, status int, body string) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s, want 400 HeaderMismatch", status, body)
	}
	var response struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("decode HeaderMismatch response: %v (body %s)", err, body)
	}
	if response.Error.Code != wireContractHeaderMismatch {
		t.Fatalf("error code = %d body = %s, want %d (HeaderMismatch)", response.Error.Code, body, wireContractHeaderMismatch)
	}
}

// The 2026-07-28 protocol makes the version and routing headers a second
// representation of the request Pipelock scans. For a current request their
// absence or disagreement cannot be tolerated as a legacy fallback.
func TestHTTPListener_CurrentWireContractRejectsIncompleteOrMismatchedHeaders(t *testing.T) {
	goodBody := currentWireBody(1, "tools/call", `"name":"echo","arguments":{}`)
	missingProtocolVersion := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}}`
	missingClientCapabilities := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}}`, currentMCPVersion)
	malformedClientCapabilities := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":false}}}`, currentMCPVersion)

	for _, tc := range []struct {
		name        string
		body        string
		mutateHeads func(http.Header)
	}{
		{
			name: "missing protocol header",
			body: goodBody,
			mutateHeads: func(headers http.Header) {
				headers.Del(wireContractProtocolHeader)
			},
		},
		{
			name:        "missing body protocol version",
			body:        missingProtocolVersion,
			mutateHeads: func(http.Header) {},
		},
		{
			name:        "missing body client capabilities",
			body:        missingClientCapabilities,
			mutateHeads: func(http.Header) {},
		},
		{
			name:        "client capabilities is not an object",
			body:        malformedClientCapabilities,
			mutateHeads: func(http.Header) {},
		},
		{
			name: "protocol version mismatch",
			body: goodBody,
			mutateHeads: func(headers http.Header) {
				headers.Set(wireContractProtocolHeader, "2025-11-25")
			},
		},
		{
			name: "missing method header",
			body: goodBody,
			mutateHeads: func(headers http.Header) {
				headers.Del(wireContractMethodHeader)
			},
		},
		{
			name: "method mismatch",
			body: goodBody,
			mutateHeads: func(headers http.Header) {
				headers.Set(wireContractMethodHeader, "tools/list")
			},
		},
		{
			name: "missing name header",
			body: goodBody,
			mutateHeads: func(headers http.Header) {
				headers.Del(wireContractNameHeader)
			},
		},
		{
			name: "name mismatch",
			body: goodBody,
			mutateHeads: func(headers http.Header) {
				headers.Set(wireContractNameHeader, "read_note")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, capture := newWireContractUpstream(t)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
			headers := currentWireHeaders("tools/call", "echo")
			tc.mutateHeads(headers)

			status, _, body := postWireContractRequest(t, baseURL, tc.body, headers)
			requireWireHeaderMismatch(t, status, body)
			if got := capture.calls.Load(); got != 0 {
				t.Fatalf("upstream calls = %d, want 0 for rejected current request", got)
			}
		})
	}
}

func TestHTTPListener_CurrentWireContractMatchesToolResourceAndPromptNames(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		params     string
		headerName string
		wantPass   bool
	}{
		{
			name:       "tool name matches",
			method:     "tools/call",
			params:     `"name":"echo","arguments":{}`,
			headerName: "echo",
			wantPass:   true,
		},
		{
			name:       "resource URI matches",
			method:     "resources/read",
			params:     `"uri":"file:///project/config.json"`,
			headerName: "file:///project/config.json",
			wantPass:   true,
		},
		{
			name:       "prompt name matches",
			method:     "prompts/get",
			params:     `"name":"release-check"`,
			headerName: "release-check",
			wantPass:   true,
		},
		{
			name:       "resource URI mismatch",
			method:     "resources/read",
			params:     `"uri":"file:///project/config.json"`,
			headerName: "file:///project/other.json",
			wantPass:   false,
		},
		{
			name:       "prompt name mismatch",
			method:     "prompts/get",
			params:     `"name":"release-check"`,
			headerName: "other-prompt",
			wantPass:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, capture := newWireContractUpstream(t)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
			status, _, body := postWireContractRequest(t, baseURL,
				currentWireBody(1, tc.method, tc.params), currentWireHeaders(tc.method, tc.headerName))

			if tc.wantPass {
				if status != http.StatusOK {
					t.Fatalf("status = %d body = %s, want 200", status, body)
				}
				if got := capture.calls.Load(); got != 1 {
					t.Fatalf("upstream calls = %d, want 1 for agreeing current request", got)
				}
				return
			}

			requireWireHeaderMismatch(t, status, body)
			if got := capture.calls.Load(); got != 0 {
				t.Fatalf("upstream calls = %d, want 0 for name mismatch", got)
			}
		})
	}
}

func TestHTTPListener_CurrentWireContractAcceptsEncodedUnicodeName(t *testing.T) {
	upstream, capture := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})

	status, _, body := postWireContractRequest(t, baseURL,
		currentWireBody(1, "tools/call", `"name":"héllo","arguments":{}`),
		currentWireHeaders("tools/call", "=?base64?aMOpbGxv?="))
	if status != http.StatusOK {
		t.Fatalf("encoded Unicode Mcp-Name status = %d body = %s, want 200", status, body)
	}
	if got := capture.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 for encoded Unicode name", got)
	}
}

func TestHTTPListener_LegacyRoutingHeaderRequiresComparableBodyName(t *testing.T) {
	for _, params := range []string{`"arguments":{}`, `"name":false,"arguments":{}`} {
		upstream, capture := newWireContractUpstream(t)
		baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
		headers := http.Header{}
		headers.Set(wireContractMethodHeader, "tools/call")
		headers.Set(wireContractNameHeader, "echo")
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{%s}}`, params)
		status, _, response := postWireContractRequest(t, baseURL, body, headers)
		requireWireHeaderMismatch(t, status, response)
		if got := capture.calls.Load(); got != 0 {
			t.Fatalf("legacy header without comparable body name reached upstream %d times", got)
		}
	}
}

func TestHTTPListener_CurrentWireContractForwardsMCPParamHeaders(t *testing.T) {
	upstream, capture := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
	headers := currentWireHeaders("tools/call", "echo")
	headers.Add("Mcp-Param-Region", "us-west-2")
	headers.Add("Mcp-Param-Trace", "release-proof")

	status, _, body := postWireContractRequest(t, baseURL,
		currentWireBody(1, "tools/call", `"name":"echo","arguments":{}`), headers)
	if status != http.StatusOK {
		t.Fatalf("status = %d body = %s, want 200", status, body)
	}
	if got := capture.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	if got := capture.headerValues("Mcp-Param-Region"); len(got) != 1 || got[0] != "us-west-2" {
		t.Fatalf("upstream Mcp-Param-Region = %q, want [us-west-2]", got)
	}
	if got := capture.headerValues("Mcp-Param-Trace"); len(got) != 1 || got[0] != "release-proof" {
		t.Fatalf("upstream Mcp-Param-Trace = %q, want [release-proof]", got)
	}
}

func TestHTTPListener_CurrentWireContractCORSAllowsRequestedMCPParamHeaders(t *testing.T) {
	upstream, _ := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:                testScannerForHTTP(t),
		ListenerAllowedOrigins: []string{"https://client.example"},
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions, baseURL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", "https://client.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Mcp-Param-Region")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS listener: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers")), "mcp-param-region") {
		t.Fatalf("Access-Control-Allow-Headers = %q, want requested Mcp-Param-Region", resp.Header.Get("Access-Control-Allow-Headers"))
	}
}

func TestHTTPListener_CurrentWireContractRejectsGETAndDELETE(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			upstream, capture := newWireContractUpstream(t)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
			req, err := http.NewRequestWithContext(context.Background(), method, baseURL+"/", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set(wireContractProtocolHeader, wireContractProtocolVersion)
			req.Header.Set(wireContractMethodHeader, "tools/call")
			req.Header.Set(wireContractNameHeader, "echo")
			req.Header.Set("Mcp-Param-Region", "us-west-2")
			if method == http.MethodGet {
				req.Header.Set("Accept", "text/event-stream")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405 for current protocol %s", resp.StatusCode, method)
			}
			if got := capture.calls.Load(); got != 0 {
				t.Fatalf("current %s reached upstream %d times", method, got)
			}
		})
	}
}

func TestHTTPListener_LegacyNonPOSTRejectsPOSTOnlyHeaders(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			upstream, capture := newWireContractUpstream(t)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
			req, err := http.NewRequestWithContext(context.Background(), method, baseURL+"/", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set(wireContractMethodHeader, "tools/call")
			if method == http.MethodGet {
				req.Header.Set("Accept", "text/event-stream")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if got := capture.calls.Load(); got != 0 {
				t.Fatalf("legacy %s reached upstream %d times", method, got)
			}
		})
	}
}

func TestHTTPListener_FutureWireVersionFailsClosedAsUnsupported(t *testing.T) {
	upstream, capture := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
	body := strings.Replace(currentWireBody(1, "tools/call", `"name":"echo","arguments":{}`), wireContractProtocolVersion, "2027-01-15", 1)
	headers := currentWireHeaders("tools/call", "echo")
	headers.Set(wireContractProtocolHeader, "2027-01-15")
	status, _, response := postWireContractRequest(t, baseURL, body, headers)
	if status != http.StatusBadRequest || !strings.Contains(response, `"code":-32022`) {
		t.Fatalf("matching future version status = %d body = %s, want 400 unsupported version", status, response)
	}
	if got := capture.calls.Load(); got != 0 {
		t.Fatalf("unsupported future version reached upstream %d times", got)
	}
}

func TestHTTPListener_FutureBodyVersionWithoutHeaderFailsClosed(t *testing.T) {
	upstream, capture := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})
	body := strings.Replace(currentWireBody(1, "tools/call", `"name":"echo","arguments":{}`), wireContractProtocolVersion, "2027-01-15", 1)
	headers := currentWireHeaders("tools/call", "echo")
	headers.Del(wireContractProtocolHeader)
	status, _, response := postWireContractRequest(t, baseURL, body, headers)
	if status != http.StatusBadRequest || !strings.Contains(response, `"code":-32022`) {
		t.Fatalf("future body version = status %d body %s, want 400 unsupported version", status, response)
	}
	if got := capture.calls.Load(); got != 0 {
		t.Fatalf("unsupported future body version reached upstream %d times", got)
	}
}

// Legacy clients omit the current-version headers and metadata entirely. Their
// availability must not be mistaken for permission to accept an incomplete
// current request, which the preceding test rejects.
func TestHTTPListener_LegacyHeaderlessRequestRemainsAvailable(t *testing.T) {
	upstream, capture := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})

	status, _, body := postWireContractRequest(t, baseURL,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, http.Header{})
	if status != http.StatusOK {
		t.Fatalf("legacy headerless status = %d body = %s, want 200", status, body)
	}
	if got := capture.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 for legacy request", got)
	}
}

// Current Streamable HTTP eliminated initialize-based session negotiation.
// A stateful listener must not issue its private compatibility token merely
// because a current client sends initialize; doing so creates a fake stateful
// capability the client neither requested nor can use in the current protocol.
func TestHTTPListener_CurrentWireContractInitializeDoesNotMintPipelockToken(t *testing.T) {
	upstream, capture := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner: testScannerForHTTP(t),
		ToolCfg: &tools.ToolScanConfig{Action: config.ActionBlock},
	})

	status, responseHeaders, body := postWireContractRequest(t, baseURL,
		currentWireBody(1, "initialize", ""), currentWireHeaders("initialize", ""))
	if status != http.StatusOK {
		t.Fatalf("current initialize status = %d body = %s, want 200", status, body)
	}
	if token := responseHeaders.Get("Pipelock-Session-Token"); token != "" {
		t.Fatalf("current initialize minted Pipelock-Session-Token %q", token)
	}
	if got := capture.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestHTTPListener_CurrentWireContractRejectsLegacyStateCapability(t *testing.T) {
	upstream, capture := newWireContractUpstream(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner: testScannerForHTTP(t),
		ToolCfg: &tools.ToolScanConfig{BindingUnknownAction: config.ActionBlock},
	})
	legacyToken := listenerSetupToken(t, baseURL)
	headers := currentWireHeaders("tools/call", "echo")
	headers.Set(listenerSessionTokenHeader, legacyToken)
	status, _, body := postWireContractRequest(t, baseURL,
		currentWireBody(2, "tools/call", `"name":"echo","arguments":{}`), headers)
	if status != http.StatusForbidden || !strings.Contains(body, "cannot select current-protocol") {
		t.Fatalf("current request with legacy capability = status %d body %s, want explicit compatibility denial", status, body)
	}
	if got := capture.calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want legacy initialize only", got)
	}
}
