// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const routingHeaderToolsCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`

// Mcp-Method and Mcp-Name route the request at the upstream, while Pipelock
// scans and applies policy to the JSON-RPC body. A header that disagrees with
// the body means Pipelock inspects one call and the upstream performs another,
// so the disagreement must be refused locally rather than forwarded. The spec
// allocates HeaderMismatch (-32020) for exactly this condition.
func TestHTTPListener_RejectsRoutingHeaderBodyDisagreement(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})

	// A bare 400 can be returned for many reasons. The revision allocates
	// HeaderMismatch (-32020) for this specific condition, so assert the code.
	requireHeaderMismatch := func(body string, setHeaders func(http.Header)) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		setHeaders(req.Header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		var rpc struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if rpc.Error.Code != mcpHeaderMismatchCode {
			t.Errorf("error code = %d, want %d (HeaderMismatch)", rpc.Error.Code, mcpHeaderMismatchCode)
		}
	}

	request := func(body string, setHeaders func(http.Header)) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		setHeaders(req.Header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	t.Run("method header disagrees with body", func(t *testing.T) {
		requireHeaderMismatch(jsonToolsList, func(h http.Header) {
			h.Set(listenerMCPMethod, "tools/call")
		})
	})

	t.Run("name header disagrees with body tool name", func(t *testing.T) {
		requireHeaderMismatch(routingHeaderToolsCall, func(h http.Header) {
			h.Set(listenerMCPMethod, "tools/call")
			h.Set(listenerMCPName, "read_note")
		})
	})

	t.Run("malformed routing headers", func(t *testing.T) {
		for _, tc := range []struct{ name, value string }{
			{"tab", "tools/\tlist"},
			{"non-ascii", "tools/lïst"},
			{"oversized", strings.Repeat("a", 9010)},
			{"empty", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := request(jsonToolsList, func(h http.Header) {
					h[listenerMCPMethod] = []string{tc.value}
				}); got != http.StatusBadRequest {
					t.Errorf("status = %d, want 400", got)
				}
			})
		}
		t.Run("duplicate", func(t *testing.T) {
			if got := request(jsonToolsList, func(h http.Header) {
				h.Add(listenerMCPMethod, "tools/list")
				h.Add(listenerMCPMethod, "tools/call")
			}); got != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", got)
			}
		})
		// Mcp-Name is equally untrusted routing input. Exercised with a valid
		// tools/call body and an agreeing method header, so a rejection can
		// only come from the name header's own shape validation.
		for _, tc := range []struct{ name, value string }{
			{"tab", "ec\tho"},
			{"non-ascii", "ech\u00f6"},
			{"oversized", strings.Repeat("a", 9010)},
			{"empty", ""},
		} {
			t.Run("name/"+tc.name, func(t *testing.T) {
				if got := request(routingHeaderToolsCall, func(h http.Header) {
					h.Set(listenerMCPMethod, "tools/call")
					h[listenerMCPName] = []string{tc.value}
				}); got != http.StatusBadRequest {
					t.Errorf("status = %d, want 400", got)
				}
			})
		}
		t.Run("name/duplicate", func(t *testing.T) {
			if got := request(routingHeaderToolsCall, func(h http.Header) {
				h.Set(listenerMCPMethod, "tools/call")
				h.Add(listenerMCPName, "echo")
				h.Add(listenerMCPName, "read_note")
			}); got != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", got)
			}
		})
	})

	// Availability: a matching header must pass, and an ABSENT header must pass
	// too. Revisions before 2026-07-28 do not send these headers at all, and a
	// mixed-revision fleet is the normal state for at least the deprecation
	// window, so requiring them would refuse every older client.
	t.Run("agreement and absence are allowed", func(t *testing.T) {
		before := upstreamCalls.Load()
		if got := request(jsonToolsList, func(h http.Header) {
			h.Set(listenerMCPMethod, "tools/list")
		}); got != http.StatusOK {
			t.Errorf("matching header status = %d, want 200", got)
		}
		if got := request(routingHeaderToolsCall, func(h http.Header) {
			h.Set(listenerMCPMethod, "tools/call")
			h.Set(listenerMCPName, "echo")
		}); got != http.StatusOK {
			t.Errorf("matching method and name status = %d, want 200", got)
		}
		if got := request(jsonToolsList, func(http.Header) {}); got != http.StatusOK {
			t.Errorf("absent routing headers status = %d, want 200 (older revisions omit them)", got)
		}
		if got := upstreamCalls.Load() - before; got != 3 {
			t.Errorf("upstream calls = %d, want 3 (only the allowed requests)", got)
		}
	})

	t.Run("no rejected request reached upstream", func(t *testing.T) {
		if got := upstreamCalls.Load(); got != 3 {
			t.Errorf("total upstream calls = %d, want 3", got)
		}
	})
}
