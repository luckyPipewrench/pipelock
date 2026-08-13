// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// a client must not clobber an operator-pinned upstream header.
func TestHTTPListener_ClientCannotOverrideOperatorPinnedHeaders(t *testing.T) {
	var gotVersion, gotExt, gotVer, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion, gotExt = r.Header.Get(listenerProtocolVersion), r.Header.Get("A2A-Extensions")
		gotVer, gotAuth = r.Header.Get("A2A-Version"), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner: testScannerForHTTP(t),
		UpstreamHeaders: http.Header{
			"Authorization":         []string{"Bearer operator-upstream"},
			listenerProtocolVersion: []string{"2025-06-18"},
			"A2A-Extensions":        []string{"https://operator.example/ext"},
			"A2A-Version":           []string{"1.0"},
		},
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer attacker")
	req.Header.Set(listenerProtocolVersion, "1999-01-01-DOWNGRADE")
	req.Header.Set("A2A-Extensions", "https://attacker.example/ext")
	req.Header.Set("A2A-Version", "ATTACKER-VERSION")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request status = %d, want 200", resp.StatusCode)
	}

	for _, c := range []struct{ name, got, want string }{
		{"Authorization", gotAuth, "Bearer operator-upstream"},
		{listenerProtocolVersion, gotVersion, "2025-06-18"},
		{"A2A-Extensions", gotExt, "https://operator.example/ext"},
		{"A2A-Version", gotVer, "1.0"},
	} {
		if c.got != c.want {
			t.Errorf("client CLOBBERED operator-pinned %s: upstream got %q, want %q", c.name, c.got, c.want)
		}
	}
}

// Mcp-Method and Mcp-Name describe the individual call, so no single pinned
// value can be right for a session. Pinning one is startup-valid on its face
// but refuses every request whose method differs from the pin, because the
// pinned value replaces the client's before the agreement check runs. The
// listener must refuse to start rather than serve that configuration.
func TestValidateListenerUpstreamHeaders_RejectsPinnedRoutingHeaders(t *testing.T) {
	for _, name := range []string{listenerMCPMethod, listenerMCPName} {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set(name, "tools/list")
			if err := validateListenerUpstreamHeaders(headers); err == nil {
				t.Errorf("pinning %s was accepted; it would refuse every other method at runtime", name)
			}
		})
	}
}

// protocol revision 2026-07-28 requires Mcp-Method and Mcp-Name on Streamable
// HTTP POST. Stripping them makes a conforming upstream answer HeaderMismatch
// (-32020), which pushes a fallback-capable client off the stateless transport
// and back onto the deprecated session handshake: the proxy would silently
// downgrade the protocol it is mediating.
func TestHTTPListener_ForwardsRequiredMCPRequestHeaders(t *testing.T) {
	// The handler runs on the server goroutine, so hand the captured values back
	// over a channel rather than reading plain variables across goroutines.
	type captured struct{ method, name string }
	seen := make(chan captured, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- captured{r.Header.Get(listenerMCPMethod), r.Header.Get(listenerMCPName)}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	baseURL, logBuf := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner: testScannerForHTTP(t),
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(listenerMCPMethod, "tools/call")
	req.Header.Set(listenerMCPName, "echo")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	payload, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request status = %d body=%s log=%s, want 200", resp.StatusCode, payload, logBuf.String())
	}

	got := <-seen
	if got.method != "tools/call" {
		t.Errorf("upstream got %s = %q, want %q (stripped header downgrades the protocol)", listenerMCPMethod, got.method, "tools/call")
	}
	if got.name != "echo" {
		t.Errorf("upstream got %s = %q, want %q", listenerMCPName, got.name, "echo")
	}
}

// a browser MCP client on protocol revision 2026-07-28 names Mcp-Method and
// Mcp-Name in its preflight. listenerCORSPreflightAllowed refuses the whole
// preflight if any requested header is outside the allowlist, so omitting them
// blocks browser clients outright rather than degrading.
func TestHTTPListener_CORSPreflightAllowsRequiredMCPRequestHeaders(t *testing.T) {
	const origin = "https://client.vendor.example"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:                testScannerForHTTP(t),
		ListenerAllowedOrigins: []string{origin},
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, baseURL+"/", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type,mcp-protocol-version,mcp-method,mcp-name")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204 (browser MCP clients are refused outright)", resp.StatusCode)
	}
	allow := strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers"))
	for _, name := range []string{"mcp-method", "mcp-name"} {
		if !strings.Contains(allow, name) {
			t.Errorf("Access-Control-Allow-Headers = %q, missing %q", allow, name)
		}
	}
}

// the listener token must never reach upstream, even when the client
// presents it in BOTH auth headers.
func TestHTTPListener_ListenerTokenNeverForwardedUpstream(t *testing.T) {
	const secret = "listener-secret-DO-NOT-FORWARD"
	var gotAuth, gotProxyAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotProxyAuth = r.Header.Get("Authorization"), r.Header.Get(listenerProxyAuthorization)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner: testScannerForHTTP(t), ListenerBearerToken: secret,
	})

	for _, tc := range []struct{ name, proxyAuth, auth string }{
		{"both carry listener token", "Bearer " + secret, "Bearer " + secret},
		{"proxy-auth only", "Bearer " + secret, ""},
		{"authorization only", "", "Bearer " + secret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotAuth, gotProxyAuth = "", ""
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
			req.Header.Set("Content-Type", "application/json")
			if tc.proxyAuth != "" {
				req.Header.Set(listenerProxyAuthorization, tc.proxyAuth)
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("request status = %d, want 200", resp.StatusCode)
			}
			if strings.Contains(gotAuth, secret) {
				t.Errorf("LISTENER TOKEN LEAKED UPSTREAM in Authorization = %q", gotAuth)
			}
			if strings.Contains(gotProxyAuth, secret) {
				t.Errorf("LISTENER TOKEN LEAKED UPSTREAM in Proxy-Authorization = %q", gotProxyAuth)
			}
		})
	}

	t.Run("duplicate Authorization values including listener token", func(t *testing.T) {
		gotAuth, gotProxyAuth = "", ""
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(listenerProxyAuthorization, "Bearer "+secret)
		req.Header.Add(listenerAuthorization, "Bearer "+secret)
		req.Header.Add(listenerAuthorization, "Bearer upstream-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request status = %d, want 200", resp.StatusCode)
		}
		if strings.Contains(gotAuth, secret) || strings.Contains(gotProxyAuth, secret) {
			t.Fatalf("listener token leaked through duplicate auth values: Authorization=%q Proxy-Authorization=%q", gotAuth, gotProxyAuth)
		}
	})
}
