// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
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
