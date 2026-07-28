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

// Protocol revision 2026-07-28 adds ttlMs and cacheScope to list and read
// results, where cacheScope "public" invites shared intermediaries to cache the
// response. Pipelock IS such an intermediary, and a cached tools/list is
// precisely the tool-poisoning surface: a poisoned or since-revoked tool
// definition served from a cache outlives the revocation.
//
// Pipelock does not cache, but its own JSON responses carried no cache
// directive, leaving any cache between Pipelock and the agent free to retain
// them. Every MCP response must be explicitly non-storable.
func TestHTTPListener_MCPResponsesAreNotStorable(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// An upstream that explicitly invites shared caching.
		w.Header().Set("Cache-Control", "public, max-age=600")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[],"ttlMs":600000,"cacheScope":"public"}}`))
	}))
	defer upstream.Close()

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	if !strings.Contains(cacheControl, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store: a shared cache may otherwise retain a tool list past revocation", cacheControl)
	}
	if strings.Contains(cacheControl, "public") {
		t.Errorf("Cache-Control = %q still invites shared caching", cacheControl)
	}
}
