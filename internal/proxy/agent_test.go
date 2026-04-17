// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStripInternalIdentity covers the pre-tag gate-found bug where the
// X-Pipelock-Agent header and ?agent= query parameter both bled
// through to destinations on the TLS-interception outbound path.
// The strip must always remove the header and, when present, also
// remove the query parameter without disturbing sibling params.
func TestStripInternalIdentity(t *testing.T) {
	t.Parallel()

	const attackerAgent = "evil-actor"

	tests := []struct {
		name          string
		path          string
		setAgentHdr   bool
		wantQuery     string
		wantHdrEmpty  bool
		wantOtherHdrs map[string]string
	}{
		{
			name:         "header only",
			path:         "/anything",
			setAgentHdr:  true,
			wantQuery:    "",
			wantHdrEmpty: true,
		},
		{
			name:         "query only",
			path:         "/anything?agent=" + attackerAgent,
			setAgentHdr:  false,
			wantQuery:    "",
			wantHdrEmpty: true,
		},
		{
			name:         "header and query both set",
			path:         "/anything?agent=" + attackerAgent,
			setAgentHdr:  true,
			wantQuery:    "",
			wantHdrEmpty: true,
		},
		{
			name:         "unrelated query preserved",
			path:         "/anything?foo=bar&agent=" + attackerAgent + "&baz=qux",
			setAgentHdr:  false,
			wantQuery:    "baz=qux&foo=bar",
			wantHdrEmpty: true,
		},
		{
			name:         "no agent markers leaves request untouched",
			path:         "/anything?foo=bar",
			setAgentHdr:  false,
			wantQuery:    "foo=bar",
			wantHdrEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://example.com"+tt.path, http.NoBody)
			if tt.setAgentHdr {
				req.Header.Set(AgentHeader, attackerAgent)
			}
			req.Header.Set("X-Other", "keep-me")

			stripInternalIdentity(req)

			if tt.wantHdrEmpty && req.Header.Get(AgentHeader) != "" {
				t.Errorf("%s leaked downstream: %q", AgentHeader, req.Header.Get(AgentHeader))
			}
			if got := req.URL.RawQuery; got != tt.wantQuery {
				t.Errorf("raw query mismatch: got %q, want %q", got, tt.wantQuery)
			}
			if got := req.Header.Get("X-Other"); got != "keep-me" {
				t.Errorf("unrelated header lost: got %q, want %q", got, "keep-me")
			}
		})
	}
}

// TestStripInternalIdentity_ForwardedHeaders covers the round-2 of the pre-tag gate
// finding that X-Forwarded-For / X-Real-IP / Forwarded / Via bleed
// downstream even though pipelock already knows the verified client_ip.
// An attacker could otherwise poison destination log attribution or
// abuse controls with a crafted header. The strip must remove every
// header in forwardedClientHeaders regardless of case.
func TestStripInternalIdentity_ForwardedHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", http.NoBody)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Port", "80")
	req.Header.Set("Forwarded", "for=1.2.3.4;proto=http;host=evil")
	req.Header.Set("Via", "1.1 evil-proxy")
	req.Header.Set("X-Keep", "ok")

	stripInternalIdentity(req)

	for _, name := range []string{
		"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host",
		"X-Forwarded-Proto", "X-Forwarded-Port", "Forwarded", "Via",
	} {
		if got := req.Header.Get(name); got != "" {
			t.Errorf("%s leaked downstream: %q", name, got)
		}
	}
	if got := req.Header.Get("X-Keep"); got != "ok" {
		t.Errorf("unrelated header lost: got %q, want ok", got)
	}
}

// TestStripInternalIdentity_NilSafe confirms the helper does not panic
// on nil inputs. Both nil request and nil URL are valid zero states
// pipelock code sometimes hands to header filters.
func TestStripInternalIdentity_NilSafe(t *testing.T) {
	t.Parallel()

	stripInternalIdentity(nil)

	req := &http.Request{Header: http.Header{}}
	req.Header.Set(AgentHeader, "would-leak")
	stripInternalIdentity(req)
	if req.Header.Get(AgentHeader) != "" {
		t.Errorf("nil URL path did not strip header: %q", req.Header.Get(AgentHeader))
	}
}
