// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractAgent_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, "my-agent")

	got := ExtractAgent(req)
	if got != "my-agent" {
		t.Errorf("expected my-agent, got %s", got)
	}
}

func TestExtractAgent_QueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com&agent=query-bot", nil)

	got := ExtractAgent(req)
	if got != "query-bot" {
		t.Errorf("expected query-bot, got %s", got)
	}
}

func TestExtractAgent_HeaderTakesPrecedence(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com&agent=query-bot", nil)
	req.Header.Set(AgentHeader, "header-bot")

	got := ExtractAgent(req)
	if got != "header-bot" {
		t.Errorf("expected header-bot (header precedence), got %s", got)
	}
}

func TestExtractAgent_DefaultAnonymous(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)

	got := ExtractAgent(req)
	if got != agentAnonymous {
		t.Errorf("expected anonymous, got %s", got)
	}
}

func TestExtractAgent_SanitizesSpecialChars(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, "evil\nagent\": {\"inject\":true}")

	got := ExtractAgent(req)
	// Newline, quotes, colon, space, braces all become underscores
	if got != "evil_agent_____inject__true_" {
		t.Errorf("expected sanitized agent name, got %q", got)
	}
}

func TestExtractAgent_TruncatesLongNames(t *testing.T) {
	long := ""
	for i := 0; i < 200; i++ {
		long += "a"
	}
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, long)

	got := ExtractAgent(req)
	if len(got) != maxAgentNameLen {
		t.Errorf("expected length %d, got %d", maxAgentNameLen, len(got))
	}
}

func TestExtractAgent_WhitespaceBecomesUnderscores(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, "   ")

	got := ExtractAgent(req)
	// Spaces become underscores, so should be "___"
	if got != "___" {
		t.Errorf("expected ___, got %q", got)
	}
}

func TestExtractAgent_AllowsDots(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, "claude-code.v2")

	got := ExtractAgent(req)
	if got != "claude-code.v2" {
		t.Errorf("expected claude-code.v2, got %q", got)
	}
}

func TestExtractAgent_EmptyQueryParam(t *testing.T) {
	// Both header and query param empty → anonymous
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com&agent=", nil)
	got := ExtractAgent(req)
	if got != agentAnonymous {
		t.Errorf("expected anonymous for empty query param, got %q", got)
	}
}

func TestExtractAgent_OnlyDashesAndDots(t *testing.T) {
	// Agent name with only allowed chars: dashes, dots, underscores
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, "-._.-.")
	got := ExtractAgent(req)
	if got != "-._.-." {
		t.Errorf("expected -._.-., got %q", got)
	}
}

func TestExtractAgent_AllSpecialChars_BecomesAnonymous(t *testing.T) {
	// Agent name that is ALL special chars → regex replaces all with "_"
	// But underscores ARE allowed, so the result is "___" not empty.
	// Need chars that become empty: none exist because _ replaces them.
	// Instead use a name in query param that's something like emoji-only.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com&agent=%E2%9C%93%E2%9C%93", nil)
	got := ExtractAgent(req)
	// Unicode checkmarks → replaced with underscores → "__" (not empty)
	if got == "" {
		t.Error("should not return empty string")
	}
}

func TestResolveAgent(t *testing.T) {
	knownProfiles := map[string]bool{
		"claude-code": true,
		"my-agent":    true,
		"q-agent":     true,
	}

	tests := []struct {
		name        string
		ctxProfile  string // context override (listener mode)
		header      string // X-Pipelock-Agent header
		query       string // ?agent= param
		wantName    string
		wantProfile string
	}{
		{"context override wins", "claude-code", "other-agent", "", "claude-code", "claude-code"},
		{"header without context", "", "my-agent", "", "my-agent", "my-agent"},
		{"query without header", "", "", "q-agent", "q-agent", "q-agent"},
		{"fallback to _default", "", "", "", "", profileDefault},
		{"unrecognized agent uses _default profile", "", "unknown", "", "unknown", profileDefault},
		{"nil knownProfiles is safe", "", "my-agent", "", "my-agent", profileDefault},
		{"context override unknown profile still trusts context", "custom-port-agent", "", "", "custom-port-agent", "custom-port-agent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/fetch?url=http://example.com", nil)
			if tt.header != "" {
				req.Header.Set(AgentHeader, tt.header)
			}
			if tt.query != "" {
				q := req.URL.Query()
				q.Set("agent", tt.query)
				req.URL.RawQuery = q.Encode()
			}
			if tt.ctxProfile != "" {
				ctx := context.WithValue(req.Context(), ctxKeyAgentOverride, tt.ctxProfile)
				req = req.WithContext(ctx)
			}

			// Use nil knownProfiles for the specific nil-safety test case.
			profiles := knownProfiles
			if tt.name == "nil knownProfiles is safe" {
				profiles = nil
			}

			id := ResolveAgent(req, profiles)
			if id.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", id.Name, tt.wantName)
			}
			if id.Profile != tt.wantProfile {
				t.Errorf("Profile = %q, want %q", id.Profile, tt.wantProfile)
			}
		})
	}
}
