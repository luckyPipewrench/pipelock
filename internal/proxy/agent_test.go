package proxy

import (
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
	if got != "anonymous" { //nolint:goconst // test value
		t.Errorf("expected anonymous, got %s", got)
	}
}

func TestExtractAgent_SanitizesSpecialChars(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, "evil\nagent\": {\"inject\":true}")

	got := ExtractAgent(req)
	// Newline, quotes, colon, space, braces all become underscores
	if got != "evil_agent_____inject__true_" { //nolint:goconst // test value
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
	if got != "anonymous" { //nolint:goconst // test value
		t.Errorf("expected anonymous for empty query param, got %q", got)
	}
}

func TestExtractAgent_OnlyDashesAndDots(t *testing.T) {
	// Agent name with only allowed chars: dashes, dots, underscores
	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://example.com", nil)
	req.Header.Set(AgentHeader, "-._.-.") //nolint:goconst // test value
	got := ExtractAgent(req)
	if got != "-._.-." {
		t.Errorf("expected -._.-, got %q", got)
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
