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
