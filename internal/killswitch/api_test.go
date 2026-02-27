package killswitch

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIHandler_Toggle_Activate(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token-123" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{"active": true}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token-123") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify kill switch is now active
	req := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(req)
	if !d.Active {
		t.Fatal("expected kill switch active after API toggle")
	}
	if d.Source != "api" { //nolint:goconst // test value
		t.Errorf("expected source %q, got %q", "api", d.Source)
	}
}

func TestAPIHandler_Toggle_Deactivate(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token-123" //nolint:goconst // test value
	c := New(cfg)
	c.SetAPI(true) // pre-activate
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{"active": false}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token-123") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(req)
	if d.Active {
		t.Fatal("expected kill switch inactive after API deactivate")
	}
}

func TestAPIHandler_Toggle_NoToken(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "secret" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{"active": true}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	// No Authorization header
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestAPIHandler_Toggle_WrongToken(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "correct-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{"active": true}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer wrong-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIHandler_Toggle_NoAPIToken_Configured(t *testing.T) {
	cfg := testConfig()
	// No APIToken configured
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{"active": true}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer something") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no api_token configured, got %d", w.Code)
	}
}

func TestAPIHandler_Toggle_WrongMethod(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/killswitch", nil)
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestAPIHandler_Toggle_InvalidJSON(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`not json`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAPIHandler_Toggle_UnknownFields(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{"active": true, "extra": "field"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown fields, got %d", w.Code)
	}
}

func TestAPIHandler_Toggle_MissingActiveField(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing active field, got %d", w.Code)
	}
}

func TestAPIHandler_Toggle_ConcatenatedJSON(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Two concatenated JSON objects — only first should be parsed, second should cause rejection.
	body := bytes.NewBufferString(`{"active":true}{"active":false}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for concatenated JSON, got %d", w.Code)
	}
	if c.Sources()["api"] {
		t.Error("kill switch should not be activated by concatenated JSON payload")
	}
}

func TestAPIHandler_Toggle_TrailingGarbage(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Valid JSON followed by trailing non-JSON data.
	body := bytes.NewBufferString(`{"active":true}x`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing garbage, got %d", w.Code)
	}
	if c.Sources()["api"] {
		t.Error("kill switch should not be activated by payload with trailing garbage")
	}
}

func TestAPIHandler_Toggle_OversizedBody(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Body exceeding MaxBytesReader limit (1024 bytes).
	bigBody := `{"active":true,` + strings.Repeat(`"x":"y",`, 200) + `"z":"z"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", strings.NewReader(bigBody))
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleToggle(w, r)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 400 or 413 for oversized body, got %d", w.Code)
	}
	if c.Sources()["api"] {
		t.Error("kill switch should not be activated by oversized payload")
	}
}

func TestAPIHandler_Status(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	c.SetAPI(true)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/killswitch/status", nil)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Active  bool            `json:"active"`
		Sources map[string]bool `json:"sources"`
		Message string          `json:"message"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Active {
		t.Error("expected active true")
	}
	if !resp.Sources["config"] {
		t.Error("expected config source active")
	}
	if !resp.Sources["api"] {
		t.Error("expected api source active")
	}
}

func TestAPIHandler_Status_Unauthorized(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "secret" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/killswitch/status", nil)
	w := httptest.NewRecorder()

	h.HandleStatus(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIHandler_RateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Send apiRateLimitMax+1 requests
	for i := 0; i < apiRateLimitMax+1; i++ {
		body := bytes.NewBufferString(`{"active": true}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
		r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
		w := httptest.NewRecorder()

		h.HandleToggle(w, r)

		if i < apiRateLimitMax {
			if w.Code != http.StatusOK {
				t.Fatalf("request %d: expected 200, got %d", i, w.Code)
			}
		} else {
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: expected 429, got %d", i, w.Code)
			}
			if w.Header().Get("Retry-After") == "" {
				t.Error("expected Retry-After header on rate limit")
			}
		}
	}
}

func TestAPIHandler_RateLimitWindowReset(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Exhaust the rate limit.
	for i := 0; i < apiRateLimitMax; i++ {
		body := bytes.NewBufferString(`{"active": true}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
		r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
		w := httptest.NewRecorder()
		h.HandleToggle(w, r)
	}

	// Simulate window expiration by moving windowStart into the past.
	h.mu.Lock()
	h.windowStart = time.Now().Add(-apiRateLimitWindow - time.Second)
	h.mu.Unlock()

	// Next request should succeed — window has reset.
	body := bytes.NewBufferString(`{"active": false}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()
	h.HandleToggle(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after window reset, got %d", w.Code)
	}
}

func TestAPIHandler_TokenAddedViaReload(t *testing.T) {
	cfg := testConfig()
	// No token initially — API returns 503
	c := New(cfg)
	h := NewAPIHandler(c)

	body := bytes.NewBufferString(`{"active": true}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer new-token") //nolint:goconst // test value
	w := httptest.NewRecorder()
	h.HandleToggle(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before reload, got %d", w.Code)
	}

	// Reload config with a token
	cfg2 := testConfig()
	cfg2.KillSwitch.APIToken = "new-token" //nolint:goconst // test value
	c.Reload(cfg2)

	// Now the API should accept the token
	body2 := bytes.NewBufferString(`{"active": true}`)
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body2)
	r2.Header.Set("Authorization", "Bearer new-token") //nolint:goconst // test value
	w2 := httptest.NewRecorder()
	h.HandleToggle(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 after reload with token, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestAPIHandler_Status_WrongMethod(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch/status", nil)
	r.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleStatus(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestAPIHandler_Status_NoTokenConfigured(t *testing.T) {
	cfg := testConfig()
	// No APIToken configured
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/killswitch/status", nil)
	r.Header.Set("Authorization", "Bearer something") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleStatus(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no api_token configured, got %d", w.Code)
	}
}

func TestAPIHandler_TokenRotation(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "old-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Old token works
	body := bytes.NewBufferString(`{"active": true}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	r.Header.Set("Authorization", "Bearer old-token") //nolint:goconst // test value
	w := httptest.NewRecorder()
	h.HandleToggle(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with old token, got %d", w.Code)
	}

	// Reload config with new token
	cfg2 := testConfig()
	cfg2.KillSwitch.APIToken = "new-token" //nolint:goconst // test value
	c.Reload(cfg2)

	// Old token no longer works
	body2 := bytes.NewBufferString(`{"active": false}`)
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body2)
	r2.Header.Set("Authorization", "Bearer old-token") //nolint:goconst // test value
	w2 := httptest.NewRecorder()
	h.HandleToggle(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with old token after rotation, got %d", w2.Code)
	}

	// New token works
	body3 := bytes.NewBufferString(`{"active": false}`)
	r3 := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body3)
	r3.Header.Set("Authorization", "Bearer new-token") //nolint:goconst // test value
	w3 := httptest.NewRecorder()
	h.HandleToggle(w3, r3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 with new token, got %d", w3.Code)
	}
}
