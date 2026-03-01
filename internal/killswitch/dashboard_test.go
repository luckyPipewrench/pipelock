package killswitch

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDashboard_GET_Inactive(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", "Bearer dash-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "KILL SWITCH INACTIVE") {
		t.Error("expected INACTIVE status banner")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html content type, got %q", ct)
	}

	// All 4 sources should appear
	for _, src := range []string{"config", "api", "signal", "sentinel"} {
		if !strings.Contains(body, src) {
			t.Errorf("expected source %q in dashboard HTML", src)
		}
	}
}

func TestDashboard_GET_Active(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	cfg.KillSwitch.Message = "emergency shutdown"
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", "Bearer dash-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "KILL SWITCH ACTIVE") {
		t.Error("expected ACTIVE status banner")
	}
	if !strings.Contains(body, "status-active") {
		t.Error("expected status-active CSS class")
	}
	if !strings.Contains(body, "emergency shutdown") {
		t.Error("expected message in dashboard")
	}
}

func TestDashboard_GET_NoToken(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "secret" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestDashboard_GET_WrongToken(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "correct" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", "Bearer wrong") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestDashboard_GET_NoAPITokenConfigured(t *testing.T) {
	cfg := testConfig()
	// No APIToken configured
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", "Bearer something") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestDashboard_GET_QueryTokenRejected(t *testing.T) {
	// GET must only accept Bearer header, not query param.
	// Accepting tokens in query strings leaks them to browser history,
	// server access logs, and referrer headers.
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "secret-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard?token=secret-token", nil)
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET with query token should be rejected, got %d", w.Code)
	}
}

func TestDashboard_POST_Activate(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	form := url.Values{}
	form.Set("token", "dash-token")
	form.Set("action", "activate")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Kill switch should now be active via API source
	if !c.Sources()["api"] {
		t.Error("expected API source active after activate")
	}

	body := w.Body.String()
	if !strings.Contains(body, "Kill switch activated") {
		t.Error("expected activation flash message")
	}
	if !strings.Contains(body, "KILL SWITCH ACTIVE") {
		t.Error("expected ACTIVE banner after activation")
	}
}

func TestDashboard_POST_Deactivate(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	c.SetAPI(true) // pre-activate
	h := NewAPIHandler(c)

	form := url.Values{}
	form.Set("token", "dash-token")
	form.Set("action", "deactivate")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if c.Sources()["api"] {
		t.Error("expected API source inactive after deactivate")
	}

	body := w.Body.String()
	if !strings.Contains(body, "deactivated") {
		t.Error("expected deactivation flash message")
	}
}

func TestDashboard_POST_BearerAuth(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// POST with Bearer header instead of form token
	form := url.Values{}
	form.Set("action", "activate")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer dash-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with Bearer auth on POST, got %d", w.Code)
	}
	if !c.Sources()["api"] {
		t.Error("expected API source active")
	}
}

func TestDashboard_POST_NoToken(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "secret" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	form := url.Values{}
	form.Set("action", "activate")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestDashboard_POST_WrongToken(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "correct" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	form := url.Values{}
	form.Set("token", "incorrect")
	form.Set("action", "activate")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestDashboard_POST_UnknownAction(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	form := url.Values{}
	form.Set("token", "dash-token")
	form.Set("action", "destroy")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Unknown action") {
		t.Error("expected unknown action flash message")
	}
}

func TestDashboard_POST_RateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Exhaust rate limit via dashboard POST
	for i := 0; i < apiRateLimitMax+1; i++ {
		form := url.Values{}
		form.Set("token", "dash-token")
		form.Set("action", "activate")
		r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		h.HandleDashboard(w, r)

		if i < apiRateLimitMax {
			if w.Code != http.StatusOK {
				t.Fatalf("request %d: expected 200, got %d", i, w.Code)
			}
		} else {
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: expected 429, got %d", i, w.Code)
			}
			if w.Header().Get("Retry-After") == "" {
				t.Error("expected Retry-After header")
			}
		}
	}
}

func TestDashboard_POST_SharedRateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Exhaust rate limit via HandleToggle
	for i := 0; i < apiRateLimitMax; i++ {
		body := strings.NewReader(`{"active": true}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
		r.Header.Set("Authorization", "Bearer dash-token") //nolint:goconst // test value
		w := httptest.NewRecorder()
		h.HandleToggle(w, r)
	}

	// Dashboard POST should be rate-limited (shared counter)
	form := url.Values{}
	form.Set("token", "dash-token")
	form.Set("action", "deactivate")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (shared rate limit), got %d", w.Code)
	}
}

func TestDashboard_MethodNotAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := httptest.NewRequest(method, "/dashboard", nil)
		r.Header.Set("Authorization", "Bearer dash-token") //nolint:goconst // test value
		w := httptest.NewRecorder()

		h.HandleDashboard(w, r)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, w.Code)
		}
		if allow := w.Header().Get("Allow"); allow == "" {
			t.Errorf("%s: expected Allow header", method)
		}
	}
}

func TestDashboard_TokenEchoedInForm(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "echo-me-123" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", "Bearer echo-me-123") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	// Token should be echoed in hidden form fields for browser resubmission
	if !strings.Contains(body, `value="echo-me-123"`) {
		t.Error("expected token echoed in hidden form field")
	}
}

func TestDashboard_TokenHTMLEscaped(t *testing.T) {
	// Tokens with special HTML chars must be escaped to prevent XSS
	cfg := testConfig()
	cfg.KillSwitch.APIToken = `token<script>alert(1)</script>` //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", `Bearer token<script>alert(1)</script>`) //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if strings.Contains(body, "<script>") {
		t.Error("token with HTML should be escaped, found raw <script> tag")
	}
}

func TestDashboard_POST_ActivateThenGETReflectsState(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Activate via POST
	form := url.Values{}
	form.Set("token", "dash-token")
	form.Set("action", "activate")
	r := httptest.NewRequest(http.MethodPost, "/dashboard", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("POST: expected 200, got %d", w.Code)
	}

	// GET should show active state
	r2 := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r2.Header.Set("Authorization", "Bearer dash-token") //nolint:goconst // test value
	w2 := httptest.NewRecorder()
	h.HandleDashboard(w2, r2)

	if w2.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d", w2.Code)
	}

	body := w2.Body.String()
	if !strings.Contains(body, "KILL SWITCH ACTIVE") {
		t.Error("GET after activate should show ACTIVE")
	}
}

func TestDashboard_SecurityHeaders(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", "Bearer dash-token") //nolint:goconst // test value
	w := httptest.NewRecorder()

	h.HandleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Token is in the response body (hidden form fields). These headers prevent
	// caching, clickjacking, and content-type sniffing.
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", cc)
	}
	if xfo := w.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("expected X-Frame-Options: DENY, got %q", xfo)
	}
	if xcto := w.Header().Get("X-Content-Type-Options"); xcto != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", xcto)
	}
}

func TestDashboard_APIExempt_DashboardReachable(t *testing.T) {
	// When kill switch is active on main port with api_exempt=true,
	// /dashboard must be reachable (same as /api/v1/killswitch).
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.APIToken = "dash-token" //nolint:goconst // test value
	cfg.KillSwitch.APIExempt = ptrBool(true)
	c := New(cfg)

	// Verify kill switch blocks a non-exempt path.
	nonExempt := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	if d := c.IsActiveHTTP(nonExempt); !d.Active {
		t.Fatal("expected kill switch active for /fetch")
	}

	// /dashboard should be exempt (returns inactive decision).
	exempt := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	if d := c.IsActiveHTTP(exempt); d.Active {
		t.Errorf("expected /dashboard exempt, got active (source=%q)", d.Source)
	}
}
