// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type analyticsRoundTripper struct{ captures chan analyticsCapture }

var analyticsTestSigningKey = []byte("0123456789abcdef0123456789abcdef")

func (rt analyticsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var capture analyticsCapture
	if err := json.NewDecoder(req.Body).Decode(&capture); err != nil {
		return nil, err
	}
	rt.captures <- capture
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
}

func TestAnalyticsRelayAcceptsOnlyCountsSchema(t *testing.T) {
	captures := make(chan analyticsCapture, 1)
	relay, err := NewAnalyticsRelay(t.Context(), AnalyticsConfig{ProjectKey: "public-project-key", Endpoint: "https://analytics.example/i/v0/e/", Client: &http.Client{Transport: analyticsRoundTripper{captures: captures}}, SigningKey: analyticsTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteAnalytics, strings.NewReader(`{"event":"playground_live_session_failed","properties":{"status":503,"reason":"provider_unavailable"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	relay.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	cookie := rec.Result().Cookies()
	if len(cookie) != 1 || !cookie[0].HttpOnly || !cookie[0].Secure || cookie[0].Name != analyticsCookieName {
		t.Fatalf("unexpected anonymous cookie: %#v", cookie)
	}
	select {
	case got := <-captures:
		if got.APIKey != "public-project-key" || got.Event != "playground_live_session_failed" {
			t.Fatalf("unexpected capture: %#v", got)
		}
		if got.Properties["status"] != float64(503) || got.Properties["reason"] != "provider_unavailable" ||
			got.Properties["$geoip_disable"] != true || got.Properties["$process_person_profile"] != false {
			t.Fatalf("unexpected properties: %#v", got.Properties)
		}
		if _, ok := got.Properties["distinct_id"].(string); !ok {
			t.Fatalf("missing server distinct_id: %#v", got.Properties)
		}
	case <-time.After(time.Second):
		t.Fatal("capture was not forwarded")
	}
}

func TestAnalyticsSchemaCoversViewerContract(t *testing.T) {
	tests := []struct {
		event string
		props map[string]any
	}{
		{"playground_demo_viewed", map[string]any{"mode": "replay"}},
		{"playground_mode_selected", map[string]any{"mode": "live"}},
		{"playground_live_unavailable", map[string]any{"reason": "probe_timeout"}},
		{"playground_live_session_failed", map[string]any{"status": float64(503), "reason": "at_capacity"}},
		{"playground_live_session_started", map[string]any{}},
		{"playground_message_sent", map[string]any{"turn": float64(1)}},
		{"playground_message_failed", map[string]any{"status": float64(429), "reason": "rate_limited"}},
		{"playground_attack_blocked", map[string]any{}},
		{"playground_verify_clicked", map[string]any{"surface": "kit", "mode": "live"}},
		{"playground_verify_result", map[string]any{"valid": true, "checks": float64(12)}},
		{"playground_kit_downloaded", map[string]any{"os": "linux"}},
	}
	for _, test := range tests {
		t.Run(test.event, func(t *testing.T) {
			if _, ok := validateAnalyticsProperties(test.event, test.props); !ok {
				t.Fatalf("viewer contract rejected: %#v", test.props)
			}
		})
	}
}

func TestAnalyticsRelayRejectsUnboundedOrMalformedInput(t *testing.T) {
	captures := make(chan analyticsCapture, 1)
	relay, err := NewAnalyticsRelay(context.Background(), AnalyticsConfig{ProjectKey: "key", Endpoint: "https://analytics.example/i/v0/e/", Client: &http.Client{Transport: analyticsRoundTripper{captures: captures}}, SigningKey: analyticsTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body string
	}{
		{"unknown_event", `{"event":"unknown","properties":{}}`},
		{"unknown_property", `{"event":"playground_live_session_started","properties":{"prompt":"secret"}}`},
		{"number_too_large", `{"event":"playground_message_sent","properties":{"turn":1000}}`},
		{"negative_status", `{"event":"playground_live_session_failed","properties":{"status":-1}}`},
		{"fractional_turn", `{"event":"playground_message_sent","properties":{"turn":1.5}}`},
		{"fractional_checks", `{"event":"playground_verify_result","properties":{"checks":1.5}}`},
		{"invalid_enum", `{"event":"playground_demo_viewed","properties":{"mode":"other"}}`},
		{"removed_layer", `{"event":"playground_attack_blocked","properties":{"layer":"body_dlp"}}`},
		{"browser_distinct_id", `{"event":"playground_live_session_started","properties":{},"distinct_id":"browser-controlled"}`},
		{"trailing_json", `{"event":"playground_live_session_started","properties":{}} {}`},
		{"oversize", `{"event":"playground_live_session_started","properties":{}` + strings.Repeat(" ", maxAnalyticsBody) + `}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteAnalytics, strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			relay.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %q: status = %d", test.body, rec.Code)
			}
		})
	}
	select {
	case got := <-captures:
		t.Fatalf("rejected event escaped to analytics sink: %#v", got)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestAnalyticsRelayRejectsCrossSiteAndPlainText(t *testing.T) {
	relay, err := NewAnalyticsRelay(t.Context(), AnalyticsConfig{ProjectKey: "key", Endpoint: "https://analytics.example/i/v0/e/", SigningKey: analyticsTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		headers map[string]string
	}{
		{"plain_text", map[string]string{"Content-Type": "text/plain", "Sec-Fetch-Site": "same-origin"}},
		{"cross_site", map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}},
		{"missing_fetch_site", map[string]string{"Content-Type": "application/json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteAnalytics, strings.NewReader(`{"event":"playground_live_session_started","properties":{}}`))
			for key, value := range test.headers {
				req.Header.Set(key, value)
			}
			rec := httptest.NewRecorder()
			relay.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("headers %#v: status = %d", test.headers, rec.Code)
			}
		})
	}
}

func TestAnalyticsRelayAcceptsJSONCharset(t *testing.T) {
	captures := make(chan analyticsCapture, 1)
	relay, err := NewAnalyticsRelay(t.Context(), AnalyticsConfig{
		ProjectKey: "key", Endpoint: "https://analytics.example/i/v0/e/",
		Client: &http.Client{Transport: analyticsRoundTripper{captures: captures}}, SigningKey: analyticsTestSigningKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteAnalytics, strings.NewReader(`{"event":"playground_attack_blocked","properties":{}}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	relay.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
}

func TestAnalyticsRelayStopsWhenDisabledOrContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	enabled := true
	relay, err := NewAnalyticsRelay(ctx, AnalyticsConfig{
		ProjectKey: "key", Endpoint: "https://analytics.example/i/v0/e/",
		Client:     &http.Client{Transport: analyticsRoundTripper{captures: make(chan analyticsCapture, 1)}},
		SigningKey: analyticsTestSigningKey, Enabled: func() bool { return enabled },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func() int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteAnalytics, strings.NewReader(`{"event":"playground_live_session_started","properties":{}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		relay.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	enabled = false
	if got := request(); got != http.StatusServiceUnavailable {
		t.Fatalf("disabled status = %d", got)
	}
	enabled = true
	cancel()
	select {
	case <-relay.done:
	case <-time.After(time.Second):
		t.Fatal("relay worker did not stop")
	}
	if got := request(); got != http.StatusServiceUnavailable {
		t.Fatalf("cancelled status = %d", got)
	}
}

func TestAnalyticsRelayReusesOnlyValidServerCookie(t *testing.T) {
	valid := strings.Repeat("a", 32)
	relay, err := NewAnalyticsRelay(t.Context(), AnalyticsConfig{ProjectKey: "key", Endpoint: "https://analytics.example/i/v0/e/", SigningKey: analyticsTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	validCookie := valid + "." + hex.EncodeToString(relay.signID(valid))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteAnalytics, nil)
	req.AddCookie(&http.Cookie{Name: analyticsCookieName, Value: validCookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	got, _, fresh, err := relay.analyticsDistinctID(req)
	if err != nil || fresh || got != valid {
		t.Fatalf("valid cookie: got=%q fresh=%v err=%v", got, fresh, err)
	}
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteAnalytics, nil)
	req.AddCookie(&http.Cookie{
		Name: analyticsCookieName, Value: valid + "." + strings.Repeat("0", sha256.Size*2),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	got, _, fresh, err = relay.analyticsDistinctID(req)
	if err != nil || !fresh || got == valid || len(got) != 32 {
		t.Fatalf("invalid cookie: got=%q fresh=%v err=%v", got, fresh, err)
	}
}

func TestNewAnalyticsRelayPreservesEndpointParseError(t *testing.T) {
	_, err := NewAnalyticsRelay(t.Context(), AnalyticsConfig{
		ProjectKey: "key", Endpoint: "https://[::1", SigningKey: analyticsTestSigningKey,
	})
	if err == nil || !strings.Contains(err.Error(), "parse analytics endpoint") {
		t.Fatalf("error = %v", err)
	}
}
