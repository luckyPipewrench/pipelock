// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// assertBearer checks the Authorization header on a handler request.
func assertBearer(t *testing.T, r *http.Request) {
	t.Helper()
	got := r.Header.Get("Authorization")
	want := "Bearer " + testToken
	if got != want {
		t.Errorf("Authorization: got %q, want %q", got, want)
	}
}

func TestClient_List_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.URL.Path != sessionListURL {
			t.Errorf("path: got %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("tier"); got != "hard" {
			t.Errorf("tier query: got %q", got)
		}
		writeJSONResponse(w, http.StatusOK, listResponse{Sessions: makeSnapshotList(), Count: 1})
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	resp, err := c.List(context.Background(), "hard")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Count != 1 || len(resp.Sessions) != 1 || resp.Sessions[0].Key != testKeyIdent {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestClient_List_NoTierOmitsParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query params, got %q", r.URL.RawQuery)
		}
		writeJSONResponse(w, http.StatusOK, listResponse{})
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	if _, err := c.List(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestClient_Inspect_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, testKeyIdent) && !strings.Contains(r.URL.Path, "agent-z%7C10.0.0.42") {
			t.Errorf("path does not contain expected key: %q", r.URL.Path)
		}
		writeJSONResponse(w, http.StatusOK, makeDetail())
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	detail, err := c.Inspect(context.Background(), testKeyIdent)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Key != testKeyIdent {
		t.Errorf("detail.Key: %q", detail.Key)
	}
}

func TestClient_Explain_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, makeExplanation())
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	exp, err := c.Explain(context.Background(), testKeyIdent)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Trigger != "on_critical" {
		t.Errorf("Trigger: %q", exp.Trigger)
	}
}

func TestClient_Release_SendsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["tier"] != "none" {
			t.Errorf("tier: got %q, want none", body["tier"])
		}
		writeJSONResponse(w, http.StatusOK, airlockResponse{
			Key: testKeyIdent, PreviousTier: "hard", NewTier: "none", Changed: true,
		})
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	resp, err := c.Release(context.Background(), testKeyIdent, "none")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Changed {
		t.Error("Changed: false")
	}
}

func TestClient_Terminate_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s", r.Method)
		}
		writeJSONResponse(w, http.StatusOK, proxy.SessionTerminateResult{
			Key: testKeyIdent, Terminated: true, PreviousTier: "hard",
		})
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	resp, err := c.Terminate(context.Background(), testKeyIdent)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminated {
		t.Error("Terminated: false")
	}
}

func TestClient_AdaptiveStatus_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.Method != http.MethodGet {
			t.Errorf("method: got %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/adaptive/status" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		writeJSONResponse(w, http.StatusOK, proxy.AdaptiveStatus{
			ActiveSessions:     1,
			MaxEscalationLevel: "normal",
			SessionsByLevel:    map[string]int{"normal": 1},
			AirlockTiers:       map[string]int{"none": 1},
		})
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	resp, err := c.AdaptiveStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.ActiveSessions != 1 || resp.MaxEscalationLevel != "normal" {
		t.Errorf("unexpected adaptive status: %+v", resp)
	}
}

func TestClient_AdaptiveFlush_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/adaptive/flush" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		writeJSONResponse(w, http.StatusOK, proxy.AdaptiveFlushResult{
			Flushed:            true,
			IdentitySessions:   2,
			SkippedInvocations: 1,
		})
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	resp, err := c.AdaptiveFlush(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Flushed || resp.IdentitySessions != 2 || resp.SkippedInvocations != 1 {
		t.Errorf("unexpected adaptive flush: %+v", resp)
	}
}

func TestClient_AdaptiveWhoami_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.Method != http.MethodGet {
			t.Errorf("method: got %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/adaptive/whoami" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		writeJSONResponse(w, http.StatusOK, proxy.AdaptiveWhoami{
			ClientIP:       "203.0.113.9",
			SessionKey:     "agent-a|203.0.113.9",
			Exists:         true,
			Classification: "observe",
		})
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	resp, err := c.AdaptiveWhoami(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.SessionKey != "agent-a|203.0.113.9" || resp.Classification != "observe" {
		t.Errorf("unexpected adaptive whoami: %+v", resp)
	}
}

func TestClient_AdaptiveMethodsReturnAPIError(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{
			name: "status",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.AdaptiveStatus(ctx)
				return err
			},
		},
		{
			name: "flush",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.AdaptiveFlush(ctx)
				return err
			},
		},
		{
			name: "whoami",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.AdaptiveWhoami(ctx)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "bad token", http.StatusUnauthorized)
			}))
			defer srv.Close()

			c := newClient(endpoint{URL: srv.URL, Token: testToken})
			err := tt.call(context.Background(), c)
			if err == nil {
				t.Fatal("expected error")
			}
			if !IsUnauthorized(err) {
				t.Fatalf("expected unauthorized APIError, got %v", err)
			}
		})
	}
}

func TestClient_NonSuccessReturnsAPIError(t *testing.T) {
	tests := []struct {
		status     int
		headerRA   string
		bodyText   string
		checkFn    func(error) bool
		wantPrefix string
	}{
		{http.StatusNotFound, "", "session not found", IsNotFound, ""},
		{http.StatusUnauthorized, "", "unauthorized", IsUnauthorized, ""},
		{http.StatusTooManyRequests, "60", "rate limit exceeded", IsRateLimited, "Retry-After: 60"},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("status=%d", tt.status)
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.headerRA != "" {
					w.Header().Set("Retry-After", tt.headerRA)
				}
				http.Error(w, tt.bodyText, tt.status)
			}))
			defer srv.Close()

			c := newClient(endpoint{URL: srv.URL, Token: testToken})
			_, err := c.List(context.Background(), "")
			if err == nil {
				t.Fatal("expected error")
			}
			if !tt.checkFn(err) {
				t.Errorf("classifier failed for status %d", tt.status)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatal("expected APIError")
			}
			if apiErr.StatusCode != tt.status {
				t.Errorf("StatusCode: got %d, want %d", apiErr.StatusCode, tt.status)
			}
		})
	}
}

func TestClient_HTTPError_Propagates(t *testing.T) {
	// Use an intentionally-unreachable port to force a network error.
	c := newClient(endpoint{URL: "http://127.0.0.1:1", Token: testToken})
	_, err := c.List(context.Background(), "")
	if err == nil {
		t.Fatal("expected network error")
	}
	// Should NOT be an APIError - it's a transport failure.
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Error("network failure should not be APIError")
	}
}

func TestClient_EmptyResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		// No body.
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	_, err := c.Inspect(context.Background(), testKeyIdent)
	if err == nil {
		t.Error("expected error decoding empty body")
	}
}

func TestAPIError_ErrorString(t *testing.T) {
	e := &APIError{Method: "GET", URL: "http://x/api/v1/sessions/abc", StatusCode: 404, Body: "not found"}
	got := e.Error()
	if !strings.Contains(got, "404") || !strings.Contains(got, "not found") {
		t.Errorf("unexpected error string: %s", got)
	}
	// scheme + host must be stripped so operators can paste error output
	// into less-trusted channels without leaking the admin endpoint.
	if strings.Contains(got, "http://") || strings.Contains(got, "://") {
		t.Errorf("scheme should be stripped: %s", got)
	}
	if strings.Contains(got, "x/api") {
		t.Errorf("host should be stripped: %s", got)
	}
	if !strings.Contains(got, "/api/v1/sessions/abc") {
		t.Errorf("path should be preserved: %s", got)
	}

	e.RetryAfter = "30"
	if got := e.Error(); !strings.Contains(got, "30") {
		t.Errorf("should include retry-after: %s", got)
	}
}

func TestAPIError_ErrorString_StripsQuery(t *testing.T) {
	// Query strings are part of the path for display purposes - they
	// belong in the error (they might say ?tier=hard) but the scheme
	// and host still need stripping.
	e := &APIError{
		Method:     "GET",
		URL:        "https://admin.internal.example:9090/api/v1/sessions?tier=hard",
		StatusCode: 429,
		Body:       "rate limit exceeded",
	}
	got := e.Error()
	if strings.Contains(got, "https://") || strings.Contains(got, "admin.internal.example") {
		t.Errorf("scheme/host should be stripped: %s", got)
	}
	if !strings.Contains(got, "/api/v1/sessions?tier=hard") {
		t.Errorf("path+query should be preserved: %s", got)
	}
}

func TestAPIError_ErrorString_FallbackOnUnparseable(t *testing.T) {
	// When url.Parse cannot recover a Path - e.g. the caller handed us
	// something exotic - fall back to the raw URL rather than emitting
	// an empty path that would make the error unreadable.
	e := &APIError{Method: "POST", URL: "not a url", StatusCode: 500, Body: "internal"}
	got := e.Error()
	if !strings.Contains(got, "500") || !strings.Contains(got, "internal") {
		t.Errorf("missing status/body: %s", got)
	}
	if !strings.Contains(got, "not a url") {
		t.Errorf("fallback should preserve raw URL: %s", got)
	}
}

func TestIsNotFound_Nil(t *testing.T) {
	if IsNotFound(nil) {
		t.Error("nil should not classify as 404")
	}
	if IsUnauthorized(nil) {
		t.Error("nil should not classify as 401")
	}
	if IsRateLimited(nil) {
		t.Error("nil should not classify as 429")
	}
}

func TestClient_Release_MarshalError(t *testing.T) {
	// Release builds a bytes.NewReader from a map[string]string which never
	// fails to marshal - the happy-path test above exercises that branch.
	// Here we assert Release on an unreachable server returns a transport
	// error rather than a marshal error.
	c := newClient(endpoint{URL: "http://127.0.0.1:1", Token: testToken})
	_, err := c.Release(context.Background(), testKeyIdent, "none")
	if err == nil {
		t.Error("expected transport error")
	}
}

func TestClient_Do_BadJSONBody(t *testing.T) {
	// Server returns 200 with a body that isn't valid JSON - the decode
	// branch should surface an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	_, err := c.Inspect(context.Background(), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode error, got %v", err)
	}
}

func TestClient_NewClient_UsesDefaultWhenNil(t *testing.T) {
	c := newClient(endpoint{URL: "http://x:1", Token: testToken})
	if c.http == nil {
		t.Error("http client should default to a real *http.Client")
	}
}
