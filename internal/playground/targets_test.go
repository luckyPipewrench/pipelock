// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

const (
	testCanaryID = "aws_canary"
	testRunN1    = "run-nonce-1"
	testRunN2    = "run-nonce-2"
)

// testCanaryValue builds the canary at runtime to dodge gosec G101.
func testCanaryValue() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

// postBody sends a POST with the given body string to the URL.
func postBody(t *testing.T, url, body string) *http.Response {
	t.Helper()
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// get sends a GET and returns the response.
func get(t *testing.T, url string) *http.Response {
	t.Helper()
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func TestCollector_RecordsArrival_ByRunNonce(t *testing.T) {
	t.Parallel()

	canary := testCanaryValue()
	c := playground.NewCollector(testCanaryID, canary)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// Agent posts the canary under run nonce N1.
	resp := postBody(t, srv.URL+"/?run="+testRunN1, "secret="+canary)
	defer func() { _ = resp.Body.Close() }()

	if got := c.ObservedCount(testRunN1); got != 1 {
		t.Fatalf("want 1 observed for n1, got %d", got)
	}
	if c.ObservedCount(testRunN2) != 0 {
		t.Fatalf("other run must be 0, got %d", c.ObservedCount(testRunN2))
	}
}

func TestCollector_WitnessQuery_NeverCarriesCanaryValue(t *testing.T) {
	t.Parallel()

	canary := testCanaryValue()
	c := playground.NewCollector(testCanaryID, canary)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// Query is by run nonce ONLY.
	resp := get(t, srv.URL+"/witness?run="+testRunN1)
	defer func() { _ = resp.Body.Close() }()

	raw := c.LastWitnessQueryRaw()
	if strings.Contains(raw, "AKIA") {
		t.Fatal("witness query must never carry the canary value")
	}
}

func TestCollector_DetectsCanary_InBodyHeaderQuery(t *testing.T) {
	t.Parallel()

	canary := testCanaryValue()

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		header map[string]string
	}{
		{
			name:   "canary in POST body",
			method: http.MethodPost,
			path:   "/?run=body-test",
			body:   "payload=" + canary,
		},
		{
			name:   "canary in header",
			method: http.MethodGet,
			path:   "/?run=header-test",
			header: map[string]string{"X-Secret": canary},
		},
		{
			name:   "canary in query param",
			method: http.MethodGet,
			path:   "/?run=query-test&token=" + canary,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := playground.NewCollector(testCanaryID, canary)
			srv := httptest.NewServer(c.Handler())
			defer srv.Close()

			ctx := context.Background()
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}
			req, err := http.NewRequestWithContext(ctx, tt.method, srv.URL+tt.path, bodyReader)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// Extract run nonce from the path.
			nonce := req.URL.Query().Get("run")
			if got := c.ObservedCount(nonce); got != 1 {
				t.Fatalf("want 1 observed for %s, got %d", nonce, got)
			}
		})
	}
}

func TestCollector_WitnessEndpoint_ReturnsJSON(t *testing.T) {
	t.Parallel()

	canary := testCanaryValue()
	c := playground.NewCollector(testCanaryID, canary)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// Send a request carrying the canary.
	resp := postBody(t, srv.URL+"/?run="+testRunN1, "secret="+canary)
	_ = resp.Body.Close()

	// Also send one that does NOT carry the canary.
	resp2 := get(t, srv.URL+"/?run="+testRunN1)
	_ = resp2.Body.Close()

	// Query witness.
	witnessResp := get(t, srv.URL+"/witness?run="+testRunN1)
	defer func() { _ = witnessResp.Body.Close() }()

	if witnessResp.StatusCode != http.StatusOK {
		t.Fatalf("witness want 200, got %d", witnessResp.StatusCode)
	}

	var result struct {
		Run           string `json:"run"`
		ObservedCount int    `json:"observed_count"`
		TotalCount    int    `json:"total_count"`
	}
	if err := json.NewDecoder(witnessResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode witness JSON: %v", err)
	}
	if result.Run != testRunN1 {
		t.Fatalf("witness run want %s, got %s", testRunN1, result.Run)
	}
	if result.ObservedCount != 1 {
		t.Fatalf("witness observed_count want 1, got %d", result.ObservedCount)
	}
	if result.TotalCount != 2 {
		t.Fatalf("witness total_count want 2, got %d", result.TotalCount)
	}
}

func TestCollector_TotalCount_TracksAllRequests(t *testing.T) {
	t.Parallel()

	canary := testCanaryValue()
	c := playground.NewCollector(testCanaryID, canary)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// Two requests: one with canary, one without.
	resp := postBody(t, srv.URL+"/?run="+testRunN1, "secret="+canary)
	_ = resp.Body.Close()
	resp2 := get(t, srv.URL+"/?run="+testRunN1)
	_ = resp2.Body.Close()

	if got := c.TotalCount(testRunN1); got != 2 {
		t.Fatalf("want total 2, got %d", got)
	}
	if got := c.ObservedCount(testRunN1); got != 1 {
		t.Fatalf("want observed 1, got %d", got)
	}
}

func TestSafeTarget_Returns200(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(playground.NewSafeTarget().Handler())
	defer srv.Close()

	resp := get(t, srv.URL+"/")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("safe target must 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("safe target body must not be empty")
	}
}
