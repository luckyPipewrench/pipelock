// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	testCEEClientIP = "10.0.0.1"
	testCEEAgent    = "test-agent"
)

func TestCeeSessionKey_WithAgent(t *testing.T) {
	got := ceeSessionKey(testCEEAgent, testCEEClientIP)
	want := testCEEAgent + "|" + testCEEClientIP
	if got != want {
		t.Errorf("ceeSessionKey(%q, %q) = %q, want %q", testCEEAgent, testCEEClientIP, got, want)
	}
}

func TestCeeSessionKey_EmptyAgent(t *testing.T) {
	got := ceeSessionKey("", testCEEClientIP)
	if got != testCEEClientIP {
		t.Errorf("ceeSessionKey(%q, %q) = %q, want %q", "", testCEEClientIP, got, testCEEClientIP)
	}
}

func TestCeeSessionKey_AnonymousAgent(t *testing.T) {
	got := ceeSessionKey(agentAnonymous, testCEEClientIP)
	if got != testCEEClientIP {
		t.Errorf("ceeSessionKey(%q, %q) = %q, want %q", agentAnonymous, testCEEClientIP, got, testCEEClientIP)
	}
}

func TestExtractOutboundPayload_QueryParams(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "key=secret_value&other=data",
		},
	}
	payload := extractOutboundPayload(r)
	got := string(payload)

	// Query parameter iteration order is not guaranteed, so check both values
	// are present rather than exact string equality.
	if !strings.Contains(got, "secret_value") {
		t.Errorf("payload %q missing query value %q", got, "secret_value")
	}
	if !strings.Contains(got, "data") {
		t.Errorf("payload %q missing query value %q", got, "data")
	}
}

func TestExtractOutboundPayload_Body(t *testing.T) {
	body := "request body content"
	r := &http.Request{
		URL:           &url.URL{},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	payload := extractOutboundPayload(r)
	got := string(payload)
	if got != body {
		t.Errorf("extractOutboundPayload = %q, want %q", got, body)
	}
}

func TestExtractOutboundPayload_QueryAndBody(t *testing.T) {
	body := "body-data"
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "q=query-data",
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	payload := extractOutboundPayload(r)
	got := string(payload)

	if !strings.Contains(got, "query-data") {
		t.Errorf("payload %q missing query value %q", got, "query-data")
	}
	if !strings.Contains(got, body) {
		t.Errorf("payload %q missing body %q", got, body)
	}
}

func TestExtractOutboundPayload_NoQueryNoBody(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{},
	}
	payload := extractOutboundPayload(r)
	if len(payload) != 0 {
		t.Errorf("expected empty payload, got %q", string(payload))
	}
}

func TestExtractOutboundPayload_NilBody(t *testing.T) {
	r := &http.Request{
		URL:  &url.URL{},
		Body: nil,
	}
	payload := extractOutboundPayload(r)
	if len(payload) != 0 {
		t.Errorf("expected empty payload for nil body, got %q", string(payload))
	}
}

func TestExtractOutboundPayload_ZeroContentLength(t *testing.T) {
	// ContentLength == 0 should skip body reading even if Body is non-nil.
	r := &http.Request{
		URL:           &url.URL{},
		Body:          io.NopCloser(strings.NewReader("should not be read")),
		ContentLength: 0,
	}
	payload := extractOutboundPayload(r)
	if len(payload) != 0 {
		t.Errorf("expected empty payload for zero content-length, got %q", string(payload))
	}
}
