//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEmailSender_SendLicenseDelivery(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = w.Write([]byte(`{"id":"msg_delivery_test"}`))
	}))
	defer srv.Close()

	sender := &EmailSender{
		apiKey:    "re_" + "test_delivery",
		fromEmail: "noreply@pipelock.dev",
		client:    srv.Client(),
		apiURL:    srv.URL,
	}

	msgID, err := sender.SendLicenseDelivery(t.Context(), testCustomerEmail, "token123", tierPro)
	if err != nil {
		t.Fatalf("SendLicenseDelivery: %v", err)
	}
	if msgID != "msg_delivery_test" {
		t.Errorf("msgID = %q, want %q", msgID, "msg_delivery_test")
	}
	if !strings.Contains(gotAuth, "Bearer") {
		t.Errorf("Authorization header missing Bearer prefix: %q", gotAuth)
	}
	if !strings.Contains(gotBody, testCustomerEmail) {
		t.Errorf("body should contain recipient email")
	}
}

func TestEmailSender_SendLicenseDelivery_FoundingPro(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = w.Write([]byte(`{"id":"msg_founding"}`))
	}))
	defer srv.Close()

	sender := &EmailSender{
		apiKey:    "re_" + "test_founding",
		fromEmail: "noreply@pipelock.dev",
		client:    srv.Client(),
		apiURL:    srv.URL,
	}

	_, err := sender.SendLicenseDelivery(t.Context(), testCustomerEmail, "token456", tierFoundingPro)
	if err != nil {
		t.Fatalf("SendLicenseDelivery founding: %v", err)
	}
	if !strings.Contains(gotBody, "Founding Pro") {
		t.Error("founding pro email should have Founding Pro in subject")
	}
}

func TestEmailSender_SendSubscriptionEnded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = w.Write([]byte(`{"id":"msg_ended"}`))
	}))
	defer srv.Close()

	sender := &EmailSender{
		apiKey:    "re_" + "test_ended",
		fromEmail: "noreply@pipelock.dev",
		client:    srv.Client(),
		apiURL:    srv.URL,
	}

	expiresAt := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	msgID, err := sender.SendSubscriptionEnded(t.Context(), testCustomerEmail, expiresAt)
	if err != nil {
		t.Fatalf("SendSubscriptionEnded: %v", err)
	}
	if msgID != "msg_ended" {
		t.Errorf("msgID = %q, want %q", msgID, "msg_ended")
	}
}

func TestEmailSender_Send_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request"}`))
	}))
	defer srv.Close()

	sender := &EmailSender{
		apiKey:    "re_" + "test_error",
		fromEmail: "noreply@pipelock.dev",
		client:    srv.Client(),
		apiURL:    srv.URL,
	}

	_, err := sender.SendLicenseDelivery(t.Context(), testCustomerEmail, "token", tierPro)
	if err == nil {
		t.Fatal("expected error for 400 response, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestEmailSender_Send_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	sender := &EmailSender{
		apiKey:    "re_" + "test_badjson",
		fromEmail: "noreply@pipelock.dev",
		client:    srv.Client(),
		apiURL:    srv.URL,
	}

	_, err := sender.SendLicenseDelivery(t.Context(), testCustomerEmail, "token", tierPro)
	if err == nil {
		t.Fatal("expected error for invalid JSON response, got nil")
	}
}

func TestEmailSender_Send_NetworkError(t *testing.T) {
	// Create a sender pointing at a server that's already closed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close() // close immediately

	sender := &EmailSender{
		apiKey:    "re_" + "test_closed",
		fromEmail: "noreply@pipelock.dev",
		client:    srv.Client(),
		apiURL:    srv.URL,
	}

	_, err := sender.SendLicenseDelivery(t.Context(), testCustomerEmail, "token", tierPro)
	if err == nil {
		t.Fatal("expected network error for closed server, got nil")
	}
}

func TestEmailSender_Send_BadURL(t *testing.T) {
	sender := &EmailSender{
		apiKey:    "re_" + "test_bad_url",
		fromEmail: "noreply@pipelock.dev",
		client:    http.DefaultClient,
		apiURL:    "://invalid-url", // will fail NewRequestWithContext
	}

	_, err := sender.SendLicenseDelivery(t.Context(), testCustomerEmail, "token", tierPro)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestEmailSender_Send_CanceledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = w.Write([]byte(`{"id":"msg_ctx"}`))
	}))
	defer srv.Close()

	sender := &EmailSender{
		apiKey:    "re_" + "test_cancel",
		fromEmail: "noreply@pipelock.dev",
		client:    srv.Client(),
		apiURL:    srv.URL,
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel before sending

	_, err := sender.SendLicenseDelivery(ctx, testCustomerEmail, "token", tierPro)
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}

func TestEmailSender_Send_EmptyAPIURL(t *testing.T) {
	// When apiURL is empty, send() should fall back to resendAPIURL.
	// Use a custom transport to capture the outgoing URL without making
	// a real network request.
	var gotURL string
	stubTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"id":"msg_fallback"}`)),
			Header:     http.Header{"Content-Type": []string{testContentTypeJSON}},
		}, nil
	})

	sender := &EmailSender{
		apiKey:    "re_" + "test_fallback",
		fromEmail: "noreply@pipelock.dev",
		client:    &http.Client{Transport: stubTransport},
		apiURL:    "", // empty, triggers fallback
	}

	msgID, err := sender.SendLicenseDelivery(t.Context(), testCustomerEmail, "token", tierPro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgID != "msg_fallback" {
		t.Errorf("msgID = %q, want %q", msgID, "msg_fallback")
	}
	if gotURL != resendAPIURL {
		t.Errorf("fallback URL = %q, want %q", gotURL, resendAPIURL)
	}
}

// roundTripFunc adapts a function into an http.RoundTripper for test stubs.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewEmailSender(t *testing.T) {
	sender := NewEmailSender("re_"+"test_new", "from@test.com")
	if sender.apiKey != "re_"+"test_new" {
		t.Errorf("apiKey = %q", sender.apiKey)
	}
	if sender.fromEmail != "from@test.com" {
		t.Errorf("fromEmail = %q, want %q", sender.fromEmail, "from@test.com")
	}
	if sender.client == nil {
		t.Error("client should not be nil")
	}
	if sender.apiURL != resendAPIURL {
		t.Errorf("apiURL = %q, want %q", sender.apiURL, resendAPIURL)
	}
}
