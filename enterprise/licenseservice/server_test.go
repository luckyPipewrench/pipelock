//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

const (
	testServerSecret = "test-server-secret-key-12345"
)

// newTestServer creates a fully wired Server for HTTP-level testing.
// Returns the server and a cleanup function.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	db := openTestDB(t)
	ledger, _ := openTestLedger(t)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Polar mock returns active pro subscription.
	polarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"id": "%s",
			"status": "active",
			"customer": {"email": "%s", "metadata": {}},
			"product": {"id": "%s", "name": "%s", "metadata": {"pipelock_tier": "pro"}},
			"recurring_interval": "month",
			"current_period_end": "2026-04-12T00:00:00Z"
		}`, testSubscriptionID, testCustomerEmail, testProductID, testProductName)
	}))
	t.Cleanup(polarSrv.Close)

	// Email mock always succeeds.
	emailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_server_test"}`))
	}))
	t.Cleanup(emailSrv.Close)

	secret := base64.StdEncoding.EncodeToString([]byte(testServerSecret))
	cfg := &Config{
		PolarWebhookSecret:  "whsec_" + secret,
		PolarAPIToken:       testPolarAPIToken,
		PrivateKeyPath:      filepath.Join(t.TempDir(), "test.key"),
		ResendAPIKey:        "re_" + "test_server_key",
		DBPath:              ":memory:",
		LedgerPath:          filepath.Join(t.TempDir(), "server-test.jsonl"),
		FoundingProCap:      50,
		FoundingProDeadline: time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
		ListenAddr:          ":0",
		FromEmail:           "test@pipelock.dev",
		PolarAPIBase:        polarSrv.URL,
	}

	polar := NewPolarClient(cfg.PolarAPIToken, cfg.PolarAPIBase)
	email := &EmailSender{
		apiKey:    cfg.ResendAPIKey,
		fromEmail: cfg.FromEmail,
		client:    emailSrv.Client(),
		apiURL:    emailSrv.URL,
	}

	handler, err := NewWebhookHandler(cfg, db, polar, email, ledger, priv, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	return NewServer(cfg, handler, ledger, zerolog.Nop())
}

// signedWebhookRequest creates a properly signed webhook request for testing.
func signedWebhookRequest(t *testing.T, srv *Server, body string) *http.Request {
	t.Helper()

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := signWebhook(t, []byte(body), timestamp, srv.cfg.PolarWebhookSecret)

	req := httptest.NewRequest(http.MethodPost, "/webhook/polar", strings.NewReader(body))
	req.Header.Set("Webhook-Id", testWebhookMsgID)
	req.Header.Set("Webhook-Timestamp", timestamp)
	req.Header.Set("Webhook-Signature", sig)

	return req
}

func TestServer_HealthEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health status = %d, want %d", w.Code, http.StatusOK)
	}

	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "healthy") {
		t.Errorf("health body = %q, want contains 'healthy'", string(body))
	}

	ct := w.Header().Get("Content-Type")
	if ct != testContentTypeJSON {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestServer_WebhookValidSignature(t *testing.T) {
	srv := newTestServer(t)

	body := fmt.Sprintf(`{"type":"%s","data":{"id":"%s"}}`, EventSubscriptionCreated, testSubscriptionID)
	req := signedWebhookRequest(t, srv, body)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Body)
		t.Errorf("webhook status = %d, want %d, body = %s", w.Code, http.StatusOK, string(respBody))
	}

	ct := w.Header().Get("Content-Type")
	if ct != testContentTypeJSON {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestServer_WebhookInvalidSignature(t *testing.T) {
	srv := newTestServer(t)

	body := `{"type":"subscription.created","data":{"id":"sub_123"}}`
	req := httptest.NewRequest(http.MethodPost, "/webhook/polar", strings.NewReader(body))
	req.Header.Set("Webhook-Id", testWebhookMsgID)
	req.Header.Set("Webhook-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("Webhook-Signature", "v1,aW52YWxpZHNpZw==")
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("webhook status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestServer_WebhookMissingHeaders(t *testing.T) {
	srv := newTestServer(t)

	body := `{"type":"subscription.created","data":{"id":"sub_123"}}`
	req := httptest.NewRequest(http.MethodPost, "/webhook/polar", strings.NewReader(body))
	// No webhook headers set.
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("webhook status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestServer_WebhookInvalidJSON(t *testing.T) {
	srv := newTestServer(t)

	body := `{not valid json}`
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := signWebhook(t, []byte(body), timestamp, srv.cfg.PolarWebhookSecret)

	req := httptest.NewRequest(http.MethodPost, "/webhook/polar", strings.NewReader(body))
	req.Header.Set("Webhook-Id", testWebhookMsgID)
	req.Header.Set("Webhook-Timestamp", timestamp)
	req.Header.Set("Webhook-Signature", sig)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("webhook status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestServer_WebhookNonSubscriptionEvent(t *testing.T) {
	srv := newTestServer(t)

	body := `{"type":"order.created","data":{"id":"order_123"}}`
	req := signedWebhookRequest(t, srv, body)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	// Non-subscription events should get 200 with "ignored" status.
	if w.Code != http.StatusOK {
		t.Errorf("webhook status = %d, want %d", w.Code, http.StatusOK)
	}

	respBody, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(respBody), "ignored") {
		t.Errorf("body = %q, want contains 'ignored'", string(respBody))
	}
}

func TestServer_WebhookWrongMethod(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/webhook/polar", nil)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	// Go 1.22+ mux returns 405 for wrong method.
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /webhook/polar status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestServer_WebhookProcessingError_Returns500(t *testing.T) {
	srv := newTestServer(t)

	// Use a subscription event with a product that has no tier metadata.
	// This will cause processSubscription to fail on tier mapping.
	// But the Polar mock always returns a valid pro sub, so we need to
	// set up a Polar mock that returns a bad product.
	badPolarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Product with no pipelock_tier metadata.
		_, _ = fmt.Fprintf(w, `{
			"id": "sub_bad",
			"status": "active",
			"customer": {"email": "test@example.com", "metadata": {}},
			"product": {"id": "prod_bad", "name": "Bad Product", "metadata": {}},
			"recurring_interval": "month",
			"current_period_end": "2026-04-12T00:00:00Z"
		}`)
	}))
	defer badPolarSrv.Close()

	// Rewire the handler's Polar client.
	srv.handler.polar = NewPolarClient(testPolarAPIToken, badPolarSrv.URL)

	body := `{"type":"subscription.created","data":{"id":"sub_bad"}}`
	req := signedWebhookRequest(t, srv, body)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("webhook status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	ct := w.Header().Get("Content-Type")
	if ct != testContentTypeJSON {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestServer_ListenAndShutdown(t *testing.T) {
	srv := newTestServer(t)

	// Use a random port for this test.
	srv.cfg.ListenAddr = "127.0.0.1:0"
	srv.srv.Addr = "127.0.0.1:0"

	// Start the server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	// Gracefully shut down.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// ListenAndServe should return http.ErrServerClosed.
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("ListenAndServe returned unexpected error: %v", err)
	}
}
