//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
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

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/webhook/polar", strings.NewReader(body))
	req.Header.Set("Webhook-Id", testWebhookMsgID)
	req.Header.Set("Webhook-Timestamp", timestamp)
	req.Header.Set("Webhook-Signature", sig)

	return req
}

func TestServer_HealthEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
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

func TestServer_CRLEndpoint(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now().UTC()
	if err := srv.handler.db.UpsertLicenseRevocation(t.Context(), RevokedLicenseRecord{
		LicenseID:      "lic_crl_endpoint",
		SubscriptionID: testSubscriptionID,
		Reason:         "subscription_canceled",
		RevokedAt:      now,
	}); err != nil {
		t.Fatalf("UpsertLicenseRevocation: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/crl.json", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var crl license.CRL
	if err := json.Unmarshal(w.Body.Bytes(), &crl); err != nil {
		t.Fatalf("decode CRL: %v", err)
	}
	if _, ok := crl.RevocationFor("lic_crl_endpoint"); !ok {
		t.Fatalf("CRL missing revocation: %+v", crl.Payload.Revoked)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header")
	}
	if cacheControl := w.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "max-age=60") {
		t.Fatalf("Cache-Control = %q, want max-age=60", cacheControl)
	}

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/crl.json", nil)
	req.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d, want 304", w.Code)
	}

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/crl.json", nil)
	req.Header.Set("If-None-Match", `W/`+etag+`, "other"`)
	w = httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotModified {
		t.Fatalf("weak conditional status = %d, want 304", w.Code)
	}
}

func TestIfNoneMatch(t *testing.T) {
	tests := []struct {
		name   string
		header string
		etag   string
		want   bool
	}{
		{name: "empty", header: "", etag: `"abc"`, want: false},
		{name: "exact", header: `"abc"`, etag: `"abc"`, want: true},
		{name: "weak", header: `W/"abc"`, etag: `"abc"`, want: true},
		{name: "list", header: `"other", W/"abc"`, etag: `"abc"`, want: true},
		{name: "wildcard", header: "*", etag: `"abc"`, want: true},
		{name: "miss", header: `"other"`, etag: `"abc"`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ifNoneMatch(tt.header, tt.etag); got != tt.want {
				t.Fatalf("ifNoneMatch(%q, %q) = %v, want %v", tt.header, tt.etag, got, tt.want)
			}
		})
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
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/webhook/polar", strings.NewReader(body))
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
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/webhook/polar", strings.NewReader(body))
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

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/webhook/polar", strings.NewReader(body))
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

	body := `{"type":"checkout.created","data":{"id":"checkout_123"}}`
	req := signedWebhookRequest(t, srv, body)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	// Unhandled event types should get 200 with "ignored" status.
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

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/webhook/polar", nil)
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

func TestServer_ServeAndShutdown(t *testing.T) {
	srv := newTestServer(t)

	// Bind an ephemeral loopback port and read the resolved address back so
	// readiness is observable (dialable) without a startup sleep. The public
	// ListenAndServe binds a :0 port it never surfaces, leaving nothing to
	// poll. Serving the underlying http.Server with a test-owned listener
	// exercises the graceful-shutdown path deterministically; the
	// ListenAndServe wrapper only logs startup and delegates to this server.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.srv.Serve(ln)
	}()

	// Wait until the server actually accepts connections before shutting down.
	testwait.For(t, 2*time.Second, func() bool {
		conn, derr := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(t.Context(), "tcp", addr)
		if derr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, "license server to accept connections")

	// Gracefully shut down.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Serve should return http.ErrServerClosed after graceful shutdown.
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve returned unexpected error: %v", err)
	}
}
