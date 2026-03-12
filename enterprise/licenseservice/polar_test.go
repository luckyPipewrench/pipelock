//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const (
	// testWebhookSecretB64 is the base64-encoded HMAC key for webhook tests.
	// Pre-computed: base64("test-secret-key-1234567890").
	testWebhookSecretB64 = "dGVzdC1zZWNyZXQta2V5LTEy" + "MzQ1Njc4OTA=" //nolint:gosec // gitleaks:allow

	testSubscriptionID     = "sub_test123"
	testWebhookMsgID       = "msg_test456"
	testProductID          = "prod_abc"
	testProductName        = "Pipelock Pro Monthly"
	testCustomerEmail      = "test@example.com"
	testPolarAPIToken      = "polar_" + "test_token"
	testSubscriptionJSON   = `{"id":"sub_test123"}`
	testContentTypeJSON    = "application/json"
	testStatusCanceled     = "canceled"
	testStatusPending      = "pending"
	testIntervalMonth      = "month"
	testDeliveryStatusSent = "sent"
	testEmailNew           = "new@example.com"
	testLicenseIDOld       = "lic_old"
)

// signWebhook computes a Standard Webhooks HMAC-SHA256 signature for testing.
// Always uses testWebhookMsgID as the message ID.
func signWebhook(t *testing.T, body []byte, timestamp, secret string) string {
	t.Helper()

	// Strip whsec_ prefix if present.
	rawSecret := secret
	if len(rawSecret) > 6 && rawSecret[:6] == "whsec_" {
		rawSecret = rawSecret[6:]
	}
	secretBytes, err := base64.StdEncoding.DecodeString(rawSecret)
	if err != nil {
		t.Fatalf("decode test secret: %v", err)
	}

	signedContent := testWebhookMsgID + "." + timestamp + "." + string(body)
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(signedContent))
	sig := mac.Sum(nil)

	return "v1," + base64.StdEncoding.EncodeToString(sig)
}

func TestValidateWebhookSignature(t *testing.T) {
	body := []byte(`{"type":"subscription.created","data":{"id":"sub_123"}}`)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	secret := "whsec_" + testWebhookSecretB64
	sig := signWebhook(t, body, timestamp, secret)

	tests := []struct {
		name      string
		body      []byte
		msgID     string
		timestamp string
		signature string
		secret    string
		wantErr   bool
	}{
		{
			name:      "valid signature",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: sig,
			secret:    secret,
			wantErr:   false,
		},
		{
			name:      "missing webhook-id",
			body:      body,
			msgID:     "",
			timestamp: timestamp,
			signature: sig,
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "missing webhook-timestamp",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: "",
			signature: sig,
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "missing webhook-signature",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: "",
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "wrong signature",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: "v1,aW52YWxpZHNpZ25hdHVyZQ==",
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "tampered body",
			body:      []byte(`{"type":"subscription.created","data":{"id":"sub_TAMPERED"}}`),
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: sig,
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "expired timestamp",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10),
			signature: signWebhook(t, body, strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10), secret),
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "future timestamp beyond tolerance",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10),
			signature: signWebhook(t, body, strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10), secret),
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "invalid timestamp",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: "not-a-number",
			signature: signWebhook(t, body, "not-a-number", secret),
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "secret without whsec prefix",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: signWebhook(t, body, timestamp, testWebhookSecretB64),
			secret:    testWebhookSecretB64,
			wantErr:   false,
		},
		{
			name:      "multiple signatures with valid last",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: "v1,aW52YWxpZA== " + sig,
			secret:    secret,
			wantErr:   false,
		},
		{
			name:      "non-v1 prefix skipped",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: "v2,abc123 " + sig,
			secret:    secret,
			wantErr:   false,
		},
		{
			name:      "malformed base64 in signature skipped",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: "v1,!!!not-base64!!! " + sig,
			secret:    secret,
			wantErr:   false,
		},
		{
			name:      "invalid base64 secret",
			body:      body,
			msgID:     testWebhookMsgID,
			timestamp: timestamp,
			signature: sig,
			secret:    "whsec_" + "!!!not-base64",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookSignature(tt.body, tt.msgID, tt.timestamp, tt.signature, tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebhookSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseWebhookEvent(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{
			name:    "valid event",
			body:    []byte(`{"type":"subscription.created","data":{"id":"sub_123"}}`),
			wantErr: false,
		},
		{
			name:    "missing type field",
			body:    []byte(`{"data":{"id":"sub_123"}}`),
			wantErr: true,
		},
		{
			name:    "empty type field",
			body:    []byte(`{"type":"","data":{"id":"sub_123"}}`),
			wantErr: true,
		},
		{
			name:    "invalid json",
			body:    []byte(`{not valid json`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := ParseWebhookEvent(tt.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWebhookEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && event.Type == "" {
				t.Error("ParseWebhookEvent() returned event with empty type")
			}
		})
	}
}

func TestExtractSubscriptionID(t *testing.T) {
	tests := []struct {
		name    string
		data    json.RawMessage
		want    string
		wantErr bool
	}{
		{
			name:    "valid id",
			data:    json.RawMessage(`{"id":"sub_abc123"}`),
			want:    "sub_abc123",
			wantErr: false,
		},
		{
			name:    "empty id",
			data:    json.RawMessage(`{"id":""}`),
			want:    "",
			wantErr: true,
		},
		{
			name:    "missing id field",
			data:    json.RawMessage(`{"status":"active"}`),
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid json",
			data:    json.RawMessage(`{broken`),
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractSubscriptionID(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractSubscriptionID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ExtractSubscriptionID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPolarClient_GetSubscription(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
		wantStatus string
	}{
		{
			name:       "active subscription",
			statusCode: http.StatusOK,
			body: `{
				"id": "sub_test123",
				"status": "active",
				"customer": {"email": "test@example.com", "metadata": {}},
				"product": {"id": "prod_abc", "name": "Pro", "metadata": {"pipelock_tier": "pro"}},
				"recurring_interval": "month",
				"current_period_end": "2026-04-12T00:00:00Z"
			}`,
			wantErr:    false,
			wantStatus: "active",
		},
		{
			name:       "404 not found",
			statusCode: http.StatusNotFound,
			body:       `{"error": "not found"}`,
			wantErr:    true,
		},
		{
			name:       "500 server error",
			statusCode: http.StatusInternalServerError,
			body:       `{"error": "internal error"}`,
			wantErr:    true,
		},
		{
			name:       "invalid json response",
			statusCode: http.StatusOK,
			body:       `{not valid json`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify authorization header is sent.
				if auth := r.Header.Get("Authorization"); auth != "Bearer "+testPolarAPIToken {
					t.Errorf("expected Bearer token, got %q", auth)
				}
				// Verify correct endpoint path.
				wantPath := fmt.Sprintf("/v1/subscriptions/%s", testSubscriptionID)
				if r.URL.Path != wantPath {
					t.Errorf("got path %q, want %q", r.URL.Path, wantPath)
				}

				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			client := NewPolarClient(testPolarAPIToken, srv.URL)
			sub, err := client.GetSubscription(t.Context(), testSubscriptionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSubscription() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && sub.Status != tt.wantStatus {
				t.Errorf("GetSubscription() status = %q, want %q", sub.Status, tt.wantStatus)
			}
		})
	}
}

func TestPolarClient_GetSubscription_NetworkError(t *testing.T) {
	// Closed server causes a network error on client.Do.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close()

	client := NewPolarClient(testPolarAPIToken, srv.URL)
	_, err := client.GetSubscription(t.Context(), testSubscriptionID)
	if err == nil {
		t.Fatal("expected network error for closed server, got nil")
	}
}

func TestIsSubscriptionEvent(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		want      bool
	}{
		{"subscription created", EventSubscriptionCreated, true},
		{"subscription updated", EventSubscriptionUpdated, true},
		{"subscription active", EventSubscriptionActive, true},
		{"subscription revoked", EventSubscriptionRevoked, true},
		{"subscription canceled", EventSubscriptionCanceled, true},
		{"order created", "order.created", false},
		{"checkout completed", "checkout.completed", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSubscriptionEvent(tt.eventType)
			if got != tt.want {
				t.Errorf("isSubscriptionEvent(%q) = %v, want %v", tt.eventType, got, tt.want)
			}
		})
	}
}
