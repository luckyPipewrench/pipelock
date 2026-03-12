//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Polar webhook event types we handle.
const (
	EventSubscriptionCreated  = "subscription.created"
	EventSubscriptionUpdated  = "subscription.updated"
	EventSubscriptionActive   = "subscription.active"
	EventSubscriptionRevoked  = "subscription.revoked"
	EventSubscriptionCanceled = "subscription.canceled"
)

// PolarWebhookEvent is the top-level envelope for all Polar webhook deliveries.
type PolarWebhookEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// PolarSubscription represents the subscription object returned by Polar's API
// and embedded in webhook event payloads.
type PolarSubscription struct {
	ID                string    `json:"id"`
	Status            string    `json:"status"`
	CustomerEmail     string    `json:"customer_email"`
	ProductID         string    `json:"product_id"`
	ProductName       string    `json:"product_name"`
	CurrentPeriodEnd  time.Time `json:"current_period_end"`
	RecurringInterval string    `json:"recurring_interval"` // "month" or "year"

	// Customer metadata (may contain org name).
	Customer struct {
		Email    string            `json:"email"`
		Metadata map[string]string `json:"metadata"`
	} `json:"customer"`

	// Product metadata (must contain tier info).
	Product struct {
		ID       string            `json:"id"`
		Name     string            `json:"name"`
		Metadata map[string]string `json:"metadata"`
	} `json:"product"`
}

// PolarClient handles communication with the Polar API.
type PolarClient struct {
	apiToken string
	baseURL  string
	client   *http.Client
}

// NewPolarClient creates a Polar API client with the given token and base URL.
func NewPolarClient(apiToken, baseURL string) *PolarClient {
	return &PolarClient{
		apiToken: apiToken,
		baseURL:  baseURL,
		client: &http.Client{
			Timeout: 15 * time.Second, // 15s: generous for external API, prevents hanging
		},
	}
}

// GetSubscription fetches the current state of a subscription from Polar's API.
// This is the source of truth: we always re-fetch after receiving a webhook
// rather than trusting webhook payload data alone.
func (p *PolarClient) GetSubscription(ctx context.Context, subscriptionID string) (*PolarSubscription, error) {
	url := fmt.Sprintf("%s/v1/subscriptions/%s", p.baseURL, subscriptionID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create subscription request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription %s: %w", subscriptionID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap response body to prevent memory exhaustion from malformed responses.
	// 1 MiB is generous for a single subscription JSON object.
	const maxResponseBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("read subscription response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("polar API returned %d for subscription %s: %s",
			resp.StatusCode, subscriptionID, string(body))
	}

	var sub PolarSubscription
	if err := json.Unmarshal(body, &sub); err != nil {
		return nil, fmt.Errorf("parse subscription response: %w", err)
	}

	return &sub, nil
}

// webhookTimestampTolerance is the maximum age (or future drift) allowed
// for a webhook timestamp. Prevents replay of captured webhook deliveries.
const webhookTimestampTolerance = 5 * time.Minute

// ValidateWebhookSignature verifies a Standard Webhooks signature on a
// Polar webhook delivery. Polar uses the Standard Webhooks specification:
//   - webhook-id: unique message identifier
//   - webhook-timestamp: Unix timestamp (seconds)
//   - webhook-signature: "v1,<base64-hmac>" (space-separated if multiple)
//
// The signed content is "{msg_id}.{timestamp}.{body}". The secret may
// have a "whsec_" prefix and is base64-encoded.
func ValidateWebhookSignature(body []byte, msgID, timestamp, signatureHeader, secret string) error {
	if msgID == "" {
		return fmt.Errorf("missing webhook-id header")
	}
	if timestamp == "" {
		return fmt.Errorf("missing webhook-timestamp header")
	}
	if signatureHeader == "" {
		return fmt.Errorf("missing webhook-signature header")
	}

	// Verify timestamp is within tolerance to prevent replay attacks.
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("parse webhook timestamp: %w", err)
	}
	msgTime := time.Unix(ts, 0)
	if time.Since(msgTime).Abs() > webhookTimestampTolerance {
		return fmt.Errorf("webhook timestamp outside %s tolerance", webhookTimestampTolerance)
	}

	// Decode the signing secret (strip "whsec_" prefix, base64 decode).
	secretStr := secret
	if len(secretStr) > 6 && secretStr[:6] == "whsec_" {
		secretStr = secretStr[6:]
	}
	secretBytes, err := base64.StdEncoding.DecodeString(secretStr)
	if err != nil {
		return fmt.Errorf("decode webhook secret: %w", err)
	}

	// Construct the signed content per Standard Webhooks spec.
	signedContent := msgID + "." + timestamp + "." + string(body)

	// Compute expected HMAC-SHA256.
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(signedContent))
	expectedSig := mac.Sum(nil)

	// Check each signature in the header (space-separated, "v1,<base64>").
	for _, part := range strings.Split(signatureHeader, " ") {
		if !strings.HasPrefix(part, "v1,") {
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(part[3:])
		if err != nil {
			continue // skip malformed signature entries
		}
		if hmac.Equal(sigBytes, expectedSig) {
			return nil
		}
	}

	return fmt.Errorf("webhook signature mismatch")
}

// ParseWebhookEvent parses the raw body into a PolarWebhookEvent.
func ParseWebhookEvent(body []byte) (*PolarWebhookEvent, error) {
	var event PolarWebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, fmt.Errorf("parse webhook event: %w", err)
	}
	if event.Type == "" {
		return nil, fmt.Errorf("webhook event missing type field")
	}
	return &event, nil
}

// ExtractSubscriptionID pulls the subscription ID from the webhook event
// data payload. Works for subscription.* event types.
func ExtractSubscriptionID(data json.RawMessage) (string, error) {
	var partial struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &partial); err != nil {
		return "", fmt.Errorf("extract subscription ID from event data: %w", err)
	}
	if partial.ID == "" {
		return "", fmt.Errorf("subscription ID is empty in event data")
	}
	return partial.ID, nil
}
