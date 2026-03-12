//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent types for the append-only JSONL ledger.
const (
	AuditWebhookReceived = "webhook_received"
	AuditLicenseIssued   = "license_issued"
	AuditEmailSent       = "email_sent"
	AuditEmailFailed     = "email_failed"
	AuditRefreshIssued   = "refresh_issued"
	AuditSubscriptionEnd = "subscription_ended"
	AuditFoundingCapHit  = "founding_cap_hit"
	AuditError           = "error"
)

// AuditEntry is a single line in the append-only JSONL audit ledger.
// PII is explicitly excluded: no card numbers, billing addresses, or
// full webhook payloads.
type AuditEntry struct {
	Timestamp      time.Time `json:"ts"`
	Event          string    `json:"event"`
	SubscriptionID string    `json:"subscription_id,omitempty"`
	CustomerEmail  string    `json:"customer_email,omitempty"`
	LicenseID      string    `json:"license_id,omitempty"`
	Tier           string    `json:"tier,omitempty"`
	ExpiresAt      string    `json:"expires_at,omitempty"`
	Detail         string    `json:"detail,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// AuditLedger is a concurrency-safe, append-only JSONL file writer.
// Entries are serialized through a mutex to prevent interleaved writes.
type AuditLedger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// OpenAuditLedger opens (or creates) the audit ledger file at path.
// The file is opened in append-only mode with restrictive permissions.
func OpenAuditLedger(path string) (*AuditLedger, error) {
	cleanPath := filepath.Clean(path)

	// Reject symlinks to prevent writing to unexpected locations.
	if info, err := os.Lstat(cleanPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("ledger path %s is a symlink (not allowed for security)", cleanPath)
		}
	}

	f, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit ledger: %w", err)
	}

	return &AuditLedger{file: f, path: cleanPath}, nil
}

// Close flushes and closes the audit ledger file.
func (a *AuditLedger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}

// Log writes an audit entry to the ledger. The entry is JSON-serialized
// and appended as a single line. Errors are returned but should not block
// the main request flow (caller decides whether to log and continue or fail).
func (a *AuditLedger) Log(entry AuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.file.Write(data); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}

// LogWebhookReceived records a webhook delivery.
func (a *AuditLedger) LogWebhookReceived(eventType, subscriptionID string) error {
	return a.Log(AuditEntry{
		Event:          AuditWebhookReceived,
		SubscriptionID: subscriptionID,
		Detail:         eventType,
	})
}

// LogLicenseIssued records a license issuance.
func (a *AuditLedger) LogLicenseIssued(subscriptionID, email, licenseID, tier string, expiresAt time.Time) error {
	return a.Log(AuditEntry{
		Event:          AuditLicenseIssued,
		SubscriptionID: subscriptionID,
		CustomerEmail:  email,
		LicenseID:      licenseID,
		Tier:           tier,
		ExpiresAt:      expiresAt.UTC().Format(time.DateOnly),
	})
}

// LogEmailSent records a successful email delivery.
func (a *AuditLedger) LogEmailSent(subscriptionID, email, detail string) error {
	return a.Log(AuditEntry{
		Event:          AuditEmailSent,
		SubscriptionID: subscriptionID,
		CustomerEmail:  email,
		Detail:         detail,
	})
}

// LogEmailFailed records a failed email delivery attempt.
func (a *AuditLedger) LogEmailFailed(subscriptionID, email string, sendErr error) error {
	return a.Log(AuditEntry{
		Event:          AuditEmailFailed,
		SubscriptionID: subscriptionID,
		CustomerEmail:  email,
		Error:          sendErr.Error(),
	})
}

// LogError records a general error event.
func (a *AuditLedger) LogError(subscriptionID, detail string, err error) error {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return a.Log(AuditEntry{
		Event:          AuditError,
		SubscriptionID: subscriptionID,
		Detail:         detail,
		Error:          errStr,
	})
}

// RedactPII strips sensitive fields from a Polar webhook payload before
// logging or storage. Returns a sanitized copy suitable for audit records.
// Removes: card details, billing address, phone numbers.
func RedactPII(data json.RawMessage) json.RawMessage {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		// If we can't parse it, return a redacted placeholder.
		return json.RawMessage(`{"redacted": true, "reason": "parse_error"}`)
	}

	redactedFields := []string{
		"card", "billing_address", "phone", "address",
		"payment_method", "tax_id", "ip_address",
	}

	redactMap(m, redactedFields)

	result, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{"redacted": true, "reason": "marshal_error"}`)
	}
	return result
}

// redactMap recursively removes sensitive keys from a map.
func redactMap(m map[string]interface{}, fields []string) {
	for _, field := range fields {
		if _, ok := m[field]; ok {
			m[field] = "[REDACTED]"
		}
	}

	// Recurse into nested objects.
	for _, v := range m {
		if nested, ok := v.(map[string]interface{}); ok {
			redactMap(nested, fields)
		}
	}
}

// Ensure AuditLedger satisfies a minimal interface for testing.
var _ interface {
	Log(AuditEntry) error
	Close() error
} = (*AuditLedger)(nil)
