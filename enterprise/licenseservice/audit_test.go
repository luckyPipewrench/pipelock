//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// openTestLedger creates a temporary audit ledger for testing.
func openTestLedger(t *testing.T) (*AuditLedger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-audit.jsonl")
	ledger, err := OpenAuditLedger(path)
	if err != nil {
		t.Fatalf("open test ledger: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger, path
}

func TestAuditLedger_LogAndRead(t *testing.T) {
	ledger, path := openTestLedger(t)

	// Write an entry.
	entry := AuditEntry{
		Event:          AuditLicenseIssued,
		SubscriptionID: testSubscriptionID,
		CustomerEmail:  testCustomerEmail,
		LicenseID:      "lic_test123",
		Tier:           tierPro,
	}
	if err := ledger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Close and read back.
	_ = ledger.Close()

	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open ledger file: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected at least one line in ledger")
	}

	var got AuditEntry
	if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal ledger entry: %v", err)
	}

	if got.Event != AuditLicenseIssued {
		t.Errorf("Event = %q, want %q", got.Event, AuditLicenseIssued)
	}
	if got.SubscriptionID != testSubscriptionID {
		t.Errorf("SubscriptionID = %q, want %q", got.SubscriptionID, testSubscriptionID)
	}
	if got.Timestamp.IsZero() {
		t.Error("Timestamp should be auto-filled, got zero")
	}
}

func TestAuditLedger_TimestampAutoFill(t *testing.T) {
	ledger, path := openTestLedger(t)

	before := time.Now().UTC().Add(-1 * time.Second)
	if err := ledger.Log(AuditEntry{Event: AuditWebhookReceived}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	after := time.Now().UTC().Add(1 * time.Second)

	_ = ledger.Close()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}

	var got AuditEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Timestamp.Before(before) || got.Timestamp.After(after) {
		t.Errorf("Timestamp %v not in expected range [%v, %v]", got.Timestamp, before, after)
	}
}

func TestAuditLedger_PreservesExplicitTimestamp(t *testing.T) {
	ledger, path := openTestLedger(t)

	explicit := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	if err := ledger.Log(AuditEntry{Event: AuditError, Timestamp: explicit}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	_ = ledger.Close()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var got AuditEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !got.Timestamp.Equal(explicit) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, explicit)
	}
}

func TestAuditLedger_ConcurrentWrites(t *testing.T) {
	ledger, path := openTestLedger(t)

	const goroutines = 20
	const entriesPerGoroutine = 5

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				_ = ledger.Log(AuditEntry{
					Event:          AuditWebhookReceived,
					SubscriptionID: testSubscriptionID,
				})
			}
		}()
	}
	wg.Wait()

	_ = ledger.Close()

	// Count lines in the ledger file.
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	lineCount := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineCount++
		// Verify each line is valid JSON.
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Errorf("invalid JSON on line %d: %v", lineCount, err)
		}
	}

	want := goroutines * entriesPerGoroutine
	if lineCount != want {
		t.Errorf("line count = %d, want %d", lineCount, want)
	}
}

func TestAuditLedger_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	link := filepath.Join(dir, "link.jsonl")

	// Create a real file first.
	f, err := os.Create(filepath.Clean(target))
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	_ = f.Close()

	// Create symlink.
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err = OpenAuditLedger(link)
	if err == nil {
		t.Error("expected error opening symlink, got nil")
	}
}

func TestAuditLedger_LogEmailFailed_NilError(t *testing.T) {
	ledger, path := openTestLedger(t)

	// Should not panic with nil error.
	if err := ledger.LogEmailFailed(testSubscriptionID, testCustomerEmail, nil); err != nil {
		t.Fatalf("LogEmailFailed with nil: %v", err)
	}

	_ = ledger.Close()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var got AuditEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Error != "" {
		t.Errorf("Error field = %q, want empty for nil error", got.Error)
	}
}

func TestAuditLedger_LogEmailFailed_WithError(t *testing.T) {
	ledger, path := openTestLedger(t)

	testErr := errors.New("smtp timeout")
	if err := ledger.LogEmailFailed(testSubscriptionID, testCustomerEmail, testErr); err != nil {
		t.Fatalf("LogEmailFailed: %v", err)
	}

	_ = ledger.Close()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var got AuditEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Error != "smtp timeout" {
		t.Errorf("Error = %q, want %q", got.Error, "smtp timeout")
	}
}

func TestAuditLedger_ConvenienceMethods(t *testing.T) {
	ledger, path := openTestLedger(t)

	// Exercise all convenience methods.
	_ = ledger.LogWebhookReceived("subscription.created", testSubscriptionID)
	_ = ledger.LogLicenseIssued(testSubscriptionID, testCustomerEmail, "lic_1", tierPro, time.Now())
	_ = ledger.LogEmailSent(testSubscriptionID, testCustomerEmail, "msg_123")
	_ = ledger.LogError(testSubscriptionID, "test error", errors.New("boom"))
	_ = ledger.LogError(testSubscriptionID, "nil error", nil)

	_ = ledger.Close()

	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}

	// 5 log calls = 5 lines.
	if lineCount != 5 {
		t.Errorf("line count = %d, want 5", lineCount)
	}
}

func TestAuditLedger_WriteAfterClose(t *testing.T) {
	ledger, _ := openTestLedger(t)

	// Close the ledger, then try to write.
	_ = ledger.Close()

	err := ledger.Log(AuditEntry{Event: AuditWebhookReceived})
	if err == nil {
		t.Error("Log after Close should return error")
	}
}

func TestOpenAuditLedger_InvalidPath(t *testing.T) {
	// Path inside a nonexistent directory should fail.
	_, err := OpenAuditLedger("/proc/nonexistent/dir/audit.jsonl")
	if err == nil {
		t.Fatal("expected error for invalid ledger path, got nil")
	}
}

func TestRedactPII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		checkKey string
		want     string
	}{
		{
			name:     "redacts top-level card",
			input:    `{"id":"sub_1","card":"4111111111111111","email":"a@b.com"}`,
			checkKey: "card",
			want:     "[REDACTED]",
		},
		{
			name:     "redacts nested billing_address",
			input:    `{"customer":{"billing_address":"123 Main St","email":"a@b.com"}}`,
			checkKey: "", // just verify no error
		},
		{
			name:     "redacts in array elements",
			input:    `{"orders":[{"card":"4111","amount":100},{"card":"5222","amount":200}]}`,
			checkKey: "", // check via deeper inspection
		},
		{
			name:  "invalid json returns redacted placeholder",
			input: `{not valid`,
		},
		{
			name:     "preserves non-sensitive fields",
			input:    `{"id":"sub_1","status":"active"}`,
			checkKey: "status",
			want:     "active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactPII(json.RawMessage(tt.input))
			if result == nil {
				t.Fatal("RedactPII returned nil")
			}

			// Verify result is valid JSON.
			var m map[string]interface{}
			if err := json.Unmarshal(result, &m); err != nil {
				t.Fatalf("RedactPII result is not valid JSON: %v", err)
			}

			if tt.checkKey != "" && tt.want != "" {
				val, ok := m[tt.checkKey]
				if !ok {
					t.Errorf("key %q not found in redacted output", tt.checkKey)
				} else if fmt, ok := val.(string); ok && fmt != tt.want {
					t.Errorf("key %q = %q, want %q", tt.checkKey, fmt, tt.want)
				}
			}
		})
	}
}

func TestRedactPII_ArrayNesting(t *testing.T) {
	input := `{"orders":[{"card":"4111","amount":100},{"phone":"555-1234","amount":200}]}`
	result := RedactPII(json.RawMessage(input))

	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	orders, ok := m["orders"].([]interface{})
	if !ok {
		t.Fatal("orders field not an array")
	}
	if len(orders) != 2 {
		t.Fatalf("expected 2 orders, got %d", len(orders))
	}

	order0 := orders[0].(map[string]interface{})
	if order0["card"] != "[REDACTED]" {
		t.Errorf("order[0].card = %v, want [REDACTED]", order0["card"])
	}

	order1 := orders[1].(map[string]interface{})
	if order1["phone"] != "[REDACTED]" {
		t.Errorf("order[1].phone = %v, want [REDACTED]", order1["phone"])
	}
}
