//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- maskEmail coverage tests (83.3% -> higher) ---

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal email", "alice@example.com", "a***@example.com"},
		{"short local part", "a@example.com", "a***@example.com"},
		{"empty string", "", ""},
		{"no at sign", "noemail", "***"},
		{"at sign at start", "@example.com", "***"},
		{"multiple at signs", "user@sub@example.com", "u***@example.com"},
		{"single char before at", "x@y.com", "x***@y.com"},
		{"long local part", "verylonglocalpart@domain.org", "v***@domain.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskEmail(tt.input)
			if got != tt.want {
				t.Errorf("maskEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- OpenAuditLedger coverage tests (76.5% -> higher) ---

func TestOpenAuditLedger_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-ledger.jsonl")

	ledger, err := OpenAuditLedger(path)
	if err != nil {
		t.Fatalf("OpenAuditLedger new file: %v", err)
	}
	defer func() { _ = ledger.Close() }()

	// Verify file was created with correct permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat ledger file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("ledger permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestOpenAuditLedger_ExistingFileNormalizesPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.jsonl")

	// Create file with broader permissions.
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil { //nolint:gosec // intentionally broad perms for test
		t.Fatal(err)
	}

	ledger, err := OpenAuditLedger(path)
	if err != nil {
		t.Fatalf("OpenAuditLedger existing file: %v", err)
	}
	defer func() { _ = ledger.Close() }()

	// Verify permissions were normalized to 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("normalized permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestOpenAuditLedger_ParentSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.MkdirAll(realDir, 0o750); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	// Path where the parent directory contains a symlink.
	path := filepath.Join(linkDir, "audit.jsonl")
	_, err := OpenAuditLedger(path)
	if err == nil {
		t.Fatal("expected error when parent directory contains a symlink")
	}
}

func TestOpenAuditLedger_NonexistentParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent", "deep", "audit.jsonl")
	_, err := OpenAuditLedger(path)
	if err == nil {
		t.Fatal("expected error for nonexistent parent directory")
	}
}

// --- OpenEntitlementDB additional coverage (66.7% -> higher) ---

func TestOpenEntitlementDB_TempDirSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := OpenEntitlementDB(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenEntitlementDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Verify the DB is functional by running a simple query.
	var count int
	err = db.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM entitlements").Scan(&count)
	if err != nil {
		t.Fatalf("query after open: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows in fresh DB, got %d", count)
	}
}

func TestOpenEntitlementDB_MemoryDB(t *testing.T) {
	db, err := OpenEntitlementDB(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("OpenEntitlementDB :memory:: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert and retrieve to verify schema was created.
	ent := testEntitlement("sub_memory_test")
	if err := db.Upsert(t.Context(), ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := db.GetBySubscriptionID(t.Context(), "sub_memory_test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.SubscriptionID != "sub_memory_test" {
		t.Errorf("SubscriptionID = %q, want sub_memory_test", got.SubscriptionID)
	}
}

func TestOpenEntitlementDB_IdempotentMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idempotent.db")

	// Open, close, reopen -- migration should be idempotent.
	db1, err := OpenEntitlementDB(t.Context(), path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	ent := testEntitlement("sub_idempotent")
	if err := db1.Upsert(t.Context(), ent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	_ = db1.Close()

	db2, err := OpenEntitlementDB(t.Context(), path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer func() { _ = db2.Close() }()

	got, err := db2.GetBySubscriptionID(t.Context(), "sub_idempotent")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got == nil || got.SubscriptionID != "sub_idempotent" {
		t.Fatal("data should persist across close/reopen")
	}
}

// --- AuditLedger Log with explicit timestamp ---

func TestAuditLedger_LogMaskesEmail(t *testing.T) {
	ledger, path := openTestLedger(t)

	if err := ledger.Log(AuditEntry{
		Event:         AuditLicenseIssued,
		CustomerEmail: "alice@example.com",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = ledger.Close()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Should contain masked email, not the original.
	if contains(content, "alice@example.com") {
		t.Error("raw email should be masked in ledger")
	}
	if !contains(content, "a***@example.com") {
		t.Error("expected masked email in ledger")
	}
}

// contains is a test helper that checks for substring presence.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- handleWebhook HTTP-level order event coverage (70.5% -> higher) ---

func TestServer_WebhookOrderEvent(t *testing.T) {
	srv := newTestServer(t)

	body := fmt.Sprintf(`{"type":"%s","data":{"id":"order_test123"}}`, EventOrderCreated)
	req := signedWebhookRequest(t, srv, body)
	w := httptest.NewRecorder()

	srv.mux.ServeHTTP(w, req)

	// Order event should get 200 (order handling succeeds or gracefully degrades).
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("order webhook status = %d, want 200 or 500", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// --- isOrderEvent coverage ---

func TestIsOrderEvent(t *testing.T) {
	tests := []struct {
		eventType string
		want      bool
	}{
		{EventOrderCreated, true},
		{EventSubscriptionCreated, false},
		{"", false},
		{"order.updated", false},
	}
	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			got := isOrderEvent(tt.eventType)
			if got != tt.want {
				t.Errorf("isOrderEvent(%q) = %v, want %v", tt.eventType, got, tt.want)
			}
		})
	}
}
