//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// openTestDB creates an in-memory SQLite database for testing.
// The database is automatically closed when the test finishes.
func openTestDB(t *testing.T) *EntitlementDB {
	t.Helper()
	db, err := OpenEntitlementDB(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestEntitlementDB_ConcurrentWritersClaimOneActiveTrialSlot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "entitlements.db")
	first, err := OpenEntitlementDB(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("open first writer: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := OpenEntitlementDB(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("open second writer: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	now := time.Now().UTC()
	makeTrial := func(id string) (*Entitlement, LicenseIssuance) {
		ent := testEntitlement(id)
		ent.CustomerEmail = "buyer@example.com"
		ent.Tier = tierTrial
		ent.BillingInterval = billingIntervalOneTime
		ent.CurrentPeriodEnd = now.Add(time.Hour)
		issuance := LicenseIssuance{
			LicenseID:      "lic_" + id,
			SubscriptionID: id,
			IssuedAt:       now,
			ExpiresAt:      ent.CurrentPeriodEnd,
		}
		return ent, issuance
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var writers sync.WaitGroup
	for i, db := range []*EntitlementDB{first, second} {
		writers.Add(1)
		go func(i int, db *EntitlementDB) {
			defer writers.Done()
			<-start
			ent, issuance := makeTrial(fmt.Sprintf("order_%d", i))
			errs <- db.UpsertWithLicenseIssuance(t.Context(), ent, issuance)
		}(i, db)
	}
	close(start)
	writers.Wait()
	close(errs)

	succeeded, denied := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrActiveTrialExists):
			denied++
		default:
			t.Fatalf("unexpected writer result: %v", err)
		}
	}
	if succeeded != 1 || denied != 1 {
		t.Fatalf("writer results: succeeded=%d denied=%d, want 1 each", succeeded, denied)
	}
}

type claimResult struct {
	changed int64
	err     error
}

func (r claimResult) LastInsertId() (int64, error) { return 0, nil }
func (r claimResult) RowsAffected() (int64, error) { return r.changed, r.err }

type claimExecer struct {
	result sql.Result
	err    error
}

func (e claimExecer) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return e.result, e.err
}

func TestClaimActiveTrialSlotErrorsFailClosed(t *testing.T) {
	ent := testEntitlement("order_claim_errors")
	ent.CustomerEmail = "buyer@example.com"
	ent.Tier = tierTrial

	if err := claimActiveTrialSlot(t.Context(), claimExecer{err: errors.New("write failed")}, ent); err == nil || !strings.Contains(err.Error(), "claim active trial slot") {
		t.Fatalf("exec error = %v", err)
	}
	if err := claimActiveTrialSlot(t.Context(), claimExecer{result: claimResult{err: errors.New("result failed")}}, ent); err == nil || !strings.Contains(err.Error(), "read active trial slot result") {
		t.Fatalf("result error = %v", err)
	}
}

func TestSyncActiveTrialSlotErrorFailsClosed(t *testing.T) {
	ent := testEntitlement("order_sync_error")
	err := syncActiveTrialSlot(t.Context(), claimExecer{err: errors.New("write failed")}, ent)
	if err == nil || !strings.Contains(err.Error(), "sync active trial slot") {
		t.Fatalf("sync error = %v", err)
	}
}

// testEntitlement returns a minimal valid entitlement for testing.
func testEntitlement(subID string) *Entitlement {
	return &Entitlement{
		SubscriptionID:   subID,
		CustomerEmail:    testCustomerEmail,
		ProductID:        testProductID,
		Tier:             tierPro,
		BillingInterval:  "month",
		Status:           "active",
		CurrentPeriodEnd: time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
		Founding:         false,
		Org:              "testorg",
		Features:         `["agents"]`,
	}
}

func TestEntitlementDB_UpsertAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	ent := testEntitlement(testSubscriptionID)

	// Insert.
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert insert: %v", err)
	}

	// Retrieve.
	got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got == nil {
		t.Fatal("GetBySubscriptionID returned nil for existing record")
	}
	if got.SubscriptionID != testSubscriptionID {
		t.Errorf("SubscriptionID = %q, want %q", got.SubscriptionID, testSubscriptionID)
	}
	if got.Tier != tierPro {
		t.Errorf("Tier = %q, want %q", got.Tier, tierPro)
	}
	if got.CustomerEmail != testCustomerEmail {
		t.Errorf("CustomerEmail = %q, want %q", got.CustomerEmail, testCustomerEmail)
	}

	// Update via upsert (change email).
	ent.CustomerEmail = "updated@example.com"
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}

	got, err = db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID after update: %v", err)
	}
	if got.CustomerEmail != "updated@example.com" {
		t.Errorf("CustomerEmail after update = %q, want %q", got.CustomerEmail, "updated@example.com")
	}
}

func TestEntitlementDB_LicenseRevocationAndIssuanceValidation(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	now := time.Now().UTC()

	if err := db.Upsert(ctx, nil); err == nil {
		t.Fatal("Upsert nil should error")
	}
	if err := db.UpsertWithLicenseIssuance(ctx, nil, LicenseIssuance{}); err == nil {
		t.Fatal("UpsertWithLicenseIssuance nil entitlement should error")
	}

	for _, rec := range []RevokedLicenseRecord{
		{SubscriptionID: testSubscriptionID},
		{LicenseID: "lic_missing_sub"},
	} {
		if err := db.UpsertLicenseRevocation(ctx, rec); err == nil {
			t.Fatalf("UpsertLicenseRevocation(%+v) should error", rec)
		}
	}

	if err := db.UpsertLicenseRevocation(ctx, RevokedLicenseRecord{
		LicenseID:      "lic_default_reason",
		SubscriptionID: testSubscriptionID,
	}); err != nil {
		t.Fatalf("UpsertLicenseRevocation default fields: %v", err)
	}
	revoked, err := db.ListLicenseRevocations(ctx)
	if err != nil {
		t.Fatalf("ListLicenseRevocations: %v", err)
	}
	if len(revoked) != 1 || revoked[0].Reason != "subscription_ended" || revoked[0].RevokedAt.IsZero() {
		t.Fatalf("revocations = %+v, want default reason and timestamp", revoked)
	}

	for _, issuance := range []LicenseIssuance{
		{SubscriptionID: testSubscriptionID, ExpiresAt: now.Add(time.Hour)},
		{LicenseID: "lic_missing_sub", ExpiresAt: now.Add(time.Hour)},
		{LicenseID: "lic_missing_expiry", SubscriptionID: testSubscriptionID},
	} {
		if err := db.InsertLicenseIssuance(ctx, issuance); err == nil {
			t.Fatalf("InsertLicenseIssuance(%+v) should error", issuance)
		}
	}

	if err := db.InsertLicenseIssuance(ctx, LicenseIssuance{
		LicenseID:      "lic_valid_issuance",
		SubscriptionID: testSubscriptionID,
		ExpiresAt:      now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("InsertLicenseIssuance valid: %v", err)
	}
	issuances, err := db.ListUnexpiredLicenseIssuances(ctx, testSubscriptionID, now)
	if err != nil {
		t.Fatalf("ListUnexpiredLicenseIssuances: %v", err)
	}
	if len(issuances) != 1 || issuances[0].IssuedAt.IsZero() {
		t.Fatalf("issuances = %+v, want default issued_at", issuances)
	}
}

func TestEntitlementDB_UpsertWithLicenseIssuance(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	now := time.Now().UTC()

	ent := testEntitlement("sub_atomic")
	issuance := LicenseIssuance{
		LicenseID:      "lic_atomic",
		SubscriptionID: ent.SubscriptionID,
		ExpiresAt:      now.Add(24 * time.Hour),
		IssuedAt:       now,
	}
	if err := db.UpsertWithLicenseIssuance(ctx, ent, issuance); err != nil {
		t.Fatalf("UpsertWithLicenseIssuance: %v", err)
	}
	got, err := db.GetBySubscriptionID(ctx, ent.SubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got == nil || got.SubscriptionID != ent.SubscriptionID {
		t.Fatalf("entitlement = %+v, want %s", got, ent.SubscriptionID)
	}
	issuances, err := db.ListUnexpiredLicenseIssuances(ctx, ent.SubscriptionID, now.Add(-time.Second))
	if err != nil {
		t.Fatalf("ListUnexpiredLicenseIssuances: %v", err)
	}
	if len(issuances) != 1 || issuances[0].LicenseID != issuance.LicenseID {
		t.Fatalf("issuances = %+v, want %s", issuances, issuance.LicenseID)
	}

	terminal := testEntitlement("sub_terminal")
	terminal.Status = statusCanceled
	if err := db.Upsert(ctx, terminal); err != nil {
		t.Fatalf("Upsert terminal: %v", err)
	}
	terminal.Status = statusActive
	err = db.UpsertWithLicenseIssuance(ctx, terminal, LicenseIssuance{
		LicenseID:      "lic_terminal",
		SubscriptionID: terminal.SubscriptionID,
		ExpiresAt:      now.Add(24 * time.Hour),
		IssuedAt:       now,
	})
	if !errors.Is(err, ErrTerminalEntitlement) {
		t.Fatalf("err = %v, want ErrTerminalEntitlement", err)
	}
}

func TestEntitlementDB_GetBySubscriptionID_NotFound(t *testing.T) {
	db := openTestDB(t)

	got, err := db.GetBySubscriptionID(t.Context(), "sub_nonexistent")
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent subscription, got non-nil")
	}
}

func TestEntitlementDB_ListDueForRefresh(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	future := now.Add(24 * time.Hour)

	// Entitlement due for refresh (next_refresh_at in the past).
	due := testEntitlement("sub_due")
	due.NextRefreshAt = &past
	if err := db.Upsert(ctx, due); err != nil {
		t.Fatalf("Upsert due: %v", err)
	}

	// Entitlement not yet due (next_refresh_at in the future).
	notDue := testEntitlement("sub_not_due")
	notDue.NextRefreshAt = &future
	if err := db.Upsert(ctx, notDue); err != nil {
		t.Fatalf("Upsert not due: %v", err)
	}

	// Canceled entitlement (should not appear even if refresh is due).
	canceled := testEntitlement("sub_canceled")
	canceled.Status = "canceled"
	canceled.NextRefreshAt = &past
	if err := db.Upsert(ctx, canceled); err != nil {
		t.Fatalf("Upsert canceled: %v", err)
	}

	// Entitlement with no refresh scheduled.
	noRefresh := testEntitlement("sub_no_refresh")
	if err := db.Upsert(ctx, noRefresh); err != nil {
		t.Fatalf("Upsert no refresh: %v", err)
	}

	results, err := db.ListDueForRefresh(ctx, now)
	if err != nil {
		t.Fatalf("ListDueForRefresh: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 due entitlement, got %d", len(results))
	}
	if results[0].SubscriptionID != "sub_due" {
		t.Errorf("due entitlement ID = %q, want %q", results[0].SubscriptionID, "sub_due")
	}
}

func TestEntitlementDB_CountFounding(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	// No founding yet.
	count, err := db.CountFounding(ctx)
	if err != nil {
		t.Fatalf("CountFounding: %v", err)
	}
	if count != 0 {
		t.Errorf("initial founding count = %d, want 0", count)
	}

	// Add founding entitlement with reservation timestamp.
	reserved := time.Now().UTC()
	ent := testEntitlement("sub_founding1")
	ent.Founding = true
	ent.FoundingReservedAt = &reserved
	ent.Tier = tierFoundingPro
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert founding: %v", err)
	}

	count, err = db.CountFounding(ctx)
	if err != nil {
		t.Fatalf("CountFounding after insert: %v", err)
	}
	if count != 1 {
		t.Errorf("founding count = %d, want 1", count)
	}

	// Add a non-founding entitlement (should not affect count).
	ent2 := testEntitlement("sub_regular")
	if err := db.Upsert(ctx, ent2); err != nil {
		t.Fatalf("Upsert regular: %v", err)
	}

	count, err = db.CountFounding(ctx)
	if err != nil {
		t.Fatalf("CountFounding with regular: %v", err)
	}
	if count != 1 {
		t.Errorf("founding count with regular = %d, want 1", count)
	}
}

func TestEntitlementDB_UpdateDeliveryStatus(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	ent := testEntitlement(testSubscriptionID)
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	now := time.Now().UTC()
	if err := db.UpdateDeliveryStatus(ctx, testSubscriptionID, testDeliveryStatusSent, now); err != nil {
		t.Fatalf("UpdateDeliveryStatus: %v", err)
	}

	got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got.LastDeliveryStatus != testDeliveryStatusSent {
		t.Errorf("LastDeliveryStatus = %q, want %q", got.LastDeliveryStatus, testDeliveryStatusSent)
	}
}

func TestEntitlementDB_UpdateNextRefresh(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	ent := testEntitlement(testSubscriptionID)
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	nextRefresh := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if err := db.UpdateNextRefresh(ctx, testSubscriptionID, nextRefresh); err != nil {
		t.Fatalf("UpdateNextRefresh: %v", err)
	}

	got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got.NextRefreshAt == nil {
		t.Fatal("NextRefreshAt is nil after update")
	}
}

func TestOpenEntitlementDB_InvalidPath(t *testing.T) {
	// Opening a DB at a path inside a nonexistent directory should fail.
	_, err := OpenEntitlementDB(t.Context(), "/proc/nonexistent/dir/test.db")
	if err == nil {
		t.Fatal("expected error for invalid DB path, got nil")
	}
}

func TestOpenEntitlementDB_CanceledContext(t *testing.T) {
	// A canceled context should cause the PRAGMA ExecContext calls to fail,
	// exercising the error-return paths that clean up the DB handle.
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel before calling

	_, err := OpenEntitlementDB(ctx, filepath.Join(t.TempDir(), "canceled.db"))
	if err == nil {
		t.Fatal("expected error with canceled context, got nil")
	}
}

func TestOpenEntitlementDB_CorruptFile(t *testing.T) {
	// Write garbage to a file so sql.Open accepts the path (lazy)
	// but the first PRAGMA fails because it's not a valid SQLite database.
	path := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(path, []byte("this is not sqlite"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, err := OpenEntitlementDB(t.Context(), path)
	if err == nil {
		t.Fatal("expected error for corrupt DB file, got nil")
	}
}

func TestEntitlementDB_ClosedDBErrors(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	// Close the underlying connection.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// All operations should return errors on a closed DB.
	ent := testEntitlement("sub_closed")
	if err := db.Upsert(ctx, ent); err == nil {
		t.Error("Upsert on closed DB should error")
	}
	trial := testEntitlement("trial_closed")
	trial.Tier = tierTrial
	if err := db.Upsert(ctx, trial); err == nil {
		t.Error("trial Upsert on closed DB should error")
	}
	if err := db.migrate(ctx); err == nil {
		t.Error("migrate on closed DB should error")
	}

	_, err := db.GetBySubscriptionID(ctx, "sub_closed")
	if err == nil {
		t.Error("GetBySubscriptionID on closed DB should error")
	}

	_, err = db.ListDueForRefresh(ctx, time.Now())
	if err == nil {
		t.Error("ListDueForRefresh on closed DB should error")
	}

	_, err = db.CountFounding(ctx)
	if err == nil {
		t.Error("CountFounding on closed DB should error")
	}

	if err := db.UpdateDeliveryStatus(ctx, "sub_x", testDeliveryStatusSent, time.Now()); err == nil {
		t.Error("UpdateDeliveryStatus on closed DB should error")
	}

	if err := db.UpdateNextRefresh(ctx, "sub_x", time.Now()); err == nil {
		t.Error("UpdateNextRefresh on closed DB should error")
	}
}

func TestEntitlementDB_UpsertPreservesLicenseState(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert with license state.
	now := time.Now().UTC()
	ent := testEntitlement(testSubscriptionID)
	ent.LastLicenseID = "lic_test123"
	ent.LastLicenseIssuedAt = &now
	ent.LastLicenseTier = tierPro
	ent.LastLicenseInterval = "month"
	ent.LastLicenseProductID = testProductID
	ent.LastDeliveryStatus = testDeliveryStatusSent

	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Update metadata only (new email), keeping license state.
	ent.CustomerEmail = testEmailNew
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}

	got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got.LastLicenseID != "lic_test123" {
		t.Errorf("LastLicenseID = %q, want %q", got.LastLicenseID, "lic_test123")
	}
	if got.CustomerEmail != testEmailNew {
		t.Errorf("CustomerEmail = %q, want %q", got.CustomerEmail, testEmailNew)
	}
}
