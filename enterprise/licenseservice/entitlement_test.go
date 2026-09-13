//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"bytes"
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

	"github.com/rs/zerolog"
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

// trialEntitlement builds an active one-time trial for slot tests.
func trialEntitlement(subscriptionID, email string, periodEnd time.Time) *Entitlement {
	return &Entitlement{
		SubscriptionID:   subscriptionID,
		CustomerEmail:    email,
		ProductID:        "prod_trial_free",
		Tier:             tierTrial,
		Status:           statusActive,
		BillingInterval:  billingIntervalOneTime,
		CurrentPeriodEnd: periodEnd,
	}
}

func issueTrial(t *testing.T, db *EntitlementDB, ent *Entitlement) error {
	t.Helper()
	return db.UpsertWithLicenseIssuanceAndWebhook(t.Context(), ent, LicenseIssuance{
		LicenseID:      "lic_" + ent.SubscriptionID,
		SubscriptionID: ent.SubscriptionID,
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      ent.CurrentPeriodEnd,
	}, "msg_"+ent.SubscriptionID, "order.paid")
}

// TestActiveTrialSlot_CaseAndWhitespaceVariantsShareOneSlot pins the identity
// the slot is keyed by. The column is named normalized_email, and if the value
// is not actually canonical then "Buyer@Example.com" and " buyer@example.com "
// own separate slots and the one-active-trial rule enforces nothing.
func TestActiveTrialSlot_CaseAndWhitespaceVariantsShareOneSlot(t *testing.T) {
	db := openTestDB(t)
	periodEnd := time.Now().UTC().Add(24 * time.Hour)

	if err := issueTrial(t, db, trialEntitlement("order_mixed_case", "Buyer@Example.com", periodEnd)); err != nil {
		t.Fatalf("first trial: %v", err)
	}
	for _, variant := range []string{" buyer@example.com ", "BUYER@EXAMPLE.COM", "Buyer@example.com"} {
		err := issueTrial(t, db, trialEntitlement("order_variant", variant, periodEnd))
		if !errors.Is(err, ErrActiveTrialExists) {
			t.Fatalf("variant %q: err = %v, want ErrActiveTrialExists", variant, err)
		}
	}
	// A genuinely different address is unaffected.
	if err := issueTrial(t, db, trialEntitlement("order_other", "someone@example.com", periodEnd)); err != nil {
		t.Fatalf("different email denied: %v", err)
	}
}

// TestUpsert_ActiveTrialClaimsItsSlot pins the bypass that update-only
// synchronization left open: an active trial written through Upsert must OWN a
// slot, or a different subscription can claim the still-free slot afterwards
// and two active trials exist for one email.
func TestUpsert_ActiveTrialClaimsItsSlot(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	periodEnd := time.Now().UTC().Add(24 * time.Hour)

	if err := db.Upsert(ctx, trialEntitlement("order_upsert_trial", "holder@example.com", periodEnd)); err != nil {
		t.Fatalf("upsert active trial: %v", err)
	}
	err := issueTrial(t, db, trialEntitlement("order_second", "holder@example.com", periodEnd))
	if !errors.Is(err, ErrActiveTrialExists) {
		t.Fatalf("second trial after Upsert: err = %v, want ErrActiveTrialExists", err)
	}
	// The same subscription may still renew its own slot.
	renewal := trialEntitlement("order_upsert_trial", "holder@example.com", periodEnd.Add(24*time.Hour))
	if err := db.Upsert(ctx, renewal); err != nil {
		t.Fatalf("renew own trial: %v", err)
	}

	// A revocation is a record, not a claim: it must not be refused.
	revoked := trialEntitlement("order_revoked", "revoked@example.com", periodEnd)
	revoked.Status = statusRevoked
	if err := db.Upsert(ctx, revoked); err != nil {
		t.Fatalf("revoked trial upsert: %v", err)
	}
}

// TestBackfillActiveTrialSlots_BindsOwnerToItsOwnExpiry pins that the migration
// takes the owner and the expiry from the SAME entitlement. Selecting them with
// independent aggregates can seed one trial's owner beside another trial's end
// date, and a later write for that owner then shortens the slot while the
// longer trial is still running, freeing a trial early.
func TestBackfillActiveTrialSlots_BindsOwnerToItsOwnExpiry(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	now := time.Now().UTC()
	shortEnd := now.Add(24 * time.Hour)
	longEnd := now.Add(240 * time.Hour)

	// Legacy state: two active trials on one canonical email. The
	// lowest-sorting subscription ID deliberately holds the SHORTER trial, so
	// a min-id/max-expiry pairing would bind "order_aaa" to longEnd.
	legacy := []*Entitlement{
		trialEntitlement("order_aaa", "Legacy@Example.com", shortEnd),
		trialEntitlement("order_zzz", "legacy@example.com", longEnd),
	}
	for _, row := range legacy {
		if err := upsertEntitlement(ctx, db.db, row); err != nil {
			t.Fatalf("seed %s: %v", row.SubscriptionID, err)
		}
	}
	if _, err := db.db.ExecContext(ctx, `DELETE FROM active_trial_slots`); err != nil {
		t.Fatalf("clear slots: %v", err)
	}
	if err := db.backfillActiveTrialSlots(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var (
		email    string
		owner    string
		expires  time.Time
		rowsSeen int
	)
	rows, err := db.db.QueryContext(ctx, `SELECT normalized_email, subscription_id, expires_at FROM active_trial_slots`)
	if err != nil {
		t.Fatalf("read slots: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := rows.Scan(&email, &owner, &expires); err != nil {
			t.Fatalf("scan slot: %v", err)
		}
		rowsSeen++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate slots: %v", err)
	}
	if rowsSeen != 1 {
		t.Fatalf("slot rows = %d, want exactly 1 canonical slot", rowsSeen)
	}
	if email != "legacy@example.com" {
		t.Fatalf("slot key = %q, want the canonical address", email)
	}
	if owner != "order_zzz" {
		t.Fatalf("slot owner = %q, want order_zzz, the subscription that owns the latest expiry", owner)
	}
	if !expires.UTC().Equal(longEnd.Truncate(time.Second)) && expires.UTC().Sub(longEnd).Abs() > time.Second {
		t.Fatalf("slot expiry = %v, want %v (the owner's own expiry)", expires.UTC(), longEnd)
	}
}

// TestTrialSlot_UncanonicalizableEmailIsRecordedButNeverGranted pins the split
// between enforcement and record. An address the service cannot canonicalize
// can hold no slot, so the one-active-trial rule cannot bound it: a GRANT is
// refused rather than minted unbounded. Merely RECORDING such an entitlement
// still succeeds, because refusing that would block revoking a legacy row and
// would buy no enforcement.
func TestTrialSlot_UncanonicalizableEmailIsRecordedButNeverGranted(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	periodEnd := time.Now().UTC().Add(24 * time.Hour)

	grant := trialEntitlement("order_bad_email_grant", "not-an-email", periodEnd)
	err := issueTrial(t, db, grant)
	if !errors.Is(err, ErrTrialEmailNotCanonical) {
		t.Fatalf("grant with uncanonicalizable email: err = %v, want ErrTrialEmailNotCanonical", err)
	}

	// Recording the same entitlement succeeds and leaves no slot behind.
	record := trialEntitlement("order_bad_email_record", "not-an-email", periodEnd)
	if err := db.Upsert(ctx, record); err != nil {
		t.Fatalf("record active trial with uncanonicalizable email: %v", err)
	}
	var slots int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM active_trial_slots`).Scan(&slots); err != nil {
		t.Fatalf("count slots: %v", err)
	}
	if slots != 0 {
		t.Fatalf("slot rows = %d, want 0: an uncanonicalizable address must hold no slot", slots)
	}

	// Revoking it also succeeds: the update-only refresh skips the missing slot
	// instead of failing the write.
	record.Status = statusRevoked
	if err := db.Upsert(ctx, record); err != nil {
		t.Fatalf("revoke trial with uncanonicalizable email: %v", err)
	}
}

// TestBackfillActiveTrialSlots_FailsClosedOnStoreErrors pins that the migration
// reports a store failure instead of returning success with an empty or partial
// slot table, which would silently disable the one-active-trial rule.
func TestBackfillActiveTrialSlots_FailsClosedOnStoreErrors(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	if err := upsertEntitlement(ctx, db.db, trialEntitlement("order_backfill", "backfill@example.com", time.Now().UTC().Add(24*time.Hour))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if err := db.backfillActiveTrialSlots(ctx); err == nil {
		t.Fatal("backfill on a closed database returned success")
	}
}

// TestBackfillActiveTrialSlots_SkipsUncanonicalizableRows pins that the
// migration gives no slot to an address it cannot canonicalize. Seeding one
// under a raw key would create a slot no later claim could ever match, which
// silently exempts that address from the one-active-trial rule forever.
func TestBackfillActiveTrialSlots_SkipsUncanonicalizableRows(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	periodEnd := time.Now().UTC().Add(24 * time.Hour)

	seed := []*Entitlement{
		trialEntitlement("order_garbage", "not-an-email", periodEnd),
		trialEntitlement("order_good", "Good@Example.com", periodEnd),
	}
	for _, row := range seed {
		if err := upsertEntitlement(ctx, db.db, row); err != nil {
			t.Fatalf("seed %s: %v", row.SubscriptionID, err)
		}
	}
	if _, err := db.db.ExecContext(ctx, `DELETE FROM active_trial_slots`); err != nil {
		t.Fatalf("clear slots: %v", err)
	}
	if err := db.backfillActiveTrialSlots(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var email string
	var count int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM active_trial_slots`).Scan(&count); err != nil {
		t.Fatalf("count slots: %v", err)
	}
	if count != 1 {
		t.Fatalf("slot rows = %d, want 1: only the canonicalizable address gets a slot", count)
	}
	if err := db.db.QueryRowContext(ctx, `SELECT normalized_email FROM active_trial_slots`).Scan(&email); err != nil {
		t.Fatalf("read slot: %v", err)
	}
	if email != "good@example.com" {
		t.Fatalf("slot key = %q, want the canonical good address", email)
	}
}

// TestUpsert_ActiveTrialDeniedWhenSlotIsHeld pins that a collision detected
// inside Upsert surfaces as a denial instead of committing a second active
// trial for one canonical email.
func TestUpsert_ActiveTrialDeniedWhenSlotIsHeld(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	periodEnd := time.Now().UTC().Add(24 * time.Hour)

	if err := issueTrial(t, db, trialEntitlement("order_holder", "Shared@Example.com", periodEnd)); err != nil {
		t.Fatalf("seed holder: %v", err)
	}
	err := db.Upsert(ctx, trialEntitlement("order_intruder", "shared@example.com", periodEnd))
	if !errors.Is(err, ErrActiveTrialExists) {
		t.Fatalf("Upsert into a held slot: err = %v, want ErrActiveTrialExists", err)
	}
	got, lerr := db.GetBySubscriptionID(ctx, "order_intruder")
	if lerr != nil {
		t.Fatalf("load intruder: %v", lerr)
	}
	if got != nil {
		t.Fatalf("denied trial was persisted: %+v", got)
	}
}

// TestDuplicateActiveTrialEmails_ReportsPreservedLegacyTrials pins that the
// migration's preservation of pre-existing duplicates is visible. The slot
// table holds one owner per canonical email, so a second legacy trial keeps
// running; an operator has to be told, because reconciling a live paid trial
// is their decision and not a silent migration side effect.
func TestDuplicateActiveTrialEmails_ReportsPreservedLegacyTrials(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	periodEnd := time.Now().UTC().Add(24 * time.Hour)

	seed := []*Entitlement{
		trialEntitlement("order_dup_a", "Dup@Example.com", periodEnd),
		trialEntitlement("order_dup_b", "dup@example.com", periodEnd.Add(time.Hour)),
		trialEntitlement("order_solo", "solo@example.com", periodEnd),
	}
	for _, row := range seed {
		if err := upsertEntitlement(ctx, db.db, row); err != nil {
			t.Fatalf("seed %s: %v", row.SubscriptionID, err)
		}
	}

	duplicates, err := db.DuplicateActiveTrialEmails(ctx)
	if err != nil {
		t.Fatalf("duplicate report: %v", err)
	}
	if len(duplicates) != 1 {
		t.Fatalf("duplicate emails = %v, want exactly the one shared address", duplicates)
	}
	subs, ok := duplicates["dup@example.com"]
	if !ok {
		t.Fatalf("duplicate report = %v, want the canonical shared address", duplicates)
	}
	if len(subs) != 2 {
		t.Fatalf("duplicate subscriptions = %v, want both orders", subs)
	}
	// The longest-running trial is named first, which is the one the backfill
	// gives the slot to.
	if subs[0] != "order_dup_b" {
		t.Fatalf("first reported subscription = %q, want the longest-running trial", subs[0])
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if _, err := db.DuplicateActiveTrialEmails(ctx); err == nil {
		t.Fatal("duplicate report on a closed database returned success")
	}
}

// TestReportDuplicateActiveTrials_NamesEachAffectedCustomer pins the operator
// signal: every customer the migration could not bring under the limit is named
// with its order IDs, a customer with a single trial is not, and a read failure
// warns instead of taking the service down over a report.
func TestReportDuplicateActiveTrials_NamesEachAffectedCustomer(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	periodEnd := time.Now().UTC().Add(24 * time.Hour)

	seed := []*Entitlement{
		trialEntitlement("order_rep_a", "Rep@Example.com", periodEnd),
		trialEntitlement("order_rep_b", "rep@example.com", periodEnd.Add(time.Hour)),
		trialEntitlement("order_rep_solo", "solo@example.com", periodEnd),
	}
	for _, row := range seed {
		if err := upsertEntitlement(ctx, db.db, row); err != nil {
			t.Fatalf("seed %s: %v", row.SubscriptionID, err)
		}
	}

	var buf bytes.Buffer
	db.ReportDuplicateActiveTrials(ctx, zerolog.New(&buf))
	out := buf.String()
	for _, want := range []string{"order_rep_a", "order_rep_b"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "order_rep_solo") {
		t.Fatalf("single-trial customer was reported as a duplicate: %s", out)
	}
	// Logs are retained and shipped, so the address itself must not appear:
	// the order IDs are the reconciliation handle.
	for _, forbidden := range []string{"rep@example.com", "Rep@Example.com", "solo@example.com"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("customer email %q was written to the log: %s", forbidden, out)
		}
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	buf.Reset()
	db.ReportDuplicateActiveTrials(ctx, zerolog.New(&buf))
	if !strings.Contains(buf.String(), "could not check") {
		t.Fatalf("read failure was not reported: %s", buf.String())
	}
}
