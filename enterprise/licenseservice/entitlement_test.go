//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
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
	"slices"
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
	// The same subscription may write again (idempotent redelivery, a status
	// mirror), but expires_at is write-once: it must not move even for its
	// own owner, or a stale/earlier terminal write could reopen the slot
	// before the trial the operator sees is actually over.
	renewal := trialEntitlement("order_upsert_trial", "holder@example.com", periodEnd.Add(24*time.Hour))
	if err := db.Upsert(ctx, renewal); err != nil {
		t.Fatalf("re-upsert own trial: %v", err)
	}
	slotExpiry := readSlotExpiry(t, db, "holder@example.com")
	if !slotExpiry.Equal(periodEnd) {
		t.Fatalf("slot expires_at = %s, want unchanged original %s", slotExpiry, periodEnd)
	}

	// A revocation is a record, not a claim: it must not be refused.
	revoked := trialEntitlement("order_revoked", "revoked@example.com", periodEnd)
	revoked.Status = statusRevoked
	if err := db.Upsert(ctx, revoked); err != nil {
		t.Fatalf("revoked trial upsert: %v", err)
	}
}

// readSlotExpiry reads the raw expires_at for a canonical email's slot.
func readSlotExpiry(t *testing.T, db *EntitlementDB, email string) time.Time {
	t.Helper()
	canonical, err := NormalizeEmail(email)
	if err != nil {
		t.Fatalf("NormalizeEmail(%q): %v", email, err)
	}
	var got time.Time
	if err := db.db.QueryRowContext(t.Context(),
		`SELECT expires_at FROM active_trial_slots WHERE normalized_email = ?`, canonical,
	).Scan(&got); err != nil {
		t.Fatalf("read slot expiry for %q: %v", email, err)
	}
	return got.UTC()
}

// TestClaimActiveTrialSlot_SameOwnerCannotMoveExpiryEarlier reproduces the
// exact drift the same-owner conflict branch used to allow: claim a slot
// through its original expiry, then a later active Upsert for the SAME
// subscription with an EARLIER CurrentPeriodEnd (a stale/incorrect terminal
// write) must not move the slot into the past, because that would let a new
// order for the same email mint a second trial while the first subscription's
// token is still valid.
func TestClaimActiveTrialSlot_SameOwnerCannotMoveExpiryEarlier(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	now := time.Now().UTC()
	originalExpiry := now.Add(30 * 24 * time.Hour)

	if err := db.Upsert(ctx, trialEntitlement("order_owner_a", "owner@example.com", originalExpiry)); err != nil {
		t.Fatalf("initial claim: %v", err)
	}

	// A later active write for the SAME subscription reports an earlier
	// period end than what was originally claimed.
	staleEarlier := trialEntitlement("order_owner_a", "owner@example.com", now.Add(-time.Minute))
	if err := db.Upsert(ctx, staleEarlier); err != nil {
		t.Fatalf("stale earlier upsert for same owner: %v", err)
	}

	gotExpiry := readSlotExpiry(t, db, "owner@example.com")
	if !gotExpiry.Equal(originalExpiry) {
		t.Fatalf("slot expires_at = %s, want unchanged original %s (write-once)", gotExpiry, originalExpiry)
	}

	// A second order for the same email must still be denied: the slot did
	// NOT move into the past.
	err := issueTrial(t, db, trialEntitlement("order_owner_b", "owner@example.com", originalExpiry))
	if !errors.Is(err, ErrActiveTrialExists) {
		t.Fatalf("second trial after stale same-owner write: err = %v, want ErrActiveTrialExists", err)
	}
}

func TestClaimActiveTrialSlot_SuspectExpiredSlotIsNotTakenOver(t *testing.T) {
	tests := []struct {
		name            string
		setClaimTimeEnd bool
	}{
		{name: "drifted claim-time expiry", setClaimTimeEnd: true},
		{name: "unverifiable claim-time expiry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestDB(t)
			ctx := t.Context()
			now := time.Now().UTC()
			originalExpiry := now.Add(24 * time.Hour)
			first := trialEntitlement("order_suspect_slot_owner", "suspect-slot@example.com", originalExpiry)
			if tt.setClaimTimeEnd {
				first.LastLicensePeriodEnd = &originalExpiry
			}
			if err := db.Upsert(ctx, first); err != nil {
				t.Fatalf("seed first trial: %v", err)
			}
			if _, err := db.db.ExecContext(ctx,
				`UPDATE active_trial_slots SET expires_at = ? WHERE normalized_email = ?`,
				now.Add(-time.Hour), "suspect-slot@example.com",
			); err != nil {
				t.Fatalf("expire suspect slot: %v", err)
			}

			replacement := trialEntitlement("order_suspect_slot_replacement", "suspect-slot@example.com", now.Add(48*time.Hour))
			if err := db.Upsert(ctx, replacement); !errors.Is(err, ErrActiveTrialExists) {
				t.Fatalf("take over suspect expired slot: err = %v, want ErrActiveTrialExists", err)
			}
		})
	}
}

func TestClaimActiveTrialSlot_HealthyExpiredSlotIsTakenOver(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	now := time.Now().UTC()
	expired := now.Add(-time.Hour)
	first := trialEntitlement("order_healthy_slot_owner", "healthy-slot@example.com", expired)
	first.LastLicensePeriodEnd = &expired
	if err := db.Upsert(ctx, first); err != nil {
		t.Fatalf("seed expired trial: %v", err)
	}

	replacementExpiry := now.Add(24 * time.Hour)
	replacement := trialEntitlement("order_healthy_slot_replacement", "healthy-slot@example.com", replacementExpiry)
	replacement.LastLicensePeriodEnd = &replacementExpiry
	if err := db.Upsert(ctx, replacement); err != nil {
		t.Fatalf("take over healthy expired slot: %v", err)
	}

	var owner string
	if err := db.db.QueryRowContext(ctx,
		`SELECT subscription_id FROM active_trial_slots WHERE normalized_email = ?`, "healthy-slot@example.com",
	).Scan(&owner); err != nil {
		t.Fatalf("read replacement slot owner: %v", err)
	}
	if owner != replacement.SubscriptionID {
		t.Fatalf("slot owner = %q, want %q", owner, replacement.SubscriptionID)
	}
}

func TestUpsertWithLicenseIssuanceAndWebhook_TrialRechecksPendingRefund(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
	ent := trialEntitlement("order_refund_before_mint", "refund-before-mint@example.com", expiresAt)

	// This is the committed state from the refund handler after another
	// service instance already completed its stale preflight read. The mint
	// transaction itself must re-read it, rather than trusting that earlier
	// read, before it can claim a slot or insert an entitlement.
	if got, err := db.RecordPendingOneTimeTrialRefund(ctx, &EvalOrder{
		OrderID:          ent.SubscriptionID,
		NormalizedEmail:  ent.CustomerEmail,
		ProductID:        ent.ProductID,
		RefundState:      refundStateFull,
		FulfillmentState: fulfillmentRevoked,
		RevocationState:  revocationPendingNoLicense,
	}); err != nil || got != nil {
		t.Fatalf("RecordPendingOneTimeTrialRefund = (%+v, %v), want (nil, nil)", got, err)
	}

	issuance := LicenseIssuance{
		LicenseID:      "lic_refund_before_mint",
		SubscriptionID: ent.SubscriptionID,
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      expiresAt,
	}
	err := db.UpsertWithLicenseIssuanceAndWebhook(ctx, ent, issuance, "msg_refund_before_mint", "order.paid")
	if !errors.Is(err, ErrTrialRefundPending) {
		t.Fatalf("mint after pending refund: err = %v, want ErrTrialRefundPending", err)
	}
	if got, err := db.GetBySubscriptionID(ctx, ent.SubscriptionID); err != nil || got != nil {
		t.Fatalf("GetBySubscriptionID after refused mint = (%+v, %v), want (nil, nil)", got, err)
	}
	if got := countLicenseIssuances(t, db, ent.SubscriptionID); got != 0 {
		t.Fatalf("license issuances after refused mint = %d, want 0", got)
	}
	if err := db.UpsertWithLicenseIssuanceAndWebhook(ctx, ent, issuance, "msg_refund_before_mint", "order.paid"); !errors.Is(err, ErrTrialRefundPending) {
		t.Fatalf("retry after refused mint: err = %v, want ErrTrialRefundPending", err)
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

// TestOpenEntitlementDB_PragmasApplyToEveryConnection pins that the busy
// timeout, journal mode and foreign-key enforcement come from the connection
// string rather than a one-off PRAGMA statement, INCLUDING on a connection the
// pool opens later. A PRAGMA applies only to the connection that ran it, so a
// replacement connection would otherwise arrive without a busy timeout and a
// concurrent trial claim would surface SQLITE_BUSY as a failed grant.
func TestOpenEntitlementDB_PragmasApplyToEveryConnection(t *testing.T) {
	fileDB, err := OpenEntitlementDB(t.Context(), filepath.Join(t.TempDir(), "pragmas.db"))
	if err != nil {
		t.Fatalf("open file db: %v", err)
	}
	t.Cleanup(func() { _ = fileDB.Close() })

	assertPragmas := func(t *testing.T, db *EntitlementDB, label string) {
		t.Helper()
		var busyTimeout, foreignKeys int
		if err := db.db.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatalf("%s: read busy_timeout: %v", label, err)
		}
		if busyTimeout != 5000 {
			t.Fatalf("%s: busy_timeout = %d, want 5000", label, busyTimeout)
		}
		if err := db.db.QueryRowContext(t.Context(), "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatalf("%s: read foreign_keys: %v", label, err)
		}
		if foreignKeys != 1 {
			t.Fatalf("%s: foreign_keys = %d, want 1", label, foreignKeys)
		}
	}

	assertPragmas(t, fileDB, "file, first connection")
	assertPragmas(t, openTestDB(t), "memory, first connection")

	// Stop the pool from keeping the connection idle, so releasing it closes it
	// and the next query opens a new one. Without the connection string
	// carrying the pragmas, that replacement comes back with busy_timeout 0.
	// MaxOpenConns stays as production sets it, and no sleep is involved: the
	// turnover is a property of the pool settings, not of timing.
	fileDB.db.SetMaxIdleConns(0)
	assertPragmas(t, fileDB, "file, replacement connection")
	assertPragmas(t, fileDB, "file, second replacement connection")
	fileDB.db.SetMaxIdleConns(2)

	// A file database takes WAL; :memory: keeps its own journal mode, and
	// asking for WAL must not make opening it fail.
	if got := fileDB.JournalMode(); got != journalModeWAL {
		t.Fatalf("JournalMode() = %q, want %q for a file database", got, journalModeWAL)
	}
	var journalMode string
	if err := fileDB.db.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal for a file database", journalMode)
	}
	if err := openTestDB(t).db.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read in-memory journal_mode: %v", err)
	}
	if journalMode != "memory" {
		t.Fatalf("in-memory journal_mode = %q, want memory", journalMode)
	}
}

// TestEntitlementDSN_EscapesAwkwardPaths pins that a configured database path
// selects the file it names and still receives the pragmas. The driver reads
// '?' as the start of its parameters even in a bare path, so concatenating the
// pragmas onto /dir/we?ird.db both opened a different database and silently
// dropped the busy timeout.
func TestEntitlementDSN_EscapesAwkwardPaths(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"plain.db", "we?ird.db", "sp ace&x.db", "hash#tag.db"} {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(dir, name)
			db, err := OpenEntitlementDB(t.Context(), target)
			if err != nil {
				t.Fatalf("open %q: %v", name, err)
			}
			t.Cleanup(func() { _ = db.Close() })

			var busyTimeout int
			if err := db.db.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
				t.Fatalf("read busy_timeout: %v", err)
			}
			if busyTimeout != 5000 {
				t.Fatalf("busy_timeout = %d for %q, want 5000", busyTimeout, name)
			}
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("database was not created at the configured path %q: %v", target, err)
			}
		})
	}

	// A filesystem path always becomes an ABSOLUTE file URI. A Windows path
	// arrives without a leading slash, and without one the driver opens a
	// database beside the process rather than the configured one.
	dsn, err := entitlementDSN(filepath.Join(dir, "shape.db"))
	if err != nil {
		t.Fatalf("build dsn: %v", err)
	}
	if !strings.HasPrefix(dsn, "file:///") {
		t.Fatalf("filesystem path produced a relative URI: %s", dsn)
	}
	if got := fileURI("C:/data/entitlements.db"); !strings.HasPrefix(got, "file:///C:/data/entitlements.db?") {
		t.Fatalf("windows-shaped path = %s, want an absolute file:///C:/... URI", got)
	}
}

// TestEntitlementDSN_ExplicitURIKeepsItsOwnParameters opens the DSN it builds
// rather than asserting on substrings: the parameters have to be honored by
// the driver, not merely present in the string.
func TestEntitlementDSN_ExplicitURIKeepsItsOwnParameters(t *testing.T) {
	target := filepath.Join(t.TempDir(), "explicit.db")
	seed, err := OpenEntitlementDB(t.Context(), target)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	dsn, err := entitlementDSN("file:" + target + "?_pragma=cache_size(-2000)")
	if err != nil {
		t.Fatalf("build dsn: %v", err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var busyTimeout, cacheSize int
	if err := db.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000: the merged pragmas were not honored", busyTimeout)
	}
	if err := db.QueryRowContext(t.Context(), "PRAGMA cache_size").Scan(&cacheSize); err != nil {
		t.Fatalf("read cache_size: %v", err)
	}
	if cacheSize != -2000 {
		t.Fatalf("cache_size = %d, want -2000: the URI's own parameter was lost", cacheSize)
	}
}

// TestEntitlementDSN_RefusesAFragment pins that a fragment is named at startup
// rather than carried into the driver. SQLite has no use for one and this
// driver rejects it at the first query with a syntax error pointing at nothing
// the operator can act on, long after the service appeared to start.
func TestEntitlementDSN_RefusesAFragment(t *testing.T) {
	target := filepath.Join(t.TempDir(), "frag.db")
	if _, err := entitlementDSN("file:" + target + "?_pragma=cache_size(-2000)#fragment"); err == nil {
		t.Fatal("a database uri with a fragment was accepted")
	}
	if _, err := OpenEntitlementDB(t.Context(), "file:"+target+"#fragment"); err == nil {
		t.Fatal("OpenEntitlementDB accepted a uri with a fragment")
	} else if !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("error does not name the problem: %v", err)
	}
}

// TestEnableWAL_ToleratesAnotherWriterHoldingTheDatabase pins that a locked
// database does not stop the service from starting.
//
// Changing journal_mode needs an exclusive lock, and SQLite refuses that
// request immediately rather than waiting out busy_timeout. While WAL was a
// connection-string pragma that refusal failed every connection the driver
// opened, at zero elapsed time, so a database another process held for even a
// moment took the whole service down with it. Trial-claim correctness rests on
// the transactional slot constraint rather than on WAL, so a lock here is a
// condition to report, not to die on.
//
// An ordinary write does still wait out busy_timeout and then fail, which is
// correct: migration cannot proceed without writing. The difference this pins
// is that the JOURNAL MODE alone no longer gets a vote.
func TestEnableWAL_ToleratesAnotherWriterHoldingTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.db")

	// Create the database in the default rollback-journal mode, so enabling WAL
	// genuinely has to CHANGE the mode rather than finding it already set.
	holder, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	t.Cleanup(func() { _ = holder.Close() })
	if _, err := holder.ExecContext(t.Context(), "CREATE TABLE lock_probe (x INTEGER)"); err != nil {
		t.Fatalf("seed holder: %v", err)
	}
	var seeded string
	if err := holder.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&seeded); err != nil {
		t.Fatalf("read seeded journal_mode: %v", err)
	}
	if seeded == journalModeWAL {
		t.Fatalf("seeded journal_mode = %q, want a rollback-journal mode so this exercises a real mode change", seeded)
	}

	// Take a write lock and hold it across the WAL attempt.
	tx, err := holder.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), "INSERT INTO lock_probe VALUES (1)"); err != nil {
		t.Fatalf("hold write lock: %v", err)
	}

	contender, err := sql.Open("sqlite", "file://"+path+"?"+dsnPragmas)
	if err != nil {
		t.Fatalf("open contender: %v", err)
	}
	t.Cleanup(func() { _ = contender.Close() })

	mode, err := enableWAL(t.Context(), contender)
	if err != nil {
		t.Fatalf("enableWAL while another writer holds the lock = %v, want it tolerated", err)
	}
	if mode == journalModeWAL {
		t.Fatalf("enableWAL reported %q while the lock was held, want it to report it did not get WAL", mode)
	}

	// WAL is not abandoned: it is taken once nothing holds the lock.
	if err := tx.Rollback(); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	db, err := OpenEntitlementDB(t.Context(), path)
	if err != nil {
		t.Fatalf("open once the lock cleared: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if got := db.JournalMode(); got != journalModeWAL {
		t.Fatalf("JournalMode() = %q, want %q once nothing holds the lock", got, journalModeWAL)
	}

	// And the store works: the slot constraint is what enforces one trial.
	ent := trialEntitlement("sub_locked", "owner@vendor.example", time.Now().Add(24*time.Hour))
	if err := db.Upsert(t.Context(), ent); err != nil {
		t.Fatalf("upsert after the lock cleared: %v", err)
	}
}

// TestDSNPragmas_OmitJournalMode pins that journal_mode is not a connection
// pragma. It is a property of the database file, and asking for it per
// connection is what coupled a transient lock to a failed startup.
func TestDSNPragmas_OmitJournalMode(t *testing.T) {
	if strings.Contains(dsnPragmas, "journal_mode") {
		t.Fatalf("dsnPragmas = %q, want journal_mode set once by enableWAL instead", dsnPragmas)
	}
	for _, required := range []string{"busy_timeout(5000)", "foreign_keys(1)"} {
		if !strings.Contains(dsnPragmas, required) {
			t.Fatalf("dsnPragmas = %q, want it to carry %s on every connection", dsnPragmas, required)
		}
	}
}

// TestReportJournalMode_SpeaksUpOnlyWhenSomethingIsWrong pins what the startup
// report says about each mode the database can settle in.
//
// Two of them are working as intended and stay quiet, and a file database that
// missed write-ahead logging is survivable and warns. An in-memory database
// nobody asked for never reaches this report at all: OpenEntitlementDB refuses
// it outright, which
// TestOpenEntitlementDB_RefusesAConfiguredInMemoryDatabase covers.
func TestReportJournalMode_SpeaksUpOnlyWhenSomethingIsWrong(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		inMemory  bool
		wantLevel string
		wantSays  string
	}{
		{name: "file database took WAL", mode: journalModeWAL},
		{name: "the operator asked for an in-memory database", mode: journalModeMemory, inMemory: true},
		{
			name: "a file database did not get WAL", mode: "delete",
			wantLevel: "warn", wantSays: "restart this service",
		},
		{
			name: "the mode could not be read at all", mode: "",
			wantLevel: "warn", wantSays: "restart this service",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			db := &EntitlementDB{journalMode: tc.mode, inMemory: tc.inMemory}
			db.ReportJournalMode(zerolog.New(&buf))

			out := buf.String()
			if !strings.Contains(out, `"journal_mode":"`+tc.mode+`"`) {
				t.Fatalf("report did not record the mode it saw: %s", out)
			}
			for _, level := range []string{"warn", "error"} {
				got := strings.Contains(out, `"level":"`+level+`"`)
				if got != (tc.wantLevel == level) {
					t.Fatalf("level %q present = %v, want %v: %s", level, got, tc.wantLevel == level, out)
				}
			}
			if tc.wantSays != "" && !strings.Contains(out, tc.wantSays) {
				t.Fatalf("report does not say %q: %s", tc.wantSays, out)
			}
		})
	}
}

// TestEnableWAL_FailsClosedOnANonLockError pins that only a lock is tolerated.
// A lock is transient and another process's doing; an I/O or corruption error
// is neither, and starting anyway would hide it.
func TestEnableWAL_FailsClosedOnANonLockError(t *testing.T) {
	db, err := sql.Open("sqlite", "file://"+filepath.Join(t.TempDir(), "closed.db")+"?"+dsnPragmas)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	mode, err := enableWAL(t.Context(), db)
	if err == nil {
		t.Fatalf("enableWAL on a closed database = %q, want an error", mode)
	}
	if !strings.Contains(err.Error(), "enable write-ahead logging") {
		t.Fatalf("error = %v, want it to name the operation", err)
	}
}

// TestEntitlementDSN_RefusesARelativePathItCannotResolve pins that a path the
// service cannot make absolute is refused rather than guessed at.
//
// filepath.Abs fails only when the working directory is gone. The fallback
// that used to stand here kept the relative path, which then picked up a
// leading slash on its way into a file: URI and named a database at the
// filesystem ROOT: a different, empty entitlement store that would have
// re-granted every trial the real one had already spent.
func TestEntitlementDSN_RefusesARelativePathItCannotResolve(t *testing.T) {
	// Sit in a directory and then remove it, which is what makes the working
	// directory unavailable. t.Chdir restores the original when the test ends.
	dir := filepath.Join(t.TempDir(), "vanishing")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("create dir: %v", err)
	}
	t.Chdir(dir)
	if err := os.Remove(dir); err != nil {
		t.Fatalf("remove dir: %v", err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("this platform still resolves a removed working directory, so Abs cannot fail here")
	}

	dsn, err := entitlementDSN("entitlements.db")
	if err == nil {
		t.Fatalf("entitlementDSN = %q, want a refusal rather than a guessed path", dsn)
	}
	if !strings.Contains(err.Error(), "resolve database path") {
		t.Fatalf("error = %v, want it to name what could not be resolved", err)
	}
}

// TestOpenEntitlementDB_RefusesAConfiguredInMemoryDatabase pins that a database
// which keeps nothing across a restart is refused rather than merely reported.
//
// A configured URI can carry mode=memory. It opens successfully and then
// discards every entitlement and trial slot when the process stops, so the
// table the one-trial limit is read from is empty on every start and each
// customer is handed their trial again. Logging that and serving anyway does
// not stop it, so startup fails instead.
func TestOpenEntitlementDB_RefusesAConfiguredInMemoryDatabase(t *testing.T) {
	uri := "file://" + filepath.Join(t.TempDir(), "ephemeral.db") + "?mode=memory"

	db, err := OpenEntitlementDB(t.Context(), uri)
	if err == nil {
		_ = db.Close()
		t.Fatal("opened an in-memory database from a configured URI, want a refusal")
	}
	for _, want := range []string{"keeps no entitlement or trial state", inMemoryPath} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to mention %q", err, want)
		}
	}

	// The sentinel is still how a caller asks for an ephemeral database.
	sentinel, err := OpenEntitlementDB(t.Context(), inMemoryPath)
	if err != nil {
		t.Fatalf("open %s: %v", inMemoryPath, err)
	}
	t.Cleanup(func() { _ = sentinel.Close() })
	if got := sentinel.JournalMode(); got != journalModeMemory {
		t.Fatalf("sentinel JournalMode() = %q, want %q", got, journalModeMemory)
	}
}

func TestTrialSlotExpiryDriftReport(t *testing.T) {
	tests := []struct {
		name             string
		drifted          []string
		unverifiable     []string
		wantDrifted      []string
		wantUnverifiable []string
	}{
		{name: "no slots"},
		{
			name:        "one drifted",
			drifted:     []string{"order_drifted"},
			wantDrifted: []string{"order_drifted"},
		},
		{
			name:             "one legacy null row",
			unverifiable:     []string{"order_legacy"},
			wantUnverifiable: []string{"order_legacy"},
		},
		{
			name:             "mixed rows",
			drifted:          []string{"order_drifted"},
			unverifiable:     []string{"order_legacy"},
			wantDrifted:      []string{"order_drifted"},
			wantUnverifiable: []string{"order_legacy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestDB(t)
			ctx := t.Context()
			original := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

			for _, subscriptionID := range append(tt.drifted, tt.unverifiable...) {
				ent := trialEntitlement(subscriptionID, subscriptionID+"@example.com", original)
				if !slices.Contains(tt.unverifiable, subscriptionID) {
					ent.LastLicensePeriodEnd = &original
				}
				if err := db.Upsert(ctx, ent); err != nil {
					t.Fatalf("seed trial %s: %v", subscriptionID, err)
				}
			}
			for _, subscriptionID := range tt.drifted {
				if _, err := db.db.ExecContext(ctx,
					`UPDATE active_trial_slots SET expires_at = ? WHERE subscription_id = ?`, original.Add(-time.Hour), subscriptionID,
				); err != nil {
					t.Fatalf("simulate drifted slot %s: %v", subscriptionID, err)
				}
			}

			report, err := db.TrialSlotExpiryDriftReport(ctx)
			if err != nil {
				t.Fatalf("TrialSlotExpiryDriftReport: %v", err)
			}
			gotDrifted := make([]string, 0, len(report.Drifted))
			for _, drifted := range report.Drifted {
				gotDrifted = append(gotDrifted, drifted.SubscriptionID)
			}
			if !slices.Equal(gotDrifted, tt.wantDrifted) {
				t.Fatalf("drifted subscription IDs = %v, want %v", gotDrifted, tt.wantDrifted)
			}
			if !slices.Equal(report.UnverifiableSubscriptionIDs, tt.wantUnverifiable) {
				t.Fatalf("unverifiable subscription IDs = %v, want %v", report.UnverifiableSubscriptionIDs, tt.wantUnverifiable)
			}
			for _, subscriptionID := range tt.drifted {
				if got := readSlotExpiry(t, db, subscriptionID+"@example.com"); !got.Equal(original.Add(-time.Hour)) {
					t.Fatalf("drift report repaired %s: got %s, want %s", subscriptionID, got, original.Add(-time.Hour))
				}
			}

			var buf bytes.Buffer
			if got := db.ReportDriftedTrialSlots(ctx, zerolog.New(&buf)); !slices.Equal(got, tt.wantUnverifiable) {
				t.Fatalf("reported unverifiable subscription IDs = %v, want %v", got, tt.wantUnverifiable)
			}
			if strings.Contains(buf.String(), "order_legacy") {
				t.Fatalf("drift report logged unverifiable row: %s", buf.String())
			}
			for _, subscriptionID := range tt.drifted {
				if !strings.Contains(buf.String(), subscriptionID) {
					t.Fatalf("drift report did not log drifted row %q: %s", subscriptionID, buf.String())
				}
			}
		})
	}
}
