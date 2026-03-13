//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/rs/zerolog"
)

// testSetup creates a fully wired test environment with in-memory DB,
// temp ledger, mock Polar server, and mock email server.
type testSetup struct {
	handler    *WebhookHandler
	db         *EntitlementDB
	ledger     *AuditLedger
	cfg        *Config
	polarSrv   *httptest.Server
	emailSrv   *httptest.Server
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// newTestSetup creates a complete test environment. The Polar mock returns
// the subscription set via setPolarResponse. The email mock always succeeds.
func newTestSetup(t *testing.T) *testSetup {
	t.Helper()

	db := openTestDB(t)
	ledger, _ := openTestLedger(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Default Polar mock: returns an active pro subscription.
	polarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"id": "%s",
			"status": "active",
			"customer": {"email": "%s", "metadata": {"org": "testcorp"}},
			"product": {"id": "%s", "name": "%s", "metadata": {"pipelock_tier": "pro"}},
			"recurring_interval": "month",
			"current_period_end": "2026-04-12T00:00:00Z"
		}`, testSubscriptionID, testCustomerEmail, testProductID, testProductName)
	}))
	t.Cleanup(polarSrv.Close)

	// Email mock: always returns success.
	emailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_test789"}`))
	}))
	t.Cleanup(emailSrv.Close)

	cfg := &Config{
		PolarWebhookSecret:  "whsec_" + "dGVzdA==",
		PolarAPIToken:       testPolarAPIToken,
		PrivateKeyPath:      filepath.Join(t.TempDir(), "test.key"),
		ResendAPIKey:        "re_" + "test_key",
		DBPath:              ":memory:",
		LedgerPath:          filepath.Join(t.TempDir(), "test.jsonl"),
		FoundingProCap:      50,
		FoundingProDeadline: time.Date(2099, 6, 30, 0, 0, 0, 0, time.UTC),
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

	log := zerolog.Nop()

	handler, err := NewWebhookHandler(cfg, db, polar, email, ledger, priv, log)
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	return &testSetup{
		handler:    handler,
		db:         db,
		ledger:     ledger,
		cfg:        cfg,
		polarSrv:   polarSrv,
		emailSrv:   emailSrv,
		privateKey: priv,
		publicKey:  pub,
	}
}

func TestMapProductToTier(t *testing.T) {
	ts := newTestSetup(t)

	tests := []struct {
		name      string
		metadata  map[string]string
		wantTier  string
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "pro tier",
			metadata:  map[string]string{"pipelock_tier": "pro"},
			wantTier:  tierPro,
			wantFound: false,
			wantErr:   false,
		},
		{
			name:      "founding pro tier",
			metadata:  map[string]string{"pipelock_tier": "founding_pro"},
			wantTier:  tierFoundingPro,
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "enterprise tier",
			metadata:  map[string]string{"pipelock_tier": "enterprise"},
			wantTier:  tierEnterprise,
			wantFound: false,
			wantErr:   false,
		},
		{
			name:     "missing tier metadata",
			metadata: map[string]string{},
			wantErr:  true,
		},
		{
			name:     "unrecognized tier value",
			metadata: map[string]string{"pipelock_tier": "premium"},
			wantErr:  true,
		},
		{
			name:     "typo in tier",
			metadata: map[string]string{"pipelock_tier": "pr0"},
			wantErr:  true,
		},
		{
			name:     "empty tier value",
			metadata: map[string]string{"pipelock_tier": ""},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub := &PolarSubscription{
				Product: struct {
					ID       string            `json:"id"`
					Name     string            `json:"name"`
					Metadata map[string]string `json:"metadata"`
				}{
					ID:       testProductID,
					Name:     testProductName,
					Metadata: tt.metadata,
				},
			}

			tier, founding, err := ts.handler.mapProductToTier(sub)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapProductToTier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if tier != tt.wantTier {
				t.Errorf("tier = %q, want %q", tier, tt.wantTier)
			}
			if founding != tt.wantFound {
				t.Errorf("founding = %v, want %v", founding, tt.wantFound)
			}
		})
	}
}

func TestTierToFeatures(t *testing.T) {
	ts := newTestSetup(t)

	tests := []struct {
		name string
		tier string
		want []string
	}{
		{"pro", tierPro, []string{license.FeatureAgents}},
		{"founding pro", tierFoundingPro, []string{license.FeatureAgents}},
		{"enterprise", tierEnterprise, []string{license.FeatureAgents}},
		{"unknown returns nil (fail-closed)", "unknown", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ts.handler.tierToFeatures(tt.tier)
			if len(got) != len(tt.want) {
				t.Errorf("tierToFeatures(%q) = %v, want %v", tt.tier, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("feature[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsIdempotent(t *testing.T) {
	ts := newTestSetup(t)
	periodEnd := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		current  *Entitlement
		existing *Entitlement
		want     bool
	}{
		{
			name: "identical state is idempotent",
			current: &Entitlement{
				CurrentPeriodEnd: periodEnd,
				Tier:             tierPro,
				BillingInterval:  testIntervalMonth,
				ProductID:        testProductID,
			},
			existing: &Entitlement{
				LastLicensePeriodEnd: &periodEnd,
				LastLicenseTier:      tierPro,
				LastLicenseInterval:  testIntervalMonth,
				LastLicenseProductID: testProductID,
			},
			want: true,
		},
		{
			name: "different period end is not idempotent",
			current: &Entitlement{
				CurrentPeriodEnd: periodEnd.Add(30 * 24 * time.Hour),
				Tier:             tierPro,
				BillingInterval:  testIntervalMonth,
				ProductID:        testProductID,
			},
			existing: &Entitlement{
				LastLicensePeriodEnd: &periodEnd,
				LastLicenseTier:      tierPro,
				LastLicenseInterval:  testIntervalMonth,
				LastLicenseProductID: testProductID,
			},
			want: false,
		},
		{
			name: "different tier is not idempotent",
			current: &Entitlement{
				CurrentPeriodEnd: periodEnd,
				Tier:             tierEnterprise,
				BillingInterval:  testIntervalMonth,
				ProductID:        testProductID,
			},
			existing: &Entitlement{
				LastLicensePeriodEnd: &periodEnd,
				LastLicenseTier:      tierPro,
				LastLicenseInterval:  testIntervalMonth,
				LastLicenseProductID: testProductID,
			},
			want: false,
		},
		{
			name: "never issued before",
			current: &Entitlement{
				CurrentPeriodEnd: periodEnd,
				Tier:             tierPro,
				BillingInterval:  testIntervalMonth,
				ProductID:        testProductID,
			},
			existing: &Entitlement{
				LastLicensePeriodEnd: nil,
			},
			want: false,
		},
		{
			name: "different interval is not idempotent",
			current: &Entitlement{
				CurrentPeriodEnd: periodEnd,
				Tier:             tierPro,
				BillingInterval:  testIntervalYear,
				ProductID:        testProductID,
			},
			existing: &Entitlement{
				LastLicensePeriodEnd: &periodEnd,
				LastLicenseTier:      tierPro,
				LastLicenseInterval:  testIntervalMonth,
				LastLicenseProductID: testProductID,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ts.handler.isIdempotent(tt.current, tt.existing)
			if got != tt.want {
				t.Errorf("isIdempotent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckFoundingCap_ReservesSlot(t *testing.T) {
	ts := newTestSetup(t)
	ts.cfg.FoundingProCap = 5

	ctx := t.Context()

	ent := testEntitlement("sub_founding_new")
	ent.Tier = tierFoundingPro
	ent.Founding = true

	if err := ts.handler.checkFoundingCap(ctx, ent); err != nil {
		t.Fatalf("checkFoundingCap: %v", err)
	}

	if ent.Tier != tierFoundingPro {
		t.Errorf("Tier = %q, want %q (should remain founding)", ent.Tier, tierFoundingPro)
	}
	if ts.handler.foundingCount != 1 {
		t.Errorf("foundingCount = %d, want 1", ts.handler.foundingCount)
	}
	if ent.FoundingReservedAt == nil {
		t.Error("FoundingReservedAt should be set after reservation")
	}
}

func TestCheckFoundingCap_CapReached(t *testing.T) {
	ts := newTestSetup(t)
	ts.cfg.FoundingProCap = 2
	ctx := t.Context()

	// Insert 2 founding entitlements so DB count matches the cap.
	reserved := time.Now().UTC()
	for i := 0; i < 2; i++ {
		e := testEntitlement(fmt.Sprintf("sub_cap_fill_%d", i))
		e.Founding = true
		e.FoundingReservedAt = &reserved
		e.Tier = tierFoundingPro
		if err := ts.db.Upsert(ctx, e); err != nil {
			t.Fatalf("Upsert cap fill %d: %v", i, err)
		}
	}
	ts.handler.foundingCount = 2

	ent := testEntitlement("sub_over_cap")
	ent.Tier = tierFoundingPro
	ent.Founding = true

	if err := ts.handler.checkFoundingCap(ctx, ent); err != nil {
		t.Fatalf("checkFoundingCap: %v", err)
	}

	// Should be downgraded to pro.
	if ent.Tier != tierPro {
		t.Errorf("Tier = %q, want %q (should be downgraded)", ent.Tier, tierPro)
	}
	if ent.Founding {
		t.Error("Founding should be false after cap downgrade")
	}
}

func TestCheckFoundingCap_DeadlinePassed(t *testing.T) {
	ts := newTestSetup(t)
	ts.cfg.FoundingProDeadline = time.Now().Add(-24 * time.Hour) // yesterday

	ctx := t.Context()

	ent := testEntitlement("sub_past_deadline")
	ent.Tier = tierFoundingPro
	ent.Founding = true

	if err := ts.handler.checkFoundingCap(ctx, ent); err != nil {
		t.Fatalf("checkFoundingCap: %v", err)
	}

	if ent.Tier != tierPro {
		t.Errorf("Tier = %q, want %q (deadline passed)", ent.Tier, tierPro)
	}
	if ent.Founding {
		t.Error("Founding should be false after deadline")
	}
}

func TestCheckFoundingCap_AlreadyHasSlot(t *testing.T) {
	ts := newTestSetup(t)
	ts.cfg.FoundingProCap = 1
	ts.handler.foundingCount = 1 // at cap

	ctx := t.Context()

	// Insert an existing founding entitlement in the DB.
	reserved := time.Now().UTC()
	existing := testEntitlement("sub_existing_founding")
	existing.Founding = true
	existing.FoundingReservedAt = &reserved
	existing.Tier = tierFoundingPro
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	ent := testEntitlement("sub_existing_founding")
	ent.Tier = tierFoundingPro
	ent.Founding = true

	// Should not downgrade because this sub already has a founding slot.
	if err := ts.handler.checkFoundingCap(ctx, ent); err != nil {
		t.Fatalf("checkFoundingCap: %v", err)
	}

	if ent.Tier != tierFoundingPro {
		t.Errorf("Tier = %q, want %q (already has slot)", ent.Tier, tierFoundingPro)
	}
}

func TestCheckFoundingCap_ProductChangeCantReopenSlot(t *testing.T) {
	ts := newTestSetup(t)
	ts.cfg.FoundingProCap = 1
	ctx := t.Context()

	// A subscriber reserved the only founding slot, then changed products.
	// The founding bool is now false (current product), but
	// FoundingReservedAt is still set (immutable reservation).
	reserved := time.Now().UTC()
	original := testEntitlement("sub_switched_product")
	original.Founding = false // product changed away from founding
	original.FoundingReservedAt = &reserved
	original.Tier = tierPro
	if err := ts.db.Upsert(ctx, original); err != nil {
		t.Fatalf("Upsert original: %v", err)
	}

	// A new subscriber tries to claim the "freed" slot.
	ent := testEntitlement("sub_new_claimant")
	ent.Tier = tierFoundingPro
	ent.Founding = true

	if err := ts.handler.checkFoundingCap(ctx, ent); err != nil {
		t.Fatalf("checkFoundingCap: %v", err)
	}

	// Should be downgraded because the slot is still reserved (count=1, cap=1).
	if ent.Tier != tierPro {
		t.Errorf("Tier = %q, want %q (slot should not reopen)", ent.Tier, tierPro)
	}
	if ent.Founding {
		t.Error("Founding should be false (slot not available)")
	}
}

func TestProcessSubscription_ActiveMintsCertificate(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{"org": "testcorp"}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	// Point the email sender at our mock server.
	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription: %v", err)
	}

	// Verify entitlement was persisted.
	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent == nil {
		t.Fatal("entitlement not found after processSubscription")
	}
	if ent.Tier != tierPro {
		t.Errorf("Tier = %q, want %q", ent.Tier, tierPro)
	}
	if ent.LastLicenseID == "" {
		t.Error("LastLicenseID should be set after issuance")
	}
	if ent.LastLicenseIssuedAt == nil {
		t.Error("LastLicenseIssuedAt should be set")
	}
	if ent.NextRefreshAt == nil {
		t.Error("NextRefreshAt should be set")
	}

	// Verify the issued license is valid.
	// We can't easily get the token from here, but we can verify the license ID format.
	if len(ent.LastLicenseID) < 4 || ent.LastLicenseID[:4] != "lic_" {
		t.Errorf("LastLicenseID format wrong: %q", ent.LastLicenseID)
	}
}

func TestProcessSubscription_CanceledClearsRefresh(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Pre-insert an active entitlement with license state.
	now := time.Now().UTC()
	expires := now.Add(45 * 24 * time.Hour)
	refresh := now.Add(30 * 24 * time.Hour)
	existing := testEntitlement(testSubscriptionID)
	existing.LastLicenseID = testLicenseIDOld
	existing.LastLicenseIssuedAt = &now
	existing.LastLicenseExpiresAt = &expires
	existing.NextRefreshAt = &refresh
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "canceled",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	// Point email sender at mock (cancellation email).
	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription canceled: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.Status != testStatusCanceled {
		t.Errorf("Status = %q, want %q", ent.Status, testStatusCanceled)
	}
	if ent.NextRefreshAt != nil {
		t.Error("NextRefreshAt should be nil after cancellation")
	}
}

func TestProcessSubscription_IdempotentSkipsReissue(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	periodEnd := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

	// Pre-insert an entitlement that matches the incoming subscription state
	// exactly (email, org, tier, interval, product, period, delivery status).
	now := time.Now().UTC()
	existing := testEntitlement(testSubscriptionID)
	existing.Org = "testcorp"
	existing.LastLicenseID = "lic_existing"
	existing.LastLicenseIssuedAt = &now
	existing.LastLicensePeriodEnd = &periodEnd
	existing.LastLicenseTier = tierPro
	existing.LastLicenseInterval = testIntervalMonth
	existing.LastLicenseProductID = testProductID
	existing.LastDeliveryStatus = testDeliveryStatusSent
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  periodEnd,
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{"org": "testcorp"}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription idempotent: %v", err)
	}

	// License ID should be preserved (not re-minted).
	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.LastLicenseID != "lic_existing" {
		t.Errorf("LastLicenseID = %q, want %q (should be preserved)", ent.LastLicenseID, "lic_existing")
	}
}

func TestProcessSubscription_RefreshDueBypassesIdempotency(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	periodEnd := time.Date(2027, 3, 12, 0, 0, 0, 0, time.UTC) // annual plan

	// Pre-insert an entitlement with an overdue refresh (simulates cron pickup).
	now := time.Now().UTC()
	pastDue := now.Add(-1 * time.Hour) // refresh was due 1 hour ago
	existing := testEntitlement(testSubscriptionID)
	existing.Org = "testcorp"
	existing.BillingInterval = testIntervalYear
	existing.CurrentPeriodEnd = periodEnd
	existing.LastLicenseID = "lic_annual_old"
	existing.LastLicenseIssuedAt = &now
	existing.LastLicensePeriodEnd = &periodEnd
	existing.LastLicenseTier = tierPro
	existing.LastLicenseInterval = testIntervalYear
	existing.LastLicenseProductID = testProductID
	existing.LastDeliveryStatus = testDeliveryStatusSent
	existing.NextRefreshAt = &pastDue
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	// Same subscription state (annual plan, nothing changed).
	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "active",
		RecurringInterval: testIntervalYear,
		CurrentPeriodEnd:  periodEnd,
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{"org": "testcorp"}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	// Must get a new token even though subscription state is unchanged.
	if ent.LastLicenseID == "lic_annual_old" {
		t.Error("license should have been re-minted for due refresh")
	}
}

func TestProcessSubscription_IdempotentReissuesOnEmailChange(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	periodEnd := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

	// Pre-insert an entitlement with a delivered license.
	now := time.Now().UTC()
	existing := testEntitlement(testSubscriptionID)
	existing.LastLicenseID = "lic_old_email"
	existing.LastLicenseIssuedAt = &now
	existing.LastLicensePeriodEnd = &periodEnd
	existing.LastLicenseTier = tierPro
	existing.LastLicenseInterval = testIntervalMonth
	existing.LastLicenseProductID = testProductID
	existing.LastDeliveryStatus = testDeliveryStatusSent
	existing.CustomerEmail = "old@example.com"
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	// Same plan but different email. Should re-mint.
	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  periodEnd,
	}
	sub.Customer.Email = testEmailNew
	sub.Customer.Metadata = map[string]string{"org": "testcorp"}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.LastLicenseID == "lic_old_email" {
		t.Error("license should have been re-minted for email change")
	}
}

func TestProcessSubscription_IdempotentRetriesFailedDelivery(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	periodEnd := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

	// Pre-insert an entitlement where delivery failed.
	now := time.Now().UTC()
	existing := testEntitlement(testSubscriptionID)
	existing.LastLicenseID = "lic_failed_delivery"
	existing.LastLicenseIssuedAt = &now
	existing.LastLicensePeriodEnd = &periodEnd
	existing.LastLicenseTier = tierPro
	existing.LastLicenseInterval = testIntervalMonth
	existing.LastLicenseProductID = testProductID
	existing.LastDeliveryStatus = "failed"
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	// Same plan, same email. But delivery failed, so should re-mint and retry.
	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  periodEnd,
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{"org": "testorg"}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.LastLicenseID == "lic_failed_delivery" {
		t.Error("license should have been re-minted to retry failed delivery")
	}
	if ent.LastDeliveryStatus != testDeliveryStatusSent {
		t.Errorf("LastDeliveryStatus = %q, want %q", ent.LastDeliveryStatus, testDeliveryStatusSent)
	}
}

func TestProcessSubscription_RejectsUnknownTier(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	sub := &PolarSubscription{
		ID:                "sub_bad_tier",
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = "prod_misconfigured"
	sub.Product.Name = "Bad Product"
	sub.Product.Metadata = map[string]string{"pipelock_tier": "trial"}

	err := ts.handler.processSubscription(ctx, sub)
	if err == nil {
		t.Fatal("expected error for unrecognized tier, got nil")
	}

	// Verify no entitlement was created.
	ent, _ := ts.db.GetBySubscriptionID(ctx, "sub_bad_tier")
	if ent != nil {
		t.Error("should not persist entitlement for rejected tier")
	}
}

func TestProcessSubscription_UnknownStatusRecorded(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	sub := &PolarSubscription{
		ID:                "sub_unknown_status",
		Status:            testStatusPending,
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription unknown status: %v", err)
	}

	// Should be recorded with the unknown status.
	ent, err := ts.db.GetBySubscriptionID(ctx, "sub_unknown_status")
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent == nil {
		t.Fatal("entitlement should be recorded for unknown status")
	}
	if ent.Status != testStatusPending {
		t.Errorf("Status = %q, want %q", ent.Status, testStatusPending)
	}
}

func TestProcessSubscription_UnknownStatusPreservesLicense(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Pre-insert an active entitlement with full license state.
	now := time.Now().UTC()
	expires := now.Add(45 * 24 * time.Hour)
	refresh := now.Add(30 * 24 * time.Hour)
	periodEnd := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	existing := testEntitlement("sub_unknown_preserve")
	existing.LastLicenseID = "lic_preserve_me"
	existing.LastLicenseIssuedAt = &now
	existing.LastLicenseExpiresAt = &expires
	existing.LastLicensePeriodEnd = &periodEnd
	existing.LastLicenseTier = tierPro
	existing.LastLicenseInterval = testIntervalMonth
	existing.LastLicenseProductID = testProductID
	existing.LastDeliveryStatus = testDeliveryStatusSent
	existing.LastDeliveryAttemptAt = &now
	existing.NextRefreshAt = &refresh
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	sub := &PolarSubscription{
		ID:                "sub_unknown_preserve",
		Status:            testStatusPending,
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  periodEnd,
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription unknown status: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, "sub_unknown_preserve")
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.Status != testStatusPending {
		t.Errorf("Status = %q, want %q", ent.Status, testStatusPending)
	}
	// License state must be preserved, not wiped.
	if ent.LastLicenseID != "lic_preserve_me" {
		t.Errorf("LastLicenseID = %q, want %q (should be preserved)", ent.LastLicenseID, "lic_preserve_me")
	}
	if ent.NextRefreshAt == nil {
		t.Error("NextRefreshAt should be preserved for unknown status")
	}
	if ent.LastDeliveryStatus != testDeliveryStatusSent {
		t.Errorf("LastDeliveryStatus = %q, want %q", ent.LastDeliveryStatus, testDeliveryStatusSent)
	}
}

func TestHandleEvent_EndToEnd(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Point email sender at mock.
	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	event := &PolarWebhookEvent{
		Type: EventSubscriptionCreated,
		Data: json.RawMessage(testSubscriptionJSON),
	}

	if err := ts.handler.HandleEvent(ctx, event); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}

	// Verify entitlement was created.
	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent == nil {
		t.Fatal("entitlement not created after HandleEvent")
	}
	if ent.LastLicenseID == "" {
		t.Error("license should have been issued")
	}
}

func TestSubscriptionToEntitlement(t *testing.T) {
	ts := newTestSetup(t)

	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "active",
		RecurringInterval: testIntervalYear,
		CurrentPeriodEnd:  time.Date(2027, 3, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{"org": "acme-corp"}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "enterprise"}

	ent, err := ts.handler.subscriptionToEntitlement(sub)
	if err != nil {
		t.Fatalf("subscriptionToEntitlement: %v", err)
	}

	if ent.SubscriptionID != testSubscriptionID {
		t.Errorf("SubscriptionID = %q, want %q", ent.SubscriptionID, testSubscriptionID)
	}
	if ent.Tier != tierEnterprise {
		t.Errorf("Tier = %q, want %q", ent.Tier, tierEnterprise)
	}
	if ent.BillingInterval != testIntervalYear {
		t.Errorf("BillingInterval = %q, want %q", ent.BillingInterval, testIntervalYear)
	}
	if ent.Org != "acme-corp" {
		t.Errorf("Org = %q, want %q", ent.Org, "acme-corp")
	}
	if ent.Founding {
		t.Error("enterprise tier should not be founding")
	}

	// Verify features JSON contains "agents".
	var features []string
	if err := json.Unmarshal([]byte(ent.Features), &features); err != nil {
		t.Fatalf("unmarshal features: %v", err)
	}
	if len(features) == 0 || features[0] != license.FeatureAgents {
		t.Errorf("features = %v, want [%q]", features, license.FeatureAgents)
	}
}

func TestNewWebhookHandler_InitializesFoundingCount(t *testing.T) {
	db := openTestDB(t)
	ledger, _ := openTestLedger(t)
	ctx := context.Background()

	// Insert 3 founding entitlements with reservation timestamps.
	reserved := time.Now().UTC()
	for i := 0; i < 3; i++ {
		ent := testEntitlement(fmt.Sprintf("sub_founding_%d", i))
		ent.Founding = true
		ent.FoundingReservedAt = &reserved
		ent.Tier = tierFoundingPro
		if err := db.Upsert(ctx, ent); err != nil {
			t.Fatalf("Upsert founding %d: %v", i, err)
		}
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg := &Config{
		FoundingProCap:      50,
		FoundingProDeadline: time.Date(2099, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	polar := NewPolarClient("token", "http://localhost")
	email := NewEmailSender("key", "from@test.com")

	handler, err := NewWebhookHandler(cfg, db, polar, email, ledger, priv, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	if handler.foundingCount != 3 {
		t.Errorf("foundingCount = %d, want 3", handler.foundingCount)
	}
}

func TestHandleEvent_BadSubscriptionID(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Event data with no "id" field.
	event := &PolarWebhookEvent{
		Type: EventSubscriptionCreated,
		Data: json.RawMessage(`{"status":"active"}`),
	}

	err := ts.handler.HandleEvent(ctx, event)
	if err == nil {
		t.Fatal("expected error for missing subscription ID, got nil")
	}
}

func TestHandleEvent_PolarFetchError(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Replace Polar with error server.
	errorPolar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"down"}`))
	}))
	defer errorPolar.Close()
	ts.handler.polar = NewPolarClient(testPolarAPIToken, errorPolar.URL)

	event := &PolarWebhookEvent{
		Type: EventSubscriptionCreated,
		Data: json.RawMessage(testSubscriptionJSON),
	}

	err := ts.handler.HandleEvent(ctx, event)
	if err == nil {
		t.Fatal("expected error for Polar fetch failure, got nil")
	}
}

func TestProcessSubscription_RevokedClearsRefresh(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Pre-insert active entitlement with license.
	now := time.Now().UTC()
	expires := now.Add(45 * 24 * time.Hour)
	existing := testEntitlement(testSubscriptionID)
	existing.LastLicenseID = "lic_revoked"
	existing.LastLicenseIssuedAt = &now
	existing.LastLicenseExpiresAt = &expires
	refresh := now.Add(30 * 24 * time.Hour)
	existing.NextRefreshAt = &refresh
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "revoked",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	// Point email sender at mock.
	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription revoked: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.Status != "revoked" {
		t.Errorf("Status = %q, want %q", ent.Status, "revoked")
	}
	if ent.NextRefreshAt != nil {
		t.Error("NextRefreshAt should be nil after revocation")
	}
}

func TestProcessSubscription_EmailFailureStillPersists(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Email mock that always fails.
	failEmailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"email down"}`))
	}))
	defer failEmailSrv.Close()

	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_fail",
		fromEmail: "test@pipelock.dev",
		client:    failEmailSrv.Client(),
		apiURL:    failEmailSrv.URL,
	}

	sub := &PolarSubscription{
		ID:                "sub_email_fail",
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	// Should NOT return error (email failure is non-fatal for persistence).
	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, "sub_email_fail")
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent == nil {
		t.Fatal("entitlement should be persisted even with email failure")
	}
	if ent.LastLicenseID == "" {
		t.Error("license should still be issued despite email failure")
	}
}

func TestProcessSubscription_HandleEndedNoExistingLicense(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Canceled subscription with NO prior entitlement (no license to expire).
	sub := &PolarSubscription{
		ID:                "sub_cancel_fresh",
		Status:            "canceled",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, "sub_cancel_fresh")
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.Status != testStatusCanceled {
		t.Errorf("Status = %q, want %q", ent.Status, testStatusCanceled)
	}
}

func TestProcessSubscription_EndedEmailFailure(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Pre-insert an existing entitlement with a license expiry so handleEnded
	// will attempt to send a cancellation email.
	now := time.Now().UTC()
	expires := now.Add(45 * 24 * time.Hour)
	existing := testEntitlement(testSubscriptionID)
	existing.LastLicenseID = testLicenseIDOld
	existing.LastLicenseIssuedAt = &now
	existing.LastLicenseExpiresAt = &expires
	if err := ts.db.Upsert(ctx, existing); err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}

	// Email mock that always fails.
	failEmailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"email down"}`))
	}))
	defer failEmailSrv.Close()

	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_fail",
		fromEmail: "test@pipelock.dev",
		client:    failEmailSrv.Client(),
		apiURL:    failEmailSrv.URL,
	}

	sub := &PolarSubscription{
		ID:                testSubscriptionID,
		Status:            "canceled",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	// handleEnded should NOT return error even when email fails.
	// Email failure is logged but non-fatal.
	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.Status != testStatusCanceled {
		t.Errorf("Status = %q, want %q", ent.Status, testStatusCanceled)
	}
}

func TestNewWebhookHandler_DBError(t *testing.T) {
	db := openTestDB(t)
	ledger, _ := openTestLedger(t)

	// Close the DB so CountFounding fails.
	_ = db.Close()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg := &Config{
		FoundingProCap:      50,
		FoundingProDeadline: time.Date(2099, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	polar := NewPolarClient("token", "http://localhost")
	email := NewEmailSender("key", "from@test.com")

	_, err = NewWebhookHandler(cfg, db, polar, email, ledger, priv, zerolog.Nop())
	if err == nil {
		t.Fatal("expected error when DB is closed, got nil")
	}
}

func TestProcessSubscription_DBErrorOnGetExisting(t *testing.T) {
	ts := newTestSetup(t)

	// Close the DB so GetBySubscriptionID fails.
	_ = ts.db.Close()

	sub := &PolarSubscription{
		ID:                "sub_db_error",
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	err := ts.handler.processSubscription(t.Context(), sub)
	if err == nil {
		t.Fatal("expected DB error, got nil")
	}
}

func TestProcessSubscription_LicenseIssueError(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	// Replace private key with an invalid one (wrong length).
	ts.handler.privateKey = ed25519.PrivateKey([]byte("too-short"))

	sub := &PolarSubscription{
		ID:                "sub_bad_key",
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	err := ts.handler.processSubscription(ctx, sub)
	if err == nil {
		t.Fatal("expected license issue error, got nil")
	}
}

func TestProcessSubscription_FoundingCapDBError(t *testing.T) {
	ts := newTestSetup(t)

	// Close the DB so the founding cap check's DB lookup fails.
	_ = ts.db.Close()

	sub := &PolarSubscription{
		ID:                "sub_founding_db_err",
		Status:            "active",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "founding_pro"}

	err := ts.handler.processSubscription(t.Context(), sub)
	if err == nil {
		t.Fatal("expected founding cap DB error, got nil")
	}
}

func TestProcessSubscription_UnpaidStatus(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()

	sub := &PolarSubscription{
		ID:                "sub_unpaid",
		Status:            "unpaid",
		RecurringInterval: testIntervalMonth,
		CurrentPeriodEnd:  time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
	}
	sub.Customer.Email = testCustomerEmail
	sub.Customer.Metadata = map[string]string{}
	sub.Product.ID = testProductID
	sub.Product.Name = testProductName
	sub.Product.Metadata = map[string]string{"pipelock_tier": "pro"}

	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	if err := ts.handler.processSubscription(ctx, sub); err != nil {
		t.Fatalf("processSubscription unpaid: %v", err)
	}

	ent, err := ts.db.GetBySubscriptionID(ctx, "sub_unpaid")
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if ent.Status != "unpaid" {
		t.Errorf("Status = %q, want %q", ent.Status, "unpaid")
	}
}
