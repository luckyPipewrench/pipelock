//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestHandleOrderRefundEvent_EvalStorageFailures keeps the refund acknowledgement
// last: a storage failure is returned to Polar and the delivery stays retryable.
func TestHandleOrderRefundEvent_EvalStorageFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, s *evalTestSetup)
	}{
		{
			name: "list issuances",
			setup: func(t *testing.T, s *evalTestSetup) {
				seedRefundEvalOrder(t, s)
				renameTable(t, s.db, "license_issuances", "license_issuances_fault")
			},
		},
		{
			name: "record revocation",
			setup: func(t *testing.T, s *evalTestSetup) {
				seedRefundEvalOrder(t, s)
				seedRefundIssuance(t, s.db, testEvalOrderID)
				createFaultTrigger(t, s.db, "fail_eval_revocation")
			},
		},
		{
			name: "upsert eval refund",
			setup: func(t *testing.T, s *evalTestSetup) {
				seedRefundEvalOrder(t, s)
				createFaultTrigger(t, s.db, "fail_eval_upsert")
			},
		},
		{
			name: "mark webhook committed",
			setup: func(t *testing.T, s *evalTestSetup) {
				seedRefundEvalOrder(t, s)
				createFaultTrigger(t, s.db, "fail_eval_commit")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newEvalTestSetup(t)
			refundBody := defaultEvalOrderJSON(orderStatusRefunded)
			s.orderJSON.Store(&refundBody)
			tt.setup(t, s)
			msgID := "msg_eval_refund_" + strings.ReplaceAll(tt.name, " ", "_")
			err := s.handler.HandleOrderRefundEvent(t.Context(), evalRefundEvent(), msgID)
			if err == nil {
				t.Fatal("HandleOrderRefundEvent succeeded after a storage failure")
			}
			assertWebhookUncommitted(t, s.db, msgID)
			if tt.name == "mark webhook committed" {
				assertEvalRefundRecorded(t, s.db)
			} else {
				assertEvalRefundUnchanged(t, s.db)
			}
			if tt.name != "list issuances" {
				assertNoRevocations(t, s.db)
			}
		})
	}
}

// TestHandleOrderRefundEvent_TrialStorageFailures exercises the same real
// entry point for the one-time trial branch.  The commit-marker case records
// the entitlement revocation before attempting the marker; that is the
// deliberate retry-safe ordering of the production handler.
func TestHandleOrderRefundEvent_TrialStorageFailures(t *testing.T) {
	tests := []struct {
		name         string
		withIssuance bool
		setup        func(t *testing.T, s *testSetup)
		wantStatus   string
	}{
		{
			name: "list issuances", withIssuance: true, wantStatus: statusActive,
			setup: func(t *testing.T, s *testSetup) { renameTable(t, s.db, "license_issuances", "license_issuances_fault") },
		},
		{
			name: "record revocation", withIssuance: true, wantStatus: statusActive,
			setup: func(t *testing.T, s *testSetup) {
				createFaultTrigger(t, s.db, "fail_trial_revocation")
			},
		},
		{
			name: "upsert entitlement", wantStatus: statusActive,
			setup: func(t *testing.T, s *testSetup) {
				createFaultTrigger(t, s.db, "fail_trial_upsert")
			},
		},
		{
			name: "mark webhook committed", wantStatus: statusRevoked,
			setup: func(t *testing.T, s *testSetup) {
				createFaultTrigger(t, s.db, "fail_trial_commit")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSetup(t)
			const orderID = "order_enterprise_trial_refunded"
			seedOneTimeTrial(t, s.db, orderID, tt.withIssuance)
			tt.setup(t, s)
			msgID := "msg_trial_refund_" + strings.ReplaceAll(tt.name, " ", "_")
			err := s.handler.HandleOrderRefundEvent(t.Context(), refundEvent(orderID), msgID)
			if err == nil {
				t.Fatal("HandleOrderRefundEvent succeeded after a storage failure")
			}
			assertWebhookUncommitted(t, s.db, msgID)
			ent, getErr := s.db.GetBySubscriptionID(t.Context(), orderID)
			if getErr != nil || ent == nil || ent.Status != tt.wantStatus {
				t.Fatalf("entitlement after failed refund = %+v, %v; want status %q", ent, getErr, tt.wantStatus)
			}
			if tt.name != "list issuances" {
				assertNoRevocations(t, s.db)
			}
		})
	}
}

func TestHandleOrderRefundEvent_GetEntitlementFailureIsUncommitted(t *testing.T) {
	s := newTestSetup(t)
	const orderID = "order_enterprise_trial_refunded"
	renameTable(t, s.db, "entitlements", "entitlements_fault")
	const msgID = "msg_trial_refund_get_entitlement"
	if err := s.handler.HandleOrderRefundEvent(t.Context(), refundEvent(orderID), msgID); err == nil {
		t.Fatal("HandleOrderRefundEvent succeeded when entitlement lookup failed")
	}
	assertWebhookUncommitted(t, s.db, msgID)
	assertNoRevocations(t, s.db)
}

func TestHandleOrderEvent_OneTimeRetryWithoutIssuanceRefuses(t *testing.T) {
	s := newTestSetup(t)
	const orderID = "order_enterprise_trial_retry_missing"
	now := time.Now().UTC()
	ent := &Entitlement{
		SubscriptionID: orderID, CustomerEmail: "enterprise-trial@example.com", ProductID: "prod_enterprise_trial_free",
		Tier: tierEnterpriseTrial, BillingInterval: billingIntervalOneTime, Status: statusActive, CurrentPeriodEnd: now.Add(enterpriseTrialTokenLifetime),
		LastLicensePeriodEnd: &now, LastLicenseTier: tierEnterpriseTrial, LastLicenseInterval: billingIntervalOneTime,
		LastLicenseProductID: "prod_enterprise_trial_free", LastDeliveryStatus: "failed",
	}
	// Match the order's period end so this is an idempotent retry, but leave
	// issuance fields empty to prove it refuses rather than minting.
	ent.CurrentPeriodEnd = now.Add(enterpriseTrialTokenLifetime)
	ent.LastLicensePeriodEnd = &ent.CurrentPeriodEnd
	if err := s.db.Upsert(t.Context(), ent); err != nil {
		t.Fatalf("seed entitlement: %v", err)
	}
	err := s.handler.HandleOrderEvent(t.Context(), enterpriseTrialOrderEvent(t, orderID))
	if err == nil || !strings.Contains(err.Error(), "no persisted issuance") {
		t.Fatalf("retry error = %v, want persisted-issuance refusal", err)
	}
	after, err := s.db.GetBySubscriptionID(t.Context(), orderID)
	if err != nil || after == nil || after.Status != statusActive || after.LastLicenseID != "" {
		t.Fatalf("entitlement changed after refused retry = %+v, %v", after, err)
	}
	assertNoRevocations(t, s.db)
}

func seedRefundEvalOrder(t *testing.T, s *evalTestSetup) {
	t.Helper()
	if err := s.db.UpsertEvalOrder(t.Context(), &EvalOrder{OrderID: testEvalOrderID, NormalizedEmail: testEvalEmail, ProductID: testEvalProductID, FulfillmentState: fulfillmentMinted, LicenseID: "lic_eval_refund"}); err != nil {
		t.Fatalf("seed eval order: %v", err)
	}
}

func seedRefundIssuance(t *testing.T, db *EntitlementDB, orderID string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.UpsertWithLicenseIssuance(t.Context(), &Entitlement{SubscriptionID: orderID, CustomerEmail: "buyer@example.com", ProductID: "prod_seed", Tier: tierEnterpriseTrial, BillingInterval: billingIntervalOneTime, Status: statusActive, CurrentPeriodEnd: now.Add(time.Hour)}, LicenseIssuance{LicenseID: "lic_" + orderID, SubscriptionID: orderID, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("seed issuance: %v", err)
	}
}

func seedOneTimeTrial(t *testing.T, db *EntitlementDB, orderID string, withIssuance bool) {
	t.Helper()
	now := time.Now().UTC()
	ent := &Entitlement{SubscriptionID: orderID, CustomerEmail: "enterprise-trial@example.com", ProductID: "prod_enterprise_trial_free", Tier: tierEnterpriseTrial, BillingInterval: billingIntervalOneTime, Status: statusActive, CurrentPeriodEnd: now.Add(time.Hour)}
	if !withIssuance {
		if err := db.Upsert(t.Context(), ent); err != nil {
			t.Fatalf("seed trial entitlement: %v", err)
		}
		return
	}
	if err := db.UpsertWithLicenseIssuance(t.Context(), ent, LicenseIssuance{LicenseID: "lic_" + orderID, SubscriptionID: orderID, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("seed trial issuance: %v", err)
	}
}

func refundEvent(orderID string) *PolarWebhookEvent {
	return &PolarWebhookEvent{Type: EventOrderRefunded, Data: []byte(fmt.Sprintf(`{"id":%q}`, orderID))}
}

func createFaultTrigger(t *testing.T, db *EntitlementDB, name string) {
	t.Helper()
	queries := map[string]string{
		"fail_eval_revocation":  "CREATE TRIGGER fail_eval_revocation BEFORE INSERT ON license_revocations BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END",
		"fail_eval_upsert":      "CREATE TRIGGER fail_eval_upsert BEFORE UPDATE ON eval_orders BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END",
		"fail_eval_commit":      "CREATE TRIGGER fail_eval_commit BEFORE INSERT ON webhook_deliveries BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END",
		"fail_trial_revocation": "CREATE TRIGGER fail_trial_revocation BEFORE INSERT ON license_revocations BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END",
		"fail_trial_upsert":     "CREATE TRIGGER fail_trial_upsert BEFORE UPDATE ON entitlements BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END",
		"fail_trial_commit":     "CREATE TRIGGER fail_trial_commit BEFORE INSERT ON webhook_deliveries BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END",
	}
	query, ok := queries[name]
	if !ok {
		t.Fatalf("unknown fault trigger %q", name)
	}
	if _, err := db.db.ExecContext(t.Context(), query); err != nil {
		t.Fatalf("create fault trigger: %v", err)
	}
}

func renameTable(t *testing.T, db *EntitlementDB, from, to string) {
	t.Helper()
	queries := map[string]string{
		"license_issuances/license_issuances_fault": "ALTER TABLE license_issuances RENAME TO license_issuances_fault",
		"entitlements/entitlements_fault":           "ALTER TABLE entitlements RENAME TO entitlements_fault",
	}
	query, ok := queries[from+"/"+to]
	if !ok {
		t.Fatalf("unknown rename %s to %s", from, to)
	}
	if _, err := db.db.ExecContext(t.Context(), query); err != nil {
		t.Fatalf("rename %s: %v", from, err)
	}
}

func assertWebhookUncommitted(t *testing.T, db *EntitlementDB, msgID string) {
	t.Helper()
	committed, err := db.WebhookCommitted(t.Context(), msgID)
	if err != nil || committed {
		t.Fatalf("webhook committed = %t, %v; want false", committed, err)
	}
}

func assertNoRevocations(t *testing.T, db *EntitlementDB) {
	t.Helper()
	got, err := db.ListLicenseRevocations(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("revocations = %+v, %v; want none", got, err)
	}
}

func assertEvalRefundUnchanged(t *testing.T, db *EntitlementDB) {
	t.Helper()
	got, err := db.GetEvalOrder(t.Context(), testEvalOrderID)
	if err != nil || got == nil || got.FulfillmentState != fulfillmentMinted || got.RevocationState != revocationNone {
		t.Fatalf("eval order after failed refund = %+v, %v; want minted/unrevoked", got, err)
	}
}

func assertEvalRefundRecorded(t *testing.T, db *EntitlementDB) {
	t.Helper()
	got, err := db.GetEvalOrder(t.Context(), testEvalOrderID)
	if err != nil || got == nil || got.FulfillmentState != fulfillmentRevoked || got.RevocationState != revocationPendingNoLicense {
		t.Fatalf("eval order after failed commit marker = %+v, %v; want revoked/pending", got, err)
	}
}
