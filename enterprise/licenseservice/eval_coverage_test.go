//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// mintParams builds a valid EvalMintParams for order o / email e.
func mintParams(orderID, email string) EvalMintParams {
	exp := time.Now().Add(evalTokenLifetime)
	return EvalMintParams{
		Entitlement: &Entitlement{
			SubscriptionID:   orderID,
			CustomerEmail:    email,
			Tier:             tierEnterpriseEval,
			BillingInterval:  billingIntervalOneTime,
			Status:           statusActive,
			CurrentPeriodEnd: exp,
		},
		Issuance:     LicenseIssuance{LicenseID: "lic_" + orderID, SubscriptionID: orderID, ExpiresAt: exp, IssuedAt: time.Now()},
		EvalOrder:    &EvalOrder{OrderID: orderID, NormalizedEmail: email, FulfillmentState: fulfillmentMinted, RevocationState: revocationNone, RefundState: refundStateNone, LicenseID: "lic_" + orderID},
		WebhookMsgID: "msg_" + orderID,
		EventType:    EventOrderPaid,
	}
}

func TestFulfillEvalMint_RefusesNonMintableStates(t *testing.T) {
	tests := []struct {
		name string
		seed *EvalOrder
	}{
		{"already minted", &EvalOrder{OrderID: "o", NormalizedEmail: "a@b.com", FulfillmentState: fulfillmentMinted, LicenseID: "lic_prev"}},
		{"already refunded", &EvalOrder{OrderID: "o", NormalizedEmail: "a@b.com", RefundState: refundStateFull, FulfillmentState: fulfillmentRevoked, RevocationState: revocationApplied}},
		{"revocation pending", &EvalOrder{OrderID: "o", NormalizedEmail: "a@b.com", RevocationState: revocationPendingNoLicense, FulfillmentState: fulfillmentRevoked}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestDB(t)
			ctx := t.Context()
			if err := db.UpsertEvalOrder(ctx, tt.seed); err != nil {
				t.Fatalf("seed: %v", err)
			}
			err := db.FulfillEvalMint(ctx, mintParams("o", "a@b.com"))
			if !errors.Is(err, ErrEvalOrderNotMintable) {
				t.Fatalf("err = %v, want ErrEvalOrderNotMintable", err)
			}
			ent, _ := db.GetBySubscriptionID(ctx, "o")
			if ent != nil {
				t.Errorf("entitlement created despite non-mintable state: %+v", ent)
			}
		})
	}
}

func TestFulfillEvalMint_CommitsAtomically(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	if err := db.FulfillEvalMint(ctx, mintParams("o", "a@b.com")); err != nil {
		t.Fatalf("FulfillEvalMint: %v", err)
	}
	ent, _ := db.GetBySubscriptionID(ctx, "o")
	if ent == nil || ent.Tier != tierEnterpriseEval {
		t.Fatalf("entitlement not committed: %+v", ent)
	}
	committed, _ := db.WebhookCommitted(ctx, "msg_o")
	if !committed {
		t.Error("webhook not marked committed in mint tx")
	}
	eo, _ := db.GetEvalOrder(ctx, "o")
	if eo == nil || eo.FulfillmentState != fulfillmentMinted {
		t.Errorf("eval order not minted: %+v", eo)
	}
}

func TestFulfillEvalMint_RejectsIncompleteParams(t *testing.T) {
	db := openTestDB(t)
	if err := db.FulfillEvalMint(t.Context(), EvalMintParams{}); err == nil {
		t.Error("expected error for incomplete params")
	}
}

func TestValidateEvalOrderStates_RejectsInvalid(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	bad := []*EvalOrder{
		{OrderID: "r", NormalizedEmail: "a@b.com", RefundState: "weird"},
		{OrderID: "v", NormalizedEmail: "a@b.com", RevocationState: "weird"},
	}
	for _, eo := range bad {
		if err := db.UpsertEvalOrder(ctx, eo); err == nil {
			t.Errorf("expected validation error for %+v", eo)
		}
	}
}

func TestResendEvalIfNeeded_NoopWhenAlreadySent(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if s.emailHits.Load() != 1 {
		t.Fatalf("email hits after mint = %d, want 1", s.emailHits.Load())
	}
	// Delivery already succeeded → resend path must not send again.
	if err := s.handler.resendEvalIfNeeded(ctx, testEvalOrderID); err != nil {
		t.Fatalf("resend: %v", err)
	}
	if s.emailHits.Load() != 1 {
		t.Errorf("email hits after resend = %d, want 1 (already sent)", s.emailHits.Load())
	}
}

func TestResendEvalIfNeeded_NoopForUnknownOrder(t *testing.T) {
	s := newEvalTestSetup(t)
	if err := s.handler.resendEvalIfNeeded(t.Context(), "order_does_not_exist"); err != nil {
		t.Errorf("resend for unknown order should be a no-op, got %v", err)
	}
	if s.emailHits.Load() != 0 {
		t.Errorf("email hits = %d, want 0", s.emailHits.Load())
	}
}

func TestHandleOrderPaid_InvalidEmailDenied(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	body := strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), testEvalEmail, "not-an-email")
	s.orderJSON.Store(&body)
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("should not hard-error on invalid email: %v", err)
	}
	ent, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if ent != nil {
		t.Errorf("minted despite invalid email: %+v", ent)
	}
	eo, _ := s.db.GetEvalOrder(ctx, testEvalOrderID)
	if eo == nil || eo.FulfillmentState != fulfillmentGatedDenied {
		t.Errorf("eval order = %+v, want gated_denied", eo)
	}
}

func TestHandleOrderRefund_BeforePaidRecordsPending(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	refundBody := defaultEvalOrderJSON(orderStatusRefunded)
	s.orderJSON.Store(&refundBody)
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_refund"); err != nil {
		t.Fatalf("refund: %v", err)
	}
	eo, _ := s.db.GetEvalOrder(ctx, testEvalOrderID)
	if eo == nil {
		t.Fatal("eval order not recorded on refund-before-paid")
	}
	if eo.RevocationState != revocationPendingNoLicense || eo.FulfillmentState != fulfillmentRevoked {
		t.Errorf("eval order = %+v, want revoked/pending_no_license", eo)
	}
}

func TestHandleOrderRefund_NonEvalOrderIgnored(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	// Refunded order whose product is not in the eval allowlist.
	body := strings.ReplaceAll(defaultEvalOrderJSON(orderStatusRefunded), testEvalProductID, "prod_other")
	body = strings.ReplaceAll(body, `"pipelock_tier": "enterprise_eval"`, `"pipelock_tier": "pro"`)
	s.orderJSON.Store(&body)
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_refund"); err != nil {
		t.Fatalf("refund: %v", err)
	}
	eo, _ := s.db.GetEvalOrder(ctx, testEvalOrderID)
	if eo != nil {
		t.Errorf("non-eval refunded order should not create an eval_order record: %+v", eo)
	}
	committed, _ := s.db.WebhookCommitted(ctx, "msg_refund")
	if !committed {
		t.Error("non-eval refund webhook should still be marked committed")
	}
}

func TestHandleOrderRefund_MetadataEvalRecordsPendingEvenWhenUnallowlisted(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()

	body := strings.ReplaceAll(defaultEvalOrderJSON(orderStatusRefunded), testEvalProductID, "prod_other")
	s.orderJSON.Store(&body)
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_refund"); err != nil {
		t.Fatalf("refund: %v", err)
	}

	eo, _ := s.db.GetEvalOrder(ctx, testEvalOrderID)
	if eo == nil {
		t.Fatal("metadata-marked eval refund should record a pending eval_order")
	}
	if eo.RevocationState != revocationPendingNoLicense {
		t.Errorf("RevocationState = %q, want %q", eo.RevocationState, revocationPendingNoLicense)
	}

	paid := strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), testEvalProductID, "prod_other")
	s.orderJSON.Store(&paid)
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_paid"); err != nil {
		t.Fatalf("paid after refund: %v", err)
	}
	ent, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if ent != nil {
		t.Errorf("minted after metadata-marked refund-before-paid: %+v", ent)
	}
}

func TestHandleOrderRefund_NoRefundComponentMarksCommitted(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	// order.updated with no refund: paid body, no refund.
	if err := s.handler.HandleOrderRefundEvent(ctx, &PolarWebhookEvent{Type: EventOrderUpdated, Data: evalPaidEvent().Data}, "msg_upd"); err != nil {
		t.Fatalf("updated: %v", err)
	}
	committed, _ := s.db.WebhookCommitted(ctx, "msg_upd")
	if !committed {
		t.Error("no-refund order.updated should be marked committed")
	}
}

// TestHandleOrderPaid_AlreadyMintedNewDeliveryResends covers the crash-recovery
// branch: an order was minted, but a *new* delivery id arrives (the prior
// dedupe marker was lost). It must not mint again — it marks the new delivery
// committed and resends only if the email never landed.
func TestHandleOrderPaid_AlreadyMintedNewDeliveryResends(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("mint: %v", err)
	}
	first, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)

	// New delivery id for the same already-minted order.
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_2"); err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	second, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if first.LastLicenseID != second.LastLicenseID {
		t.Errorf("re-minted on new delivery of minted order: %q -> %q", first.LastLicenseID, second.LastLicenseID)
	}
	committed, _ := s.db.WebhookCommitted(ctx, "msg_2")
	if !committed {
		t.Error("new delivery for minted order should be marked committed")
	}
}

func TestEvalStore_ClosedDBErrors(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := db.GetEvalOrder(ctx, "o"); err == nil {
		t.Error("GetEvalOrder on closed db should error")
	}
	if err := db.UpsertEvalOrder(ctx, &EvalOrder{OrderID: "o", NormalizedEmail: "a@b.com"}); err == nil {
		t.Error("UpsertEvalOrder on closed db should error")
	}
	if _, err := db.WebhookCommitted(ctx, "m"); err == nil {
		t.Error("WebhookCommitted on closed db should error")
	}
	if err := db.MarkWebhookCommitted(ctx, "m", "t", "o"); err == nil {
		t.Error("MarkWebhookCommitted on closed db should error")
	}
	if _, err := db.CountActiveEvalForEmail(ctx, "a@b.com", time.Now()); err == nil {
		t.Error("CountActiveEvalForEmail on closed db should error")
	}
	if err := db.FulfillEvalMint(ctx, mintParams("o", "a@b.com")); err == nil {
		t.Error("FulfillEvalMint on closed db should error")
	}
}

func TestHandleOrderPaid_PolarFetchFailureRetries(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	// An order body that fails to parse as an order makes GetOrder return an error.
	bad := `{not json`
	s.orderJSON.Store(&bad)
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err == nil {
		t.Error("expected error when order fetch fails (so Polar retries)")
	}
	// Same for the refund path.
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_2"); err == nil {
		t.Error("expected error when refund order fetch fails")
	}
}

func TestHandlers_ClosedDBError(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err == nil {
		t.Error("HandleOrderPaidEvent should error when the dedupe lookup fails")
	}
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_2"); err == nil {
		t.Error("HandleOrderRefundEvent should error when the dedupe lookup fails")
	}
}

func TestHandleOrderRefund_DuplicateIsNoop(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	refundBody := defaultEvalOrderJSON(orderStatusRefunded)
	s.orderJSON.Store(&refundBody)
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_refund"); err != nil {
		t.Fatalf("refund: %v", err)
	}
	// Replay same delivery id: dedupe short-circuits.
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_refund"); err != nil {
		t.Fatalf("refund replay: %v", err)
	}
}
