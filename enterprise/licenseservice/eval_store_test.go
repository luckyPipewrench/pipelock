//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"testing"
)

func TestEntitlementDB_EvalOrderUpsertAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	// Not found returns nil, nil.
	got, err := db.GetEvalOrder(ctx, "order_missing")
	if err != nil {
		t.Fatalf("GetEvalOrder(missing): %v", err)
	}
	if got != nil {
		t.Fatalf("GetEvalOrder(missing) = %+v, want nil", got)
	}

	eo := &EvalOrder{
		OrderID:          "order_1",
		NormalizedEmail:  "buyer@example.com",
		ProductID:        "prod_eval",
		TotalAmount:      500000,
		RefundedAmount:   0,
		Currency:         "usd",
		PolarPaid:        true,
		RefundState:      refundStateNone,
		FulfillmentState: fulfillmentMinted,
		RevocationState:  revocationNone,
		LicenseID:        "lic_abc",
	}
	if err := db.UpsertEvalOrder(ctx, eo); err != nil {
		t.Fatalf("UpsertEvalOrder: %v", err)
	}

	got, err = db.GetEvalOrder(ctx, "order_1")
	if err != nil {
		t.Fatalf("GetEvalOrder: %v", err)
	}
	if got == nil {
		t.Fatal("GetEvalOrder returned nil after upsert")
	}
	if got.NormalizedEmail != "buyer@example.com" || got.FulfillmentState != fulfillmentMinted ||
		got.LicenseID != "lic_abc" || got.TotalAmount != 500000 || !got.PolarPaid {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Update in place: transition to revoked.
	eo.FulfillmentState = fulfillmentRevoked
	eo.RevocationState = revocationApplied
	eo.RefundState = refundStateFull
	eo.RefundedAmount = 500000
	if err := db.UpsertEvalOrder(ctx, eo); err != nil {
		t.Fatalf("UpsertEvalOrder(update): %v", err)
	}
	got, err = db.GetEvalOrder(ctx, "order_1")
	if err != nil {
		t.Fatalf("GetEvalOrder(after update): %v", err)
	}
	if got.FulfillmentState != fulfillmentRevoked || got.RevocationState != revocationApplied ||
		got.RefundState != refundStateFull || got.RefundedAmount != 500000 {
		t.Errorf("update not persisted: %+v", got)
	}
}

func TestEntitlementDB_EvalOrderRefundBeforePaidBlocksStaleMintState(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	const orderID = "order_refund_before_paid"
	refundFirst := &EvalOrder{
		OrderID:          orderID,
		NormalizedEmail:  "buyer@example.com",
		ProductID:        "prod_eval",
		TotalAmount:      500000,
		RefundedAmount:   500000,
		Currency:         "usd",
		PolarPaid:        false,
		RefundState:      refundStateFull,
		FulfillmentState: fulfillmentNone,
		RevocationState:  revocationPendingNoLicense,
	}
	if err := db.UpsertEvalOrder(ctx, refundFirst); err != nil {
		t.Fatalf("UpsertEvalOrder(refund first): %v", err)
	}

	stalePaidMint := &EvalOrder{
		OrderID:          orderID,
		NormalizedEmail:  "buyer@example.com",
		ProductID:        "prod_eval",
		TotalAmount:      500000,
		RefundedAmount:   0,
		Currency:         "usd",
		PolarPaid:        true,
		RefundState:      refundStateNone,
		FulfillmentState: fulfillmentMinted,
		RevocationState:  revocationNone,
		LicenseID:        "lic_should_not_land",
	}
	if err := db.UpsertEvalOrder(ctx, stalePaidMint); err != nil {
		t.Fatalf("UpsertEvalOrder(stale paid mint): %v", err)
	}

	got, err := db.GetEvalOrder(ctx, orderID)
	if err != nil {
		t.Fatalf("GetEvalOrder: %v", err)
	}
	if got == nil {
		t.Fatal("eval order missing")
	}
	if got.RefundState != refundStateFull {
		t.Errorf("RefundState = %q, want %q", got.RefundState, refundStateFull)
	}
	if got.RefundedAmount != 500000 {
		t.Errorf("RefundedAmount = %d, want 500000", got.RefundedAmount)
	}
	if !got.PolarPaid {
		t.Error("PolarPaid should remain true once a paid event is observed")
	}
	if got.FulfillmentState != fulfillmentNone {
		t.Errorf("FulfillmentState = %q, want %q", got.FulfillmentState, fulfillmentNone)
	}
	if got.RevocationState != revocationPendingNoLicense {
		t.Errorf("RevocationState = %q, want %q", got.RevocationState, revocationPendingNoLicense)
	}
	if got.LicenseID != "" {
		t.Errorf("LicenseID = %q, want empty because refund-before-paid blocks stale mint state", got.LicenseID)
	}
}

func TestEntitlementDB_EvalOrderDefaultsAndValidation(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	eo := &EvalOrder{
		OrderID:         "order_defaults",
		NormalizedEmail: "buyer@example.com",
	}
	if err := db.UpsertEvalOrder(ctx, eo); err != nil {
		t.Fatalf("UpsertEvalOrder(defaults): %v", err)
	}
	got, err := db.GetEvalOrder(ctx, "order_defaults")
	if err != nil {
		t.Fatalf("GetEvalOrder(defaults): %v", err)
	}
	if got.RefundState != refundStateNone || got.FulfillmentState != fulfillmentNone ||
		got.RevocationState != revocationNone {
		t.Fatalf("defaults not applied: %+v", got)
	}

	if err := db.UpsertEvalOrder(ctx, &EvalOrder{OrderID: "order_no_email"}); err == nil {
		t.Fatal("expected error for missing normalized email")
	}
	if err := db.UpsertEvalOrder(ctx, &EvalOrder{
		OrderID:          "order_bad_state",
		NormalizedEmail:  "buyer@example.com",
		FulfillmentState: "minted_by_accident",
	}); err == nil {
		t.Fatal("expected error for invalid fulfillment state")
	}
}

func TestEntitlementDB_WebhookDeliveryDedupe(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	// Unknown delivery is not committed.
	committed, err := db.WebhookCommitted(ctx, "msg_1")
	if err != nil {
		t.Fatalf("WebhookCommitted(unknown): %v", err)
	}
	if committed {
		t.Fatal("unknown delivery reported committed")
	}

	if err := db.MarkWebhookCommitted(ctx, "msg_1", "order.paid", "order_1"); err != nil {
		t.Fatalf("MarkWebhookCommitted: %v", err)
	}

	committed, err = db.WebhookCommitted(ctx, "msg_1")
	if err != nil {
		t.Fatalf("WebhookCommitted: %v", err)
	}
	if !committed {
		t.Fatal("committed delivery reported not committed")
	}

	// Marking again is idempotent (no error, still committed).
	if err := db.MarkWebhookCommitted(ctx, "msg_1", "order.paid", "order_1"); err != nil {
		t.Fatalf("MarkWebhookCommitted(repeat): %v", err)
	}
	committed, err = db.WebhookCommitted(ctx, "msg_1")
	if err != nil {
		t.Fatalf("WebhookCommitted(after repeat): %v", err)
	}
	if !committed {
		t.Fatal("delivery not committed after repeat mark")
	}
}
