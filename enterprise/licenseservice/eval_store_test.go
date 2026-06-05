//go:build enterprise

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
