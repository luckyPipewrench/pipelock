//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Eval order refund states.
const (
	refundStateNone    = "none"
	refundStatePartial = "partial"
	refundStateFull    = "full"
)

// Eval order fulfillment states.
const (
	fulfillmentNone        = "none"
	fulfillmentGatedDenied = "gated_denied"
	fulfillmentMinted      = "minted"
	fulfillmentRevoked     = "revoked"
)

// Eval order revocation states.
const (
	revocationNone           = "none"
	revocationPendingNoLicen = "pending_no_license"
	revocationApplied        = "applied"
)

// EvalOrder tracks the fulfillment + refund lifecycle of a one-time Enterprise
// Eval purchase, keyed by the Polar order ID. It exists separately from
// entitlements so a refund that arrives BEFORE the paid event (out-of-order
// webhook delivery) is still recorded and can block a later mint, and so a
// later mint can be refused when the order is already revoked.
type EvalOrder struct {
	OrderID          string
	NormalizedEmail  string
	ProductID        string
	TotalAmount      int
	RefundedAmount   int
	Currency         string
	PolarPaid        bool
	RefundState      string // refundState*
	FulfillmentState string // fulfillment*
	RevocationState  string // revocation*
	GateDenialReason string // populated when FulfillmentState == fulfillmentGatedDenied
	LicenseID        string // populated when FulfillmentState == fulfillmentMinted
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// UpsertEvalOrder inserts or updates an eval-order record outside a transaction.
func (e *EntitlementDB) UpsertEvalOrder(ctx context.Context, eo *EvalOrder) error {
	return upsertEvalOrder(ctx, e.db, eo)
}

// upsertEvalOrder inserts or updates an eval-order record using the given execer
// (the DB or a transaction), so the eval fulfillment path can write it atomically
// alongside the entitlement and issuance.
func upsertEvalOrder(ctx context.Context, exec entitlementExecer, eo *EvalOrder) error {
	if eo == nil {
		return errors.New("eval order is nil")
	}
	if eo.OrderID == "" {
		return errors.New("eval order order_id is required")
	}
	const query = `
	INSERT INTO eval_orders (
		order_id, normalized_email, product_id, total_amount, refunded_amount,
		currency, polar_paid, refund_state, fulfillment_state, revocation_state,
		gate_denial_reason, license_id, created_at, updated_at
	) VALUES (
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, datetime('now'), datetime('now')
	)
	ON CONFLICT(order_id) DO UPDATE SET
		normalized_email   = excluded.normalized_email,
		product_id         = excluded.product_id,
		total_amount       = excluded.total_amount,
		refunded_amount    = excluded.refunded_amount,
		currency           = excluded.currency,
		polar_paid         = excluded.polar_paid,
		refund_state       = excluded.refund_state,
		fulfillment_state  = excluded.fulfillment_state,
		revocation_state   = excluded.revocation_state,
		gate_denial_reason = excluded.gate_denial_reason,
		license_id         = COALESCE(NULLIF(excluded.license_id, ''), eval_orders.license_id),
		updated_at         = datetime('now')
	`
	//nolint:gosec // G701 false positive: const query with parameterized placeholders
	_, err := exec.ExecContext(ctx, query,
		eo.OrderID, eo.NormalizedEmail, eo.ProductID, eo.TotalAmount, eo.RefundedAmount,
		eo.Currency, eo.PolarPaid, eo.RefundState, eo.FulfillmentState, eo.RevocationState,
		eo.GateDenialReason, eo.LicenseID,
	)
	if err != nil {
		return fmt.Errorf("upsert eval order %s: %w", eo.OrderID, err)
	}
	return nil
}

// GetEvalOrder retrieves an eval order by Polar order ID. Returns nil, nil if
// not found.
func (e *EntitlementDB) GetEvalOrder(ctx context.Context, orderID string) (*EvalOrder, error) {
	const query = `
	SELECT order_id, normalized_email, product_id, total_amount, refunded_amount,
		currency, polar_paid, refund_state, fulfillment_state, revocation_state,
		gate_denial_reason, license_id, created_at, updated_at
	FROM eval_orders
	WHERE order_id = ?
	`
	eo := &EvalOrder{}
	err := e.db.QueryRowContext(ctx, query, orderID).Scan(
		&eo.OrderID, &eo.NormalizedEmail, &eo.ProductID, &eo.TotalAmount, &eo.RefundedAmount,
		&eo.Currency, &eo.PolarPaid, &eo.RefundState, &eo.FulfillmentState, &eo.RevocationState,
		&eo.GateDenialReason, &eo.LicenseID, &eo.CreatedAt, &eo.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get eval order %s: %w", orderID, err)
	}
	return eo, nil
}

// MarkWebhookCommitted records that a webhook delivery's business side effects
// have committed, keyed by the provider message ID. Idempotent: a repeat call
// for the same message ID is a no-op. "Committed" means business state landed,
// NOT that email was delivered — email retry is tracked separately.
func (e *EntitlementDB) MarkWebhookCommitted(ctx context.Context, msgID, eventType, resourceID string) error {
	return markWebhookCommitted(ctx, e.db, msgID, eventType, resourceID)
}

func markWebhookCommitted(ctx context.Context, exec entitlementExecer, msgID, eventType, resourceID string) error {
	if msgID == "" {
		return errors.New("webhook msg_id is required")
	}
	const query = `
	INSERT INTO webhook_deliveries (msg_id, event_type, resource_id, status, committed_at)
	VALUES (?, ?, ?, 'committed', datetime('now'))
	ON CONFLICT(msg_id) DO NOTHING
	`
	if _, err := exec.ExecContext(ctx, query, msgID, eventType, resourceID); err != nil {
		return fmt.Errorf("mark webhook delivery %s committed: %w", msgID, err)
	}
	return nil
}

// WebhookCommitted reports whether a webhook delivery with the given message ID
// has already committed its business side effects.
func (e *EntitlementDB) WebhookCommitted(ctx context.Context, msgID string) (bool, error) {
	const query = `SELECT 1 FROM webhook_deliveries WHERE msg_id = ? AND status = 'committed'`
	var one int
	err := e.db.QueryRowContext(ctx, query, msgID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check webhook delivery %s: %w", msgID, err)
	}
	return true, nil
}
