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
	revocationNone             = "none"
	revocationPendingNoLicense = "pending_no_license"
	revocationApplied          = "applied"
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
	if eo.NormalizedEmail == "" {
		return errors.New("eval order normalized_email is required")
	}
	defaultEvalOrderStates(eo)
	if err := validateEvalOrderStates(eo); err != nil {
		return err
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
		refunded_amount    = MAX(eval_orders.refunded_amount, excluded.refunded_amount),
		currency           = excluded.currency,
		polar_paid         = eval_orders.polar_paid OR excluded.polar_paid,
		refund_state       = CASE
			WHEN eval_orders.refund_state = 'full' OR excluded.refund_state = 'full' THEN 'full'
			WHEN eval_orders.refund_state = 'partial' OR excluded.refund_state = 'partial' THEN 'partial'
			ELSE excluded.refund_state
		END,
		fulfillment_state  = CASE
			WHEN eval_orders.fulfillment_state = 'revoked' AND excluded.fulfillment_state != 'revoked' THEN eval_orders.fulfillment_state
			WHEN eval_orders.revocation_state != 'none' AND excluded.fulfillment_state = 'minted' THEN eval_orders.fulfillment_state
			ELSE excluded.fulfillment_state
		END,
		revocation_state   = CASE
			WHEN eval_orders.revocation_state = 'applied' OR excluded.revocation_state = 'applied' THEN 'applied'
			WHEN eval_orders.revocation_state = 'pending_no_license' OR excluded.revocation_state = 'pending_no_license' THEN 'pending_no_license'
			ELSE excluded.revocation_state
		END,
		gate_denial_reason = excluded.gate_denial_reason,
		license_id         = CASE
			WHEN eval_orders.revocation_state != 'none' AND excluded.fulfillment_state = 'minted' THEN eval_orders.license_id
			WHEN eval_orders.fulfillment_state = 'revoked' AND excluded.fulfillment_state != 'revoked' THEN eval_orders.license_id
			ELSE COALESCE(NULLIF(excluded.license_id, ''), eval_orders.license_id)
		END,
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

func defaultEvalOrderStates(eo *EvalOrder) {
	if eo.RefundState == "" {
		eo.RefundState = refundStateNone
	}
	if eo.FulfillmentState == "" {
		eo.FulfillmentState = fulfillmentNone
	}
	if eo.RevocationState == "" {
		eo.RevocationState = revocationNone
	}
}

func validateEvalOrderStates(eo *EvalOrder) error {
	switch eo.RefundState {
	case refundStateNone, refundStatePartial, refundStateFull:
	default:
		return fmt.Errorf("eval order %s has invalid refund_state %q", eo.OrderID, eo.RefundState)
	}
	switch eo.FulfillmentState {
	case fulfillmentNone, fulfillmentGatedDenied, fulfillmentMinted, fulfillmentRevoked:
	default:
		return fmt.Errorf("eval order %s has invalid fulfillment_state %q", eo.OrderID, eo.FulfillmentState)
	}
	switch eo.RevocationState {
	case revocationNone, revocationPendingNoLicense, revocationApplied:
	default:
		return fmt.Errorf("eval order %s has invalid revocation_state %q", eo.OrderID, eo.RevocationState)
	}
	return nil
}

// GetEvalOrder retrieves an eval order by Polar order ID. Returns nil, nil if
// not found.
func (e *EntitlementDB) GetEvalOrder(ctx context.Context, orderID string) (*EvalOrder, error) {
	return getEvalOrder(ctx, e.db, orderID)
}

// getEvalOrder reads an eval order using the given queryer (the DB or a
// transaction), so the mint path can re-check state inside its transaction.
func getEvalOrder(ctx context.Context, q entitlementQueryer, orderID string) (*EvalOrder, error) {
	const query = `
	SELECT order_id, normalized_email, product_id, total_amount, refunded_amount,
		currency, polar_paid, refund_state, fulfillment_state, revocation_state,
		gate_denial_reason, license_id, created_at, updated_at
	FROM eval_orders
	WHERE order_id = ?
	`
	eo := &EvalOrder{}
	err := q.QueryRowContext(ctx, query, orderID).Scan(
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

// CountActiveEvalForEmail returns the number of active, unexpired Enterprise
// Eval entitlements for a normalized email. Used to enforce one active eval per
// email at mint time.
func (e *EntitlementDB) CountActiveEvalForEmail(ctx context.Context, normalizedEmail string, now time.Time) (int, error) {
	const query = `
	SELECT COUNT(*) FROM entitlements
	WHERE tier = ? AND status = ? AND customer_email = ? AND current_period_end > ?
	`
	var count int
	err := e.db.QueryRowContext(ctx, query, tierEnterpriseEval, statusActive, normalizedEmail, now.UTC()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active eval for %s: %w", normalizedEmail, err)
	}
	return count, nil
}

// ErrEvalOrderNotMintable means the eval order's persisted state changed (refund,
// revocation, or an existing mint) between validation and the mint transaction,
// so minting must be refused.
var ErrEvalOrderNotMintable = errors.New("eval order is not mintable")

// EvalMintParams carries everything the atomic eval mint commits together.
type EvalMintParams struct {
	Entitlement  *Entitlement
	Issuance     LicenseIssuance
	EvalOrder    *EvalOrder
	WebhookMsgID string
	EventType    string
}

// FulfillEvalMint atomically commits an eval token issuance: it re-checks the
// eval order state inside the transaction (refusing if it became refunded,
// revoked, or already minted), then writes the entitlement, license issuance,
// eval-order (minted), and the webhook-committed marker as a single unit. Either
// all of it commits or none of it does, so a crash cannot leave an entitlement
// without its eval-order/dedupe record.
func (e *EntitlementDB) FulfillEvalMint(ctx context.Context, p EvalMintParams) error {
	if p.Entitlement == nil || p.EvalOrder == nil {
		return errors.New("eval mint params incomplete")
	}
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin eval mint transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	existing, err := getEvalOrder(ctx, tx, p.EvalOrder.OrderID)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.FulfillmentState == fulfillmentMinted ||
			existing.RefundState != refundStateNone ||
			existing.RevocationState != revocationNone {
			return ErrEvalOrderNotMintable
		}
	}

	if err := upsertEntitlement(ctx, tx, p.Entitlement); err != nil {
		return fmt.Errorf("upsert eval entitlement: %w", err)
	}
	if err := insertLicenseIssuance(ctx, tx, p.Issuance); err != nil {
		return fmt.Errorf("insert eval issuance: %w", err)
	}
	if err := upsertEvalOrder(ctx, tx, p.EvalOrder); err != nil {
		return fmt.Errorf("upsert eval order: %w", err)
	}
	if err := markWebhookCommitted(ctx, tx, p.WebhookMsgID, p.EventType, p.EvalOrder.OrderID); err != nil {
		return fmt.Errorf("mark eval webhook committed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit eval mint transaction: %w", err)
	}
	committed = true
	return nil
}
