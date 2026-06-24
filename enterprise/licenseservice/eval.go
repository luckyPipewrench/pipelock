//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// Polar order status values consumed by eval fulfillment.
const (
	orderStatusPaid              = "paid"
	orderStatusRefunded          = "refunded"
	orderStatusPartiallyRefunded = "partially_refunded"
)

// Eval gate-denial reasons (recorded in the ledger + eval_orders, never returned
// verbatim to the caller).
const (
	denyReasonUnpaid             = "unpaid"
	denyReasonNotPurchase        = "not_purchase"
	denyReasonNotEvalTier        = "not_eval_tier"
	denyReasonProductNotAllowed  = "product_not_allowlisted"
	denyReasonCurrencyMismatch   = "currency_mismatch"
	denyReasonAmountMismatch     = "amount_mismatch"
	denyReasonRefunded           = "refunded"
	denyReasonInvalidEmail       = "invalid_email"
	denyReasonRefundedBeforePaid = "refunded_before_paid"
	denyReasonActiveEvalExists   = "active_eval_exists"
)

const deliveryStatusPending = "pending"

// HandleOrderPaidEvent fulfills (or refuses) an Enterprise Eval purchase on a
// Polar order.paid delivery. It is fail-closed: it mints only after re-fetching
// the order from Polar and validating paid state, product allowlist, tier,
// amount, currency, and refund state, and only when no conflicting eval-order or
// active eval exists. The mint is atomic; email is a post-commit side effect that
// resends the SAME token on retry (never re-mints, never restarts the clock).
func (h *WebhookHandler) HandleOrderPaidEvent(ctx context.Context, event *PolarWebhookEvent, msgID string) error {
	order0, err := extractOrderData(event.Data)
	if err != nil {
		return fmt.Errorf("extract order data: %w", err)
	}
	_ = h.ledger.LogWebhookReceived(event.Type, order0.ID)

	h.processMu.Lock()
	defer h.processMu.Unlock()

	// Dedupe: if this delivery's business state already committed, do not
	// re-mint. Resend the token if the prior email never landed.
	committed, err := h.db.WebhookCommitted(ctx, msgID)
	if err != nil {
		return fmt.Errorf("check webhook delivery: %w", err)
	}
	if committed {
		return h.resendEvalIfNeeded(ctx, order0.ID)
	}

	// Re-fetch the order from Polar (source of truth; webhook body is not trusted).
	order, err := h.polar.GetOrder(ctx, order0.ID)
	if err != nil {
		_ = h.ledger.LogError(order0.ID, "fetch order from polar", err)
		return fmt.Errorf("fetch order from polar: %w", err)
	}

	if reason := h.evalOrderDenialReason(order); reason != "" {
		return h.denyEvalOrder(ctx, order, msgID, reason)
	}

	email, err := NormalizeEmail(order.Customer.Email)
	if err != nil {
		return h.denyEvalOrder(ctx, order, msgID, denyReasonInvalidEmail)
	}

	existing, err := h.db.GetEvalOrder(ctx, order.ID)
	if err != nil {
		return fmt.Errorf("load eval order: %w", err)
	}
	if existing != nil {
		if existing.FulfillmentState == fulfillmentMinted {
			// Already minted (e.g. dedupe row missing after a crash). Mark this
			// delivery committed and resend if needed; never mint twice.
			if markErr := h.db.MarkWebhookCommitted(ctx, msgID, event.Type, order.ID); markErr != nil {
				return fmt.Errorf("mark webhook committed: %w", markErr)
			}
			return h.resendEvalIfNeeded(ctx, order.ID)
		}
		if existing.RefundState != refundStateNone || existing.RevocationState != revocationNone {
			// Refund arrived before paid: refuse to mint a refunded order.
			return h.denyEvalOrder(ctx, order, msgID, denyReasonRefundedBeforePaid)
		}
	}

	// One active eval per normalized email.
	active, err := h.db.CountActiveEvalForEmail(ctx, email, time.Now())
	if err != nil {
		return fmt.Errorf("count active eval: %w", err)
	}
	if active > 0 {
		return h.denyEvalOrder(ctx, order, msgID, denyReasonActiveEvalExists)
	}

	// Build the license, entitlement, and issuance.
	now := time.Now()
	expiresAt := now.Add(evalTokenLifetime)
	idBytes := make([]byte, 6) // 12 hex chars
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("generate license ID: %w", err)
	}
	org := order.Customer.Metadata["org"]
	lic := license.License{
		ID:             "lic_" + hex.EncodeToString(idBytes),
		Email:          email,
		Org:            org,
		IssuedAt:       now.Unix(),
		ExpiresAt:      expiresAt.Unix(),
		Features:       h.tierToFeatures(tierEnterpriseEval),
		Tier:           tierEnterpriseEval,
		SubscriptionID: order.ID,
	}
	token, err := license.Issue(lic, h.privateKey)
	if err != nil {
		_ = h.ledger.LogError(order.ID, "issue eval license token", err)
		return fmt.Errorf("issue eval license: %w", err)
	}

	features, err := json.Marshal(lic.Features)
	if err != nil {
		return fmt.Errorf("marshal features: %w", err)
	}
	issuedAt := now
	ent := &Entitlement{
		SubscriptionID:        order.ID,
		CustomerEmail:         email,
		ProductID:             order.Product.ID,
		Tier:                  tierEnterpriseEval,
		BillingInterval:       billingIntervalOneTime, // one-time → cron never refreshes it
		Status:                statusActive,
		CurrentPeriodEnd:      expiresAt,
		Org:                   org,
		Features:              string(features),
		LastLicenseID:         lic.ID,
		LastLicenseIssuedAt:   &issuedAt,
		LastLicenseExpiresAt:  &expiresAt,
		LastLicensePeriodEnd:  &expiresAt,
		LastLicenseTier:       tierEnterpriseEval,
		LastLicenseInterval:   billingIntervalOneTime,
		LastLicenseProductID:  order.Product.ID,
		LastDeliveryStatus:    deliveryStatusPending,
		LastDeliveryAttemptAt: &issuedAt,
		NextRefreshAt:         nil,
	}
	evalOrder := &EvalOrder{
		OrderID:          order.ID,
		NormalizedEmail:  email,
		ProductID:        order.Product.ID,
		TotalAmount:      order.TotalAmount,
		RefundedAmount:   order.RefundedAmount,
		Currency:         order.Currency,
		PolarPaid:        true,
		RefundState:      refundStateNone,
		FulfillmentState: fulfillmentMinted,
		RevocationState:  revocationNone,
		LicenseID:        lic.ID,
	}

	// Atomic: re-check + entitlement + issuance + eval-order + webhook-committed.
	if err := h.db.FulfillEvalMint(ctx, EvalMintParams{
		Entitlement:  ent,
		Issuance:     LicenseIssuance{LicenseID: lic.ID, SubscriptionID: order.ID, ExpiresAt: expiresAt, IssuedAt: now},
		EvalOrder:    evalOrder,
		WebhookMsgID: msgID,
		EventType:    event.Type,
	}); err != nil {
		if errors.Is(err, ErrEvalOrderNotMintable) {
			h.log.Warn().Str("order_id", order.ID).Msg("eval order no longer mintable at commit; skipping")
			return nil
		}
		_ = h.ledger.LogError(order.ID, "fulfill eval mint", err)
		return fmt.Errorf("fulfill eval mint: %w", err)
	}
	_ = h.ledger.Log(AuditEntry{
		Event:          AuditEvalMinted,
		SubscriptionID: order.ID,
		CustomerEmail:  email,
		LicenseID:      lic.ID,
		Tier:           tierEnterpriseEval,
		ExpiresAt:      expiresAt.UTC().Format(time.RFC3339),
	})

	return h.deliverEvalToken(ctx, ent, token)
}

// HandleOrderRefundEvent processes an order.refunded or refund-state
// order.updated delivery: it revokes every unexpired license minted for the
// order (full OR partial refund — conservative) and records the refund/revocation
// on the eval order, even when no license was minted yet (refund-before-paid).
func (h *WebhookHandler) HandleOrderRefundEvent(ctx context.Context, event *PolarWebhookEvent, msgID string) error {
	order0, err := extractOrderData(event.Data)
	if err != nil {
		return fmt.Errorf("extract order data: %w", err)
	}
	_ = h.ledger.LogWebhookReceived(event.Type, order0.ID)

	h.processMu.Lock()
	defer h.processMu.Unlock()

	committed, err := h.db.WebhookCommitted(ctx, msgID)
	if err != nil {
		return fmt.Errorf("check webhook delivery: %w", err)
	}
	if committed {
		return nil
	}

	order, err := h.polar.GetOrder(ctx, order0.ID)
	if err != nil {
		_ = h.ledger.LogError(order0.ID, "fetch order from polar", err)
		return fmt.Errorf("fetch order from polar: %w", err)
	}

	refundState := classifyRefund(order)
	if refundState == refundStateNone {
		// order.updated with no refund component: nothing to revoke.
		return h.db.MarkWebhookCommitted(ctx, msgID, event.Type, order.ID)
	}

	// Only act on eval-related orders: an existing eval-order record, a product
	// in the eval allowlist, or tier metadata explicitly marking the order as an
	// Enterprise Eval. The metadata fallback is conservative for refund-before-
	// paid races under allowlist/config drift: recording a pending revocation can
	// only block a later stale mint.
	existing, err := h.db.GetEvalOrder(ctx, order.ID)
	if err != nil {
		return fmt.Errorf("load eval order for refund: %w", err)
	}
	if existing == nil && !h.isEvalOrderCandidate(order) {
		return h.db.MarkWebhookCommitted(ctx, msgID, event.Type, order.ID)
	}

	return h.revokeEvalForOrder(ctx, order, refundState, msgID, event.Type)
}

// revokeEvalForOrder revokes minted licenses for an order and records the refund.
// Operations are individually idempotent and the webhook is marked committed last,
// so a crash mid-revoke is safely re-processed on Polar retry.
func (h *WebhookHandler) revokeEvalForOrder(ctx context.Context, order *PolarOrder, refundState, msgID, eventType string) error {
	now := time.Now().UTC()
	existing, err := h.db.GetEvalOrder(ctx, order.ID)
	if err != nil {
		return fmt.Errorf("load eval order for revoke: %w", err)
	}

	issuances, err := h.db.ListUnexpiredLicenseIssuances(ctx, order.ID, now)
	if err != nil {
		_ = h.ledger.LogError(order.ID, "list issuances for eval revoke", err)
		return fmt.Errorf("list issuances for eval revoke: %w", err)
	}
	reason := refundRevocationReason(refundState)
	revoked := false
	for _, iss := range issuances {
		if err := h.db.UpsertLicenseRevocation(ctx, RevokedLicenseRecord{
			LicenseID:      iss.LicenseID,
			SubscriptionID: order.ID,
			Reason:         reason,
			RevokedAt:      now,
		}); err != nil {
			_ = h.ledger.LogError(order.ID, "record eval revocation", err)
			return fmt.Errorf("record eval revocation: %w", err)
		}
		revoked = true
		_ = h.ledger.Log(AuditEntry{Event: AuditEvalRefundRevoked, SubscriptionID: order.ID, LicenseID: iss.LicenseID, Detail: reason})
	}

	revocationState := revocationApplied
	if !revoked {
		// Refund before any license was minted: remember to refuse a later mint.
		revocationState = revocationPendingNoLicense
	}

	eo := &EvalOrder{
		OrderID:          order.ID,
		NormalizedEmail:  evalRecordEmail(existing, order),
		ProductID:        order.Product.ID,
		TotalAmount:      order.TotalAmount,
		RefundedAmount:   order.RefundedAmount,
		Currency:         order.Currency,
		PolarPaid:        order.Paid || (existing != nil && existing.PolarPaid),
		RefundState:      refundState,
		FulfillmentState: fulfillmentRevoked,
		RevocationState:  revocationState,
	}
	if existing != nil {
		eo.LicenseID = existing.LicenseID
	}
	if err := h.db.UpsertEvalOrder(ctx, eo); err != nil {
		return fmt.Errorf("record eval refund: %w", err)
	}
	if err := h.db.MarkWebhookCommitted(ctx, msgID, eventType, order.ID); err != nil {
		return fmt.Errorf("mark refund webhook committed: %w", err)
	}
	return nil
}

// deliverEvalToken sends the eval license email and records delivery status. On
// failure it returns an error so the caller returns 500 and Polar retries; the
// retry resends the same token via resendEvalIfNeeded (no re-mint).
func (h *WebhookHandler) deliverEvalToken(ctx context.Context, ent *Entitlement, token string) error {
	now := time.Now()
	msgID, emailErr := h.email.SendLicenseDelivery(ctx, ent.CustomerEmail, token, ent.Tier, string(h.cfg.IntermediateCert))
	if emailErr != nil {
		if err := h.db.UpdateDeliveryStatus(ctx, ent.SubscriptionID, "failed", now); err != nil {
			return fmt.Errorf("update delivery status after email failure: %w", err)
		}
		_ = h.ledger.LogEmailFailed(ent.SubscriptionID, ent.CustomerEmail, emailErr)
		return fmt.Errorf("eval email delivery failed: %w", emailErr)
	}
	if err := h.db.UpdateDeliveryStatus(ctx, ent.SubscriptionID, "sent", now); err != nil {
		return fmt.Errorf("update delivery status after email success: %w", err)
	}
	_ = h.ledger.LogEmailSent(ent.SubscriptionID, ent.CustomerEmail, msgID)
	return nil
}

// resendEvalIfNeeded resends the deterministic eval token if it was minted but
// the prior email never succeeded. It never mints and never changes expiry.
func (h *WebhookHandler) resendEvalIfNeeded(ctx context.Context, orderID string) error {
	ent, err := h.db.GetBySubscriptionID(ctx, orderID)
	if err != nil {
		return fmt.Errorf("load entitlement for resend: %w", err)
	}
	if ent == nil || ent.Tier != tierEnterpriseEval || ent.LastLicenseID == "" {
		return nil // nothing minted to resend (e.g. a denied order)
	}
	if ent.LastDeliveryStatus == "sent" {
		return nil
	}
	return h.deliverEvalToken(ctx, ent, h.regenerateEvalToken(ent))
}

// regenerateEvalToken rebuilds the exact token from persisted claims. license.Issue
// is deterministic for identical claims + key, so the regenerated token is
// byte-identical to the original — enabling resend without re-minting.
func (h *WebhookHandler) regenerateEvalToken(ent *Entitlement) string {
	lic := license.License{
		ID:             ent.LastLicenseID,
		Email:          ent.CustomerEmail,
		Org:            ent.Org,
		Features:       h.tierToFeatures(ent.LastLicenseTier),
		Tier:           ent.LastLicenseTier,
		SubscriptionID: ent.SubscriptionID,
	}
	if ent.LastLicenseIssuedAt != nil {
		lic.IssuedAt = ent.LastLicenseIssuedAt.Unix()
	}
	if ent.LastLicenseExpiresAt != nil {
		lic.ExpiresAt = ent.LastLicenseExpiresAt.Unix()
	}
	token, _ := license.Issue(lic, h.privateKey)
	return token
}

// denyEvalOrder records a refused eval order (gated_denied) without minting,
// marks the delivery committed so Polar stops retrying, and audits the reason.
// The external result is a benign success (no token); the reason stays internal.
func (h *WebhookHandler) denyEvalOrder(ctx context.Context, order *PolarOrder, msgID, reason string) error {
	eo := &EvalOrder{
		OrderID:          order.ID,
		NormalizedEmail:  evalRecordEmail(nil, order),
		ProductID:        order.Product.ID,
		TotalAmount:      order.TotalAmount,
		RefundedAmount:   order.RefundedAmount,
		Currency:         order.Currency,
		PolarPaid:        order.Paid,
		RefundState:      classifyRefund(order),
		FulfillmentState: fulfillmentGatedDenied,
		RevocationState:  revocationNone,
		GateDenialReason: reason,
	}
	if err := h.db.UpsertEvalOrder(ctx, eo); err != nil {
		// Recording the denial is best-effort; still mark committed + audit.
		h.log.Error().Err(err).Str("order_id", order.ID).Msg("record denied eval order")
	}
	if err := h.db.MarkWebhookCommitted(ctx, msgID, EventOrderPaid, order.ID); err != nil {
		return fmt.Errorf("mark denied webhook committed: %w", err)
	}
	_ = h.ledger.Log(AuditEntry{
		Event:          AuditEvalRejected,
		SubscriptionID: order.ID,
		CustomerEmail:  order.Customer.Email,
		Detail:         reason,
	})
	h.log.Warn().Str("order_id", order.ID).Str("reason", reason).Msg("eval order denied")
	return nil
}

// evalOrderDenialReason returns "" if the order is a fulfillable eval purchase,
// or a denial reason. Fail-closed: any failed check denies.
func (h *WebhookHandler) evalOrderDenialReason(order *PolarOrder) string {
	if !order.Paid {
		return denyReasonUnpaid
	}
	if order.BillingReason != "purchase" {
		return denyReasonNotPurchase
	}
	if order.Product.Metadata["pipelock_tier"] != tierEnterpriseEval {
		return denyReasonNotEvalTier
	}
	if !h.isEvalProduct(order.Product.ID) {
		return denyReasonProductNotAllowed
	}
	if order.Currency != h.cfg.EvalCurrency {
		return denyReasonCurrencyMismatch
	}
	// Compare the tax-EXCLUSIVE net amount, not the gross total. Polar is the
	// merchant of record and adds sales tax/VAT on top of the price, so
	// total_amount varies by buyer jurisdiction while net_amount equals the
	// configured product price for every buyer. Comparing total_amount rejected
	// any taxed purchase (e.g. $5000 + tax > 500000) and never minted a token.
	if order.NetAmount != h.cfg.EvalAmountCents {
		return denyReasonAmountMismatch
	}
	if classifyRefund(order) != refundStateNone {
		return denyReasonRefunded
	}
	return ""
}

func (h *WebhookHandler) isEvalProduct(productID string) bool {
	for _, id := range h.cfg.EvalProductIDs {
		if id == productID {
			return true
		}
	}
	return false
}

func (h *WebhookHandler) isEvalOrderCandidate(order *PolarOrder) bool {
	return h.isEvalProduct(order.Product.ID) || order.Product.Metadata["pipelock_tier"] == tierEnterpriseEval
}

// classifyRefund maps a Polar order's refund fields to a refund state.
func classifyRefund(order *PolarOrder) string {
	if order.Status == orderStatusRefunded || (order.TotalAmount > 0 && order.RefundedAmount >= order.TotalAmount) {
		return refundStateFull
	}
	if order.Status == orderStatusPartiallyRefunded || order.RefundedAmount > 0 {
		return refundStatePartial
	}
	return refundStateNone
}

func refundRevocationReason(refundState string) string {
	if refundState == refundStatePartial {
		return "order_partially_refunded"
	}
	return "order_refunded"
}

// evalRecordEmail picks a non-empty email for an eval_orders record (normalized
// when possible), since normalized_email is NOT NULL. Used for audit/denial rows
// where strict identity matching is not required.
func evalRecordEmail(existing *EvalOrder, order *PolarOrder) string {
	if existing != nil && existing.NormalizedEmail != "" {
		return existing.NormalizedEmail
	}
	if n, err := NormalizeEmail(order.Customer.Email); err == nil {
		return n
	}
	return "unknown"
}
