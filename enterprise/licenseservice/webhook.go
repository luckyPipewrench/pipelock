//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/rs/zerolog"
)

// tokenLifetime is the validity period for all issued license tokens,
// regardless of billing interval. 45 days gives enough buffer for
// monthly subscribers to receive their refresh before expiration.
const tokenLifetime = 45 * 24 * time.Hour

// refreshLeadDays is how many days before a token expires we schedule
// the next refresh. 15 days means monthly subscribers get refreshed
// at day 30 (15 days before the 45-day expiry).
const refreshLeadDays = 15

// Tier constants for Pipelock subscription levels.
const (
	tierFoundingPro = "founding_pro"
	tierPro         = "pro"
	tierEnterprise  = "enterprise"
)

// validTiers is the allowlist of accepted pipelock_tier metadata values.
// Unknown tier values are rejected to prevent misconfigured Polar products
// from silently granting paid features.
var validTiers = map[string]bool{
	tierFoundingPro: true,
	tierPro:         true,
	tierEnterprise:  true,
}

// WebhookHandler processes Polar webhook events and coordinates license
// issuance, entitlement tracking, and email delivery.
type WebhookHandler struct {
	cfg        *Config
	db         *EntitlementDB
	polar      *PolarClient
	email      *EmailSender
	ledger     *AuditLedger
	privateKey ed25519.PrivateKey
	log        zerolog.Logger

	// Founding Pro cap tracking. Loaded from DB at startup, mutex-protected.
	// Count includes all founding subscriptions ever created, including
	// canceled and refunded. Slots never reopen.
	foundingMu    sync.Mutex
	foundingCount int
}

// NewWebhookHandler creates a fully-wired webhook handler. The founding
// counter is initialized from the database at construction time.
func NewWebhookHandler(
	cfg *Config,
	db *EntitlementDB,
	polar *PolarClient,
	email *EmailSender,
	ledger *AuditLedger,
	privateKey ed25519.PrivateKey,
	log zerolog.Logger,
) (*WebhookHandler, error) {
	// Load founding count from DB to initialize the in-memory counter.
	count, err := db.CountFounding(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load founding count: %w", err)
	}

	return &WebhookHandler{
		cfg:           cfg,
		db:            db,
		polar:         polar,
		email:         email,
		ledger:        ledger,
		privateKey:    privateKey,
		log:           log,
		foundingCount: count,
	}, nil
}

// HandleEvent processes a validated Polar webhook event. This is the
// webhook entry point called after signature validation and parsing.
//
// Processing flow:
//  1. Extract subscription_id from event data
//  2. Fetch current subscription state from Polar API (source of truth)
//  3. Delegate to processSubscription for shared business logic
func (h *WebhookHandler) HandleEvent(ctx context.Context, event *PolarWebhookEvent) error {
	subID, err := ExtractSubscriptionID(event.Data)
	if err != nil {
		return fmt.Errorf("extract subscription ID: %w", err)
	}

	_ = h.ledger.LogWebhookReceived(event.Type, subID)

	h.log.Info().
		Str("event_type", event.Type).
		Str("subscription_id", subID).
		Msg("processing webhook event")

	// Fetch current subscription state from Polar (source of truth).
	sub, err := h.polar.GetSubscription(ctx, subID)
	if err != nil {
		_ = h.ledger.LogError(subID, "fetch subscription from polar", err)
		return fmt.Errorf("fetch subscription from polar: %w", err)
	}

	return h.processSubscription(ctx, sub)
}

// processSubscription handles the core subscription logic shared by both
// webhook events and cron refreshes. Takes an already-fetched subscription
// to avoid redundant Polar API calls.
//
// Flow:
//  1. Map Polar product to Pipelock tier (rejects unmapped products)
//  2. Check founding cap for founding subscriptions
//  3. Load existing entitlement for idempotency comparison
//  4. If active: mint license token, persist, attempt email delivery
//  5. If ended: persist, send cancellation email
func (h *WebhookHandler) processSubscription(ctx context.Context, sub *PolarSubscription) error {
	ent, err := h.subscriptionToEntitlement(sub)
	if err != nil {
		_ = h.ledger.LogError(sub.ID, "map subscription to entitlement", err)
		return fmt.Errorf("map subscription: %w", err)
	}

	if ent.Founding {
		if err := h.checkFoundingCap(ctx, ent); err != nil {
			return err
		}
	}

	existing, err := h.db.GetBySubscriptionID(ctx, sub.ID)
	if err != nil {
		return fmt.Errorf("load existing entitlement: %w", err)
	}

	switch sub.Status {
	case "active":
		return h.handleActive(ctx, ent, existing)
	case "canceled", "revoked", "unpaid":
		return h.handleEnded(ctx, ent, existing)
	default:
		h.log.Warn().
			Str("subscription_id", sub.ID).
			Str("status", sub.Status).
			Msg("unrecognized subscription status, recording without action")
		// Preserve existing license state so an unknown status doesn't
		// wipe previously-tracked fields (LastLicense*, NextRefreshAt, etc.).
		if existing != nil {
			ent.LastLicenseID = existing.LastLicenseID
			ent.LastLicenseIssuedAt = existing.LastLicenseIssuedAt
			ent.LastLicenseExpiresAt = existing.LastLicenseExpiresAt
			ent.LastLicensePeriodEnd = existing.LastLicensePeriodEnd
			ent.LastLicenseTier = existing.LastLicenseTier
			ent.LastLicenseInterval = existing.LastLicenseInterval
			ent.LastLicenseProductID = existing.LastLicenseProductID
			ent.LastDeliveryStatus = existing.LastDeliveryStatus
			ent.LastDeliveryAttemptAt = existing.LastDeliveryAttemptAt
			ent.NextRefreshAt = existing.NextRefreshAt
		}
		return h.db.Upsert(ctx, ent)
	}
}

// handleActive processes an active subscription: checks idempotency,
// mints a license if needed, persists state, then attempts email delivery.
func (h *WebhookHandler) handleActive(ctx context.Context, ent *Entitlement, existing *Entitlement) error {
	// Idempotency check: compare the tuple that determines license content.
	// If all match, no new token is needed. But we still upsert because
	// metadata (email, org) may have changed since last issuance.
	if existing != nil && h.isIdempotent(ent, existing) {
		// Preserve existing license state so upsert doesn't blank it out.
		ent.LastLicenseID = existing.LastLicenseID
		ent.LastLicenseIssuedAt = existing.LastLicenseIssuedAt
		ent.LastLicenseExpiresAt = existing.LastLicenseExpiresAt
		ent.LastLicensePeriodEnd = existing.LastLicensePeriodEnd
		ent.LastLicenseTier = existing.LastLicenseTier
		ent.LastLicenseInterval = existing.LastLicenseInterval
		ent.LastLicenseProductID = existing.LastLicenseProductID
		ent.LastDeliveryStatus = existing.LastDeliveryStatus
		ent.LastDeliveryAttemptAt = existing.LastDeliveryAttemptAt
		ent.NextRefreshAt = existing.NextRefreshAt

		h.log.Info().
			Str("subscription_id", ent.SubscriptionID).
			Msg("idempotent: license state unchanged, persisting metadata only")
		return h.db.Upsert(ctx, ent)
	}

	// Mint a new license token.
	now := time.Now()
	expiresAt := now.Add(tokenLifetime)

	idBytes := make([]byte, 6) // 6 bytes = 12 hex chars
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("generate license ID: %w", err)
	}

	features := h.tierToFeatures(ent.Tier)

	lic := license.License{
		ID:        "lic_" + hex.EncodeToString(idBytes),
		Email:     ent.CustomerEmail,
		Org:       ent.Org,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		Features:  features,
	}

	token, err := license.Issue(lic, h.privateKey)
	if err != nil {
		_ = h.ledger.LogError(ent.SubscriptionID, "issue license token", err)
		return fmt.Errorf("issue license token: %w", err)
	}

	_ = h.ledger.LogLicenseIssued(ent.SubscriptionID, ent.CustomerEmail, lic.ID, ent.Tier, expiresAt)

	// Update entitlement with license state.
	ent.LastLicenseID = lic.ID
	issuedAt := now
	ent.LastLicenseIssuedAt = &issuedAt
	ent.LastLicenseExpiresAt = &expiresAt
	periodEnd := ent.CurrentPeriodEnd
	ent.LastLicensePeriodEnd = &periodEnd
	ent.LastLicenseTier = ent.Tier
	ent.LastLicenseInterval = ent.BillingInterval
	ent.LastLicenseProductID = ent.ProductID

	// Schedule next refresh: 15 days before token expiry.
	nextRefresh := expiresAt.Add(-time.Duration(refreshLeadDays) * 24 * time.Hour)
	ent.NextRefreshAt = &nextRefresh

	// Persist entitlement BEFORE external side effects (email).
	// If email fails, we still have the issuance record and can retry later.
	ent.LastDeliveryStatus = "pending"
	deliveryAttempt := now
	ent.LastDeliveryAttemptAt = &deliveryAttempt

	if err := h.db.Upsert(ctx, ent); err != nil {
		return fmt.Errorf("persist entitlement: %w", err)
	}

	// Attempt email delivery, update delivery status after.
	msgID, emailErr := h.email.SendLicenseDelivery(ctx, ent.CustomerEmail, token, ent.Tier)
	if emailErr != nil {
		h.log.Error().Err(emailErr).
			Str("subscription_id", ent.SubscriptionID).
			Msg("email delivery failed")
		if err := h.db.UpdateDeliveryStatus(ctx, ent.SubscriptionID, "failed", now); err != nil {
			return fmt.Errorf("update delivery status after email failure: %w", err)
		}
		_ = h.ledger.LogEmailFailed(ent.SubscriptionID, ent.CustomerEmail, emailErr)
	} else {
		if err := h.db.UpdateDeliveryStatus(ctx, ent.SubscriptionID, "sent", now); err != nil {
			return fmt.Errorf("update delivery status after email success: %w", err)
		}
		_ = h.ledger.LogEmailSent(ent.SubscriptionID, ent.CustomerEmail, msgID)
	}

	h.log.Info().
		Str("subscription_id", ent.SubscriptionID).
		Str("license_id", lic.ID).
		Str("tier", ent.Tier).
		Msg("license issued")

	return nil
}

// handleEnded processes a canceled/revoked/unpaid subscription.
func (h *WebhookHandler) handleEnded(ctx context.Context, ent *Entitlement, existing *Entitlement) error {
	// Clear the refresh schedule.
	ent.NextRefreshAt = nil

	// Upsert the entitlement to record the ended status.
	if err := h.db.Upsert(ctx, ent); err != nil {
		return fmt.Errorf("persist ended entitlement: %w", err)
	}

	// Send cancellation email if we have a last-issued license.
	if existing != nil && existing.LastLicenseExpiresAt != nil {
		_, emailErr := h.email.SendSubscriptionEnded(ctx, ent.CustomerEmail, *existing.LastLicenseExpiresAt)
		if emailErr != nil {
			h.log.Error().Err(emailErr).
				Str("subscription_id", ent.SubscriptionID).
				Msg("cancellation email failed")
			_ = h.ledger.LogEmailFailed(ent.SubscriptionID, ent.CustomerEmail, emailErr)
		}
	}

	_ = h.ledger.Log(AuditEntry{
		Event:          AuditSubscriptionEnd,
		SubscriptionID: ent.SubscriptionID,
		CustomerEmail:  ent.CustomerEmail,
		Tier:           ent.Tier,
		Detail:         ent.Status,
	})

	h.log.Info().
		Str("subscription_id", ent.SubscriptionID).
		Str("status", ent.Status).
		Msg("subscription ended")

	return nil
}

// isIdempotent returns true if the current subscription state matches
// the last-issued license state. If all four fields match, re-issuing
// would produce a functionally identical token.
func (h *WebhookHandler) isIdempotent(current, existing *Entitlement) bool {
	if existing.LastLicensePeriodEnd == nil {
		return false // never issued before
	}
	return existing.LastLicensePeriodEnd.Equal(current.CurrentPeriodEnd) &&
		existing.LastLicenseTier == current.Tier &&
		existing.LastLicenseInterval == current.BillingInterval &&
		existing.LastLicenseProductID == current.ProductID
}

// subscriptionToEntitlement maps a Polar subscription to an entitlement record.
func (h *WebhookHandler) subscriptionToEntitlement(sub *PolarSubscription) (*Entitlement, error) {
	tier, founding, err := h.mapProductToTier(sub)
	if err != nil {
		return nil, fmt.Errorf("map product to tier: %w", err)
	}

	features, err := json.Marshal(h.tierToFeatures(tier))
	if err != nil {
		return nil, fmt.Errorf("marshal features: %w", err)
	}

	org := sub.Customer.Metadata["org"]

	return &Entitlement{
		SubscriptionID:   sub.ID,
		CustomerEmail:    sub.Customer.Email,
		ProductID:        sub.Product.ID,
		Tier:             tier,
		BillingInterval:  sub.RecurringInterval,
		Status:           sub.Status,
		CurrentPeriodEnd: sub.CurrentPeriodEnd,
		Founding:         founding,
		Org:              org,
		Features:         string(features),
	}, nil
}

// mapProductToTier determines the Pipelock tier from the Polar product metadata.
// Rejects products with missing or unrecognized tier values to prevent
// misconfigured products from silently granting paid features.
func (h *WebhookHandler) mapProductToTier(sub *PolarSubscription) (tier string, founding bool, err error) {
	t, ok := sub.Product.Metadata["pipelock_tier"]
	if !ok {
		return "", false, fmt.Errorf("product %s (%s) has no pipelock_tier metadata",
			sub.Product.ID, sub.Product.Name)
	}

	if !validTiers[t] {
		return "", false, fmt.Errorf("product %s has unrecognized pipelock_tier %q",
			sub.Product.ID, t)
	}

	founding = t == tierFoundingPro
	return t, founding, nil
}

// tierToFeatures returns the feature list for a given tier.
// Returns nil for unknown tiers (fail-closed). Callers must validate
// tiers via mapProductToTier before reaching this point.
func (h *WebhookHandler) tierToFeatures(tier string) []string {
	switch tier {
	case tierFoundingPro, tierPro:
		return []string{license.FeatureAgents}
	case tierEnterprise:
		// TODO: Define enterprise-specific features as they're built.
		return []string{license.FeatureAgents}
	default:
		return nil
	}
}

// checkFoundingCap verifies that the Founding Pro cap has not been reached.
// If the cap is hit or the deadline has passed, downgrades to regular pro.
//
// The reservation is atomic: the mutex serializes access, and the founding
// count is read from the DB (not an in-memory cache) to prevent drift
// between the counter and persisted state.
func (h *WebhookHandler) checkFoundingCap(ctx context.Context, ent *Entitlement) error {
	h.foundingMu.Lock()
	defer h.foundingMu.Unlock()

	// Check if this subscription already holds a founding slot.
	// Prevents double-counting on Polar webhook retries.
	existing, err := h.db.GetBySubscriptionID(ctx, ent.SubscriptionID)
	if err != nil {
		return fmt.Errorf("check existing founding status: %w", err)
	}
	if existing != nil && existing.Founding {
		return nil // already has a slot
	}

	now := time.Now()

	if now.After(h.cfg.FoundingProDeadline) {
		_ = h.ledger.Log(AuditEntry{
			Event:          AuditFoundingCapHit,
			SubscriptionID: ent.SubscriptionID,
			CustomerEmail:  ent.CustomerEmail,
			Detail:         "founding pro deadline passed",
		})
		ent.Tier = tierPro
		ent.Founding = false
		h.log.Warn().
			Str("subscription_id", ent.SubscriptionID).
			Msg("founding pro deadline passed, downgrading to pro")
		return nil
	}

	// Read authoritative founding count from DB, not in-memory cache.
	// This prevents drift if the process restarted or a previous Upsert
	// changed the DB state outside the mutex.
	count, err := h.db.CountFounding(ctx)
	if err != nil {
		return fmt.Errorf("count founding slots: %w", err)
	}

	if count >= h.cfg.FoundingProCap {
		_ = h.ledger.Log(AuditEntry{
			Event:          AuditFoundingCapHit,
			SubscriptionID: ent.SubscriptionID,
			CustomerEmail:  ent.CustomerEmail,
			Detail:         fmt.Sprintf("founding pro cap reached (%d/%d)", count, h.cfg.FoundingProCap),
		})
		ent.Tier = tierPro
		ent.Founding = false
		h.log.Warn().
			Str("subscription_id", ent.SubscriptionID).
			Int("current_count", count).
			Int("cap", h.cfg.FoundingProCap).
			Msg("founding pro cap reached, downgrading to pro")
		return nil
	}

	// Reserve the slot atomically by persisting to DB within the mutex.
	// This ensures concurrent calls see the reservation immediately via
	// CountFounding, preventing double-allocation of founding slots.
	if err := h.db.Upsert(ctx, ent); err != nil {
		return fmt.Errorf("reserve founding slot: %w", err)
	}

	h.foundingCount = count + 1
	h.log.Info().
		Str("subscription_id", ent.SubscriptionID).
		Int("founding_count", h.foundingCount).
		Int("cap", h.cfg.FoundingProCap).
		Msg("founding pro slot reserved")

	return nil
}
