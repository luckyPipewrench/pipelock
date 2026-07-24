//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/rs/zerolog"
)

// tokenLifetime is the default validity period for issued license tokens.
// 45 days gives enough buffer for monthly subscribers to receive their
// refresh before expiration.
const tokenLifetime = 45 * 24 * time.Hour

// trialTokenLifetime is the validity period for trial license tokens.
// 30 days matches the one-time purchase duration (no renewal).
const trialTokenLifetime = 30 * 24 * time.Hour

// evalTokenLifetime is the validity period for Enterprise Eval license tokens.
// 60 days matches the paid one-time eval window (no renewal). When it expires,
// Conductor refuses to start; Apache-tier security scanning is unaffected.
const evalTokenLifetime = 60 * 24 * time.Hour

// refreshLeadDays is how many days before a token expires we schedule
// the next refresh. 15 days means monthly subscribers get refreshed
// at day 30 (15 days before the 45-day expiry).
const refreshLeadDays = 15

// billingIntervalOneTime identifies one-time purchases (trials).
const billingIntervalOneTime = "one_time"

// Subscription/entitlement status values used by Polar.
const (
	statusActive   = "active"
	statusCanceled = "canceled"
	statusRevoked  = "revoked"
	statusUnpaid   = "unpaid"
)

// Tier constants for Pipelock subscription levels.
const (
	tierFoundingPro    = "founding_pro"
	tierPro            = "pro"
	tierEnterprise     = "enterprise"
	tierEnterpriseEval = "enterprise_eval"
	tierTrial          = "trial"
	tierAssess         = "assess"
)

// validTiers is the allowlist of accepted pipelock_tier metadata values.
// Unknown tier values are rejected to prevent misconfigured Polar products
// from silently granting paid features.
var validTiers = map[string]bool{
	tierFoundingPro:    true,
	tierPro:            true,
	tierEnterprise:     true,
	tierEnterpriseEval: true,
	tierTrial:          true,
	tierAssess:         true,
}

// WebhookHandler processes Polar webhook events and coordinates license
// issuance, entitlement tracking, and email delivery.
type WebhookHandler struct {
	cfg              *Config
	db               *EntitlementDB
	polar            *PolarClient
	email            *EmailSender
	ledger           *AuditLedger
	privateKey       ed25519.PrivateKey
	rootPub          ed25519.PublicKey
	intermediate     license.Intermediate
	intermediateCert []byte
	log              zerolog.Logger

	// processMu serializes processSubscription calls to prevent concurrent
	// webhook deliveries for the same subscription_id from double-minting.
	// Single-pod SQLite deployment with <50 customers - global mutex is fine.
	processMu sync.Mutex

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
	rootPub, err := resolveServiceRootPublicKey(cfg)
	if err != nil {
		return nil, err
	}
	if len(cfg.IntermediateCert) == 0 {
		return nil, errors.New("intermediate certificate is required")
	}
	intermediateCert := append([]byte(nil), cfg.IntermediateCert...)
	im, err := license.ParseAndVerifyIntermediate(intermediateCert, rootPub, time.Now())
	if err != nil {
		return nil, fmt.Errorf("verify intermediate certificate: %w", err)
	}
	signingPub, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(im.PublicKey(), signingPub) {
		return nil, errors.New("intermediate certificate public key does not match license signing private key")
	}
	// Load founding count from DB to initialize the in-memory counter.
	count, err := db.CountFounding(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load founding count: %w", err)
	}

	return &WebhookHandler{
		cfg:              cfg,
		db:               db,
		polar:            polar,
		email:            email,
		ledger:           ledger,
		privateKey:       privateKey,
		rootPub:          rootPub,
		intermediate:     im,
		intermediateCert: intermediateCert,
		log:              log,
		foundingCount:    count,
	}, nil
}

func resolveServiceRootPublicKey(cfg *Config) (ed25519.PublicKey, error) {
	if len(cfg.RootPublicKey) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), cfg.RootPublicKey...), nil
	}
	if key := license.EmbeddedPublicKey(); key != nil {
		return key, nil
	}
	publicKey := strings.TrimSpace(cfg.LicensePublicKey)
	if publicKey == "" {
		publicKey = strings.TrimSpace(os.Getenv(license.EnvLicensePublicKey))
	}
	if publicKey == "" {
		return nil, errors.New("license root public key is required (official builds embed it; dev/self-hosted builds set PIPELOCK_LICENSE_PUBLIC_KEY)")
	}
	parsed, err := signing.ParsePublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parse license root public key: %w", err)
	}
	if len(parsed) != ed25519.PublicKeySize {
		return nil, errors.New("license root public key has invalid size")
	}
	return parsed, nil
}

// IntermediateCert returns the verified root-signed intermediate certificate
// bytes the handler accepted at startup.
func (h *WebhookHandler) IntermediateCert() []byte {
	return append([]byte(nil), h.intermediateCert...)
}

// HandleEvent processes a validated Polar webhook event. This is the
// webhook entry point called after signature validation and parsing.
//
// Processing flow:
//  1. Extract subscription_id from event data
//  2. Fetch current subscription state from Polar API (source of truth)
//  3. Delegate to processSubscription for shared business logic
func (h *WebhookHandler) HandleEvent(ctx context.Context, event *PolarWebhookEvent) error {
	return h.HandleEventDelivery(ctx, event, "")
}

// HandleEventDelivery processes a validated Polar subscription webhook and uses
// msgID for durable delivery dedupe when called from the HTTP webhook path.
func (h *WebhookHandler) HandleEventDelivery(ctx context.Context, event *PolarWebhookEvent, msgID string) error {
	subID, err := ExtractSubscriptionID(event.Data)
	if err != nil {
		return fmt.Errorf("extract subscription ID: %w", err)
	}

	_ = h.ledger.LogWebhookReceived(event.Type, subID)

	h.log.Info().
		Str("event_type", event.Type).
		Str("subscription_id", subID).
		Msg("processing webhook event")

	if msgID != "" {
		committed, err := h.db.WebhookCommitted(ctx, msgID)
		if err != nil {
			return fmt.Errorf("check webhook delivery: %w", err)
		}
		if committed {
			return h.resendSubscriptionIfNeeded(ctx, subID)
		}
	}

	// Fetch current subscription state from Polar (source of truth).
	sub, err := h.polar.GetSubscription(ctx, subID)
	if err != nil {
		_ = h.ledger.LogError(subID, "fetch subscription from polar", err)
		return fmt.Errorf("fetch subscription from polar: %w", err)
	}

	return h.processSubscriptionDelivery(ctx, sub, event.Type, msgID)
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
//
// isTerminalSubscriptionStatus reports whether a Polar status ends the
// subscription, meaning the event removes entitlement rather than granting it.
func isTerminalSubscriptionStatus(status string) bool {
	switch status {
	case statusCanceled, statusRevoked, statusUnpaid:
		return true
	default:
		return false
	}
}

func (h *WebhookHandler) processSubscription(ctx context.Context, sub *PolarSubscription) error {
	return h.processSubscriptionDelivery(ctx, sub, "", "")
}

func (h *WebhookHandler) processSubscriptionDelivery(ctx context.Context, sub *PolarSubscription, eventType, msgID string) error {
	h.processMu.Lock()
	defer h.processMu.Unlock()

	ent, err := h.subscriptionToEntitlement(sub)
	if err != nil {
		// Refusing to GRANT on a product we cannot map is correct. Refusing to
		// process the END of one is not: a cancellation or revocation that
		// cannot be recorded leaves the local entitlement sitting active, which
		// is the wrong direction to fail. Terminal events are processed from
		// the stored entitlement so revocation always lands, while any active
		// event on an unmappable product is still rejected below.
		if isTerminalSubscriptionStatus(sub.Status) {
			existing, loadErr := h.db.GetBySubscriptionID(ctx, sub.ID)
			if loadErr != nil {
				return fmt.Errorf("load existing entitlement for terminal event: %w", loadErr)
			}
			if existing != nil {
				terminal := *existing
				terminal.Status = sub.Status
				return h.handleEnded(ctx, &terminal, existing, eventType, msgID)
			}
		}
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
	case statusActive:
		return h.handleActiveDelivery(ctx, ent, existing, eventType, msgID)
	case statusCanceled, statusRevoked, statusUnpaid:
		return h.handleEnded(ctx, ent, existing, eventType, msgID)
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
		err := h.db.UpsertWithWebhook(ctx, ent, msgID, eventType)
		if errors.Is(err, ErrWebhookAlreadyCommitted) {
			return h.resendSubscriptionIfNeeded(ctx, ent.SubscriptionID)
		}
		return err
	}
}

// handleActive processes an active subscription: checks idempotency,
// mints a license if needed, persists state, then attempts email delivery.
func (h *WebhookHandler) handleActive(ctx context.Context, ent *Entitlement, existing *Entitlement) error {
	return h.handleActiveDelivery(ctx, ent, existing, "", "")
}

func (h *WebhookHandler) handleActiveDelivery(ctx context.Context, ent *Entitlement, existing *Entitlement, eventType, msgID string) error {
	if existing != nil && isTerminalEntitlementStatus(existing.Status) {
		err := fmt.Errorf("%w: subscription %s status %s", ErrTerminalEntitlement, ent.SubscriptionID, existing.Status)
		h.log.Warn().
			Err(err).
			Str("subscription_id", ent.SubscriptionID).
			Msg("stale active subscription state ignored after terminal entitlement")
		_ = h.ledger.LogError(ent.SubscriptionID, "ignore stale active subscription after terminal entitlement", err)
		return nil
	}

	// Idempotency check: compare the full set of fields that affect the
	// signed token (period, tier, interval, product, email, org). Also
	// skip the fast path if delivery never succeeded (retry), or if the
	// scheduled refresh is due (cron needs to mint a fresh token even
	// when the subscription state hasn't changed).
	refreshDue := existing != nil &&
		existing.NextRefreshAt != nil &&
		!time.Now().Before(*existing.NextRefreshAt)
	if existing != nil &&
		!refreshDue &&
		h.isIdempotent(ent, existing) &&
		existing.CustomerEmail == ent.CustomerEmail &&
		existing.Org == ent.Org &&
		existing.LastDeliveryStatus == "sent" {
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
		err := h.db.UpsertWithWebhook(ctx, ent, msgID, eventType)
		if errors.Is(err, ErrWebhookAlreadyCommitted) {
			return nil
		}
		return err
	}

	// Mint a new license token.
	now := time.Now()
	im, err := h.verifiedIntermediateAt(now)
	if err != nil {
		_ = h.ledger.LogError(ent.SubscriptionID, "verify intermediate before issue", err)
		return fmt.Errorf("verify intermediate before issue: %w", err)
	}
	expiresAt := h.clampedTokenExpiry(now, h.tokenLifetimeForTier(ent.Tier), im)

	idBytes := make([]byte, 6) // 6 bytes = 12 hex chars
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("generate license ID: %w", err)
	}

	features := h.tierToFeatures(ent.Tier)

	lic := license.License{
		ID:             "lic_" + hex.EncodeToString(idBytes),
		Email:          ent.CustomerEmail,
		Org:            ent.Org,
		IssuedAt:       now.Unix(),
		ExpiresAt:      expiresAt.Unix(),
		Features:       features,
		Tier:           ent.Tier,
		SubscriptionID: ent.SubscriptionID,
	}

	token, err := license.Issue(lic, h.privateKey)
	if err != nil {
		_ = h.ledger.LogError(ent.SubscriptionID, "issue license token", err)
		return fmt.Errorf("issue license token: %w", err)
	}

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

	// Schedule next refresh for subscription tiers only. One-time purchases
	// (trials) expire and are done - no refresh, no cron pickup.
	if ent.BillingInterval != billingIntervalOneTime {
		nextRefresh := expiresAt.Add(-time.Duration(refreshLeadDays) * 24 * time.Hour)
		ent.NextRefreshAt = &nextRefresh
	}

	// Persist entitlement BEFORE external side effects (email).
	// If email fails, we still have the issuance record and can retry later.
	ent.LastDeliveryStatus = "pending"
	deliveryAttempt := now
	ent.LastDeliveryAttemptAt = &deliveryAttempt

	if err := h.db.UpsertWithLicenseIssuanceAndWebhook(ctx, ent, LicenseIssuance{
		LicenseID:      lic.ID,
		SubscriptionID: ent.SubscriptionID,
		ExpiresAt:      expiresAt,
		IssuedAt:       now,
	}, msgID, eventType); err != nil {
		if errors.Is(err, ErrWebhookAlreadyCommitted) {
			return h.resendSubscriptionIfNeeded(ctx, ent.SubscriptionID)
		}
		if errors.Is(err, ErrTerminalEntitlement) {
			h.log.Warn().
				Err(err).
				Str("subscription_id", ent.SubscriptionID).
				Msg("stale active subscription state ignored after terminal entitlement")
			_ = h.ledger.LogError(ent.SubscriptionID, "ignore stale active subscription after terminal entitlement", err)
			return nil
		}
		_ = h.ledger.LogError(ent.SubscriptionID, "persist entitlement and license issuance", err)
		return fmt.Errorf("persist entitlement and license issuance: %w", err)
	}
	_ = h.ledger.LogLicenseIssued(ent.SubscriptionID, ent.CustomerEmail, lic.ID, ent.Tier, expiresAt)

	// Attempt email delivery, update delivery status after.
	if err := h.deliverLicenseEmail(ctx, ent, token, ent.Tier, now); err != nil {
		return err
	}

	h.log.Info().
		Str("subscription_id", ent.SubscriptionID).
		Str("license_id", lic.ID).
		Str("tier", ent.Tier).
		Msg("license issued")

	return nil
}

func (h *WebhookHandler) verifiedIntermediateAt(now time.Time) (license.Intermediate, error) {
	im, err := license.ParseAndVerifyIntermediate(h.intermediateCert, h.rootPub, now)
	if err != nil {
		return license.Intermediate{}, err
	}
	if !bytes.Equal(im.PublicKey(), h.intermediate.PublicKey()) || im.Serial() != h.intermediate.Serial() {
		return license.Intermediate{}, errors.New("intermediate certificate changed since startup")
	}
	return im, nil
}

func (h *WebhookHandler) clampedTokenExpiry(now time.Time, lifetime time.Duration, im license.Intermediate) time.Time {
	expiresAt := now.Add(lifetime)
	imNotAfter := time.Unix(im.Payload.NotAfter, 0).UTC()
	if expiresAt.After(imNotAfter) {
		return imNotAfter
	}
	return expiresAt
}

func (h *WebhookHandler) resendSubscriptionIfNeeded(ctx context.Context, subID string) error {
	ent, err := h.db.GetBySubscriptionID(ctx, subID)
	if err != nil {
		return fmt.Errorf("load entitlement for resend: %w", err)
	}
	if ent == nil || ent.LastLicenseID == "" || ent.LastDeliveryStatus == "sent" {
		return nil
	}
	// A replayed webhook reaches this path from the already-committed branch,
	// which skips the Polar re-fetch and reads only local state. Without these
	// guards a redelivery arriving after cancellation, or after the token has
	// expired, would re-send a paid license to someone no longer entitled to
	// it. Retry delivery only while the entitlement is still active and the
	// token it would resend is still valid.
	if ent.Status != statusActive {
		return nil
	}
	if ent.LastLicenseExpiresAt == nil || !time.Now().Before(*ent.LastLicenseExpiresAt) {
		return nil
	}
	token, err := h.regenerateToken(ent)
	if err != nil {
		return err
	}
	return h.deliverLicenseEmail(ctx, ent, token, ent.LastLicenseTier, time.Now())
}

// deliverLicenseEmail sends a license token and records the outcome in both the
// entitlement's delivery status and the audit ledger. Both the first-issue path
// and the redelivery path run this same sequence, and it is security-and-audit
// relevant, so it lives in one place: a future change (a retry limit, another
// audit field) must not be able to land on one path and miss the other.
func (h *WebhookHandler) deliverLicenseEmail(ctx context.Context, ent *Entitlement, token, tier string, now time.Time) error {
	msgID, emailErr := h.email.SendLicenseDelivery(ctx, ent.CustomerEmail, token, tier, string(h.intermediateCert))
	if emailErr != nil {
		h.log.Error().Err(emailErr).
			Str("subscription_id", ent.SubscriptionID).
			Msg("email delivery failed")
		if err := h.db.UpdateDeliveryStatus(ctx, ent.SubscriptionID, "failed", now); err != nil {
			return fmt.Errorf("update delivery status after email failure: %w", err)
		}
		_ = h.ledger.LogEmailFailed(ent.SubscriptionID, ent.CustomerEmail, emailErr)
		return nil
	}
	if err := h.db.UpdateDeliveryStatus(ctx, ent.SubscriptionID, "sent", now); err != nil {
		return fmt.Errorf("update delivery status after email success: %w", err)
	}
	_ = h.ledger.LogEmailSent(ent.SubscriptionID, ent.CustomerEmail, msgID)
	return nil
}

func (h *WebhookHandler) regenerateToken(ent *Entitlement) (string, error) {
	if ent.LastLicenseIssuedAt == nil || ent.LastLicenseExpiresAt == nil {
		return "", errors.New("cannot regenerate token without persisted issue and expiry timestamps")
	}
	lic := license.License{
		ID:             ent.LastLicenseID,
		Email:          ent.CustomerEmail,
		Org:            ent.Org,
		IssuedAt:       ent.LastLicenseIssuedAt.Unix(),
		ExpiresAt:      ent.LastLicenseExpiresAt.Unix(),
		Features:       h.tierToFeatures(ent.LastLicenseTier),
		Tier:           ent.LastLicenseTier,
		SubscriptionID: ent.SubscriptionID,
	}
	token, err := license.Issue(lic, h.privateKey)
	if err != nil {
		return "", fmt.Errorf("regenerate license token: %w", err)
	}
	return token, nil
}

// handleEnded processes a canceled/revoked/unpaid subscription. The terminal
// entitlement state and the webhook delivery marker are persisted in one
// transaction, before any non-idempotent side effect, so a crash between them
// cannot leave the subscription ended while the marker is absent and a Polar
// redelivery reprocesses the same terminal event.
func (h *WebhookHandler) handleEnded(ctx context.Context, ent *Entitlement, existing *Entitlement, eventType, msgID string) error {
	// Clear the refresh schedule.
	ent.NextRefreshAt = nil

	// Preserve license state from existing entitlement so the upsert
	// doesn't wipe last-issued license fields (needed for support
	// lookups, email retry, and the cancellation email below).
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
	}

	// Upsert the entitlement to record the ended status, committing the webhook
	// marker in the same transaction when this came from a delivery.
	if err := h.db.UpsertWithWebhook(ctx, ent, msgID, eventType); err != nil {
		if !errors.Is(err, ErrWebhookAlreadyCommitted) {
			return fmt.Errorf("persist ended entitlement: %w", err)
		}
	}

	if existing != nil {
		reason := "subscription_" + ent.Status
		if err := h.revokeSubscriptionLicenses(ctx, ent, existing, reason); err != nil {
			return err
		}
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

func (h *WebhookHandler) revokeSubscriptionLicenses(ctx context.Context, ent, existing *Entitlement, reason string) error {
	now := time.Now().UTC()
	issuances, err := h.db.ListUnexpiredLicenseIssuances(ctx, ent.SubscriptionID, now)
	if err != nil {
		_ = h.ledger.LogError(ent.SubscriptionID, "list license issuances for revocation", err)
		return fmt.Errorf("list license issuances for revocation: %w", err)
	}
	if existing.LastLicenseID != "" {
		found := false
		for _, issuance := range issuances {
			if issuance.LicenseID == existing.LastLicenseID {
				found = true
				break
			}
		}
		if !found {
			issuances = append(issuances, LicenseIssuance{
				LicenseID:      existing.LastLicenseID,
				SubscriptionID: ent.SubscriptionID,
				IssuedAt:       now,
			})
		}
	}
	for _, issuance := range issuances {
		if err := h.db.UpsertLicenseRevocation(ctx, RevokedLicenseRecord{
			LicenseID:      issuance.LicenseID,
			SubscriptionID: ent.SubscriptionID,
			Reason:         reason,
			RevokedAt:      now,
		}); err != nil {
			_ = h.ledger.LogError(ent.SubscriptionID, "record license revocation", err)
			return fmt.Errorf("record license revocation: %w", err)
		}
		_ = h.ledger.LogLicenseRevoked(ent.SubscriptionID, ent.CustomerEmail, issuance.LicenseID, reason)
	}
	return nil
}

// SignedCRL returns the current signed license revocation list.
func (h *WebhookHandler) SignedCRL(ctx context.Context, now time.Time) (license.CRL, error) {
	if len(h.cfg.CRLPrivateKey) != ed25519.PrivateKeySize {
		return license.CRL{}, errors.New("license CRL signing key not configured")
	}
	records, err := h.db.ListLicenseRevocations(ctx)
	if err != nil {
		return license.CRL{}, fmt.Errorf("list license revocations: %w", err)
	}
	revoked := make([]license.RevokedLicense, 0, len(records))
	for _, rec := range records {
		revoked = append(revoked, license.RevokedLicense{
			ID:        rec.LicenseID,
			RevokedAt: rec.RevokedAt.UTC().Unix(),
		})
	}
	// Issuer-side intermediate revocation: include every revoked intermediate
	// serial so consumers actually fail closed on a rotated/compromised
	// intermediate. Without this the model + consumer check exist but the issuer
	// never publishes the serials, making intermediate revocation a consumer-side
	// illusion.
	intRecords, err := h.db.ListRevokedIntermediates(ctx)
	if err != nil {
		return license.CRL{}, fmt.Errorf("list revoked intermediates: %w", err)
	}
	revokedInt := make([]license.RevokedIntermediate, 0, len(intRecords))
	for _, rec := range intRecords {
		revokedInt = append(revokedInt, license.RevokedIntermediate{
			Serial:    rec.Serial,
			Reason:    rec.Reason,
			RevokedAt: rec.RevokedAt.UTC().Unix(),
		})
	}
	// Advance the durable monotonic generation BEFORE signing so every CRL this
	// service emits carries a strictly higher generation than the previous one.
	// Consumers reject any CRL below their accepted high-water mark, which stops
	// a rolled-back (older, revocation-omitting) CRL from re-validating a
	// revoked license.
	generation, err := h.db.NextCRLGeneration(ctx)
	if err != nil {
		return license.CRL{}, fmt.Errorf("advance CRL generation: %w", err)
	}
	return license.SignCRL(license.CRLPayload{
		Version:              license.CRLVersion,
		Generation:           generation,
		IssuedAt:             now.UTC().Unix(),
		ExpiresAt:            now.UTC().Add(7 * 24 * time.Hour).Unix(),
		Revoked:              revoked,
		RevokedIntermediates: revokedInt,
	}, h.cfg.CRLPrivateKey)
}

// RecoverCRLGenerationFromSignedCRL re-seeds the durable monotonic CRL
// generation high-water from a PREVIOUSLY PUBLISHED signed CRL (P0.2 recovery).
// After a DB restore the in-DB counter can be behind the highest generation a
// consumer has already accepted; minting a lower generation next would let a
// restored CRL un-revoke a license. The operator feeds the last published signed
// CRL (fetched from the CRL endpoint cache / CDN / object store) and this:
//
//  1. verifies it against the service's CRL signing public key (an unsigned or
//     wrong-key CRL cannot move the high-water — fail closed), and
//  2. raises the DB counter to at least that CRL's generation (never lowers it).
//
// It reads the generation from the SIGNED CRL, not the DB, exactly as the spec
// requires.
func (h *WebhookHandler) RecoverCRLGenerationFromSignedCRL(ctx context.Context, signedCRL []byte) (uint64, error) {
	if len(h.cfg.CRLPrivateKey) != ed25519.PrivateKeySize {
		return 0, errors.New("license CRL signing key not configured")
	}
	pub, ok := h.cfg.CRLPrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return 0, errors.New("CRL signing key has no public half")
	}
	// Signature-only verify: a forged or wrong-key CRL cannot move the
	// high-water. Expiry is intentionally NOT enforced — a previously published
	// CRL may have aged out, but its generation is still a real high-water the
	// service must not regress below.
	crl, err := license.ParseAndVerifyCRLSignatureOnly(signedCRL, pub)
	if err != nil {
		return 0, fmt.Errorf("verify published CRL for recovery: %w", err)
	}
	return h.db.RecoverCRLGeneration(ctx, crl.Payload.Generation)
}

// RevokeIntermediate records an intermediate signing-cert serial as revoked so
// the next published SignedCRL carries it. This is the admin flow that makes
// intermediate revocation real: an operator (or rotation automation) calls it
// when an intermediate is rotated out or compromised. Idempotent — re-revoking
// the same serial updates the reason/timestamp without faulting.
func (h *WebhookHandler) RevokeIntermediate(ctx context.Context, serial, reason string, now time.Time) error {
	if serial == "" {
		return errors.New("intermediate serial is required")
	}
	if err := h.db.UpsertRevokedIntermediate(ctx, RevokedIntermediateRecord{
		Serial:    serial,
		Reason:    reason,
		RevokedAt: now.UTC(),
	}); err != nil {
		return fmt.Errorf("record intermediate revocation: %w", err)
	}
	_ = h.ledger.LogIntermediateRevoked(serial, reason)
	return nil
}

// RevokeImportedIssuance adds an imported break-glass license to the signed CRL
// revocation set. Importing proves the externally-minted token exists; this
// method is the operator surface that makes "imported == revocable" true.
func (h *WebhookHandler) RevokeImportedIssuance(ctx context.Context, licenseID, reason string, now time.Time) error {
	if licenseID == "" {
		return errors.New("license_id is required")
	}
	rec, err := h.db.GetImportedIssuance(ctx, licenseID)
	if err != nil {
		return fmt.Errorf("load imported issuance %s: %w", licenseID, err)
	}
	if rec == nil {
		return fmt.Errorf("imported issuance %s not found", licenseID)
	}
	if reason == "" {
		reason = "imported_license_revoked"
	}
	if now.IsZero() {
		now = time.Now()
	}
	subID := rec.SubscriptionID
	if subID == "" {
		subID = "imported:" + rec.ImportID
	}
	if err := h.db.UpsertLicenseRevocation(ctx, RevokedLicenseRecord{
		LicenseID:      rec.LicenseID,
		SubscriptionID: subID,
		Reason:         reason,
		RevokedAt:      now.UTC(),
	}); err != nil {
		return fmt.Errorf("record imported issuance revocation: %w", err)
	}
	_ = h.ledger.LogLicenseRevoked(subID, "", rec.LicenseID, reason)
	return nil
}

// ImportSignedIssuance verifies a SIGNED issuance export and durably records the
// externally-minted license token in the import table so it becomes revocable.
// This is the consumer of the break-glass / standalone-CLI export: a paid token
// minted outside the service is invisible to revocation until it is imported.
//
// issuerPub is the public half of the key that signed BOTH the token and the
// export (the offline root, an intermediate, or the online signer, depending on
// how the break-glass token was minted). The operator supplies it. Verification
// fails closed on a bad signature, an issuer-key-id mismatch, or a malformed
// export — a forged or tampered export cannot enter the revocation surface.
//
// Outcomes: ImportOutcomeImported (new record written), ImportOutcomeReplay (the
// identical export was already imported — idempotent, returns a nil error), and
// ImportOutcomeConflict (collides with a DIFFERENT record on a unique key —
// returns ErrIssuanceConflict). Every attempt is recorded in the audit ledger.
func (h *WebhookHandler) ImportSignedIssuance(
	ctx context.Context,
	signedExport []byte,
	issuerPub ed25519.PublicKey,
	importID string,
	now time.Time,
) (license.IssuanceExportPayload, ImportOutcome, error) {
	if importID == "" {
		return license.IssuanceExportPayload{}, "", errors.New("import id is required")
	}
	verified, err := license.ParseAndVerifyIssuanceExport(signedExport, issuerPub)
	if err != nil {
		// Fail closed: a malformed / forged / wrong-key export never imports.
		return license.IssuanceExportPayload{}, "", fmt.Errorf("verify issuance export: %w", err)
	}
	if now.IsZero() {
		now = time.Now()
	}
	rec := importedIssuanceFromExport(verified.Payload, importID)
	rec.ImportedAt = now.UTC()

	switch err := h.db.ImportIssuance(ctx, rec); {
	case err == nil:
		_ = h.ledger.LogIssuanceImported(rec.LicenseID, importID, string(ImportOutcomeImported))
		return verified.Payload, ImportOutcomeImported, nil
	case errors.Is(err, ErrIssuanceReplay):
		_ = h.ledger.LogIssuanceImported(rec.LicenseID, importID, string(ImportOutcomeReplay))
		return verified.Payload, ImportOutcomeReplay, nil
	case errors.Is(err, ErrIssuanceConflict):
		_ = h.ledger.LogIssuanceImported(rec.LicenseID, importID, string(ImportOutcomeConflict))
		return verified.Payload, ImportOutcomeConflict, err
	default:
		// Unexpected DB error (disk full, context cancellation, corruption): the
		// import failed closed (nothing recorded, nothing revocable), but a verified
		// export was presented and lost. Record the attempt so it leaves a forensic
		// trace in the ledger rather than vanishing silently.
		_ = h.ledger.LogIssuanceImported(rec.LicenseID, importID, "error: "+err.Error())
		return verified.Payload, "", fmt.Errorf("import issuance: %w", err)
	}
}

// ListImportedIssuances returns every imported (externally-minted) issuance for
// operator inspection.
func (h *WebhookHandler) ListImportedIssuances(ctx context.Context) ([]ImportedIssuance, error) {
	return h.db.ListImportedIssuances(ctx)
}

// GetImportedIssuance returns a single imported issuance by license id, or
// (nil, nil) when not found.
func (h *WebhookHandler) GetImportedIssuance(ctx context.Context, licenseID string) (*ImportedIssuance, error) {
	return h.db.GetImportedIssuance(ctx, licenseID)
}

// HandleOrderEvent processes a Polar order.created webhook event for
// one-time purchases (e.g., trial tier). Subscription-related billing
// reasons are ignored because subscription.* events handle those.
func (h *WebhookHandler) HandleOrderEvent(ctx context.Context, event *PolarWebhookEvent) error {
	order, err := extractOrderData(event.Data)
	if err != nil {
		return fmt.Errorf("extract order data: %w", err)
	}

	_ = h.ledger.LogWebhookReceived(event.Type, order.ID)

	// Only process one-time purchases. Subscription-related billing reasons
	// (subscription_create, subscription_cycle, subscription_update) are
	// handled by subscription.* events via HandleEvent.
	if order.BillingReason != "purchase" {
		h.log.Info().
			Str("order_id", order.ID).
			Str("billing_reason", order.BillingReason).
			Msg("ignoring non-purchase order (subscription events handle these)")
		return nil
	}
	if order.Product.Metadata["pipelock_tier"] == tierEnterpriseEval {
		h.log.Info().
			Str("order_id", order.ID).
			Str("event_type", event.Type).
			Msg("ignoring enterprise eval order in legacy order handler")
		return nil
	}

	currentOrder, err := h.polar.GetOrder(ctx, order.ID)
	if err != nil {
		return fmt.Errorf("load current order %s: %w", order.ID, err)
	}
	if currentOrder.ID != order.ID {
		return fmt.Errorf("load current order %s: response ID %q does not match", order.ID, currentOrder.ID)
	}
	order = currentOrder
	if order.BillingReason != "purchase" {
		h.log.Info().
			Str("order_id", order.ID).
			Str("billing_reason", order.BillingReason).
			Msg("ignoring current non-purchase order")
		return nil
	}
	if order.Product.Metadata["pipelock_tier"] == tierEnterpriseEval {
		h.log.Info().
			Str("order_id", order.ID).
			Str("event_type", event.Type).
			Msg("ignoring current enterprise eval order in legacy order handler")
		return nil
	}

	// The order path is an authorization boundary: require settled payment and
	// server-side product, tier, price, and currency facts. Product metadata is
	// only a defense-in-depth consistency check, never the source of authority.
	tier, err := h.mapOrderProductToTier(order)
	if err != nil {
		return fmt.Errorf("authorize order %s: %w", order.ID, err)
	}
	features, err := json.Marshal(h.tierToFeatures(tier))
	if err != nil {
		return fmt.Errorf("marshal features: %w", err)
	}

	org := order.Customer.Metadata["org"]

	h.processMu.Lock()
	defer h.processMu.Unlock()

	// Load existing entitlement for idempotency. If a previous webhook
	// delivery already processed this order, reuse its period end so the
	// idempotency check in handleActive sees matching state. Without this,
	// time.Now() drift would bypass idempotency on replays.
	existing, err := h.db.GetBySubscriptionID(ctx, order.ID)
	if err != nil {
		return fmt.Errorf("load existing entitlement for order %s: %w", order.ID, err)
	}

	var periodEnd time.Time
	if existing != nil {
		periodEnd = existing.CurrentPeriodEnd
	} else {
		periodEnd = time.Now().Add(h.tokenLifetimeForTier(tier))
	}

	ent := &Entitlement{
		SubscriptionID:   order.ID, // Use order_id as unique key.
		CustomerEmail:    order.Customer.Email,
		ProductID:        order.Product.ID,
		Tier:             tier,
		BillingInterval:  billingIntervalOneTime,
		Status:           statusActive,
		CurrentPeriodEnd: periodEnd,
		Founding:         false, // Trials are never founding.
		Org:              org,
		Features:         string(features),
	}

	return h.handleActive(ctx, ent, existing)
}

func (h *WebhookHandler) mapOrderProductToTier(order *PolarOrder) (string, error) {
	if !order.Paid || order.Status != orderStatusPaid {
		return "", errors.New("order is not paid")
	}
	if classifyRefund(order) != refundStateNone {
		return "", errors.New("order is refunded")
	}
	var configured *OrderProductConfig
	for i := range h.cfg.OrderProducts {
		if h.cfg.OrderProducts[i].ProductID == order.Product.ID {
			configured = &h.cfg.OrderProducts[i]
			break
		}
	}
	if configured == nil {
		return "", fmt.Errorf("product %s is not allowlisted", order.Product.ID)
	}
	if order.Product.Metadata["pipelock_tier"] != configured.Tier {
		return "", fmt.Errorf("product %s tier metadata %q does not match allowlist tier %q",
			order.Product.ID, order.Product.Metadata["pipelock_tier"], configured.Tier)
	}
	if order.NetAmount != configured.AmountCents {
		return "", fmt.Errorf("product %s amount %d does not match allowlist amount %d",
			order.Product.ID, order.NetAmount, configured.AmountCents)
	}
	if strings.ToLower(order.Currency) != configured.Currency {
		return "", fmt.Errorf("product %s currency %q does not match allowlist currency %q",
			order.Product.ID, order.Currency, configured.Currency)
	}
	return configured.Tier, nil
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
	if len(h.cfg.SubscriptionProducts) > 0 {
		product, ok := h.subscriptionProduct(sub.Product.ID)
		if !ok {
			return "", false, fmt.Errorf("subscription product %s is not allowlisted", sub.Product.ID)
		}
		if sub.Product.Metadata["pipelock_tier"] != product.Tier {
			return "", false, fmt.Errorf("subscription product %s tier metadata %q does not match allowlist tier %q",
				sub.Product.ID, sub.Product.Metadata["pipelock_tier"], product.Tier)
		}
		if sub.RecurringInterval != product.Interval {
			return "", false, fmt.Errorf("subscription product %s interval %q does not match allowlist interval %q",
				sub.Product.ID, sub.RecurringInterval, product.Interval)
		}
		if sub.AmountCents != product.AmountCents {
			return "", false, fmt.Errorf("subscription product %s amount %d does not match allowlist amount %d",
				sub.Product.ID, sub.AmountCents, product.AmountCents)
		}
		if strings.ToLower(sub.Currency) != product.Currency {
			return "", false, fmt.Errorf("subscription product %s currency %q does not match allowlist currency %q",
				sub.Product.ID, sub.Currency, product.Currency)
		}
		return product.Tier, product.Tier == tierFoundingPro, nil
	}

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

func (h *WebhookHandler) subscriptionProduct(productID string) (SubscriptionProductConfig, bool) {
	for _, product := range h.cfg.SubscriptionProducts {
		if product.ProductID == productID {
			return product, true
		}
	}
	return SubscriptionProductConfig{}, false
}

// tierToFeatures returns the feature list for a given tier.
// Returns nil for unknown tiers (fail-closed). Callers must validate
// tiers via mapProductToTier before reaching this point.
func (h *WebhookHandler) tierToFeatures(tier string) []string {
	switch tier {
	case tierFoundingPro, tierPro, tierTrial:
		return []string{license.FeatureAgents}
	case tierEnterprise, tierEnterpriseEval:
		// Enterprise (and the time-boxed Enterprise Eval) carry the fleet control
		// plane (Conductor + audit sink) on top of the Pro multi-agent profile
		// feature. Eval gets the same capabilities as full Enterprise; the only
		// difference is the 60-day, non-renewing token lifetime. Add additional
		// Enterprise-only features (hosted services, transparency log, …) to this
		// slice as they ship.
		return []string{license.FeatureAgents, license.FeatureFleet}
	case tierAssess:
		return []string{license.FeatureAssess}
	default:
		return nil
	}
}

// tokenLifetimeForTier returns the token validity period for a given tier.
// Trials get 30 days and Enterprise Eval gets 60 days (both one-time, no
// renewal). All other tiers get 45 days with rolling refresh.
func (h *WebhookHandler) tokenLifetimeForTier(tier string) time.Duration {
	switch tier {
	case tierTrial:
		return trialTokenLifetime
	case tierEnterpriseEval:
		return evalTokenLifetime
	default:
		return tokenLifetime
	}
}

// checkFoundingCap verifies that the Founding Pro cap has not been reached.
// If the cap is hit or the deadline has passed, the checkout is still honored
// (customer paid the founding price). Logs a warning to archive the Polar
// product so no further founding checkouts are possible.
//
// The reservation is atomic: the mutex serializes access, and the founding
// count is read from the DB (not an in-memory cache) to prevent drift
// between the counter and persisted state.
func (h *WebhookHandler) checkFoundingCap(ctx context.Context, ent *Entitlement) error {
	h.foundingMu.Lock()
	defer h.foundingMu.Unlock()

	// Check if this subscription already holds a founding slot.
	// Uses FoundingReservedAt (immutable) instead of Founding (mutable)
	// so a product change can't reopen slots.
	existing, err := h.db.GetBySubscriptionID(ctx, ent.SubscriptionID)
	if err != nil {
		return fmt.Errorf("check existing founding status: %w", err)
	}
	if existing != nil && existing.FoundingReservedAt != nil {
		return nil // already has a slot
	}

	now := time.Now()

	if now.After(h.cfg.FoundingProDeadline) {
		_ = h.ledger.Log(AuditEntry{
			Event:          AuditFoundingCapHit,
			SubscriptionID: ent.SubscriptionID,
			CustomerEmail:  ent.CustomerEmail,
			Detail:         "founding pro deadline passed, honoring paid checkout",
		})
		h.log.Warn().
			Str("subscription_id", ent.SubscriptionID).
			Msg("founding pro deadline passed, honoring paid checkout — archive Polar products")
		// Fall through to reserve the founding slot. The customer paid the
		// founding price, so they get founding. The real defense is archiving
		// the Polar product so no new checkouts are possible.
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
			Detail:         fmt.Sprintf("founding pro cap reached (%d/%d), honoring paid checkout", count, h.cfg.FoundingProCap),
		})
		h.log.Warn().
			Str("subscription_id", ent.SubscriptionID).
			Int("current_count", count).
			Int("cap", h.cfg.FoundingProCap).
			Msg("founding pro cap reached, honoring paid checkout — archive Polar products")
		// Fall through to reserve the slot. The customer paid the founding
		// price, so they get founding. Archive the Polar product to prevent
		// further checkouts at the founding price.
	}

	// Stamp the reservation time. COALESCE in the Upsert ON CONFLICT clause
	// ensures this value is never overwritten once set, so product changes
	// can't reopen founding slots.
	reservedAt := time.Now().UTC()
	ent.FoundingReservedAt = &reservedAt

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
