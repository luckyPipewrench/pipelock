//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

// cronCheckInterval is how often the refresh loop checks for due renewals.
// 5 minutes balances responsiveness with database load.
const cronCheckInterval = 5 * time.Minute

// RefreshCron runs a periodic loop that checks for active subscriptions
// due for token refresh and issues fresh 45-day tokens. This ensures
// customers always have a valid token without needing to re-download
// after every billing cycle.
type RefreshCron struct {
	handler *WebhookHandler
	db      *EntitlementDB
	ledger  *AuditLedger
	log     zerolog.Logger
}

// NewRefreshCron creates a refresh cron with access to the handler's
// license-issuing machinery.
func NewRefreshCron(handler *WebhookHandler, db *EntitlementDB, ledger *AuditLedger, log zerolog.Logger) *RefreshCron {
	return &RefreshCron{
		handler: handler,
		db:      db,
		ledger:  ledger,
		log:     log,
	}
}

// Run starts the refresh loop. It blocks until the context is canceled.
// Errors on individual subscriptions are logged but do not stop the loop.
func (c *RefreshCron) Run(ctx context.Context) {
	c.log.Info().
		Dur("interval", cronCheckInterval).
		Msg("refresh cron started")

	ticker := time.NewTicker(cronCheckInterval)
	defer ticker.Stop()

	// Run once immediately at startup.
	c.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			c.log.Info().Msg("refresh cron stopped")
			return
		case <-ticker.C:
			c.tick(ctx)
		}
	}
}

// tick performs a single refresh cycle: finds all due subscriptions and
// issues fresh tokens for each.
func (c *RefreshCron) tick(ctx context.Context) {
	now := time.Now()

	due, err := c.db.ListDueForRefresh(ctx, now)
	if err != nil {
		c.log.Error().Err(err).Msg("list due for refresh")
		return
	}

	if len(due) == 0 {
		return
	}

	c.log.Info().
		Int("count", len(due)).
		Msg("processing due refreshes")

	for _, ent := range due {
		if err := c.refreshOne(ctx, ent); err != nil {
			c.log.Error().Err(err).
				Str("subscription_id", ent.SubscriptionID).
				Msg("refresh failed")
			_ = c.ledger.LogError(ent.SubscriptionID, "cron refresh failed", err)
		}
	}
}

// refreshOne issues a fresh token for a single subscription. It re-fetches
// the subscription from Polar to ensure the status is still active before
// issuing.
func (c *RefreshCron) refreshOne(ctx context.Context, ent *Entitlement) error {
	// Re-fetch from Polar to verify the subscription is still active.
	// This prevents issuing tokens for subscriptions that were canceled
	// between the last webhook and this refresh cycle.
	sub, err := c.handler.polar.GetSubscription(ctx, ent.SubscriptionID)
	if err != nil {
		return err
	}

	if sub.Status != "active" {
		c.log.Info().
			Str("subscription_id", ent.SubscriptionID).
			Str("status", sub.Status).
			Msg("subscription no longer active, skipping refresh")

		// Update the local entitlement status and clear refresh schedule.
		ent.Status = sub.Status
		ent.NextRefreshAt = nil
		return c.db.Upsert(ctx, ent)
	}

	_ = c.ledger.Log(AuditEntry{
		Event:          AuditRefreshIssued,
		SubscriptionID: ent.SubscriptionID,
		CustomerEmail:  ent.CustomerEmail,
		Tier:           ent.Tier,
		Detail:         "cron refresh",
	})

	// Use the shared processing path directly, avoiding a redundant
	// Polar API fetch that HandleEvent would perform.
	return c.handler.processSubscription(ctx, sub)
}
