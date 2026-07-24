// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package licenseservice

import (
	"strings"
	"testing"
)

// A product that is not on the allowlist must not GRANT entitlement, but it
// must still be able to LOSE it. Gating terminal events on mappability leaves a
// canceled or revoked subscription recorded as active locally, which fails in
// the wrong direction: the safe answer to "I cannot map this product" is to
// deny the grant and honor the revocation, never to ignore both.
func TestProcessSubscription_TerminalEventsSurviveUnmappableProduct(t *testing.T) {
	allowlist := []SubscriptionProductConfig{
		{ProductID: testProductID, Tier: tierPro, Interval: testIntervalMonth, AmountCents: 2900, Currency: "usd"},
	}

	t.Run("active event on an unmappable product is rejected", func(t *testing.T) {
		ts := newTestSetup(t)
		ts.cfg.SubscriptionProducts = allowlist
		sub := testActiveSubscription("prod_not_allowlisted", tierEnterprise)

		err := ts.handler.processSubscription(t.Context(), sub)
		if err == nil {
			t.Fatal("active event on a non-allowlisted product was accepted, want rejection")
		}
		if !strings.Contains(err.Error(), "map subscription") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("cancellation on an unmappable product is still recorded", func(t *testing.T) {
		ts := newTestSetup(t)
		ctx := t.Context()

		// Seed an active entitlement the way a pre-enforcement grant would have.
		ts.cfg.SubscriptionProducts = nil
		if err := ts.handler.processSubscription(ctx, testActiveSubscription("prod_not_allowlisted", tierEnterprise)); err != nil {
			t.Fatalf("seed active entitlement: %v", err)
		}
		seeded, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
		if err != nil {
			t.Fatalf("GetBySubscriptionID(seeded): %v", err)
		}
		if seeded == nil || seeded.Status != statusActive {
			t.Fatalf("seeded entitlement = %+v, want an active record", seeded)
		}

		// Enforcement turns on, and the product is not on the list.
		ts.cfg.SubscriptionProducts = allowlist
		canceled := testActiveSubscription("prod_not_allowlisted", tierEnterprise)
		canceled.Status = statusCanceled

		if err := ts.handler.processSubscription(ctx, canceled); err != nil {
			t.Fatalf("cancellation on a non-allowlisted product: %v", err)
		}

		got, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
		if err != nil {
			t.Fatalf("GetBySubscriptionID(after cancel): %v", err)
		}
		if got.Status != statusCanceled {
			t.Fatalf("Status = %q, want %q: the revocation must land even when the product cannot be mapped", got.Status, statusCanceled)
		}
		if got.NextRefreshAt != nil {
			t.Error("NextRefreshAt is set after cancellation, want cleared")
		}
	})
}

// Assess is a live recurring product, so it has to be allowlistable. Rejecting
// it at config load would make an Assess customer impossible to map once
// enforcement is on, and would fail service startup on a correct config.
func TestLoadConfig_SubscriptionProductsAcceptsAssess(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("SUBSCRIPTION_PRODUCTS", "prod_assess:assess:year:99900:usd")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.SubscriptionProducts) != 1 || cfg.SubscriptionProducts[0].Tier != tierAssess {
		t.Fatalf("SubscriptionProducts = %+v, want one Assess product", cfg.SubscriptionProducts)
	}

	products := parseSubscriptionProducts("prod_assess:assess:year:99900:usd")
	if len(products) != 1 {
		t.Fatalf("parsed %d products, want 1", len(products))
	}
	if products[0].Tier != tierAssess {
		t.Fatalf("Tier = %q, want %q", products[0].Tier, tierAssess)
	}
	if !validTiers[products[0].Tier] {
		t.Fatalf("%q is not a valid tier", products[0].Tier)
	}
	// The one-time tiers stay out: they belong to the order path's allowlist.
	for _, tier := range []string{tierEnterpriseEval, tierTrial} {
		if tier == products[0].Tier {
			t.Fatalf("subscription allowlist accepted one-time tier %q", tier)
		}
	}
}
