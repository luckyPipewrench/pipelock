//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"testing"
)

// setRequiredConfigEnv sets all required env vars for LoadConfig tests.
// Split credential-like values at runtime to avoid gosec G101.
func setRequiredConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("POLAR_WEBHOOK_SECRET", "whsec_"+"dGVzdA==")
	t.Setenv("POLAR_API_TOKEN", "polar_"+"test")
	t.Setenv("PIPELOCK_LICENSE_KEY_PATH", "/tmp/test.key")
	t.Setenv("PIPELOCK_LICENSE_INTERMEDIATE_FILE", "/tmp/intermediate.json")
	t.Setenv("RESEND_API_KEY", "re_"+"test")
	t.Setenv("SUBSCRIPTION_PRODUCTS", "prod_test:pro:month:2900:usd")
}

func TestLoadConfig_AllRequired(t *testing.T) {
	setRequiredConfigEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.PolarWebhookSecret != "whsec_"+"dGVzdA==" {
		t.Errorf("PolarWebhookSecret = %q", cfg.PolarWebhookSecret)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, defaultListenAddr)
	}
	if cfg.FoundingProCap != defaultFoundingProCap {
		t.Errorf("FoundingProCap = %d, want %d", cfg.FoundingProCap, defaultFoundingProCap)
	}
	if cfg.DBPath != defaultDBPath {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, defaultDBPath)
	}
}

func TestLoadConfig_MissingRequired(t *testing.T) {
	tests := []struct {
		name     string
		clearEnv string
	}{
		{"missing POLAR_WEBHOOK_SECRET", "POLAR_WEBHOOK_SECRET"},
		{"missing POLAR_API_TOKEN", "POLAR_API_TOKEN"},
		{"missing PIPELOCK_LICENSE_KEY_PATH", "PIPELOCK_LICENSE_KEY_PATH"},
		{"missing PIPELOCK_LICENSE_INTERMEDIATE_FILE", "PIPELOCK_LICENSE_INTERMEDIATE_FILE"},
		{"missing RESEND_API_KEY", "RESEND_API_KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredConfigEnv(t)
			t.Setenv(tt.clearEnv, "")

			_, err := LoadConfig()
			if err == nil {
				t.Error("expected error for missing required config, got nil")
			}
		})
	}
}

func TestLoadConfig_NegativeFoundingCap(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_CAP", "-1")

	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for negative founding cap, got nil")
	}
}

func TestLoadConfig_InvalidFoundingCap(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_CAP", "not-a-number")

	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for invalid founding cap, got nil")
	}
}

func TestLoadConfig_InvalidDeadline(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_DEADLINE", "not-a-date")

	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for invalid deadline, got nil")
	}
}

func TestLoadConfig_CustomValues(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("LISTEN_ADDR", ":9090")
	t.Setenv("DB_PATH", "/tmp/custom.db")
	t.Setenv("FOUNDING_PRO_CAP", "100")
	t.Setenv("FOUNDING_PRO_DEADLINE", "2027-01-01")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9090")
	}
	if cfg.DBPath != "/tmp/custom.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "/tmp/custom.db")
	}
	if cfg.FoundingProCap != 100 {
		t.Errorf("FoundingProCap = %d, want %d", cfg.FoundingProCap, 100)
	}
}

func TestLoadConfig_EvalDefaults(t *testing.T) {
	setRequiredConfigEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// With no eval product IDs configured, eval selling is effectively disabled
	// and currency defaults to usd. No amount requirement.
	if len(cfg.EvalProductIDs) != 0 {
		t.Errorf("EvalProductIDs = %v, want empty", cfg.EvalProductIDs)
	}
	if cfg.EvalCurrency != defaultEvalCurrency {
		t.Errorf("EvalCurrency = %q, want %q", cfg.EvalCurrency, defaultEvalCurrency)
	}
}

func TestLoadConfig_EvalConfigured(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("EVAL_PRODUCT_IDS", "prod_eval_a, prod_eval_b")
	t.Setenv("EVAL_AMOUNT_CENTS", "500000")
	t.Setenv("EVAL_CURRENCY", "USD")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.EvalProductIDs) != 2 || cfg.EvalProductIDs[0] != "prod_eval_a" || cfg.EvalProductIDs[1] != "prod_eval_b" {
		t.Errorf("EvalProductIDs = %v, want [prod_eval_a prod_eval_b] (trimmed)", cfg.EvalProductIDs)
	}
	if cfg.EvalAmountCents != 500000 {
		t.Errorf("EvalAmountCents = %d, want 500000", cfg.EvalAmountCents)
	}
	// Currency is normalized to lowercase for comparison against Polar.
	if cfg.EvalCurrency != "usd" {
		t.Errorf("EvalCurrency = %q, want usd", cfg.EvalCurrency)
	}
}

func TestLoadConfig_EvalTrimsWhitespace(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("EVAL_PRODUCT_IDS", "prod_eval_a")
	t.Setenv("EVAL_AMOUNT_CENTS", "  500000  ")
	t.Setenv("EVAL_CURRENCY", "  USD  ")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.EvalAmountCents != 500000 {
		t.Errorf("EvalAmountCents = %d, want 500000 (padded value should trim+parse)", cfg.EvalAmountCents)
	}
	if cfg.EvalCurrency != "usd" {
		t.Errorf("EvalCurrency = %q, want usd (padded value should trim+lowercase)", cfg.EvalCurrency)
	}
}

func TestLoadConfig_EvalProductsRequireAmount(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("EVAL_PRODUCT_IDS", "prod_eval_a")
	// EVAL_AMOUNT_CENTS unset → must error: a configured eval product without a
	// fixed expected amount would let any amount through.
	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error when eval products configured without EVAL_AMOUNT_CENTS")
	}
}

func TestLoadConfig_EvalInvalidAmount(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("EVAL_PRODUCT_IDS", "prod_eval_a")
	t.Setenv("EVAL_AMOUNT_CENTS", "not-a-number")
	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for invalid EVAL_AMOUNT_CENTS")
	}
}

func TestLoadConfig_SubscriptionProductsConfigured(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("SUBSCRIPTION_PRODUCTS", "prod_pro:pro:month:2900:USD, prod_ent:enterprise:year:990000:usd")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.SubscriptionProducts) != 2 {
		t.Fatalf("SubscriptionProducts = %v, want 2 entries", cfg.SubscriptionProducts)
	}
	if got := cfg.SubscriptionProducts[0]; got.ProductID != "prod_pro" || got.Tier != tierPro || got.Interval != testIntervalMonth || got.AmountCents != 2900 || got.Currency != "usd" {
		t.Fatalf("first SubscriptionProduct = %+v", got)
	}
}

func TestLoadConfig_SubscriptionProductsRequiredAndUnique(t *testing.T) {
	t.Run("required", func(t *testing.T) {
		setRequiredConfigEnv(t)
		t.Setenv("SUBSCRIPTION_PRODUCTS", "")
		if _, err := LoadConfig(); err == nil {
			t.Fatal("LoadConfig accepted an empty subscription allowlist")
		}
	})
	t.Run("unique product IDs", func(t *testing.T) {
		setRequiredConfigEnv(t)
		t.Setenv("SUBSCRIPTION_PRODUCTS", "prod_pro:pro:month:2900:usd,prod_pro:pro:year:29000:usd")
		if _, err := LoadConfig(); err == nil {
			t.Fatal("LoadConfig accepted duplicate subscription product IDs")
		}
	})
}

func TestLoadConfig_OrderProducts(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("ORDER_PRODUCTS", "prod_trial:TRIAL:100:USD")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.OrderProducts) != 1 {
		t.Fatalf("OrderProducts = %+v, want one product", cfg.OrderProducts)
	}
	if got := cfg.OrderProducts[0]; got.ProductID != "prod_trial" || got.Tier != tierTrial || got.AmountCents != 100 || got.Currency != "usd" {
		t.Fatalf("OrderProducts[0] = %+v", got)
	}
}

func TestLoadConfig_OrderProductsRejectMalformed(t *testing.T) {
	for _, value := range []string{
		"prod_only",
		":trial:100:usd",
		"prod_trial:pro:100:usd",
		"prod_trial:trial:0:usd",
		"prod_trial:trial:not-money:usd",
		"prod_trial:trial:100:",
		"prod_trial:trial:100:usd,prod_trial:trial:100:usd",
	} {
		t.Run(value, func(t *testing.T) {
			setRequiredConfigEnv(t)
			t.Setenv("ORDER_PRODUCTS", value)
			if _, err := LoadConfig(); err == nil {
				t.Fatal("LoadConfig accepted malformed ORDER_PRODUCTS")
			}
		})
	}
}

func TestLoadConfig_SubscriptionProductsRejectMalformed(t *testing.T) {
	tests := []struct {
		name string
		env  string
	}{
		{name: "missing fields", env: "prod_only"},
		{name: "bad amount", env: "prod_pro:pro:month:not-money:usd"},
		{name: "invalid tier", env: "prod_eval:enterprise_eval:month:500000:usd"},
		{name: "missing interval", env: "prod_pro:pro::2900:usd"},
		{name: "missing currency", env: "prod_pro:pro:month:2900:"},
		{name: "empty product id", env: ":pro:month:2900:usd"},
		{name: "zero amount", env: "prod_pro:pro:month:0:usd"},
		{name: "negative amount", env: "prod_pro:pro:month:-2900:usd"},
		// trial and enterprise_eval are one-time purchases handled by the order
		// path, so they must not be accepted as recurring subscription products.
		{name: "one-time trial tier", env: "prod_trial:trial:month:4900:usd"},
		{name: "unknown tier", env: "prod_x:platinum:month:2900:usd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredConfigEnv(t)
			t.Setenv("SUBSCRIPTION_PRODUCTS", tt.env)
			if _, err := LoadConfig(); err == nil {
				t.Fatal("expected malformed SUBSCRIPTION_PRODUCTS to fail config load")
			}
		})
	}
}

func TestLoadConfig_ZeroFoundingCap(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_CAP", "0")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Zero is valid (means no founding slots at all).
	if cfg.FoundingProCap != 0 {
		t.Errorf("FoundingProCap = %d, want 0", cfg.FoundingProCap)
	}
}
