//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the license service, loaded from
// environment variables. Every secret is a reference (file path or env var),
// never a literal baked into config structs.
type Config struct {
	// PolarWebhookSecret is the HMAC secret for validating Polar webhook signatures.
	PolarWebhookSecret string

	// PolarAPIToken is the bearer token for Polar API calls.
	PolarAPIToken string

	// PrivateKeyPath is the filesystem path to the Ed25519 intermediate
	// private key used for signing license tokens. The offline root key must
	// never be deployed to the license service.
	PrivateKeyPath string

	// IntermediateCertPath is the filesystem path to the root-signed
	// intermediate certificate served beside issued tokens.
	IntermediateCertPath string

	// IntermediateCert is populated by cmd/license-service after loading
	// IntermediateCertPath. It is public certificate bytes, not a secret.
	IntermediateCert []byte

	// CRLSigningKeyPath optionally points at the root/private key used to sign
	// dynamic CRLs. Leave empty when CRLs are signed offline and distributed as
	// files. The token signing key must not be reused for CRLs.
	CRLSigningKeyPath string

	// CRLPrivateKey is populated by cmd/license-service when CRLSigningKeyPath
	// is set. It is intentionally separate from PrivateKeyPath.
	CRLPrivateKey ed25519.PrivateKey

	// ResendAPIKey is the API key for the Resend email service.
	ResendAPIKey string

	// DBPath is the filesystem path to the SQLite database file.
	DBPath string

	// LedgerPath is the filesystem path to the append-only JSONL audit ledger.
	LedgerPath string

	// FoundingProCap is the maximum number of Founding Pro subscriptions
	// that will ever be issued. Slots never reopen (canceled/refunded still count).
	FoundingProCap int

	// FoundingProDeadline is the date after which no new Founding Pro
	// subscriptions are accepted, regardless of remaining slots.
	FoundingProDeadline time.Time

	// ListenAddr is the address the HTTP server binds to.
	ListenAddr string

	// FromEmail is the sender address for license delivery emails.
	FromEmail string

	// PolarAPIBase is the base URL for the Polar API. Defaults to production.
	PolarAPIBase string

	// EvalProductIDs is the allowlist of Polar product IDs that fulfill the
	// Enterprise Eval. An order only mints an eval token if its product ID is in
	// this list AND its tier metadata is enterprise_eval (defense in depth against
	// metadata misconfiguration). Empty list disables eval fulfillment entirely.
	EvalProductIDs []string

	// EvalAmountCents is the exact expected order total (minor units) for an
	// Enterprise Eval purchase. A paid order whose total differs is refused.
	// Required (>0) whenever EvalProductIDs is non-empty.
	EvalAmountCents int

	// EvalCurrency is the expected ISO 4217 currency (lowercase) for an eval
	// order. Defaults to usd.
	EvalCurrency string
}

const (
	defaultListenAddr       = ":8080"
	defaultFoundingProCap   = 50
	defaultFoundingDeadline = "2026-06-30"
	defaultDBPath           = "licenses.db"
	defaultLedgerPath       = "audit.jsonl"
	defaultFromEmail        = "licenses@mail.pipelab.org"
	defaultPolarAPIBase     = "https://api.polar.sh"
	defaultEvalCurrency     = "usd"
)

// LoadConfig reads configuration from environment variables with sensible
// defaults for non-secret values. Returns an error if any required secret
// is missing.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		PolarWebhookSecret: os.Getenv("POLAR_WEBHOOK_SECRET"),
		PolarAPIToken:      os.Getenv("POLAR_API_TOKEN"),
		PrivateKeyPath:     os.Getenv("PIPELOCK_LICENSE_KEY_PATH"),
		IntermediateCertPath: os.Getenv(
			"PIPELOCK_LICENSE_INTERMEDIATE_FILE",
		),
		CRLSigningKeyPath: os.Getenv("PIPELOCK_LICENSE_CRL_SIGNING_KEY_PATH"),
		ResendAPIKey:      os.Getenv("RESEND_API_KEY"),
		DBPath:            envOrDefault("DB_PATH", defaultDBPath),
		LedgerPath:        envOrDefault("LEDGER_PATH", defaultLedgerPath),
		ListenAddr:        envOrDefault("LISTEN_ADDR", defaultListenAddr),
		FromEmail:         envOrDefault("FROM_EMAIL", defaultFromEmail),
		PolarAPIBase:      envOrDefault("POLAR_API_BASE", defaultPolarAPIBase),
	}

	// Parse founding pro cap.
	capStr := envOrDefault("FOUNDING_PRO_CAP", strconv.Itoa(defaultFoundingProCap))
	foundingCap, err := strconv.Atoi(capStr)
	if err != nil {
		return nil, fmt.Errorf("parse FOUNDING_PRO_CAP: %w", err)
	}
	if foundingCap < 0 {
		return nil, fmt.Errorf("FOUNDING_PRO_CAP must be non-negative, got %d", foundingCap)
	}
	cfg.FoundingProCap = foundingCap

	// Parse founding pro deadline.
	deadlineStr := envOrDefault("FOUNDING_PRO_DEADLINE", defaultFoundingDeadline)
	deadline, err := time.Parse(time.DateOnly, deadlineStr)
	if err != nil {
		return nil, fmt.Errorf("parse FOUNDING_PRO_DEADLINE (use YYYY-MM-DD): %w", err)
	}
	cfg.FoundingProDeadline = deadline

	// Parse Enterprise Eval fulfillment config. Eval selling is opt-in: with no
	// product IDs configured, eval orders are never fulfilled.
	cfg.EvalProductIDs = splitAndTrim(os.Getenv("EVAL_PRODUCT_IDS"))
	cfg.EvalCurrency = strings.ToLower(strings.TrimSpace(envOrDefault("EVAL_CURRENCY", defaultEvalCurrency)))
	if amountStr := strings.TrimSpace(os.Getenv("EVAL_AMOUNT_CENTS")); amountStr != "" {
		amount, err := strconv.Atoi(amountStr)
		if err != nil {
			return nil, fmt.Errorf("parse EVAL_AMOUNT_CENTS: %w", err)
		}
		if amount < 0 {
			return nil, fmt.Errorf("EVAL_AMOUNT_CENTS must be non-negative, got %d", amount)
		}
		cfg.EvalAmountCents = amount
	}
	// A configured eval product without a fixed expected amount would let any
	// paid amount through, so require a positive amount when products are set.
	if len(cfg.EvalProductIDs) > 0 && cfg.EvalAmountCents <= 0 {
		return nil, fmt.Errorf("EVAL_AMOUNT_CENTS must be set (>0) when EVAL_PRODUCT_IDS is configured")
	}

	// Validate required secrets.
	if cfg.PolarWebhookSecret == "" {
		return nil, fmt.Errorf("POLAR_WEBHOOK_SECRET is required")
	}
	if cfg.PolarAPIToken == "" {
		return nil, fmt.Errorf("POLAR_API_TOKEN is required")
	}
	if cfg.PrivateKeyPath == "" {
		return nil, fmt.Errorf("PIPELOCK_LICENSE_KEY_PATH is required (path to Ed25519 intermediate private key file)")
	}
	if cfg.IntermediateCertPath == "" {
		return nil, fmt.Errorf("PIPELOCK_LICENSE_INTERMEDIATE_FILE is required (path to root-signed intermediate certificate)")
	}
	if cfg.ResendAPIKey == "" {
		return nil, fmt.Errorf("RESEND_API_KEY is required")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// splitAndTrim splits a comma-separated env value into trimmed, non-empty
// entries. Returns nil for an empty/blank input.
func splitAndTrim(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
