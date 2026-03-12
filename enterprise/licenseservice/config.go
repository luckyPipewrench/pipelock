//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"fmt"
	"os"
	"strconv"
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

	// PrivateKeyPath is the filesystem path to the Ed25519 private key
	// used for signing license tokens.
	PrivateKeyPath string

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
}

const (
	defaultListenAddr       = ":8080"
	defaultFoundingProCap   = 50
	defaultFoundingDeadline = "2026-06-30"
	defaultDBPath           = "licenses.db"
	defaultLedgerPath       = "audit.jsonl"
	defaultFromEmail        = "licenses@pipelock.dev"
	defaultPolarAPIBase     = "https://api.polar.sh"
)

// LoadConfig reads configuration from environment variables with sensible
// defaults for non-secret values. Returns an error if any required secret
// is missing.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		PolarWebhookSecret: os.Getenv("POLAR_WEBHOOK_SECRET"),
		PolarAPIToken:      os.Getenv("POLAR_API_TOKEN"),
		PrivateKeyPath:     os.Getenv("PIPELOCK_LICENSE_KEY_PATH"),
		ResendAPIKey:       os.Getenv("RESEND_API_KEY"),
		DBPath:             envOrDefault("DB_PATH", defaultDBPath),
		LedgerPath:         envOrDefault("LEDGER_PATH", defaultLedgerPath),
		ListenAddr:         envOrDefault("LISTEN_ADDR", defaultListenAddr),
		FromEmail:          envOrDefault("FROM_EMAIL", defaultFromEmail),
		PolarAPIBase:       envOrDefault("POLAR_API_BASE", defaultPolarAPIBase),
	}

	// Parse founding pro cap.
	capStr := envOrDefault("FOUNDING_PRO_CAP", strconv.Itoa(defaultFoundingProCap))
	foundingCap, err := strconv.Atoi(capStr)
	if err != nil {
		return nil, fmt.Errorf("parse FOUNDING_PRO_CAP: %w", err)
	}
	cfg.FoundingProCap = foundingCap

	// Parse founding pro deadline.
	deadlineStr := envOrDefault("FOUNDING_PRO_DEADLINE", defaultFoundingDeadline)
	deadline, err := time.Parse(time.DateOnly, deadlineStr)
	if err != nil {
		return nil, fmt.Errorf("parse FOUNDING_PRO_DEADLINE (use YYYY-MM-DD): %w", err)
	}
	cfg.FoundingProDeadline = deadline

	// Validate required secrets.
	if cfg.PolarWebhookSecret == "" {
		return nil, fmt.Errorf("POLAR_WEBHOOK_SECRET is required")
	}
	if cfg.PolarAPIToken == "" {
		return nil, fmt.Errorf("POLAR_API_TOKEN is required")
	}
	if cfg.PrivateKeyPath == "" {
		return nil, fmt.Errorf("PIPELOCK_LICENSE_KEY_PATH is required (path to Ed25519 private key file)")
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
