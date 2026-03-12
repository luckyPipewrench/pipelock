//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package main is the entry point for the Pipelock license service.
// It loads configuration from environment variables, initializes all
// subsystems (SQLite, signing key, Polar client, Resend client, audit
// ledger), and starts the HTTP server with graceful shutdown.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/licenseservice"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/rs/zerolog"
)

// shutdownTimeout is the maximum time allowed for graceful shutdown.
// 10 seconds lets in-flight webhook processing complete.
const shutdownTimeout = 10 * time.Second

func main() {
	// Structured logging to stdout (matches pipelock convention).
	log := zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = os.Stderr
		w.TimeFormat = time.RFC3339
	})).With().Timestamp().Str("service", "license-service").Logger()

	if err := run(log); err != nil {
		log.Fatal().Err(err).Msg("license service failed")
	}
}

func run(log zerolog.Logger) error {
	// Load configuration from environment.
	cfg, err := licenseservice.LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Load the Ed25519 private key for signing license tokens.
	// Uses the same key format as `pipelock license keygen`.
	privateKey, err := signing.LoadPrivateKeyFile(cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}
	log.Info().Str("key_path", cfg.PrivateKeyPath).Msg("signing key loaded")

	// Open SQLite entitlement database (runs migrations).
	db, err := licenseservice.OpenEntitlementDB(context.Background(), cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	log.Info().Str("db_path", cfg.DBPath).Msg("entitlement database ready")

	// Open the append-only audit ledger.
	ledger, err := licenseservice.OpenAuditLedger(cfg.LedgerPath)
	if err != nil {
		return fmt.Errorf("open audit ledger: %w", err)
	}
	defer func() { _ = ledger.Close() }()
	log.Info().Str("ledger_path", cfg.LedgerPath).Msg("audit ledger ready")

	// Create subsystem clients.
	polar := licenseservice.NewPolarClient(cfg.PolarAPIToken, cfg.PolarAPIBase)
	email := licenseservice.NewEmailSender(cfg.ResendAPIKey, cfg.FromEmail)

	// Create the webhook handler (loads founding count from DB).
	handler, err := licenseservice.NewWebhookHandler(cfg, db, polar, email, ledger, privateKey, log)
	if err != nil {
		return fmt.Errorf("create webhook handler: %w", err)
	}

	// Create the HTTP server.
	srv := licenseservice.NewServer(cfg, handler, ledger, log)

	// Start the refresh cron in the background.
	cronCtx, cronCancel := context.WithCancel(context.Background())
	defer cronCancel()

	cron := licenseservice.NewRefreshCron(handler, db, ledger, log)
	go cron.Run(cronCtx)

	// Graceful shutdown on SIGTERM/SIGINT.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %w", err)
		}
	}

	// Stop the refresh cron.
	cronCancel()

	// Graceful HTTP shutdown.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	log.Info().Msg("license service stopped")
	return nil
}
