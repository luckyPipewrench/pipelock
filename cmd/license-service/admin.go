//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/licenseservice"
	"github.com/rs/zerolog"
)

// adminSubcommands are the offline admin operations the license-service binary
// supports in addition to serving. They open the same DB the daemon uses and
// mutate revocation / high-water state without bringing up the HTTP server, so
// an operator can run them as one-shot jobs against the live database.
var adminSubcommands = map[string]bool{
	"revoke-intermediate":    true,
	"recover-crl-generation": true,
}

// dispatchAdmin runs an admin subcommand if os.Args names one, returning
// (handled, error). When handled is false the caller falls through to the normal
// serve path.
func dispatchAdmin(log zerolog.Logger) (bool, error) {
	if len(os.Args) < 2 || !adminSubcommands[os.Args[1]] {
		return false, nil
	}
	sub := os.Args[1]
	args := os.Args[2:]
	switch sub {
	case "revoke-intermediate":
		return true, runRevokeIntermediate(log, args)
	case "recover-crl-generation":
		return true, runRecoverCRLGeneration(log, args)
	default:
		return true, fmt.Errorf("unknown admin subcommand %q", sub)
	}
}

// adminHandler builds a webhook handler wired to the live DB + ledger, exactly
// as run() does, so admin operations share the same construction (and the same
// intermediate-signing-key consistency check).
func adminHandler(ctx context.Context, log zerolog.Logger) (*licenseservice.WebhookHandler, func(), error) {
	cfg, err := licenseservice.LoadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	privateKey, err := loadSigningKey(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := loadCRLSigningKey(cfg); err != nil {
		return nil, nil, err
	}
	db, err := licenseservice.OpenEntitlementDB(ctx, cfg.DBPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	ledger, err := licenseservice.OpenAuditLedger(cfg.LedgerPath)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("open audit ledger: %w", err)
	}
	polar := licenseservice.NewPolarClient(cfg.PolarAPIToken, cfg.PolarAPIBase)
	email := licenseservice.NewEmailSender(cfg.ResendAPIKey, cfg.FromEmail)
	handler, err := licenseservice.NewWebhookHandler(cfg, db, polar, email, ledger, privateKey, log)
	if err != nil {
		_ = db.Close()
		_ = ledger.Close()
		return nil, nil, fmt.Errorf("create webhook handler: %w", err)
	}
	cleanup := func() {
		_ = db.Close()
		_ = ledger.Close()
	}
	return handler, cleanup, nil
}

func runRevokeIntermediate(log zerolog.Logger, args []string) error {
	fs := flag.NewFlagSet("revoke-intermediate", flag.ContinueOnError)
	serial := fs.String("serial", "", "intermediate certificate serial to revoke (required)")
	reason := fs.String("reason", "rotated", "human-readable revocation reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serial == "" {
		return errors.New("--serial is required")
	}
	ctx := context.Background()
	handler, cleanup, err := adminHandler(ctx, log)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := handler.RevokeIntermediate(ctx, *serial, *reason, time.Now()); err != nil {
		return fmt.Errorf("revoke intermediate: %w", err)
	}
	log.Info().Str("serial", *serial).Str("reason", *reason).Msg("intermediate revoked; next published CRL will carry it")
	return nil
}

func runRecoverCRLGeneration(log zerolog.Logger, args []string) error {
	fs := flag.NewFlagSet("recover-crl-generation", flag.ContinueOnError)
	crlPath := fs.String("crl", "", "path to the last PUBLISHED signed CRL to recover the high-water from (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *crlPath == "" {
		return errors.New("--crl is required")
	}
	data, err := os.ReadFile(*crlPath) // #nosec G304 -- operator-supplied admin path
	if err != nil {
		return fmt.Errorf("read CRL %s: %w", *crlPath, err)
	}
	ctx := context.Background()
	handler, cleanup, err := adminHandler(ctx, log)
	if err != nil {
		return err
	}
	defer cleanup()
	recovered, err := handler.RecoverCRLGenerationFromSignedCRL(ctx, data)
	if err != nil {
		return fmt.Errorf("recover CRL generation: %w", err)
	}
	log.Info().Uint64("generation", recovered).Msg("CRL generation high-water recovered; next CRL will be strictly higher")
	return nil
}
