//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/licenseservice"
	"github.com/rs/zerolog"
)

// adminSubcommands are the offline admin operations the license-service binary
// supports in addition to serving. They open the same DB the daemon uses and
// mutate revocation / high-water state without bringing up the HTTP server, so
// an operator can run them as one-shot jobs against the live database.
var adminSubcommands = map[string]bool{
	"revoke-intermediate":     true,
	"revoke-imported-license": true,
	"recover-crl-generation":  true,
	"import-issuance":         true,
	"list-imported-issuances": true,
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
	case "revoke-imported-license":
		return true, runRevokeImportedLicense(log, args)
	case "recover-crl-generation":
		return true, runRecoverCRLGeneration(log, args)
	case "import-issuance":
		return true, runImportIssuance(log, args)
	case "list-imported-issuances":
		return true, runListImportedIssuances(log, args)
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

func runRevokeImportedLicense(log zerolog.Logger, args []string) error {
	fs := flag.NewFlagSet("revoke-imported-license", flag.ContinueOnError)
	licenseID := fs.String("license-id", "", "imported break-glass license id to revoke (required)")
	reason := fs.String("reason", "operator_revoked", "human-readable revocation reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *licenseID == "" {
		return errors.New("--license-id is required")
	}
	ctx := context.Background()
	handler, cleanup, err := adminHandler(ctx, log)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := handler.RevokeImportedIssuance(ctx, *licenseID, *reason, time.Now()); err != nil {
		return fmt.Errorf("revoke imported license: %w", err)
	}
	log.Info().Str("license_id", *licenseID).Str("reason", *reason).Msg("imported license revoked; next published CRL will carry it")
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

// runImportIssuance imports a SIGNED issuance export (produced by
// `pipelock license issue --break-glass --export`) into the durable signed
// import table, making an externally-minted paid token revocable. It verifies
// the export's Ed25519 signature against the operator-supplied issuer public key
// (the key that minted the break-glass token) and fails closed on a bad
// signature, key-id mismatch, or malformed export. Replaying the identical
// export is an idempotent no-op; a conflicting import (a unique-key collision
// with a different record) is rejected.
func runImportIssuance(log zerolog.Logger, args []string) error {
	fs := flag.NewFlagSet("import-issuance", flag.ContinueOnError)
	exportPath := fs.String("export", "", "path to the signed issuance export file (required)")
	issuerKey := fs.String("issuer-pubkey", "", "issuer public key that signed the export: hex string or path to a .pub file (required)")
	importID := fs.String("import-id", "", "unique import id (default: a random imp_ id)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exportPath == "" {
		return errors.New("--export is required")
	}
	if *issuerKey == "" {
		return errors.New("--issuer-pubkey is required")
	}
	issuerPub, err := loadIssuerPublicKey(*issuerKey)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Clean(*exportPath)) // #nosec G304 -- operator-supplied admin path
	if err != nil {
		return fmt.Errorf("read export %s: %w", *exportPath, err)
	}
	id := *importID
	if id == "" {
		id, err = randomImportID()
		if err != nil {
			return err
		}
	}

	ctx := context.Background()
	handler, cleanup, err := adminHandler(ctx, log)
	if err != nil {
		return err
	}
	defer cleanup()

	payload, outcome, importErr := handler.ImportSignedIssuance(ctx, data, issuerPub, id, time.Now())
	switch outcome {
	case licenseservice.ImportOutcomeImported:
		log.Info().
			Str("license_id", payload.LicenseID).
			Str("import_id", id).
			Msg("issuance imported; token is now revocable via the CRL")
		return nil
	case licenseservice.ImportOutcomeReplay:
		log.Info().
			Str("license_id", payload.LicenseID).
			Str("import_id", id).
			Msg("issuance already imported (idempotent no-op)")
		return nil
	case licenseservice.ImportOutcomeConflict:
		// Rejected, fail closed. Surface as an error so the operator sees a
		// non-zero exit and does not assume the token was recorded.
		return fmt.Errorf("import rejected: %w", importErr)
	default:
		return fmt.Errorf("import issuance: %w", importErr)
	}
}

// runListImportedIssuances prints every externally-minted issuance recorded in
// the import table so an operator can SEE the revocation surface, not just the
// Go methods. Output is one line per record with the load-bearing fields.
func runListImportedIssuances(log zerolog.Logger, args []string) error {
	fs := flag.NewFlagSet("list-imported-issuances", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	handler, cleanup, err := adminHandler(ctx, log)
	if err != nil {
		return err
	}
	defer cleanup()

	records, err := handler.ListImportedIssuances(ctx)
	if err != nil {
		return fmt.Errorf("list imported issuances: %w", err)
	}
	if len(records) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "no imported issuances")
		return nil
	}
	for _, r := range records {
		expires := "never"
		if r.ExpiresAt != nil {
			expires = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(os.Stdout,
			"license_id=%s import_id=%s issuer_key_id=%s sub=%s issued=%s expires=%s token_sha256=%s imported=%s\n",
			r.LicenseID, r.ImportID, r.IssuerKeyID, r.SubscriptionID,
			r.IssuedAt.UTC().Format(time.RFC3339), expires, r.TokenSHA256,
			r.ImportedAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// loadIssuerPublicKey resolves the issuer public key from either a hex string
// (64 hex chars = 32-byte Ed25519 key) or a path to a .pub file containing the
// hex-encoded key. Fails closed on any malformed input.
func loadIssuerPublicKey(spec string) (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(spec)
	// Treat it as a hex key first; if that fails and it looks like a path, read
	// the file and try again.
	if key, err := decodeEd25519PublicHex(raw); err == nil {
		return key, nil
	}
	data, readErr := os.ReadFile(filepath.Clean(raw)) // #nosec G304 -- operator-supplied admin path
	if readErr != nil {
		return nil, fmt.Errorf("issuer-pubkey is neither a valid hex key nor a readable file: %w", readErr)
	}
	key, err := decodeEd25519PublicHex(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("issuer-pubkey file %s does not contain a valid hex Ed25519 public key: %w", raw, err)
	}
	return key, nil
}

func decodeEd25519PublicHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte Ed25519 public key, got %d bytes", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// randomImportID generates a unique import id (imp_ + 12 hex chars).
func randomImportID() (string, error) {
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("generate import id: %w", err)
	}
	return "imp_" + hex.EncodeToString(idBytes), nil
}
