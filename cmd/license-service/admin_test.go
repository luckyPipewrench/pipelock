//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/licenseservice"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/rs/zerolog"
)

// setAdminEnv wires the env the admin subcommands' adminHandler() reads via
// LoadConfig: a token signing key, a matching root-signed intermediate cert, a
// CRL signing key, and a writable DB/ledger path. The intermediate cert is
// signed for the token key's public half, satisfying NewWebhookHandler's
// signing-key consistency check.
func setAdminEnv(t *testing.T) (tokenKeyPath, crlKeyPath string, crlPub ed25519.PublicKey) {
	t.Helper()
	tokenPub, tokenKeyPath := writeServiceTestKey(t, "token")
	certPath := writeServiceTestIntermediate(t, tokenPub)
	crlPub, crlKeyPath = writeServiceTestKey(t, "crl")
	dir := t.TempDir()
	t.Setenv("POLAR_WEBHOOK_SECRET", "whsec_"+"dGVzdA==")
	t.Setenv("POLAR_API_TOKEN", "polar_"+"test")
	t.Setenv("PIPELOCK_LICENSE_KEY_PATH", tokenKeyPath)
	t.Setenv("PIPELOCK_LICENSE_INTERMEDIATE_FILE", certPath)
	t.Setenv("PIPELOCK_LICENSE_CRL_SIGNING_KEY_PATH", crlKeyPath)
	t.Setenv("RESEND_API_KEY", "re_"+"test")
	t.Setenv("DB_PATH", filepath.Join(dir, "licenses.db"))
	t.Setenv("LEDGER_PATH", filepath.Join(dir, "audit.jsonl"))
	return tokenKeyPath, crlKeyPath, crlPub
}

func discardLog() zerolog.Logger { return zerolog.New(io.Discard) }

func TestRunRevokeIntermediate(t *testing.T) {
	t.Run("happy_path_revokes_and_publishes", func(t *testing.T) {
		setAdminEnv(t)
		if err := runRevokeIntermediate(discardLog(), []string{"--serial", "im-admin-1", "--reason", "rotated"}); err != nil {
			t.Fatalf("runRevokeIntermediate: %v", err)
		}
		// Reopen the same handler and confirm the next SignedCRL carries the serial,
		// proving the admin command actually persisted the revocation.
		handler, cleanup, err := adminHandler(context.Background(), discardLog())
		if err != nil {
			t.Fatalf("adminHandler: %v", err)
		}
		defer cleanup()
		crl, err := handler.SignedCRL(context.Background(), time.Now())
		if err != nil {
			t.Fatalf("SignedCRL: %v", err)
		}
		found := false
		for _, ri := range crl.Payload.RevokedIntermediates {
			if ri.Serial == "im-admin-1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("published CRL must carry the revoked serial, got %+v", crl.Payload.RevokedIntermediates)
		}
	})

	t.Run("missing_serial_errors", func(t *testing.T) {
		setAdminEnv(t)
		if err := runRevokeIntermediate(discardLog(), []string{"--reason", "x"}); err == nil {
			t.Fatal("missing --serial must error")
		}
	})

	t.Run("bad_flag_errors", func(t *testing.T) {
		setAdminEnv(t)
		if err := runRevokeIntermediate(discardLog(), []string{"--nope"}); err == nil {
			t.Fatal("unknown flag must error")
		}
	})

	t.Run("config_load_failure_errors", func(t *testing.T) {
		// No env set -> LoadConfig fails closed (missing required secrets).
		clearLicenseServiceEnv(t)
		if err := runRevokeIntermediate(discardLog(), []string{"--serial", "im-x"}); err == nil {
			t.Fatal("missing config must error")
		}
	})
}

func TestRunRecoverCRLGeneration(t *testing.T) {
	t.Run("happy_path_recovers_high_water", func(t *testing.T) {
		_, crlKeyPath, _ := setAdminEnv(t)

		// Emit a real signed CRL (generation advances) and write it to disk as the
		// "last published" CRL the operator feeds to recovery.
		handler, cleanup, err := adminHandler(context.Background(), discardLog())
		if err != nil {
			t.Fatalf("adminHandler: %v", err)
		}
		published, err := handler.SignedCRL(context.Background(), time.Now())
		if err != nil {
			t.Fatalf("SignedCRL: %v", err)
		}
		cleanup()

		crlBytes, err := json.Marshal(published)
		if err != nil {
			t.Fatalf("marshal CRL: %v", err)
		}
		crlPath := filepath.Join(t.TempDir(), "published-crl.json")
		if err := os.WriteFile(crlPath, crlBytes, 0o600); err != nil {
			t.Fatalf("write CRL: %v", err)
		}
		_ = crlKeyPath

		if err := runRecoverCRLGeneration(discardLog(), []string{"--crl", crlPath}); err != nil {
			t.Fatalf("runRecoverCRLGeneration: %v", err)
		}
	})

	t.Run("missing_crl_flag_errors", func(t *testing.T) {
		setAdminEnv(t)
		if err := runRecoverCRLGeneration(discardLog(), []string{}); err == nil {
			t.Fatal("missing --crl must error")
		}
	})

	t.Run("unreadable_crl_path_errors", func(t *testing.T) {
		setAdminEnv(t)
		if err := runRecoverCRLGeneration(discardLog(), []string{"--crl", filepath.Join(t.TempDir(), "nope.json")}); err == nil {
			t.Fatal("missing CRL file must error")
		}
	})

	t.Run("forged_crl_rejected", func(t *testing.T) {
		setAdminEnv(t)
		// A CRL signed by an unrelated key must not move the high-water.
		_, attackerPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		forged, err := license.SignCRL(license.CRLPayload{
			Version:    license.CRLVersion,
			Generation: 9_999_999,
			IssuedAt:   time.Now().Add(-time.Hour).Unix(),
			ExpiresAt:  time.Now().Add(time.Hour).Unix(),
		}, attackerPriv)
		if err != nil {
			t.Fatalf("sign forged: %v", err)
		}
		data, err := json.Marshal(forged)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		p := filepath.Join(t.TempDir(), "forged.json")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("write forged: %v", err)
		}
		if err := runRecoverCRLGeneration(discardLog(), []string{"--crl", p}); err == nil {
			t.Fatal("forged CRL must be rejected for recovery")
		}
	})

	t.Run("config_load_failure_errors", func(t *testing.T) {
		clearLicenseServiceEnv(t)
		p := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := runRecoverCRLGeneration(discardLog(), []string{"--crl", p}); err == nil {
			t.Fatal("missing config must error")
		}
	})
}

func TestDispatchAdmin(t *testing.T) {
	swapArgs := func(t *testing.T, args ...string) {
		t.Helper()
		orig := os.Args
		os.Args = append([]string{"license-service"}, args...)
		t.Cleanup(func() { os.Args = orig })
	}

	t.Run("not_an_admin_subcommand_returns_unhandled", func(t *testing.T) {
		swapArgs(t, "serve")
		handled, err := dispatchAdmin(discardLog())
		if handled || err != nil {
			t.Fatalf("serve must not be handled by dispatchAdmin: handled=%v err=%v", handled, err)
		}
	})

	t.Run("no_args_returns_unhandled", func(t *testing.T) {
		swapArgs(t)
		handled, err := dispatchAdmin(discardLog())
		if handled || err != nil {
			t.Fatalf("no args must not be handled: handled=%v err=%v", handled, err)
		}
	})

	t.Run("revoke_intermediate_dispatched", func(t *testing.T) {
		setAdminEnv(t)
		swapArgs(t, "revoke-intermediate", "--serial", "im-dispatch-1")
		handled, err := dispatchAdmin(discardLog())
		if !handled {
			t.Fatal("revoke-intermediate must be handled")
		}
		if err != nil {
			t.Fatalf("dispatch err: %v", err)
		}
	})

	t.Run("recover_dispatched_and_surfaces_error", func(t *testing.T) {
		setAdminEnv(t)
		// recover-crl-generation with a missing --crl: handled=true, err!=nil.
		swapArgs(t, "recover-crl-generation")
		handled, err := dispatchAdmin(discardLog())
		if !handled {
			t.Fatal("recover-crl-generation must be handled")
		}
		if err == nil {
			t.Fatal("missing --crl must surface an error through dispatch")
		}
	})
}

func TestLoadSigningKeyHelpers(t *testing.T) {
	t.Run("loadSigningKey_happy", func(t *testing.T) {
		tokenPub, keyPath := writeServiceTestKey(t, "token")
		certPath := writeServiceTestIntermediate(t, tokenPub)
		cfg := &licenseservice.Config{PrivateKeyPath: keyPath, IntermediateCertPath: certPath}
		priv, err := loadSigningKey(cfg)
		if err != nil {
			t.Fatalf("loadSigningKey: %v", err)
		}
		if len(priv) != ed25519.PrivateKeySize {
			t.Fatalf("priv key size = %d", len(priv))
		}
		if len(cfg.IntermediateCert) == 0 {
			t.Fatal("loadSigningKey must populate cfg.IntermediateCert")
		}
	})

	t.Run("loadSigningKey_missing_key_errors", func(t *testing.T) {
		cfg := &licenseservice.Config{PrivateKeyPath: filepath.Join(t.TempDir(), "nope.key")}
		if _, err := loadSigningKey(cfg); err == nil {
			t.Fatal("missing signing key must error")
		}
	})

	t.Run("loadSigningKey_missing_intermediate_errors", func(t *testing.T) {
		_, keyPath := writeServiceTestKey(t, "token")
		cfg := &licenseservice.Config{
			PrivateKeyPath:       keyPath,
			IntermediateCertPath: filepath.Join(t.TempDir(), "nope.json"),
		}
		if _, err := loadSigningKey(cfg); err == nil {
			t.Fatal("missing intermediate cert must error")
		}
	})

	t.Run("loadCRLSigningKey_unset_is_noop", func(t *testing.T) {
		cfg := &licenseservice.Config{}
		if err := loadCRLSigningKey(cfg); err != nil {
			t.Fatalf("unset CRL key path must be a no-op, got %v", err)
		}
		if cfg.CRLPrivateKey != nil {
			t.Fatal("unset CRL key path must leave CRLPrivateKey nil")
		}
	})

	t.Run("loadCRLSigningKey_loads_when_set", func(t *testing.T) {
		_, crlKeyPath := writeServiceTestKey(t, "crl")
		cfg := &licenseservice.Config{CRLSigningKeyPath: crlKeyPath}
		if err := loadCRLSigningKey(cfg); err != nil {
			t.Fatalf("loadCRLSigningKey: %v", err)
		}
		if len(cfg.CRLPrivateKey) != ed25519.PrivateKeySize {
			t.Fatal("CRLPrivateKey must be populated")
		}
	})

	t.Run("loadCRLSigningKey_missing_file_errors", func(t *testing.T) {
		cfg := &licenseservice.Config{CRLSigningKeyPath: filepath.Join(t.TempDir(), "nope.key")}
		if err := loadCRLSigningKey(cfg); err == nil {
			t.Fatal("missing CRL key file must error")
		}
	})
}

func TestAdminHandler_FailurePaths(t *testing.T) {
	t.Run("signing_key_load_failure", func(t *testing.T) {
		// Config loads (required secrets present) but the token signing key path
		// points at a missing file, so adminHandler fails inside loadSigningKey.
		setAdminEnv(t)
		t.Setenv("PIPELOCK_LICENSE_KEY_PATH", filepath.Join(t.TempDir(), "missing-token.key"))
		_, _, err := adminHandler(context.Background(), discardLog())
		if err == nil {
			t.Fatal("adminHandler must fail when the signing key cannot be loaded")
		}
	})

	t.Run("audit_ledger_open_failure", func(t *testing.T) {
		// Point the ledger at a path whose parent does not exist so OpenAuditLedger
		// fails AFTER the DB opened — exercising the db.Close() cleanup branch.
		setAdminEnv(t)
		t.Setenv("LEDGER_PATH", filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl"))
		_, _, err := adminHandler(context.Background(), discardLog())
		if err == nil {
			t.Fatal("adminHandler must fail when the audit ledger cannot be opened")
		}
	})
}

// clearLicenseServiceEnv blanks every env var LoadConfig reads so a test can
// exercise the config-load failure path deterministically regardless of the
// ambient environment.
func clearLicenseServiceEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"POLAR_WEBHOOK_SECRET", "POLAR_API_TOKEN", "PIPELOCK_LICENSE_KEY_PATH",
		"PIPELOCK_LICENSE_INTERMEDIATE_FILE", "PIPELOCK_LICENSE_CRL_SIGNING_KEY_PATH",
		"RESEND_API_KEY", "DB_PATH", "LEDGER_PATH",
	} {
		t.Setenv(k, "")
	}
}
