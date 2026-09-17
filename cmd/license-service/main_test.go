//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/licenseservice"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/rs/zerolog"
)

func writeServiceTestIntermediate(t *testing.T, intermediatePub ed25519.PublicKey) (string, ed25519.PublicKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	now := time.Now().UTC()
	im, err := license.SignIntermediate(license.IntermediatePayload{
		Serial:    "im_cmd_test",
		Purpose:   license.PurposeLicenseSigning,
		Algorithm: license.AlgorithmEd25519,
		PublicKey: hex.EncodeToString(intermediatePub),
		NotBefore: now.Add(-time.Minute).Unix(),
		NotAfter:  now.Add(90 * 24 * time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Minute).Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}
	data, err := json.Marshal(im)
	if err != nil {
		t.Fatalf("Marshal intermediate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "intermediate.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write intermediate: %v", err)
	}
	return path, rootPub
}

func writeServiceTestKey(t *testing.T, name string) (ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name+".key")
	if err := signing.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("SavePrivateKey(%s): %v", name, err)
	}
	return pub, path
}

func setServiceRunEnv(t *testing.T, keyPath, certPath string) {
	t.Helper()
	t.Setenv("POLAR_WEBHOOK_SECRET", "whsec_"+"dGVzdA==")
	t.Setenv("POLAR_API_TOKEN", "polar_"+"test")
	t.Setenv("PIPELOCK_LICENSE_KEY_PATH", keyPath)
	t.Setenv("PIPELOCK_LICENSE_INTERMEDIATE_FILE", certPath)
	t.Setenv("RESEND_API_KEY", "re_"+"test")
	t.Setenv("SUBSCRIPTION_PRODUCTS", "prod_test:pro:month:2900:usd")
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "missing-parent", "licenses.db"))
}

func TestRun_LoadsIntermediateAndCRLKeysBeforeDatabaseOpen(t *testing.T) {
	pub, keyPath := writeServiceTestKey(t, "token")
	certPath, rootPub := writeServiceTestIntermediate(t, pub)
	_, crlKeyPath := writeServiceTestKey(t, "crl")
	setServiceRunEnv(t, keyPath, certPath)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(rootPub))
	t.Setenv("PIPELOCK_LICENSE_CRL_SIGNING_KEY_PATH", crlKeyPath)

	err := run(zerolog.New(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "open database") {
		t.Fatalf("run() error = %v, want database open failure after key/cert loading", err)
	}
}

func TestRun_LoadIntermediateFailure(t *testing.T) {
	_, keyPath := writeServiceTestKey(t, "token")
	setServiceRunEnv(t, keyPath, filepath.Join(t.TempDir(), "missing-intermediate.json"))

	err := run(zerolog.New(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "load intermediate certificate") {
		t.Fatalf("run() error = %v, want intermediate load failure", err)
	}
}

func TestRun_LoadCRLSigningKeyFailure(t *testing.T) {
	pub, keyPath := writeServiceTestKey(t, "token")
	certPath, rootPub := writeServiceTestIntermediate(t, pub)
	setServiceRunEnv(t, keyPath, certPath)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(rootPub))
	t.Setenv("PIPELOCK_LICENSE_CRL_SIGNING_KEY_PATH", filepath.Join(t.TempDir(), "missing-crl.key"))

	err := run(zerolog.New(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "load CRL signing key") {
		t.Fatalf("run() error = %v, want CRL key load failure", err)
	}
}

func TestRun_ReportsTrialSlotExpiryDrift(t *testing.T) {
	pub, keyPath := writeServiceTestKey(t, "token")
	certPath, rootPub := writeServiceTestIntermediate(t, pub)
	dbPath := filepath.Join(t.TempDir(), "licenses.db")
	seedTrialSlotExpiryReport(t, dbPath)
	setServiceRunEnv(t, keyPath, certPath)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(rootPub))
	t.Setenv("DB_PATH", dbPath)
	t.Setenv("LEDGER_PATH", filepath.Join(t.TempDir(), "missing-parent", "audit.jsonl"))

	var buf bytes.Buffer
	err := run(zerolog.New(&buf))
	if err == nil || !strings.Contains(err.Error(), "open audit ledger") {
		t.Fatalf("run() error = %v, want audit-ledger open failure after reporting", err)
	}
	for _, want := range []string{
		"slot_drifted",
		"trial slot expiry disagrees with its entitlement's claim-time expiry",
		"slot_unverifiable",
		"trial slot expiry drift report has unverifiable legacy rows",
		"slot_orphaned",
		"trial slot has no owning entitlement",
	} {
		if got := buf.String(); !strings.Contains(got, want) {
			t.Errorf("startup report = %s, want %q", got, want)
		}
	}
}

func TestReportTrialSlotExpiryDrift(t *testing.T) {
	tests := []struct {
		name string
		seed func(t *testing.T, dbPath string)
		want []string
	}{
		{
			name: "reports each unsafe slot category",
			seed: seedTrialSlotExpiryReport,
			want: []string{
				"slot_drifted",
				"trial slot expiry disagrees with its entitlement's claim-time expiry",
				"slot_unverifiable",
				"trial slot expiry drift report has unverifiable legacy rows",
				"slot_orphaned",
				"trial slot has no owning entitlement",
			},
		},
		{name: "clean database is quiet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "licenses.db")
			if tt.seed != nil {
				tt.seed(t, dbPath)
			}
			db, err := licenseservice.OpenEntitlementDB(t.Context(), dbPath)
			if err != nil {
				t.Fatalf("open entitlement database: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Reporting is diagnostic and must never repair: an
			// implementation that rewrote an expiry, reassigned an owner, or
			// dropped a row before logging would satisfy every log assertion
			// below while silently changing who holds a trial.
			before := readTrialSlotRows(t, dbPath)

			var buf bytes.Buffer
			reportTrialSlotExpiryDrift(t.Context(), db, zerolog.New(&buf))

			if after := readTrialSlotRows(t, dbPath); after != before {
				t.Fatalf("drift reporting modified slots:\nbefore:\n%safter:\n%s", before, after)
			}
			if len(tt.want) == 0 {
				if got := buf.String(); got != "" {
					t.Fatalf("clean startup report = %q, want no output", got)
				}
				return
			}
			for _, want := range tt.want {
				if got := buf.String(); !strings.Contains(got, want) {
					t.Errorf("startup report = %s, want %q", got, want)
				}
			}
		})
	}
}

// readTrialSlotRows returns every active trial slot as comparable text so a
// caller can assert the rows are byte-identical before and after an operation.
func readTrialSlotRows(t *testing.T, dbPath string) string {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open database for slot snapshot: %v", err)
	}
	defer func() { _ = raw.Close() }()
	rows, err := raw.QueryContext(t.Context(),
		`SELECT normalized_email, subscription_id, expires_at, takeover_state,
			COALESCE(legacy_entitlement_expires_at, '')
		 FROM active_trial_slots ORDER BY normalized_email`)
	if err != nil {
		t.Fatalf("read trial slot rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out strings.Builder
	for rows.Next() {
		var email, sub, expires, state, legacy string
		if err := rows.Scan(&email, &sub, &expires, &state, &legacy); err != nil {
			t.Fatalf("scan trial slot row: %v", err)
		}
		fmt.Fprintf(&out, "%s|%s|%s|%s|%s\n", email, sub, expires, state, legacy)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate trial slot rows: %v", err)
	}
	return out.String()
}

func seedTrialSlotExpiryReport(t *testing.T, dbPath string) {
	t.Helper()
	db, err := licenseservice.OpenEntitlementDB(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("open seed entitlement database: %v", err)
	}
	expiresAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, subscriptionID := range []string{"slot_drifted", "slot_unverifiable"} {
		ent := &licenseservice.Entitlement{
			SubscriptionID:   subscriptionID,
			CustomerEmail:    subscriptionID + "@example.com",
			ProductID:        "prod_trial",
			Tier:             "trial",
			BillingInterval:  "one_time",
			Status:           "active",
			CurrentPeriodEnd: expiresAt,
			Features:         "[]",
		}
		if subscriptionID == "slot_drifted" {
			ent.LastLicensePeriodEnd = &expiresAt
		}
		if err := db.Upsert(t.Context(), ent); err != nil {
			t.Fatalf("seed %s: %v", subscriptionID, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seeded entitlement database: %v", err)
	}

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open seeded database directly: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.ExecContext(t.Context(), `UPDATE active_trial_slots SET expires_at = ?, takeover_state = 'unclassified' WHERE subscription_id = ?`, expiresAt.Add(-time.Hour), "slot_drifted"); err != nil {
		t.Fatalf("drift slot expiry: %v", err)
	}
	if _, err := raw.ExecContext(t.Context(), `UPDATE entitlements SET tier = ? WHERE subscription_id = ?`, "pro", "slot_unverifiable"); err != nil {
		t.Fatalf("make owner unverifiable: %v", err)
	}
	if _, err := raw.ExecContext(t.Context(), `UPDATE active_trial_slots SET takeover_state = 'unclassified' WHERE subscription_id = ?`, "slot_unverifiable"); err != nil {
		t.Fatalf("mark unverifiable slot for legacy classification: %v", err)
	}
	if _, err := raw.ExecContext(t.Context(), `INSERT INTO active_trial_slots (normalized_email, subscription_id, expires_at) VALUES (?, ?, ?)`, "slot_orphaned@example.com", "slot_orphaned", expiresAt); err != nil {
		t.Fatalf("seed orphaned slot: %v", err)
	}
}
