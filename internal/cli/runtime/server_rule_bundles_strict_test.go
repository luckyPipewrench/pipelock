// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestStrictRuleBundleIntegrityError exercises the shared fail-closed decision
// used by both the main server startup path and `pipelock mcp proxy`: strict
// mode refuses to start only on installed-bundle INTEGRITY loss, never on
// availability failures, and only when the operator has not opted into
// rules.allow_degraded.
func TestStrictRuleBundleIntegrityError(t *testing.T) {
	t.Parallel()

	integrity := rules.BundleError{Name: "pipelock-standard", Reason: "hash mismatch", Class: rules.BundleErrorClassIntegrity}
	availability := rules.BundleError{Name: "community", Reason: "requires future feature", Class: rules.BundleErrorClassAvailability}

	tests := []struct {
		name         string
		mode         string
		allowDegrade bool
		result       *rules.LoadResult
		wantErr      bool
		wantContains []string
		wantAbsent   []string
	}{
		{name: "nil result", mode: config.ModeStrict, result: nil, wantErr: false},
		{name: "non-strict integrity tolerated", mode: config.ModeBalanced, result: &rules.LoadResult{Errors: []rules.BundleError{integrity}}, wantErr: false},
		{name: "strict allow_degraded tolerated", mode: config.ModeStrict, allowDegrade: true, result: &rules.LoadResult{Errors: []rules.BundleError{integrity}}, wantErr: false},
		{name: "strict availability-only tolerated", mode: config.ModeStrict, result: &rules.LoadResult{Errors: []rules.BundleError{availability}}, wantErr: false},
		{name: "strict no errors", mode: config.ModeStrict, result: &rules.LoadResult{}, wantErr: false},
		{
			name: "strict integrity refuses", mode: config.ModeStrict,
			result:       &rules.LoadResult{Errors: []rules.BundleError{integrity}},
			wantErr:      true,
			wantContains: []string{"strict mode", "pipelock-standard: hash mismatch", "allow_degraded"},
		},
		{
			name: "strict mixed names only integrity", mode: config.ModeStrict,
			result:       &rules.LoadResult{Errors: []rules.BundleError{integrity, availability}},
			wantErr:      true,
			wantContains: []string{"pipelock-standard: hash mismatch"},
			wantAbsent:   []string{"community"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Mode = tt.mode
			cfg.Rules.AllowDegraded = tt.allowDegrade

			err := strictRuleBundleIntegrityError(cfg, tt.result)
			if tt.wantErr != (err != nil) {
				t.Fatalf("strictRuleBundleIntegrityError err = %v, wantErr = %v", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want substring %q", err.Error(), want)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(err.Error(), absent) {
					t.Errorf("error = %q, must not mention availability-only failure %q", err.Error(), absent)
				}
			}
		})
	}
}

// TestStrictRuleBundleIntegrityError_RealBundleLoad proves the decision against
// a real rules.MergeIntoConfig load of an installed bundle whose lock file is
// missing (an integrity failure), matching exactly what the runtime feeds the
// helper. Strict refuses; balanced and strict+allow_degraded tolerate.
func TestStrictRuleBundleIntegrityError_RealBundleLoad(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, "pipelock-standard")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// bundle.yaml present but bundle.lock absent => integrity-class load error.
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), []byte("name: pipelock-standard\nversion: 2026.01.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Rules.RulesDir = rulesDir
	result := rules.MergeIntoConfig(cfg, "3.0.0")
	if len(result.IntegrityErrors()) == 0 {
		t.Fatalf("expected an integrity-class load error, got errors: %+v", result.Errors)
	}

	cfg.Mode = config.ModeStrict
	if err := strictRuleBundleIntegrityError(cfg, result); err == nil {
		t.Fatal("strict mode must refuse a real integrity-failed bundle load")
	} else if !strings.Contains(err.Error(), "pipelock-standard") {
		t.Fatalf("error = %q, want the failing bundle named", err.Error())
	}

	cfg.Mode = config.ModeBalanced
	if err := strictRuleBundleIntegrityError(cfg, result); err != nil {
		t.Fatalf("balanced mode must tolerate a degraded bundle, got %v", err)
	}

	cfg.Mode = config.ModeStrict
	cfg.Rules.AllowDegraded = true
	if err := strictRuleBundleIntegrityError(cfg, result); err != nil {
		t.Fatalf("strict + allow_degraded must tolerate, got %v", err)
	}
}

func TestStrictRuleBundleIntegrityError_DisabledEmbeddedKeysFailClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	origDefault := rules.DefaultKeyringHex
	origKeyring := rules.KeyringHex
	rules.DefaultKeyringHex = ""
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() {
		rules.DefaultKeyringHex = origDefault
		rules.KeyringHex = origKeyring
	})

	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, "private-root-only")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	bundleData := []byte(fmt.Sprintf("format_version: 2\nname: private-root-only\nversion: 2026.01.1\nauthor: test\n"+
		"description: test bundle\n"+
		"tier: community\nmonotonic_version: 1\npublished_at: 2026-01-01T00:00:00Z\n"+
		"expires_at: 2036-01-01T00:00:00Z\nkey_id: %s\nrules: []\n", rules.KeyFingerprint(pub)))
	bundlePath := filepath.Join(bundleDir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		t.Fatal(err)
	}
	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("SaveSignature: %v", err)
	}
	hash := sha256.Sum256(bundleData)
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), &rules.LockFile{
		InstalledVersion:  "2026.01.1",
		Source:            "test",
		BundleSHA256:      hex.EncodeToString(hash[:]),
		SignerFingerprint: rules.KeyFingerprint(pub),
	}); err != nil {
		t.Fatalf("WriteLockFile: %v", err)
	}

	cfg := config.Defaults()
	cfg.Mode = config.ModeStrict
	cfg.Rules.RulesDir = rulesDir
	cfg.Rules.TrustEmbeddedKeys = false
	result := rules.MergeIntoConfig(cfg, "3.0.0")
	if len(result.IntegrityErrors()) == 0 {
		t.Fatalf("expected disabled embedded key to produce integrity error, got errors: %+v", result.Errors)
	}
	if reason := result.IntegrityErrors()[0].Reason; !strings.Contains(reason, "no matching signer") {
		t.Fatalf("integrity error reason = %q, want no matching signer", reason)
	}
	if err := strictRuleBundleIntegrityError(cfg, result); err == nil {
		t.Fatal("strict mode must refuse startup when embedded keys are disabled and no trusted key verifies the bundle")
	}
}
