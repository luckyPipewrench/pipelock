// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadPrivateKeyFileForPurpose(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "receipt.json")
	data, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"purpose":        PurposeReceiptSigning,
		"public":         hex.EncodeToString(pub),
		"private":        hex.EncodeToString(priv),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(jsonPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	legacyPath := filepath.Join(dir, "legacy.key")
	if err := SavePrivateKey(priv, legacyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	t.Run("matching purpose", func(t *testing.T) {
		loaded, err := LoadPrivateKeyFileForPurpose(jsonPath, PurposeReceiptSigning)
		if err != nil {
			t.Fatalf("matching purpose rejected: %v", err)
		}
		if !loaded.Equal(priv) {
			t.Fatal("loaded private key differs")
		}
	})
	t.Run("wrong purpose", func(t *testing.T) {
		if _, err := LoadPrivateKeyFileForPurpose(jsonPath, PurposeRosterRoot); err == nil ||
			!strings.Contains(err.Error(), `purpose mismatch: file="receipt-signing" expected="roster-root"`) {
			t.Fatalf("wrong-purpose error = %v", err)
		}
	})
	t.Run("generic loading", func(t *testing.T) {
		if _, err := LoadPrivateKeyFile(jsonPath); err != nil {
			t.Fatalf("generic loader must preserve existing behavior: %v", err)
		}
	})
	t.Run("legacy compatibility", func(t *testing.T) {
		if _, err := LoadPrivateKeyFileForPurpose(legacyPath, PurposeReceiptSigning); err != nil {
			t.Fatalf("legacy purpose-less key rejected: %v", err)
		}
	})
	t.Run("strict legacy rejection", func(t *testing.T) {
		if _, err := LoadPrivateKeyFileForPurposeStrict(legacyPath, PurposeReceiptSigning); err == nil ||
			!strings.Contains(err.Error(), "purpose-bound JSON private key required") {
			t.Fatalf("strict legacy-key error = %v", err)
		}
	})
	t.Run("strict matching purpose", func(t *testing.T) {
		if _, err := LoadPrivateKeyFileForPurposeStrict(jsonPath, PurposeReceiptSigning); err != nil {
			t.Fatalf("strict matching-purpose key rejected: %v", err)
		}
	})
	t.Run("contained symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privileges on Windows")
		}
		linkPath := filepath.Join(dir, "receipt-link.json")
		if err := os.Symlink(filepath.Base(jsonPath), linkPath); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if _, err := LoadPrivateKeyFileForPurpose(linkPath, PurposeReceiptSigning); err != nil {
			t.Fatalf("contained Kubernetes-style symlink rejected: %v", err)
		}
	})
}

func TestDecodePrivateKeyForPurposeRejectsMissingPurpose(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"private":        hex.EncodeToString(priv),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := DecodePrivateKeyForPurpose(string(data), PurposeReceiptSigning); err == nil ||
		!strings.Contains(err.Error(), `purpose mismatch: file="" expected="receipt-signing"`) {
		t.Fatalf("missing-purpose error = %v", err)
	}
}
