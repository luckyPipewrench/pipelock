//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// TestLegalHoldCmd_StoreErrorsPropagate proves the legal-hold subcommands surface
// store-level errors through RunE rather than swallowing them.
func TestLegalHoldCmd_StoreErrorsPropagate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))

	store := filepath.Join(t.TempDir(), "holds.json")

	run := func(t *testing.T, args ...string) error {
		t.Helper()
		cmd := legalHoldCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		return cmd.Execute()
	}

	t.Run("release of missing hold propagates not-found", func(t *testing.T) {
		err := run(t, "release", "--store", store, "--id", "missing")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("release = %v, want propagated not-found error", err)
		}
	})

	t.Run("duplicate add propagates store error", func(t *testing.T) {
		if err := run(t, "add", "--store", store, "--id", "hold-a", "--scope", "agent-a", "--reason", "review"); err != nil {
			t.Fatalf("first add: %v", err)
		}
		err := run(t, "add", "--store", store, "--id", "hold-a", "--scope", "agent-a", "--reason", "review")
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate add = %v, want propagated duplicate-id store error", err)
		}
	})
}
