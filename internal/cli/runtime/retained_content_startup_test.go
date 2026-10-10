// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// retainedActorPattern matches only the actor every receipt carries, so the
// emitter's retained-content check trips while no traffic is involved.
const retainedActorPattern = "^pipelock$"

// Retained content is a configuration refusal on every startup path, even
// when receipts are optional: a single-chain MCP proxy must not start with
// receipts quietly disabled.
func TestMCPStartupRefusesRetainedContent(t *testing.T) {
	_, keyPath := writeReceiptSigningKey(t)
	evidenceDir := filepath.Join(t.TempDir(), "evidence")
	configPath := writeMCPProxyConfig(t, evidenceDir, keyPath, true)
	f, err := os.OpenFile(filepath.Clean(configPath), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("dlp:\n  patterns:\n    - name: retained actor\n      regex: \"" + retainedActorPattern + "\"\n      severity: high\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := runMCPProxyCommand(t, configPath)
	if err == nil || !strings.Contains(err.Error(), "configuration content trips the receipt detector") {
		t.Fatalf("mcp proxy err = %v, want a retained-content refusal\nstderr:\n%s", err, stderr)
	}
	if strings.Contains(stderr, "chain could not be resumed") {
		t.Fatalf("retained content reported as a chain-resume fault:\n%s", stderr)
	}
}

func TestGuardSetupRefusesRetainedContentWithoutRequiredReceipts(t *testing.T) {
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "evidence")
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.Redact = true
	cfg.FlightRecorder.RequireReceipts = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "retained actor", Regex: retainedActorPattern, Severity: config.SeverityHigh})
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)

	evidence, err := newGuardEvidence(t.Context(), cfg, sc, metrics.New(), io.Discard)
	if evidence != nil {
		t.Cleanup(evidence.close)
	}
	if !errors.Is(err, receipt.ErrRetainedContent) {
		t.Fatalf("Guard setup err = %v, want a retained-content refusal", err)
	}
	if strings.Contains(err.Error(), "pipelock\"") {
		t.Fatalf("refusal echoes the retained value: %v", err)
	}
}
