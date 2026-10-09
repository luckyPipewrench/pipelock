// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlightRecorderReceiptChainsLoad(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, value string
		want        int
		invalid     bool
	}{
		{name: "omitted", want: 1},
		{name: "null", value: "null", want: 1},
		{name: "zero", value: "0"},
		{name: "one", value: "1", want: 1},
		{name: "two-inert-without-recorder", value: "2", want: 2},
		{name: "thirty-two-inert-without-recorder", value: "32", want: 32},
		{name: "negative", value: "-1", invalid: true},
		{name: "thirty-three", value: "33", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var body strings.Builder
			body.WriteString("mode: balanced\nflight_recorder:\n  enabled: true\n")
			if tc.value != "" {
				body.WriteString("  receipt_chains: " + tc.value + "\n")
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tc.invalid {
				if err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_chains") {
					t.Fatalf("Load error = %v, want receipt_chains error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.FlightRecorder.ReceiptChainCount(); got != max(tc.want, 1) {
				t.Fatalf("receipt_chains effective = %d, want %d", got, max(tc.want, 1))
			}
		})
	}
}

func TestActiveMultiChainValidation(t *testing.T) {
	cfg := Defaults()
	cfg.FlightRecorder.Dir = t.TempDir()
	cfg.FlightRecorder.ReceiptChains = 2
	cfg.FlightRecorder.SigningKeyPath = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_chains") {
		t.Fatalf("multi-chain recorder accepted: %v", err)
	}
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "receipt.key")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("signed multi-chain recorder rejected: %v", err)
	}
	cfg.FlightRecorder.Anchor.LocalLog = filepath.Join(t.TempDir(), "anchor.log")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_chains") {
		t.Fatalf("multi-chain recorder with anchor accepted: %v", err)
	}
}

func TestReceiptGroupPriorSignerKeysValidation(t *testing.T) {
	valid := strings.Repeat("ab", 32)
	for name, keys := range map[string][]string{
		"valid":     {valid},
		"malformed": {"not-a-key"},
		"uppercase": {strings.ToUpper(valid)},
		"duplicate": {valid, valid},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = keys
			err := cfg.Validate()
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				clone := cfg.Clone()
				clone.FlightRecorder.ReceiptGroupPriorSignerKeys[0] = strings.Repeat("cd", 32)
				if cfg.FlightRecorder.ReceiptGroupPriorSignerKeys[0] != valid {
					t.Fatal("clone shares prior signer key backing slice")
				}
			} else if err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_group_prior_signer_keys") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}
