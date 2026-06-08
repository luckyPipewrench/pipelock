// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !enterprise

package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestScanRequestBody_NamedAgentAddressAllowlistIgnoredWithoutFeatureAgents(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = config.ActionBlock
	cfg.AddressProtection.UnknownAction = config.ActionAllow
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4
	eth := true
	f := false
	cfg.AddressProtection.Chains.ETH = &eth
	cfg.AddressProtection.Chains.BTC = &f
	cfg.AddressProtection.Chains.SOL = &f
	cfg.AddressProtection.Chains.BNB = &f
	cfg.Agents = map[string]config.AgentProfile{
		"trader": {
			AllowedAddresses: []string{
				"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e",
			},
		},
	}
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024

	sc := scanner.New(cfg)
	defer sc.Close()

	body := `{"to": "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1024 * 1024,
		Scanner:     sc,
		AgentID:     "trader",
	})
	if !result.Clean {
		t.Fatalf("unlicensed named-agent allowed_addresses affected body scan: %+v", result)
	}
	if len(result.AddressFindings) != 0 {
		t.Fatalf("unlicensed named-agent allowed_addresses produced findings: %+v", result.AddressFindings)
	}
}
