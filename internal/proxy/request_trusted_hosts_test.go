// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const trustedHostsTestDestination = "api.vendor.example"

func requestTrustedHostsTestConfig() *config.Config {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	return cfg
}

func redactedCriticalDLPResult() BodyScanResult {
	return BodyScanResult{
		DLPMatches:      []scanner.TextDLPMatch{{PatternName: "AWS Access ID", Severity: config.SeverityCritical}},
		Action:          config.ActionWarn,
		RedactedDLPOnly: true,
		RedactionReport: &redact.Report{Applied: true, TotalRedactions: 1},
	}
}

// The response-scanning exemption list describes inbound trust and is
// documented as never loosening outbound controls. Naming a destination there
// must leave both request-side hard blocks in force.
func TestRequestHardBlocks_IgnoreResponseExemptDomains(t *testing.T) {
	cfg := requestTrustedHostsTestConfig()
	cfg.ResponseScanning.ExemptDomains = []string{trustedHostsTestDestination}

	injection := BodyScanResult{InjectionMatches: []scanner.ResponseMatch{{PatternName: "instruction"}}}
	if !shouldHardBlockBodyPromptInjection(injection, trustedHostsTestDestination, cfg) {
		t.Fatal("response_scanning.exempt_domains downgraded a request-body injection hard block")
	}
	if !shouldHardBlockBodyCriticalDLP(redactedCriticalDLPResult(), trustedHostsTestDestination, cfg) {
		t.Fatal("response_scanning.exempt_domains downgraded the redacted critical DLP hard block")
	}
}

// request_body_scanning.trusted_hosts is the request-side list: on a trusted
// destination both escalations fall back to the configured action.
func TestRequestHardBlocks_HonorTrustedHosts(t *testing.T) {
	for _, entry := range []string{trustedHostsTestDestination, "*.vendor.example", "API.Vendor.Example"} {
		t.Run(entry, func(t *testing.T) {
			cfg := requestTrustedHostsTestConfig()
			cfg.RequestBodyScanning.TrustedHosts = []string{entry}

			injection := BodyScanResult{InjectionMatches: []scanner.ResponseMatch{{PatternName: "instruction"}}}
			if shouldHardBlockBodyPromptInjection(injection, trustedHostsTestDestination, cfg) {
				t.Fatal("trusted host still hard-blocked request-body injection")
			}
			if shouldHardBlockBodyCriticalDLP(redactedCriticalDLPResult(), trustedHostsTestDestination, cfg) {
				t.Fatal("trusted host still hard-blocked fully redacted critical DLP")
			}
		})
	}
}

// Trust is exact to the listed destination and never widens to another host,
// and a redacted result that is not fully redacted keeps the hard block.
func TestRequestHardBlocks_TrustedHostsStayNarrow(t *testing.T) {
	cfg := requestTrustedHostsTestConfig()
	cfg.RequestBodyScanning.TrustedHosts = []string{trustedHostsTestDestination}

	injection := BodyScanResult{InjectionMatches: []scanner.ResponseMatch{{PatternName: "instruction"}}}
	if !shouldHardBlockBodyPromptInjection(injection, "other.vendor.example", cfg) {
		t.Fatal("trust leaked to an unlisted destination for injection")
	}
	if !shouldHardBlockBodyCriticalDLP(redactedCriticalDLPResult(), "other.vendor.example", cfg) {
		t.Fatal("trust leaked to an unlisted destination for redacted DLP")
	}
	partial := redactedCriticalDLPResult()
	partial.RedactedDLPOnly = false
	if !shouldHardBlockBodyCriticalDLP(partial, trustedHostsTestDestination, cfg) {
		t.Fatal("a critical DLP finding that was not fully redacted must still hard block on a trusted host")
	}
	if !shouldHardBlockBodyPromptInjection(injection, trustedHostsTestDestination, nil) {
		t.Fatal("nil config must fail closed")
	}
}
