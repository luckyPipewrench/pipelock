// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"regexp"
	"testing"
)

// techniqueIDPattern matches MITRE ATT&CK technique IDs: T#### or T####.###.
var techniqueIDPattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func TestTechniqueForScanner_AllMappedEntries(t *testing.T) {
	tests := []struct {
		scanner   string
		technique string
	}{
		// Exfiltration
		{"dlp", "T1048"},
		{"entropy", "T1048"},
		{"subdomain_entropy", "T1048"},
		{"length", "T1048"},
		{"path_entropy", "T1048"},
		{"env_leak", "T1048"},

		// Data transfer limits
		{"databudget", "T1030"},
		{"ratelimit", "T1030"},

		// URL injection (scanner pipeline layers 2-3)
		{"crlf_injection", "T1190"},
		{"path_traversal", "T1083"},

		// SSRF
		{"ssrf", "T1046"},

		// Application layer protocol
		{"blocklist", "T1071.001"},
		{"allowlist", "T1071.001"},
		{"scheme", "T1071"},
		{"redirect", "T1071.001"},

		// Command/scripting interpreter
		{"response_scan", "T1059"},
		{"policy", "T1059"},

		// WebSocket transport
		{"ws_protocol", "T1071"},

		// Exploitation
		{"parser", "T1190"},

		// Supply chain
		{"mcp_unknown_tool", "T1195.002"},

		// Session anomaly
		{"session_anomaly", "T1078"},

		// Domain fronting
		{"sni_mismatch", "T1090.004"},

		// Request body/header DLP
		{"body_dlp", "T1048"},
		{"header_dlp", "T1048"},

		// TLS interception
		{"tls_intercept", "T1557"},
		{"tls_response_blocked", "T1659"},
		{"tls_authority_mismatch", "T1090.004"},
		{"tls_handshake_error", "T1573"},

		// Chain detection
		{"chain_detection", "T1059"},

		// Persistence
		{"persist", "T1053"},
	}

	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			got := TechniqueForScanner(tt.scanner)
			if got != tt.technique {
				t.Errorf("TechniqueForScanner(%q) = %q, want %q", tt.scanner, got, tt.technique)
			}
		})
	}
}

func TestTechniqueForChainPattern_PersistReturnsT1053(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{"write-persist", "T1053"},
		{"persist-callback", "T1053"},
		{"Write-Persist", "T1053"},
		{"PERSIST-CALLBACK", "T1053"},
		{"custom-persist-chain", "T1053"},
		{"exfil_then_delete", "T1059"},
		{"read-then-exec", "T1059"},
		{"env-exfil", "T1059"},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := TechniqueForChainPattern(tt.pattern)
			if got != tt.want {
				t.Errorf("TechniqueForChainPattern(%q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestTechniqueForScanner_UnknownReturnsEmpty(t *testing.T) {
	unknowns := []string{
		"",
		"nonexistent",
		"kill_switch_deny",
		"adaptive_escalation",
		"config_reload",
		"startup",
		"readability",
	}

	for _, scanner := range unknowns {
		t.Run(scanner, func(t *testing.T) {
			got := TechniqueForScanner(scanner)
			if got != "" {
				t.Errorf("TechniqueForScanner(%q) = %q, want empty string", scanner, got)
			}
		})
	}
}

func TestTechniqueMap_AllValuesAreValidFormat(t *testing.T) {
	for scanner, technique := range techniqueMap {
		t.Run(scanner, func(t *testing.T) {
			if !techniqueIDPattern.MatchString(technique) {
				t.Errorf("techniqueMap[%q] = %q, not a valid MITRE ATT&CK technique ID (expected T####[.###])", scanner, technique)
			}
		})
	}
}

func TestTechniqueMap_NoDuplicateKeys(t *testing.T) {
	// This test is a compile-time guarantee in Go (duplicate map keys are a
	// compile error), but we verify the map has the expected number of entries
	// to catch accidental deletions during refactoring.
	const expectedEntries = 31
	if len(techniqueMap) != expectedEntries {
		t.Errorf("techniqueMap has %d entries, expected %d (was an entry added or removed?)", len(techniqueMap), expectedEntries)
	}
}
