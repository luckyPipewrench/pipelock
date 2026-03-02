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
	const expectedEntries = 19
	if len(techniqueMap) != expectedEntries {
		t.Errorf("techniqueMap has %d entries, expected %d (was an entry added or removed?)", len(techniqueMap), expectedEntries)
	}
}
