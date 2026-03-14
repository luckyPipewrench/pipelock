// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import "strings"

// techniqueMap maps scanner/event labels to MITRE ATT&CK technique IDs.
// Scanner labels come from scanner.Result.Scanner (e.g. "dlp", "ssrf") and
// from hardcoded event-specific values (e.g. "response_scan", "mcp_unknown_tool").
//
// Technique IDs follow the format T####[.###] (base or sub-technique).
// Defensive events (kill switch deny, adaptive escalation, config reload) have
// no technique mapping because they represent operator actions, not attacks.
var techniqueMap = map[string]string{
	// Exfiltration techniques (scanner pipeline layers 2-5, 8-9)
	"dlp":               "T1048", // Exfiltration Over Alternative Protocol
	"entropy":           "T1048", // High-entropy data in URL path
	"subdomain_entropy": "T1048", // DNS subdomain exfiltration
	"length":            "T1048", // Oversized URL exfiltration
	"databudget":        "T1030", // Data Transfer Size Limits
	"ratelimit":         "T1030", // Data Transfer Size Limits (burst)
	"path_entropy":      "T1048", // Path-based entropy exfiltration
	"env_leak":          "T1048", // Environment variable exfiltration

	// Network discovery / SSRF (scanner pipeline layer 6)
	"ssrf": "T1046", // Network Service Discovery

	// URL injection (scanner pipeline layers 2-3)
	"crlf_injection": "T1190", // Exploit Public-Facing Application (header injection)
	"path_traversal": "T1083", // File and Directory Discovery

	// Application layer protocol abuse (scanner pipeline layers 4-5)
	"blocklist": "T1071.001", // Application Layer Protocol: Web Protocols
	"allowlist": "T1071.001", // Domain not in allowlist
	"scheme":    "T1071",     // Application Layer Protocol (non-HTTP scheme)
	"redirect":  "T1071.001", // Redirect to blocked domain

	// Command and scripting interpreter (response-side / MCP)
	"response_scan": "T1059", // Command and Scripting Interpreter (prompt injection)
	"policy":        "T1059", // MCP tool policy violation

	// WebSocket transport protocol enforcement
	"ws_protocol": "T1071", // Application Layer Protocol (binary frame / fragment violation)

	// Exploitation / parsing
	"parser":  "T1190", // Exploit Public-Facing Application
	"context": "T1190", // Exploit Public-Facing Application (cancelled/nil request context)

	// Supply chain (MCP tool inventory)
	"mcp_unknown_tool": "T1195.002", // Supply Chain Compromise: Software Supply Chain

	// Session behavioral anomaly
	"session_anomaly": "T1078", // Valid Accounts (anomalous session behavior)

	// Domain fronting (SNI mismatch)
	"sni_mismatch": "T1090.004", // Proxy: Domain Fronting

	// Request body/header DLP (forward proxy + TLS interception)
	"body_dlp":   "T1048", // Exfiltration Over Alternative Protocol
	"header_dlp": "T1048", // Exfiltration via HTTP headers

	// TLS interception events
	"tls_intercept":          "T1557",     // Adversary-in-the-Middle
	"tls_response_blocked":   "T1659",     // Content Injection
	"tls_authority_mismatch": "T1090.004", // Proxy: Domain Fronting
	"tls_handshake_error":    "T1573",     // Encrypted Channel

	// Tool call chain pattern detection
	"chain_detection": "T1059", // Command and Scripting Interpreter (multi-step attack chain)

	// Persistence techniques (policy + chain detection)
	"persist": "T1053", // Scheduled Task/Job (cron, systemd, launchd)
}

// TechniqueForScanner returns the MITRE ATT&CK technique ID for a scanner
// or event label. Returns an empty string if no mapping exists (defensive
// events, operational warnings, unknown labels).
func TechniqueForScanner(scanner string) string {
	return techniqueMap[scanner]
}

// persistChainPatterns lists built-in chain pattern names that map to T1053.
var persistChainPatterns = map[string]bool{
	"write-persist":    true,
	"persist-callback": true,
}

// TechniqueForChainPattern returns the MITRE ATT&CK technique ID for a
// chain detection pattern. Built-in persistence patterns and any custom
// pattern whose name contains "persist" map to T1053 (Scheduled Task/Job);
// all others fall back to T1059 (Command and Scripting Interpreter).
func TechniqueForChainPattern(pattern string) string {
	lower := strings.ToLower(pattern)
	if persistChainPatterns[lower] || strings.Contains(lower, "persist") {
		return techniqueMap["persist"]
	}
	return techniqueMap["chain_detection"]
}
