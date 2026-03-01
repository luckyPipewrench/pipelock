package audit

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

	// Application layer protocol abuse (scanner pipeline layers 1-2)
	"blocklist": "T1071.001", // Application Layer Protocol: Web Protocols
	"allowlist": "T1071.001", // Domain not in allowlist
	"scheme":    "T1071",     // Application Layer Protocol (non-HTTP scheme)
	"redirect":  "T1071.001", // Redirect to blocked domain

	// Command and scripting interpreter (response-side / MCP)
	"response_scan": "T1059", // Command and Scripting Interpreter (prompt injection)
	"policy":        "T1059", // Tool policy violation

	// Exploitation / parsing
	"parser": "T1190", // Exploit Public-Facing Application

	// Supply chain (MCP tool inventory)
	"mcp_unknown_tool": "T1195.002", // Supply Chain Compromise: Software Supply Chain

	// Session behavioral anomaly
	"session_anomaly": "T1078", // Valid Accounts (anomalous session behavior)
}

// TechniqueForScanner returns the MITRE ATT&CK technique ID for a scanner
// or event label. Returns an empty string if no mapping exists (defensive
// events, operational warnings, unknown labels).
func TechniqueForScanner(scanner string) string {
	return techniqueMap[scanner]
}
