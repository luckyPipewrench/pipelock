package preflight

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/projectscan"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Compiled regexes (package-level, compiled once).
var (
	shellMetaRe      = regexp.MustCompile(`[|&;` + "`" + `]|\$\(|&&|\|\|`)
	networkExfilRe   = regexp.MustCompile(`(?i)\b(curl|wget|nc|netcat|ncat|socat|ssh)\b`)
	encodingRe       = regexp.MustCompile(`(?i)\b(base64|xxd|eval|exec)\b`)
	credAccessRe     = regexp.MustCompile(`(?i)(\.ssh[/\\]|\.aws[/\\]|\.env\b|\.netrc|/etc/passwd|\.gnupg|\.kube[/\\])`)
	npxAutoInstallRe = regexp.MustCompile(`(?i)\bnpx\s+(-y|--yes)\b`)
	base64PaddedRe   = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	hexEscapeRe      = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	secretEnvNameRe  = regexp.MustCompile(`(?i)(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AUTH)`)
)

// standardAnthropicHosts are legitimate Anthropic API hostnames.
// Checked with exact match or valid subdomain boundary (not substring).
var standardAnthropicHosts = []string{
	"api.anthropic.com",
	"anthropic.com",
}

// checkHookCommand inspects a single hook/statusline command for Classes A + E.
func checkHookCommand(cmd, filePath, context string) []projectscan.Finding {
	if cmd == "" {
		return nil
	}
	var findings []projectscan.Finding

	// Class A: Hook RCE
	if shellMetaRe.MatchString(cmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevCritical,
			Category: CatHookRCE,
			Message:  fmt.Sprintf("shell metacharacters in %s command: %s", context, truncate(cmd, 80)),
			File:     filePath,
		})
	}
	if networkExfilRe.MatchString(cmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevCritical,
			Category: CatHookRCE,
			Message:  fmt.Sprintf("network exfiltration tool in %s command: %s", context, truncate(cmd, 80)),
			File:     filePath,
		})
	}
	if credAccessRe.MatchString(cmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevCritical,
			Category: CatHookRCE,
			Message:  fmt.Sprintf("credential path access in %s command: %s", context, truncate(cmd, 80)),
			File:     filePath,
		})
	}
	if encodingRe.MatchString(cmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevCritical,
			Category: CatHookRCE,
			Message:  fmt.Sprintf("encoding/eval in %s command: %s", context, truncate(cmd, 80)),
			File:     filePath,
		})
	}

	// Class E: Obfuscation (warning severity, entropy-gated)
	findings = append(findings, checkObfuscation(cmd, filePath)...)

	return findings
}

// checkMCPServer inspects a single MCP server definition for Class B.
func checkMCPServer(name string, server mcpServerDef, filePath string) []projectscan.Finding {
	var findings []projectscan.Finding

	// Combine command + args for full analysis
	fullCmd := server.Command
	if len(server.Args) > 0 {
		fullCmd += " " + strings.Join(server.Args, " ")
	}

	// Class B: MCP Server RCE
	if shellMetaRe.MatchString(fullCmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevCritical,
			Category: CatMCPServerRCE,
			Message:  fmt.Sprintf("shell metacharacters in MCP server %q: %s", name, truncate(fullCmd, 80)),
			File:     filePath,
		})
	}
	if npxAutoInstallRe.MatchString(fullCmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevCritical,
			Category: CatMCPServerRCE,
			Message:  fmt.Sprintf("npx auto-install (-y) in MCP server %q: %s", name, truncate(fullCmd, 80)),
			File:     filePath,
		})
	}
	if networkExfilRe.MatchString(fullCmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevCritical,
			Category: CatMCPServerRCE,
			Message:  fmt.Sprintf("network tool in MCP server %q: %s", name, truncate(fullCmd, 80)),
			File:     filePath,
		})
	}

	// Absolute path alone = info (hardened practice), NOT critical.
	// Only escalate if combined with risky indicators (already caught above).
	if strings.HasPrefix(server.Command, "/") &&
		!shellMetaRe.MatchString(fullCmd) &&
		!networkExfilRe.MatchString(fullCmd) {
		findings = append(findings, projectscan.Finding{
			Severity: SevInfo,
			Category: CatMCPServerRCE,
			Message:  fmt.Sprintf("absolute path in MCP server %q command: %s", name, truncate(server.Command, 80)),
			File:     filePath,
		})
	}

	// Class E: Obfuscation
	findings = append(findings, checkObfuscation(fullCmd, filePath)...)

	// Check env vars on this server
	findings = append(findings, checkEnvVarsRaw(server.Env, filePath, fmt.Sprintf("MCP server %q", name))...)

	return findings
}

// checkEnvVarsRaw inspects env vars (from json.RawMessage map) for Class C.
func checkEnvVarsRaw(env map[string]json.RawMessage, filePath, context string) []projectscan.Finding {
	if len(env) == 0 {
		return nil
	}
	var findings []projectscan.Finding

	for name, raw := range env {
		value := rawToString(raw)

		// ANTHROPIC_BASE_URL redirect
		if strings.EqualFold(name, "ANTHROPIC_BASE_URL") || strings.EqualFold(name, "ANTHROPIC_API_BASE") {
			if !isStandardAnthropicURL(value) {
				findings = append(findings, projectscan.Finding{
					Severity: SevCritical,
					Category: CatCredRedirect,
					Message:  fmt.Sprintf("API base URL redirect in %s: %s=%s", context, name, truncate(value, 60)),
					File:     filePath,
				})
			}
		}

		// High-entropy value in secret-named env var
		if secretEnvNameRe.MatchString(name) && len(value) >= 16 {
			entropy := scanner.ShannonEntropy(value)
			if entropy > 4.0 {
				findings = append(findings, projectscan.Finding{
					Severity: SevCritical,
					Category: CatCredRedirect,
					Message:  fmt.Sprintf("high-entropy value in secret-named env var in %s: %s (entropy %.1f)", context, name, entropy),
					File:     filePath,
				})
			}
		}
	}

	return findings
}

// checkAutoApproval inspects raw Claude settings bytes for Class D.
func checkAutoApproval(data []byte, filePath string) []projectscan.Finding {
	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil // parse errors handled by caller
	}
	var findings []projectscan.Finding

	if settings.EnableAllProjectMcpServers {
		findings = append(findings, projectscan.Finding{
			Severity: SevHigh,
			Category: CatAutoApproval,
			Message:  "enableAllProjectMcpServers is true: all project MCP servers auto-approved",
			File:     filePath,
		})
	}
	if len(settings.EnabledMcpServers) > 0 {
		findings = append(findings, projectscan.Finding{
			Severity: SevHigh,
			Category: CatAutoApproval,
			Message:  fmt.Sprintf("enabledMcpServers pre-approves %d server(s): %s", len(settings.EnabledMcpServers), strings.Join(settings.EnabledMcpServers, ", ")),
			File:     filePath,
		})
	}

	return findings
}

// checkObfuscation checks for encoding-based evasion (Class E).
// Severity: warning (not high). Entropy-gated to reduce false positives.
func checkObfuscation(s, filePath string) []projectscan.Finding {
	var findings []projectscan.Finding

	// Base64: only flag if entropy > 4.5 AND length > 40 (regex enforces >= 40)
	if matches := base64PaddedRe.FindAllString(s, -1); len(matches) > 0 {
		for _, m := range matches {
			if scanner.ShannonEntropy(m) > 4.5 {
				findings = append(findings, projectscan.Finding{
					Severity: SevWarning,
					Category: CatObfuscation,
					Message:  fmt.Sprintf("possible base64-encoded payload: %s", truncate(m, 40)),
					File:     filePath,
				})
				break // one per string is enough
			}
		}
	}

	// Hex escapes
	if hexEscapeRe.MatchString(s) {
		findings = append(findings, projectscan.Finding{
			Severity: SevWarning,
			Category: CatObfuscation,
			Message:  fmt.Sprintf("hex escape sequences detected: %s", truncate(s, 60)),
			File:     filePath,
		})
	}

	return findings
}

// --- Helpers ---

// rawToString coerces a json.RawMessage to a string.
// Handles: "string", 123, true, null.
func rawToString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Non-string JSON value: return the raw representation
	return strings.TrimSpace(string(raw))
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// isStandardAnthropicURL checks if a URL points to a legitimate Anthropic host.
// Uses parsed hostname matching, NOT substring matching.
// Prevents bypass via attacker domains like api.anthropic.com.attacker.tld.
func isStandardAnthropicURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	// Ensure URL has a scheme for proper parsing
	u := rawURL
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}

	parsed, err := url.Parse(u)
	if err != nil || parsed.Hostname() == "" {
		return false
	}

	// Reject non-HTTPS schemes (HTTP downgrade attack)
	if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	for _, trusted := range standardAnthropicHosts {
		// Exact match
		if host == trusted {
			return true
		}
		// Valid subdomain: host ends with ".trusted"
		if strings.HasSuffix(host, "."+trusted) {
			return true
		}
	}
	return false
}

// sortedKeys returns map keys in sorted order for deterministic output.
func sortedKeys(m map[string]mcpServerDef) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
