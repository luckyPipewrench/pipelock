// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const redactedPlaceholder = "<redacted>"

// secretFields enumerates config fields classified as secrets by their
// semantic role. The bundle serialises a sanitised copy of the config
// where every named path is replaced with redactedPlaceholder.
//
// Rules:
//   - Private key material (CA key, signing keys, escrow keys) is NEVER
//     included — not even a placeholder. Only presence/path is recorded.
//   - High-entropy tokens and bearer credentials → redactedPlaceholder.
//   - Path fields that point to files containing secrets (LicenseFile,
//     EnrollmentTokenPath) → the path itself is kept (non-secret) but the
//     file contents are never read or included.
func redactConfig(cfg *config.Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}

	// Build a redacted shallow summary of the operator-visible config.
	// We marshal only the fields we want; we do NOT marshal the full struct
	// and strip afterwards — that risks missing a newly-added secret field.
	out := map[string]any{
		"mode": cfg.Mode,
		"fetch_proxy": map[string]any{
			"listen": cfg.FetchProxy.Listen,
		},
		"forward_proxy": map[string]any{
			"enabled": cfg.ForwardProxy.Enabled,
		},
		"mcp_ws_listener_max_connections": cfg.MCPWSListener.MaxConnections,
		"api_allowlist_count":             len(cfg.APIAllowlist),
		"blocklist_count":                 len(cfg.FetchProxy.Monitoring.Blocklist),
		"dlp": map[string]any{
			"include_defaults": cfg.DLP.IncludeDefaults,
			"pattern_count":    len(cfg.DLP.Patterns),
			"scan_env":         cfg.DLP.ScanEnv,
		},
		"response_scanning_enabled":    cfg.ResponseScanning.Enabled,
		"mcp_input_scanning_enabled":   cfg.MCPInputScanning.Enabled,
		"mcp_tool_scanning_enabled":    cfg.MCPToolScanning.Enabled,
		"mcp_tool_policy_enabled":      cfg.MCPToolPolicy.Enabled,
		"mcp_session_binding_enabled":  cfg.MCPSessionBinding.Enabled,
		"tool_chain_detection_enabled": cfg.ToolChainDetection.Enabled,
		"adaptive_enforcement_enabled": cfg.AdaptiveEnforcement.Enabled,
		"tls_interception_enabled":     cfg.TLSInterception.Enabled,
		"sandbox_enabled":              cfg.Sandbox.Enabled,
		"emit": map[string]any{
			"webhook_url": redactURL(cfg.Emit.Webhook.URL),
			"webhook_auth_token": func() string {
				if cfg.Emit.Webhook.AuthToken != "" {
					return redactedPlaceholder
				}
				return ""
			}(),
			"otlp_endpoint":  redactURL(cfg.Emit.OTLP.Endpoint),
			"otlp_headers":   redactHeaders(cfg.Emit.OTLP.Headers),
			"syslog_address": redactURL(cfg.Emit.Syslog.Address),
		},
		"kill_switch": map[string]any{
			"enabled":       cfg.KillSwitch.Enabled,
			"sentinel_file": cfg.KillSwitch.SentinelFile,
			"api_listen":    cfg.KillSwitch.APIListen,
			"api_token": func() string {
				if cfg.KillSwitch.APIToken != "" {
					return redactedPlaceholder
				}
				return ""
			}(),
		},
		"license": map[string]any{
			"license_key": func() string {
				if cfg.LicenseKey != "" {
					return redactedPlaceholder
				}
				return ""
			}(),
			// Path fields are kept; contents are never read.
			"license_file":              cfg.LicenseFile,
			"license_crl_file":          cfg.LicenseCRLFile,
			"license_intermediate_file": cfg.LicenseIntermediateFile,
			// The public key is non-secret (verification material only).
			"license_public_key": cfg.LicensePublicKey,
		},
		"tls_interception": map[string]any{
			"ca_cert": cfg.TLSInterception.CACertPath,
			// CAKeyPath is a private key — record presence only, never path.
			"ca_key_configured": cfg.TLSInterception.CAKeyPath != "",
		},
		"scan_api": map[string]any{
			"listen":              cfg.ScanAPI.Listen,
			"bearer_tokens_count": len(cfg.ScanAPI.Auth.BearerTokens),
		},
		"learn_privacy_salt_source_configured": cfg.Learn.Privacy.SaltSource != "",
		"logging": map[string]any{
			"format": cfg.Logging.Format,
			"output": cfg.Logging.Output,
			"file":   cfg.Logging.File,
		},
		"conductor": map[string]any{
			"enabled":               cfg.Conductor.Enabled,
			"enrollment_token_path": cfg.Conductor.EnrollmentTokenPath,
			// client_key_path is a private key — presence only.
			"client_key_configured": cfg.Conductor.ClientKeyPath != "",
			"audit_signing_key_id":  cfg.Conductor.AuditSigningKeyID,
		},
		"flight_recorder": map[string]any{
			"enabled": cfg.FlightRecorder.Enabled,
			// signing_key_path is a private key — presence only.
			"signing_key_configured":       cfg.FlightRecorder.SigningKeyPath != "",
			"escrow_public_key_configured": cfg.FlightRecorder.EscrowPublicKey != "",
		},
	}

	return out
}

// redactURL replaces userinfo (user:pass@) and known secret query params in
// a URL with redactedPlaceholder, then returns the sanitised URL string.
// Returns the original string unchanged if it cannot be parsed as a URL.
func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Cannot parse — redact the whole value to be safe.
		return redactedPlaceholder
	}
	// Strip userinfo (Basic auth credentials in URL).
	if u.User != nil {
		u.User = url.User("<redacted>")
	}
	// Redact known secret query params, matching param NAMES case-insensitively
	// (a key may be spelled Token or API_KEY just as easily as lowercase).
	q := u.Query()
	secretParams := map[string]bool{
		"token": true, "access_token": true, "api_key": true, "apikey": true,
		"secret": true, "password": true, "passwd": true, "key": true,
		"auth": true, "authorization": true, "client_secret": true, "client_id": true,
	}
	modified := false
	for key := range q {
		if secretParams[strings.ToLower(key)] {
			q.Set(key, redactedPlaceholder)
			modified = true
		}
	}
	if modified {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// redactHeaders returns a copy of the header map with values for headers that
// look like authentication credentials replaced with redactedPlaceholder.
func redactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	secretHeaderPrefixes := []string{
		"authorization", "x-api-key", "x-auth", "x-token",
		"api-key", "token", "bearer", "secret",
	}
	for k, v := range headers {
		lower := strings.ToLower(k)
		isSecret := false
		for _, prefix := range secretHeaderPrefixes {
			if strings.HasPrefix(lower, prefix) || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") {
				isSecret = true
				break
			}
		}
		if isSecret {
			out[k] = redactedPlaceholder
		} else {
			out[k] = v
		}
	}
	return out
}
