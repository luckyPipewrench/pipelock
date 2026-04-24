// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// ReloadWarning describes a potential security downgrade from a config reload.
type ReloadWarning struct {
	Field   string
	Message string
}

// ValidateReload compares old and new configs and returns warnings for
// potential security downgrades. Warnings don't block the reload.
func ValidateReload(old, updated *Config) []ReloadWarning {
	var warnings []ReloadWarning

	// Mode downgrade: strict → balanced → audit
	modeRank := map[string]int{ModeStrict: 3, ModeBalanced: 2, ModeAudit: 1}
	if modeRank[updated.Mode] < modeRank[old.Mode] {
		warnings = append(warnings, ReloadWarning{
			Field:   "mode",
			Message: fmt.Sprintf("mode downgraded from %s to %s", old.Mode, updated.Mode),
		})
	}

	// DLP patterns removed or weakened. Plain len() comparison misses
	// same-length downgrades (e.g. swapping (?i)secret_key for (?i)key
	// under the same pattern name). Pattern count stays constant but
	// coverage drops silently, violating the "hot reload must preserve
	// security state" invariant. Diff by (name, regex) identity so
	// name-preserving regex swaps are surfaced too.
	if removed := removedOrWeakenedDLPPatterns(old.DLP.Patterns, updated.DLP.Patterns); len(removed) > 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "dlp.patterns",
			Message: "DLP patterns removed or regex-swapped on reload: " + strings.Join(removed, ", "),
		})
	}

	// DLP include_defaults disabled
	oldInclude := old.DLP.IncludeDefaults == nil || *old.DLP.IncludeDefaults
	newInclude := updated.DLP.IncludeDefaults == nil || *updated.DLP.IncludeDefaults
	if oldInclude && !newInclude {
		warnings = append(warnings, ReloadWarning{
			Field:   "dlp.include_defaults",
			Message: "DLP include_defaults disabled — new default patterns will not be merged on future upgrades",
		})
	}

	// Internal CIDRs emptied
	if len(old.Internal) > 0 && len(updated.Internal) == 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "internal",
			Message: "internal CIDR list emptied — SSRF protection disabled",
		})
	}

	// Enforce disabled
	if old.EnforceEnabled() && !updated.EnforceEnabled() {
		warnings = append(warnings, ReloadWarning{
			Field:   "enforce",
			Message: "enforcement disabled — switching to detect-only mode",
		})
	}

	// Response scanning disabled
	if old.ResponseScanning.Enabled && !updated.ResponseScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "response_scanning.enabled",
			Message: "response scanning disabled",
		})
	}

	// Response scanning exempt_domains: warn when the exemption surface may have
	// widened (new/changed entries) or was cleared entirely. Subset removal
	// (tightening) does not warn — it makes scanning stricter.
	if len(old.ResponseScanning.ExemptDomains) > 0 && len(updated.ResponseScanning.ExemptDomains) == 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "response_scanning.exempt_domains",
			Message: "response scanning exempt_domains cleared (was non-empty)",
		})
	} else if len(updated.ResponseScanning.ExemptDomains) > 0 {
		oldExempt := make(map[string]bool, len(old.ResponseScanning.ExemptDomains))
		for _, d := range old.ResponseScanning.ExemptDomains {
			oldExempt[d] = true
		}
		for _, d := range updated.ResponseScanning.ExemptDomains {
			if !oldExempt[d] {
				warnings = append(warnings, ReloadWarning{
					Field:   "response_scanning.exempt_domains",
					Message: fmt.Sprintf("response scanning exempt_domains changed: %q not in previous set", d),
				})
				break
			}
		}
	}

	// MCP input scanning disabled
	if old.MCPInputScanning.Enabled && !updated.MCPInputScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_input_scanning.enabled",
			Message: "MCP input scanning disabled",
		})
	}

	// MCP tool scanning disabled
	if old.MCPToolScanning.Enabled && !updated.MCPToolScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_tool_scanning.enabled",
			Message: "MCP tool scanning disabled",
		})
	}

	// MCP tool policy disabled
	if old.MCPToolPolicy.Enabled && !updated.MCPToolPolicy.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_tool_policy.enabled",
			Message: "MCP tool call policy disabled",
		})
	}

	// MCP tool policy rules reduced
	if len(updated.MCPToolPolicy.Rules) < len(old.MCPToolPolicy.Rules) {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_tool_policy.rules",
			Message: fmt.Sprintf("tool policy rules reduced from %d to %d", len(old.MCPToolPolicy.Rules), len(updated.MCPToolPolicy.Rules)),
		})
	}

	// Forward proxy disabled
	if old.ForwardProxy.Enabled && !updated.ForwardProxy.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "forward_proxy.enabled",
			Message: "forward proxy disabled",
		})
	}

	// WebSocket proxy disabled
	if old.WebSocketProxy.Enabled && !updated.WebSocketProxy.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "websocket_proxy.enabled",
			Message: "WebSocket proxy disabled",
		})
	}

	// Session profiling disabled
	if old.SessionProfiling.Enabled && !updated.SessionProfiling.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "session_profiling.enabled",
			Message: "session behavioral profiling disabled",
		})
	}

	// Adaptive enforcement disabled
	if old.AdaptiveEnforcement.Enabled && !updated.AdaptiveEnforcement.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "adaptive_enforcement.enabled",
			Message: "adaptive enforcement disabled",
		})
	}
	// Warn if escalation levels are weakened on reload.
	if old.AdaptiveEnforcement.Enabled && updated.AdaptiveEnforcement.Enabled {
		checkEscalationWeakening(&old.AdaptiveEnforcement.Levels, &updated.AdaptiveEnforcement.Levels, &warnings)
	}

	// Taint escalation disabled or weakened.
	if old.Taint.Enabled && !updated.Taint.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "taint.enabled",
			Message: "taint-aware policy escalation disabled",
		})
	}
	taintPolicyRank := map[string]int{ModeStrict: 3, ModeBalanced: 2, ModePermissive: 1}
	if old.Taint.Enabled && updated.Taint.Enabled && taintPolicyRank[updated.Taint.Policy] < taintPolicyRank[old.Taint.Policy] {
		warnings = append(warnings, ReloadWarning{
			Field:   "taint.policy",
			Message: fmt.Sprintf("taint policy downgraded from %s to %s", old.Taint.Policy, updated.Taint.Policy),
		})
	}
	if old.Taint.Enabled && updated.Taint.Enabled {
		if added := passthroughDomainsAdded(old.Taint.AllowlistedDomains, updated.Taint.AllowlistedDomains); len(added) > 0 {
			warnings = append(warnings, ReloadWarning{
				Field:   "taint.allowlisted_domains",
				Message: fmt.Sprintf("taint allowlisted domains added: %s — these sources now downgrade from untrusted to allowlisted", strings.Join(added, ", ")),
			})
		}
		if removed := removedPatterns(old.Taint.ProtectedPaths, updated.Taint.ProtectedPaths); len(removed) > 0 {
			warnings = append(warnings, ReloadWarning{
				Field:   "taint.protected_paths",
				Message: fmt.Sprintf("taint protected paths removed: %s — fewer actions are treated as protected under taint", strings.Join(removed, ", ")),
			})
		}
		if removed := removedPatterns(old.Taint.ElevatedPaths, updated.Taint.ElevatedPaths); len(removed) > 0 {
			warnings = append(warnings, ReloadWarning{
				Field:   "taint.elevated_paths",
				Message: fmt.Sprintf("taint elevated paths removed: %s — fewer actions are treated as elevated under taint", strings.Join(removed, ", ")),
			})
		}
		if added := taintOverridesAdded(old.Taint.TrustOverrides, updated.Taint.TrustOverrides); len(added) > 0 {
			warnings = append(warnings, ReloadWarning{
				Field:   "taint.trust_overrides",
				Message: fmt.Sprintf("taint trust overrides added: %s", strings.Join(added, ", ")),
			})
		}
	}

	// MCP session binding disabled
	if old.MCPSessionBinding.Enabled && !updated.MCPSessionBinding.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_session_binding.enabled",
			Message: "MCP session binding disabled",
		})
	}

	// A2A scanning disabled or downgraded
	if old.A2AScanning.Enabled && !updated.A2AScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.enabled",
			Message: "A2A scanning disabled",
		})
	}
	if old.A2AScanning.Action == ActionBlock && updated.A2AScanning.Action == ActionWarn {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.action",
			Message: "A2A scanning action downgraded from block to warn",
		})
	}
	if old.A2AScanning.ScanAgentCards && !updated.A2AScanning.ScanAgentCards {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.scan_agent_cards",
			Message: "A2A Agent Card scanning disabled",
		})
	}
	if old.A2AScanning.DetectCardDrift && !updated.A2AScanning.DetectCardDrift {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.detect_card_drift",
			Message: "A2A Agent Card drift detection disabled",
		})
	}
	if old.A2AScanning.SessionSmugglingDetection && !updated.A2AScanning.SessionSmugglingDetection {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.session_smuggling_detection",
			Message: "A2A session smuggling detection disabled",
		})
	}
	if old.A2AScanning.ScanRawParts && !updated.A2AScanning.ScanRawParts {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.scan_raw_parts",
			Message: "A2A raw part scanning disabled — text-like attachments will not be scanned",
		})
	}

	// TLS interception disabled
	if old.TLSInterception.Enabled && !updated.TLSInterception.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "tls_interception.enabled",
			Message: "TLS interception disabled — CONNECT tunnel body/header scanning lost",
		})
	}

	// TLS passthrough domains changed (scanning coverage may be reduced).
	// Uses set-diff semantics: warns when new domains are added that weren't
	// in the old list, even if the total count stays the same or shrinks.
	if old.TLSInterception.Enabled && updated.TLSInterception.Enabled {
		added := passthroughDomainsAdded(old.TLSInterception.PassthroughDomains, updated.TLSInterception.PassthroughDomains)
		if len(added) > 0 {
			warnings = append(warnings, ReloadWarning{
				Field:   "tls_interception.passthrough_domains",
				Message: fmt.Sprintf("passthrough domains added: %s — these CONNECT tunnels now bypass body scanning", strings.Join(added, ", ")),
			})
		}
	}

	// Subdomain entropy exclusions expanded (reduces detection coverage)
	if added := passthroughDomainsAdded(
		old.FetchProxy.Monitoring.SubdomainEntropyExclusions,
		updated.FetchProxy.Monitoring.SubdomainEntropyExclusions,
	); len(added) > 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "fetch_proxy.monitoring.subdomain_entropy_exclusions",
			Message: fmt.Sprintf("subdomain entropy exclusions added: %s — entropy detection coverage reduced", strings.Join(added, ", ")),
		})
	}

	// Trusted domains expanded (SSRF protection scope reduced)
	if added := passthroughDomainsAdded(old.TrustedDomains, updated.TrustedDomains); len(added) > 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "trusted_domains",
			Message: fmt.Sprintf("trusted domains added: %s — SSRF internal-IP check bypassed for these hosts", strings.Join(added, ", ")),
		})
	}
	// SSRF IP allowlist expanded (SSRF protection scope reduced).
	// CIDR-semantic comparison: a new entry expands coverage only if it is
	// not already contained within a previously-configured CIDR.
	if expanded := ssrfIPAllowlistExpanded(old.SSRF.IPAllowlist, updated.SSRF.IPAllowlist); len(expanded) > 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "ssrf.ip_allowlist",
			Message: fmt.Sprintf("SSRF IP allowlist expanded: %s — SSRF check bypassed for these IP ranges", strings.Join(expanded, ", ")),
		})
	}

	// TODO: emit reload warnings for agent-scoped trusted_domains (enterprise profiles).
	// Agent profiles live in the enterprise package, so diffing them here would require
	// either a hook or moving the diff logic into the enterprise reload path.

	// Request body scanning disabled
	if old.RequestBodyScanning.Enabled && !updated.RequestBodyScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "request_body_scanning.enabled",
			Message: "request body scanning disabled",
		})
	}

	// Tool chain detection disabled
	if old.ToolChainDetection.Enabled && !updated.ToolChainDetection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "tool_chain_detection.enabled",
			Message: "tool chain detection disabled",
		})
	}

	// Cross-request detection disabled
	if old.CrossRequestDetection.Enabled && !updated.CrossRequestDetection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "cross_request_detection.enabled",
			Message: "cross-request exfiltration detection disabled",
		})
	}
	// Per-detector warnings only matter when the parent stays enabled.
	// If the parent is being disabled, the parent warning above covers it.
	if old.CrossRequestDetection.Enabled &&
		updated.CrossRequestDetection.Enabled &&
		old.CrossRequestDetection.EntropyBudget.Enabled &&
		!updated.CrossRequestDetection.EntropyBudget.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "cross_request_detection.entropy_budget.enabled",
			Message: "cross-request entropy budget detection disabled",
		})
	}
	if old.CrossRequestDetection.Enabled &&
		updated.CrossRequestDetection.Enabled &&
		old.CrossRequestDetection.FragmentReassembly.Enabled &&
		!updated.CrossRequestDetection.FragmentReassembly.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "cross_request_detection.fragment_reassembly.enabled",
			Message: "cross-request fragment reassembly disabled",
		})
	}

	// Address protection disabled
	if old.AddressProtection.Enabled && !updated.AddressProtection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "address_protection.enabled",
			Message: "address protection disabled",
		})
	}

	// Seed phrase detection disabled
	if (old.SeedPhraseDetection.Enabled == nil || *old.SeedPhraseDetection.Enabled) &&
		updated.SeedPhraseDetection.Enabled != nil && !*updated.SeedPhraseDetection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "seed_phrase_detection.enabled",
			Message: "seed phrase detection disabled",
		})
	}
	// Seed phrase checksum verification disabled
	if (old.SeedPhraseDetection.VerifyChecksum == nil || *old.SeedPhraseDetection.VerifyChecksum) &&
		updated.SeedPhraseDetection.VerifyChecksum != nil && !*updated.SeedPhraseDetection.VerifyChecksum {
		warnings = append(warnings, ReloadWarning{
			Field:   "seed_phrase_detection.verify_checksum",
			Message: "seed phrase checksum verification disabled — increased false positive risk",
		})
	}
	// Seed phrase min_words decreased
	if old.SeedPhraseDetection.MinWords > 0 &&
		updated.SeedPhraseDetection.MinWords > 0 &&
		updated.SeedPhraseDetection.MinWords < old.SeedPhraseDetection.MinWords {
		warnings = append(warnings, ReloadWarning{
			Field:   "seed_phrase_detection.min_words",
			Message: fmt.Sprintf("seed phrase min_words decreased from %d to %d", old.SeedPhraseDetection.MinWords, updated.SeedPhraseDetection.MinWords),
		})
	}

	// Emit sinks removed
	if old.Emit.Webhook.URL != "" && updated.Emit.Webhook.URL == "" {
		warnings = append(warnings, ReloadWarning{
			Field:   "emit.webhook.url",
			Message: "webhook emission disabled",
		})
	}
	if old.Emit.Syslog.Address != "" && updated.Emit.Syslog.Address == "" {
		warnings = append(warnings, ReloadWarning{
			Field:   "emit.syslog.address",
			Message: "syslog emission disabled",
		})
	}
	if old.Emit.OTLP.Endpoint != "" && updated.Emit.OTLP.Endpoint == "" {
		warnings = append(warnings, ReloadWarning{
			Field:   "emit.otlp.endpoint",
			Message: "OTLP log emission disabled",
		})
	}

	// Kill switch API listen address changed (requires restart)
	if old.KillSwitch.APIListen != updated.KillSwitch.APIListen {
		warnings = append(warnings, ReloadWarning{
			Field:   "kill_switch.api_listen",
			Message: "api_listen cannot change at runtime (requires restart) — ignoring",
		})
	}

	// Metrics listen address changed (requires restart)
	if old.MetricsListen != updated.MetricsListen {
		warnings = append(warnings, ReloadWarning{
			Field:   "metrics_listen",
			Message: "metrics_listen cannot change at runtime (requires restart) — ignoring",
		})
	}

	// Secrets file changed or removed (security-relevant)
	if old.DLP.SecretsFile != updated.DLP.SecretsFile {
		if updated.DLP.SecretsFile == "" {
			warnings = append(warnings, ReloadWarning{
				Field:   "dlp.secrets_file",
				Message: "secrets_file removed — known secret scanning disabled",
			})
		} else if old.DLP.SecretsFile != "" {
			warnings = append(warnings, ReloadWarning{
				Field: "dlp.secrets_file",
				Message: fmt.Sprintf("secrets_file changed from %q to %q — secrets will be reloaded",
					old.DLP.SecretsFile, updated.DLP.SecretsFile),
			})
		}
	}

	// Sentry DSN changed (requires restart — scrubber is built once at init)
	if old.Sentry.DSN != updated.Sentry.DSN {
		warnings = append(warnings, ReloadWarning{Field: "sentry.dsn", Message: "Sentry DSN changes require restart"})
	}

	// Sentry scrubber uses DLP patterns, env secrets, and file secrets from
	// init time. Warn on ANY change that would affect scrubbing coverage.
	if dlpPatternsChanged(old.DLP.Patterns, updated.DLP.Patterns) {
		warnings = append(warnings, ReloadWarning{
			Field:   "sentry",
			Message: "DLP patterns changed; Sentry scrubber uses init-time patterns until restart",
		})
	}
	if old.DLP.ScanEnv != updated.DLP.ScanEnv {
		warnings = append(warnings, ReloadWarning{
			Field:   "sentry",
			Message: "dlp.scan_env changed; Sentry scrubber uses init-time env secrets until restart",
		})
	}
	if old.DLP.SecretsFile != updated.DLP.SecretsFile {
		warnings = append(warnings, ReloadWarning{
			Field:   "sentry",
			Message: "dlp.secrets_file changed; Sentry scrubber uses init-time file secrets until restart",
		})
	}

	// File sentry config is startup-only (watches are armed once at init).
	// ALL fields are reload-immutable, not just enabled/best_effort.
	if fileSentryChanged(old, updated) {
		warnings = append(warnings, ReloadWarning{
			Field:   "file_sentry",
			Message: "file_sentry config changes require restart — ignored on reload",
		})
	}

	// Sandbox config is startup-only. Warn if any sandbox fields changed
	// so operators know the reload had no effect on the running sandbox.
	if sandboxChanged(old, updated) {
		warnings = append(warnings, ReloadWarning{
			Field:   "sandbox",
			Message: "sandbox config changes require restart — ignored on reload",
		})
	}

	// Media policy downgrades. Each toggle that weakens protection gets a
	// dedicated warning so operators see the field-level cause of the
	// downgrade rather than a generic "media_policy changed" message.
	if old.MediaPolicy.IsEnabled() && !updated.MediaPolicy.IsEnabled() {
		warnings = append(warnings, ReloadWarning{
			Field:   "media_policy.enabled",
			Message: "media policy disabled — image metadata stripping, audio/video blocks, and exposure events no longer apply",
		})
	}
	if old.MediaPolicy.ShouldStripImages() && !updated.MediaPolicy.ShouldStripImages() {
		warnings = append(warnings, ReloadWarning{
			Field:   "media_policy.strip_images",
			Message: "media_policy.strip_images disabled — image responses now forwarded without stripping",
		})
	}
	if old.MediaPolicy.ShouldStripAudio() && !updated.MediaPolicy.ShouldStripAudio() {
		warnings = append(warnings, ReloadWarning{
			Field:   "media_policy.strip_audio",
			Message: "media_policy.strip_audio disabled — audio responses now forwarded",
		})
	}
	if old.MediaPolicy.ShouldStripVideo() && !updated.MediaPolicy.ShouldStripVideo() {
		warnings = append(warnings, ReloadWarning{
			Field:   "media_policy.strip_video",
			Message: "media_policy.strip_video disabled — video responses now forwarded",
		})
	}
	if old.MediaPolicy.ShouldStripImageMetadata() && !updated.MediaPolicy.ShouldStripImageMetadata() {
		warnings = append(warnings, ReloadWarning{
			Field:   "media_policy.strip_image_metadata",
			Message: "media_policy.strip_image_metadata disabled — image metadata no longer removed",
		})
	}
	if old.MediaPolicy.ShouldLogExposure() && !updated.MediaPolicy.ShouldLogExposure() {
		warnings = append(warnings, ReloadWarning{
			Field:   "media_policy.log_media_exposure",
			Message: "media_policy.log_media_exposure disabled — media responses no longer emit exposure events",
		})
	}
	oldMax := old.MediaPolicy.EffectiveMaxImageBytes()
	newMax := updated.MediaPolicy.EffectiveMaxImageBytes()
	if newMax > oldMax {
		warnings = append(warnings, ReloadWarning{
			Field:   "media_policy.max_image_bytes",
			Message: fmt.Sprintf("media_policy.max_image_bytes raised from %d to %d — larger images now accepted", oldMax, newMax),
		})
	}
	// Allowed image types widened: warn when any effective entry is newly
	// admitted. Compare on the EFFECTIVE list so reloading from an
	// explicit narrow list like ["image/png"] back to "" (which falls
	// through to DefaultAllowedImageTypes, i.e., {png, jpeg}) still
	// counts as a widening. The previous guard was a raw-list length
	// check that missed the "clear to defaults" transition.
	oldEffective := old.MediaPolicy.EffectiveAllowedImageTypes()
	newEffective := updated.MediaPolicy.EffectiveAllowedImageTypes()
	oldAllowed := make(map[string]bool, len(oldEffective))
	for _, t := range oldEffective {
		oldAllowed[t] = true
	}
	for _, t := range newEffective {
		if !oldAllowed[t] {
			warnings = append(warnings, ReloadWarning{
				Field:   "media_policy.allowed_image_types",
				Message: fmt.Sprintf("media_policy.allowed_image_types widened: %q newly admitted", t),
			})
			break
		}
	}

	// Mediation envelope signing downgraded or disabled.
	//
	// Downgrading from sign:true to sign:false means every mediated
	// request loses its RFC 9421 signature. Downstream verifiers that
	// were relying on the signature as part of an admission decision
	// will start accepting unsigned envelopes — a silent weakening of
	// the trust chain. Warn the operator on every such transition so a
	// revocation shows up in logs.
	if old.MediationEnvelope.Sign && !updated.MediationEnvelope.Sign {
		warnings = append(warnings, ReloadWarning{
			Field:   "mediation_envelope.sign",
			Message: "mediation envelope signing disabled — outbound requests will no longer carry an RFC 9421 signature",
		})
	}
	// Disabling the envelope entirely is a bigger step: no mediation
	// header at all. Same reasoning; warn separately so operators can
	// distinguish "lost the signature" from "lost the whole envelope".
	if old.MediationEnvelope.Enabled && !updated.MediationEnvelope.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mediation_envelope.enabled",
			Message: "mediation envelope disabled — outbound requests will no longer carry the Pipelock-Mediation header",
		})
	}
	// Key rotation is not a downgrade, but an operator rotating the
	// key id without first publishing the new public key will silently
	// start emitting signatures no verifier can check. Warn on change.
	if old.MediationEnvelope.Sign && updated.MediationEnvelope.Sign &&
		old.MediationEnvelope.KeyID != updated.MediationEnvelope.KeyID {
		warnings = append(warnings, ReloadWarning{
			Field: "mediation_envelope.key_id",
			Message: fmt.Sprintf("mediation envelope signing key_id changed from %q to %q — verifiers must have the new public key published",
				old.MediationEnvelope.KeyID, updated.MediationEnvelope.KeyID),
		})
	}
	if old.MediationEnvelope.Sign && updated.MediationEnvelope.Sign {
		updatedComponents := make(map[string]struct{}, len(updated.MediationEnvelope.SignedComponents))
		for _, comp := range updated.MediationEnvelope.SignedComponents {
			updatedComponents[strings.ToLower(strings.TrimSpace(comp))] = struct{}{}
		}
		removedComponents := make([]string, 0, len(old.MediationEnvelope.SignedComponents))
		for _, comp := range old.MediationEnvelope.SignedComponents {
			normalized := strings.ToLower(strings.TrimSpace(comp))
			if normalized == "" {
				continue
			}
			if _, ok := updatedComponents[normalized]; !ok && !slices.Contains(removedComponents, normalized) {
				removedComponents = append(removedComponents, normalized)
			}
		}
		if len(removedComponents) > 0 {
			slices.Sort(removedComponents)
			warnings = append(warnings, ReloadWarning{
				Field: "mediation_envelope.signed_components",
				Message: fmt.Sprintf("mediation envelope signed_components narrowed — removed %s from RFC 9421 coverage",
					strings.Join(removedComponents, ", ")),
			})
		}
		if updated.MediationEnvelope.MaxBodyBytes < old.MediationEnvelope.MaxBodyBytes {
			warnings = append(warnings, ReloadWarning{
				Field: "mediation_envelope.max_body_bytes",
				Message: fmt.Sprintf("mediation envelope max_body_bytes reduced from %d to %d — fewer request bodies will carry content-digest coverage",
					old.MediationEnvelope.MaxBodyBytes, updated.MediationEnvelope.MaxBodyBytes),
			})
		}
	}

	// Redaction disabled or default profile changed under our feet — both
	// are policy downgrades an operator should see in the reload log.
	if old.Redaction.Enabled && !updated.Redaction.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "redaction.enabled",
			Message: "redaction disabled — request bodies will no longer be rewritten before forwarding",
		})
	}
	if old.Redaction.Enabled && updated.Redaction.Enabled &&
		old.Redaction.DefaultProfile != updated.Redaction.DefaultProfile {
		warnings = append(warnings, ReloadWarning{
			Field: "redaction.default_profile",
			Message: fmt.Sprintf("redaction default_profile changed from %q to %q — matcher rules updated",
				old.Redaction.DefaultProfile, updated.Redaction.DefaultProfile),
		})
	}

	return warnings
}

// sandboxChanged returns true if any sandbox-related config field differs.
// fileSentryChanged returns true if any file_sentry config field differs.
// File sentry is startup-only: watches are armed once at init and cannot
// be reconfigured on reload.
func fileSentryChanged(old, updated *Config) bool {
	if old.FileSentry.Enabled != updated.FileSentry.Enabled {
		return true
	}
	if old.FileSentry.BestEffort != updated.FileSentry.BestEffort {
		return true
	}
	if !slices.Equal(old.FileSentry.WatchPaths, updated.FileSentry.WatchPaths) {
		return true
	}
	if !boolPtrEqual(old.FileSentry.ScanContent, updated.FileSentry.ScanContent) {
		return true
	}
	if !slices.Equal(old.FileSentry.IgnorePatterns, updated.FileSentry.IgnorePatterns) {
		return true
	}
	return false
}

func sandboxChanged(old, updated *Config) bool {
	if old.Sandbox.Enabled != updated.Sandbox.Enabled {
		return true
	}
	if old.Sandbox.Strict != updated.Sandbox.Strict {
		return true
	}
	if old.Sandbox.BestEffort != updated.Sandbox.BestEffort {
		return true
	}
	if old.Sandbox.Workspace != updated.Sandbox.Workspace {
		return true
	}
	if sandboxFSChanged(old.Sandbox.FS, updated.Sandbox.FS) {
		return true
	}
	// Check per-agent sandbox overrides (bidirectional: added, removed, changed).
	for name, oldProfile := range old.Agents {
		newProfile, ok := updated.Agents[name]
		if !ok {
			// Agent removed — if it had sandbox overrides, that's a change.
			if oldProfile.Sandbox != nil {
				return true
			}
			continue
		}
		if agentSandboxChanged(oldProfile.Sandbox, newProfile.Sandbox) {
			return true
		}
	}
	// Check for newly added agents with sandbox overrides.
	for name, newProfile := range updated.Agents {
		if _, existed := old.Agents[name]; !existed && newProfile.Sandbox != nil {
			return true
		}
	}
	return false
}

// sandboxFSChanged compares two SandboxFilesystem structs by content.
func sandboxFSChanged(oldFS, newFS *SandboxFilesystem) bool {
	if (oldFS == nil) != (newFS == nil) {
		return true
	}
	if oldFS == nil {
		return false
	}
	if !stringSlicesEqual(oldFS.AllowRead, newFS.AllowRead) {
		return true
	}
	return !stringSlicesEqual(oldFS.AllowWrite, newFS.AllowWrite)
}

// agentSandboxChanged compares two AgentSandboxOverride pointers.
func agentSandboxChanged(old, updated *AgentSandboxOverride) bool {
	if (old == nil) != (updated == nil) {
		return true
	}
	if old == nil {
		return false
	}
	if !boolPtrEqual(old.Enabled, updated.Enabled) || !boolPtrEqual(old.Strict, updated.Strict) || !boolPtrEqual(old.BestEffort, updated.BestEffort) {
		return true
	}
	if old.Workspace != updated.Workspace {
		return true
	}
	return sandboxFSChanged(old.FS, updated.FS)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func boolPtrEqual(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return *a == *b
}

// dlpPatternsChanged returns true if the DLP pattern set differs in ways that
// affect the Sentry scrubber (count, name, or regex content). exempt_domains
// changes are intentionally excluded — the scrubber compiles regexes only and
// does not use destination-domain exemptions.
func dlpPatternsChanged(old, updated []DLPPattern) bool {
	if len(old) != len(updated) {
		return true
	}
	for i := range old {
		if old[i].Regex != updated[i].Regex {
			return true
		}
		if old[i].Name != updated[i].Name {
			return true
		}
	}
	return false
}

// passthroughDomainsAdded returns domains present in updated but not in old.
func passthroughDomainsAdded(old, updated []string) []string {
	oldSet := make(map[string]struct{}, len(old))
	for _, d := range old {
		oldSet[strings.ToLower(d)] = struct{}{}
	}
	var added []string
	for _, d := range updated {
		if _, exists := oldSet[strings.ToLower(d)]; !exists {
			added = append(added, d)
		}
	}
	return added
}

func taintOverridesAdded(old, updated []TaintTrustOverride) []string {
	oldExpiry := make(map[string]time.Time, len(old))
	for _, override := range old {
		key := taintOverrideReloadKey(override)
		if expiry, exists := oldExpiry[key]; !exists || override.ExpiresAt.After(expiry) {
			oldExpiry[key] = override.ExpiresAt
		}
	}
	var added []string
	for _, override := range updated {
		key := taintOverrideReloadKey(override)
		oldExpiresAt, exists := oldExpiry[key]
		switch {
		case !exists:
			added = append(added, key)
		case override.ExpiresAt.After(oldExpiresAt):
			added = append(added, fmt.Sprintf("%s expires_at=%s", key, override.ExpiresAt.UTC().Format(time.RFC3339)))
		}
	}
	return added
}

func removedPatterns(old, updated []string) []string {
	updatedSet := make(map[string]struct{}, len(updated))
	for _, pattern := range updated {
		updatedSet[pattern] = struct{}{}
	}
	var removed []string
	for _, pattern := range old {
		if _, exists := updatedSet[pattern]; !exists {
			removed = append(removed, pattern)
		}
	}
	return removed
}

func taintOverrideReloadKey(override TaintTrustOverride) string {
	scope := strings.ToLower(strings.TrimSpace(override.Scope))
	source := strings.ToLower(strings.TrimSpace(override.SourceMatch))
	action := strings.ToLower(strings.TrimSpace(override.ActionMatch))

	switch scope {
	case "source":
		return fmt.Sprintf("scope=%s source=%s", scope, source)
	case "action":
		return fmt.Sprintf("scope=%s action=%s", scope, action)
	default:
		return fmt.Sprintf("scope=%s source=%s action=%s", scope, source, action)
	}
}

// ssrfIPAllowlistExpanded returns CIDR strings from updated that expand coverage
// beyond what old already covered. A CIDR is considered expanding if its network
// address is not contained by any CIDR in the old list. Malformed entries that
// passed validation are included verbatim (fail-open for warnings, not security).
func ssrfIPAllowlistExpanded(old, updated []string) []string {
	oldNets := make([]*net.IPNet, 0, len(old))
	for _, cidr := range old {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			oldNets = append(oldNets, ipNet)
		}
	}

	var expanded []string
	for _, cidr := range updated {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			expanded = append(expanded, cidr) // malformed — warn anyway
			continue
		}
		covered := false
		for _, oldNet := range oldNets {
			if oldNet.Contains(ipNet.IP) {
				oOnes, oSize := oldNet.Mask.Size()
				nOnes, nSize := ipNet.Mask.Size()
				// Same address family and old mask is equal or broader.
				if oSize == nSize && oOnes <= nOnes {
					covered = true
					break
				}
			}
		}
		if !covered {
			expanded = append(expanded, cidr)
		}
	}
	return expanded
}

// checkEscalationWeakening compares effective (post-default) escalation levels
// and appends warnings for any enforcement that was reduced on reload.
func checkEscalationWeakening(old, updated *EscalationLevels, warnings *[]ReloadWarning) {
	type levelPair struct {
		name    string
		oldActs *EscalationActions
		newActs *EscalationActions
	}
	pairs := []levelPair{
		{"elevated", &old.Elevated, &updated.Elevated},
		{"high", &old.High, &updated.High},
		{"critical", &old.Critical, &updated.Critical},
	}
	for _, lp := range pairs {
		if upgradeActionStrength(lp.newActs.UpgradeWarn) < upgradeActionStrength(lp.oldActs.UpgradeWarn) {
			*warnings = append(*warnings, ReloadWarning{
				Field:   fmt.Sprintf("adaptive_enforcement.levels.%s.upgrade_warn", lp.name),
				Message: fmt.Sprintf("%s.upgrade_warn weakened", lp.name),
			})
		}
		if upgradeActionStrength(lp.newActs.UpgradeAsk) < upgradeActionStrength(lp.oldActs.UpgradeAsk) {
			*warnings = append(*warnings, ReloadWarning{
				Field:   fmt.Sprintf("adaptive_enforcement.levels.%s.upgrade_ask", lp.name),
				Message: fmt.Sprintf("%s.upgrade_ask weakened", lp.name),
			})
		}
		// block_all: true -> false is weakening.
		oldBlock := lp.oldActs.BlockAll != nil && *lp.oldActs.BlockAll
		newBlock := lp.newActs.BlockAll != nil && *lp.newActs.BlockAll
		if oldBlock && !newBlock {
			*warnings = append(*warnings, ReloadWarning{
				Field:   fmt.Sprintf("adaptive_enforcement.levels.%s.block_all", lp.name),
				Message: fmt.Sprintf("%s.block_all weakened", lp.name),
			})
		}
	}
}

// removedOrWeakenedDLPPatterns returns human-readable labels for any DLP
// pattern that disappeared entirely or whose regex changed while keeping
// the same name. Same-name regex swaps are the load-bearing case: an
// attacker or misconfigured reload can keep pattern count identical while
// silently downgrading coverage (e.g. (?i)secret_key -> (?i)key under the
// same "AWS Secret" name). Legitimate strengthening under the same name
// also triggers a warning; operators can resolve by reviewing the diff,
// which is the point. Renames appear as both a removal (old name) and an
// implicit add (new name), which the reload surface does not warn about.
func removedOrWeakenedDLPPatterns(old, updated []DLPPattern) []string {
	updatedByName := make(map[string]string, len(updated))
	for _, p := range updated {
		updatedByName[p.Name] = p.Regex
	}
	var changed []string
	for _, p := range old {
		newRegex, ok := updatedByName[p.Name]
		switch {
		case !ok:
			changed = append(changed, p.Name)
		case newRegex != p.Regex:
			changed = append(changed, p.Name+" (regex changed)")
		}
	}
	return changed
}
