//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"gopkg.in/yaml.v3"
)

// canonicalizeAddr normalizes a listen address so equivalent forms collide.
// All "bind all interfaces" forms (empty host, "0.0.0.0", "::") are treated
// as equivalent because on dual-stack Linux, [::] grabs IPv4 too, causing
// EADDRINUSE. Loopback addresses (127.0.0.1, ::1) stay distinct.
// Non-canonical IP representations (e.g. [0000::1]) are normalized via
// net.ParseIP so string comparison catches them.
func canonicalizeAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // invalid; let downstream validation catch it
	}
	if host == "" {
		return net.JoinHostPort("0.0.0.0", port)
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		// All unspecified addresses (0.0.0.0, ::, ::ffff:0.0.0.0) collapse
		// to a single form so they collide in the reserved map.
		return net.JoinHostPort("0.0.0.0", port)
	}
	if ip != nil {
		// Normalize parsed IP to canonical string (e.g. 0000::1 -> ::1).
		return net.JoinHostPort(ip.String(), port)
	}
	return net.JoinHostPort(host, port)
}

// wildcardPortConflict checks whether a canonicalized address conflicts with
// any existing reserved address via wildcard-vs-specific binding. On Linux,
// binding 0.0.0.0:PORT grabs all interfaces including loopback, so a
// subsequent 127.0.0.1:PORT would fail with EADDRINUSE.
// Returns the source label of the conflicting address, or "" if no conflict.
func wildcardPortConflict(canon string, reserved map[string]string) string {
	host, port, err := net.SplitHostPort(canon)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	isWildcard := ip != nil && ip.IsUnspecified()

	for existingCanon, source := range reserved {
		existingHost, existingPort, err2 := net.SplitHostPort(existingCanon)
		if err2 != nil || existingPort != port {
			continue
		}
		existingIP := net.ParseIP(existingHost)
		existingIsWildcard := existingIP != nil && existingIP.IsUnspecified()

		// Same port, one side wildcard and the other specific: conflict.
		if isWildcard != existingIsWildcard {
			return source
		}
	}
	return ""
}

// ValidateAgents validates agent profiles in config. This is the implementation
// behind edition.ValidateAgentsFunc. Called during config.Validate().
func ValidateAgents(cfg *config.Config) error {
	if len(cfg.Agents) == 0 {
		return nil
	}

	// Collect all reserved addresses for collision detection.
	// Addresses are canonicalized so ":8888" and "0.0.0.0:8888" collide.
	reserved := make(map[string]string)
	reserved[canonicalizeAddr(cfg.FetchProxy.Listen)] = "fetch_proxy.listen"
	if cfg.MetricsListen != "" {
		reserved[canonicalizeAddr(cfg.MetricsListen)] = "metrics_listen"
	}
	if cfg.KillSwitch.APIListen != "" {
		reserved[canonicalizeAddr(cfg.KillSwitch.APIListen)] = "kill_switch.api_listen"
	}

	// Track parsed CIDRs for cross-agent containment-based overlap detection.
	type cidrOwner struct {
		network *net.IPNet
		agent   string
		label   string
	}
	var cidrNets []cidrOwner

	// Sort agent names for deterministic validation order.
	agentNames := make([]string, 0, len(cfg.Agents))
	for name := range cfg.Agents {
		agentNames = append(agentNames, name)
	}
	slices.Sort(agentNames)

	for _, name := range agentNames {
		profile := cfg.Agents[name]

		// Validate name against the request-side sanitizer. Names that
		// would be rewritten by ExtractAgent silently fall back to
		// _default at runtime; reject them at config load instead.
		if name != edition.ProfileDefault {
			if err := edition.ValidateAgentName(name); err != nil {
				return err
			}
		}

		// Validate mode if set.
		if profile.Mode != "" {
			switch profile.Mode {
			case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
				// valid
			default:
				return fmt.Errorf("agent %q: invalid mode %q: must be strict, balanced, or audit", name, profile.Mode)
			}
		}

		// Validate listeners: no duplicates, valid format.
		for _, addr := range profile.Listeners {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				return fmt.Errorf("agent %q: invalid listener address %q: %w", name, addr, err)
			}
			canon := canonicalizeAddr(addr)
			if source, exists := reserved[canon]; exists {
				return fmt.Errorf("agent %q: listener %q collides with %s", name, addr, source)
			}
			// Wildcard-vs-specific port conflict: on Linux, 0.0.0.0:P
			// binds all interfaces including loopback, so 127.0.0.1:P
			// would EADDRINUSE. Detect both directions.
			if source := wildcardPortConflict(canon, reserved); source != "" {
				return fmt.Errorf("agent %q: listener %q collides with %s (wildcard binds all interfaces)", name, addr, source)
			}
			reserved[canon] = fmt.Sprintf("agent %q listener", name)
		}

		// Validate DLP patterns in agent profile.
		if profile.DLP != nil {
			for _, p := range profile.DLP.Patterns {
				if p.Name == "" {
					return fmt.Errorf("agent %q: DLP pattern missing name", name)
				}
				if p.Regex == "" {
					return fmt.Errorf("agent %q: DLP pattern %q missing regex", name, p.Name)
				}
				if _, err := regexp.Compile(p.Regex); err != nil {
					return fmt.Errorf("agent %q: DLP pattern %q has invalid regex: %w", name, p.Name, err)
				}
			}
		}

		// Validate source CIDRs: parseable and non-overlapping across agents.
		for _, cidr := range profile.SourceCIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("agent %q: invalid source_cidrs entry %q: %w", name, cidr, err)
			}
			for _, prev := range cidrNets {
				if prev.agent == name {
					continue // same agent, overlap is harmless
				}
				if prev.network.Contains(network.IP) || network.Contains(prev.network.IP) {
					return fmt.Errorf("agent %q: source_cidrs %q overlaps with %s", name, cidr, prev.label)
				}
			}
			cidrNets = append(cidrNets, cidrOwner{network: network, agent: name, label: fmt.Sprintf("agent %q source_cidrs", name)})
		}

		// Validate budget fields are non-negative.
		if profile.Budget.MaxRequestsPerSession < 0 {
			return fmt.Errorf("agent %q: budget.max_requests_per_session must be >= 0", name)
		}
		if profile.Budget.MaxBytesPerSession < 0 {
			return fmt.Errorf("agent %q: budget.max_bytes_per_session must be >= 0", name)
		}
		if profile.Budget.MaxUniqueDomainsPerSession < 0 {
			return fmt.Errorf("agent %q: budget.max_unique_domains_per_session must be >= 0", name)
		}
		if profile.Budget.WindowMinutes < 0 {
			return fmt.Errorf("agent %q: budget.window_minutes must be >= 0", name)
		}

		// Validate rate limit fields are non-negative.
		if profile.RateLimit != nil {
			if profile.RateLimit.MaxRequestsPerMinute < 0 {
				return fmt.Errorf("agent %q: rate_limit.max_requests_per_minute must be >= 0", name)
			}
			if profile.RateLimit.MaxDataPerMinute < 0 {
				return fmt.Errorf("agent %q: rate_limit.max_data_per_minute must be >= 0", name)
			}
		}

		// Validate trusted_domains in agent profile (same rules as top-level).
		if err := config.ValidateTrustedDomains(profile.TrustedDomains, fmt.Sprintf("agent %q trusted_domains", name)); err != nil {
			return err
		}

		// Validate sandbox filesystem paths (reject empty entries).
		if profile.Sandbox != nil && profile.Sandbox.FS != nil {
			for _, p := range profile.Sandbox.FS.AllowRead {
				if p == "" {
					return fmt.Errorf("agent %q: sandbox filesystem allow_read contains empty path", name)
				}
			}
			for _, p := range profile.Sandbox.FS.AllowWrite {
				if p == "" {
					return fmt.Errorf("agent %q: sandbox filesystem allow_write contains empty path", name)
				}
			}
		}
	}

	return nil
}

// EnforceLicenseGate verifies the license_key using Ed25519 signature
// verification. If the license is missing, invalid, expired, or lacks the
// "agents" feature, named agent profiles are disabled with a warning.
//
// The _default profile is exempted: it represents single-agent config
// customization (mode, allowlist overrides) which works without a license.
//
// This is the implementation behind edition.EnforceLicenseGateFunc.
func EnforceLicenseGate(c *config.Config) {
	if len(c.Agents) == 0 {
		return
	}

	// Check if there are any non-default agent profiles.
	hasNonDefault := false
	for name := range c.Agents {
		if name != "_default" {
			hasNonDefault = true
			break
		}
	}
	if !hasNonDefault {
		return
	}

	if c.LicenseKey == "" {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: agents: section requires a license key. "+
			"Multi-agent profiles disabled. Single-agent protection is active.\n"+
			"Get a license key at https://pipelab.org/pricing\n")
		c.Agents = nil
		return
	}

	// Resolve public key: embedded build-time key > config field.
	pubKey := resolvePublicKey(c)
	if pubKey == nil {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: no license public key available. "+
			"Set license_public_key in config or build with embedded key.\n"+
			"Multi-agent profiles disabled.\n")
		c.Agents = nil
		return
	}

	// Verify the license token signature and expiration.
	lic, err := license.Verify(c.LicenseKey, pubKey)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: license verification failed: %v\n"+
			"Multi-agent profiles disabled. Single-agent protection is active.\n", err)
		c.Agents = nil
		return
	}

	// Check that the license includes the "agents" feature.
	if !lic.HasFeature(license.FeatureAgents) {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: license %s does not include the 'agents' feature.\n"+
			"Multi-agent profiles disabled.\n", lic.ID)
		c.Agents = nil
		return
	}

	// Store expiry for runtime enforcement. Zero means perpetual.
	c.LicenseExpiresAt = lic.ExpiresAt
}

// resolvePublicKey returns the Ed25519 public key for license verification.
// Priority: embedded build-time key > config field.
// The embedded key (set via ldflags in official releases) always wins to
// prevent users from supplying their own public key to self-sign licenses.
func resolvePublicKey(c *config.Config) ed25519.PublicKey {
	if key := license.EmbeddedPublicKey(); key != nil {
		return key
	}
	if c.LicensePublicKey != "" {
		keyBytes, err := hex.DecodeString(c.LicensePublicKey)
		if err == nil && len(keyBytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(keyBytes)
		}
	}
	return nil
}

// MergeAgentProfile creates a new Config by deep-merging profile overrides
// into a deep copy of the base config. The base config is not modified.
// If profile is nil, a deep copy of base is returned with no modifications.
//
// This is the implementation behind edition.MergeAgentProfileFunc.
func MergeAgentProfile(base *config.Config, profile *config.AgentProfile) (*config.Config, error) {
	merged, err := deepCopyConfig(base)
	if err != nil {
		return nil, err
	}

	if profile == nil {
		return merged, nil
	}

	if profile.Mode != "" {
		merged.Mode = profile.Mode
	}
	if profile.Enforce != nil {
		merged.Enforce = profile.Enforce
	}
	if profile.APIAllowlist != nil {
		merged.APIAllowlist = profile.APIAllowlist // replace
	}
	if profile.TrustedDomains != nil {
		merged.TrustedDomains = profile.TrustedDomains // replace
	}
	if profile.RateLimit != nil {
		// Wholesale replacement: setting rate_limit on an agent replaces
		// both fields, so explicit zero means "unlimited" (no inherited limit).
		merged.FetchProxy.Monitoring.MaxReqPerMinute = profile.RateLimit.MaxRequestsPerMinute
		merged.FetchProxy.Monitoring.MaxDataPerMinute = profile.RateLimit.MaxDataPerMinute
	}
	if profile.DLP != nil {
		includeDefaults := profile.DLP.IncludeDefaults == nil || *profile.DLP.IncludeDefaults
		if includeDefaults {
			// Build a set of agent pattern names for dedup.
			agentNames := make(map[string]struct{}, len(profile.DLP.Patterns))
			for _, p := range profile.DLP.Patterns {
				agentNames[p.Name] = struct{}{}
			}
			// Keep base patterns that aren't overridden by agent.
			filtered := make([]config.DLPPattern, 0, len(merged.DLP.Patterns))
			for _, p := range merged.DLP.Patterns {
				if _, overridden := agentNames[p.Name]; !overridden {
					filtered = append(filtered, p)
				}
			}
			merged.DLP.Patterns = append(filtered, profile.DLP.Patterns...)
		} else {
			merged.DLP.Patterns = profile.DLP.Patterns
		}
	}
	if profile.SessionProfiling != nil {
		// Wholesale replacement: agent values unconditionally override all
		// per-agent fields (even zero values win). Global-only fields
		// (MaxSessions, SessionTTLMinutes, CleanupIntervalSeconds) are
		// preserved from the base config.
		merged.SessionProfiling.DomainBurst = profile.SessionProfiling.DomainBurst
		merged.SessionProfiling.AnomalyAction = profile.SessionProfiling.AnomalyAction
		merged.SessionProfiling.VolumeSpikeRatio = profile.SessionProfiling.VolumeSpikeRatio
	}
	if profile.MCPToolPolicy != nil {
		// Wholesale replacement: setting mcp_tool_policy on an agent
		// replaces the entire base section, consistent with rate_limit
		// and session_profiling behavior.
		merged.MCPToolPolicy = *profile.MCPToolPolicy
	}

	if profile.Sandbox != nil {
		// Selective merge: override non-nil fields, append filesystem paths.
		if profile.Sandbox.Enabled != nil {
			merged.Sandbox.Enabled = *profile.Sandbox.Enabled
		}
		if profile.Sandbox.Strict != nil {
			merged.Sandbox.Strict = *profile.Sandbox.Strict
		}
		if profile.Sandbox.BestEffort != nil {
			merged.Sandbox.BestEffort = *profile.Sandbox.BestEffort
		}
		if profile.Sandbox.Workspace != "" {
			merged.Sandbox.Workspace = profile.Sandbox.Workspace
		}
		if profile.Sandbox.FS != nil {
			// Append per-agent paths to the base policy (never replace).
			if merged.Sandbox.FS == nil {
				merged.Sandbox.FS = &config.SandboxFilesystem{}
			}
			merged.Sandbox.FS.AllowRead = append(merged.Sandbox.FS.AllowRead, profile.Sandbox.FS.AllowRead...)
			merged.Sandbox.FS.AllowWrite = append(merged.Sandbox.FS.AllowWrite, profile.Sandbox.FS.AllowWrite...)
		}
	}

	return merged, nil
}

// ValidateMergedAgent validates a merged agent config.
func ValidateMergedAgent(name string, cfg *config.Config) error {
	// Validate trusted_domains inherited or overridden by the agent profile.
	if err := config.ValidateTrustedDomains(cfg.TrustedDomains, fmt.Sprintf("agent %q trusted_domains", name)); err != nil {
		return err
	}
	if cfg.Mode == config.ModeStrict && len(cfg.APIAllowlist) == 0 {
		return fmt.Errorf("agent %q: strict mode requires at least one domain in api_allowlist", name)
	}
	if cfg.SessionProfiling.Enabled && cfg.SessionProfiling.AnomalyAction != "" {
		validActions := map[string]bool{config.ActionBlock: true, config.ActionWarn: true}
		if !validActions[cfg.SessionProfiling.AnomalyAction] {
			return fmt.Errorf("agent %q: session_profiling.anomaly_action must be %q or %q, got %q", name, config.ActionBlock, config.ActionWarn, cfg.SessionProfiling.AnomalyAction)
		}
	}
	if cfg.MCPToolPolicy.Enabled && cfg.MCPToolPolicy.Action != "" {
		validActions := map[string]bool{config.ActionBlock: true, config.ActionWarn: true, config.ActionRedirect: true}
		if !validActions[cfg.MCPToolPolicy.Action] {
			return fmt.Errorf("agent %q: mcp_tool_policy.action must be %q, %q, or %q, got %q", name, config.ActionBlock, config.ActionWarn, config.ActionRedirect, cfg.MCPToolPolicy.Action)
		}
	}
	// Validate redirect profiles and rule references in agent policy.
	if cfg.MCPToolPolicy.Enabled {
		for pname, profile := range cfg.MCPToolPolicy.RedirectProfiles {
			if len(profile.Exec) == 0 || profile.Exec[0] == "" {
				return fmt.Errorf("agent %q: redirect_profile %q has empty exec", name, pname)
			}
		}
		for _, r := range cfg.MCPToolPolicy.Rules {
			effectiveAction := r.Action
			if effectiveAction == "" {
				effectiveAction = cfg.MCPToolPolicy.Action
			}
			if effectiveAction == config.ActionRedirect {
				if r.RedirectProfile == "" {
					return fmt.Errorf("agent %q: mcp_tool_policy rule %q has action=redirect but no redirect_profile", name, r.Name)
				}
				if _, ok := cfg.MCPToolPolicy.RedirectProfiles[r.RedirectProfile]; !ok {
					return fmt.Errorf("agent %q: mcp_tool_policy rule %q references unknown redirect_profile %q", name, r.Name, r.RedirectProfile)
				}
			}
		}
	}
	return nil
}

// deepCopyConfig creates an independent deep copy of a Config via
// YAML round-trip. This ensures no shared pointers between base and merged.
func deepCopyConfig(cfg *config.Config) (*config.Config, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("deep copy marshal: %w", err)
	}
	var out config.Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("deep copy unmarshal: %w", err)
	}
	return &out, nil
}
