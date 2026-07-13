// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// PreserveConductorBundleLocalRuntimeState copies follower-local runtime and
// scanner settings from oldCfg onto newCfg before a Conductor policy bundle is
// applied. Detection list sections explicitly present in bundleYAML are merged
// additively: follower-local coverage stays first, and bundle entries may only
// add new named definitions.
func PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg *Config, bundleYAML string) error {
	if oldCfg == nil || newCfg == nil {
		return nil
	}
	sections, err := conductorBundleTopLevelSections(bundleYAML)
	if err != nil {
		return err
	}
	rawBundleCfg, err := conductorBundleRawConfig(bundleYAML)
	if err != nil {
		return err
	}
	// Current Conductor bundles own fleet posture fields
	// (mode/enforce/api_allowlist). Runtime plumbing and ambiguous scanner
	// controls remain follower-local so an omitted YAML section cannot reset a
	// follower to defaults or silently drop locally enabled enforcement. Pure
	// detection lists are merged additively below; every struct/scalar surface
	// still needs an explicit ownership/version marker before it can be remotely
	// overridden.
	newCfg.FetchProxy = oldCfg.FetchProxy
	newCfg.ForwardProxy = oldCfg.ForwardProxy
	newCfg.WebSocketProxy = oldCfg.WebSocketProxy
	newCfg.TLSInterception = oldCfg.TLSInterception
	newCfg.KillSwitch = oldCfg.KillSwitch
	newCfg.ExplainBlocks = oldCfg.ExplainBlocks
	newCfg.Logging = oldCfg.Logging
	newCfg.Emit = oldCfg.Emit
	newCfg.Sentry = oldCfg.Sentry
	newCfg.MetricsListen = oldCfg.MetricsListen
	newCfg.MCPWSListener = oldCfg.MCPWSListener
	newCfg.ReverseProxy = oldCfg.ReverseProxy
	newCfg.ScanAPI = oldCfg.ScanAPI
	newCfg.Sandbox = oldCfg.Sandbox
	newCfg.FlightRecorder = oldCfg.FlightRecorder

	if oldCfg.Agents != nil {
		newCfg.Agents = make(map[string]AgentProfile, len(oldCfg.Agents))
		for name, profile := range oldCfg.Agents {
			newCfg.Agents[name] = profile
		}
	} else {
		newCfg.Agents = nil
	}
	newCfg.LicenseKey = oldCfg.LicenseKey
	newCfg.LicenseFile = oldCfg.LicenseFile

	newCfg.Internal = append([]string(nil), oldCfg.Internal...)
	newCfg.TrustedDomains = append([]string(nil), oldCfg.TrustedDomains...)
	newCfg.SSRF = oldCfg.SSRF
	newCfg.DNS = oldCfg.DNS
	newCfg.Suppress = append([]SuppressEntry(nil), oldCfg.Suppress...)
	if err := preserveConductorBundleDLP(newCfg, oldCfg, sections["dlp"], rawBundleCfg.DLP.Patterns); err != nil {
		return err
	}
	if err := preserveConductorBundleCanaryTokens(newCfg, oldCfg, sections["canary_tokens"], rawBundleCfg.CanaryTokens); err != nil {
		return err
	}
	if err := preserveConductorBundleResponseScanning(newCfg, oldCfg, sections["response_scanning"], rawBundleCfg.ResponseScanning.Patterns); err != nil {
		return err
	}
	newCfg.MCPInputScanning = oldCfg.MCPInputScanning
	newCfg.MCPToolScanning = oldCfg.MCPToolScanning
	if err := preserveConductorBundleMCPToolPolicy(newCfg, oldCfg, sections["mcp_tool_policy"], rawBundleCfg.MCPToolPolicy.Rules); err != nil {
		return err
	}
	newCfg.Defer = oldCfg.Defer
	newCfg.GitProtection = oldCfg.GitProtection
	newCfg.RequestBodyScanning = oldCfg.RequestBodyScanning
	newCfg.RequestPolicy = oldCfg.RequestPolicy
	newCfg.SessionProfiling = oldCfg.SessionProfiling
	newCfg.AdaptiveEnforcement = oldCfg.AdaptiveEnforcement
	newCfg.MCPSessionBinding = oldCfg.MCPSessionBinding
	newCfg.A2AScanning = oldCfg.A2AScanning
	newCfg.ToolChainDetection = oldCfg.ToolChainDetection
	newCfg.CrossRequestDetection = oldCfg.CrossRequestDetection
	newCfg.AddressProtection = oldCfg.AddressProtection
	newCfg.SeedPhraseDetection = oldCfg.SeedPhraseDetection
	newCfg.Rules = oldCfg.Rules
	newCfg.FileSentry = oldCfg.FileSentry
	newCfg.MCPBinaryIntegrity = oldCfg.MCPBinaryIntegrity
	newCfg.MCPToolProvenance = oldCfg.MCPToolProvenance
	newCfg.BehavioralBaseline = oldCfg.BehavioralBaseline
	newCfg.Airlock = oldCfg.Airlock
	newCfg.BrowserShield = oldCfg.BrowserShield
	newCfg.MediaPolicy = oldCfg.MediaPolicy
	newCfg.Redaction = oldCfg.Redaction
	newCfg.Taint = oldCfg.Taint
	newCfg.MediationEnvelope = oldCfg.MediationEnvelope
	newCfg.Learn = oldCfg.Learn
	newCfg.LearnLock = oldCfg.LearnLock
	newCfg.DefaultAgentIdentity = oldCfg.DefaultAgentIdentity
	newCfg.BindDefaultAgentIdentity = oldCfg.BindDefaultAgentIdentity
	return nil
}

func conductorBundleTopLevelSections(src string) (map[string]bool, error) {
	sections := make(map[string]bool)
	dec := yaml.NewDecoder(strings.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return sections, nil
		}
		return nil, fmt.Errorf("parse conductor policy bundle config sections: %w", err)
	}
	var extra yaml.Node
	err := dec.Decode(&extra)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse conductor policy bundle config sections: %w", err)
	}
	if err == nil {
		return nil, errors.New("parse conductor policy bundle config sections: multiple YAML documents")
	}
	if len(doc.Content) == 0 {
		return sections, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return sections, nil
	}
	collectConductorBundleTopLevelSections(root, sections, make(map[*yaml.Node]bool))
	return sections, nil
}

func collectConductorBundleTopLevelSections(n *yaml.Node, sections map[string]bool, seen map[*yaml.Node]bool) {
	if n == nil {
		return
	}
	if n.Kind == yaml.AliasNode {
		collectConductorBundleTopLevelSections(n.Alias, sections, seen)
		return
	}
	if seen[n] {
		return
	}
	seen[n] = true
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i]
		value := n.Content[i+1]
		if key.Value == "<<" {
			collectConductorBundleMergeSections(value, sections, seen)
			continue
		}
		sections[key.Value] = true
	}
}

func collectConductorBundleMergeSections(n *yaml.Node, sections map[string]bool, seen map[*yaml.Node]bool) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.AliasNode, yaml.MappingNode:
		collectConductorBundleTopLevelSections(n, sections, seen)
	case yaml.SequenceNode:
		for _, item := range n.Content {
			collectConductorBundleTopLevelSections(item, sections, seen)
		}
	}
}

func conductorBundleRawConfig(src string) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(src))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return cfg, nil
		}
		return nil, fmt.Errorf("parse conductor policy bundle raw config: %w", err)
	}
	var extra yaml.Node
	err := dec.Decode(&extra)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse conductor policy bundle raw config: %w", err)
	}
	if err == nil {
		return nil, errors.New("parse conductor policy bundle raw config: multiple YAML documents")
	}
	if err := normalizeConductorBundleRawConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func normalizeConductorBundleRawConfig(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if err := cfg.validateDLPPatternConfig(); err != nil {
		return fmt.Errorf("parse conductor policy bundle raw config: %w", err)
	}
	if err := validateConductorBundleRawResponsePatterns(cfg.ResponseScanning.Patterns); err != nil {
		return fmt.Errorf("parse conductor policy bundle raw config: %w", err)
	}
	if err := validateConductorBundleRawToolPolicyRules(cfg.MCPToolPolicy.Rules); err != nil {
		return fmt.Errorf("parse conductor policy bundle raw config: %w", err)
	}
	return nil
}

func validateConductorBundleRawResponsePatterns(patterns []ResponseScanPattern) error {
	for _, p := range patterns {
		if p.Name == "" {
			return fmt.Errorf("response scanning pattern missing name")
		}
		if p.Regex == "" {
			return fmt.Errorf("response scanning pattern %q missing regex", p.Name)
		}
		if _, err := regexp.Compile(p.Regex); err != nil {
			return fmt.Errorf("response scanning pattern %q has invalid regex: %w", p.Name, err)
		}
	}
	return nil
}

func validateConductorBundleRawToolPolicyRules(rules []ToolPolicyRule) error {
	for i, r := range rules {
		if r.Name == "" {
			return fmt.Errorf("mcp_tool_policy rule %d missing name", i)
		}
		if r.ToolPattern == "" {
			return fmt.Errorf("mcp_tool_policy rule %q missing tool_pattern", r.Name)
		}
		if _, err := regexp.Compile(r.ToolPattern); err != nil {
			return fmt.Errorf("mcp_tool_policy rule %q has invalid tool_pattern: %w", r.Name, err)
		}
		if r.ArgPattern != "" {
			if _, err := regexp.Compile(r.ArgPattern); err != nil {
				return fmt.Errorf("mcp_tool_policy rule %q has invalid arg_pattern: %w", r.Name, err)
			}
		}
		hasStructuralValidators := r.hasStructuralArgValidators()
		if r.ArgKey != "" {
			if r.ArgPattern == "" && !hasStructuralValidators {
				return fmt.Errorf("mcp_tool_policy rule %q has arg_key without arg_pattern", r.Name)
			}
			if _, err := regexp.Compile(r.ArgKey); err != nil {
				return fmt.Errorf("mcp_tool_policy rule %q has invalid arg_key: %w", r.Name, err)
			}
		} else if hasStructuralValidators {
			return fmt.Errorf("mcp_tool_policy rule %q has structural argument validators but no arg_key", r.Name)
		}
		if err := validateToolPolicyStructuralArgs(r); err != nil {
			return err
		}
		if r.Action != "" {
			switch r.Action {
			case ActionWarn, ActionBlock, ActionRedirect, ActionDefer:
			default:
				return fmt.Errorf("mcp_tool_policy rule %q has invalid action %q: must be warn, block, redirect, or defer", r.Name, r.Action)
			}
		}
	}
	return nil
}

func preserveConductorBundleDLP(newCfg, oldCfg *Config, bundleOwnsSection bool, bundlePatterns []DLPPattern) error {
	newCfg.DLP = oldCfg.DLP
	newCfg.DLP.Patterns = cloneDLPPatterns(oldCfg.DLP.Patterns)
	if !bundleOwnsSection {
		return nil
	}
	merged, err := mergeConductorBundleDLPPatterns(newCfg.DLP.Patterns, bundlePatterns)
	if err != nil {
		return err
	}
	newCfg.DLP.Patterns = merged
	return nil
}

func mergeConductorBundleDLPPatterns(local, bundle []DLPPattern) ([]DLPPattern, error) {
	merged := cloneDLPPatterns(local)
	byName := make(map[string]DLPPattern, len(local))
	byIdentity := make(map[string]struct{}, len(local))
	for _, p := range local {
		byName[p.Name] = p
		byIdentity[dlpPatternIdentity(p)] = struct{}{}
	}
	for _, p := range bundle {
		if existing, ok := byName[p.Name]; ok {
			if !sameDLPPatternDefinition(existing, p) {
				return nil, fmt.Errorf("conductor policy bundle cannot redefine local dlp.patterns item %q", p.Name)
			}
			continue
		}
		key := dlpPatternIdentity(p)
		if _, ok := byIdentity[key]; ok {
			continue
		}
		byName[p.Name] = p
		byIdentity[key] = struct{}{}
		merged = append(merged, p)
	}
	return merged, nil
}

func dlpPatternIdentity(p DLPPattern) string {
	return p.Name + "\x00" + p.Regex
}

func sameDLPPatternDefinition(a, b DLPPattern) bool {
	return a.Name == b.Name &&
		a.Regex == b.Regex &&
		a.Severity == b.Severity &&
		a.Validator == b.Validator &&
		a.Action == b.Action &&
		slices.Equal(a.ExemptDomains, b.ExemptDomains)
}

func preserveConductorBundleCanaryTokens(newCfg, oldCfg *Config, bundleOwnsSection bool, bundleCanaryTokens CanaryTokens) error {
	bundleTokens := cloneCanaryTokens(bundleCanaryTokens.Tokens)
	newCfg.CanaryTokens = CanaryTokens{
		Enabled: oldCfg.CanaryTokens.Enabled,
		Tokens:  cloneCanaryTokens(oldCfg.CanaryTokens.Tokens),
	}
	if !bundleOwnsSection {
		return nil
	}
	merged, err := mergeConductorBundleCanaryTokens(newCfg.CanaryTokens.Tokens, bundleTokens)
	if err != nil {
		return err
	}
	newCfg.CanaryTokens.Enabled = oldCfg.CanaryTokens.Enabled || bundleCanaryTokens.Enabled
	newCfg.CanaryTokens.Tokens = merged
	return nil
}

func mergeConductorBundleCanaryTokens(local, bundle []CanaryToken) ([]CanaryToken, error) {
	merged := cloneCanaryTokens(local)
	byName := make(map[string]CanaryToken, len(local))
	byIdentity := make(map[string]struct{}, len(local))
	for _, token := range local {
		byName[token.Name] = token
		byIdentity[canaryTokenIdentity(token)] = struct{}{}
	}
	for _, token := range bundle {
		if existing, ok := byName[token.Name]; ok {
			if existing != token {
				return nil, fmt.Errorf("conductor policy bundle cannot redefine local canary_tokens.tokens item %q", token.Name)
			}
			continue
		}
		key := canaryTokenIdentity(token)
		if _, ok := byIdentity[key]; ok {
			continue
		}
		byName[token.Name] = token
		byIdentity[key] = struct{}{}
		merged = append(merged, token)
	}
	return merged, nil
}

func canaryTokenIdentity(token CanaryToken) string {
	return token.Name + "\x00" + token.Value + "\x00" + token.EnvVar
}

func cloneCanaryTokens(src []CanaryToken) []CanaryToken {
	if src == nil {
		return nil
	}
	dst := make([]CanaryToken, len(src))
	copy(dst, src)
	return dst
}

func preserveConductorBundleResponseScanning(newCfg, oldCfg *Config, bundleOwnsSection bool, bundlePatterns []ResponseScanPattern) error {
	newCfg.ResponseScanning = oldCfg.ResponseScanning
	newCfg.ResponseScanning.Patterns = cloneResponseScanPatterns(oldCfg.ResponseScanning.Patterns)
	if !bundleOwnsSection {
		return nil
	}
	merged, err := mergeConductorBundleResponsePatterns(newCfg.ResponseScanning.Patterns, bundlePatterns)
	if err != nil {
		return err
	}
	newCfg.ResponseScanning.Patterns = merged
	return nil
}

func mergeConductorBundleResponsePatterns(local, bundle []ResponseScanPattern) ([]ResponseScanPattern, error) {
	merged := cloneResponseScanPatterns(local)
	byName := make(map[string]ResponseScanPattern, len(local))
	byIdentity := make(map[string]struct{}, len(local))
	for _, p := range local {
		byName[p.Name] = p
		byIdentity[responsePatternIdentity(p)] = struct{}{}
	}
	for _, p := range bundle {
		if existing, ok := byName[p.Name]; ok {
			if !sameResponsePatternDefinition(existing, p) {
				return nil, fmt.Errorf("conductor policy bundle cannot redefine local response_scanning.patterns item %q", p.Name)
			}
			continue
		}
		key := responsePatternIdentity(p)
		if _, ok := byIdentity[key]; ok {
			continue
		}
		byName[p.Name] = p
		byIdentity[key] = struct{}{}
		merged = append(merged, p)
	}
	return merged, nil
}

func responsePatternIdentity(p ResponseScanPattern) string {
	return p.Name + "\x00" + p.Regex
}

func sameResponsePatternDefinition(a, b ResponseScanPattern) bool {
	return a.Name == b.Name && a.Regex == b.Regex
}

func preserveConductorBundleMCPToolPolicy(newCfg, oldCfg *Config, bundleOwnsSection bool, bundleRules []ToolPolicyRule) error {
	newCfg.MCPToolPolicy = oldCfg.MCPToolPolicy
	newCfg.MCPToolPolicy.Rules = cloneToolPolicyRules(oldCfg.MCPToolPolicy.Rules)
	if !bundleOwnsSection {
		return nil
	}
	merged, err := mergeConductorBundleToolPolicyRules(newCfg.MCPToolPolicy.Rules, bundleRules)
	if err != nil {
		return err
	}
	// Bundles contribute only rules here. Redirect and defer resolver profiles
	// stay follower-local, so bundle redirect/defer rules must reference
	// profiles that already exist in the preserved local policy.
	validationPolicy := newCfg.MCPToolPolicy
	validationPolicy.Rules = merged
	if err := validateConductorBundleToolPolicyRuleActions(validationPolicy, oldCfg.Defer, bundleRules); err != nil {
		return err
	}
	newCfg.MCPToolPolicy.Rules = merged
	return nil
}

func validateConductorBundleToolPolicyRuleActions(policy MCPToolPolicy, deferCfg DeferConfig, bundleRules []ToolPolicyRule) error {
	for _, rule := range bundleRules {
		effectiveAction := rule.Action
		if effectiveAction == "" {
			effectiveAction = policy.Action
		}
		switch effectiveAction {
		case "", ActionWarn, ActionBlock:
			continue
		case ActionRedirect:
			if err := validateConductorBundleToolPolicyRedirectRule(policy, rule); err != nil {
				return err
			}
		case ActionDefer:
			if err := validateConductorBundleToolPolicyDeferRule(policy, deferCfg, rule); err != nil {
				return err
			}
		default:
			return fmt.Errorf("mcp_tool_policy rule %q inherits invalid action %q: must be warn, block, redirect, or defer", rule.Name, effectiveAction)
		}
	}
	return nil
}

func validateConductorBundleToolPolicyRedirectRule(policy MCPToolPolicy, rule ToolPolicyRule) error {
	if rule.RedirectProfile == "" {
		return fmt.Errorf("mcp_tool_policy rule %q has action=redirect but no redirect_profile", rule.Name)
	}
	profile, ok := policy.RedirectProfiles[rule.RedirectProfile]
	if !ok {
		return fmt.Errorf("mcp_tool_policy rule %q references unknown redirect_profile %q", rule.Name, rule.RedirectProfile)
	}
	return validateConductorBundleToolPolicyProfile("redirect_profile", rule.RedirectProfile, profile.Exec, profile.MatchAbsPath)
}

func validateConductorBundleToolPolicyDeferRule(policy MCPToolPolicy, deferCfg DeferConfig, rule ToolPolicyRule) error {
	if !deferCfg.Enabled {
		return fmt.Errorf("mcp_tool_policy rule %q has action=defer but defer.enabled is false", rule.Name)
	}
	if rule.ResolutionPolicy == nil {
		return fmt.Errorf("mcp_tool_policy rule %q has action=defer but no affirmative resolution_policy", rule.Name)
	}
	if rule.ResolutionPolicy.AllowOn.PolicyPermits {
		return fmt.Errorf("mcp_tool_policy rule %q has resolution_policy.allow_on.policy_permits but policy_reload cannot fire on supported defer transports yet", rule.Name)
	}
	if !rule.ResolutionPolicy.HasAffirmativeSignal() {
		return fmt.Errorf("mcp_tool_policy rule %q has action=defer but no affirmative resolution_policy", rule.Name)
	}
	approvalRequested := rule.ResolutionPolicy.AllowOn.Approval || rule.ResolutionPolicy.StepUpOn.ApprovalRequestsHuman
	if !approvalRequested {
		return nil
	}
	if rule.ResolutionPolicy.ResolverProfile == "" {
		return fmt.Errorf("mcp_tool_policy rule %q uses approval resolution but has no resolution_policy.resolver_profile", rule.Name)
	}
	profile, ok := policy.DeferResolverProfiles[rule.ResolutionPolicy.ResolverProfile]
	if !ok {
		return fmt.Errorf("mcp_tool_policy rule %q references unknown defer resolver profile %q", rule.Name, rule.ResolutionPolicy.ResolverProfile)
	}
	return validateConductorBundleToolPolicyProfile("defer_resolver_profile", rule.ResolutionPolicy.ResolverProfile, profile.Exec, profile.MatchAbsPath)
}

func validateConductorBundleToolPolicyProfile(kind, name string, exec []string, matchAbsPath bool) error {
	if len(exec) == 0 || exec[0] == "" {
		return fmt.Errorf("mcp_tool_policy %s %q has empty exec", kind, name)
	}
	if matchAbsPath && !filepath.IsAbs(exec[0]) {
		return fmt.Errorf("mcp_tool_policy %s %q: match_abs_path is true but exec[0] %q is not absolute", kind, name, exec[0])
	}
	return nil
}

func mergeConductorBundleToolPolicyRules(local, bundle []ToolPolicyRule) ([]ToolPolicyRule, error) {
	merged := cloneToolPolicyRules(local)
	byName := make(map[string]ToolPolicyRule, len(local))
	byIdentity := make(map[string]struct{}, len(local))
	for _, rule := range local {
		byName[rule.Name] = rule
		byIdentity[toolPolicyRuleIdentity(rule)] = struct{}{}
	}
	for _, rule := range bundle {
		if existing, ok := byName[rule.Name]; ok {
			if !reflect.DeepEqual(existing, rule) {
				return nil, fmt.Errorf("conductor policy bundle cannot redefine local mcp_tool_policy.rules item %q", rule.Name)
			}
			continue
		}
		key := toolPolicyRuleIdentity(rule)
		if _, ok := byIdentity[key]; ok {
			continue
		}
		byName[rule.Name] = rule
		byIdentity[key] = struct{}{}
		merged = append(merged, rule)
	}
	return merged, nil
}

func toolPolicyRuleIdentity(rule ToolPolicyRule) string {
	return rule.Name + "\x00" + rule.ToolPattern + "\x00" + rule.ArgPattern + "\x00" + rule.ArgKey
}
