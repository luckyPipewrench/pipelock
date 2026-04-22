// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

// RuntimeMode selects which runtime-time defaults ResolveRuntime applies.
// It is an explicit CLI-surface value: the same loaded Config can produce
// different effective policies depending on which command path consumes it
// (forward proxy alone, forward proxy with an MCP listener, or `mcp proxy`
// wrapper), and canonical policy hashes stamped on receipts/envelopes must
// reflect the mode-specific defaults that actually ran.
type RuntimeMode uint8

const (
	// RuntimeForward runs the forward / fetch proxy without an MCP listener.
	RuntimeForward RuntimeMode = iota + 1

	// RuntimeForwardWithMCPListener runs the forward / fetch proxy alongside
	// an MCP HTTP listener (run --mcp-listen). MCP input scanning, tool
	// scanning, and tool policy auto-enable with safe defaults when the
	// operator did not configure them.
	RuntimeForwardWithMCPListener

	// RuntimeMCPProxy runs `pipelock mcp proxy` in stdio or HTTP wrapping
	// mode. Same MCP auto-enable as the listener mode, plus a response
	// scanning fallback that re-enables defaults if the operator disabled
	// response scanning (response scanning is the MCP proxy's primary
	// injection surface).
	RuntimeMCPProxy
)

// WrapsMCP reports whether the mode routes MCP traffic through pipelock and
// therefore needs MCP scanning auto-enable defaults.
func (m RuntimeMode) WrapsMCP() bool {
	return m == RuntimeForwardWithMCPListener || m == RuntimeMCPProxy
}

// RuntimeResolveOpts controls how ResolveRuntime assembles the effective
// runtime policy. Each field is independently optional; zero-value opts
// still produce a valid clone (no bundle merge, no auto-enable, no
// fallback).
type RuntimeResolveOpts struct {
	// Mode selects the runtime profile. A zero value skips mode-specific
	// auto-enable and the MCP proxy response-scanning fallback.
	Mode RuntimeMode

	// MergeBundles, if non-nil, is invoked on the freshly cloned config
	// before any mode-specific auto-enable runs. Callers use it to merge
	// rule bundles into DLP and response scanning pattern lists without
	// creating an import cycle on the rules package.
	MergeBundles func(*Config)

	// DefaultToolPolicyRules, if non-nil, is invoked when MCP tool policy
	// auto-enables to populate MCPToolPolicy.Rules. Passed as a function
	// (rather than a slice) so it is only evaluated when auto-enable
	// actually fires, and so the config package does not import the
	// mcp/policy package that owns the defaults.
	DefaultToolPolicyRules func() []ToolPolicyRule
}

// ResolveRuntimeInfo captures which auto-enable and fallback branches
// fired during ResolveRuntime. Callers log operator-facing messages based
// on these flags: the config package does not print directly so it stays
// free of an io.Writer dependency and so tests can verify the resolution
// decisions without parsing stderr.
type ResolveRuntimeInfo struct {
	// ResponseScanningFallback is true when MCP proxy mode re-enabled
	// default response scanning because the operator had disabled it.
	ResponseScanningFallback bool

	// MCPInputScanningAutoEnabled is true when input scanning was
	// unconfigured and the runtime default was applied.
	MCPInputScanningAutoEnabled bool

	// MCPToolScanningAutoEnabled is true when tool scanning was
	// unconfigured and the runtime default was applied.
	MCPToolScanningAutoEnabled bool

	// MCPToolPolicyAutoEnabled is true when tool policy was
	// unconfigured and the runtime default was applied.
	MCPToolPolicyAutoEnabled bool
}

// ResolveRuntime returns a cloned *Config with runtime-mode policy
// resolution applied, plus a ResolveRuntimeInfo describing which defaults
// fired. The receiver is never mutated; downstream runtime wiring
// (scanner construction, emitters, proxy) must consume the returned
// clone so any canonical policy hash stamped on receipts or envelopes
// reflects the effective policy that was actually enforced.
//
// The resolution order is intentional: (1) deep clone, (2) MCP proxy
// response-scanning fallback, (3) caller-supplied bundle merge,
// (4) mode-aware MCP scanning auto-enable. The fallback runs before the
// bundle merge because it replaces the entire ResponseScanning struct
// with defaults; any bundle-appended ResponseScanning.Patterns applied
// before the fallback would be wiped. Running the fallback first lets
// the merge append its patterns on top of the default set.
func (c *Config) ResolveRuntime(opts RuntimeResolveOpts) (*Config, ResolveRuntimeInfo) {
	clone := c.Clone()
	var info ResolveRuntimeInfo

	if opts.Mode == RuntimeMCPProxy && !clone.ResponseScanning.Enabled {
		// MCP proxy mode re-enables default response scanning if the
		// operator disabled it. Response scanning is the primary injection
		// defence on the MCP response path; silently running without it
		// would leave tool responses unscanned. Runs before MergeBundles
		// because this replaces the entire struct, which would otherwise
		// wipe bundle-appended patterns.
		clone.ResponseScanning = Defaults().ResponseScanning
		info.ResponseScanningFallback = true
	}

	if opts.MergeBundles != nil {
		opts.MergeBundles(clone)
	}

	if opts.Mode.WrapsMCP() {
		applyMCPAutoEnable(clone, opts.DefaultToolPolicyRules, &info)
	}

	return clone, info
}

// applyMCPAutoEnable flips MCP scanning sections on when the operator did
// not explicitly configure them. A section counts as unconfigured when
// Enabled is false AND Action is empty (ApplyDefaults sets Action only
// when Enabled is true, so an empty Action with Enabled false indicates
// an unset YAML section rather than an explicit disable). Tool policy also
// requires len(Rules)==0 for the same reason. Each auto-enable branch
// records its decision on info so callers can print operator-facing
// log messages without replicating the predicate.
func applyMCPAutoEnable(c *Config, defaultToolPolicyRules func() []ToolPolicyRule, info *ResolveRuntimeInfo) {
	if !c.MCPInputScanning.Enabled && c.MCPInputScanning.Action == "" {
		c.MCPInputScanning.Enabled = true
		c.MCPInputScanning.Action = ActionBlock
		info.MCPInputScanningAutoEnabled = true
	}
	if !c.MCPToolScanning.Enabled && c.MCPToolScanning.Action == "" {
		c.MCPToolScanning.Enabled = true
		c.MCPToolScanning.Action = ActionWarn
		c.MCPToolScanning.DetectDrift = true
		info.MCPToolScanningAutoEnabled = true
	}
	if !c.MCPToolPolicy.Enabled && c.MCPToolPolicy.Action == "" && len(c.MCPToolPolicy.Rules) == 0 {
		c.MCPToolPolicy.Enabled = true
		c.MCPToolPolicy.Action = ActionWarn
		if defaultToolPolicyRules != nil {
			c.MCPToolPolicy.Rules = defaultToolPolicyRules()
		}
		info.MCPToolPolicyAutoEnabled = true
	}
}

// Clone returns a deep copy of c suitable for runtime mutation. The clone
// has a fresh canonical hash cache, and policy-semantic slices (DLP
// patterns, response scan patterns, tool policy rules) are independently
// allocated so mutations to the clone never alias back into the receiver.
//
// rawBytes is copied verbatim so Hash() on the clone still reflects the
// on-disk YAML bytes that were loaded — the receipt-audit fingerprint is
// about "what YAML file was loaded", which does not change under bundle
// merge or auto-enable. CanonicalPolicyHash recomputes from the clone's
// current state the first time it is called.
//
// Nested slices inside DLPPattern (ExemptDomains) and other mutable
// collections touched by ResolveRuntime are copied as well. Unmodified
// nested collections (map fields in MCPToolPolicy, AgentProfile maps, and
// similar) are shallow-copied; callers that mutate those directly outside
// the ResolveRuntime pipeline are responsible for their own aliasing.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	clone := *c

	// atomic.Value must not be copied after first use. Replace with a
	// fresh zero value so the clone starts with an empty canonical hash
	// cache and computes against its own post-resolve state.
	clone.canonicalHashCache = canonicalHashCacheHolder{}

	// Copy rawBytes so mutations to the clone's byte buffer do not alias
	// back to the receiver. Hash() on the clone continues to reflect the
	// original on-disk YAML bytes.
	if c.rawBytes != nil {
		buf := make([]byte, len(c.rawBytes))
		copy(buf, c.rawBytes)
		clone.rawBytes = buf
	}

	clone.DLP.Patterns = cloneDLPPatterns(c.DLP.Patterns)
	clone.ResponseScanning.Patterns = cloneResponseScanPatterns(c.ResponseScanning.Patterns)
	clone.MCPToolPolicy.Rules = cloneToolPolicyRules(c.MCPToolPolicy.Rules)

	return &clone
}

// cloneDLPPatterns returns a deep copy of src. Each pattern's ExemptDomains
// slice is copied so mutating the clone never leaks back into src.
func cloneDLPPatterns(src []DLPPattern) []DLPPattern {
	if src == nil {
		return nil
	}
	dst := make([]DLPPattern, len(src))
	for i := range src {
		dst[i] = src[i]
		if src[i].ExemptDomains != nil {
			dst[i].ExemptDomains = append([]string(nil), src[i].ExemptDomains...)
		}
	}
	return dst
}

// cloneResponseScanPatterns returns a deep copy of src. ResponseScanPattern
// has no nested slices today; the helper exists so future additions pick up
// deep-copy behavior without caller churn.
func cloneResponseScanPatterns(src []ResponseScanPattern) []ResponseScanPattern {
	if src == nil {
		return nil
	}
	dst := make([]ResponseScanPattern, len(src))
	copy(dst, src)
	return dst
}

// cloneToolPolicyRules returns a deep copy of src. ToolPolicyRule has only
// scalar fields today; the helper keeps the pattern consistent with the
// other clone helpers and gives future nested-slice additions a clear home.
func cloneToolPolicyRules(src []ToolPolicyRule) []ToolPolicyRule {
	if src == nil {
		return nil
	}
	dst := make([]ToolPolicyRule, len(src))
	copy(dst, src)
	return dst
}
