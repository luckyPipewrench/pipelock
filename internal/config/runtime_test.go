// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"
)

const mutatedSentinel = "mutated"

// TestResolveRuntime_LoadedConfigNotMutated is the core immutability
// invariant: ResolveRuntime must not mutate its receiver. The loaded
// *Config is treated as immutable after Load() returns, and its
// canonical hash cache is warmed against that post-Load snapshot.
// Runtime-mode defaults (bundle merges, MCP auto-enable) apply to the
// returned clone only.
func TestResolveRuntime_LoadedConfigNotMutated(t *testing.T) {
	cfg := Defaults()
	cfg.rawBytes = []byte("mode: balanced\n")
	beforeHash := cfg.CanonicalPolicyHash()
	beforeRawHash := cfg.Hash()
	beforeInput := cfg.MCPInputScanning
	beforeTool := cfg.MCPToolScanning
	beforePolicy := cfg.MCPToolPolicy
	beforeResponse := cfg.ResponseScanning

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{
		Mode: RuntimeForwardWithMCPListener,
		MergeBundles: func(c *Config) {
			c.DLP.Patterns = append(c.DLP.Patterns, DLPPattern{Name: "bundle", Regex: "."})
		},
	})

	if got := cfg.CanonicalPolicyHash(); got != beforeHash {
		t.Errorf("CanonicalPolicyHash on loaded config changed after resolve: before=%s after=%s", beforeHash, got)
	}
	if got := cfg.Hash(); got != beforeRawHash {
		t.Errorf("Hash on loaded config changed after resolve: before=%s after=%s", beforeRawHash, got)
	}
	if !reflect.DeepEqual(cfg.MCPInputScanning, beforeInput) {
		t.Errorf("MCPInputScanning mutated on loaded config: got %+v want %+v", cfg.MCPInputScanning, beforeInput)
	}
	if !reflect.DeepEqual(cfg.MCPToolScanning, beforeTool) {
		t.Errorf("MCPToolScanning mutated on loaded config: got %+v want %+v", cfg.MCPToolScanning, beforeTool)
	}
	if !reflect.DeepEqual(cfg.MCPToolPolicy, beforePolicy) {
		t.Errorf("MCPToolPolicy mutated on loaded config: got %+v want %+v", cfg.MCPToolPolicy, beforePolicy)
	}
	if !reflect.DeepEqual(cfg.ResponseScanning, beforeResponse) {
		t.Errorf("ResponseScanning mutated on loaded config: got %+v want %+v", cfg.ResponseScanning, beforeResponse)
	}
	if resolved == cfg {
		t.Error("ResolveRuntime returned the same *Config; expected a clone")
	}
}

// TestResolveRuntime_HashReflectsAutoEnable verifies that when a runtime
// mode triggers auto-enable, the clone's CanonicalPolicyHash differs from
// the loaded config's — receipts and envelopes stamped with the clone's
// hash will therefore match the policy the proxy enforces, not the
// pre-resolve state.
func TestResolveRuntime_HashReflectsAutoEnable(t *testing.T) {
	cfg := Defaults()
	cfg.rawBytes = []byte("mode: balanced\n")
	cfg.MCPInputScanning = MCPInputScanning{}
	cfg.MCPToolScanning = MCPToolScanning{}
	cfg.MCPToolPolicy = MCPToolPolicy{}
	loadedHash := cfg.CanonicalPolicyHash()

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})

	if got := resolved.CanonicalPolicyHash(); got == loadedHash {
		t.Errorf("resolved CanonicalPolicyHash matches loaded; auto-enable not reflected (both %s)", got)
	}
	if !resolved.MCPInputScanning.Enabled {
		t.Error("MCPInputScanning not auto-enabled on resolved clone")
	}
	if resolved.MCPInputScanning.Action != ActionBlock {
		t.Errorf("MCPInputScanning.Action = %q, want %q", resolved.MCPInputScanning.Action, ActionBlock)
	}
}

// TestResolveRuntime_Deterministic: identical inputs produce identical
// canonical hashes. Without this, a verifier that caches policy hashes
// across restarts would see spurious divergence on reload.
func TestResolveRuntime_Deterministic(t *testing.T) {
	cfg := Defaults()
	cfg.rawBytes = []byte("mode: balanced\n")
	opts := RuntimeResolveOpts{Mode: RuntimeForwardWithMCPListener}

	r1, _ := cfg.ResolveRuntime(opts)
	r2, _ := cfg.ResolveRuntime(opts)

	if got, want := r1.CanonicalPolicyHash(), r2.CanonicalPolicyHash(); got != want {
		t.Errorf("non-deterministic canonical hash: %s vs %s", got, want)
	}
	if got, want := r1.Hash(), r2.Hash(); got != want {
		t.Errorf("non-deterministic raw hash: %s vs %s", got, want)
	}
}

// TestResolveRuntime_SliceAliasingPrevented: mutating slices on the
// resolved clone must not leak into the loaded config. Without deep clone
// of the mutable policy surface, runtime auto-enable or bundle merge
// could retroactively change the policy the loaded config represents.
func TestResolveRuntime_SliceAliasingPrevented(t *testing.T) {
	cfg := Defaults()
	cfg.rawBytes = []byte("mode: balanced\n")
	cfg.DLP.Patterns = []DLPPattern{{Name: "seed", Regex: ".", ExemptDomains: []string{"example.com"}}}
	cfg.ResponseScanning.Patterns = []ResponseScanPattern{{Name: "seed", Regex: "."}}
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{Name: "seed", ToolPattern: "."}}

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeForward})

	resolved.DLP.Patterns[0].Name = mutatedSentinel
	resolved.DLP.Patterns[0].ExemptDomains[0] = "mutated.example"
	resolved.ResponseScanning.Patterns[0].Name = mutatedSentinel
	resolved.MCPToolPolicy.Rules[0].Name = mutatedSentinel

	if cfg.DLP.Patterns[0].Name == mutatedSentinel {
		t.Error("DLP.Patterns aliased — mutation on clone leaked into loaded config")
	}
	if cfg.DLP.Patterns[0].ExemptDomains[0] == "mutated.example" {
		t.Error("DLPPattern.ExemptDomains aliased — nested mutation leaked")
	}
	if cfg.ResponseScanning.Patterns[0].Name == mutatedSentinel {
		t.Error("ResponseScanning.Patterns aliased")
	}
	if cfg.MCPToolPolicy.Rules[0].Name == mutatedSentinel {
		t.Error("MCPToolPolicy.Rules aliased")
	}
}

// TestResolveRuntime_BundleMergeOnClone: the MergeBundles hook receives
// the clone, not the receiver. Callers that mutate patterns in the hook
// must see those changes on the resolved clone but never on the loaded
// config.
func TestResolveRuntime_BundleMergeOnClone(t *testing.T) {
	cfg := Defaults()
	cfg.DLP.Patterns = []DLPPattern{{Name: "seed", Regex: "."}}
	before := len(cfg.DLP.Patterns)

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{
		Mode: RuntimeForward,
		MergeBundles: func(c *Config) {
			c.DLP.Patterns = append(c.DLP.Patterns, DLPPattern{Name: "bundle", Regex: "."})
		},
	})

	if got := len(cfg.DLP.Patterns); got != before {
		t.Errorf("loaded DLP.Patterns mutated by merge hook: got %d want %d", got, before)
	}
	if got := len(resolved.DLP.Patterns); got != before+1 {
		t.Errorf("resolved DLP.Patterns missing bundle pattern: got %d want %d", got, before+1)
	}
}

// TestResolveRuntime_RespectsExplicitConfig: auto-enable must not override
// explicit operator configuration. An operator who set action=warn must
// get action=warn, not action=block.
func TestResolveRuntime_RespectsExplicitConfig(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning = MCPInputScanning{Enabled: true, Action: ActionWarn}

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})

	if resolved.MCPInputScanning.Action != ActionWarn {
		t.Errorf("auto-enable clobbered explicit action: got %q want %q", resolved.MCPInputScanning.Action, ActionWarn)
	}
	if !resolved.MCPInputScanning.Enabled {
		t.Error("auto-enable disabled an explicitly enabled section")
	}
}

// TestResolveRuntime_ForwardModeSkipsMCPAutoEnable: plain forward proxy
// mode (no MCP listener) must not auto-enable MCP scanning. Enabling it
// would waste cycles scanning non-MCP traffic and potentially produce
// spurious blocks.
func TestResolveRuntime_ForwardModeSkipsMCPAutoEnable(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning = MCPInputScanning{}
	cfg.MCPToolScanning = MCPToolScanning{}
	cfg.MCPToolPolicy = MCPToolPolicy{}

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeForward})

	if resolved.MCPInputScanning.Enabled {
		t.Error("RuntimeForward should not auto-enable MCPInputScanning")
	}
	if resolved.MCPToolScanning.Enabled {
		t.Error("RuntimeForward should not auto-enable MCPToolScanning")
	}
	if resolved.MCPToolPolicy.Enabled {
		t.Error("RuntimeForward should not auto-enable MCPToolPolicy")
	}
}

// TestResolveRuntime_MCPProxyResponseScanningFallback: when the operator
// disables response scanning, RuntimeMCPProxy falls back to defaults so
// tool responses still get scanned for injection. The fallback only
// applies in MCP proxy mode.
func TestResolveRuntime_MCPProxyResponseScanningFallback(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Enabled = false

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})

	if !resolved.ResponseScanning.Enabled {
		t.Error("RuntimeMCPProxy should fall back to default response scanning when disabled")
	}
	if cfg.ResponseScanning.Enabled {
		t.Error("loaded config mutated by response scanning fallback")
	}
}

// TestResolveRuntime_MCPProxyFallbackPreservesBundlePatterns ensures the
// response-scanning fallback runs BEFORE the caller-supplied bundle merge.
// The fallback replaces the entire ResponseScanning struct with defaults,
// so if it ran after MergeBundles the bundle-appended patterns would be
// silently discarded. Original mcp.go ordering was fallback-then-merge;
// this test pins that ordering inside ResolveRuntime.
func TestResolveRuntime_MCPProxyFallbackPreservesBundlePatterns(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Enabled = false

	resolved, info := cfg.ResolveRuntime(RuntimeResolveOpts{
		Mode: RuntimeMCPProxy,
		MergeBundles: func(c *Config) {
			c.ResponseScanning.Patterns = append(c.ResponseScanning.Patterns, ResponseScanPattern{
				Name:  "bundle-added",
				Regex: "bundle-only-regex",
			})
		},
	})

	if !info.ResponseScanningFallback {
		t.Fatal("expected response-scanning fallback to fire")
	}
	found := false
	for _, p := range resolved.ResponseScanning.Patterns {
		if p.Name == "bundle-added" {
			found = true
			break
		}
	}
	if !found {
		t.Error("bundle-added pattern missing from resolved ResponseScanning.Patterns; fallback ran after merge and wiped bundle appends")
	}
}

// TestResolveRuntime_MCPProxyFallbackSkippedWhenEnabled: the fallback
// does not clobber an explicitly enabled response-scanning config.
func TestResolveRuntime_MCPProxyFallbackSkippedWhenEnabled(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = ActionWarn

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})

	if resolved.ResponseScanning.Action != ActionWarn {
		t.Errorf("fallback clobbered explicit response scanning action: got %q want %q", resolved.ResponseScanning.Action, ActionWarn)
	}
}

// TestResolveRuntime_DefaultToolPolicyRulesCalledOnAutoEnable: when tool
// policy auto-enables, DefaultToolPolicyRules is invoked exactly once and
// its result populates Rules.
func TestResolveRuntime_DefaultToolPolicyRulesCalledOnAutoEnable(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy = MCPToolPolicy{}

	callCount := 0
	defaults := []ToolPolicyRule{{Name: "rule-a", ToolPattern: "."}}
	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{
		Mode: RuntimeMCPProxy,
		DefaultToolPolicyRules: func() []ToolPolicyRule {
			callCount++
			return defaults
		},
	})

	if callCount != 1 {
		t.Errorf("DefaultToolPolicyRules called %d times, want 1", callCount)
	}
	if got, want := len(resolved.MCPToolPolicy.Rules), 1; got != want {
		t.Fatalf("resolved.MCPToolPolicy.Rules len = %d, want %d", got, want)
	}
	if resolved.MCPToolPolicy.Rules[0].Name != "rule-a" {
		t.Errorf("auto-enable did not populate default rule: got %q", resolved.MCPToolPolicy.Rules[0].Name)
	}
}

// TestResolveRuntime_DefaultToolPolicyRulesNotCalledWhenRulesPresent:
// when the operator supplied rules explicitly, auto-enable leaves them
// alone and DefaultToolPolicyRules is not invoked.
func TestResolveRuntime_DefaultToolPolicyRulesNotCalledWhenRulesPresent(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy = MCPToolPolicy{
		Rules: []ToolPolicyRule{{Name: "operator", ToolPattern: "."}},
	}

	callCount := 0
	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{
		Mode: RuntimeMCPProxy,
		DefaultToolPolicyRules: func() []ToolPolicyRule {
			callCount++
			return nil
		},
	})

	if callCount != 0 {
		t.Errorf("DefaultToolPolicyRules called %d times, want 0", callCount)
	}
	if got, want := len(resolved.MCPToolPolicy.Rules), 1; got != want {
		t.Fatalf("operator rules overwritten: got %d rules, want %d", got, want)
	}
	if resolved.MCPToolPolicy.Rules[0].Name != "operator" {
		t.Errorf("operator rules clobbered: got %q", resolved.MCPToolPolicy.Rules[0].Name)
	}
}

// TestClone_FreshCanonicalHashCache: cloning must produce a *Config whose
// canonical hash cache starts empty. Without this, mutations on the clone
// would silently return the receiver's cached hash.
func TestClone_FreshCanonicalHashCache(t *testing.T) {
	cfg := Defaults()
	cfg.rawBytes = []byte("mode: balanced\n")
	// Warm source cache.
	_ = cfg.CanonicalPolicyHash()

	clone := cfg.Clone()
	if clone.canonicalHashCache == nil {
		t.Fatal("Clone returned a *Config with a nil canonical hash cache holder; expected a fresh allocation")
	}
	if clone.canonicalHashCache == cfg.canonicalHashCache {
		t.Error("Clone aliased the receiver's canonical hash cache pointer; expected a separate holder")
	}
	if cached := clone.canonicalHashCache.Load(); cached != nil {
		t.Errorf("Clone returned a *Config with a pre-warmed canonical hash cache: %v", cached)
	}

	// Clone computes its own hash.
	got := clone.CanonicalPolicyHash()
	if want := clone.computeCanonicalPolicyHash(); got != want {
		t.Errorf("cloned canonical hash mismatch: got %s want %s", got, want)
	}
}

// TestClone_RawBytesCopiedNotAliased: editing the clone's rawBytes must
// not mutate the receiver's rawBytes. Without the copy, receipt Hash()
// could be retroactively invalidated by downstream code that edits raw
// bytes (e.g., canary injection or serialization helpers).
func TestClone_RawBytesCopiedNotAliased(t *testing.T) {
	cfg := Defaults()
	cfg.rawBytes = []byte("mode: balanced\n")
	srcHash := cfg.Hash()

	clone := cfg.Clone()
	clone.rawBytes[0] = 'Z'

	if got := cfg.Hash(); got != srcHash {
		t.Errorf("Clone aliased rawBytes; src Hash changed from %s to %s after clone edit", srcHash, got)
	}
}

// TestClone_NilSafe: Clone on a nil receiver returns nil without panicking.
// Defensive: some test paths pass optional configs as *Config.
func TestClone_NilSafe(t *testing.T) {
	var c *Config
	if got := c.Clone(); got != nil {
		t.Errorf("Clone(nil) = %v, want nil", got)
	}
}

// TestResolveRuntime_HashSemanticsStable pins the intentional split
// between Hash() (raw YAML audit fingerprint) and CanonicalPolicyHash()
// (effective policy attestation). After resolve, the clone's raw Hash()
// must equal the receiver's Hash() — both refer to the on-disk YAML that
// was loaded. The clone's CanonicalPolicyHash() may differ because bundle
// merge and auto-enable shift effective policy. This split is the reason
// receipts (point-in-time audit) use Hash() and envelopes (policy
// attestation) use CanonicalPolicyHash(). A future refactor that unifies
// them must explicitly update this test.
func TestResolveRuntime_HashSemanticsStable(t *testing.T) {
	cfg := Defaults()
	cfg.rawBytes = []byte("mode: balanced\n")
	cfg.MCPInputScanning = MCPInputScanning{}
	cfg.MCPToolScanning = MCPToolScanning{}
	cfg.MCPToolPolicy = MCPToolPolicy{}

	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})

	if got, want := resolved.Hash(), cfg.Hash(); got != want {
		t.Errorf("resolved Hash() diverged from loaded: got %s want %s (rawBytes should be preserved)", got, want)
	}
	if resolved.CanonicalPolicyHash() == cfg.CanonicalPolicyHash() {
		t.Error("resolved CanonicalPolicyHash() matched loaded; expected divergence once auto-enable fired")
	}
}

// TestResolveRuntime_InfoReportsFiredBranches pins the operator-visible
// side of ResolveRuntime: the returned ResolveRuntimeInfo must flag every
// auto-enable or fallback branch that fired so CLI callers can emit a
// matching log line. Without this contract, moving the auto-enable
// predicates into the config package silently removes the "auto-enabling
// MCP ..." operator messages and any tooling that grep-parses those
// lines silently breaks.
func TestResolveRuntime_InfoReportsFiredBranches(t *testing.T) {
	t.Run("all unconfigured fire", func(t *testing.T) {
		cfg := Defaults()
		cfg.ResponseScanning.Enabled = false
		cfg.MCPInputScanning = MCPInputScanning{}
		cfg.MCPToolScanning = MCPToolScanning{}
		cfg.MCPToolPolicy = MCPToolPolicy{}

		_, info := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})

		if !info.ResponseScanningFallback {
			t.Error("ResponseScanningFallback not flagged")
		}
		if !info.MCPInputScanningAutoEnabled {
			t.Error("MCPInputScanningAutoEnabled not flagged")
		}
		if !info.MCPToolScanningAutoEnabled {
			t.Error("MCPToolScanningAutoEnabled not flagged")
		}
		if !info.MCPToolPolicyAutoEnabled {
			t.Error("MCPToolPolicyAutoEnabled not flagged")
		}
	})

	t.Run("all explicit: no flags fire", func(t *testing.T) {
		cfg := Defaults()
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.Action = ActionBlock
		cfg.MCPInputScanning = MCPInputScanning{Enabled: true, Action: ActionBlock}
		cfg.MCPToolScanning = MCPToolScanning{Enabled: true, Action: ActionBlock}
		cfg.MCPToolPolicy = MCPToolPolicy{Enabled: true, Action: ActionBlock}

		_, info := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})

		if info.ResponseScanningFallback {
			t.Error("ResponseScanningFallback should not fire on explicit config")
		}
		if info.MCPInputScanningAutoEnabled {
			t.Error("MCPInputScanningAutoEnabled should not fire on explicit config")
		}
		if info.MCPToolScanningAutoEnabled {
			t.Error("MCPToolScanningAutoEnabled should not fire on explicit config")
		}
		if info.MCPToolPolicyAutoEnabled {
			t.Error("MCPToolPolicyAutoEnabled should not fire on explicit config")
		}
	})

	t.Run("forward mode skips all MCP flags", func(t *testing.T) {
		cfg := Defaults()
		cfg.MCPInputScanning = MCPInputScanning{}
		cfg.MCPToolScanning = MCPToolScanning{}
		cfg.MCPToolPolicy = MCPToolPolicy{}

		_, info := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeForward})

		if info.MCPInputScanningAutoEnabled || info.MCPToolScanningAutoEnabled || info.MCPToolPolicyAutoEnabled {
			t.Errorf("RuntimeForward should not fire any MCP auto-enable flags: %+v", info)
		}
	})
}

// TestResolveRuntime_ResolvedComparisonAvoidsFalseReloadWarnings pins the
// hot-reload contract behind run.go: ValidateReload must compare two
// resolved runtime configs, not a resolved live config against a freshly
// loaded unresolved one. Otherwise bundle merges and MCP listener
// auto-enable look like operator downgrades.
func TestResolveRuntime_ResolvedComparisonAvoidsFalseReloadWarnings(t *testing.T) {
	base := Defaults()
	base.DLP.Patterns = []DLPPattern{{Name: "seed", Regex: "."}}
	base.MCPInputScanning = MCPInputScanning{}
	base.MCPToolScanning = MCPToolScanning{}
	base.MCPToolPolicy = MCPToolPolicy{}

	opts := RuntimeResolveOpts{
		Mode: RuntimeForwardWithMCPListener,
		MergeBundles: func(c *Config) {
			c.DLP.Patterns = append(c.DLP.Patterns, DLPPattern{Name: "bundle", Regex: "."})
		},
		DefaultToolPolicyRules: func() []ToolPolicyRule {
			return []ToolPolicyRule{{Name: "default-rule", ToolPattern: "."}}
		},
	}

	oldResolved, _ := base.ResolveRuntime(opts)
	unresolvedNext := base.Clone()

	unresolvedWarnings := ValidateReload(oldResolved, unresolvedNext)
	if len(unresolvedWarnings) == 0 {
		t.Fatal("ValidateReload(resolved, unresolved) returned no warnings; test setup is not exercising the hot-reload bug")
	}

	expectedFalsePositives := map[string]bool{
		"dlp.patterns":               false,
		"mcp_input_scanning.enabled": false,
		"mcp_tool_scanning.enabled":  false,
		"mcp_tool_policy.enabled":    false,
		"mcp_tool_policy.rules":      false,
	}
	for _, w := range unresolvedWarnings {
		if _, ok := expectedFalsePositives[w.Field]; ok {
			expectedFalsePositives[w.Field] = true
		}
	}
	for field, seen := range expectedFalsePositives {
		if !seen {
			t.Errorf("ValidateReload(resolved, unresolved) missing expected false-positive warning for %s", field)
		}
	}

	newResolved, _ := unresolvedNext.ResolveRuntime(opts)
	if warnings := ValidateReload(oldResolved, newResolved); len(warnings) != 0 {
		t.Fatalf("ValidateReload(resolved, resolved) returned unexpected warnings: %+v", warnings)
	}
}

// TestCloneHelpers_NilAndEmpty covers the nil/empty slice paths in the
// internal clone helpers. Explicit so goconst + coverage stay honest:
// the clone helpers must produce nil when given nil (not an empty slice)
// so canonical-hash stability is preserved across the omitted-field vs
// empty-slice distinction.
func TestCloneHelpers_NilAndEmpty(t *testing.T) {
	if got := cloneDLPPatterns(nil); got != nil {
		t.Errorf("cloneDLPPatterns(nil) = %v, want nil", got)
	}
	if got := cloneResponseScanPatterns(nil); got != nil {
		t.Errorf("cloneResponseScanPatterns(nil) = %v, want nil", got)
	}
	if got := cloneToolPolicyRules(nil); got != nil {
		t.Errorf("cloneToolPolicyRules(nil) = %v, want nil", got)
	}
}

// TestRuntimeMode_WrapsMCP exercises the mode helper used across the
// resolve pipeline. Exported so runtime code can branch on it without
// replicating the set membership test.
func TestRuntimeMode_WrapsMCP(t *testing.T) {
	cases := []struct {
		mode RuntimeMode
		want bool
	}{
		{RuntimeForward, false},
		{RuntimeForwardWithMCPListener, true},
		{RuntimeMCPProxy, true},
		{RuntimeMCPScan, false}, // scan consumes stdin, not a proxy
		{RuntimeMode(0), false}, // zero value
	}
	for _, tc := range cases {
		if got := tc.mode.WrapsMCP(); got != tc.want {
			t.Errorf("RuntimeMode(%d).WrapsMCP() = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

// TestRuntimeMode_NeedsResponseScanningFallback: both proxy and scan
// modes process MCP responses and need the response-scanning fallback
// to fire; forward-only modes do not.
func TestRuntimeMode_NeedsResponseScanningFallback(t *testing.T) {
	cases := []struct {
		mode RuntimeMode
		want bool
	}{
		{RuntimeForward, false},
		{RuntimeForwardWithMCPListener, false},
		{RuntimeMCPProxy, true},
		{RuntimeMCPScan, true},
		{RuntimeMode(0), false},
	}
	for _, tc := range cases {
		if got := tc.mode.NeedsResponseScanningFallback(); got != tc.want {
			t.Errorf("RuntimeMode(%d).NeedsResponseScanningFallback() = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

// TestResolveRuntime_MCPScanFallbackNoAutoEnable: RuntimeMCPScan should
// enable the response-scanning fallback but leave MCP input / tool /
// policy sections alone (scan mode never wraps an upstream server).
func TestResolveRuntime_MCPScanFallbackNoAutoEnable(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Enabled = false
	cfg.MCPInputScanning = MCPInputScanning{}
	cfg.MCPToolScanning = MCPToolScanning{}
	cfg.MCPToolPolicy = MCPToolPolicy{}

	resolved, info := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPScan})

	if !info.ResponseScanningFallback {
		t.Error("RuntimeMCPScan should fire the response-scanning fallback when operator disabled it")
	}
	if !resolved.ResponseScanning.Enabled {
		t.Error("resolved ResponseScanning.Enabled = false; fallback didn't take effect")
	}
	if info.MCPInputScanningAutoEnabled || info.MCPToolScanningAutoEnabled || info.MCPToolPolicyAutoEnabled {
		t.Errorf("RuntimeMCPScan should not fire any MCP auto-enable flags: %+v", info)
	}
	if resolved.MCPInputScanning.Enabled || resolved.MCPToolScanning.Enabled || resolved.MCPToolPolicy.Enabled {
		t.Error("MCP scanning sections auto-enabled under RuntimeMCPScan; expected to stay off")
	}
}
