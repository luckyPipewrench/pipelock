// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func ptrBool(v bool) *bool { return &v }

func TestResolveRulesDir_ExplicitOverride(t *testing.T) {
	got := ResolveRulesDir("/custom/rules")
	if got != "/custom/rules" {
		t.Fatalf("expected /custom/rules, got %s", got)
	}
}

func TestResolveRulesDir_XDGOverride(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	got := ResolveRulesDir("")
	want := filepath.Join("/xdg/data", "pipelock", "rules")
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestResolveRulesDir_DefaultFallback(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}
	got := ResolveRulesDir("")
	want := filepath.Join(home, ".local", "share", "pipelock", "rules")
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestMergeIntoConfig_NoBundles(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	// Point to an empty temp dir.
	cfg.Rules.RulesDir = t.TempDir()

	origDLP := len(cfg.DLP.Patterns)
	origInj := len(cfg.ResponseScanning.Patterns)

	result := MergeIntoConfig(cfg, "1.0.0")
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	if len(result.DLP) != 0 {
		t.Fatalf("expected no DLP patterns, got %d", len(result.DLP))
	}
	if len(cfg.DLP.Patterns) != origDLP {
		t.Fatalf("DLP patterns changed: was %d, now %d", origDLP, len(cfg.DLP.Patterns))
	}
	if len(cfg.ResponseScanning.Patterns) != origInj {
		t.Fatalf("injection patterns changed: was %d, now %d", origInj, len(cfg.ResponseScanning.Patterns))
	}
}

func TestMergeIntoConfig_AppendsPatterns(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}

	// Set up a temp rules dir with a valid bundle.
	rulesDir := t.TempDir()
	cfg.Rules.RulesDir = rulesDir

	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	bundleYAML := `format_version: 1
name: test-bundle
version: "2026.01.0"
author: Test Author
description: Test bundle
license: Apache-2.0
rules:
  - id: test-dlp-rule
    type: dlp
    status: stable
    name: Test DLP
    description: Detects test patterns
    severity: high
    confidence: high
    pattern:
      regex: "test-secret-[a-z]{10}"
  - id: test-injection-rule
    type: injection
    status: stable
    name: Test Injection
    description: Detects test injection
    severity: high
    confidence: high
    pattern:
      regex: "do-evil-things"
  - id: test-poison-rule
    type: tool-poison
    status: stable
    name: Test Poison
    description: Detects poisoned tools
    severity: high
    confidence: high
    pattern:
      regex: "steal-all-data"
      scan_field: description
`
	bundlePath := filepath.Join(bundleDir, bundleFilename)
	if err := os.WriteFile(bundlePath, []byte(bundleYAML), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	// Create lock file with SHA-256 unsigned.
	data, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	h := sha256.Sum256(data)
	lock := &LockFile{
		Unsigned:     true,
		BundleSHA256: hex.EncodeToString(h[:]),
	}
	if err := WriteLockFile(filepath.Join(bundleDir, lockFilename), lock); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	origDLP := len(cfg.DLP.Patterns)
	origInj := len(cfg.ResponseScanning.Patterns)

	result := MergeIntoConfig(cfg, "1.0.0")
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}

	// DLP pattern should be appended.
	if len(cfg.DLP.Patterns) != origDLP+1 {
		t.Fatalf("expected %d DLP patterns, got %d", origDLP+1, len(cfg.DLP.Patterns))
	}
	lastDLP := cfg.DLP.Patterns[len(cfg.DLP.Patterns)-1]
	if lastDLP.Name != "test-bundle:test-dlp-rule" {
		t.Fatalf("unexpected DLP pattern name: %s", lastDLP.Name)
	}
	if lastDLP.Bundle != testBundleName {
		t.Fatalf("expected Bundle='test-bundle', got %q", lastDLP.Bundle)
	}
	if lastDLP.BundleVersion != "2026.01.0" {
		t.Fatalf("expected BundleVersion='2026.01.0', got %q", lastDLP.BundleVersion)
	}

	// Injection pattern should be appended.
	if len(cfg.ResponseScanning.Patterns) != origInj+1 {
		t.Fatalf("expected %d injection patterns, got %d", origInj+1, len(cfg.ResponseScanning.Patterns))
	}
	lastInj := cfg.ResponseScanning.Patterns[len(cfg.ResponseScanning.Patterns)-1]
	if lastInj.Name != "test-bundle:test-injection-rule" {
		t.Fatalf("unexpected injection pattern name: %s", lastInj.Name)
	}
	if lastInj.Bundle != testBundleName {
		t.Fatalf("expected Bundle='test-bundle', got %q", lastInj.Bundle)
	}

	// Tool poison should be in LoadResult.
	if len(result.ToolPoison) != 1 {
		t.Fatalf("expected 1 tool poison, got %d", len(result.ToolPoison))
	}
	if result.ToolPoison[0].Name != "test-bundle:test-poison-rule" {
		t.Fatalf("unexpected poison name: %s", result.ToolPoison[0].Name)
	}
}

func TestMergeIntoConfig_IdempotentForAlreadyMergedBundlePatterns(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.Rules.RulesDir = t.TempDir()

	bundleDir := filepath.Join(cfg.Rules.RulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	writeUnsignedBundle(t, bundleDir, testBundle(testBundleName, []Rule{
		testDLPRule("dlp-rule-001", confidenceHigh, StatusStable),
		testInjectionRule("inj-rule-001", confidenceHigh),
	}))

	first := MergeIntoConfig(cfg, "1.0.0")
	if len(first.Errors) != 0 {
		t.Fatalf("first merge errors: %v", first.Errors)
	}
	dlpCount := len(cfg.DLP.Patterns)
	responseCount := len(cfg.ResponseScanning.Patterns)
	wantDLP := append([]config.DLPPattern(nil), cfg.DLP.Patterns...)
	wantResponse := append([]config.ResponseScanPattern(nil), cfg.ResponseScanning.Patterns...)

	second := MergeIntoConfig(cfg, "1.0.0")
	if len(second.Errors) != 0 {
		t.Fatalf("second merge errors: %v", second.Errors)
	}
	if len(cfg.DLP.Patterns) != dlpCount {
		t.Fatalf("second merge DLP count = %d, want %d", len(cfg.DLP.Patterns), dlpCount)
	}
	if len(cfg.ResponseScanning.Patterns) != responseCount {
		t.Fatalf("second merge response count = %d, want %d", len(cfg.ResponseScanning.Patterns), responseCount)
	}
	if !reflect.DeepEqual(cfg.DLP.Patterns, wantDLP) {
		t.Fatal("second merge changed DLP pattern slice; want byte-identical resolved policy")
	}
	if !reflect.DeepEqual(cfg.ResponseScanning.Patterns, wantResponse) {
		t.Fatal("second merge changed response pattern slice; want byte-identical resolved policy")
	}
	if got := countDLPPatternsFromBundle(cfg, testBundleName); got != 1 {
		t.Fatalf("bundle DLP patterns = %d, want 1", got)
	}
	if got := countResponsePatternsFromBundle(cfg, testBundleName); got != 1 {
		t.Fatalf("bundle response patterns = %d, want 1", got)
	}
}

func TestMergeIntoConfig_ReResolveDifferentBundleReplacesPreviousBundlePatterns(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.Rules.RulesDir = t.TempDir()

	bundleADir := installUnsignedMergeTestBundle(t, cfg.Rules.RulesDir, "bundle-a", []Rule{
		testDLPRule("dlp-rule-a", confidenceHigh, StatusStable),
		testInjectionRule("inj-rule-a", confidenceHigh),
	})
	first := MergeIntoConfig(cfg, "1.0.0")
	if len(first.Errors) != 0 {
		t.Fatalf("first merge errors: %v", first.Errors)
	}
	if got := countDLPPatternsFromBundle(cfg, "bundle-a"); got != 1 {
		t.Fatalf("bundle-a DLP patterns after first merge = %d, want 1", got)
	}
	if got := countResponsePatternsFromBundle(cfg, "bundle-a"); got != 1 {
		t.Fatalf("bundle-a response patterns after first merge = %d, want 1", got)
	}

	if err := os.RemoveAll(bundleADir); err != nil {
		t.Fatalf("remove bundle-a: %v", err)
	}
	installUnsignedMergeTestBundle(t, cfg.Rules.RulesDir, "bundle-b", []Rule{
		testDLPRule("dlp-rule-b", confidenceHigh, StatusStable),
		testInjectionRule("inj-rule-b", confidenceHigh),
	})
	second := MergeIntoConfig(cfg, "1.0.0")
	if len(second.Errors) != 0 {
		t.Fatalf("second merge errors: %v", second.Errors)
	}
	if got := countDLPPatternsFromBundle(cfg, "bundle-a"); got != 0 {
		t.Fatalf("bundle-a DLP patterns after bundle swap = %d, want 0", got)
	}
	if got := countResponsePatternsFromBundle(cfg, "bundle-a"); got != 0 {
		t.Fatalf("bundle-a response patterns after bundle swap = %d, want 0", got)
	}
	if got := countDLPPatternsFromBundle(cfg, "bundle-b"); got != 1 {
		t.Fatalf("bundle-b DLP patterns after bundle swap = %d, want 1", got)
	}
	if got := countResponsePatternsFromBundle(cfg, "bundle-b"); got != 1 {
		t.Fatalf("bundle-b response patterns after bundle swap = %d, want 1", got)
	}
}

func TestMergeIntoConfig_RestoresCompiledStandardFallbackAfterStandardBundleRemoved(t *testing.T) {
	rulesDir := t.TempDir()
	userDLP := config.DLPPattern{
		Name:     "User DLP",
		Regex:    `user-secret-[0-9]+`,
		Severity: config.SeverityHigh,
	}
	userResponse := config.ResponseScanPattern{
		Name:  "User Response",
		Regex: `(?i)user-response`,
	}

	firstLoad := config.Defaults()
	firstLoad.Rules.RulesDir = rulesDir
	firstLoad.DLP.Patterns = append(firstLoad.DLP.Patterns, userDLP)
	firstLoad.ResponseScanning.Patterns = append(firstLoad.ResponseScanning.Patterns, userResponse)
	firstResult := MergeIntoConfig(firstLoad, "1.0.0")
	if len(firstResult.Errors) != 0 {
		t.Fatalf("first-load merge errors: %v", firstResult.Errors)
	}

	cfg := config.Defaults()
	cfg.Rules.RulesDir = rulesDir
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, userDLP)
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, userResponse)
	cfg.DLP.Patterns = append(removeStandardTierDLP(cfg.DLP.Patterns), config.DLPPattern{
		Name:          "Anthropic API Key",
		Regex:         `bundle-anthropic-[A-Z]+`,
		Severity:      config.SeverityCritical,
		Bundle:        StandardBundleName,
		BundleVersion: "2026.07.0",
	})
	cfg.ResponseScanning.Patterns = append(removeStandardTierResponse(cfg.ResponseScanning.Patterns), config.ResponseScanPattern{
		Name:          "New Instructions",
		Regex:         `(?i)bundle-new-instructions`,
		Bundle:        StandardBundleName,
		BundleVersion: "2026.07.0",
	})

	result := MergeIntoConfig(cfg, "1.0.0")
	if len(result.Errors) != 0 {
		t.Fatalf("merge errors: %v", result.Errors)
	}
	if result.StandardDLP != StandardSourceCompiled {
		t.Fatalf("StandardDLP = %s, want %s", result.StandardDLP, StandardSourceCompiled)
	}
	if result.StandardResponse != StandardSourceCompiled {
		t.Fatalf("StandardResponse = %s, want %s", result.StandardResponse, StandardSourceCompiled)
	}
	if p, ok := dlpPatternByName(cfg.DLP.Patterns, "Anthropic API Key"); !ok || !p.Compiled || p.Bundle != "" {
		t.Fatalf("Anthropic API Key fallback = %+v, ok=%v; want compiled non-bundle default", p, ok)
	}
	if p, ok := responsePatternByName(cfg.ResponseScanning.Patterns, "New Instructions"); !ok || !p.Compiled || p.Bundle != "" {
		t.Fatalf("New Instructions fallback = %+v, ok=%v; want compiled non-bundle default", p, ok)
	}
	if !reflect.DeepEqual(cfg.DLP.Patterns, firstLoad.DLP.Patterns) {
		t.Fatal("restored DLP fallback differs from first-load compiled defaults plus user patterns")
	}
	if !reflect.DeepEqual(cfg.ResponseScanning.Patterns, firstLoad.ResponseScanning.Patterns) {
		t.Fatal("restored response fallback differs from first-load compiled defaults plus user patterns")
	}
	if got, want := cfg.CanonicalPolicyHash(), firstLoad.CanonicalPolicyHash(); got != want {
		t.Fatalf("restored fallback canonical policy hash = %s, want first-load hash %s", got, want)
	}
}

func TestMergeIntoConfig_PreservesResolvedPatternsOnBundleLoadError(t *testing.T) {
	// A bundle that fails to load (here: missing bundle.lock) produces
	// result.Errors and contributes no patterns. Re-resolving an
	// already-bundle-resolved config must NOT strip its previously-validated
	// bundle patterns and degrade to compiled fallback — that would be a
	// fail-open weakening triggered by a transient load error.
	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, "community-x")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// bundle.yaml with NO bundle.lock -> loader appends a load error and skips.
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), []byte(
		"format_version: 1\nname: community-x\nversion: \"1.0.0\"\nauthor: t\ndescription: d\nlicense: Apache-2.0\nrules:\n  - id: dlp-1\n    type: dlp\n    status: stable\n    name: X\n    description: d\n    severity: high\n    confidence: high\n    pattern:\n      regex: 'abc'\n"),
		0o600); err != nil {
		t.Fatalf("write bundle.yaml: %v", err)
	}

	cfg := config.Defaults()
	cfg.Rules.RulesDir = rulesDir
	// Simulate an already-resolved config carrying a validated bundle pattern.
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: "Prior Bundle DLP", Regex: `prior-secret-[0-9]+`,
		Severity: config.SeverityHigh, Bundle: "prior-bundle", BundleVersion: "1.0.0",
	})
	before := append([]config.DLPPattern(nil), cfg.DLP.Patterns...)
	beforeResp := append([]config.ResponseScanPattern(nil), cfg.ResponseScanning.Patterns...)

	result := MergeIntoConfig(cfg, "1.0.0")
	if len(result.Errors) == 0 {
		t.Fatal("expected a load error from the lock-less bundle")
	}
	if !reflect.DeepEqual(cfg.DLP.Patterns, before) {
		t.Fatalf("bundle load error stripped previously-resolved DLP patterns (fail-open); got %d want %d", len(cfg.DLP.Patterns), len(before))
	}
	if !reflect.DeepEqual(cfg.ResponseScanning.Patterns, beforeResp) {
		t.Fatal("bundle load error mutated response patterns")
	}
}

func installUnsignedMergeTestBundle(t *testing.T, rulesDir, name string, rules []Rule) string {
	t.Helper()
	bundleDir := filepath.Join(rulesDir, name)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("mkdir bundle dir %q: %v", name, err)
	}
	writeUnsignedBundle(t, bundleDir, testBundle(name, rules))
	return bundleDir
}

func dlpPatternByName(patterns []config.DLPPattern, name string) (config.DLPPattern, bool) {
	for _, p := range patterns {
		if p.Name == name {
			return p, true
		}
	}
	return config.DLPPattern{}, false
}

func responsePatternByName(patterns []config.ResponseScanPattern, name string) (config.ResponseScanPattern, bool) {
	for _, p := range patterns {
		if p.Name == name {
			return p, true
		}
	}
	return config.ResponseScanPattern{}, false
}

func countDLPPatternsFromBundle(cfg *config.Config, bundle string) int {
	count := 0
	for _, p := range cfg.DLP.Patterns {
		if p.Bundle == bundle {
			count++
		}
	}
	return count
}

func countResponsePatternsFromBundle(cfg *config.Config, bundle string) int {
	count := 0
	for _, p := range cfg.ResponseScanning.Patterns {
		if p.Bundle == bundle {
			count++
		}
	}
	return count
}

func TestConvertToolPoison(t *testing.T) {
	rules := []CompiledToolPoisonRule{
		{
			Name:          "bundle:rule-1",
			RuleID:        "bundle:rule-1",
			Re:            regexp.MustCompile("(?i)steal"),
			ScanField:     "description",
			Bundle:        testBundleName,
			BundleVersion: "2026.01.0",
		},
	}

	result := ConvertToolPoison(rules)
	if len(result) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(result))
	}
	if result[0].Name != "bundle:rule-1" {
		t.Fatalf("unexpected name: %s", result[0].Name)
	}
	if result[0].Bundle != testBundleName {
		t.Fatalf("unexpected bundle: %s", result[0].Bundle)
	}
	if result[0].Re == nil {
		t.Fatal("expected non-nil regex")
	}
}

func TestConvertToolPoison_Empty(t *testing.T) {
	result := ConvertToolPoison(nil)
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
	result = ConvertToolPoison([]CompiledToolPoisonRule{})
	if result != nil {
		t.Fatalf("expected nil for empty slice, got %v", result)
	}
}

func TestMergeIntoConfig_NoBundles_StandardSourceCompiled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules.RulesDir = t.TempDir()
	result := MergeIntoConfig(cfg, "1.0.0")
	if result.StandardDLP != StandardSourceCompiled {
		t.Errorf("expected StandardSourceCompiled for DLP, got %s", result.StandardDLP)
	}
	if result.StandardResponse != StandardSourceCompiled {
		t.Errorf("expected StandardSourceCompiled for response, got %s", result.StandardResponse)
	}
	if len(cfg.DLP.Patterns) != 65 {
		t.Errorf("expected 65 DLP patterns (compiled fallback), got %d", len(cfg.DLP.Patterns))
	}
}

func TestMergeIntoConfig_IncludeDefaultsFalse_StandardSourceNone(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.IncludeDefaults = ptrBool(false)
	cfg.ResponseScanning.IncludeDefaults = ptrBool(false)
	cfg.ApplyDefaults()
	cfg.Rules.RulesDir = t.TempDir()
	result := MergeIntoConfig(cfg, "1.0.0")
	if result.StandardDLP != StandardSourceNone {
		t.Errorf("expected StandardSourceNone for DLP, got %s", result.StandardDLP)
	}
	if result.StandardResponse != StandardSourceNone {
		t.Errorf("expected StandardSourceNone for response, got %s", result.StandardResponse)
	}
}

func TestRemoveStandardTierDLP(t *testing.T) {
	t.Parallel()
	patterns := []config.DLPPattern{
		{Name: "AWS Access ID", Compiled: true},                   // core compiled - kept (core name)
		{Name: "Anthropic API Key", Compiled: true},               // standard compiled - removed
		{Name: "Stripe Key", Compiled: true},                      // standard compiled - removed
		{Name: "Stripe Key"},                                      // user override (same name, Compiled=false) - kept
		{Name: "Custom User Pattern"},                             // user-defined - kept
		{Name: "community:custom-rule", Bundle: "community-pack"}, // bundle - kept
	}
	result := removeStandardTierDLP(patterns)
	if len(result) != 4 {
		t.Fatalf("expected 4 patterns (core + user override + user custom + bundle), got %d", len(result))
	}
	want := []string{"AWS Access ID", "Stripe Key", "Custom User Pattern", "community:custom-rule"}
	for i, w := range want {
		if result[i].Name != w {
			t.Errorf("result[%d] = %q, want %q", i, result[i].Name, w)
		}
	}
}

func TestRemoveStandardTierResponse(t *testing.T) {
	t.Parallel()
	patterns := []config.ResponseScanPattern{
		{Name: "Prompt Injection", Compiled: true},               // core compiled - kept
		{Name: "New Instructions", Compiled: true},               // standard compiled - removed
		{Name: "CJK Jailbreak Mode", Compiled: true},             // standard compiled - removed
		{Name: "My Custom Detection"},                            // user-defined - kept
		{Name: "community:custom-inj", Bundle: "community-pack"}, // bundle - kept
	}
	result := removeStandardTierResponse(patterns)
	if len(result) != 3 {
		t.Fatalf("expected 3 patterns (core + user + bundle), got %d", len(result))
	}
	if result[0].Name != "Prompt Injection" {
		t.Errorf("expected core pattern first, got %s", result[0].Name)
	}
	if result[1].Name != "My Custom Detection" {
		t.Errorf("expected user pattern second, got %s", result[1].Name)
	}
	if result[2].Name != "community:custom-inj" {
		t.Errorf("expected bundle pattern third, got %s", result[2].Name)
	}
}

func TestMergeIntoConfig_NonexistentDir(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.Rules.RulesDir = filepath.Join(t.TempDir(), "nonexistent")

	result := MergeIntoConfig(cfg, "1.0.0")
	// Non-existent dir is not an error (no bundles installed).
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
}

// TestCompiledStandardNames_SyncWithDefaults asserts that the compiled
// standard name maps exactly match the non-core patterns in config.Defaults().
// If a default pattern is renamed or added, this test fails until the maps
// are updated, preventing silent drift that would cause duplicate scanning.
func TestCompiledStandardNames_SyncWithDefaults(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()

	// Core DLP names (from scanner/core.go).
	coreDLP := map[string]bool{
		"AWS Access ID": true, "AWS Secret Key": true,
		"GCP Service Account Key": true, "GitHub Token": true,
		"GitHub Fine-Grained PAT": true, "GitLab PAT": true,
		"Slack Token": true, "Private Key Header": true,
	}
	// Core response names (from scanner/core.go).
	coreResp := map[string]bool{
		"Prompt Injection": true, "System Override": true,
		"Role Override": true, "Hidden Instruction": true,
		"Credential Solicitation": true, "Credential Path Directive": true,
		"Covert Action Directive": true, "Instruction Boundary": true,
	}

	// Collect non-core DLP names from Defaults.
	var gotDLP []string
	for _, p := range cfg.DLP.Patterns {
		if !coreDLP[p.Name] {
			gotDLP = append(gotDLP, p.Name)
		}
	}
	// Assert every Defaults non-core DLP name is in compiledStandardDLPNames.
	for _, name := range gotDLP {
		if !compiledStandardDLPNames[name] {
			t.Errorf("DLP pattern %q is in Defaults but not in compiledStandardDLPNames", name)
		}
	}
	// Assert no stale entries in compiledStandardDLPNames.
	defaultDLPSet := make(map[string]bool, len(gotDLP))
	for _, name := range gotDLP {
		defaultDLPSet[name] = true
	}
	for name := range compiledStandardDLPNames {
		if !defaultDLPSet[name] {
			t.Errorf("compiledStandardDLPNames has %q but it is not in Defaults (stale entry)", name)
		}
	}

	// Same for response patterns.
	var gotResp []string
	for _, p := range cfg.ResponseScanning.Patterns {
		if !coreResp[p.Name] {
			gotResp = append(gotResp, p.Name)
		}
	}
	for _, name := range gotResp {
		if !compiledStandardResponseNames[name] {
			t.Errorf("response pattern %q is in Defaults but not in compiledStandardResponseNames", name)
		}
	}
	defaultRespSet := make(map[string]bool, len(gotResp))
	for _, name := range gotResp {
		defaultRespSet[name] = true
	}
	for name := range compiledStandardResponseNames {
		if !defaultRespSet[name] {
			t.Errorf("compiledStandardResponseNames has %q but it is not in Defaults (stale entry)", name)
		}
	}
}
