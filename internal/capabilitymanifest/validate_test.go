// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capabilitymanifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The manifest is only worth having because it is validated, so the rejection
// paths are the part that has to work. These build one valid value and break a
// single field per case, which keeps each failure attributable to the branch it
// names rather than to an unrelated missing field.

func validSourceReference() SourceReference {
	return SourceReference{File: "internal/config/schema.go", Symbol: "Config"}
}

func validEntryPoint() *OperatorEntryPoint {
	return &OperatorEntryPoint{
		Kind:   "command",
		Value:  "pipelock run",
		Source: validSourceReference(),
	}
}

func validCapability() Capability {
	return Capability{
		ID:                 "example-capability",
		Name:               "Example capability",
		Summary:            "An example used only by tests.",
		Tier:               "Free",
		Visibility:         VisibilityOperator,
		Gate:               Gate{Kind: GateFree},
		Implementation:     validSourceReference(),
		OperatorEntryPoint: validEntryPoint(),
	}
}

func TestCapabilityValidateRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Capability)
		want   string
	}{
		// The entry point value and the availability qualifier are rendered
		// into table cells alongside name and tier, so they carry the same
		// delimiter rule. Both were unchecked until the renderer's own list
		// became the validator's list, and neither had a case here.
		{"pipe in entry point value", func(c *Capability) {
			c.OperatorEntryPoint.Value = "pipelock run | Enterprise"
		}, "pipe or a line break"},
		{"newline in entry point value", func(c *Capability) {
			c.OperatorEntryPoint.Value = "pipelock run\nsecond line"
		}, "pipe or a line break"},
		{"carriage return in entry point value", func(c *Capability) {
			c.OperatorEntryPoint.Value = "pipelock run\rsecond line"
		}, "pipe or a line break"},
		{"pipe in availability qualifier", func(c *Capability) {
			c.Availability = &Availability{Qualifier: "Linux only | Enterprise"}
		}, "pipe or a line break"},
		{"newline in availability qualifier", func(c *Capability) {
			c.Availability = &Availability{Qualifier: "Linux only\nsecond line"}
		}, "pipe or a line break"},
		{"carriage return in availability qualifier", func(c *Capability) {
			c.Availability = &Availability{Qualifier: "Linux only\rsecond line"}
		}, "pipe or a line break"},
		{"upper case id", func(c *Capability) { c.ID = "Example" }, "kebab-case"},
		{"empty id", func(c *Capability) { c.ID = "" }, "kebab-case"},
		{"missing name", func(c *Capability) { c.Name = "" }, "is required"},
		{"missing summary", func(c *Capability) { c.Summary = "" }, "is required"},
		{"missing tier", func(c *Capability) { c.Tier = "" }, "is required"},
		{"unsupported visibility", func(c *Capability) { c.Visibility = "internal" }, "visibility"},
		{"bad implementation", func(c *Capability) { c.Implementation.Symbol = "" }, "implementation"},
		{"absent entry point", func(c *Capability) { c.OperatorEntryPoint = nil }, "operator_entry_point is required"},
		{"bad entry point", func(c *Capability) { c.OperatorEntryPoint.Value = "" }, "operator_entry_point"},
		{"bad surface coverage", func(c *Capability) {
			c.SurfaceCoverage = []SurfaceReference{{Kind: "nonsense", Value: "x"}}
		}, "surface coverage"},
		{"bad availability", func(c *Capability) {
			c.Availability = &Availability{Scope: "nonsense", Qualifier: "q"}
		}, "availability"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validCapability()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a capability broken by %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	if err := validCapability().Validate(); err != nil {
		t.Fatalf("the valid fixture must pass, otherwise every case above is vacuous: %v", err)
	}
}

func TestSurfaceReferenceValidateRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  SurfaceReference
		want string
	}{
		{"unsupported kind", SurfaceReference{Kind: "topic", Value: "x"}, "kind"},
		{"empty value", SurfaceReference{Kind: SurfaceConfigSection, Value: ""}, "value is required"},
		{"padded value", SurfaceReference{Kind: SurfaceConfigSection, Value: " dlp "}, "value is required"},
		{"wildcard value", SurfaceReference{Kind: SurfaceConfigSection, Value: "dlp*"}, "wildcard"},
		{"command without prefix", SurfaceReference{Kind: SurfaceCommand, Value: "run"}, "pipelock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.ref.Validate(); err == nil {
				t.Fatalf("Validate accepted %+v", tc.ref)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	if err := (SurfaceReference{Kind: SurfaceCommand, Value: "pipelock run"}).Validate(); err != nil {
		t.Fatalf("valid command surface rejected: %v", err)
	}
	if err := (SurfaceReference{Kind: SurfaceConfigSection, Value: "dlp"}).Validate(); err != nil {
		t.Fatalf("valid config surface rejected: %v", err)
	}
}

func TestExclusionsRequireAReason(t *testing.T) {
	// An exclusion without a stated reason is how a capability disappears
	// quietly, which is the failure this manifest replaces.
	if err := (SurfaceExclusion{Kind: SurfaceCommand, Value: "pipelock version"}).Validate(); err == nil {
		t.Fatal("surface exclusion without a reason was accepted")
	}
	if err := (GateExclusion{Feature: "agents", Prefix: "enterprise/x/"}).Validate(); err == nil {
		t.Fatal("gate exclusion without a reason was accepted")
	}
}

func TestAvailabilityValidateRejects(t *testing.T) {
	if err := (Availability{Scope: "nonsense", Qualifier: "q"}).Validate(); err == nil {
		t.Fatal("unsupported availability scope was accepted")
	}
	if err := (Availability{Scope: "platform_dependent"}).Validate(); err == nil {
		t.Fatal("platform-dependent availability without a qualifier was accepted")
	}
}

func TestGateValidateRejects(t *testing.T) {
	free := Gate{Kind: GateFree}
	if err := free.Validate("Pro"); err == nil {
		t.Fatal("a free gate claiming a Pro tier was accepted")
	}
	withFeatures := Gate{Kind: GateFree, Features: []GateFeature{{Name: "agents"}}}
	if err := withFeatures.Validate("Free"); err == nil {
		t.Fatal("a free gate listing license features was accepted")
	}
	empty := Gate{Kind: GateLicense}
	if err := empty.Validate("Pro"); err == nil {
		t.Fatal("a license gate with no features was accepted")
	}
	unknown := Gate{Kind: "handshake"}
	if err := unknown.Validate("Free"); err == nil {
		t.Fatal("an unsupported gate kind was accepted")
	}
}

func TestSourceReferenceValidateRejects(t *testing.T) {
	if err := (SourceReference{File: "internal/config/schema.go"}).Validate(); err == nil {
		t.Fatal("a source reference without a symbol was accepted")
	}
	if err := (SourceReference{File: "/etc/passwd", Symbol: "Config"}).Validate(); err == nil {
		t.Fatal("a non repository-relative source file was accepted")
	}
	if err := (SourceReference{File: "README.md", Symbol: "Config"}).Validate(); err == nil {
		t.Fatal("a non-Go source file was accepted")
	}
}

func TestOperatorEntryPointValidateRejects(t *testing.T) {
	base := validEntryPoint()
	for _, tc := range []struct {
		name   string
		mutate func(*OperatorEntryPoint)
	}{
		{"empty value", func(o *OperatorEntryPoint) { o.Value = "" }},
		{"command without the binary prefix", func(o *OperatorEntryPoint) { o.Value = "run" }},
		{"command that also sets a field", func(o *OperatorEntryPoint) { o.Field = "dlp" }},
		{"config without a field", func(o *OperatorEntryPoint) { o.Kind = "config"; o.Value = "dlp"; o.Field = "" }},
		{"unsupported kind", func(o *OperatorEntryPoint) { o.Kind = "signal" }},
		{"bad source", func(o *OperatorEntryPoint) { o.Source = SourceReference{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := *base
			tc.mutate(&o)
			if err := o.Validate(); err == nil {
				t.Fatalf("Validate accepted an entry point broken by %q", tc.name)
			}
		})
	}
}

func TestManifestValidateRejects(t *testing.T) {
	// The scope claims to cover "agents" gates, so the capability it names has
	// to actually be gated on that feature. A free capability cannot answer for
	// a licensed gate, and the manifest now says so.
	licensed := validCapability()
	licensed.ID = "example-paid-capability"
	licensed.Tier = "Pro"
	licensed.Gate = Gate{Kind: GateLicense, Features: []GateFeature{{
		Name:        "agents",
		Enforcement: EnforcementCheck{Source: validSourceReference(), Call: "license.HasFeature"},
		Proof:       validSourceReference(),
	}}}

	valid := Manifest{
		SchemaVersion: SchemaVersion,
		Capabilities:  []Capability{licensed},
		GateCoverage:  []GateSourceScope{{Feature: "agents", Prefix: "enterprise/", Capability: "example-paid-capability"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("the valid fixture must pass, otherwise every case below is vacuous: %v", err)
	}

	wrongVersion := valid
	wrongVersion.SchemaVersion = SchemaVersion + 1
	if err := wrongVersion.Validate(); err == nil {
		t.Fatal("a manifest declaring an unknown schema version was accepted")
	}

	noCaps := valid
	noCaps.Capabilities = nil
	if err := noCaps.Validate(); err == nil {
		t.Fatal("an empty manifest was accepted")
	}

	noCoverage := valid
	noCoverage.GateCoverage = nil
	if err := noCoverage.Validate(); err == nil {
		t.Fatal("a manifest with no gate coverage scopes was accepted")
	}

	free := validCapability()
	for _, testCase := range []struct {
		name    string
		mutate  func(*Manifest)
		wantErr string
	}{
		{"duplicated capability id", func(m *Manifest) {
			m.Capabilities = []Capability{licensed, licensed}
		}, "duplicated"},
		{"scope names a capability that does not exist", func(m *Manifest) {
			m.GateCoverage = []GateSourceScope{{Feature: "agents", Prefix: "enterprise/", Capability: "no-such-capability"}}
		}, "unknown capability"},
		// The point of the capability field: a scope cannot cover gates on
		// behalf of an entry that is not gated on the feature it claims.
		{"scope covered by a free capability", func(m *Manifest) {
			m.Capabilities = []Capability{licensed, free}
			m.GateCoverage = []GateSourceScope{{Feature: "agents", Prefix: "enterprise/", Capability: free.ID}}
		}, "does not declare"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			mutated := valid
			testCase.mutate(&mutated)
			err := mutated.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a manifest whose %s", testCase.name)
			}
			// Asserting the message keeps a case from passing because some
			// unrelated rule rejected the mutation first.
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("Validate error = %q, want it to mention %q", err, testCase.wantErr)
			}
		})
	}
}

func TestGateFeatureValidateRejects(t *testing.T) {
	good := GateFeature{
		Name:        "agents",
		Enforcement: EnforcementCheck{Source: validSourceReference(), Call: "license.HasFeature"},
		Proof:       validSourceReference(),
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("the valid fixture must pass, otherwise every case below is vacuous: %v", err)
	}

	unknown := good
	unknown.Name = "telepathy"
	if err := unknown.Validate(); err == nil {
		t.Fatal("an unsupported license feature was accepted")
	}

	badEnforcement := good
	badEnforcement.Enforcement.Call = "HasFeature"
	if err := badEnforcement.Validate(); err == nil {
		t.Fatal("an enforcement call that is not a qualified selector was accepted")
	}

	badProof := good
	badProof.Proof = SourceReference{}
	if err := badProof.Validate(); err == nil {
		t.Fatal("a feature with no proof source was accepted")
	}
}

func TestGateSourceScopeValidateRejects(t *testing.T) {
	if err := (GateSourceScope{Feature: "agents", Prefix: "enterprise/", Capability: "named-agent-profiles"}).Validate(); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	for _, tc := range []struct {
		name  string
		scope GateSourceScope
	}{
		{"unsupported feature", GateSourceScope{Feature: "telepathy", Prefix: "enterprise/", Capability: "named-agent-profiles"}},
		{"empty prefix", GateSourceScope{Feature: "agents", Prefix: "  ", Capability: "named-agent-profiles"}},
		{"absolute prefix", GateSourceScope{Feature: "agents", Prefix: "/etc/", Capability: "named-agent-profiles"}},
		{"escaping prefix", GateSourceScope{Feature: "agents", Prefix: "../elsewhere/", Capability: "named-agent-profiles"}},
		// Every case above names a valid capability, so the pattern check
		// that makes a scope answer for someone was never reached here.
		{"missing capability", GateSourceScope{Feature: "agents", Prefix: "enterprise/"}},
		{"malformed capability", GateSourceScope{Feature: "agents", Prefix: "enterprise/", Capability: "Named_Agent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.scope.Validate(); err == nil {
				t.Fatalf("Validate accepted %+v", tc.scope)
			}
		})
	}
}

func TestEnforcementCheckValidateRejects(t *testing.T) {
	good := EnforcementCheck{Source: validSourceReference(), Call: "license.HasFeature"}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid enforcement rejected: %v", err)
	}
	for _, tc := range []struct {
		name  string
		check EnforcementCheck
	}{
		{"bad source", EnforcementCheck{Call: "license.HasFeature"}},
		{"unqualified call", EnforcementCheck{Source: validSourceReference(), Call: "HasFeature"}},
		{"over-qualified call", EnforcementCheck{Source: validSourceReference(), Call: "a.b.c"}},
		{"padded call", EnforcementCheck{Source: validSourceReference(), Call: " license.HasFeature "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check.Validate(); err == nil {
				t.Fatalf("Validate accepted %+v", tc.check)
			}
		})
	}
}

func TestGateExclusionRejectsABadScopeBeforeItsReason(t *testing.T) {
	// The reason check is worthless if a malformed scope slips past it.
	if err := (GateExclusion{Feature: "telepathy", Prefix: "enterprise/", Reason: "stated"}).Validate(); err == nil {
		t.Fatal("a gate exclusion naming an unsupported feature was accepted")
	}
	if err := (GateExclusion{Feature: "agents", Prefix: "enterprise/x/", Reason: "no operator entry point"}).Validate(); err != nil {
		t.Fatalf("a well-formed, reasoned exclusion was rejected: %v", err)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return p
	}

	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("Load accepted a path that does not exist")
	}
	if _, err := Load(write("garbage.json", "{not json")); err == nil {
		t.Fatal("Load accepted malformed JSON")
	}
	// A misspelled key must not silently disappear from the coverage check, so
	// the decoder rejects unknown fields rather than dropping them.
	if _, err := Load(write("unknown.json", `{"schema_version":1,"capabilitys":[]}`)); err == nil {
		t.Fatal("Load accepted an unknown top-level field")
	}
	if _, err := Load(write("trailing.json", `{"schema_version":1}{"schema_version":1}`)); err == nil {
		t.Fatal("Load accepted a second trailing JSON document")
	}
	// A structurally valid document that fails the contract must still fail.
	if _, err := Load(write("empty.json", `{"schema_version":1,"capabilities":[],"gate_coverage":[]}`)); err == nil {
		t.Fatal("Load accepted a manifest with no capabilities")
	}
}

func TestReplaceAgentsSectionRejectsBadMarkers(t *testing.T) {
	section := "REPLACED"
	for _, tc := range []struct {
		name   string
		agents string
	}{
		{"no markers", "# nothing here\n"},
		{"start only", "# doc\n" + AgentsSectionStart + "\nbody\n"},
		{"end only", "# doc\n" + AgentsSectionEnd + "\n"},
		{"reversed order", "# doc\n" + AgentsSectionEnd + "\nbody\n" + AgentsSectionStart + "\n"},
		{"duplicate pair", "# doc\n" + AgentsSectionStart + "\na\n" + AgentsSectionEnd + "\n" +
			AgentsSectionStart + "\nb\n" + AgentsSectionEnd + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReplaceAgentsSection(tc.agents, section); err == nil {
				t.Fatalf("ReplaceAgentsSection accepted %q", tc.name)
			}
		})
	}

	good := "before\n" + AgentsSectionStart + "\nold\n" + AgentsSectionEnd + "\nafter\n"
	out, err := ReplaceAgentsSection(good, section)
	if err != nil {
		t.Fatalf("a well-formed pair was rejected: %v", err)
	}
	if !strings.Contains(out, section) || strings.Contains(out, "old") {
		t.Fatalf("section not replaced: %q", out)
	}
	if !strings.HasPrefix(out, "before\n") || !strings.HasSuffix(out, "after\n") {
		t.Fatalf("surrounding content was not preserved: %q", out)
	}
}

func TestGateValidateRejectsDuplicateFeaturesAndTierMismatch(t *testing.T) {
	// A licence gate must be built from real features for these branches to be
	// reachable at all; the earlier cases only exercised the empty-gate paths.
	feature := func(name string) GateFeature {
		return GateFeature{
			Name:        name,
			Enforcement: EnforcementCheck{Source: validSourceReference(), Call: "license.HasFeature"},
			Proof:       validSourceReference(),
		}
	}

	good := Gate{Kind: GateLicense, Features: []GateFeature{feature("agents")}}
	if err := good.Validate("Pro"); err != nil {
		t.Fatalf("the valid fixture must pass, otherwise every case below is vacuous: %v", err)
	}

	duplicate := Gate{Kind: GateLicense, Features: []GateFeature{feature("agents"), feature("agents")}}
	if err := duplicate.Validate("Pro"); err == nil {
		t.Fatal("a gate listing the same feature twice was accepted")
	}

	// The tier a manifest entry claims has to agree with what its features
	// actually unlock, or the generated documentation misstates the price.
	if err := good.Validate("Enterprise"); err == nil {
		t.Fatal("a gate whose declared tier disagrees with its features was accepted")
	}
}

func TestRepositoryEscapeRejectsBareParent(t *testing.T) {
	// ".." cleans to itself and carries no separator, so a prefix-only check
	// accepts it as a root-parent scope.
	if err := (GateSourceScope{Feature: "agents", Prefix: "..", Capability: "named-agent-profiles"}).Validate(); err == nil {
		t.Fatal("a gate source prefix of \"..\" was accepted")
	}
	if err := (SourceReference{File: "../outside.go", Symbol: "X"}).Validate(); err == nil {
		t.Fatal("a source file escaping the repository was accepted")
	}
}

func TestCapabilityRejectsMarkdownBreakingValues(t *testing.T) {
	// The rendered table is the surface a session reads, so a value that breaks
	// it misstates the capability surface through the manifest's own renderer.
	for _, tc := range []struct {
		name   string
		mutate func(*Capability)
	}{
		{"pipe in name", func(c *Capability) { c.Name = "Dashboard | free" }},
		{"newline in summary", func(c *Capability) { c.Summary = "First line\nSecond line" }},
		{"carriage return in summary", func(c *Capability) { c.Summary = "First\rSecond" }},
		{"pipe in tier", func(c *Capability) { c.Tier = "Pro | Enterprise" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validCapability()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate accepted a value that would corrupt the generated table (%s)", tc.name)
			}
		})
	}
}

func TestEscapesRepositoryRejectsPlatformSpecificPaths(t *testing.T) {
	// Manifest paths are repository-relative and slash separated, so a
	// backslash form and a Windows drive-relative form must be rejected on
	// every platform, not only on the one that happens to run the test.
	for _, path := range []string{"..", "../outside.go", `..\outside.go`, `C:..\outside.go`, `C:\outside.go`, ".", "/outside.go", ""} {
		t.Run(path, func(t *testing.T) {
			if !escapesRepository(path) {
				t.Fatalf("escapesRepository(%q) = false, want true", path)
			}
		})
	}
	for _, path := range []string{"internal/config/schema.go", "enterprise/cli/dashboard.go"} {
		if escapesRepository(path) {
			t.Fatalf("escapesRepository(%q) = true, want false", path)
		}
	}
}

func TestWithinScopeComparesWholeComponents(t *testing.T) {
	// A raw prefix test lets the scope "internal/foo" claim "internal/foobar",
	// silently widening coverage to a directory nobody declared.
	if withinScope("internal/foobar/x.go", "internal/foo") {
		t.Fatal("scope \"internal/foo\" matched \"internal/foobar/x.go\"")
	}
	if withinScope("enterprise/cli/dashboard_exemption.go", "enterprise/cli/dashboard.go") {
		t.Fatal("a file scope matched a sibling whose name merely starts the same")
	}
	if !withinScope("internal/foo/x.go", "internal/foo") {
		t.Fatal("scope did not match a path genuinely inside it")
	}
	if !withinScope("internal/foo/x.go", "internal/foo/") {
		t.Fatal("a trailing separator on the scope changed the result")
	}
	if !withinScope("enterprise/cli/dashboard.go", "enterprise/cli/dashboard.go") {
		t.Fatal("an exact file scope did not match its own file")
	}
	if withinScope("internal/foo/x.go", "") {
		t.Fatal("an empty scope matched everything")
	}
}
