// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capabilitymanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	gopath "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	SchemaVersion      = 1
	VisibilityOperator = "operator"

	GateFree    = "free"
	GateLicense = "license_feature"

	SurfaceConfigSection = "config_section"
	SurfaceCommand       = "command"
)

var capabilityIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Manifest is the machine-readable product capability contract. It is kept in
// docs/security so external consumers can read it without importing Go code.
type Manifest struct {
	SchemaVersion     int                `json:"schema_version"`
	Capabilities      []Capability       `json:"capabilities"`
	GateCoverage      []GateSourceScope  `json:"gate_coverage"`
	GateExclusions    []GateExclusion    `json:"gate_exclusions"`
	SurfaceExclusions []SurfaceExclusion `json:"surface_exclusions"`
}

// Capability describes one operator-visible product capability.
type Capability struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Summary            string              `json:"summary"`
	Tier               string              `json:"tier"`
	Visibility         string              `json:"visibility"`
	Gate               Gate                `json:"gate"`
	Implementation     SourceReference     `json:"implementation"`
	OperatorEntryPoint *OperatorEntryPoint `json:"operator_entry_point"`
	SurfaceCoverage    []SurfaceReference  `json:"surface_coverage,omitempty"`
	Availability       *Availability       `json:"availability,omitempty"`
}

// SurfaceReference maps a code-enumerated operator surface to the capability
// that owns it. It is separate from operator_entry_point because one
// capability can be configured or operated through more than one root surface.
type SurfaceReference struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// SurfaceExclusion records a code-enumerated surface that is deliberately not
// a separately documented capability. Exclusions are exact, never wildcards,
// and require a public reason.
type SurfaceExclusion struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Availability records a platform or deployment condition that changes the
// strength or reachability of a capability claim.
type Availability struct {
	Scope     string `json:"scope"`
	Qualifier string `json:"qualifier"`
}

// Gate records the entitlement used by a capability. A capability may accept
// either of several features, such as the dashboard's agents-or-fleet gate.
type Gate struct {
	Kind     string        `json:"kind"`
	Features []GateFeature `json:"features,omitempty"`
}

// GateFeature points at the enforcement selector and at a declaration that
// names the feature constant.
//
// Proof is a source reference for an auditor to follow, not a proof of gating.
//
// A passing check establishes that the referenced declaration exists and passes
// something spelled like the feature constant to a call. It does not establish
// that the identifier resolves to the license package's constant rather than a
// local of the same spelling, that the call uses the value, that any result is
// tested, or that the separately-checked enforcement selector names the same
// feature. The two references are validated independently and nothing connects
// them. Establishing any of that requires binding resolution through go/types
// rather than a stricter spelling rule.
//
// Proof is often a dedicated license helper such as VerifyAgentsWithOptions,
// but it does NOT have to be a separate declaration, and a feature whose
// enforcing function names the constant directly is correctly recorded with the
// same reference in both fields. Those helpers exist so require-intermediate
// mode is honoured in env-only commands that take no config file, which a
// config-driven gate resolving those options for itself does not need. A
// wrapper could still be wanted for other reasons, such as centralising
// feature-gate behaviour; it is simply not required to preserve those options.
// Reading this field as "there must be a helper" is what makes a same-reference
// row look like a defect, and the remedy then looks like adding a wrapper whose
// stated purpose would be false of its only caller. Record the asymmetry
// instead of writing code to erase it.
type GateFeature struct {
	Name        string           `json:"name"`
	Enforcement EnforcementCheck `json:"enforcement"`
	Proof       SourceReference  `json:"proof"`
}

// GateSourceScope assigns every direct runtime license check to a manifest
// capability family, or explicitly records a deliberately unreachable surface.
type GateSourceScope struct {
	Feature string `json:"feature"`
	Prefix  string `json:"prefix"`
	// Capability is the manifest entry this scope covers gates on behalf of.
	// Without it a scope answers for no one: a license gate counts as covered
	// while no capability records the behaviour being gated, which is the
	// single-source contract failing quietly rather than loudly.
	Capability string `json:"capability"`
}

// GateExclusion records a runtime license check that is deliberately outside
// the operator capability surface and therefore has no public manifest row.
type GateExclusion struct {
	Feature string `json:"feature"`
	Prefix  string `json:"prefix"`
	Reason  string `json:"reason"`
}

// EnforcementCheck identifies the gating selector inside the enforcing
// declaration.
//
// Call is a selector that must APPEAR in that declaration, and the parity check
// proves presence, not invocation. It cannot show the selector is reached, that
// its result is tested, or that the guarded work is refused when it fails, so a
// row here is a pointer for an auditor rather than proof of enforcement. Some
// rows name a constant rather than a function for that reason. Treating a
// present selector as a verified deny is the over-reading this field invites,
// and it is why the value is described as a selector and not as a call.
type EnforcementCheck struct {
	Source SourceReference `json:"source"`
	Call   string          `json:"call"`
}

// SourceReference names a declaration in a repository-relative Go source file.
type SourceReference struct {
	File   string `json:"file"`
	Symbol string `json:"symbol"`
}

// OperatorEntryPoint identifies the command or YAML field an operator uses.
type OperatorEntryPoint struct {
	Kind   string          `json:"kind"`
	Value  string          `json:"value"`
	Source SourceReference `json:"source"`
	Field  string          `json:"field,omitempty"`
}

// Load reads a manifest strictly. Unknown fields and trailing JSON are errors
// so a misspelled capability claim cannot silently disappear from the check.
func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Manifest{}, fmt.Errorf("read capability manifest: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var manifest Manifest
	if err := dec.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode capability manifest: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return Manifest{}, fmt.Errorf("decode capability manifest: expected one JSON document")
	} else if !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("decode capability manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate checks the schema-level capability contract before source parity is
// evaluated. Source references are checked separately against a checkout.
func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("capability manifest schema_version = %d, want %d", m.SchemaVersion, SchemaVersion)
	}
	if len(m.Capabilities) == 0 {
		return fmt.Errorf("capability manifest has no capabilities")
	}
	if len(m.GateCoverage) == 0 {
		return fmt.Errorf("capability manifest has no gate_coverage scopes")
	}

	ids := make(map[string]struct{}, len(m.Capabilities))
	byID := make(map[string]Capability, len(m.Capabilities))
	for _, capability := range m.Capabilities {
		if err := capability.Validate(); err != nil {
			return fmt.Errorf("capability %q: %w", capability.ID, err)
		}
		if _, exists := ids[capability.ID]; exists {
			return fmt.Errorf("capability %q is duplicated", capability.ID)
		}
		ids[capability.ID] = struct{}{}
		byID[capability.ID] = capability
	}
	for _, scope := range m.GateCoverage {
		if err := scope.Validate(); err != nil {
			return err
		}
		owner, ok := byID[scope.Capability]
		if !ok {
			return fmt.Errorf("gate source scope %q names unknown capability %q", scope.Prefix, scope.Capability)
		}
		if !owner.grants(scope.Feature) {
			return fmt.Errorf("gate source scope %q is covered by capability %q, which does not declare the %q feature",
				scope.Prefix, scope.Capability, scope.Feature)
		}
	}
	for _, exclusion := range m.GateExclusions {
		if err := exclusion.Validate(); err != nil {
			return fmt.Errorf("gate exclusion %q: %w", exclusion.Prefix, err)
		}
	}
	for _, exclusion := range m.SurfaceExclusions {
		if err := exclusion.Validate(); err != nil {
			return fmt.Errorf("surface exclusion %q: %w", exclusion.Value, err)
		}
	}
	return nil
}

// Validate checks one manifest entry without inspecting source files.
func (c Capability) Validate() error {
	if !capabilityIDPattern.MatchString(c.ID) {
		return fmt.Errorf("id must be lowercase kebab-case")
	}
	// Every rendered value lands in a Markdown table cell. A pipe or a line
	// break in one silently corrupts the generated section, which would make
	// the documented capability surface misstate itself: the failure this
	// manifest exists to prevent, arriving through its own renderer.
	rendered := map[string]string{
		"name":    c.Name,
		"summary": c.Summary,
		"tier":    c.Tier,
	}
	if c.OperatorEntryPoint != nil {
		rendered["operator_entry_point value"] = c.OperatorEntryPoint.Value
	}
	if c.Availability != nil {
		rendered["availability qualifier"] = c.Availability.Qualifier
	}
	for label, value := range rendered {
		if strings.ContainsAny(value, "|\n\r") {
			return fmt.Errorf("%s must not contain a pipe or a line break; it is rendered into a Markdown table", label)
		}
	}
	for label, value := range map[string]string{
		"name": c.Name, "summary": c.Summary, "tier": c.Tier, "visibility": c.Visibility,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	if c.Visibility != VisibilityOperator {
		return fmt.Errorf("visibility %q is unsupported", c.Visibility)
	}
	if err := c.Implementation.Validate(); err != nil {
		return fmt.Errorf("implementation: %w", err)
	}
	if c.OperatorEntryPoint == nil {
		return fmt.Errorf("operator_entry_point is required")
	}
	if err := c.OperatorEntryPoint.Validate(); err != nil {
		return fmt.Errorf("operator_entry_point: %w", err)
	}
	if err := c.Gate.Validate(c.Tier); err != nil {
		return err
	}
	for _, surface := range c.SurfaceCoverage {
		if err := surface.Validate(); err != nil {
			return fmt.Errorf("surface coverage %q: %w", surface.Value, err)
		}
	}
	if c.Availability != nil {
		if err := c.Availability.Validate(); err != nil {
			return fmt.Errorf("availability: %w", err)
		}
	}
	return nil
}

func (s SurfaceReference) Validate() error {
	if s.Kind != SurfaceConfigSection && s.Kind != SurfaceCommand {
		return fmt.Errorf("kind %q is unsupported", s.Kind)
	}
	if strings.TrimSpace(s.Value) == "" || strings.TrimSpace(s.Value) != s.Value {
		return fmt.Errorf("value is required and must not have surrounding whitespace")
	}
	if strings.ContainsAny(s.Value, "*?") {
		return fmt.Errorf("value must be exact, not a wildcard")
	}
	if s.Kind == SurfaceCommand && !isShippedCommand(s.Value) {
		return fmt.Errorf("command value must name a subcommand of a shipped binary (%s)", shippedBinaryList())
	}
	return nil
}

func (s SurfaceExclusion) Validate() error {
	if err := (SurfaceReference{Kind: s.Kind, Value: s.Value}).Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(s.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	return nil
}

func (a Availability) Validate() error {
	switch a.Scope {
	case "mediated_traffic", "deployment_dependent", "platform_dependent":
	default:
		return fmt.Errorf("scope %q is unsupported", a.Scope)
	}
	if strings.TrimSpace(a.Qualifier) == "" {
		return fmt.Errorf("qualifier is required")
	}
	return nil
}

func (g Gate) Validate(tier string) error {
	switch g.Kind {
	case GateFree:
		if tier != "Free" {
			return fmt.Errorf("free capability tier = %q, want Free", tier)
		}
		if len(g.Features) != 0 {
			return fmt.Errorf("free capability must not list license features")
		}
	case GateLicense:
		if len(g.Features) == 0 {
			return fmt.Errorf("license-gated capability has no features")
		}
		seen := make(map[string]struct{}, len(g.Features))
		for _, feature := range g.Features {
			if _, exists := seen[feature.Name]; exists {
				return fmt.Errorf("feature %q is duplicated", feature.Name)
			}
			seen[feature.Name] = struct{}{}
			if err := feature.Validate(); err != nil {
				return err
			}
		}
		if got, want := tierForFeatures(g.Features), tier; got != want {
			return fmt.Errorf("tier = %q, want %q for declared feature gate", want, got)
		}
	default:
		return fmt.Errorf("gate kind %q is unsupported", g.Kind)
	}
	return nil
}

func (g GateFeature) Validate() error {
	if featureConstant(g.Name) == "" {
		return fmt.Errorf("feature %q is unsupported", g.Name)
	}
	if err := g.Enforcement.Validate(); err != nil {
		return fmt.Errorf("feature %q enforcement: %w", g.Name, err)
	}
	if err := g.Proof.Validate(); err != nil {
		return fmt.Errorf("feature %q proof: %w", g.Name, err)
	}
	return nil
}

// escapesRepository reports whether a declared path leaves the repository.
//
// Manifest paths are documented as repository-relative and slash separated, so
// this decides on the string itself rather than on host path semantics. That
// matters: filepath.VolumeName returns empty on Unix, so a Windows
// drive-relative path such as `C:..\outside.go` would be accepted by a Linux
// test run and rejected only on Windows, which is the platform-dependent
// validation this replaces.
//
// Rejected: a volume or drive prefix, a backslash in any position, a leading
// separator, and any path that climbs out with a ".." component. The bare
// values ".." and "." are rejected too; ".." cleans to itself and carries no
// separator, so a prefix check alone reads it as an ordinary relative path.
func escapesRepository(path string) bool {
	if strings.ContainsRune(path, '\\') {
		return true
	}
	if len(path) >= 2 && path[1] == ':' {
		return true
	}
	if strings.HasPrefix(path, "/") {
		return true
	}
	cleaned := gopath.Clean(path)
	if cleaned == ".." || cleaned == "." {
		return true
	}
	return strings.HasPrefix(cleaned, "../")
}

// withinScope reports whether a repository-relative path lies inside a declared
// prefix, comparing whole path components. A raw prefix test would let the scope
// "internal/foo" also claim "internal/foobar", which silently widens coverage to
// a directory nobody declared.
func withinScope(path, prefix string) bool {
	path = filepath.ToSlash(path)
	prefix = strings.TrimSuffix(filepath.ToSlash(prefix), "/")
	if prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// grants reports whether this capability's gate carries the named license
// feature, which is what makes a scope's claim to cover it truthful.
func (c Capability) grants(feature string) bool {
	for _, declared := range c.Gate.Features {
		if declared.Name == feature {
			return true
		}
	}
	return false
}

// validateFeatureAndPrefix checks the part a coverage scope and an exclusion
// share. It is deliberately separate from Validate: an exclusion declares that
// gates under a prefix belong to NO capability, so requiring it to name one
// would be incoherent.
func validateFeatureAndPrefix(feature, prefix string) error {
	if featureConstant(feature) == "" {
		return fmt.Errorf("gate source feature %q is unsupported", feature)
	}
	if strings.TrimSpace(prefix) == "" || filepath.IsAbs(prefix) || escapesRepository(prefix) {
		return fmt.Errorf("gate source prefix %q must be repository relative", prefix)
	}
	return nil
}

// shippedBinaries are the executables a release publishes. A command surface
// belongs to exactly one of them. This is a list rather than a prefix test
// because "starts with pipelock" would also accept a binary we do not ship.
var shippedBinaries = []string{"pipelock", "pipelock-verifier"}

func isShippedCommand(value string) bool {
	for _, binary := range shippedBinaries {
		if strings.HasPrefix(value, binary+" ") {
			return true
		}
	}
	return false
}

func shippedBinaryList() string {
	return strings.Join(shippedBinaries, ", ")
}

func (s GateSourceScope) Validate() error {
	if err := validateFeatureAndPrefix(s.Feature, s.Prefix); err != nil {
		return err
	}
	if !capabilityIDPattern.MatchString(s.Capability) {
		return fmt.Errorf("gate source scope %q must name the capability it covers", s.Prefix)
	}
	return nil
}

func (s GateExclusion) Validate() error {
	if err := validateFeatureAndPrefix(s.Feature, s.Prefix); err != nil {
		return err
	}
	if strings.TrimSpace(s.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	return nil
}

func (e EnforcementCheck) Validate() error {
	if err := e.Source.Validate(); err != nil {
		return err
	}
	if strings.Count(e.Call, ".") != 1 || strings.TrimSpace(e.Call) != e.Call {
		return fmt.Errorf("call %q must be a qualified Go selector", e.Call)
	}
	return nil
}

func (s SourceReference) Validate() error {
	if strings.TrimSpace(s.File) == "" || strings.TrimSpace(s.Symbol) == "" {
		return fmt.Errorf("file and symbol are required")
	}
	if filepath.IsAbs(s.File) || escapesRepository(s.File) || filepath.Ext(s.File) != ".go" {
		return fmt.Errorf("file %q must be a repository-relative Go file", s.File)
	}
	return nil
}

func (o OperatorEntryPoint) Validate() error {
	if strings.TrimSpace(o.Value) == "" {
		return fmt.Errorf("value is required")
	}
	if err := o.Source.Validate(); err != nil {
		return err
	}
	switch o.Kind {
	case "command":
		if !isShippedCommand(o.Value) || o.Field != "" {
			return fmt.Errorf("command must name a subcommand of a shipped binary (%s) and not set field", shippedBinaryList())
		}
	case "config":
		if strings.TrimSpace(o.Field) == "" || strings.HasPrefix(o.Value, ".") {
			return fmt.Errorf("config entry point requires a YAML field")
		}
	default:
		return fmt.Errorf("kind %q is unsupported", o.Kind)
	}
	return nil
}

func featureConstant(feature string) string {
	switch feature {
	case "agents":
		return "FeatureAgents"
	case "assess":
		return "FeatureAssess"
	case "fleet":
		return "FeatureFleet"
	default:
		return ""
	}
}

func tierForFeatures(features []GateFeature) string {
	names := make([]string, 0, len(features))
	for _, feature := range features {
		names = append(names, feature.Name)
	}
	sort.Strings(names)
	switch strings.Join(names, ",") {
	case "agents":
		return "Pro"
	case "assess":
		return "Assess"
	case "fleet":
		return "Enterprise"
	case "agents,fleet":
		return "Pro or Enterprise"
	default:
		return ""
	}
}
