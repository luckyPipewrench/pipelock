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
)

var capabilityIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Manifest is the machine-readable product capability contract. It is kept in
// docs/security so external consumers can read it without importing Go code.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Capabilities  []Capability      `json:"capabilities"`
	GateCoverage  []GateSourceScope `json:"gate_coverage"`
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
}

// Gate records the entitlement used by a capability. A capability may accept
// either of several features, such as the dashboard's agents-or-fleet gate.
type Gate struct {
	Kind     string        `json:"kind"`
	Features []GateFeature `json:"features,omitempty"`
}

// GateFeature points both at the enforcing call and the license helper that
// binds that call to a concrete feature constant.
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
}

// EnforcementCheck identifies the concrete call that denies the feature.
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
	for _, capability := range m.Capabilities {
		if err := capability.Validate(); err != nil {
			return fmt.Errorf("capability %q: %w", capability.ID, err)
		}
		if _, exists := ids[capability.ID]; exists {
			return fmt.Errorf("capability %q is duplicated", capability.ID)
		}
		ids[capability.ID] = struct{}{}
	}
	for _, scope := range m.GateCoverage {
		if err := scope.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks one manifest entry without inspecting source files.
func (c Capability) Validate() error {
	if !capabilityIDPattern.MatchString(c.ID) {
		return fmt.Errorf("id must be lowercase kebab-case")
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

func (s GateSourceScope) Validate() error {
	if featureConstant(s.Feature) == "" {
		return fmt.Errorf("gate source feature %q is unsupported", s.Feature)
	}
	if strings.TrimSpace(s.Prefix) == "" || filepath.IsAbs(s.Prefix) || strings.HasPrefix(filepath.Clean(s.Prefix), ".."+string(filepath.Separator)) {
		return fmt.Errorf("gate source prefix %q must be repository relative", s.Prefix)
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
	if filepath.IsAbs(s.File) || strings.HasPrefix(filepath.Clean(s.File), ".."+string(filepath.Separator)) || filepath.Ext(s.File) != ".go" {
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
		if !strings.HasPrefix(o.Value, "pipelock ") || o.Field != "" {
			return fmt.Errorf("command must start with \"pipelock \" and not set field")
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
