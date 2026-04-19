// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"fmt"
)

// Config is the top-level YAML config for redaction. Embedded into the
// main pipelock Config as the `redaction:` block.
type Config struct {
	// Enabled toggles the feature. When false, no other fields have any
	// effect and the feature is inert.
	Enabled bool `yaml:"enabled"`

	// DefaultProfile names the profile applied to every request unless a
	// per-agent override selects a different one. Must be a key in Profiles
	// when Enabled is true.
	DefaultProfile string `yaml:"default_profile"`

	// Profiles is the set of named redaction configurations. A profile
	// composes class names + dictionary names. Operators can ship a
	// `code` profile that enables only API/token classes, a `business`
	// profile that adds PII classes and customer dictionaries, etc.
	Profiles map[string]ProfileSpec `yaml:"profiles"`

	// Dictionaries is the set of named operator-supplied literal lists
	// that profiles reference. Each key is a dictionary name; the value
	// describes the class and entries.
	Dictionaries map[string]DictionarySpec `yaml:"dictionaries"`

	// Limits caps defensive ceilings for fail-closed behavior.
	Limits LimitsSpec `yaml:"limits"`

	// StrictReload, when true, fails requests closed if a dictionary file
	// referenced by an active profile cannot be reloaded (disappeared or
	// corrupted). Default false — retain previous snapshot instead.
	StrictReload bool `yaml:"strict_reload"`

	// AllowlistUnparseable lists hosts whose request bodies are permitted
	// to flow through redaction as opaque text when the body is not
	// parseable JSON. Bodies from hosts not in this list are blocked per
	// the fail-closed invariant.
	AllowlistUnparseable []string `yaml:"allowlist_unparseable"`
}

// ProfileSpec describes a single redaction profile as YAML.
type ProfileSpec struct {
	// Classes is the list of built-in redaction class names (e.g.
	// "ipv4", "aws-access-key") that are enabled for this profile.
	// Unknown class names are validated against the shipped registry.
	Classes []string `yaml:"classes"`
	// Dictionaries is the list of dictionary names (keys in
	// Config.Dictionaries) that this profile attaches to the matcher.
	Dictionaries []string `yaml:"dictionaries"`
}

// DictionarySpec is a YAML-friendly version of Dictionary. Either Entries
// or EntriesFile must be set; EntriesFile loading is the responsibility of
// the caller (the redact package does not touch the filesystem).
type DictionarySpec struct {
	// Class tags every hit of this dictionary.
	Class string `yaml:"class"`
	// Entries lists literal strings to match. Either this or EntriesFile
	// must be non-empty.
	Entries []string `yaml:"entries,omitempty"`
	// EntriesFile points at a YAML/JSON file containing a string list.
	// Not loaded by this package; resolve before calling BuildMatcher.
	EntriesFile string `yaml:"entries_file,omitempty"`
	// CaseInsensitive toggles case-insensitive matching.
	CaseInsensitive bool `yaml:"case_insensitive"`
	// WordBoundary requires `\b` surrounding each entry's match span.
	WordBoundary bool `yaml:"word_boundary"`
	// Priority positions this dictionary in overlap resolution.
	Priority int `yaml:"priority"`
}

// LimitsSpec mirrors Limits but uses YAML-idiomatic zero values. Fields
// with zero value take the package-level defaults (see walker.go).
type LimitsSpec struct {
	MaxBodyBytes            int `yaml:"max_body_bytes"`
	MaxRedactionsPerRequest int `yaml:"max_redactions_per_request"`
	MaxDepth                int `yaml:"max_depth"`
}

// ToLimits converts the YAML form into the internal Limits type.
// Struct fields match one-for-one so a Go conversion is sufficient.
func (s LimitsSpec) ToLimits() Limits {
	return Limits(s)
}

// Validate returns nil iff cfg is internally consistent. Callers should
// wire this into the overall config validation so startup fails closed.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // inert; no further checks.
	}
	if c.DefaultProfile == "" {
		return errors.New("redact: default_profile required when enabled")
	}
	if _, ok := c.Profiles[c.DefaultProfile]; !ok {
		return fmt.Errorf("redact: default_profile %q not defined in profiles", c.DefaultProfile)
	}

	validClasses := shippedClassNames()
	for name, p := range c.Profiles {
		if len(p.Classes) == 0 && len(p.Dictionaries) == 0 {
			return fmt.Errorf("redact: profile %q has no classes or dictionaries", name)
		}
		for _, cl := range p.Classes {
			if _, ok := validClasses[cl]; !ok {
				return fmt.Errorf("redact: profile %q references unknown class %q", name, cl)
			}
		}
		for _, dn := range p.Dictionaries {
			if _, ok := c.Dictionaries[dn]; !ok {
				return fmt.Errorf("redact: profile %q references unknown dictionary %q", name, dn)
			}
		}
	}

	for name, d := range c.Dictionaries {
		if d.Class == "" {
			return fmt.Errorf("redact: dictionary %q missing class", name)
		}
		if len(d.Entries) == 0 && d.EntriesFile == "" {
			return fmt.Errorf("redact: dictionary %q has no entries or entries_file", name)
		}
	}
	return nil
}

// BuildMatcher compiles the named profile into a Matcher. Entries from
// dictionaries referenced by the profile must already be fully resolved
// (EntriesFile loaded into Entries); the redact package does not perform
// file I/O.
func (c *Config) BuildMatcher(profileName string) (*Matcher, error) {
	if !c.Enabled {
		return nil, errors.New("redact: cannot build matcher with Enabled=false")
	}
	if profileName == "" {
		profileName = c.DefaultProfile
	}
	profile, ok := c.Profiles[profileName]
	if !ok {
		return nil, fmt.Errorf("redact: profile %q not found", profileName)
	}

	m := &Matcher{}

	// Filter the shipped class registry down to the profile's class set.
	classSet := make(map[string]struct{}, len(profile.Classes))
	for _, cl := range profile.Classes {
		classSet[cl] = struct{}{}
	}
	for _, cp := range defaultRegistry() {
		if _, ok := classSet[string(cp.class)]; ok {
			m.patterns = append(m.patterns, cp)
		}
	}

	// Attach each referenced dictionary. The redact package does not read
	// the filesystem; if EntriesFile is set, the caller must resolve it
	// into Entries before calling BuildMatcher. A dictionary with only
	// EntriesFile set will surface here as an empty-entries build error,
	// which we diagnose explicitly so operators don't think a validated
	// config somehow failed at matcher build.
	for _, dn := range profile.Dictionaries {
		spec := c.Dictionaries[dn]
		if len(spec.Entries) == 0 && spec.EntriesFile != "" {
			return nil, fmt.Errorf("redact: build dictionary %q: entries_file %q was not resolved before BuildMatcher (caller must load file contents into Entries)", dn, spec.EntriesFile)
		}
		if err := m.AddDictionary(Dictionary{
			Class:           Class(spec.Class),
			Entries:         spec.Entries,
			CaseInsensitive: spec.CaseInsensitive,
			WordBoundary:    spec.WordBoundary,
			Priority:        spec.Priority,
		}); err != nil {
			return nil, fmt.Errorf("redact: build dictionary %q: %w", dn, err)
		}
	}

	return m, nil
}

// shippedClassNames returns the set of class string values known to the
// shipped registry. Used for Validate to reject typos in operator profiles.
func shippedClassNames() map[string]struct{} {
	reg := defaultRegistry()
	out := make(map[string]struct{}, len(reg))
	for _, cp := range reg {
		out[string(cp.class)] = struct{}{}
	}
	return out
}

// DefaultLimits returns a LimitsSpec populated with the package defaults,
// suitable for emission in example configs and defaults functions.
func DefaultLimits() LimitsSpec {
	return LimitsSpec{
		MaxBodyBytes:            DefaultMaxBodyBytes,
		MaxRedactionsPerRequest: DefaultMaxRedactions,
		MaxDepth:                DefaultMaxDepth,
	}
}

// DefaultConfig returns a disabled redaction config suitable as the
// zero-value embedded in pipelock's main Config. When the operator does
// not supply a `redaction:` block, this is what they get — inert and safe.
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		Limits:  DefaultLimits(),
	}
}
