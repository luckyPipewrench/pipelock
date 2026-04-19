// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

func TestConfig_ValidateDisabledInert(t *testing.T) {
	t.Parallel()
	c := Config{}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled Config should validate, got %v", err)
	}
}

func TestConfig_ValidateRequiresDefaultProfile(t *testing.T) {
	t.Parallel()
	c := Config{Enabled: true}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "default_profile required") {
		t.Fatalf("expected default_profile error, got %v", err)
	}
}

func TestConfig_ValidateUnknownDefaultProfile(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "does-not-exist",
		Profiles:       map[string]ProfileSpec{"code": {Classes: []string{"aws-access-key"}}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "not defined in profiles") {
		t.Fatalf("expected unknown-default error, got %v", err)
	}
}

func TestConfig_ValidateUnknownClass(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "p",
		Profiles:       map[string]ProfileSpec{"p": {Classes: []string{"not-a-real-class"}}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown class") {
		t.Fatalf("expected unknown-class error, got %v", err)
	}
}

func TestConfig_ValidateEmptyProfile(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "p",
		Profiles:       map[string]ProfileSpec{"p": {}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "no classes or dictionaries") {
		t.Fatalf("expected empty-profile error, got %v", err)
	}
}

func TestConfig_ValidateUnknownDictionaryRef(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "p",
		Profiles:       map[string]ProfileSpec{"p": {Dictionaries: []string{"missing"}}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown dictionary") {
		t.Fatalf("expected unknown-dict error, got %v", err)
	}
}

func TestConfig_ValidateDictionaryMissingClass(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "p",
		Profiles: map[string]ProfileSpec{
			"p": {Classes: []string{"ipv4"}, Dictionaries: []string{"d"}},
		},
		Dictionaries: map[string]DictionarySpec{"d": {Entries: []string{"x"}}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "missing class") {
		t.Fatalf("expected missing-class error, got %v", err)
	}
}

func TestConfig_ValidateDictionaryNoEntries(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "p",
		Profiles: map[string]ProfileSpec{
			"p": {Classes: []string{"ipv4"}, Dictionaries: []string{"d"}},
		},
		Dictionaries: map[string]DictionarySpec{"d": {Class: "customer"}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "no entries") {
		t.Fatalf("expected no-entries error, got %v", err)
	}
}

func TestConfig_ValidatePassesForCompleteConfig(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]ProfileSpec{
			"code":     {Classes: []string{"aws-access-key", "github-token"}},
			"business": {Classes: []string{"email", "ipv4"}, Dictionaries: []string{"customer"}},
		},
		Dictionaries: map[string]DictionarySpec{
			"customer": {
				Class:           "customer",
				Entries:         []string{"AcmeCorp", "Contoso"},
				CaseInsensitive: true,
				WordBoundary:    true,
				Priority:        75,
			},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestConfig_BuildMatcherDefaultProfile(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]ProfileSpec{
			"code": {Classes: []string{"aws-access-key"}},
		},
	}
	m, err := c.BuildMatcher("")
	if err != nil {
		t.Fatalf("BuildMatcher: %v", err)
	}
	matches := m.Scan("hit " + "AKIA" + "IOSFODNN7EXAMPLE yes")
	if len(matches) != 1 || matches[0].Class != ClassAWSAccessKey {
		t.Fatalf("expected 1 aws-access-key match, got %+v", matches)
	}
	// Code profile does NOT enable IPv4 — it shouldn't match.
	ipMatches := m.Scan("ip 10.0.0.1 here")
	for _, mv := range ipMatches {
		if mv.Class == ClassIPv4 {
			t.Fatalf("code profile leaked ipv4 match: %+v", ipMatches)
		}
	}
}

func TestConfig_BuildMatcherWithDictionary(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "biz",
		Profiles: map[string]ProfileSpec{
			"biz": {Classes: []string{"ipv4"}, Dictionaries: []string{"customer"}},
		},
		Dictionaries: map[string]DictionarySpec{
			"customer": {
				Class:        "customer",
				Entries:      []string{"AcmeCorp"},
				WordBoundary: true,
				Priority:     80,
			},
		},
	}
	m, err := c.BuildMatcher("biz")
	if err != nil {
		t.Fatalf("BuildMatcher: %v", err)
	}
	matches := m.Scan("sold AcmeCorp licenses for 10.0.0.1")
	var foundCustomer, foundIP bool
	for _, mv := range matches {
		if mv.Class == Class("customer") {
			foundCustomer = true
		}
		if mv.Class == ClassIPv4 {
			foundIP = true
		}
	}
	if !foundCustomer || !foundIP {
		t.Fatalf("missing matches: customer=%v ipv4=%v; got %+v", foundCustomer, foundIP, matches)
	}
}

func TestConfig_BuildMatcherRejectsDisabled(t *testing.T) {
	t.Parallel()
	c := DefaultConfig()
	_, err := c.BuildMatcher("")
	if err == nil || !strings.Contains(err.Error(), "Enabled=false") {
		t.Fatalf("expected disabled error, got %v", err)
	}
}

func TestConfig_BuildMatcherUnknownProfile(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles:       map[string]ProfileSpec{"code": {Classes: []string{"email"}}},
	}
	_, err := c.BuildMatcher("does-not-exist")
	if err == nil || !strings.Contains(err.Error(), "profile \"does-not-exist\" not found") {
		t.Fatalf("expected profile-not-found error, got %v", err)
	}
}

// TestConfig_BuildMatcherUnresolvedEntriesFile diagnoses the footgun from
// review finding #2 (2026-04-19): Validate passes when only entries_file
// is set, but BuildMatcher needs Entries resolved. The error message must
// name entries_file so operators understand what the caller needs to do.
func TestConfig_BuildMatcherUnresolvedEntriesFile(t *testing.T) {
	t.Parallel()
	c := Config{
		Enabled:        true,
		DefaultProfile: "p",
		Profiles: map[string]ProfileSpec{
			"p": {Classes: []string{"ipv4"}, Dictionaries: []string{"d"}},
		},
		Dictionaries: map[string]DictionarySpec{
			"d": {
				Class:       "customer",
				EntriesFile: "/etc/pipelock/dicts/customers.yaml",
			},
		},
	}
	// Validate must accept this (entries_file is caller responsibility).
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil (caller resolves entries_file)", err)
	}
	// BuildMatcher must fail-closed with a diagnostic error naming
	// entries_file.
	_, err := c.BuildMatcher("p")
	if err == nil {
		t.Fatalf("BuildMatcher must fail when entries_file is unresolved")
	}
	if !strings.Contains(err.Error(), "entries_file") {
		t.Fatalf("error must mention entries_file, got: %v", err)
	}
}

func TestConfig_LimitsSpecToLimitsPassthrough(t *testing.T) {
	t.Parallel()
	s := LimitsSpec{MaxBodyBytes: 1024, MaxRedactionsPerRequest: 42, MaxDepth: 5}
	l := s.ToLimits()
	if l.MaxBodyBytes != 1024 || l.MaxRedactionsPerRequest != 42 || l.MaxDepth != 5 {
		t.Fatalf("pass-through broke: %+v", l)
	}
}

func TestConfig_DefaultsInert(t *testing.T) {
	t.Parallel()
	d := DefaultConfig()
	if d.Enabled {
		t.Fatal("DefaultConfig must be disabled")
	}
	if d.Limits.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("MaxBodyBytes = %d, want %d", d.Limits.MaxBodyBytes, DefaultMaxBodyBytes)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("DefaultConfig should validate, got %v", err)
	}
}
