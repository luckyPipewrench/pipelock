// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"strings"
	"testing"
)

func TestMatcher_AddDictionaryBasic(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	if err := m.AddDictionary(Dictionary{
		Class:        Class("customer"),
		Entries:      []string{"AcmeCorp", "Contoso"},
		WordBoundary: true,
		Priority:     55,
	}); err != nil {
		t.Fatalf("AddDictionary: %v", err)
	}

	matches := m.Scan("AcmeCorp was acquired by Contoso last year")
	if len(matches) != 2 {
		t.Fatalf("expected 2 dictionary matches, got %d: %+v", len(matches), matches)
	}
	for _, mv := range matches {
		if mv.Class != Class("customer") {
			t.Errorf("unexpected class %s for %q", mv.Class, mv.Original)
		}
	}
}

func TestMatcher_DictionaryCaseInsensitive(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	if err := m.AddDictionary(Dictionary{
		Class:           Class("hostname"),
		Entries:         []string{"dc01"},
		CaseInsensitive: true,
		WordBoundary:    true,
	}); err != nil {
		t.Fatalf("AddDictionary: %v", err)
	}

	cases := []string{"DC01 is down", "dc01 is down", "Dc01 is down"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			matches := m.Scan(c)
			found := false
			for _, mv := range matches {
				if mv.Class == Class("hostname") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("case-insensitive dict did not match %q", c)
			}
		})
	}
}

func TestMatcher_DictionaryWordBoundary(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	if err := m.AddDictionary(Dictionary{
		Class:        Class("codename"),
		Entries:      []string{"Phoenix"},
		WordBoundary: true,
	}); err != nil {
		t.Fatalf("AddDictionary: %v", err)
	}

	// "Phoenixville" should NOT match (word-boundary).
	matches := m.Scan("I grew up in Phoenixville PA")
	for _, mv := range matches {
		if mv.Class == Class("codename") {
			t.Fatalf("word-boundary should have prevented match, got %+v", mv)
		}
	}
	// "Project Phoenix" MUST match.
	matches = m.Scan("Operation Phoenix launches Tuesday")
	found := false
	for _, mv := range matches {
		if mv.Class == Class("codename") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dictionary match on word-bounded 'Phoenix'")
	}
}

func TestMatcher_DictionaryLongestLiteralWins(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	if err := m.AddDictionary(Dictionary{
		Class:        Class("hostname"),
		Entries:      []string{"dc01", "dc01.corp.local"},
		WordBoundary: true,
	}); err != nil {
		t.Fatalf("AddDictionary: %v", err)
	}

	matches := m.Scan("ssh dc01.corp.local now")
	if len(matches) != 1 {
		t.Fatalf("expected 1 dictionary match, got %d: %+v", len(matches), matches)
	}
	if got := matches[0].Original; got != "dc01.corp.local" {
		t.Fatalf("dictionary matched prefix %q, want full literal %q", got, "dc01.corp.local")
	}
}

func TestMatcher_DictionaryDedupAndEscape(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	// Duplicates and regex metachars in entries must be handled safely.
	err := m.AddDictionary(Dictionary{
		Class:   Class("label"),
		Entries: []string{"foo", "foo", "", "a.b.c", `x[y]`},
	})
	if err != nil {
		t.Fatalf("AddDictionary escape/dedup: %v", err)
	}

	// "a.b.c" is a regex meta-containing literal; escape must work.
	matches := m.Scan(`the literal a.b.c and x[y] are here`)
	if len(matches) < 2 {
		t.Fatalf("expected dictionary hits on escaped literals, got %d", len(matches))
	}
}

func TestMatcher_AddDictionaryEmpty(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	err := m.AddDictionary(Dictionary{Class: Class("empty")})
	if !errors.Is(err, errEmptyDictionary) {
		t.Fatalf("expected errEmptyDictionary, got %v", err)
	}
	// All-empty entries is equivalent to no entries.
	err = m.AddDictionary(Dictionary{Class: Class("empty"), Entries: []string{"", ""}})
	if !errors.Is(err, errEmptyDictionary) {
		t.Fatalf("all-empty entries: expected errEmptyDictionary, got %v", err)
	}
}

func TestMatcher_AddDictionaryNil(t *testing.T) {
	t.Parallel()
	var m *Matcher
	err := m.AddDictionary(Dictionary{Class: Class("x"), Entries: []string{"a"}})
	if !errors.Is(err, errNilMatcher) {
		t.Fatalf("expected errNilMatcher, got %v", err)
	}
}

// TestMatcher_AddDictionaryInvalidClassName enforces that operator-supplied
// class names cannot perturb the `<pl:CLASS:N>` placeholder by containing
// reserved syntax characters. Review finding #3 (2026-04-19).
func TestMatcher_AddDictionaryInvalidClassName(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",              // empty
		"Upper",         // uppercase banned for determinism
		"with space",    // whitespace
		"with:colon",    // colon would confuse placeholder parser
		"with<angle",    // angle brackets break placeholder syntax
		"with>angle",    // same
		"_starts-under", // must start with alphanumeric
		"-starts-dash",  // same
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			m := NewDefaultMatcher()
			err := m.AddDictionary(Dictionary{
				Class:   Class(c),
				Entries: []string{"foo"},
			})
			if !errors.Is(err, errInvalidClass) {
				t.Fatalf("AddDictionary(%q) = %v, want errInvalidClass", c, err)
			}
		})
	}
}

func TestMatcher_DictionaryPriorityDominates(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	// FQDN has priority 50. Give our customer-name dict priority 75 so the
	// operator-supplied label wins over generic FQDN for "corp.local".
	if err := m.AddDictionary(Dictionary{
		Class:    Class("customer"),
		Entries:  []string{"corp.local"},
		Priority: 75,
	}); err != nil {
		t.Fatalf("AddDictionary: %v", err)
	}
	matches := m.Scan("visit corp.local for the dashboard")
	classes := make([]string, 0, len(matches))
	for _, mv := range matches {
		classes = append(classes, string(mv.Class))
	}
	found := false
	for _, c := range classes {
		if c == "customer" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dictionary-priority expected 'customer' class, got %v", classes)
	}
	for _, c := range classes {
		if c == string(ClassFQDN) {
			t.Fatalf("generic FQDN should have been suppressed by customer dict, got %v", classes)
		}
	}
}

func TestMatcher_DictionaryScanInJSON(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	if err := m.AddDictionary(Dictionary{
		Class:        Class("codename"),
		Entries:      []string{"Bluebird"},
		WordBoundary: true,
	}); err != nil {
		t.Fatalf("AddDictionary: %v", err)
	}
	body := []byte(`{"note": "Project Bluebird is red."}`)
	out, report, err := RewriteJSON(body, m, NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON: %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("expected 1 redaction, got %d", report.TotalRedactions)
	}
	if strings.Contains(string(out), "Bluebird") {
		t.Fatalf("codename leaked: %s", out)
	}
	if !strings.Contains(string(out), "<pl:codename:1>") {
		t.Fatalf("codename placeholder missing: %s", out)
	}
}

func TestMatcher_DictionaryPrefixShadowDoesNotLeakTail(t *testing.T) {
	t.Parallel()
	m := &Matcher{}
	if err := m.AddDictionary(Dictionary{
		Class:        Class("hostname"),
		Entries:      []string{"dc01", "dc01.corp.local"},
		WordBoundary: true,
	}); err != nil {
		t.Fatalf("AddDictionary: %v", err)
	}

	body := []byte(`{"cmd":"ssh dc01.corp.local now"}`)
	out, report, err := RewriteJSON(body, m, NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON: %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("expected 1 redaction, got %d", report.TotalRedactions)
	}
	outStr := string(out)
	if strings.Contains(outStr, ".corp.local") {
		t.Fatalf("dictionary prefix-shadow leaked tail: %s", outStr)
	}
	if !strings.Contains(outStr, "<pl:hostname:1>") {
		t.Fatalf("hostname placeholder missing: %s", outStr)
	}
}
