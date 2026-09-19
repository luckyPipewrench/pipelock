// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// expiryDate returns a YYYY-MM-DD date offset days from today in UTC. Tests
// derive every date from the governing horizon instead of pinning a literal,
// so no case turns red on a calendar date.
func expiryDate(t *testing.T, offset time.Duration) string {
	t.Helper()
	return time.Now().UTC().Add(offset).Format("2006-01-02")
}

func validObserveEntry(t *testing.T) CoreObserveException {
	t.Helper()
	return CoreObserveException{
		Host:    "docs.vendor.example",
		Pattern: "Prompt Injection",
		Reason:  "vendor prompt-injection guide is read during rule authoring",
		Owner:   "security-team",
		Expires: expiryDate(t, 7*24*time.Hour),
	}
}

func TestValidateCoreObserveExceptions_AcceptsADeclaredEntry(t *testing.T) {
	entries := []CoreObserveException{validObserveEntry(t)}
	if err := validateCoreObserveExceptions(entries); err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	// Positive control: the validator normalizes rather than silently passing
	// whatever it was handed.
	if entries[0].Host != "docs.vendor.example" {
		t.Fatalf("host not canonicalized: %q", entries[0].Host)
	}
}

func TestValidateCoreObserveExceptions_RefusesEachMissingAuthorizationField(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*CoreObserveException)
		wantSub string
	}{
		{"wildcard host", func(e *CoreObserveException) { e.Host = "*.vendor.example" }, "without wildcards"},
		{"bare wildcard", func(e *CoreObserveException) { e.Host = "*" }, "wildcard"},
		{"empty pattern", func(e *CoreObserveException) { e.Pattern = "" }, "pattern is required"},
		{"non-core pattern", func(e *CoreObserveException) { e.Pattern = "Some Configured Pattern" }, "is not a core response pattern"},
		{"empty reason", func(e *CoreObserveException) { e.Reason = "   " }, "reason is required"},
		{"empty owner", func(e *CoreObserveException) { e.Owner = "" }, "owner is required"},
		{"control chars in reason", func(e *CoreObserveException) { e.Reason = "bad\x00reason" }, "control characters"},
		{"empty expires", func(e *CoreObserveException) { e.Expires = "" }, "expires is required"},
		{"malformed expires", func(e *CoreObserveException) { e.Expires = "next tuesday" }, "must be YYYY-MM-DD"},
		{"already expired", func(e *CoreObserveException) { e.Expires = expiryDate(t, -48*time.Hour) }, "already expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := validObserveEntry(t)
			// Prove the fixture is good before mutating it, so an
			// unconditional validator failure cannot make this case pass.
			if err := validateCoreObserveExceptions([]CoreObserveException{validObserveEntry(t)}); err != nil {
				t.Fatalf("positive control failed: %v", err)
			}
			tc.mutate(&entry)
			err := validateCoreObserveExceptions([]CoreObserveException{entry})
			if err == nil {
				t.Fatalf("expected refusal for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not name %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestValidateCoreObserveExceptions_RefusesDuplicateHostPattern(t *testing.T) {
	a := validObserveEntry(t)
	b := validObserveEntry(t)
	b.Expires = expiryDate(t, 14*24*time.Hour)
	err := validateCoreObserveExceptions([]CoreObserveException{a, b})
	if err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("expected duplicate refusal, got %v", err)
	}
}

func TestMatchCoreObserveException_ExpiryIsReEvaluatedAtScanTime(t *testing.T) {
	entry := validObserveEntry(t)
	entry.Expires = expiryDate(t, 2*24*time.Hour)
	entries := []CoreObserveException{entry}

	now := time.Now().UTC()
	if _, ok := MatchCoreObserveException(entries, "docs.vendor.example", "Prompt Injection", now); !ok {
		t.Fatal("live exception did not match")
	}
	// The same config, later. A process that loaded this months ago must stop
	// observing without waiting for a reload.
	later := now.Add(10 * 24 * time.Hour)
	if _, ok := MatchCoreObserveException(entries, "docs.vendor.example", "Prompt Injection", later); ok {
		t.Fatal("expired exception still matched; the floor would stay open")
	}
}

func TestMatchCoreObserveException_ScopeIsExact(t *testing.T) {
	entries := []CoreObserveException{validObserveEntry(t)}
	now := time.Now().UTC()
	for _, tc := range []struct{ name, host, pattern string }{
		{"other host", "evil.example", "Prompt Injection"},
		{"subdomain of declared host", "sub.docs.vendor.example", "Prompt Injection"},
		{"declared host as a suffix", "notdocs.vendor.example", "Prompt Injection"},
		{"other core pattern", "docs.vendor.example", "System Override"},
		{"non-core pattern", "docs.vendor.example", "Some Configured Pattern"},
		{"empty host", "", "Prompt Injection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := MatchCoreObserveException(entries, tc.host, tc.pattern, now); ok {
				t.Fatalf("exception leaked to %s/%s", tc.host, tc.pattern)
			}
		})
	}
	// Positive control for the same table: the exact pair still matches.
	if _, ok := MatchCoreObserveException(entries, "docs.vendor.example", "Prompt Injection", now); !ok {
		t.Fatal("exact declared pair stopped matching")
	}
}

func TestValidateCoreObserveExceptions_RefusesOverlongText(t *testing.T) {
	for _, field := range []string{"reason", "owner"} {
		t.Run(field, func(t *testing.T) {
			entry := validObserveEntry(t)
			long := strings.Repeat("x", 201)
			if field == "reason" {
				entry.Reason = long
			} else {
				entry.Owner = long
			}
			err := validateCoreObserveExceptions([]CoreObserveException{entry})
			if err == nil || !strings.Contains(err.Error(), "200 characters or fewer") {
				t.Fatalf("expected length refusal for %s, got %v", field, err)
			}
		})
	}
}

func TestValidate_RejectsABadCoreObserveEntry(t *testing.T) {
	// Proves the entry validator is actually reachable from Validate rather
	// than only from its own unit test.
	cfg := Defaults()
	bad := validObserveEntry(t)
	bad.Owner = ""
	cfg.ResponseScanning.CoreObserveExceptions = []CoreObserveException{bad}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "owner is required") {
		t.Fatalf("Validate did not reject the entry: %v", err)
	}
}

func TestMatchCoreObserveException_BlankExpiryNeverExtends(t *testing.T) {
	entry := validObserveEntry(t)
	entry.Expires = "   "
	if _, ok := MatchCoreObserveException([]CoreObserveException{entry}, "docs.vendor.example", "Prompt Injection", time.Now().UTC()); ok {
		t.Fatal("a blank expiry was treated as live")
	}
}

func TestMatchCoreObserveException_MalformedExpiryNeverExtends(t *testing.T) {
	entry := validObserveEntry(t)
	entry.Expires = "garbage"
	if _, ok := MatchCoreObserveException([]CoreObserveException{entry}, "docs.vendor.example", "Prompt Injection", time.Now().UTC()); ok {
		t.Fatal("malformed expiry was treated as live")
	}
}

func TestValidateExpiryAuthorizations_BoundsTheObserveHorizon(t *testing.T) {
	cfg := Defaults()
	entry := validObserveEntry(t)
	entry.Expires = expiryDate(t, MaxCoreObserveExceptionHorizon+7*24*time.Hour)
	cfg.ResponseScanning.CoreObserveExceptions = []CoreObserveException{entry}
	err := cfg.ValidateExpiryAuthorizations()
	if err == nil || !strings.Contains(err.Error(), "maximum temporary horizon") {
		t.Fatalf("expected horizon refusal, got %v", err)
	}

	// Positive control: inside the horizon it passes, so the case above is
	// about the horizon and not about an unrelated validation failure.
	entry.Expires = expiryDate(t, MaxCoreObserveExceptionHorizon-3*24*time.Hour)
	cfg.ResponseScanning.CoreObserveExceptions = []CoreObserveException{entry}
	if err := cfg.ValidateExpiryAuthorizations(); err != nil {
		t.Fatalf("entry inside the horizon rejected: %v", err)
	}
}
