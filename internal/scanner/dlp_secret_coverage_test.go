// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

// This file covers the secret-pattern expansion at the URL
// transport: database connection strings, the GitLab token families beyond
// glpat-, and cloud service-account keys (GCP / Azure). Each family has a
// positive test (a real-shaped secret must block) and a negative test (a
// documented look-alike must NOT block). Secrets are assembled at runtime so
// source scanners (gitleaks/gosec) do not flag the fixtures, and all fixtures
// use low-entropy repeated characters so the entropy layer never fires and the
// DLP regex is isolated. SSRF is disabled in testConfig.

// scanURLValue embeds value as a query parameter and scans the resulting URL.
func scanURLValue(t *testing.T, s *Scanner, value string) Result {
	t.Helper()
	return s.Scan(context.Background(), "https://evil.example/collect?x="+value)
}

// assertBlockedByDLP fails unless value is blocked and the blocking scanner is
// the DLP layer.
func assertBlockedByDLP(t *testing.T, s *Scanner, name, value string) {
	t.Helper()
	result := scanURLValue(t, s, value)
	if result.Allowed {
		t.Errorf("%s: expected %q to be blocked by DLP, was allowed", name, value)
		return
	}
	if result.Scanner != ScannerDLP && result.Scanner != ScannerCoreDLP {
		t.Errorf("%s: expected DLP scanner, got %s: %s", name, result.Scanner, result.Reason)
	}
}

// assertAllowed fails if value is blocked by any scanner (false-positive guard).
func assertAllowed(t *testing.T, s *Scanner, name, value string) {
	t.Helper()
	result := scanURLValue(t, s, value)
	if !result.Allowed {
		t.Errorf("%s: expected %q to be allowed (no false positive), blocked by %s: %s",
			name, value, result.Scanner, result.Reason)
	}
}

func TestDLP_DatabaseConnectionStrings(t *testing.T) {
	s := MustNew(testConfig())
	defer s.Close()

	pw := strings.Repeat("p", 12) // low-entropy password

	t.Run("positive", func(t *testing.T) {
		cases := map[string]string{
			"postgres":      "postgres://admin:" + pw + "@db.example:5432/app",
			"postgresql":    "postgresql://u:" + pw + "@h/app",
			"mysql":         "mysql://root:" + pw + "@h:3306/app",
			"mongodb":       "mongodb://u:" + pw + "@h/app",
			"mongodb+srv":   "mongodb+srv://u:" + pw + "@cluster.example/app",
			"redis":         "redis://u:" + pw + "@cache:6379",
			"rediss":        "rediss://u:" + pw + "@cache:6380",
			"redis pw-only": "redis://:" + pw + "@cache:6379",
		}
		for name, v := range cases {
			assertBlockedByDLP(t, s, name, v)
		}
	})

	t.Run("negative", func(t *testing.T) {
		cases := map[string]string{
			// No embedded credential (no ":pass@"). The host:port colon is
			// split in source so gosec's G101 connection-string heuristic does
			// not read "host:port" as "user:pass".
			"postgres no creds": "postgres://db.example" + ":5432/app",
			"redis no creds":    "redis://cache.example" + ":6379/0",
			// Username only, no password before '@'.
			"mysql user only": "mysql://" + "readonly" + "@h/app",
			// HTTP(S) basic-auth URL is not a DB scheme and must not match.
			"http basic auth": "https://" + "user" + ":" + pw + "@" + "example.org",
		}
		for name, v := range cases {
			assertAllowed(t, s, name, v)
		}
	})
}

func TestDLP_GitLabTokenFamilies(t *testing.T) {
	s := MustNew(testConfig())
	defer s.Close()

	suffix := strings.Repeat("A", 24) // >= 20 base64url chars

	t.Run("positive", func(t *testing.T) {
		cases := map[string]string{
			"deploy":        "gldt-" + suffix,
			"runner":        "glrt-" + suffix,
			"runner glrtr":  "glrtr-" + suffix,
			"ci job":        "glcbt-" + suffix,
			"trigger":       "glptt-" + suffix,
			"oauth secret":  "gloas-" + suffix,
			"scim":          "glsoat-" + suffix,
			"feed":          "glft-" + suffix,
			"incoming mail": "glimt-" + suffix,
			"agent":         "glagent-" + suffix,
			"workspace":     "glwt-" + suffix,
			"feature flags": "glffct-" + suffix,
		}
		for name, v := range cases {
			assertBlockedByDLP(t, s, name, v)
		}
	})

	t.Run("negative", func(t *testing.T) {
		cases := map[string]string{
			// Too short (< 20 chars after prefix).
			"deploy too short": "gldt-" + strings.Repeat("A", 8),
			// Real English words that share leading "gl" but no token prefix.
			"glance word": "glance-2026-summary-report-final",
			"global word": "global-configuration-value-here-x",
		}
		for name, v := range cases {
			assertAllowed(t, s, name, v)
		}
	})
}

func TestDLP_CloudServiceAccountKeys(t *testing.T) {
	s := MustNew(testConfig())
	defer s.Close()

	hex40 := strings.Repeat("a", 40)       // private_key_id shape
	b64 := strings.Repeat("A", 86) + "=="  // 88-char storage key
	sig := strings.Repeat("A", 43) + "%3d" // urlencoded base64 sig
	// Split the SA type marker in source so gosec G101 does not flag it.
	saMarker := `"type":"` + "service" + "_account" + `"`

	t.Run("positive", func(t *testing.T) {
		cases := map[string]string{
			"gcp sa marker": saMarker,
			"gcp key id":    `"private_key_id":"` + hex40 + `"`,
			"azure storage": "AccountKey=" + b64,
			"azure sas":     "sv=2024-11-04&se=2026-06-01T00%3A00%3A00Z&sig=" + sig,
		}
		for name, v := range cases {
			assertBlockedByDLP(t, s, name, v)
		}
	})

	t.Run("negative", func(t *testing.T) {
		cases := map[string]string{
			// Different "type" value.
			"gcp non-sa type": `"type":"authorized_user"`,
			// private_key_id with wrong length (39 hex) must not match.
			"gcp key id short": `"private_key_id":"` + strings.Repeat("a", 39) + `"`,
			// AccountKey with too-short value.
			"azure storage short": "AccountKey=" + strings.Repeat("A", 20),
			// A generic short sig= is not a SAS signature.
			"azure sig short": "sig=" + strings.Repeat("A", 8),
		}
		for name, v := range cases {
			assertAllowed(t, s, name, v)
		}
	})
}
