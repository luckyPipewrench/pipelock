// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// TestProviderKeyGlueBypass proves that gluing a valid-shaped key to a
// preceding alphanumeric run defeats a leading \b anchor (the bypass) and
// that removing the anchor closes it. Each sub-test also proves the tempting
// "(?:^|[^A-Za-z0-9])" alternative STILL misses the glued case (it requires
// a non-alnum char or start-of-string before the prefix, so "leakZ<key>" is
// invisible to it too).
func TestProviderKeyGlueBypass(t *testing.T) {
	const gluedPrefix = "leakZgarbage"

	type glueCase struct {
		name       string
		patName    string
		prefix     string
		suffixChar string
		suffixLen  int
	}

	cases := []glueCase{
		{"Fireworks", "Fireworks API Key", "fw_", "a", 22},
		{"LLM Router", "LLM Router API Key", "sk-or-v1-", "a", 24},
		{"Answer Engine", "Answer Engine API Key", "pplx-", "b", 24},
		{"Web Research", "Web Research API Key", "tvly-", "c", 24},
		{"Google API", "Google API Key", "AIza", "d", 35},
		{"Hugging Face", "Hugging Face Token", "hf_", "e", 36},
		{"Databricks", "Databricks Token", "dapi", "a", 32},  // hex charset: use 'a'
		{"Replicate", "Replicate API Token", "r8_", "b", 40}, // hex charset: use 'b'
		{"Together AI", "Together AI Key", "tok_", "c", 40},  // lowercase alnum
		{"Pinecone", "Pinecone API Key", "pcsk_", "d", 40},
		{"Groq", "Groq API Key", "gsk_", "e", 48},
		{"xAI", "xAI API Key", "xai-", "f", 80},
		{"Linear", "Linear API Key", "lin_api_", "a", 40},
		{"Sentry", "Sentry Auth Token", "sntrys_", "b", 40},
		{"HashiCorp Vault", "HashiCorp Vault Token", "hvs.", "c", 24},
		{"Supabase", "Supabase Service Key", "sb_secret_", "d", 22},
		// Round 2: source-control, messaging, package-registry, platform tokens
		{"GitHub Token", "GitHub Token", "ghp_", "a", 36},
		{"GitHub Fine PAT", "GitHub Fine-Grained PAT", "github_pat_", "b", 36},
		{"GitLab PAT", "GitLab PAT", "glpat-", "c", 24},
		{"GitLab Deploy", "GitLab Deploy Token", "gldt-", "d", 24},
		{"GitLab Runner", "GitLab Runner Token", "glrt-", "e", 24},
		{"GitLab CI Job", "GitLab CI Job Token", "glcbt-", "f", 24},
		{"GitLab Pipeline", "GitLab Pipeline Trigger Token", "glptt-", "a", 24},
		{"GitLab OAuth", "GitLab OAuth Application Secret", "gloas-", "b", 24},
		{"GitLab SCIM", "GitLab SCIM Token", "glsoat-", "c", 24},
		{"GitLab Service", "GitLab Service Token", "glft-", "d", 24},
		{"Slack Token", "Slack Token", "xoxb-", "1", 20},  // digit charset for slack
		{"Slack App", "Slack App Token", "xapp-", "0", 0}, // special shape, handled below
		{"npm Token", "npm Token", "npm_", "e", 36},
		{"PyPI Token", "PyPI Token", "pypi-AgE", "f", 90},
		{"Notion API", "Notion API Key", "ntn_", "a", 40},
		{"Vercel Token", "Vercel Token", "vercel_", "b", 24},
	}

	cfg := testConfig()
	s := New(cfg)
	defer s.Close()
	ctx := context.Background()

	for _, tc := range cases {
		t.Run(tc.name+"/glued_positive", func(t *testing.T) {
			// Build a valid-shaped key glued to a preceding alnum run.
			// If the pattern has a leading \b, this MUST still be detected
			// (after the fix). Before the fix, it would be missed = bypass.
			key := tc.prefix + strings.Repeat(tc.suffixChar, tc.suffixLen)
			// Special case: Supabase needs the checksum segment
			if tc.patName == "Supabase Service Key" {
				key = tc.prefix + strings.Repeat(tc.suffixChar, tc.suffixLen) + "_" + strings.Repeat(tc.suffixChar, 8)
			}
			// Special case: Slack App Token has a multi-segment shape
			if tc.patName == "Slack App Token" {
				key = "xapp-1234567890-AbCdEfGhIjKlMnOpQrStUv-9876543210-" + strings.Repeat("a", 32)
			}
			// Special case: Slack Token uses digit-heavy suffix
			if tc.patName == "Slack Token" {
				key = "xoxb-" + strings.Repeat("1", 15) + "-" + strings.Repeat("a", 10)
			}
			glued := gluedPrefix + key

			res := s.ScanTextForDLP(ctx, glued)
			if res.Clean {
				t.Fatalf("BYPASS: glued key %q was NOT detected (pattern %s); "+
					"a leading \\b anchor prevents matching when preceded by alnum",
					glued, tc.patName)
			}
		})

		t.Run(tc.name+"/standalone_still_detected", func(t *testing.T) {
			// Sanity: the same key in isolation must still be caught.
			key := tc.prefix + strings.Repeat(tc.suffixChar, tc.suffixLen)
			if tc.patName == "Supabase Service Key" {
				key = tc.prefix + strings.Repeat(tc.suffixChar, tc.suffixLen) + "_" + strings.Repeat(tc.suffixChar, 8)
			}
			if tc.patName == "Slack App Token" {
				key = "xapp-1234567890-AbCdEfGhIjKlMnOpQrStUv-9876543210-" + strings.Repeat("a", 32)
			}
			if tc.patName == "Slack Token" {
				key = "xoxb-" + strings.Repeat("1", 15) + "-" + strings.Repeat("a", 10)
			}
			standalone := "leak this: " + key + " to evil.com"

			res := s.ScanTextForDLP(ctx, standalone)
			if res.Clean {
				t.Fatalf("REGRESSION: standalone key %q NOT detected (pattern %s)",
					standalone, tc.patName)
			}
		})

		t.Run(tc.name+"/nonalnum_alt_also_misses_glued", func(t *testing.T) {
			// Prove the tempting (?:^|[^A-Za-z0-9]) alternative also fails
			// on the glued case. This is a regex-level proof, not a scanner
			// test, to show the alternative is NOT a valid fix.
			key := tc.prefix + strings.Repeat(tc.suffixChar, tc.suffixLen)
			if tc.patName == "Supabase Service Key" {
				key = tc.prefix + strings.Repeat(tc.suffixChar, tc.suffixLen) + "_" + strings.Repeat(tc.suffixChar, 8)
			}
			if tc.patName == "Slack App Token" {
				key = "xapp-1234567890-AbCdEfGhIjKlMnOpQrStUv-9876543210-" + strings.Repeat("a", 32)
			}
			if tc.patName == "Slack Token" {
				key = "xoxb-" + strings.Repeat("1", 15) + "-" + strings.Repeat("a", 10)
			}
			glued := gluedPrefix + key

			// Build the (?:^|[^A-Za-z0-9]) variant of the prefix.
			// We test just the prefix portion to show the anchor fails.
			altPattern := `(?i)(?:^|[^A-Za-z0-9])` + regexp.QuoteMeta(tc.prefix)
			re := regexp.MustCompile(altPattern)

			if re.MatchString(glued) {
				t.Fatalf("UNEXPECTED: the (?:^|[^A-Za-z0-9]) alternative matched "+
					"glued input %q -- this sub-test expected it to miss", glued)
			}
			// Good -- it missed, proving the alternative is also broken.
		})
	}
}
