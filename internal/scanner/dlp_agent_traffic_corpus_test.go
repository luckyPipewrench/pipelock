// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// dlpAgentTrafficFixtures is the positive-control corpus for every pattern in
// the shipped full preset. Values are synthetic and assembled at runtime so
// repository secret scanners do not mistake fixtures for live credentials.
func dlpAgentTrafficFixtures(t *testing.T) map[string]string {
	t.Helper()
	githubJWTHeader := strings.Join([]string{"ghs_", "eyJ", "hbG", "ciOi", "JFUz", "I1Ni", "J9."}, "")

	return map[string]string{
		"Anthropic API Key":                  "sk-" + "ant-" + strings.Repeat("A", 24),
		"OpenAI API Key":                     "sk-" + "proj-" + strings.Repeat("B", 24),
		"OpenAI Service Key":                 "sk-" + "svcacct-" + strings.Repeat("C", 24),
		"Fireworks API Key":                  "fw_" + strings.Repeat("D", 22),
		"LLM Router API Key":                 "sk-or-v1-" + strings.Repeat("a", 24),
		"Answer Engine API Key":              "pplx-" + strings.Repeat("E", 24),
		"Web Research API Key":               "tvly-" + strings.Repeat("F", 24),
		"Google API Key":                     "AIza" + strings.Repeat("G", 35),
		"Google OAuth Client Secret":         "GOCSPX-" + strings.Repeat("H", 28),
		"Stripe Key":                         "sk_" + "live_" + strings.Repeat("I", 24),
		"Stripe Webhook Secret":              "whsec_" + strings.Repeat("J", 24),
		"GitHub Token":                       githubJWTHeader + strings.Repeat("K", 240) + "." + strings.Repeat("L", 220) + "-_",
		"GitHub Fine-Grained PAT":            "github_pat_" + strings.Repeat("M", 40),
		"GitLab PAT":                         "glpat-" + strings.Repeat("N", 24),
		"GitLab Deploy Token":                "gldt-" + strings.Repeat("O", 24),
		"GitLab Runner Token":                "glrt-" + strings.Repeat("P", 24),
		"GitLab CI Job Token":                "glcbt-" + strings.Repeat("Q", 24),
		"GitLab Pipeline Trigger Token":      "glptt-" + strings.Repeat("R", 24),
		"GitLab OAuth Application Secret":    "gloas-" + strings.Repeat("S", 24),
		"GitLab SCIM Token":                  "glsoat-" + strings.Repeat("T", 24),
		"GitLab Service Token":               "glagent-" + strings.Repeat("U", 24),
		"PostgreSQL Connection String":       "postgres://user:" + strings.Repeat("p", 12) + "@db.example/app",
		"MySQL Connection String":            "mysql://user:" + strings.Repeat("q", 12) + "@db.example/app",
		"MongoDB Connection String":          "mongodb://user:" + strings.Repeat("r", 12) + "@db.example/app",
		"Redis Connection String":            "redis://:" + strings.Repeat("s", 12) + "@cache.example:6379",
		"AWS Access ID":                      "AKIA" + strings.Repeat("V", 16),
		"AWS Secret Key":                     "aws_secret_access_key = " + strings.Repeat("W", 40),
		"Google OAuth Token":                 "ya29." + strings.Repeat("X", 24),
		"GCP Service Account Private Key ID": `"private_key_id":"` + strings.Repeat("a", 40) + `"`,
		"Azure Storage Account Key":          "AccountKey=" + strings.Repeat("Y", 86) + "==",
		"Azure SAS Token":                    "sig=" + strings.Repeat("Z", 43) + "=",
		"Slack Token":                        "xoxb-" + strings.Repeat("1", 16),
		"Slack App Token":                    "xapp-1-" + strings.Repeat("A", 12) + "-2-" + strings.Repeat("b", 16),
		"Discord Bot Token":                  "M" + strings.Repeat("A", 23) + "." + strings.Repeat("B", 6) + "." + strings.Repeat("C", 27),
		"Twilio API Key":                     "SK" + strings.Repeat("a", 32),
		"SendGrid API Key":                   "SG." + strings.Repeat("D", 22) + "." + strings.Repeat("E", 43),
		"Mailgun API Key":                    "key-" + strings.Repeat("F", 32),
		"New Relic API Key":                  "NRAK-" + strings.Repeat("G", 27),
		"Hugging Face Token":                 "hf_" + strings.Repeat("H", 34),
		"Databricks Token":                   "dapi" + strings.Repeat("a", 32),
		"Replicate API Token":                "r8_" + strings.Repeat("b", 40),
		"Together AI Key":                    "tok_" + strings.Repeat("c", 40),
		"Pinecone API Key":                   "pcsk_" + strings.Repeat("I", 36),
		"Groq API Key":                       "gsk_" + strings.Repeat("J", 48),
		"xAI API Key":                        "xai-" + strings.Repeat("K", 80),
		"DigitalOcean Token":                 "dop_v1_" + strings.Repeat("d", 64),
		"HashiCorp Vault Token":              "hvs." + strings.Repeat("L", 24),
		"Vercel Token":                       "vercel_" + strings.Repeat("M", 24),
		"Supabase Service Key":               "sb_secret_" + strings.Repeat("N", 22) + "_" + strings.Repeat("O", 8),
		"npm Token":                          "npm_" + strings.Repeat("P", 36),
		"PyPI Token":                         "pypi-AgE" + strings.Repeat("Q", 90),
		"Linear API Key":                     "lin_api_" + strings.Repeat("R", 40),
		"Notion API Key":                     "ntn_" + strings.Repeat("S", 40),
		"Sentry Auth Token":                  "sntrys_" + strings.Repeat("T", 40),
		"Private Key Header":                 "-----BEGIN " + "PRIVATE KEY-----",
		"JWT Token":                          "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + strings.Repeat("U", 32),
		"Bitcoin WIF Private Key":            "5HueCGU8rMjx" + "EXxiPuD5BDku4MkFqe" + "Zyd4dZ1jvhTVqvbTLvyTJ",
		"Extended Private Key":               "xprv" + strings.Repeat("A", 107),
		"Ethereum Private Key":               "0x" + strings.Repeat("ab", 32),
		"Social Security Number":             "123-" + "45-" + "6789",
		"Google OAuth Client ID":             "123456-" + strings.Repeat("V", 32) + ".apps.googleusercontent.com",
		"Credential in URL":                  "?token=" + strings.Repeat("W", 12),
		"Environment Variable Secret":        "SERVICE_API_KEY=" + strings.Repeat("X", 12),
		"Credit Card Number":                 "4111" + "1111" + "1111" + "1111",
		"IBAN":                               "DE89" + "3704" + "0044" + "0532" + "0130" + "00",
		"Ethereum Address":                   "0x" + strings.Repeat("cd", 20),
	}
}

func TestDLPAgentTrafficCorpusCoversFullPreset(t *testing.T) {
	patterns, err := config.PresetDLPPatterns(config.DLPPresetProfileFull)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := dlpAgentTrafficFixtures(t)

	for _, pattern := range patterns {
		if _, ok := fixtures[pattern.Name]; !ok {
			t.Errorf("full-preset pattern %q has no agent-traffic fixture", pattern.Name)
		}
	}
	for name := range fixtures {
		found := false
		for _, pattern := range patterns {
			if pattern.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("agent-traffic fixture %q has no full-preset pattern", name)
		}
	}
}

func TestDLPAgentTrafficCorpusAcrossCarriers(t *testing.T) {
	patterns, err := config.PresetDLPPatterns(config.DLPPresetProfileFull)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.DLP.IncludeDefaults = ptrBool(false)
	cfg.DLP.Patterns = patterns
	s := MustNew(cfg)
	defer s.Close()

	carriers := map[string]func(string) string{
		"prompt":      func(secret string) string { return "Use this credential for the next tool call: " + secret },
		"tool_args":   func(secret string) string { return `{"arguments":{"credential":"` + secret + `"}}` },
		"form_body":   func(secret string) string { return "credential=" + url.QueryEscape(secret) },
		"base64_blob": func(secret string) string { return base64.StdEncoding.EncodeToString([]byte(secret)) },
	}

	ctx := context.Background()
	for patternName, secret := range dlpAgentTrafficFixtures(t) {
		patternName, secret := patternName, secret
		for carrierName, carry := range carriers {
			carrierName, carry := carrierName, carry
			t.Run(patternName+"/"+carrierName, func(t *testing.T) {
				result := s.ScanTextForDLP(ctx, carry(secret))
				if result.Clean {
					t.Fatalf("%s was not detected in %s traffic", patternName, carrierName)
				}
				if !hasTextDLPMatch(result.Matches, patternName, "") && !hasTextDLPMatch(result.Matches, patternName, "base64") &&
					!hasTextDLPMatch(result.Matches, patternName, "url") {
					t.Fatalf("wanted %q in matches for %s, got %v", patternName, carrierName, result.Matches)
				}
			})
		}
	}
}

func TestDLPAgentTrafficChangedFormatNearMissesStayClean(t *testing.T) {
	cfg := testConfig()
	s := MustNew(cfg)
	defer s.Close()

	tests := map[string]string{
		"github stateless under issuer floor":  "ghs_" + strings.Repeat("A", 35),
		"classic github does not gain hyphens": "ghp_" + strings.Repeat("B", 20) + "-" + strings.Repeat("C", 40),
		"azure decoded signature too short":    "sig=" + strings.Repeat("D", 42) + "=",
		"generic colon-delimited signature":    "sig=" + strings.Repeat("E", 43) + ":",
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), text)
			if !result.Clean {
				t.Fatalf("near-miss %q matched: %+v", text, result.Matches)
			}
		})
	}
}
