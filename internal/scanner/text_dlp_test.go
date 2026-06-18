// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testAnthropicPrefix = "sk-ant-"
	testAnthropicName   = "Anthropic API Key"
	testCreditCardName  = "Credit Card" + " Number"
	testIBANName        = "IBAN"
	testABARoutingName  = "ABA Routing Number"
)

func stackedDLPFixture(secret string, layers int) string {
	out := secret
	for i := 0; i < layers; i++ {
		remaining := layers - i
		if remaining%2 == 1 {
			out = hex.EncodeToString([]byte(out))
			continue
		}
		out = base64.StdEncoding.EncodeToString([]byte(out))
	}
	return out
}

func TestScanTextForDLP(t *testing.T) {
	tests := []struct {
		name         string
		setupConfig  func() *config.Config
		setupScanner func(s *Scanner)
		text         string
		wantClean    bool
		wantPattern  string // substring match on PatternName if non-empty
		wantEncoded  string // expected Encoded field value if non-empty
	}{
		{
			name:      "clean text no matches",
			text:      "This is a perfectly normal piece of text with no secrets.",
			wantClean: true,
		},
		{
			name: "raw DLP pattern match - Anthropic API Key",

			text:        "Please use this key: " + testAnthropicPrefix + strings.Repeat("a", 25),
			wantClean:   false,
			wantPattern: testAnthropicName,
		},
		{
			name:        "raw DLP pattern match - AWS Access ID",
			text:        "My access key is AKIA" + strings.Repeat("A", 16),
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "whitespace-split AWS Access ID",
			text:        "My access key is AKIA" + strings.Repeat("A", 4) + " " + strings.Repeat("B", 12),
			wantClean:   false,
			wantPattern: "AWS Access ID",
			wantEncoded: "whitespace",
		},
		{
			name:        "raw DLP pattern match - AWS Secret Key env format",
			text:        "AWS_SECRET_ACCESS_KEY=" + "wJal" + "rXUt" + "nFEM" + "I/K7" + "MDEN" + "G/bP" + "xRfi" + "CYEXAMPLEKEY",
			wantClean:   false,
			wantPattern: "AWS Secret Key",
		},
		{
			// Real env-var assignment with a secret value still blocks.
			name:        "env var secret - real value blocks",
			text:        "PROVIDER_TOKEN=" + "tok" + "_" + strings.Repeat("A", 36),
			wantClean:   false,
			wantPattern: "Environment Variable Secret",
		},
		{
			// Space-split evasion: the value delimiter is only removed by the
			// whitespace-collapsed DLP view, so this asserts the env-var pattern
			// still fires THROUGH that view (Encoded == "whitespace") because the
			// collapsed value begins with a secret-plausible char.
			name:        "env var secret - space-split evasion blocks via whitespace view",
			text:        "PROVIDER _ TOKEN = " + "tok" + "_" + strings.Repeat("A", 36),
			wantClean:   false,
			wantPattern: "Environment Variable Secret",
			wantEncoded: "whitespace",
		},
		{
			// Regression: env-var NAME referenced in a shell guard (no value).
			// Previously the collapsed view turned the trailing document into a
			// giant \S run and matched "Environment Variable Secret".
			name:      "env var secret FP - name reference in shell guard",
			text:      `if [ -z "$PROVIDER_TOKEN" ]; then echo "set PROVIDER_TOKEN first"; fi`,
			wantClean: true,
		},
		{
			// Regression: assignment from command substitution, not a real value.
			name:      "env var secret FP - command substitution assignment",
			text:      `PROVIDER_TOKEN=$(grep "^PROVIDER_TOKEN=" ~/.config/app/.env | head -1 | cut -d= -f2)`,
			wantClean: true,
		},
		{
			// Regression: backtick command substitution, not a real value.
			name:      "env var secret FP - backtick assignment",
			text:      "PROVIDER_TOKEN=`security find-generic-password -w -s provider-token`",
			wantClean: true,
		},
		{
			// Regression: shell variable expansion, not a real value.
			name:      "credential in url FP - braced variable expansion after delimiter",
			text:      "run: deploy; token=${PROVIDER_TOKEN} && curl https://api.example/x",
			wantClean: true,
		},
		{
			// Regression: the ';' param separator must not extend the captured
			// credential value, so a short token followed by ';next=...' params
			// is not a secret (the prefix already treats ';' as a delimiter).
			name:      "credential in url FP - semicolon-separated params",
			text:      "GET /p?token=a;page=2;sort=asc",
			wantClean: true,
		},
		{
			// Detection preserved: a long credential value that is followed by a
			// ';' param still blocks; only the bleed past ';' is removed.
			name:        "credential in url - long value before semicolon blocks",
			text:        "GET /p?token=abcdef123456;page=2",
			wantClean:   false,
			wantPattern: "Credential in URL",
		},
		{
			// Regression: Authorization header template referencing an env var.
			name:      "env var secret FP - authorization header template",
			text:      `curl -H "Authorization: Bearer $PROVIDER_TOKEN" https://api.vendor.example/user`,
			wantClean: true,
		},
		{
			// Regression: Credential-in-URL sibling must not fire on a shell
			// command-substitution token assignment after a ';' delimiter.
			name:      "credential in url FP - command substitution after delimiter",
			text:      "run: deploy; token=$(get_token) && curl https://api.example/x",
			wantClean: true,
		},
		{
			name:        "raw DLP pattern match - AWS Secret Key JSON format",
			text:        `"SecretAccessKey": "` + "wJal" + "rXUt" + "nFEM" + "I/K7" + "MDEN" + "G/bP" + "xRfi" + "CYEXAMPLEKEY" + `"`,
			wantClean:   false,
			wantPattern: "AWS Secret Key",
		},
		{
			name:        "raw DLP pattern match - Stripe key with hyphens",
			text:        "sk-test-" + "4eC39HqLyjWDarjtT1zdp7dc",
			wantClean:   false,
			wantPattern: "Stripe Key",
		},
		{
			name:        "raw DLP pattern match - Stripe key with underscores",
			text:        "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
			wantClean:   false,
			wantPattern: "Stripe Key",
		},
		// secret-pattern expansion (text-DLP transport).
		{
			name:        "DB connection string - postgres with password",
			text:        "DATABASE_URL=postgres://admin:" + strings.Repeat("p", 12) + "@db.example:5432/app",
			wantClean:   false,
			wantPattern: "PostgreSQL Connection String",
		},
		{
			name:        "DB connection string - redis password-only",
			text:        "redis://:" + strings.Repeat("p", 12) + "@cache:6379",
			wantClean:   false,
			wantPattern: "Redis Connection String",
		},
		{
			name:      "DB connection string FP - no embedded credential",
			text:      "postgres://db.example:5432/app",
			wantClean: true,
		},
		{
			name:        "GitLab deploy token",
			text:        "token gldt-" + strings.Repeat("A", 24),
			wantClean:   false,
			wantPattern: "GitLab Deploy Token",
		},
		{
			name:        "GitLab runner token glrtr variant",
			text:        "glrtr-" + strings.Repeat("A", 24),
			wantClean:   false,
			wantPattern: "GitLab Runner Token",
		},
		{
			name:        "GitLab grouped service token glffct variant",
			text:        "glffct-" + strings.Repeat("A", 24),
			wantClean:   false,
			wantPattern: "GitLab Service Token",
		},
		{
			name:      "GitLab FP - english word starting gl",
			text:      "glance-2026-summary-report-final",
			wantClean: true,
		},
		{
			name:        "GCP service account marker",
			text:        `{"type": "` + "service" + "_account" + `", "project_id": "x"}`,
			wantClean:   false,
			wantPattern: "GCP Service Account Key",
		},
		{
			name:        "GCP service account private_key_id",
			text:        `"private_key_id": "` + strings.Repeat("a", 40) + `"`,
			wantClean:   false,
			wantPattern: "GCP Service Account Private Key ID",
		},
		{
			name:        "Azure storage account key",
			text:        "AccountKey=" + strings.Repeat("A", 86) + "==",
			wantClean:   false,
			wantPattern: "Azure Storage Account Key",
		},
		{
			name:        "Azure SAS signature",
			text:        "sv=2024-11-04&sig=" + strings.Repeat("A", 43) + "%3D",
			wantClean:   false,
			wantPattern: "Azure SAS Token",
		},
		{
			name:      "Azure storage FP - short value",
			text:      "AccountKey=" + strings.Repeat("A", 20),
			wantClean: true,
		},
		{
			// PGP private key armor must be detected, matching the
			// ssh-private-key redaction class. Split in source so the
			// detect-private-key pre-commit hook does not flag the fixture.
			name:        "PGP private key block",
			text:        "-----BEGIN PGP PRIVATE " + "KEY BLOCK-----",
			wantClean:   false,
			wantPattern: "Private Key Header",
		},
		// Twilio / Mailgun boundary tightening. Positive cases guard against a
		// false-negative; the wantClean cases prove the old short-prefix false
		// positives are closed at the text-DLP layer.
		{
			name:        "raw DLP pattern match - Twilio API Key",
			text:        "twilio sid SK" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			wantClean:   false,
			wantPattern: "Twilio API Key",
		},
		{
			name:        "raw DLP pattern match - Mailgun API Key",
			text:        "mailgun send key-" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			wantClean:   false,
			wantPattern: "Mailgun API Key",
		},
		{
			name:      "Twilio FP - 32-hex digest after word ending in sk",
			text:      "disk" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			wantClean: true,
		},
		{
			name:      "Twilio FP - SK followed by longer hex blob",
			text:      "SK" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4",
			wantClean: true,
		},
		{
			name:      "Mailgun FP - key- embedded mid-word",
			text:      "monkey-" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			wantClean: true,
		},
		{
			name:      "Mailgun FP - key- with longer opaque value",
			text:      "key-" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4wxyzWXYZ",
			wantClean: true,
		},
		{
			name: "base64-encoded secret decoded and matched",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("b", 25)
				return base64.StdEncoding.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "base64",
		},
		{
			name: "hex-encoded secret decoded and matched",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("c", 25)
				return hex.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "base32-encoded secret decoded and matched",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("d", 25)
				return base32.StdEncoding.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "base32",
		},
		{
			name: "env variable leak detection - raw",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.DLP.ScanEnv = true
				return cfg
			},
			setupScanner: func(s *Scanner) {
				s.envSecrets = []string{"MyTopSecretEnvValue1234"}
			},
			text:        "Here is the value: MyTopSecretEnvValue1234",
			wantClean:   false,
			wantPattern: "Environment Variable Leak",
			wantEncoded: "env",
		},
		{
			name: "env variable leak detection - base64 encoded",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.DLP.ScanEnv = true
				return cfg
			},
			setupScanner: func(s *Scanner) {
				s.envSecrets = []string{"AnotherSecretValue56789"}
			},
			text: func() string {
				return "encoded: " + base64.StdEncoding.EncodeToString([]byte("AnotherSecretValue56789"))
			}(),
			wantClean:   false,
			wantPattern: "Environment Variable Leak",
			wantEncoded: "env",
		},
		{
			name: "zero-width character bypass attempt - still caught",
			text: func() string {
				// Insert zero-width space inside the key pattern
				prefix := testAnthropicPrefix
				suffix := strings.Repeat("e", 25)
				return prefix + "\u200B" + suffix
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
		},
		{
			name: "NFKC normalization - Unicode confusables",
			text: func() string {
				// Use fullwidth characters that NFKC normalizes to ASCII
				// U+FF53 = fullwidth 's', U+FF4B = fullwidth 'k'
				// sk-ant- with fullwidth s and k
				return "\uff53\uff4b-ant-" + strings.Repeat("f", 25)
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
		},
		{
			name:      "empty text returns clean",
			text:      "",
			wantClean: true,
		},
		{
			name: "no DLP patterns configured returns clean",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.DLP.Patterns = nil
				cfg.DLP.ScanEnv = false
				return cfg
			},
			text:      testAnthropicPrefix + strings.Repeat("g", 25),
			wantClean: true,
		},
		{
			name: "deduplication - same pattern raw + encoded only appears once per encoding",
			text: func() string {
				// Both the raw secret and its base64 form in same text
				secret := testAnthropicPrefix + strings.Repeat("h", 25)
				encoded := base64.StdEncoding.EncodeToString([]byte(secret))
				return secret + " " + encoded
			}(),
			wantClean: false,
		},
		{
			name: "multiple pattern matches in single text",
			text: func() string {
				anthropic := testAnthropicPrefix + strings.Repeat("i", 25)
				aws := "AKIA" + strings.Repeat("B", 16)
				return "Keys: " + anthropic + " and " + aws
			}(),
			wantClean: false,
		},
		{
			name:        "case variation - uppercase Anthropic key",
			text:        "SK-ANT-" + strings.Repeat("A", 25),
			wantClean:   false,
			wantPattern: testAnthropicName,
		},
		{
			name:        "case variation - mixed case AWS key",
			text:        "akia" + strings.Repeat("X", 16),
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "null byte injection - secret split by null bytes",
			text:        "sk-ant-\x00" + strings.Repeat("j", 25),
			wantClean:   false,
			wantPattern: testAnthropicName,
		},
		{
			name:        "case variation - uppercase private key header",
			text:        "-----BEGIN " + strings.ToUpper("rsa") + " PRIVATE KEY-----",
			wantClean:   false,
			wantPattern: "Private Key",
		},
		{
			name:        "case variation - lowercase private key header",
			text:        strings.ToLower("-----BEGIN RSA") + " private key-----",
			wantClean:   false,
			wantPattern: "Private Key",
		},
		// --- Expanded AWS credential prefixes ---
		{
			name:        "AWS STS temporary key (ASIA prefix)",
			text:        "ASIA" + "IOSFODNN7EXAMPLE",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "AWS assumed role ID (AROA prefix)",
			text:        "AROA" + "IOSFODNN7EXAMPLE",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "AWS IAM user ID (AIDA prefix)",
			text:        "AIDA" + "IOSFODNN7EXAMPLE",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "AWS IAM group ID (AGPA prefix)",
			text:        "AGPA" + "IOSFODNN7EXAMPLE",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "AWS legacy prefix (A3T prefix)",
			text:        "A3T" + "IOSFODNN7EXAMPLE0",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "AWS EC2 instance profile (AIPA prefix)",
			text:        "AIPA" + "IOSFODNN7EXAMPLE",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "AWS managed policy (ANPA prefix)",
			text:        "ANPA" + "IOSFODNN7EXAMPLE",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		{
			name:        "AWS managed policy version (ANVA prefix)",
			text:        "ANVA" + "IOSFODNN7EXAMPLE",
			wantClean:   false,
			wantPattern: "AWS Access ID",
		},
		// --- Expanded GitHub token types ---
		{
			name:        "GitHub OAuth token (gho_ prefix)",
			text:        "gho_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			wantClean:   false,
			wantPattern: "GitHub Token",
		},
		{
			name:        "GitHub User-to-Server token (ghu_ prefix)",
			text:        "ghu_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			wantClean:   false,
			wantPattern: "GitHub Token",
		},
		{
			name:        "GitHub App refresh token (ghr_ prefix)",
			text:        "ghr_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			wantClean:   false,
			wantPattern: "GitHub Token",
		},
		{
			name:        "GitHub App install token (ghs_ prefix)",
			text:        "ghs_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			wantClean:   false,
			wantPattern: "GitHub Token",
		},
		{
			name:        "raw DLP pattern match - GitLab PAT",
			text:        "My token is " + "glpat-" + strings.Repeat("aB1cD2eF3gH4iJ5k", 2),
			wantClean:   false,
			wantPattern: "GitLab PAT",
		},
		// --- New patterns ---
		{
			name:        "Fireworks API Key",
			text:        "fw_" + "aBcDeFgHiJkLmNoPqRsTuV",
			wantClean:   false,
			wantPattern: "Fireworks API Key",
		},
		{
			name:        "Google API Key",
			text:        "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
			wantClean:   false,
			wantPattern: "Google API Key",
		},
		{
			name:        "Google OAuth Client Secret (GOCSPX)",
			text:        "GOCSPX-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaB",
			wantClean:   false,
			wantPattern: "Google OAuth Client Secret",
		},
		{
			name:        "Slack App Token (xapp prefix)",
			text:        "xapp-" + "1-A0B1C2D3E4-5678901234-abcdef0123456789",
			wantClean:   false,
			wantPattern: "Slack App Token",
		},
		{
			name: "JWT Token (3-segment base64url)",
			text: "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
				".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" +
				".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantClean:   false,
			wantPattern: "JWT Token",
		},
		{
			name:        "Google OAuth Client ID",
			text:        "123456789012" + "-abcdefghij1234567890abcdefghij12" + ".apps.googleusercontent.com",
			wantClean:   false,
			wantPattern: "Google OAuth Client ID",
		},
		// Crypto private key patterns
		{
			name: "Bitcoin WIF Private Key in text",
			// Well-known test vector (Bitcoin wiki): uncompressed WIF with valid
			// Base58Check checksum. Passes the WIF validator (version 0x80, 32-byte payload).
			text:        "Send to this wallet using key " + "5HueCGU8rMjx" + "EXxiPuD5BDku4MkFqe" + "Zyd4dZ1jvhTVqvbTLvyTJ",
			wantClean:   false,
			wantPattern: "Bitcoin WIF Private Key",
		},
		{
			name:        "Extended Private Key (xprv) in text",
			text:        "Master key: xprv" + strings.Repeat("A", 107),
			wantClean:   false,
			wantPattern: "Extended Private Key",
		},
		{
			name:        "Ethereum Private Key in text",
			text:        "ETH key is 0x" + strings.Repeat("ab", 32),
			wantClean:   false,
			wantPattern: "Ethereum Private Key",
		},
		{
			name: "base64-encoded ETH private key",
			text: func() string {
				secret := "0x" + strings.Repeat("cd", 32)
				return base64.StdEncoding.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: "Ethereum Private Key",
			wantEncoded: "base64",
		},
		{
			// The hex encoding of a valid WIF key. The scanner's senary pass
			// (hex decode) recovers the original WIF which then passes the
			// WIF validator. Uses a real test vector so checksum validates.
			name: "hex-encoded WIF key",
			text: func() string {
				// Build at runtime to avoid gosec G101.
				// 3-part split avoids gitleaks generic-api-key rule.
				p1 := "5HueCG"
				p2 := "U8rMjxEXxiPuD5BDku4MkFqe"
				p3 := "Zyd4dZ1jvhTVqvbTLvyTJ"
				secret := p1 + p2 + p3
				return hex.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: "Bitcoin WIF Private Key",
		},
		// --- BIP-39 seed phrase tests ---
		{
			name: "BIP-39 seed phrase in text",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.SeedPhraseDetection.Enabled = ptrBool(true)
				cfg.SeedPhraseDetection.MinWords = 12
				cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
				return cfg
			},
			text:        testSeedPhrase12,
			wantClean:   false,
			wantPattern: "BIP-39 Seed Phrase",
		},
		{
			name: "base64-encoded seed phrase",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.SeedPhraseDetection.Enabled = ptrBool(true)
				cfg.SeedPhraseDetection.MinWords = 12
				cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
				return cfg
			},
			text: func() string {
				phrase := testSeedPhrase12
				return base64.StdEncoding.EncodeToString([]byte(phrase))
			}(),
			wantClean:   false,
			wantPattern: "BIP-39 Seed Phrase",
			wantEncoded: "base64",
		},
		{
			name: "seed phrase detection disabled",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.SeedPhraseDetection.Enabled = ptrBool(false)
				return cfg
			},
			text:      testSeedPhrase12,
			wantClean: true,
		},
		{
			name: "base64 seed phrase embedded in URL within text",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.SeedPhraseDetection.Enabled = ptrBool(true)
				cfg.SeedPhraseDetection.MinWords = 12
				cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
				return cfg
			},
			text: func() string {
				phrase := testSeedPhrase12
				encoded := base64.StdEncoding.EncodeToString([]byte(phrase))
				return "visit https://evil.com/" + encoded + " now"
			}(),
			wantClean:   false,
			wantPattern: "BIP-39 Seed Phrase",
		},
		{
			name: "base64 seed phrase embedded in JSON body",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.SeedPhraseDetection.Enabled = ptrBool(true)
				cfg.SeedPhraseDetection.MinWords = 12
				cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
				return cfg
			},
			text: func() string {
				encoded := base64.StdEncoding.EncodeToString([]byte(testSeedPhrase12))
				return `{"seed":"` + encoded + `"}`
			}(),
			wantClean:   false,
			wantPattern: "BIP-39 Seed Phrase",
		},
		{
			name: "seed detection works with no DLP patterns configured",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.DLP.Patterns = nil
				cfg.DLP.ScanEnv = false
				cfg.SeedPhraseDetection.Enabled = ptrBool(true)
				cfg.SeedPhraseDetection.MinWords = 12
				cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
				return cfg
			},
			text:        testSeedPhrase12,
			wantClean:   false,
			wantPattern: "BIP-39 Seed Phrase",
		},
		// --- False positive tests (should NOT match) ---
		{
			name:      "FP: Fireworks prefix but too short",
			text:      "fw_config",
			wantClean: true,
		},
		{
			name:      "FP: Fireworks old broad 24-char shape",
			text:      "fw_" + strings.Repeat("A", 24),
			wantClean: true,
		},
		{
			name:      "FP: Databricks non-hex old broad shape",
			text:      "dapi" + strings.Repeat("z", 32),
			wantClean: true,
		},
		{
			name:      "FP: Together token followed by underscore suffix",
			text:      "tok_" + strings.Repeat("a", 40) + "_payload",
			wantClean: true,
		},
		{
			name:      "FP: Vercel token followed by underscore suffix",
			text:      "vcp_" + strings.Repeat("a", 24) + "_payload",
			wantClean: true,
		},
		{
			name:      "FP: Notion token followed by underscore suffix",
			text:      "ntn_" + strings.Repeat("a", 40) + "_payload",
			wantClean: true,
		},
		{
			name:      "FP: GOCSPX too short",
			text:      "GOCSPX-short",
			wantClean: true,
		},
		{
			name:      "FP: Google OAuth ID wrong domain",
			text:      "123456789-abcdef.apps.example.com",
			wantClean: true,
		},
		{
			name:      "FP: JWT-like but segments too short",
			text:      "eyJhbGci.eyJzdWI.abc",
			wantClean: true,
		},
		{
			name:      "FP: Google API Key suffix too short (34 chars)",
			text:      "AIza" + "SyA1234567890abcdefghijklmnopqrstu",
			wantClean: true,
		},
		{
			name:      "FP: ASIAN_MARKETS not an AWS key",
			text:      "ASIAN_MARKETS",
			wantClean: true,
		},
		{
			name:      "FP: Google OAuth Client ID with short numeric prefix",
			text:      "12345-abcdefghij1234567890abcdefghij12.apps.googleusercontent.com",
			wantClean: true,
		},
		// --- AI/ML platform tokens ---
		{
			name:        "raw DLP pattern match - Hugging Face Token",
			text:        "My token is " + "hf_" + strings.Repeat("a", 37),
			wantClean:   false,
			wantPattern: "Hugging Face Token",
		},
		{
			name:        "raw DLP pattern match - Databricks Token",
			text:        "My token is " + "dapi" + strings.Repeat("a", 35),
			wantClean:   false,
			wantPattern: "Databricks Token",
		},
		{
			name:        "raw DLP pattern match - Replicate API Token",
			text:        "My token is " + "r8_" + strings.Repeat("b", 40),
			wantClean:   false,
			wantPattern: "Replicate API Token",
		},
		{
			name:        "raw DLP pattern match - Together AI Key",
			text:        "My token is " + "tok_" + strings.Repeat("c", 40),
			wantClean:   false,
			wantPattern: "Together AI Key",
		},
		{
			name:        "raw DLP pattern match - Pinecone API Key",
			text:        "My token is " + "pcsk_" + strings.Repeat("d", 40),
			wantClean:   false,
			wantPattern: "Pinecone API Key",
		},
		{
			name:        "raw DLP pattern match - Groq API Key",
			text:        "My key is " + "gsk_" + strings.Repeat("aB1c", 12),
			wantClean:   false,
			wantPattern: "Groq API Key",
		},
		{
			name:        "raw DLP pattern match - xAI API Key",
			text:        "My key is " + "xai-" + strings.Repeat("abcdef12", 10),
			wantClean:   false,
			wantPattern: "xAI API Key",
		},
		{
			name:        "raw DLP pattern match - Stripe Webhook Secret",
			text:        "My secret is " + "whsec_" + strings.Repeat("aB1cD2eF3gH4iJ5k", 2),
			wantClean:   false,
			wantPattern: "Stripe Webhook Secret",
		},
		{
			name:        "raw DLP pattern match - New Relic API Key",
			text:        "My key is " + "NRAK-" + strings.Repeat("ABCDEF1234567", 3),
			wantClean:   false,
			wantPattern: "New Relic API Key",
		},
		// --- Cloud/infra tokens ---
		{
			name:        "raw DLP pattern match - DigitalOcean Token",
			text:        "My token is " + "dop_v1_" + strings.Repeat("a", 64),
			wantClean:   false,
			wantPattern: "DigitalOcean Token",
		},
		{
			name:        "raw DLP pattern match - HashiCorp Vault Token",
			text:        "My token is " + "hvs." + strings.Repeat("e", 24),
			wantClean:   false,
			wantPattern: "HashiCorp Vault Token",
		},
		{
			name:        "raw DLP pattern match - Vercel Token",
			text:        "My token is " + "vcp_" + strings.Repeat("f", 30),
			wantClean:   false,
			wantPattern: "Vercel Token",
		},
		{
			name:        "raw DLP pattern match - Supabase Service Key",
			text:        "My token is " + "sb_secret_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 8),
			wantClean:   false,
			wantPattern: "Supabase Service Key",
		},
		{
			name:        "raw DLP pattern match - Supabase Service Key ending hyphen",
			text:        "My token is " + "sb_secret_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 7) + "-",
			wantClean:   false,
			wantPattern: "Supabase Service Key",
		},
		// --- Developer platform tokens ---
		{
			name:        "raw DLP pattern match - npm Token",
			text:        "My token is " + "npm_" + strings.Repeat("h", 36),
			wantClean:   false,
			wantPattern: "npm Token",
		},
		{
			name:        "raw DLP pattern match - PyPI Token",
			text:        "My token is " + "pypi-AgE" + strings.Repeat("A", 90),
			wantClean:   false,
			wantPattern: "PyPI Token",
		},
		{
			name:        "raw DLP pattern match - Linear API Key",
			text:        "My token is " + "lin_api_" + strings.Repeat("j", 45),
			wantClean:   false,
			wantPattern: "Linear API Key",
		},
		{
			name:        "raw DLP pattern match - Notion API Key",
			text:        "My token is " + "ntn_" + strings.Repeat("k", 45),
			wantClean:   false,
			wantPattern: "Notion API Key",
		},
		{
			name:        "raw DLP pattern match - Sentry Auth Token",
			text:        "My token is " + "sntrys_" + strings.Repeat("m", 45),
			wantClean:   false,
			wantPattern: "Sentry Auth Token",
		},
		// --- Delimiter-separated hex decoding ---
		{
			name: "colon-separated hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("c", 25)
				h := hex.EncodeToString([]byte(secret))
				return hexByteSep(h, ":")
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "space-separated hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("d", 25)
				h := hex.EncodeToString([]byte(secret))
				return hexByteSep(h, " ")
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "hyphen-separated hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("e", 25)
				h := hex.EncodeToString([]byte(secret))
				return hexByteSep(h, "-")
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "backslash-x notation hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("f", 25)
				h := hex.EncodeToString([]byte(secret))
				return hexBytePrefix(h, `\x`)
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "0x-prefixed hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("a", 25)
				return "0x" + hex.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "comma-separated hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("b", 25)
				h := hex.EncodeToString([]byte(secret))
				return hexByteSep(h, ",")
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "0x per-byte contiguous hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("g", 25)
				h := hex.EncodeToString([]byte(secret))
				return hexBytePrefix(h, "0x")
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "0x per-byte comma-separated hex-encoded secret",
			text: func() string {
				secret := testAnthropicPrefix + strings.Repeat("h", 25)
				h := hex.EncodeToString([]byte(secret))
				parts := make([]string, 0, len(h)/2)
				for i := 0; i < len(h); i += 2 {
					parts = append(parts, "0x"+h[i:i+2])
				}
				return strings.Join(parts, ",")
			}(),
			wantClean:   false,
			wantPattern: testAnthropicName,
			wantEncoded: "hex",
		},
		{
			name: "delimiter-hex clean text not flagged",
			text: func() string {
				h := hex.EncodeToString([]byte("hello world!"))
				return hexByteSep(h, ":")
			}(),
			wantClean: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *config.Config
			if tt.setupConfig != nil {
				cfg = tt.setupConfig()
			} else {
				cfg = testConfig()
			}
			s := New(cfg)
			defer s.Close()

			if tt.setupScanner != nil {
				tt.setupScanner(s)
			}

			result := s.ScanTextForDLP(context.Background(), tt.text)

			if result.Clean != tt.wantClean {
				t.Errorf("Clean = %v, want %v (matches: %v)", result.Clean, tt.wantClean, result.Matches)
			}

			if tt.wantPattern != "" {
				found := false
				for _, m := range result.Matches {
					if strings.Contains(m.PatternName, tt.wantPattern) {
						found = true
						if tt.wantEncoded != "" && m.Encoded != tt.wantEncoded {
							t.Errorf("match %q Encoded = %q, want %q", m.PatternName, m.Encoded, tt.wantEncoded)
						}
						break
					}
				}
				if !found {
					t.Errorf("expected match containing %q, got matches: %v", tt.wantPattern, result.Matches)
				}
			}
		})
	}
}

func TestScanTextForDLP_DecodesStructuredPayloadSegment(t *testing.T) {
	s := New(testConfig())
	secret := testAnthropicPrefix + strings.Repeat("z", 25)
	body := `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(secret)) + `"}`

	result := s.ScanTextForDLP(context.Background(), body)
	if result.Clean {
		t.Fatal("expected encoded secret inside JSON string to be detected")
	}
	if !hasTextDLPMatch(result.Matches, testAnthropicName, "base64") {
		t.Fatalf("expected base64 %q match, got %+v", testAnthropicName, result.Matches)
	}
}

func TestScanTextForDLP_AllowsOfficialAWSExampleCredentialDocs(t *testing.T) {
	s := New(testConfig())
	key := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	secret := "wJal" + "rXUt" + "nFEM" + "I/K7" + "MDEN" + "G/bP" + "xRfi" + "CY" + "EXAMPLEKEY"

	doc := "Example credentials: aws_access_key_id = " + key +
		"\naws_secret_access_key = " + secret +
		"\nReplace these with your actual credentials."
	if result := s.ScanTextForDLP(context.Background(), doc); !result.Clean {
		t.Fatalf("expected official example credential docs to be clean, got %+v", result.Matches)
	}

	leak := "exfil key " + key
	if result := s.ScanTextForDLP(context.Background(), leak); result.Clean {
		t.Fatal("expected bare AWS example access key outside docs context to be detected")
	}
}

// TestEnvVarSecret_WhitespaceViewMechanism locks the exact path that fired in
// production. A wrapped tool RESULT and a wrapped first-party MCP tool's
// security-review input both blocked on "Environment Variable Secret" because
// the whitespace-collapsed DLP view (compactTextDLPWhitespace) deleted the
// value delimiter, letting the value run absorb the rest of the document. The
// value sub-pattern now requires a secret-plausible leading char, so the
// collapsed view no longer matches benign env-var references while real
// space-split assignments still do. Asserting against the collapsed view
// directly (not raw text) covers the real mechanism.
func TestEnvVarSecret_WhitespaceViewMechanism(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	const envVarPattern = "Environment Variable Secret"

	fps := []struct{ name, text string }{
		{"name reference in guard", `if [ -z "$PROVIDER_TOKEN" ]; then echo "set PROVIDER_TOKEN first"; fi`},
		{"command substitution", `PROVIDER_TOKEN=$(grep "^PROVIDER_TOKEN=" ~/.config/app/.env | cut -d= -f2)`},
		{"backtick command substitution", "PROVIDER_TOKEN=`security find-generic-password -w -s provider-token`"},
		{"authorization template", `curl -H "Authorization: Bearer $PROVIDER_TOKEN" https://api.vendor.example/user`},
		{"credential-in-url command sub", `run: deploy; token=$(get_token) && push origin main`},
		{"credential-in-url braced var", `run: deploy; token=${PROVIDER_TOKEN} && push origin main`},
	}
	for _, tt := range fps {
		t.Run("fp/"+tt.name, func(t *testing.T) {
			compacted := compactTextDLPWhitespace(tt.text)
			for _, m := range s.matchDLPPatterns(compacted, "whitespace") {
				if m.PatternName == envVarPattern || m.PatternName == "Credential in URL" {
					t.Errorf("collapsed-view FP: %q matched on %q", m.PatternName, tt.text)
				}
			}
		})
	}

	// A real space-split env-var assignment must STILL be caught by the
	// collapsed view (detection preserved for the evasion case).
	realSecret := "tok" + "_" + strings.Repeat("A", 36)
	compacted := compactTextDLPWhitespace("PROVIDER _ TOKEN = " + realSecret)
	if !hasTextDLPMatch(s.matchDLPPatterns(compacted, "whitespace"), envVarPattern, "whitespace") {
		t.Error("collapsed view must still catch a space-split env-var secret assignment")
	}
}

// TestEnvVarSecret_BothDirections proves the env-var-secret precision fix holds
// on both the outbound (agent->tool / request) and inbound (tool result /
// response) DLP scanning entry points, since both run the same shared pattern
// set. The shell-example false positive must be clean and a real leaked value
// must still block in each direction.
func TestEnvVarSecret_BothDirections(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	shellExample := `PROVIDER_TOKEN=$(grep "^PROVIDER_TOKEN=" ~/.config/app/.env | cut -d= -f2)` +
		"\n" + `curl -H "Authorization: Bearer $PROVIDER_TOKEN" https://api.vendor.example/user`
	realLeak := "PROVIDER_TOKEN=" + "tok" + "_" + strings.Repeat("B", 36)

	directions := []struct {
		name string
		scan func(string) TextDLPResult
	}{
		{"outbound", func(text string) TextDLPResult { return s.ScanTextForDLP(context.Background(), text) }},
		{"inbound", func(text string) TextDLPResult { return s.ScanTextForDLPInbound(context.Background(), text) }},
	}
	for _, d := range directions {
		t.Run(d.name, func(t *testing.T) {
			if res := d.scan(shellExample); !res.Clean {
				t.Errorf("shell example should be clean, got matches: %v", res.Matches)
			}
			if res := d.scan(realLeak); res.Clean {
				t.Error("real leaked env-var secret must still block")
			}
		})
	}
}

func hasTextDLPMatch(matches []TextDLPMatch, name, encoded string) bool {
	for _, m := range matches {
		if m.PatternName == name && m.Encoded == encoded {
			return true
		}
	}
	return false
}

func TestScanTextForDLP_Deduplication(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// The raw secret appears in the text AND the base64-decoded form also matches.
	// The raw match (Encoded="") should appear once, the base64 match (Encoded="base64")
	// should appear once - no duplicates within the same PatternName+Encoded pair.
	secret := testAnthropicPrefix + strings.Repeat("x", 25)
	// Construct text that has the raw secret AND its base64 encoding
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	text := secret + " " + encoded

	result := s.ScanTextForDLP(context.Background(), text)
	if result.Clean {
		t.Fatal("expected matches, got clean")
	}

	// Count occurrences of testAnthropicName with Encoded=""
	rawCount := 0
	b64Count := 0
	for _, m := range result.Matches {
		if m.PatternName == testAnthropicName && m.Encoded == "" {
			rawCount++
		}
		if m.PatternName == testAnthropicName && m.Encoded == encodingBase64 {
			b64Count++
		}
	}

	if rawCount > 1 {
		t.Errorf("expected at most 1 raw match, got %d", rawCount)
	}
	if b64Count > 1 {
		t.Errorf("expected at most 1 base64 match, got %d", b64Count)
	}
}

func TestScanTextForDLP_MultiplePatterns(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	anthropic := testAnthropicPrefix + strings.Repeat("j", 25)
	aws := "AKIA" + strings.Repeat("C", 16)
	github := "ghp_" + strings.Repeat("D", 40)
	text := anthropic + " " + aws + " " + github

	result := s.ScanTextForDLP(context.Background(), text)
	if result.Clean {
		t.Fatal("expected matches, got clean")
	}

	patternNames := make(map[string]bool)
	for _, m := range result.Matches {
		patternNames[m.PatternName] = true
	}

	for _, want := range []string{testAnthropicName, "AWS Access ID", "GitHub Token"} {
		if !patternNames[want] {
			t.Errorf("expected pattern %q in matches, got: %v", want, result.Matches)
		}
	}
}

func TestDeduplicateMatches(t *testing.T) {
	tests := []struct {
		name  string
		input []TextDLPMatch
		want  int
	}{
		{
			name:  "nil input",
			input: nil,
			want:  0,
		},
		{
			name: "single match",
			input: []TextDLPMatch{
				{PatternName: "test", Encoded: ""},
			},
			want: 1,
		},
		{
			name: "duplicate same pattern and encoding",
			input: []TextDLPMatch{
				{PatternName: "test", Encoded: ""},
				{PatternName: "test", Encoded: ""},
			},
			want: 1,
		},
		{
			name: "same pattern different encoding",
			input: []TextDLPMatch{
				{PatternName: "test", Encoded: ""},
				{PatternName: "test", Encoded: "base64"},
			},
			want: 2,
		},
		{
			name: "different patterns same encoding",
			input: []TextDLPMatch{
				{PatternName: "pattern-a", Encoded: ""},
				{PatternName: "pattern-b", Encoded: ""},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateMatches(tt.input)
			if len(got) != tt.want {
				t.Errorf("deduplicateMatches returned %d matches, want %d", len(got), tt.want)
			}
		})
	}
}

func TestMatchDLPPatterns(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Test that matchDLPPatterns tags encoding correctly
	secret := testAnthropicPrefix + strings.Repeat("k", 25)
	matches := s.matchDLPPatterns(secret, "hex")

	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}

	for _, m := range matches {
		if m.Encoded != "hex" {
			t.Errorf("expected Encoded=%q, got %q", "hex", m.Encoded)
		}
	}
}

func TestCheckSecretsInText_NoEnvSecrets(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	matches := s.checkSecretsInText(nil, "some text with anything", "Environment Variable Leak", "env")
	if len(matches) != 0 {
		t.Errorf("expected no matches with empty envSecrets, got %d", len(matches))
	}
}

func TestCheckSecretsInText_HexEncodedEnvSecret(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := "SuperSecretTestValue99"
	hexEncoded := hex.EncodeToString([]byte(secret))
	matches := s.checkSecretsInText([]string{secret}, "data: "+hexEncoded, "Environment Variable Leak", "env")
	if len(matches) == 0 {
		t.Error("expected hex-encoded env leak to be caught")
	}
}

func TestCheckSecretsInText_Base32EncodedEnvSecret(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := "Base32TestSecretValue!"
	b32Encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	matches := s.checkSecretsInText([]string{secret}, "data: "+b32Encoded, "Environment Variable Leak", "env")
	if len(matches) == 0 {
		t.Error("expected base32-encoded env leak to be caught")
	}
}

func TestCheckSecretsInText_URLSafeBase64EnvSecret(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	// Use a secret that produces different URL-safe vs standard base64
	secret := "Secret?With>Special+Chars"
	urlEncoded := base64.URLEncoding.EncodeToString([]byte(secret))
	stdEncoded := base64.StdEncoding.EncodeToString([]byte(secret))

	// Verify they differ (otherwise this test isn't testing the URL-safe path)
	if urlEncoded == stdEncoded {
		t.Skip("URL-safe and standard base64 encodings are the same for this secret")
	}

	matches := s.checkSecretsInText([]string{secret}, "data: "+urlEncoded, "Environment Variable Leak", "env")
	if len(matches) == 0 {
		t.Error("expected URL-safe base64-encoded env leak to be caught")
	}
}

func TestCheckSecretsInText_DelimiterHexEnvSecret(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := "SuperSecretTestValue99"
	contiguousHex := hex.EncodeToString([]byte(secret))

	tests := []struct {
		name string
		text string
	}{
		{"colon-separated", "data: " + hexByteSep(contiguousHex, ":")},
		{"space-separated", "data: " + hexByteSep(contiguousHex, " ")},
		{"hyphen-separated", "data: " + hexByteSep(contiguousHex, "-")},
		{"comma-separated", "data: " + hexByteSep(contiguousHex, ",")},
		{"backslash-x notation", "data: " + hexBytePrefix(contiguousHex, `\x`)},
		{"0x per-byte notation", "data: " + hexBytePrefix(contiguousHex, "0x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := s.checkSecretsInText([]string{secret}, tt.text, "Environment Variable Leak", "env")
			if len(matches) == 0 {
				t.Errorf("expected %s hex-encoded env leak to be caught", tt.name)
			}
		})
	}
}

func TestScanTextForDLP_DoubleURLEncoding(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Double URL-encode an AWS key: AKIA... → %41%4B%49%41... → %2541%254B...
	// Single QueryUnescape would only decode one layer, missing the key.
	aws := "AKIA" + strings.Repeat("Z", 16)
	singleEncoded := url.QueryEscape(aws)
	doubleEncoded := url.QueryEscape(singleEncoded)

	result := s.ScanTextForDLP(context.Background(), doubleEncoded)
	if result.Clean {
		t.Fatal("expected DLP to catch double-URL-encoded AWS key via IterativeDecode")
	}
	found := false
	for _, m := range result.Matches {
		if m.PatternName == "AWS Access ID" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AWS Access ID pattern match, got: %v", result.Matches)
	}
}

func TestScanTextForDLP_StackedDecodeFixpoint(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	for _, layers := range []int{4, 5} {
		t.Run(strconv.Itoa(layers)+"_layers", func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), "token="+stackedDLPFixture(secret, layers))
			if result.Clean {
				t.Fatalf("expected DLP to catch %d-layer encoded AWS key", layers)
			}
		})
	}
}

// TestScanTextForDLP_StackedDecodePastFormerByteCeiling proves the bounded
// fixpoint decoder no longer skips a stacked-encoded secret padded past the old
// per-candidate byte ceiling. An attacker who could inflate the encoded payload
// (e.g. inside a multi-MB request body) past a low ceiling would otherwise evade
// recursive decode entirely. The total-bytes budget keeps work bounded while
// still decoding large candidates.
func TestScanTextForDLP_StackedDecodePastFormerByteCeiling(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	// Pad so the outer encoded form is well over the former 64 KiB per-candidate
	// ceiling but well under the total-bytes budget.
	padded := strings.Repeat("A", 100*1024) + secret
	encoded := stackedDLPFixture(padded, 2) // hex(base64(padded)) ~ >64 KiB
	if len(encoded) <= 64*1024 {
		t.Fatalf("fixture too small (%d bytes); test would not exercise the former ceiling", len(encoded))
	}

	result := s.ScanTextForDLP(context.Background(), "token="+encoded)
	if result.Clean {
		t.Fatalf("expected DLP to catch a stacked AWS key padded past the former 64 KiB ceiling (encoded=%d bytes)", len(encoded))
	}
}

func TestScanTextForDLP_URLEncodedNullByte(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// URL-encoded null byte %00 in the middle of a secret. After IterativeDecode,
	// the null byte should be stripped by matchDLPPatterns and the key detected.
	key := "sk-ant-%00" + strings.Repeat("a", 25)
	result := s.ScanTextForDLP(context.Background(), key)
	if result.Clean {
		t.Fatal("expected DLP to catch key with URL-encoded null byte")
	}
	found := false
	for _, m := range result.Matches {
		if strings.Contains(m.PatternName, "Anthropic") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Anthropic API Key match, got: %v", result.Matches)
	}
}

func TestScanTextForDLP_DNSSubdomainExfil(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name      string
		text      string
		wantClean bool
		wantEnc   string
	}{
		{
			name:      "secret split across subdomains",
			text:      "https://sk-ant-api03.AABBCCDD.EEFFGGHH.IIJJKKLL.evil.com/",
			wantClean: false,
			wantEnc:   "subdomain",
		},
		{
			name:      "long key in single subdomain - caught by raw match",
			text:      "https://" + testAnthropicPrefix + strings.Repeat("a", 25) + ".evil.com/",
			wantClean: false,
		},
		{
			name:      "AWS key split across subdomains",
			text:      "https://AKIA.IOSFODNN.7EXAMPLE1.evil.com/",
			wantClean: false,
			wantEnc:   "subdomain",
		},
		{
			name:      "normal domain with dots - no false positive",
			text:      "https://www.google.com/search?q=hello",
			wantClean: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), tt.text)
			if result.Clean != tt.wantClean {
				t.Errorf("Clean = %v, want %v (matches: %v)", result.Clean, tt.wantClean, result.Matches)
			}
			if tt.wantEnc != "" {
				found := false
				for _, m := range result.Matches {
					if m.Encoded == tt.wantEnc {
						found = true
					}
				}
				if !found {
					t.Errorf("expected encoding=%q in matches, got: %v", tt.wantEnc, result.Matches)
				}
			}
		})
	}
}

func TestScanTextForDLP_ControlCharBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build key at runtime to avoid gitleaks
	prefix := testAnthropicPrefix
	suffix := strings.Repeat("a", 25)

	tests := []struct {
		name    string
		ctrlStr string
	}{
		{"null_byte", "\x00"},
		{"backspace", "\x08"},
		{"tab", "\x09"},
		{"newline", "\x0a"},
		{"carriage_return", "\x0d"},
		{"vertical_tab", "\x0b"},
		{"escape", "\x1b"},
		{"DEL", "\x7f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := prefix + tt.ctrlStr + suffix
			result := s.ScanTextForDLP(context.Background(), text)
			if result.Clean {
				t.Errorf("expected DLP to catch key with %s control char", tt.name)
			}
		})
	}
}

func TestScanTextForDLP_MultipleControlChars(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Multiple control chars scattered through an AWS key
	key := "AKIA" + "\x08" + "IOSFODNN" + "\x09" + "7EXAMPLE"
	result := s.ScanTextForDLP(context.Background(), key)
	if result.Clean {
		t.Error("expected DLP to catch AWS key with multiple control chars")
	}
}

// --- DLP confusable/combining mark bypass tests ---

func TestScanTextForDLP_ConfusableBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name        string
		text        string
		wantPattern string
	}{
		{
			name:        "Cyrillic_a_in_Anthropic_key",
			text:        "sk-\u0430nt-" + strings.Repeat("a", 25), // Cyrillic а U+0430
			wantPattern: testAnthropicName,
		},
		{
			name:        "Armenian_a_in_Anthropic_key",
			text:        "sk-\u0561nt-" + strings.Repeat("a", 25), // Armenian ա U+0561 → 'a'
			wantPattern: testAnthropicName,
		},
		{
			name:        "Greek_A_in_AWS_key",
			text:        "\u0391KIA" + strings.Repeat("B", 16), // Greek Α U+0391 for A
			wantPattern: "AWS Access ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), tt.text)
			if result.Clean {
				t.Errorf("confusable bypass not caught: %s", tt.name)
			}
			found := false
			for _, m := range result.Matches {
				if strings.Contains(m.PatternName, tt.wantPattern) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected %s match, got: %v", tt.wantPattern, result.Matches)
			}
		})
	}
}

// TestScanTextForDLP_ExoticWhitespaceBypass verifies that non-ASCII
// whitespace splitters embedded in a secret do not prevent DLP detection.
// This is the scanner-level regression for the StripExoticWhitespace pass
// added to the ForDLP normalization pipeline.
func TestScanTextForDLP_ExoticWhitespaceBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	suffix := strings.Repeat("a", 25)

	tests := []struct {
		name  string
		split string
	}{
		{"NBSP", "\u00A0"},
		{"ideographic_space", "\u3000"},
		{"Ogham_space", "\u1680"},
		{"Mongolian_vowel_separator", "\u180E"},
		{"en_space", "\u2002"},
		{"em_space", "\u2003"},
		{"thin_space", "\u2009"},
		{"narrow_no_break", "\u202F"},
		{"medium_math_space", "\u205F"},
		{"line_separator", "\u2028"},
		{"paragraph_separator", "\u2029"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Insert the splitter in the middle of an Anthropic-style key.
			text := "sk-ant-" + tt.split + suffix
			result := s.ScanTextForDLP(context.Background(), text)
			if result.Clean {
				t.Errorf("exotic whitespace bypass not caught (%s): %q", tt.name, text)
			}
		})
	}
}

// TestScanTextForDLP_StackedStegoVectors layers multiple evasion techniques
// on top of each other and verifies the DLP pipeline still catches the
// secret. Represents a realistic worst-case attacker combining everything
// they know against the scanner.
func TestScanTextForDLP_StackedStegoVectors(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	suffix := strings.Repeat("a", 25)
	// sk- + Cyrillic a (U+0430) + NBSP + nt- + zero-width space + suffix.
	// Three layers: confusable homoglyph + exotic whitespace + invisible.
	text := "sk-\u0430\u00A0nt-\u200B" + suffix
	result := s.ScanTextForDLP(context.Background(), text)
	if result.Clean {
		t.Errorf("stacked stego vector bypass not caught: %q", text)
	}
}

func TestScanTextForDLP_CombiningMarkBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Combining long stroke overlay (U+0337) inserted into key prefix
	key := "sk-a\u0337nt-" + strings.Repeat("a", 25)
	result := s.ScanTextForDLP(context.Background(), key)
	if result.Clean {
		t.Error("expected DLP to catch key with combining mark in prefix")
	}
}

func TestScanTextForDLP_LatinSmallCapBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Latin small cap letters in GitHub token prefix
	key := "ghp_" + strings.Repeat("D", 40)
	// Replace 'g' with Latin Small Capital G (not in confusable map, but 'ghp_' starts with lowercase g)
	// Test combining mark + confusable in same key
	keyWithMark := "gh\u0307p_" + strings.Repeat("D", 40)
	result := s.ScanTextForDLP(context.Background(), keyWithMark)
	if result.Clean {
		t.Error("expected DLP to catch GitHub token with combining mark")
	}

	// Verify clean key still matches
	result = s.ScanTextForDLP(context.Background(), key)
	if result.Clean {
		t.Error("expected DLP to catch clean GitHub token")
	}
}

// --- DLP evasion fixes (short key, credential-in-URL) ---

func TestScanTextForDLP_ShortAnthropicKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	key := testAnthropicPrefix + strings.Repeat("A", 10)
	result := s.ScanTextForDLP(context.Background(), key)
	if result.Clean {
		t.Error("expected text DLP to catch short Anthropic key prefix")
	}
}

func TestScanTextForDLP_ShortSvcAcctKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	key := "sk-svcacct-" + strings.Repeat("A", 10)
	result := s.ScanTextForDLP(context.Background(), key)
	if result.Clean {
		t.Error("expected text DLP to catch short service-account key prefix")
	}
}

func TestScanTextForDLP_CredentialInURL(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP(context.Background(), "connect to postgres://user:pass@host/db?password=supersecret123")
	if result.Clean {
		t.Error("expected text DLP to catch password= in connection string")
	}
}

func TestScanTextForDLP_CredentialInURL_ShortValueClean(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP(context.Background(), "set token=yes in the config")
	if !result.Clean {
		t.Errorf("false positive on short credential value in text: %v", result.Matches)
	}
}

// TestScanTextForDLP_CredentialInURL_NoFPOnGoAssignment documents the
// scope of the Credential in URL rule: it only fires when the credential
// key is preceded by a URL query delimiter ([?&;]), so Go source files
// that legitimately assign to credential-named struct fields do not
// false-positive. Without this, every pipelock file that handles a
// bearer token (session admin, CLI resolver, config loader) would need
// a per-file exclude-paths entry in the GitHub Action workflow.
func TestScanTextForDLP_CredentialInURL_NoFPOnGoAssignment(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	goLines := []string{
		`ep.Token = deps.getenv(killswitch.EnvAPIToken)`,
		`user.Password = hashedValue`,
		`cfg.APIKey = loadFromFile(path)`,
		`session.Secret = base64Encode(raw)`,
		`req.APIToken = "placeholder"`,
		`h.apiToken = opts.APIToken`,
	}
	for _, line := range goLines {
		t.Run(line, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), line)
			if !result.Clean {
				t.Errorf("false positive on Go assignment %q: %+v", line, result.Matches)
			}
		})
	}
}

// TestScanTextForDLP_CredentialInURL_StillCatchesQueryDelimiter locks in
// the positive side of the rule: credentials in URL query strings are
// still caught. Covers the ?, &, and ; delimiters for parity with how
// browsers, form encoders, and connection strings carry parameters.
// Fake-secret values are concatenated from split literals at runtime so
// GitGuardian's hardcoded-password heuristic doesn't flag the fixtures
// themselves as a leak (see also CLAUDE.md G101 guidance for gosec).
func TestScanTextForDLP_CredentialInURL_StillCatchesQueryDelimiter(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	longVal := "super" + "secret" + "123"
	tokenVal := "abc" + "def" + "123456"
	dbPass := "hunter" + "x" + "abcd"
	apiVal := "real" + "secret" + "123"

	positives := []string{
		"https://example.com/api?password=" + longVal,
		"https://example.com/api?x=1&token=" + tokenVal,
		"jdbc:mysql://host/db;password=" + dbPass,
		"POSTed body: username=bob&apikey=" + apiVal,
	}
	for _, s2 := range positives {
		t.Run(s2, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), s2)
			if result.Clean {
				t.Errorf("expected catch on %q, got clean", s2)
			}
		})
	}
}

// TestScanTextForDLP_CredentialInURL_CatchesBodyStart asserts the
// post-widening coverage for the "Credential in URL" DLP pattern. The
// regex alternation `(?m)(?:^|[?&;])` catches credentials at the very
// start of the scanned text (position 0, via ^) in addition to the
// original URL-query-delimiter path ([?&;]). Common sources: env-var
// dumps, log lines, cURL -d bodies where the first field has no
// leading & or ?.
//
// Note on whitespace: ForDLP strips ASCII control chars (including \n)
// before the regex runs, so embedded newlines collapse adjacent text.
// The positive cases below are limited to inputs that stay caught
// after that normalization. The mid-text-after-random-prose case is
// a known FN that this PR deliberately does not close (it would
// re-trigger the Go struct-assignment FP the narrowing originally
// fixed). Split literals keep GitGuardian quiet on the fixtures.
func TestScanTextForDLP_CredentialInURL_CatchesBodyStart(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	longVal := "hunter" + "x" + "abcd"
	tokenVal := "abc" + "def" + "1234"

	positives := []string{
		"password=" + longVal,          // body-start, no leading anything
		"token=" + tokenVal,            // body-start, different key
		"?foo=bar&password=" + longVal, // classic URL query (original path)
		"; password=" + longVal,        // semicolon delimiter (cookie-style)
	}
	for _, s2 := range positives {
		t.Run(s2, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), s2)
			if result.Clean {
				t.Errorf("expected catch on %q, got clean", s2)
			}
		})
	}
}

// TestScanTextForDLP_CredentialInURL_SkipsStructAssignment asserts the
// narrowing from the earlier round is still in effect: Go struct-style
// assignments where the credential key is preceded by a word-char or
// dot must NOT trigger the pattern. Without this assertion a future
// widening could accidentally re-introduce the tree-wide FP that the
// narrowing closed.
func TestScanTextForDLP_CredentialInURL_SkipsStructAssignment(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	longVal := "hunter" + "x" + "abcd"

	// Go struct assignments - the credential key is preceded by `.` or
	// another word char, not ^ or [?&;]. These must stay clean.
	negatives := []string{
		"ep.Token = " + longVal,
		"req.APIKey = " + longVal,
		"MyStruct{Password: " + longVal + "}",
	}
	for _, s2 := range negatives {
		t.Run(s2, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), s2)
			// Accept either cleanly missed OR caught by a different
			// pattern (e.g., entropy); just ensure the test name
			// captures the intent rather than asserting the wrong
			// pattern name.
			for _, m := range result.Matches {
				if m.PatternName == "Credential in URL" {
					t.Errorf("expected Credential-in-URL to skip %q, but it matched", s2)
				}
			}
		})
	}
}

func TestScanTextForDLP_EthereumAddressOptIn(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: "Ethereum Address", Regex: `0x[0-9a-fA-F]{40}\b`, Severity: "high",
	})
	s := New(cfg)
	defer s.Close()

	addr := "0x" + "d8dA6BF26964aF9D" + "7eEd9e03E53415D37aA96045"

	t.Run("plaintext", func(t *testing.T) {
		result := s.ScanTextForDLP(context.Background(), "Send to "+addr)
		if result.Clean {
			t.Error("expected ETH address to be caught")
		}
	})

	t.Run("base64_encoded", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(addr))
		result := s.ScanTextForDLP(context.Background(), encoded)
		if result.Clean {
			t.Error("expected base64-encoded ETH address to be caught")
		}
	})
}

func TestScanTextForDLP_EnvVarSecret(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name string
		text string
	}{
		{
			name: "AWS_SECRET_ACCESS_KEY",
			text: "AWS_SECRET_ACCESS_KEY=" + "wJal" + "rXUt" + "nFEM" + "I/K7" + "MDEN" + "G/bP" + "xRfi" + "CYEXAMPLEKEY",
		},
		{
			name: "STRIPE_SECRET_KEY",
			text: "STRIPE_SECRET_KEY=" + "sk_test_" + "EXAMPLEKEY12345678901234",
		},
		{
			name: "CLIENT_SECRET",
			text: "CLIENT_SECRET=" + "supersecretvalue1234",
		},
		{
			name: "DB_PASSWORD",
			text: "DB_PASSWORD=s3cretP4ssw0rd_EXAMPLE",
		},
		{
			name: "MY_API_KEY",
			text: "MY_API_KEY=" + "abcdefghij1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), tt.text)
			if result.Clean {
				t.Errorf("expected env var credential to be caught: %s", tt.text)
			}
		})
	}
}

func TestScanTextForDLP_EnvVarSecret_ShortValueClean(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Short values (under 8 chars) should not trigger.
	result := s.ScanTextForDLP(context.Background(), "MY_SECRET=true")
	if !result.Clean {
		t.Errorf("false positive on short env var value: %v", result.Matches)
	}
}

func TestScanTextForDLP_EnvVarSecret_BenignUppercaseClean(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Uppercase names containing keywords as substrings must not FP.
	benign := []string{
		"DB_PASSWORD_POLICY=must_be_strong",
		"ACCESS_TOKEN_EXPIRY=3600secs",
		"APP_TOKEN_BUCKET=abcdefghij",
		"API_KEY_LENGTH=1234567890",
		"SECRET_ROTATION_DAYS=365days_minimum",
	}
	for _, text := range benign {
		t.Run(text, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), text)
			if !result.Clean {
				t.Errorf("false positive on benign env var: %v", result.Matches)
			}
		})
	}
}

// --- File Secret Text DLP Tests ---

func TestScanTextForDLP_FileSecretRawMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecret" + "Value1234"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP(context.Background(), "Here is the secret: "+secret)
	if result.Clean {
		t.Error("expected file secret to be detected in text")
	}
	found := false
	for _, m := range result.Matches {
		if m.PatternName == "Known Secret Leak" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Known Secret Leak' pattern, got %v", result.Matches)
	}
}

func TestScanTextForDLP_FileSecretBase64Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecret" + "Value1234"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	result := s.ScanTextForDLP(context.Background(), encoded)
	if result.Clean {
		t.Error("expected base64-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretHexMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecret" + "Value1234"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := hex.EncodeToString([]byte(secret))
	result := s.ScanTextForDLP(context.Background(), encoded)
	if result.Clean {
		t.Error("expected hex-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretBase32Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecret" + "Value1234"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	result := s.ScanTextForDLP(context.Background(), encoded)
	if result.Clean {
		t.Error("expected base32-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretDistinctFromEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	fileSecret := "FileOnlySecretValue1"
	if err := os.WriteFile(path, []byte(fileSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	// Also inject an env secret
	s.envSecrets = []string{"EnvOnlySecretValue11"}

	// Text contains file secret - should match "Known Secret Leak"
	result := s.ScanTextForDLP(context.Background(), fileSecret)
	if result.Clean {
		t.Fatal("expected detection")
	}
	for _, m := range result.Matches {
		if m.PatternName == "Environment Variable Leak" {
			t.Error("file secret should NOT produce 'Environment Variable Leak' pattern")
		}
	}
}

func TestScanTextForDLP_NoFileSecrets_Clean(t *testing.T) {
	cfg := testConfig()
	// No secrets_file configured
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP(context.Background(), "This text contains no secrets at all.")
	if !result.Clean {
		t.Errorf("expected clean result with no file secrets, got %v", result.Matches)
	}
}

func TestScanTextForDLP_FileSecretPresent_NoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecret" + "Value1234"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	// Text that doesn't contain the secret in any form
	result := s.ScanTextForDLP(context.Background(), "totally innocent text with no matching content")
	if !result.Clean {
		t.Errorf("expected clean result when text doesn't match loaded file secret, got %v", result.Matches)
	}
}

func TestScanTextForDLP_FileSecretEncodedFieldValues(t *testing.T) {
	secret := "MyFileSecret" + "Value1234"

	tests := []struct {
		name    string
		text    string
		wantEnc string
	}{
		{"raw", secret, ""},
		{"base64", base64.StdEncoding.EncodeToString([]byte(secret)), "base64"},
		{"hex", hex.EncodeToString([]byte(secret)), "hex"},
		{"base32", base32.StdEncoding.EncodeToString([]byte(secret)), "base32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secrets.txt")
			if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			cfg := testConfig()
			cfg.DLP.SecretsFile = path
			s := New(cfg)
			defer s.Close()

			result := s.ScanTextForDLP(context.Background(), tt.text)
			if result.Clean {
				t.Fatal("expected detection")
			}

			var found bool
			for _, m := range result.Matches {
				if m.PatternName == "Known Secret Leak" {
					found = true
					if m.Encoded != tt.wantEnc {
						t.Errorf("Encoded = %q, want %q", m.Encoded, tt.wantEnc)
					}
				}
			}
			if !found {
				t.Error("expected 'Known Secret Leak' match")
			}
		})
	}
}

func TestScanTextForDLP_FileSecretURLSafeBase64Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// 28 bytes with ~ at position 3 → produces "+" in standard base64,
	// ensuring URL-safe encoding (+ → -) differs from standard.
	secret := "ab~test-value" + "-for-28-byte-wk"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encodedURL := base64.URLEncoding.EncodeToString([]byte(secret))
	encodedStd := base64.StdEncoding.EncodeToString([]byte(secret))
	if encodedURL == encodedStd {
		t.Skip("URL-safe same as standard — pick different secret")
	}

	result := s.ScanTextForDLP(context.Background(), encodedURL)
	if result.Clean {
		t.Error("expected URL-safe base64-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretUnpaddedBase64URLMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "ab~test-value" + "-for-28-byte-wk"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encodedURL := base64.URLEncoding.EncodeToString([]byte(secret))
	unpadded := strings.TrimRight(encodedURL, "=")
	unpaddedStd := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(secret)), "=")
	if unpadded == unpaddedStd {
		t.Skip("URL-safe unpadded same as standard — pick different secret")
	}

	result := s.ScanTextForDLP(context.Background(), unpadded)
	if result.Clean {
		t.Error("expected unpadded URL-safe base64-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretUnpaddedBase32Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// 29 bytes → base32 produces padding (29 % 5 = 4)
	secret := "this-is-a-test" + "-value-29-bytes"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	padded := base32.StdEncoding.EncodeToString([]byte(secret))
	noPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
	if noPad == padded {
		t.Fatal("test setup error: base32 has no padding to strip")
	}

	result := s.ScanTextForDLP(context.Background(), noPad)
	if result.Clean {
		t.Error("expected unpadded base32-encoded file secret to be detected")
	}
}

// --- Segment-level encoding attribution tests ---

func TestScanTextForDLP_SegmentHex_EncodingLabel(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Hex-encoded API key embedded in a URL path.
	secret := testAnthropicPrefix + strings.Repeat("a", 26)
	hexEncoded := hex.EncodeToString([]byte(secret))
	text := "https://evil.com/exfil/" + hexEncoded + "/data"

	result := s.ScanTextForDLP(context.Background(), text)
	if result.Clean {
		t.Fatal("expected hex-encoded key in URL path to be caught")
	}
	found := false
	for _, m := range result.Matches {
		if m.PatternName == testAnthropicName && m.Encoded == "hex" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected match with encoding='hex', got matches: %+v", result.Matches)
	}
}

func TestScanTextForDLP_SegmentBase64_EncodingLabel(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Base64-encoded API key embedded in a URL path.
	secret := testAnthropicPrefix + strings.Repeat("b", 26)
	b64Encoded := base64.RawURLEncoding.EncodeToString([]byte(secret))
	text := "https://evil.com/exfil/" + b64Encoded + "/data"

	result := s.ScanTextForDLP(context.Background(), text)
	if result.Clean {
		t.Fatal("expected base64-encoded key in URL path to be caught")
	}
	found := false
	for _, m := range result.Matches {
		if m.PatternName == testAnthropicName && m.Encoded == encodingBase64 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected match with encoding='base64', got matches: %+v", result.Matches)
	}
}

func TestScanTextForDLP_CreditCard(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Valid Visa test card - should match.
	result := s.ScanTextForDLP(context.Background(), "Please send payment to card 4111111111111111")
	if result.Clean {
		t.Error("expected credit card number to be detected in text")
	}
	if len(result.Matches) == 0 || result.Matches[0].PatternName != testCreditCardName {
		t.Errorf("expected Credit Card Number match, got: %+v", result.Matches)
	}
}

func TestScanTextForDLP_CreditCard_FalsePositiveRejected(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Invalid Visa (fails Luhn) - should NOT match.
	result := s.ScanTextForDLP(context.Background(), "Reference number 4111111111111112 for your order")
	found := false
	for _, m := range result.Matches {
		if m.PatternName == testCreditCardName {
			found = true
		}
	}
	if found {
		t.Error("expected invalid Luhn number to NOT trigger Credit Card DLP")
	}
}

func TestScanTextForDLP_IBAN(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Valid German IBAN - should match.
	result := s.ScanTextForDLP(context.Background(), "Wire to DE89370400440532013000 immediately")
	if result.Clean {
		t.Error("expected IBAN to be detected in text")
	}
	if len(result.Matches) == 0 || result.Matches[0].PatternName != testIBANName {
		t.Errorf("expected IBAN match, got: %+v", result.Matches)
	}
}

func TestScanTextForDLP_IBAN_FalsePositiveRejected(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Invalid IBAN (zeroed check digits, fails mod-97) - should NOT match.
	result := s.ScanTextForDLP(context.Background(), "Account ref DE00370400440532013000 in our system")
	found := false
	for _, m := range result.Matches {
		if m.PatternName == testIBANName {
			found = true
		}
	}
	if found {
		t.Error("expected invalid IBAN (bad mod-97) to NOT trigger IBAN DLP")
	}
}

func TestScanTextForDLP_CreditCard_DecoyBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Regression: a Luhn-failing decoy before a valid card must not suppress
	// detection. The scanner must check all regex matches, not just the first.
	result := s.ScanTextForDLP(context.Background(),
		"First card 4111111111111112 and real card 4111111111111111")
	if result.Clean {
		t.Error("expected valid card to be detected after checksum-failing decoy")
	}
}

func TestScanTextForDLP_IBAN_DecoyBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Regression: a mod-97-failing decoy before a valid IBAN must not suppress.
	result := s.ScanTextForDLP(context.Background(),
		"Bad ref DE00370400440532013000 real ref DE89370400440532013000")
	found := false
	for _, m := range result.Matches {
		if m.PatternName == testIBANName {
			found = true
		}
	}
	if !found {
		t.Error("expected valid IBAN to be detected after mod-97-failing decoy")
	}
}

func TestScanTextForDLP_IBAN_FakeCountryCode(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// ZZ is not a valid IBAN country code - should NOT match even if mod-97 passes.
	result := s.ScanTextForDLP(context.Background(), "Wire to ZZ8212345678901234567890")
	found := false
	for _, m := range result.Matches {
		if m.PatternName == testIBANName {
			found = true
		}
	}
	if found {
		t.Error("expected fake country code ZZ to NOT trigger IBAN DLP")
	}
}

func TestScanTextForDLP_CreditCard_WithSeparators(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Visa with dashes - should match.
	result := s.ScanTextForDLP(context.Background(), "Card: 4111-1111-1111-1111")
	if result.Clean {
		t.Error("expected dash-separated credit card to be detected")
	}
}

func TestScanTextForDLP_CreditCard_Amex465Format(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Amex 4-6-5 display format with spaces - should match.
	result := s.ScanTextForDLP(context.Background(), "Pay with 3782 822463 10005")
	if result.Clean {
		t.Error("expected Amex 4-6-5 space format to be detected in text DLP")
	}

	// Amex 4-6-5 display format with dashes - should match.
	result2 := s.ScanTextForDLP(context.Background(), "Pay with 3782-822463-10005")
	if result2.Clean {
		t.Error("expected Amex 4-6-5 dash format to be detected in text DLP")
	}
}

func TestScanTextForDLP_CreditCard_WithSpaces(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Visa with spaces - should match (regex allows space separators).
	result := s.ScanTextForDLP(context.Background(), "Card: 4111 1111 1111 1111")
	if result.Clean {
		t.Error("expected space-separated credit card to be detected")
	}
}

func TestScanTextForDLP_IBAN_FormattedWithSpaces_KnownLimitation(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Space-separated IBANs (display format) are NOT detected by the text DLP
	// path because the regex requires contiguous alphanumeric BBAN characters.
	// The validator handles spaces, but the regex never matches to reach it.
	// This is a known tradeoff: adding optional spaces to the IBAN regex would
	// make it much broader and the pre-filter less effective. URL-path scanning
	// strips spaces before matching, so URL-based exfiltration IS caught.
	result := s.ScanTextForDLP(context.Background(), "Wire to GB29 NWBK 6016 1331 9268 19 immediately")
	if !result.Clean {
		t.Error("space-separated IBANs are a known limitation in text DLP — if this passes, the limitation was fixed")
	}

	// Contiguous IBAN IS detected.
	result2 := s.ScanTextForDLP(context.Background(), "Wire to GB29NWBK60161331926819 immediately")
	if result2.Clean {
		t.Error("contiguous IBAN should be detected")
	}
}

func TestScanTextForDLP_ABA_OptIn(t *testing.T) {
	// ABA is NOT in default presets. Test that adding it via config works.
	cfg := testConfig()
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:      testABARoutingName,
		Regex:     `\b\d{9}\b`,
		Severity:  "low",
		Validator: config.ValidatorABA,
	})
	s := New(cfg)
	defer s.Close()

	// Valid ABA (JPMorgan Chase) - should match.
	result := s.ScanTextForDLP(context.Background(), "Routing: 021000021")
	found := false
	for _, m := range result.Matches {
		if m.PatternName == testABARoutingName {
			found = true
		}
	}
	if !found {
		t.Error("expected valid ABA routing number to be detected")
	}

	// Invalid ABA (bad checksum + bad prefix) - should NOT match.
	result2 := s.ScanTextForDLP(context.Background(), "ID number 999999999")
	found2 := false
	for _, m := range result2.Matches {
		if m.PatternName == testABARoutingName {
			found2 = true
		}
	}
	if found2 {
		t.Error("expected invalid ABA to NOT trigger DLP")
	}
}

func TestScanTextForDLP_ValidatorSurvivesReload(t *testing.T) {
	// Verify that creating a new Scanner from the same config correctly
	// wires validators. This simulates config hot-reload where the old
	// scanner is replaced by a new one built from the reloaded config.
	cfg := testConfig()

	// First scanner - verify credit card detection works.
	s1 := New(cfg)
	result1 := s1.ScanTextForDLP(context.Background(), "Pay with 4111111111111111")
	s1.Close()
	if result1.Clean {
		t.Fatal("first scanner should detect credit card")
	}

	// Second scanner from same config - simulates reload.
	s2 := New(cfg)
	defer s2.Close()
	result2 := s2.ScanTextForDLP(context.Background(), "Pay with 4111111111111111")
	if result2.Clean {
		t.Error("second scanner (reload) should still detect credit card")
	}

	// Also verify false positive rejection survives reload.
	result3 := s2.ScanTextForDLP(context.Background(), "Ref 4111111111111112")
	found := false
	for _, m := range result3.Matches {
		if m.PatternName == testCreditCardName {
			found = true
		}
	}
	if found {
		t.Error("false positive rejection should survive reload")
	}
}

func TestScanTextForDLP_BundleProvenance(t *testing.T) {
	const (
		bundleName    = "acme-dlp-extras"
		bundleVersion = "2026.03.1"
	)

	cfg := testConfig()
	// Add a DLP pattern with bundle provenance.
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:          "Custom Bundle Secret",
		Regex:         `custsecret_[A-Za-z0-9]{20,}`,
		Severity:      "high",
		Bundle:        bundleName,
		BundleVersion: bundleVersion,
	})
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP(context.Background(), "leak: custsecret_"+strings.Repeat("x", 25))
	if result.Clean {
		t.Fatal("expected DLP match for custom bundle pattern")
	}

	var found bool
	for _, m := range result.Matches {
		if m.PatternName == "Custom Bundle Secret" {
			found = true
			if m.Bundle != bundleName {
				t.Errorf("Bundle = %q, want %q", m.Bundle, bundleName)
			}
			if m.BundleVersion != bundleVersion {
				t.Errorf("BundleVersion = %q, want %q", m.BundleVersion, bundleVersion)
			}
		}
	}
	if !found {
		t.Errorf("expected 'Custom Bundle Secret' match, got: %v", result.Matches)
	}
}

func TestScanTextForDLP_BuiltinPatternNoBundleProvenance(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Built-in Anthropic key pattern should have empty bundle fields.
	result := s.ScanTextForDLP(context.Background(), testAnthropicPrefix+strings.Repeat("a", 25))
	if result.Clean {
		t.Fatal("expected DLP match")
	}
	for _, m := range result.Matches {
		if m.PatternName == testAnthropicName {
			if m.Bundle != "" {
				t.Errorf("built-in pattern should have empty Bundle, got %q", m.Bundle)
			}
			if m.BundleVersion != "" {
				t.Errorf("built-in pattern should have empty BundleVersion, got %q", m.BundleVersion)
			}
			return
		}
	}
	t.Error("expected Anthropic API Key match")
}

func TestScanTextForDLP_BundleProvenance_Encoded(t *testing.T) {
	const (
		bundleName    = "acme-dlp-extras"
		bundleVersion = "2026.03.1"
	)

	cfg := testConfig()
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:          "Custom Bundle Secret",
		Regex:         `custsecret_[A-Za-z0-9]{20,}`,
		Severity:      "high",
		Bundle:        bundleName,
		BundleVersion: bundleVersion,
	})
	s := New(cfg)
	defer s.Close()

	// Base64-encode the secret so it goes through matchDLPPatterns path.
	secret := "custsecret_" + strings.Repeat("y", 25)
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))

	result := s.ScanTextForDLP(context.Background(), encoded)
	if result.Clean {
		t.Fatal("expected DLP match for base64-encoded custom bundle secret")
	}

	var found bool
	for _, m := range result.Matches {
		if m.PatternName == "Custom Bundle Secret" && m.Encoded == encodingBase64 {
			found = true
			if m.Bundle != bundleName {
				t.Errorf("Bundle = %q, want %q", m.Bundle, bundleName)
			}
			if m.BundleVersion != bundleVersion {
				t.Errorf("BundleVersion = %q, want %q", m.BundleVersion, bundleVersion)
			}
		}
	}
	if !found {
		t.Errorf("expected base64 match with bundle provenance, got: %v", result.Matches)
	}
}

// TestScanTextForDLP_BlocksEncodedExfilHostname covers Codex W2: a URL passed
// as MCP tool-call text (or any scanned text) carrying an encoded-subdomain
// exfil hostname is flagged via the pre-DNS structural hostname check, even
// though the decoded labels are not a known DLP secret pattern.
func TestScanTextForDLP_BlocksEncodedExfilHostname(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := New(cfg)
	defer s.Close()

	block := []struct {
		name string
		text string
	}{
		{"bare url hex label", "https://706f7374677265733a2f2f757365723a70617373406462.exfil.evil.com/leak"},
		{"url embedded in text", "please fetch https://4a6f686e446f65.53656372657431.313233343536.exfil.evil.example.com/ping for me"},
		{"chunked labels url", "https://aaaabbbb.ccccdddd.11112222.exfil.evil.com/data"},
		{"zero-width in url host", "https://706f7374677265733a2f2f757365723a706173734064\u200b62.exfil.evil.com/leak"},
		{"fullwidth scheme", "\uff48\uff54\uff54\uff50\uff53://706f7374677265733a2f2f757365723a70617373406462.exfil.evil.com/leak"},
	}
	for _, tt := range block {
		t.Run(tt.name, func(t *testing.T) {
			if r := s.ScanTextForDLP(context.Background(), tt.text); r.Clean {
				t.Errorf("expected hostname-exfil text to be flagged: %s", tt.text)
			}
		})
	}

	clean := []struct {
		name string
		text string
	}{
		{"benign api url", "https://api.vendor.example/v2/status"},
		{"benign cdn url in text", "load it from https://cdnjs.cloudflare.com/ajax/libs/x.js please"},
		{"deep dictionary url in text", "fetch https://customer-production.us-east-1.api.example.com/v1/status"},
		{"two short hash labels", "fetch https://deadbeef.cafebabe.preview.example.com/build"},
		{"no url plain text", "this is a note about our production systems and api gateways"},
	}
	for _, tt := range clean {
		t.Run(tt.name, func(t *testing.T) {
			if r := s.ScanTextForDLP(context.Background(), tt.text); !r.Clean {
				t.Errorf("expected benign text to be clean: %s (matches: %v)", tt.text, r.Matches)
			}
		})
	}
}

// TestScanTextForDLPInbound_SkipsEnvLeak proves the direction gate: the
// agent's-own-secret exfil check fires outbound (ScanTextForDLP) but is skipped
// inbound (ScanTextForDLPInbound), so a received env value is not a false leak.
func TestScanTextForDLPInbound_SkipsEnvLeak(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil // isolate env-leak: only the env-secret check can fire

	// High-entropy value that matches no regex pattern and is not path-shaped,
	// so the ONLY thing that could flag it is the env-secret exfil check.
	secret := "zQ8xR4kP2" + "mN7wL9vT3jH" // split to satisfy gosec G101
	t.Setenv("PIPELOCK_TEST_INBOUND_SECRET", secret)
	s := New(cfg)

	carrier := "operator note: the value is " + secret + " please proceed"
	ctx := context.Background()

	// Outbound: the exfil check runs and flags the leak.
	if out := s.ScanTextForDLP(ctx, carrier); out.Clean || len(out.Matches) == 0 {
		t.Fatalf("ScanTextForDLP (outbound) should flag the env-secret leak, got Clean=%v matches=%v", out.Clean, out.Matches)
	}

	// Inbound: the exfil check is skipped, so the same received value is clean.
	if in := s.ScanTextForDLPInbound(ctx, carrier); !in.Clean {
		t.Fatalf("ScanTextForDLPInbound must NOT flag a received env value, got matches=%v", in.Matches)
	}
}

// TestScanTextForDLPInbound_StillCatchesGenericDLP proves the gate is narrow:
// only the exfil-class env/file-secret checks are direction-scoped. Generic
// regex pattern DLP still runs inbound (a real secret pattern in a tool result
// is still caught).
func TestScanTextForDLPInbound_StillCatchesGenericDLP(t *testing.T) {
	s := New(testConfig()) // default DLP patterns enabled

	// An Anthropic-key-shaped value (same construction as the existing pattern
	// tests, so it reliably matches a default regex pattern and is not a
	// redacted documentation example). This is a regex DLP pattern, not an
	// exfil-class check, so it must fire on inbound too.
	key := testAnthropicPrefix + strings.Repeat("A", 10)
	carrier := "tool result payload: " + key
	ctx := context.Background()

	if out := s.ScanTextForDLP(ctx, carrier); out.Clean {
		t.Fatalf("baseline: ScanTextForDLP should flag the Anthropic key pattern, got clean")
	}
	if in := s.ScanTextForDLPInbound(ctx, carrier); in.Clean {
		t.Fatalf("ScanTextForDLPInbound must still run generic pattern DLP, got clean for key pattern")
	}
}
