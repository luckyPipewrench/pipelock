// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

//go:generate go run ./gen_dlp_presets.go

// defaultDLPPatternSet is the canonical shipped DLP pattern registry.
// Defaults, generated presets, and drift tests read from this list instead of
// carrying separate name/regex/severity copies.
var defaultDLPPatternSet = []DLPPattern{
	// Provider API keys
	{Name: "Anthropic API Key", Regex: `sk-ant-[a-zA-Z0-9\-_]{20,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Anthropic API Key")},
	{Name: "OpenAI API Key", Regex: `sk-proj-[a-zA-Z0-9\-_]{20,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("OpenAI API Key")},
	{Name: "OpenAI Service Key", Regex: `sk-svcacct-[a-zA-Z0-9\-]{20,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("OpenAI Service Key")},
	// Fireworks API keys use an "fw_" prefix with a 22-character
	// alphanumeric suffix. Keep the trailing word boundary so longer
	// opaque base64-ish IDs do not match a 22-character prefix.
	// Source: https://docs.fireworks.ai/api-reference/authentication
	{Name: "Fireworks API Key", Regex: `fw_[A-Za-z0-9]{22}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Fireworks API Key")},
	// OpenRouter keys are "sk-or-v1-" + a hex token. Keep the suffix
	// hex-only: allowing hyphens, underscores, or arbitrary letters lets
	// the pattern match ordinary prose/slugs after the prefix.
	{Name: "LLM Router API Key", Regex: `sk-or-v1-[A-Fa-f0-9]{20,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("LLM Router API Key")},
	{Name: "Answer Engine API Key", Regex: `pplx-[A-Za-z0-9]{20,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Answer Engine API Key")},
	{Name: "Web Research API Key", Regex: `tvly-[A-Za-z0-9]{20,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Web Research API Key")},
	{Name: "Google API Key", Regex: `AIza[0-9A-Za-z\-_]{35}\b`, Severity: SeverityHigh, ExemptDomains: providerKeyExemptDomains("Google API Key")},
	{Name: "Google OAuth Client Secret", Regex: `GOCSPX-[A-Za-z0-9_\-]{28,}`, Severity: SeverityCritical},
	// Stripe keys use underscores (sk_test_) or hyphens (sk-test-) depending on version.
	{Name: "Stripe Key", Regex: `[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}`, Severity: SeverityCritical},
	// Stripe webhook signing secrets: "whsec_" prefix.
	{Name: "Stripe Webhook Secret", Regex: `whsec_[a-zA-Z0-9_\-]{20,}`, Severity: SeverityCritical},

	// Source control tokens
	{Name: "GitHub Token", Regex: `gh[pousr]_[A-Za-z0-9_]{36,}`, Severity: SeverityCritical},
	{Name: "GitHub Fine-Grained PAT", Regex: `github_pat_[a-zA-Z0-9_]{36,}`, Severity: SeverityCritical},
	// GitLab personal access tokens: "glpat-" prefix, 20+ chars.
	{Name: "GitLab PAT", Regex: `glpat-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},
	// Remaining GitLab token families. All documented prefixes share
	// the gl<type>- + base64url shape (GitLab token overview). Optional
	// suffix chars use the (?:x)? form so the DLP pre-filter extracts
	// the shorter literal prefix (e.g. "glrt" gates glrt- and glrtr-).
	// Source: https://docs.gitlab.com/security/tokens/
	{Name: "GitLab Deploy Token", Regex: `gldt-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},
	{Name: "GitLab Runner Token", Regex: `glrt(?:r)?-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},
	{Name: "GitLab CI Job Token", Regex: `glcbt-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},
	{Name: "GitLab Pipeline Trigger Token", Regex: `glptt-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},
	{Name: "GitLab OAuth Application Secret", Regex: `gloas-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},
	{Name: "GitLab SCIM Token", Regex: `glsoat-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},
	// Feed / incoming-mail / agent / workspace / feature-flags-client
	// tokens grouped: lower prevalence, identical shape. Alternation
	// after "gl" yields no pre-filter prefix but is one cheap regex.
	{Name: "GitLab Service Token", Regex: `gl(?:ft|imt|agent|wt|ffct)-[a-zA-Z0-9\-_]{20,}`, Severity: SeverityCritical},

	// Database connection strings with embedded credentials. The
	// password between ':' and '@' is the secret. Scheme-locked so
	// http(s) basic-auth URLs do not match; the ":pass@" requirement
	// means a credential-less URI (postgres://host/db, redis://h:6379)
	// is ignored. Per-scheme patterns give the pre-filter a clean
	// literal prefix. The user segment is optional ([^...]*) so
	// a password-only redis URI (empty user segment, then the password,
	// then the @host separator) still matches.
	{Name: "PostgreSQL Connection String", Regex: `postgres(?:ql)?://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},
	{Name: "MySQL Connection String", Regex: `mysql://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},
	{Name: "MongoDB Connection String", Regex: `mongodb(?:\+srv)?://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},
	{Name: "Redis Connection String", Regex: `redis(?:s)?://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},

	// Cloud provider credentials
	// All AWS credential prefixes: AKIA (access key), ASIA (STS temp), AROA (role),
	// AIDA (user ID), AIPA (instance profile), AGPA (group), ANPA/ANVA (policy), A3T (legacy).
	// {16,}: real AWS IDs have 16+ chars after prefix. Avoids FPs like ASIA2025REPORT1234.
	{Name: "AWS Access ID", Regex: AWSAccessIDRegex, Severity: SeverityCritical},
	// AWS secret access keys: 40-char base64 near AWS context words.
	// Anchored to common config key names to reduce FPs on arbitrary base64.
	// Separator class handles YAML (: ), env (=), JSON (":"), and quoted formats.
	{Name: "AWS Secret Key", Regex: `(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret.?access.?key|SecretAccessKey)\s*["'=:\s]{1,5}\s*[A-Za-z0-9/+=]{40}`, Severity: SeverityCritical},
	{Name: "Google OAuth Token", Regex: `ya29\.[a-zA-Z0-9_-]{20,}`, Severity: SeverityCritical},
	// GCP service-account JSON private_key_id. The "service_account"
	// type marker is already an always-on CORE pattern (see
	// scanner/core.go), so it is deliberately NOT duplicated here;
	// this adds the 40-hex private_key_id. Detection-only marker (no
	// redaction class): a bare 40-hex value cannot be redacted
	// without over-matching git SHAs / digests. The actual signing
	// secret (the PEM private_key) is caught by "Private Key Header"
	// below and IS redactable via the ssh-private-key class, which
	// now also covers bare PKCS#8.
	{Name: "GCP Service Account Private Key ID", Regex: `"private_key_id"\s*:\s*"[a-f0-9]{40}"`, Severity: SeverityHigh},
	// Azure storage account key: 512-bit key -> 88 base64 chars
	// (86 + "==") in an AccountKey= connection-string field. Anchored
	// on AccountKey= so arbitrary 88-char base64 does not match.
	{Name: "Azure Storage Account Key", Regex: `AccountKey=[A-Za-z0-9+/]{86}==`, Severity: SeverityCritical},
	// Azure SAS signature: the sig= parameter is a URL-encoded base64
	// HMAC-SHA256 (32 bytes -> 44 base64 chars, trailing '=' as %3D).
	// Anchored on the urlencoded padding; severity "high" reflects the
	// generality of a "sig=" parameter name.
	{Name: "Azure SAS Token", Regex: `\bsig=[A-Za-z0-9%]{43,}%3d\b`, Severity: SeverityHigh},

	// Messaging platform tokens
	{Name: "Slack Token", Regex: `xox[bpras]-[0-9a-zA-Z-]{15,}`, Severity: SeverityCritical},
	{Name: "Slack App Token", Regex: `xapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+`, Severity: SeverityCritical},
	// The first segment is base64 of a snowflake user ID, which is
	// structurally an UPPERCASE M or N; the bot-token form is three
	// dot-separated base64url parts, the mfa form is "mfa." + 84 chars.
	// The leading anchor MUST stay case-sensitive: the scanner force-
	// prefixes every DLP regex with (?i), so a bare [MN] anchor matches a
	// lowercase m/n in ordinary words and, after whitespace normalization,
	// natural-language prose collapses into the 3-part dotted shape (a real
	// false positive). (?-i:...) pins the structural anchor to uppercase.
	{Name: "Discord Bot Token", Regex: `(?:(?-i:[MN])[A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}|(?-i:mfa\.)[A-Za-z0-9\-_]{84,})`, Severity: SeverityCritical},

	// Communication service keys
	// Twilio API Key SIDs are an "SK" prefix + exactly 32 hex chars
	// (34 total). Word boundaries keep the short prefix from matching
	// a 32-hex MD5/digest that merely follows a word ending in "sk"
	// (task/disk/risk...), and reject longer opaque hex blobs that
	// happen to start with SK. (?i) is retained for evasion coverage.
	// Source: https://www.twilio.com/docs/glossary/what-is-a-sid
	{Name: "Twilio API Key", Regex: `\bSK[a-f0-9]{32}\b`, Severity: SeverityHigh},
	// SendGrid keys are a literal uppercase "SG." prefix + two
	// base64url segments. The prefix must stay case-sensitive: under the
	// forced (?i) prefix a bare "SG." matches lowercase "sg." in prose,
	// and the .22.43 dotted shape can form after whitespace normalization.
	{Name: "SendGrid API Key", Regex: `(?-i:SG\.)[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, Severity: SeverityCritical},
	// Mailgun private API keys are a "key-" prefix + exactly 32
	// alphanumeric chars. The previous unbounded form matched the
	// hyper-common "key-" literal anywhere and any 32-char prefix of
	// a longer opaque ID. Boundaries require token-shaped edges:
	// "key-" must start at a word boundary (so "monkey-<id>" and
	// word-embedded uses don't match) and end after exactly 32 chars (so
	// longer opaque "key-<40+>" values don't match). Charset is kept
	// alphanumeric because real keys are lowercase base36-ish
	// (e.g. key-3ax6xnjp...), not hex - narrowing to hex would be a
	// false-negative.
	{Name: "Mailgun API Key", Regex: `\bkey-[a-zA-Z0-9]{32}\b`, Severity: SeverityHigh},

	// Observability / monitoring
	// New Relic user API keys: "NRAK-" prefix, 27+ uppercase alphanumeric.
	{Name: "New Relic API Key", Regex: `NRAK-[A-Z0-9]{27,}`, Severity: SeverityCritical},

	// AI/ML provider keys
	// Hugging Face user access tokens use an "hf_" prefix with a
	// bounded alphanumeric suffix. Keep the boundary so longer
	// opaque IDs do not match a valid token prefix.
	// Source: https://huggingface.co/docs/hub/security-tokens
	{Name: "Hugging Face Token", Regex: `hf_[A-Za-z0-9]{34,37}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Hugging Face Token")},
	// Databricks personal access tokens use a 32-character hex suffix.
	// Keep this narrow: the previous lowercase-alphanumeric suffix
	// produced false positives on base64 image payloads.
	{Name: "Databricks Token", Regex: `dapi[0-9a-f]{32,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Databricks Token")},
	// Replicate API tokens use an "r8_" prefix with a 40-character
	// hex suffix. The previous broad alphanumeric suffix was the same
	// short-prefix FP shape as Fireworks and Databricks.
	// Source: https://replicate.com/docs/topics/authentication
	{Name: "Replicate API Token", Regex: `r8_[a-f0-9]{40}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Replicate API Token")},
	{Name: "Together AI Key", Regex: `tok_[a-z0-9]{40,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Together AI Key")},
	// Pinecone API keys: "pcsk_" prefix followed by alphanumeric.
	{Name: "Pinecone API Key", Regex: `pcsk_[a-zA-Z0-9]{36,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Pinecone API Key")},
	// Groq inference API keys: "gsk_" prefix, 48+ alphanumeric chars.
	{Name: "Groq API Key", Regex: `gsk_[a-zA-Z0-9]{48,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("Groq API Key")},
	// xAI (Grok) API keys: "xai-" prefix, 80+ chars including hyphens.
	{Name: "xAI API Key", Regex: `xai-[a-zA-Z0-9\-_]{80,}\b`, Severity: SeverityCritical, ExemptDomains: providerKeyExemptDomains("xAI API Key")},

	// Infrastructure and platform tokens
	// DigitalOcean personal access tokens: 64 hex chars after prefix.
	{Name: "DigitalOcean Token", Regex: `dop_v1_[a-f0-9]{64}`, Severity: SeverityCritical},
	// Vault 1.10+ service tokens use hvs. plus 24+ random chars.
	// Source: https://developer.hashicorp.com/vault/docs/concepts/tokens#token-prefixes
	{Name: "HashiCorp Vault Token", Regex: `hvs\.[A-Za-z0-9]{24,}\b`, Severity: SeverityCritical},
	{Name: "Vercel Token", Regex: `(?:vercel|vc[piark])_[a-zA-Z0-9]{24,}\b`, Severity: SeverityCritical},
	// Supabase secret keys use sb_secret_<22-char-random>_<8-char-checksum>.
	// Both suffix parts are base64url; the final checksum char may be '-',
	// so the right edge handles that case without relying only on \b.
	// Source: https://supabase.com/docs/guides/self-hosting/self-hosted-auth-keys#new-api-keys-format
	{Name: "Supabase Service Key", Regex: `sb_secret_[A-Za-z0-9_-]{22}_(?:[A-Za-z0-9_-]{7}[A-Za-z0-9_]\b|[A-Za-z0-9_-]{7}-\B)`, Severity: SeverityCritical},

	// Package registry tokens
	{Name: "npm Token", Regex: `npm_[A-Za-z0-9]{36,}\b`, Severity: SeverityCritical},
	// PyPI API tokens are long base64url payloads with a stable
	// "pypi-AgE" prefix (v2 macaroon, empty location). If PyPI
	// rotates macaroon format or version, this regex MUST be updated:
	// current shape is intentionally precise over future-proof.
	// Source: https://pypi.org/help/#apitoken
	{Name: "PyPI Token", Regex: `pypi-AgE[A-Za-z0-9_-]{90,}`, Severity: SeverityCritical},

	// Developer platform tokens
	// Linear documents lin_api_ as the personal API key prefix; keep the
	// existing length floor but require a token boundary.
	// Source: https://linear.app/changelog/2021-08-19-github-secret-scanning
	{Name: "Linear API Key", Regex: `lin_api_[A-Za-z0-9]{40,}\b`, Severity: SeverityHigh},
	{Name: "Notion API Key", Regex: `ntn_[a-zA-Z0-9]{40,}\b`, Severity: SeverityHigh},
	// Sentry CLI documents sntrys_ auth tokens; keep the existing
	// length floor but require a token boundary.
	// Source: https://docs.sentry.dev/cli/configuration/
	{Name: "Sentry Auth Token", Regex: `sntrys_[A-Za-z0-9]{40,}\b`, Severity: SeverityHigh},

	// Cryptographic material
	// PGP + optional trailing BLOCK keep DLP detection aligned with
	// the ssh-private-key redaction class (which covers PGP/BLOCK).
	{Name: "Private Key Header", Regex: `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(\s+BLOCK)?-----`, Severity: SeverityCritical},
	// A JWT's header and payload are base64url JSON objects. Real-world
	// compact tokens normally encode from `{"...` and therefore start
	// with literal "eyJ", but valid JSON may include whitespace after
	// `{`, producing `eyA` or `ew[o/k/0]` prefixes. The previous "ey" +
	// (?i) matched "EY"/"ey" anywhere, so prose with two dot-separated
	// "ey..."-ish fragments tripped it. Keep only narrow, case-sensitive
	// JSON-object prefixes so the precision fix does not drop compact
	// JWTs serialized with whitespace.
	{Name: "JWT Token", Regex: `(?:(?-i:ey[JA])[a-zA-Z0-9_\-=]{7,}|(?-i:ew[ok0])[a-zA-Z0-9_\-=]{7,})\.(?:(?-i:ey[JA])[a-zA-Z0-9_\-=]{7,}|(?-i:ew[ok0])[a-zA-Z0-9_\-=]{7,}|(?-i:e30=?))\.[a-zA-Z0-9_\-=]{10,}`, Severity: SeverityHigh},

	// Cryptocurrency private keys
	// Bitcoin WIF: base58check. Uncompressed (5 + 50 base58 = 51 chars) or
	// compressed (K/L + 51 base58 = 52 chars). Mainnet only; testnet deferred.
	{Name: "Bitcoin WIF Private Key", Regex: `(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})`, Severity: SeverityCritical, Validator: ValidatorWIF},
	// Extended private keys (BIP-32/49/84): xprv/yprv/zprv (mainnet) + tprv (testnet).
	// 111 total chars, base58check encoded.
	{Name: "Extended Private Key", Regex: `[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,108}`, Severity: SeverityCritical},
	// Ethereum/EVM private keys: 0x-prefixed 64-char hex (256-bit).
	// Requires 0x to avoid SHA-256 hash false positives. (?i) auto-prefix covers 0X.
	{Name: "Ethereum Private Key", Regex: `0x[0-9a-f]{64}\b`, Severity: SeverityCritical},
	// Ethereum Address (0x + 40 hex) is available in preset configs
	// but NOT in defaults because DLP fires before address_protection
	// allowlists, causing unavoidable false positives for blockchain
	// agents. Operators who need ETH address DLP without address_protection
	// should add the pattern to their config or use a preset.

	// Identity / PII
	{Name: "Social Security Number", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Severity: SeverityLow},
	{Name: "Google OAuth Client ID", Regex: `[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, Severity: SeverityMedium},

	// Generic credential patterns
	// Accepts either a URL query delimiter ([?&;]) OR line-start
	// before the credential key. Line-start (via the (?m) flag +
	// ^ anchor) catches body-first credentials like
	//     password=X  (where X is the secret value)
	// that an HTTP form or env-dump log emits without a leading
	// delimiter, while the delimiter alternative still catches
	// standard query strings and connection strings prefixed by
	// ? or ; before the credential key. Go-style struct assignments
	// (ep.Token = X, req.APIKey = Y) are still immune because
	// the credential key is preceded by . or another word
	// character, which is neither ^ nor [?&;]. The rule is
	// scoped to URL/body-embedded credentials only - env-var
	// dumps like DB_PASSWORD=... are handled by the separate
	// Environment Variable Secret pattern below, which requires
	// UPPER_CASE identifiers. Hyphen-compound params
	// (show-password) are still protected because the delimiter
	// is always explicit.
	// Case-insensitive matching is added automatically by scanner.New() via (?i) prefix.
	// The value must begin with a credential-plausible character
	// ([A-Za-z0-9_+/=~%.-], covering common base64/base64url/hex/JWT
	// and URL-encoded token forms). This rejects shell/template forms
	// that the whitespace-collapsed DLP view (text_dlp.go) would
	// otherwise turn into a spurious match by deleting the value's
	// natural delimiter: command substitution (token=$(...)),
	// backticks, and quoted variable refs (password="$VAR").
	{Name: "Credential in URL", Regex: `(?m)(?:^|[?&;])\s*(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*[A-Za-z0-9_+/=~%.-][^\s&;]{3,}`, Severity: SeverityHigh},
	// Environment variable credential patterns: catches env var dumps
	// where the secret-bearing keyword is the terminal segment of an
	// UPPER_CASE name (e.g., AWS_SECRET_ACCESS_KEY=..., STRIPE_SECRET_KEY=...,
	// DB_PASSWORD=..., CLIENT_SECRET=..., MY_API_KEY=...).
	// The keyword must end the variable name so benign suffixes like
	// *_TOKEN_BUCKET, *_PASSWORD_POLICY, and *_ROTATION_DAYS do not match.
	// (?-i:) overrides the scanner's auto (?i) prefix for the variable
	// name prefix - env vars are UPPER_CASE by convention, URL params
	// are lower_case (next_token, csrf_token_id). This avoids FP on
	// URL params while catching env var dumps.
	// Min value length of 8 prevents FP on short config values. The
	// value must begin with a secret-plausible character
	// ([A-Za-z0-9_+/=~.-], covering common base64/base64url/hex/JWT
	// token forms) followed by 7+ non-whitespace chars. The
	// leading-character class is what makes this safe under the
	// whitespace-collapsed DLP view (text_dlp.go), which strips all
	// whitespace and would otherwise let the \S run absorb the rest of
	// the document when a benign env-var NAME is followed by a shell
	// example rather than a real value. It rejects command substitution
	// (TOKEN=$(...)), backticks, quoted refs (TOKEN="$VAR"), and
	// Authorization templates while still matching common real
	// assignments and space-split evasions (PROVIDER _ TOKEN =
	// realsecret).
	{Name: "Environment Variable Secret", Regex: `(?-i:[A-Z][A-Z0-9]*[_-](?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY))\b\s*=\s*[A-Za-z0-9_+/=~.-]\S{7,}`, Severity: SeverityHigh},

	// Financial identifiers - validated with post-match checksums to minimize
	// false positives. Credit card regex is intentionally broad (any 15-19
	// digit number); issuer prefix + length validation is in validateLuhn
	// where it's maintainable Go code, not regex soup across 8 files.
	// Luhn + issuer check drops ~95% of random matches. mod-97 drops ~99%
	// of random IBAN-format matches. ABA is not in defaults due to high FP
	// rate; users can add it via config with validator: "aba".
	{Name: "Credit Card Number", Regex: `\b\d{4}(?:[- ]?\d){11,15}\b`, Severity: SeverityMedium, Validator: ValidatorLuhn},
	{Name: "IBAN", Regex: `\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`, Severity: SeverityMedium, Validator: ValidatorMod97},
}

// DefaultDLPPatterns returns a copy of the canonical shipped DLP pattern list.
func DefaultDLPPatterns() []DLPPattern {
	return cloneDLPPatterns(defaultDLPPatternSet)
}

const (
	DLPPresetProfileFull       = "full"
	DLPPresetProfileHostile    = "hostile"
	DLPPresetProfileQuickstart = "quickstart"
)

var presetOnlyDLPPatterns = []DLPPattern{
	{Name: "Ethereum Address", Regex: `0x[0-9a-fA-F]{40}\b`, Severity: SeverityHigh},
}

var hostileDLPSeverityOverrides = map[string]string{
	"Credential in URL":      SeverityCritical,
	"Google API Key":         SeverityCritical,
	"Google OAuth Client ID": SeverityCritical,
	"JWT Token":              SeverityCritical,
	"Linear API Key":         SeverityCritical,
	"Mailgun API Key":        SeverityCritical,
	"Notion API Key":         SeverityCritical,
	"Sentry Auth Token":      SeverityCritical,
	"Twilio API Key":         SeverityCritical,
}

var quickstartDLPPatternNames = []string{
	"Anthropic API Key",
	"OpenAI API Key",
	"OpenAI Service Key",
	"Fireworks API Key",
	"Google API Key",
	"Google OAuth Client Secret",
	"Stripe Key",
	"GitHub Token",
	"GitHub Fine-Grained PAT",
	"AWS Access ID",
	"Google OAuth Token",
	"Slack Token",
	"Slack App Token",
	"Discord Bot Token",
	"Twilio API Key",
	"SendGrid API Key",
	"Mailgun API Key",
	"Private Key Header",
	"JWT Token",
	"Social Security Number",
	"Google OAuth Client ID",
	"Credential in URL",
}

var coreDLPPatternNames = []string{
	"AWS Access ID",
	"AWS Secret Key",
	"GitHub Token",
	"GitHub Fine-Grained PAT",
	"GitLab PAT",
	"Slack Token",
	"Private Key Header",
}

var coreOnlyDLPPatterns = []DLPPattern{
	{Name: "GCP Service Account Key", Regex: `"type"\s*:\s*"service_account"`, Severity: SeverityCritical},
}

// IsCoreDLPPatternName reports whether name belongs to the immutable DLP
// safety floor used by the scanner.
func IsCoreDLPPatternName(name string) bool {
	for _, coreName := range coreDLPPatternNames {
		if name == coreName {
			return true
		}
	}
	for _, pattern := range coreOnlyDLPPatterns {
		if name == pattern.Name {
			return true
		}
	}
	return false
}

// PresetDLPPatterns returns the generated DLP pattern set for a shipped preset
// profile. Profile-specific deltas preserve current shipped YAML behavior.
func PresetDLPPatterns(profile string) ([]DLPPattern, error) {
	switch profile {
	case DLPPresetProfileFull:
		return fullPresetDLPPatterns(nil), nil
	case DLPPresetProfileHostile:
		return fullPresetDLPPatterns(hostileDLPSeverityOverrides), nil
	case DLPPresetProfileQuickstart:
		return quickstartPresetDLPPatterns(), nil
	default:
		return nil, fmt.Errorf("unknown DLP preset profile %q", profile)
	}
}

// CoreDLPPatterns returns the immutable DLP safety floor used by the scanner.
func CoreDLPPatterns() []DLPPattern {
	defaultsByName := defaultDLPPatternsByName()
	out := make([]DLPPattern, 0, len(coreDLPPatternNames)+len(coreOnlyDLPPatterns))
	for _, name := range coreDLPPatternNames {
		pattern, ok := defaultsByName[name]
		if !ok {
			panic(fmt.Sprintf("BUG: core DLP pattern %q missing from default registry", name))
		}
		out = append(out, pattern)
		if name == "AWS Secret Key" {
			out = append(out, coreOnlyDLPPatterns...)
		}
	}
	return cloneDLPPatterns(out)
}

func quickstartPresetDLPPatterns() []DLPPattern {
	return selectDefaultDLPPatterns(quickstartDLPPatternNames)
}

func selectDefaultDLPPatterns(names []string) []DLPPattern {
	defaultsByName := defaultDLPPatternsByName()
	out := make([]DLPPattern, 0, len(names))
	for _, name := range names {
		pattern, ok := defaultsByName[name]
		if !ok {
			panic(fmt.Sprintf("BUG: DLP pattern %q missing from default registry", name))
		}
		out = append(out, pattern)
	}
	return cloneDLPPatterns(out)
}

func defaultDLPPatternsByName() map[string]DLPPattern {
	defaultsByName := make(map[string]DLPPattern, len(defaultDLPPatternSet))
	for _, pattern := range defaultDLPPatternSet {
		defaultsByName[pattern.Name] = pattern
	}
	return defaultsByName
}

func fullPresetDLPPatterns(severityOverrides map[string]string) []DLPPattern {
	patterns := DefaultDLPPatterns()
	for _, presetOnly := range presetOnlyDLPPatterns {
		patterns = insertDLPPatternAfter(patterns, "Ethereum Private Key", presetOnly)
	}
	for i := range patterns {
		if severity, ok := severityOverrides[patterns[i].Name]; ok {
			patterns[i].Severity = severity
		}
	}
	return patterns
}

func insertDLPPatternAfter(patterns []DLPPattern, after string, pattern DLPPattern) []DLPPattern {
	for i := range patterns {
		if patterns[i].Name == after {
			patterns = append(patterns, DLPPattern{})
			copy(patterns[i+2:], patterns[i+1:])
			patterns[i+1] = pattern
			return patterns
		}
	}
	return append(patterns, pattern)
}
