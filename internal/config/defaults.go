// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// Defaults returns a Config with sensible defaults for balanced mode.
func Defaults() *Config {
	cfg := &Config{
		Version:            1,
		Mode:               ModeBalanced,
		canonicalHashCache: &canonicalHashCacheHolder{},
		APIAllowlist: []string{
			"*.anthropic.com",
			"*.openai.com",
			"api.telegram.org",
			"*.discord.com",
			"gateway.discord.gg",
			"*.slack.com",
			"github.com",
			"*.github.com",
			"*.githubusercontent.com",
			"registry.npmjs.org",
		},
		FetchProxy: FetchProxy{
			Listen:         DefaultListen,
			TimeoutSeconds: 30,
			MaxResponseMB:  10,
			UserAgent:      "Pipelock Fetch/1.0",
			Monitoring: Monitoring{
				MaxURLLength:              2048,
				EntropyThreshold:          4.5,
				SubdomainEntropyThreshold: 4.0,
				MaxReqPerMinute:           60,
				Blocklist: []string{
					"*.pastebin.com",
					"*.hastebin.com",
					"*.paste.ee",
					"*.transfer.sh",
					"*.file.io",
					"*.requestbin.com",
				},
				SubdomainEntropyExclusions: []string{
					"files.pythonhosted.org",
					"pypi.org",
					"objects.githubusercontent.com",
				},
			},
		},
		ForwardProxy: ForwardProxy{
			Enabled:            false,
			MaxTunnelSeconds:   300,
			IdleTimeoutSeconds: 120,
			SNIVerification:    ptrBool(true),
		},
		WebSocketProxy: WebSocketProxy{
			Enabled:                  false,
			MaxMessageBytes:          1048576,
			MaxConcurrentConnections: 128,
			ScanTextFrames:           ptrBool(true),
			StripCompression:         ptrBool(true),
			MaxConnectionSeconds:     3600,
			IdleTimeoutSeconds:       300,
			OriginPolicy:             OriginPolicyRewrite,
		},
		RequestPolicy: RequestPolicy{
			OnParseError:      ActionBlock,
			OnOpaqueOperation: ActionBlock,
		},
		DLP: DLP{
			ScanEnv: true,
			Patterns: []DLPPattern{
				// Provider API keys
				{Name: "Anthropic API Key", Regex: `sk-ant-[a-zA-Z0-9\-_]{10,}`, Severity: SeverityCritical},
				{Name: "OpenAI API Key", Regex: `sk-proj-[a-zA-Z0-9\-_]{10,}`, Severity: SeverityCritical},
				{Name: "OpenAI Service Key", Regex: `sk-svcacct-[a-zA-Z0-9\-]{10,}`, Severity: SeverityCritical},
				// Fireworks API keys use an "fw_" prefix with a 22-character
				// alphanumeric suffix. Keep the trailing word boundary so longer
				// opaque base64-ish IDs do not match a 22-character prefix.
				// Source: https://docs.fireworks.ai/api-reference/authentication
				{Name: "Fireworks API Key", Regex: `fw_[A-Za-z0-9]{22}\b`, Severity: SeverityCritical},
				{Name: "Google API Key", Regex: `AIza[0-9A-Za-z\-_]{35}`, Severity: "high"},
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
				// redis://:password@host (password-only) still matches.
				{Name: "PostgreSQL Connection String", Regex: `postgres(?:ql)?://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},
				{Name: "MySQL Connection String", Regex: `mysql://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},
				{Name: "MongoDB Connection String", Regex: `mongodb(?:\+srv)?://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},
				{Name: "Redis Connection String", Regex: `redis(?:s)?://[^:/?#\s]*:[^@/?#\s]+@`, Severity: SeverityCritical},

				// Cloud provider credentials
				// All AWS credential prefixes: AKIA (access key), ASIA (STS temp), AROA (role),
				// AIDA (user ID), AIPA (instance profile), AGPA (group), ANPA/ANVA (policy), A3T (legacy).
				// {16,}: real AWS IDs have 16+ chars after prefix. Avoids FPs like ASIA2025REPORT1234.
				{Name: "AWS Access ID", Regex: `(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}`, Severity: SeverityCritical},
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
				{Name: "Discord Bot Token", Regex: `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}`, Severity: SeverityCritical},

				// Communication service keys
				// Twilio API Key SIDs are an "SK" prefix + exactly 32 hex chars
				// (34 total). Word boundaries keep the short prefix from matching
				// a 32-hex MD5/digest that merely follows a word ending in "sk"
				// (task/disk/risk...), and reject longer opaque hex blobs that
				// happen to start with SK. (?i) is retained for evasion coverage.
				// Source: https://www.twilio.com/docs/glossary/what-is-a-sid
				{Name: "Twilio API Key", Regex: `\bSK[a-f0-9]{32}\b`, Severity: "high"},
				{Name: "SendGrid API Key", Regex: `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, Severity: SeverityCritical},
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
				{Name: "Mailgun API Key", Regex: `\bkey-[a-zA-Z0-9]{32}\b`, Severity: "high"},

				// Observability / monitoring
				// New Relic user API keys: "NRAK-" prefix, 27+ uppercase alphanumeric.
				{Name: "New Relic API Key", Regex: `NRAK-[A-Z0-9]{27,}`, Severity: SeverityCritical},

				// AI/ML provider keys
				// Hugging Face user access tokens use an "hf_" prefix with a
				// bounded alphanumeric suffix. Keep the boundary so longer
				// opaque IDs do not match a valid token prefix.
				// Source: https://huggingface.co/docs/hub/security-tokens
				{Name: "Hugging Face Token", Regex: `hf_[A-Za-z0-9]{34,37}\b`, Severity: SeverityCritical},
				// Databricks personal access tokens use a 32-character hex suffix.
				// Keep this narrow: the previous lowercase-alphanumeric suffix
				// produced false positives on base64 image payloads.
				{Name: "Databricks Token", Regex: `dapi[0-9a-f]{32,}`, Severity: SeverityCritical},
				// Replicate API tokens use an "r8_" prefix with a 40-character
				// hex suffix. The previous broad alphanumeric suffix was the same
				// short-prefix FP shape as Fireworks and Databricks.
				// Source: https://replicate.com/docs/topics/authentication
				{Name: "Replicate API Token", Regex: `r8_[a-f0-9]{40}\b`, Severity: SeverityCritical},
				{Name: "Together AI Key", Regex: `tok_[a-z0-9]{40,}\b`, Severity: SeverityCritical},
				// Pinecone API keys: "pcsk_" prefix followed by alphanumeric.
				{Name: "Pinecone API Key", Regex: `pcsk_[a-zA-Z0-9]{36,}`, Severity: SeverityCritical},
				// Groq inference API keys: "gsk_" prefix, 48+ alphanumeric chars.
				{Name: "Groq API Key", Regex: `gsk_[a-zA-Z0-9]{48,}`, Severity: SeverityCritical},
				// xAI (Grok) API keys: "xai-" prefix, 80+ chars including hyphens.
				{Name: "xAI API Key", Regex: `xai-[a-zA-Z0-9\-_]{80,}`, Severity: SeverityCritical},

				// Infrastructure and platform tokens
				// DigitalOcean personal access tokens: 64 hex chars after prefix.
				{Name: "DigitalOcean Token", Regex: `dop_v1_[a-f0-9]{64}`, Severity: SeverityCritical},
				// Vault 1.10+ service tokens use hvs. plus 24+ random chars.
				// Source: https://developer.hashicorp.com/vault/docs/concepts/tokens#token-prefixes
				{Name: "HashiCorp Vault Token", Regex: `\bhvs\.[A-Za-z0-9]{24,}\b`, Severity: SeverityCritical},
				{Name: "Vercel Token", Regex: `(?:vercel|vc[piark])_[a-zA-Z0-9]{24,}\b`, Severity: SeverityCritical},
				// Supabase secret keys use sb_secret_<22-char-random>_<8-char-checksum>.
				// Both suffix parts are base64url; the final checksum char may be '-',
				// so the right edge handles that case without relying only on \b.
				// Source: https://supabase.com/docs/guides/self-hosting/self-hosted-auth-keys#new-api-keys-format
				{Name: "Supabase Service Key", Regex: `\bsb_secret_[A-Za-z0-9_-]{22}_(?:[A-Za-z0-9_-]{7}[A-Za-z0-9_]\b|[A-Za-z0-9_-]{7}-\B)`, Severity: SeverityCritical},

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
				{Name: "Linear API Key", Regex: `\blin_api_[A-Za-z0-9]{40,}\b`, Severity: "high"},
				{Name: "Notion API Key", Regex: `ntn_[a-zA-Z0-9]{40,}\b`, Severity: "high"},
				// Sentry CLI documents sntrys_ auth tokens; keep the existing
				// length floor but require a token boundary.
				// Source: https://docs.sentry.dev/cli/configuration/
				{Name: "Sentry Auth Token", Regex: `\bsntrys_[A-Za-z0-9]{40,}\b`, Severity: "high"},

				// Cryptographic material
				// PGP + optional trailing BLOCK keep DLP detection aligned with
				// the ssh-private-key redaction class (which covers PGP/BLOCK).
				{Name: "Private Key Header", Regex: `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(\s+BLOCK)?-----`, Severity: SeverityCritical},
				{Name: "JWT Token", Regex: `(ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}`, Severity: "high"},

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
				{Name: "Social Security Number", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Severity: "low"},
				{Name: "Google OAuth Client ID", Regex: `[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, Severity: "medium"},

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
				{Name: "Credential in URL", Regex: `(?m)(?:^|[?&;])\s*(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*[A-Za-z0-9_+/=~%.-][^\s&;]{3,}`, Severity: "high"},
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
				{Name: "Environment Variable Secret", Regex: `(?-i:[A-Z][A-Z0-9]*[_-](?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY))\b\s*=\s*[A-Za-z0-9_+/=~.-]\S{7,}`, Severity: "high"},

				// Financial identifiers - validated with post-match checksums to minimize
				// false positives. Credit card regex is intentionally broad (any 15-19
				// digit number); issuer prefix + length validation is in validateLuhn
				// where it's maintainable Go code, not regex soup across 8 files.
				// Luhn + issuer check drops ~95% of random matches. mod-97 drops ~99%
				// of random IBAN-format matches. ABA is not in defaults due to high FP
				// rate; users can add it via config with validator: "aba".
				{Name: "Credit Card Number", Regex: `\b\d{4}(?:[- ]?\d){11,15}\b`, Severity: "medium", Validator: ValidatorLuhn},
				{Name: "IBAN", Regex: `\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`, Severity: "medium", Validator: ValidatorMod97},
			},
		},
		CanaryTokens: CanaryTokens{
			Enabled: false,
		},
		MCPInputScanning: MCPInputScanning{
			Enabled:      false,
			OnParseError: ActionBlock,
		},
		MCPToolScanning: MCPToolScanning{
			Enabled: false,
		},
		MCPToolPolicy: MCPToolPolicy{
			Enabled:       false,
			QuarantineDir: filepath.Join(os.TempDir(), "pipelock-quarantine"),
		},
		GitProtection: GitProtection{
			Enabled:         false,
			AllowedBranches: []string{"feature/*", "fix/*", "main", "master"},
			PrePushScan:     true,
		},
		ResponseScanning: ResponseScanning{
			Enabled: true,
			Action:  "warn",
			SSEStreaming: GenericSSEScanning{
				Enabled:       true,
				Action:        ActionBlock,
				MaxEventBytes: 64 * 1024,
			},
			Patterns: []ResponseScanPattern{
				{Name: "Prompt Injection", Regex: `(?i)(ignore|disregard|forget|abandon)[-,;:.\s]+\s*(?:all\s+\w+\s+|\w+\s+all\s+|all\s+|\w+\s+)?(previous|prior|above|earlier)\s+(\w+\s+)?(instructions|prompts|rules|context|directives|constraints|policies|guardrails)`},
				{Name: "System Override", Regex: `(?im)^\s*system\s*:`},
				{Name: "Role Override", Regex: `(?i)you\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered)`},
				{Name: "New Instructions", Regex: `(?i)(new|updated|revised)\s+(instructions|directives|rules|prompt)`},
				{Name: "Jailbreak Attempt", Regex: `(?i)((?-i:\bDAN\b)|developer\s+mode|sudo\s+mode|unrestricted\s+mode)`},
				{Name: "Hidden Instruction", Regex: `(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instructions?\s*[:=]|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)`},
				{Name: "Behavior Override", Regex: `(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+`},
				{Name: "Encoded Payload", Regex: `(?i)(decode\s+(this|the\s+following)\s+(from\s+)?base64\s+and\s+(execute|run|follow)|eval\s*\(\s*atob\s*\()`},
				{Name: "Tool Invocation", Regex: `(?i)you\s+must\s+(\w+\s+)?(call|execute|run|invoke)\s+(the|this|a)\s+(\w+\s+)?(function|tool|command|api|endpoint)`},
				{Name: "Authority Escalation", Regex: `(?i)you\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges|permissions|rights)`},
				{Name: "Instruction Downgrade", Regex: `(?i)(treat|consider|regard|reinterpret|downgrade)\s+((?:the|all)\s+)?(previous|prior|above|earlier|system|policy|original|existing)\s+(\w+\s+)?(text|instructions?|rules|directives|guidelines|safeguards|constraints|controls|checks|context|prompt|policies|guardrails|parameters)\s+((as|to)\s+)?(historical|outdated|deprecated|optional|background|secondary|non-binding|non-authoritative|informational|advisory)`},
				{Name: "Instruction Dismissal", Regex: `(?i)(set|put)\s+(the\s+)?(previous|prior|above|earlier|system|original)\s+(\w+\s+)?(instructions?|directives|rules|constraints|context|prompt|safeguards|guidelines|policies|guardrails)\s+(aside|away|to\s+(one|the)\s+side)`},
				{Name: "Priority Override", Regex: `(?i)\bprioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)`},
				// State/control poisoning - detect credential solicitation,
				// memory persistence, and preference manipulation in tool results.
				{Name: "Credential Solicitation", Regex: `(?is)(\b(send|provide|paste|return|supply|submit|share)\b.{0,80}\b(password|passwd|token|api[_ -]?key|secret|credentials?|private[_ -]?key|ssh[_ -]?key|session[_ -]?cookie)\b|(?:^|[\n.!?]\s+|\bplease\s+)include\s+(your|my|our)\s+(password|passwd|token|api[_ -]?key|secret|credentials?|private[_ -]?key|ssh[_ -]?key|session[_ -]?cookie)\b)`},
				{Name: "Credential Path Directive", Regex: `(?is)\b(read|get|fetch|retrieve|cat|copy|extract|open|include)\b.{0,80}(\.ssh[/\\]|\.aws[/\\]credentials|\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\bid_rsa\b|\bid_ed25519\b|\bkubeconfig\b|/etc/passwd\b|/etc/shadow\b)`},
				{Name: "Auth Material Requirement", Regex: `(?is)\bto\s+(complete|continue|finish|proceed|verify)\b.{0,80}\b(authentication|credential|token|api[_ -]?key|private[_ -]?key|ssh[_ -]?key)\b.{0,40}\b(required|needed|necessary|must be)\b`},
				{Name: "Memory Persistence Directive", Regex: `(?is)\b(save|store|remember|retain|persist|record|cache)\b.{0,40}\b(this|these|that|it|the)\b.{0,60}\b(for future|for later|across sessions?|next session|next time|future tasks?|future sessions?|for all future|subsequent|permanently|from now on|going forward|in all future)\b`},
				{Name: "Preference Poisoning", Regex: `(?is)\b(from now on|always|going forward|in future)\b.{0,80}\b(prefer|prioritize|trust|choose|use|default to)\b.{0,60}\b(this tool|that tool|my tool|the external|the remote)\b`},
				{Name: "Silent Credential Handling", Regex: `(?is)\b(do not|don'?t|never)\s+(mention|display|show|tell|reveal|log|report)\b.{0,100}\b(password|token|secret|credential|private[_ -]?key|api[_ -]?key)\b`},
				// Covert action directives - instructions to perform actions
				// secretly, silently, or without the user's knowledge.
				{Name: "Covert Action Directive", Regex: `(?is)(secretly|silently|covertly|quietly|without\s+(?:the\s+user\s+)?(?:knowing|noticing|seeing))[,;:]?\s+.{0,40}\b(execut\w*|run|call|invoke|send|fetch|curl|wget|download|upload|post|exfiltrat\w*|leak|stream|transmit|relay|forward|smuggle)\b`},
				// Model-specific instruction boundary tokens - ChatML, Llama, Mistral.
				// Presence in tool output is a strong injection signal.
				{Name: "Instruction Boundary", Regex: `(<\|(?:endoftext|im_start|im_end|system|end_header_id|begin_of_text)\|>|\[/?INST\]|<\|(?:user|assistant)\|>|<<SYS>>)`},
				{Name: "Spanish Instruction Override", Regex: `(?i)\b(ignora|omite|olvida|desobedece|descarta)\b.{0,30}\b(las\s+)?(instrucciones|indicaciones|directivas|reglas)\b.{0,30}\b(anteriores|previas|precedentes|de\s+arriba)\b`},
				{Name: "Spanish System Prompt Disclosure", Regex: `(?i)\b(muestra|revela|imprime|expone|dime)\b.{0,40}\b(prompt|mensaje)\s+(del\s+)?sistema\b`},
				{Name: "Cross-Lingual Instruction Override", Regex: `(?i)\b(ignore|disregard|forget|abandon|ignora|omite|olvida|desobedece|descarta)\b.{0,40}\b(previous|prior|above|earlier|anteriores|previas|precedentes|de\s+arriba)\b.{0,40}\b(instructions?|instrucciones|indicaciones|directivas|reglas|prompts?|context|constraints?|policies|guardrails)\b`},
				{Name: "Cross-Lingual System Prompt Disclosure", Regex: `(?i)\b(show|reveal|print|display|dump|muestra|revela|imprime|expone|dime)\b.{0,40}\b(system\s+prompt|prompt\s+(del\s+)?sistema|mensaje\s+(del\s+)?sistema)\b`},
				// CJK injection patterns - Chinese, Japanese, Korean prompt
				// injection phrases sourced from published attack research,
				// jailbreak datasets, and security disclosures. Patterns use
				// .{0,N} ranges instead of \b because CJK has no word boundaries.
				{Name: "CJK Instruction Override ZH", Regex: `(忽略|无视|忽视|不理|不要遵[循守]|放弃|跳过).{0,10}(之前|以上|上述|以前|上面|先前|前面).{0,8}(所有|全部|一切)?.{0,6}(指令|指示|说明|规则|命令|提示|约束|限制)`},
				{Name: "CJK Instruction Override JP", Regex: `(以前|前|上記|これまで|今まで).{0,6}(指示|命令|ルール|規則|指令).{0,6}(すべて|全て|全部)?.{0,4}(無視|忘れ|従わな|捨て)`},
				{Name: "CJK Instruction Override KR", Regex: `(이전|위|앞|기존).{0,6}(모든\s*)?(지시|지침|명령|규칙|지령).{0,6}(무시|잊어|따르지|어기|무효)`},
				{Name: "CJK Jailbreak Mode", Regex: `(开发者模式|无限制模式|開発者モード|制限なしモード|개발자\s*모드|제한\s*없는\s*모드|没有任何?限制|制限.{0,4}(解除|無視)|제한.{0,4}(해제|무시))`},
			},
		},
		Logging: LoggingConfig{
			Format:         DefaultLogFormat,
			Output:         DefaultLogOutput,
			IncludeAllowed: true,
			IncludeBlocked: true,
		},
		MCPWSListener: MCPWSListener{
			MaxConnections: 100,
		},
		SessionProfiling: SessionProfiling{
			AnomalyAction:          ActionWarn,
			DomainBurst:            5,
			WindowMinutes:          5,
			VolumeSpikeRatio:       3.0,
			MaxSessions:            1000,
			SessionTTLMinutes:      30,
			CleanupIntervalSeconds: 60,
		},
		AdaptiveEnforcement: AdaptiveEnforcement{
			CooperativeToolDownweight: true,
		},
		TLSInterception: TLSInterception{
			Enabled: false,
			PassthroughDomains: []string{
				"*.googlevideo.com",
			},
			CertTTL:          DefaultCertTTL,
			CertCacheSize:    10000,
			MaxResponseBytes: 5 * 1024 * 1024, // 5MB
		},
		RequestBodyScanning: RequestBodyScanning{
			Enabled:      true,
			Action:       ActionWarn,
			MaxBodyBytes: 5 * 1024 * 1024, // 5MB
			ScanHeaders:  true,
			HeaderMode:   HeaderModeSensitive,
			SensitiveHeaders: []string{
				"Authorization",
				"Cookie",
				"X-Api-Key",
				"X-Token",
				"Proxy-Authorization",
				"X-Goog-Api-Key",
			},
		},
		SeedPhraseDetection: SeedPhraseDetection{
			Enabled:        ptrBool(true),
			MinWords:       12,
			VerifyChecksum: ptrBool(true),
		},
		Internal: []string{
			"0.0.0.0/8",
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"100.64.0.0/10",
			"224.0.0.0/4", // IPv4 multicast
			"::1/128",
			"fc00::/7",
			"fe80::/10",
			"ff00::/8", // IPv6 multicast
		},
		ScanAPI: ScanAPI{
			Listen: "", // disabled by default
			RateLimit: ScanAPIRateLimit{
				RequestsPerMinute: 600,
				Burst:             50,
			},
			MaxBodyBytes: 1 << 20, // 1MB
			FieldLimits: ScanAPIFieldLimits{
				URL:       8192,
				Text:      512 * 1024, // 512KB
				Content:   512 * 1024, // 512KB
				Arguments: 512 * 1024, // 512KB
			},
			Timeouts: ScanAPITimeouts{
				Read:  "2s",
				Write: "2s",
				Scan:  "5s",
			},
			ConnectionLimit: 100,
			Kinds: ScanAPIKinds{
				URL:             true,
				DLP:             true,
				PromptInjection: true,
				ToolCall:        true,
			},
		},
		Rules: Rules{
			MinConfidence: ConfidenceMedium,
		},
		A2AScanning: A2AScanning{
			Enabled:                   false,
			Action:                    ActionWarn,
			ScanAgentCards:            true,
			DetectCardDrift:           true,
			SessionSmugglingDetection: true,
			MaxContextMessages:        100,
			MaxContexts:               1000,
			ScanRawParts:              true,
			MaxRawSize:                1 << 20, // 1MB encoded
		},
		MCPBinaryIntegrity: MCPBinaryIntegrity{
			Action: ActionWarn, // default action when hash verification fails
		},
		FlightRecorder: FlightRecorder{
			// Enabled by default so receipts ("verify the boundary") are on out
			// of the box. Emission still requires Dir != "" AND a signing key
			// (see server.go), so the default flip alone records nothing: a bare
			// Defaults() with no dir/key is inert. `pipelock init` generates both
			// and writes them into the config, which is what makes receipts live.
			// Footguns handled here: Redact stays on (receipts carry targets, so
			// without scrubbing they would persist secrets in the clear) and
			// MaxEntriesPerFile caps file growth (rotation), so default-on cannot
			// silently fill the disk or leak. Evidence, not enforcement by default:
			// a recorder failure never blocks traffic unless RequireReceipts is
			// explicitly enabled by the operator.
			Enabled:            true,
			RequireReceipts:    false,
			CheckpointInterval: 1000,  // entries between signed checkpoints
			Redact:             true,  // DLP-scrub evidence before commit
			SignCheckpoints:    true,  // Ed25519 sign checkpoints
			MaxEntriesPerFile:  10000, // rotate files at this count
		},
		MCPToolProvenance: MCPToolProvenance{
			Action:      ActionWarn,
			Mode:        ProvenanceModePipelock,
			OfflineOnly: true, // no network calls for verification
		},
		BehavioralBaseline: BehavioralBaseline{
			LearningWindow:   10,
			DeviationAction:  ActionWarn,
			SensitivitySigma: 2.0,
			PoisonResistance: true, // trimmed-mean scoring resists adversarial training data
			SeasonalityMode:  SeasonalityModeNone,
		},
		Airlock: Airlock{
			Triggers: AirlockTriggers{
				OnElevated:           AirlockTierNone,
				OnHigh:               AirlockTierSoft,
				OnCritical:           AirlockTierHard,
				AnomalyWindowMinutes: 5,
			},
			Timers: AirlockTimers{
				SoftMinutes:         10,
				HardMinutes:         5,
				DrainMinutes:        2,
				DrainTimeoutSeconds: 30,
			},
			ToolFreeze: AirlockToolFreeze{
				SnapshotOnEntry:  true,
				AllowCachedTools: true,
			},
		},
		BrowserShield: BrowserShield{
			Strictness:            ShieldStrictnessStandard,
			MaxShieldBytes:        5 * 1024 * 1024, // 5MB
			OversizeAction:        ShieldOversizeScanHead,
			StripExtensionProbing: true,
			StripHiddenTraps:      true,
			StripTrackingPixels:   true,
			ExemptDomains: []string{
				"challenges.cloudflare.com",
				"developer.mozilla.org",
				"docs.github.com",
				"github.dev",
				"go.dev",
				"hcaptcha.com",
				"pkg.go.dev",
				"vscode.dev",
				"www.recaptcha.net",
			},
		},
		Taint: TaintConfig{
			Enabled: true,
			AllowlistedDomains: []string{
				"docs.anthropic.com",
				"docs.github.com",
				"developer.mozilla.org",
			},
			ProtectedPaths: []string{
				"*/auth/*",
				"*/security/*",
				"*/.github/workflows/*",
				"*/.env*",
				"*/secrets*",
				"*/policy*",
				"*/sandbox*",
			},
			ElevatedPaths: []string{
				"*/config/*",
				"*/middleware*",
			},
			Policy:        ModeBalanced,
			RecentSources: 10,
		},
		MediationEnvelope: MediationEnvelope{},
		Learn: Learn{
			Enabled:    false,
			CaptureDir: "",
			Privacy: LearnPrivacy{
				SaltSource:             "",
				PublicAllowlistDefault: true, // security-sensitive default
			},
		},
		MediaPolicy: MediaPolicy{
			// Boolean fields left nil intentionally: all getters return the
			// security-preserving default when unset. Explicit YAML values
			// override, omission hits the default (enabled, strip audio+video,
			// strip metadata, log exposure). AllowedImageTypes and
			// MaxImageBytes also fall through to defaults via their getters.
		},
		HealthWatchdog: HealthWatchdog{
			Enabled:         true,
			IntervalSeconds: 2,
		},
		LearnLock: LearnLock{
			// Default off. The lock runtime is opt-in; if Enabled is
			// flipped on without the rest of the fields the validator
			// rejects the config at startup so a half-wired lock can
			// never silently downgrade to scanner-only.
			Enabled:           false,
			Mode:              LockModeShadow, // safe-by-default; live requires explicit opt-in
			MinimumSignatures: 1,
		},
		Conductor: Conductor{
			HonorRemoteKillSwitch: true,
			EmergencyStream:       ptrBool(true),
		},
	}
	// Mark all compiled defaults with provenance so the standard tier source
	// selector can distinguish them from user-supplied patterns. Set at
	// creation time (not during merge) so provenance survives any code path
	// that copies or reconstructs patterns.
	for i := range cfg.DLP.Patterns {
		cfg.DLP.Patterns[i].Compiled = true
	}
	for i := range cfg.ResponseScanning.Patterns {
		cfg.ResponseScanning.Patterns[i].Compiled = true
	}
	// Redaction defaults to disabled. Operators opt in via YAML; see the
	// redact package for the full schema.
	cfg.Redaction = redact.DefaultConfig()
	return cfg
}
