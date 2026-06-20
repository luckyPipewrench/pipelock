// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"regexp"
	"sort"
	"sync"
)

// A classPattern associates a secret class with a compiled regex that
// matches instances of that class in arbitrary text. Patterns must not have
// anchors (^ / $) because they are applied inside larger string scalars.
type classPattern struct {
	class   Class
	pattern *regexp.Regexp
	// priority disambiguates overlapping classes: higher wins. Used when the
	// same substring matches multiple classes (e.g., a CIDR also contains an
	// IPv4). Kept small integer to make ordering obvious.
	priority int
	// skipTrailing, when non-nil, rejects a match whose immediately-following
	// text matches this anchored regex. Used to keep a class from flagging a
	// value that is a protocol artifact rather than a leaked secret (e.g. an
	// AWS access key ID inside a SigV4 pre-signed URL).
	skipTrailing *regexp.Regexp
	// skipLeading, when non-nil, additionally requires the text immediately
	// BEFORE the match to match this regex (anchored at its end) for the skip
	// to apply. Combined with skipTrailing it scopes the carve-out to a real
	// X-Amz-Credential= context, so a SigV4-shaped substring sitting in
	// arbitrary text is still redacted.
	skipLeading *regexp.Regexp
}

// sigV4CredentialScope matches the credential-scope tail that follows an AWS
// access key ID in a SigV4 pre-signed URL: AKIA<16> then
// /YYYYMMDD/<region>/<service>/aws4_request, with either literal slashes or
// URL-encoded %2F. The access key ID in a pre-signed URL is the public half of
// the credential pair (the secret signing key is never transmitted; only a
// derived signature is), so redacting it leaks no secret and corrupts the URL.
// A bare access key ID, or one not in this scope shape, is still redacted.
var sigV4CredentialScope = regexp.MustCompile(
	`^(?:/|%2[Ff])[0-9]{8}(?:/|%2[Ff])[A-Za-z0-9-]{1,30}(?:/|%2[Ff])[A-Za-z0-9]{1,20}(?:/|%2[Ff])aws4_request\b`)

// sigV4CredentialPrefix matches the X-Amz-Credential query-parameter key that
// immediately precedes the access key ID in a SigV4 pre-signed URL. Anchored
// at the end so it matches against the text just before the candidate. Both
// the literal '=' and URL-encoded '%3D' separator are accepted. Requiring this
// prefix (in addition to the credential-scope suffix) keeps the carve-out
// scoped to a real X-Amz-Credential value, so a SigV4-shaped substring that
// merely appears in arbitrary text is still redacted.
var sigV4CredentialPrefix = regexp.MustCompile(`(?i)x-amz-credential(?:=|%3d)$`)

// Shared regex fragments reused across category-specific registries.
const (
	hex32         = `[a-fA-F0-9]{32}`
	hex40         = `[a-fA-F0-9]{40}`
	hex64         = `[a-fA-F0-9]{64}`
	hex128        = `[a-fA-F0-9]{128}`
	octet         = `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`
	ipv4Str       = `\b` + octet + `\.` + octet + `\.` + octet + `\.` + octet
	cidrMask      = `/(?:3[0-2]|[12]?\d)\b`
	envSecretName = `(?:[A-Z][A-Z0-9]*[_-])+(?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY)` //nolint:gosec // credential-type regex, not a secret value
)

// classRegistry is the shipped set of structured secret classes.
// Split across category helpers so no single function trips funlen and the
// priority story stays scannable category by category.
func classRegistry() []classPattern {
	out := make([]classPattern, 0, 41)
	out = append(out, tokenClasses()...)
	out = append(out, hashClasses()...)
	out = append(out, networkClasses()...)
	out = append(out, identityClasses()...)
	out = append(out, personalClasses()...)
	return out
}

// tokenClasses is the API-key / bearer-credential category. High priority
// so specific token formats win over generic patterns sharing the span.
func tokenClasses() []classPattern {
	return []classPattern{
		// Env-style assignments must outrank embedded token formats so
		// KEY=<placeholder> does not remain shaped like an env-secret leak
		// after redaction.
		{class: ClassEnvSecret, pattern: regexp.MustCompile(`\b` + envSecretName + `\b\s*=\s*\S{8,}`), priority: 120},
		{class: ClassAWSAccessKey, pattern: regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AGPA|AROA)[A-Z0-9]{16}\b`), priority: 100, skipTrailing: sigV4CredentialScope, skipLeading: sigV4CredentialPrefix},
		{class: ClassAWSSecretKey, pattern: regexp.MustCompile(`(?i)\b(?:aws_secret_access_key|secret.?access.?key|SecretAccessKey)\s*["'=:\s]{1,5}\s*[A-Za-z0-9/+=]{40}\b`), priority: 100},
		{class: ClassGoogleAPIKey, pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), priority: 100},
		{class: ClassGitHubToken, pattern: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`), priority: 100},
		// All documented GitLab token prefixes (token overview: glpat-,
		// gloas-, gldt-, glrt-/glrtr-, glcbt-, glptt-, glft-, glimt-,
		// glagent-, glwt-, glsoat-, glffct-) share the gl<type>- + base64url
		// shape, so one class covers every DLP detection pattern in the
		// GitLab family and an allowlisted host gets a placeholder instead of
		// the raw token. (?i) tolerates an uppercased leak.
		{class: ClassGitLabToken, pattern: regexp.MustCompile(`(?i)\bgl(?:pat|oas|dt|rtr?|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{20,}\b`), priority: 100},
		// Database connection strings carry the password between ':' and '@'.
		// Redacting scheme://user:pass@host masks the credential while the rest
		// of the scalar (path, query) is untouched. Matches the four DLP
		// connection-string families (postgres, mysql, mongodb, redis).
		{class: ClassDBConnString, pattern: regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?)://[^:/?#\s]*:[^@/?#\s]+@[^/?#\s]+`), priority: 100},
		// Azure storage account key: 512-bit key -> 88 base64 chars (86 + "==")
		// in an AccountKey= connection-string field. Anchored on AccountKey= to
		// avoid matching arbitrary base64.
		{class: ClassAzureStorageKey, pattern: regexp.MustCompile(`(?i)\bAccountKey=[A-Za-z0-9+/]{86}==`), priority: 100},
		// Azure SAS signature: the sig= parameter is a URL-encoded base64
		// HMAC-SHA256 (32 bytes -> 44 base64 chars, trailing '=' as %3D).
		// Anchored on the urlencoded padding to bound the match.
		{class: ClassAzureSAS, pattern: regexp.MustCompile(`(?i)\bsig=[A-Za-z0-9%]{43,}%3d\b`), priority: 100},
		{class: ClassSlackToken, pattern: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), priority: 100},
		{class: ClassFireworksAPIKey, pattern: regexp.MustCompile(`(?i)\bfw_[A-Za-z0-9]{22}\b`), priority: 100},
		{class: ClassAIProviderKey, pattern: regexp.MustCompile(`(?i)\b(?:sk-or-v1-[A-Fa-f0-9]{20,}|pplx-[A-Za-z0-9]{20,}|tvly-[A-Za-z0-9]{20,})\b`), priority: 100},
		{class: ClassHuggingFaceToken, pattern: regexp.MustCompile(`(?i)\bhf_[A-Za-z0-9]{34,37}\b`), priority: 100},
		{class: ClassReplicateAPIToken, pattern: regexp.MustCompile(`(?i)\br8_[a-f0-9]{40}\b`), priority: 100},
		{class: ClassTogetherAIKey, pattern: regexp.MustCompile(`(?i)\btok_[a-z0-9]{40,}\b`), priority: 100},
		{class: ClassVaultToken, pattern: regexp.MustCompile(`(?i)\bhvs\.[A-Za-z0-9]{24,}\b`), priority: 100},
		{class: ClassVercelToken, pattern: regexp.MustCompile(`(?i)\b(?:vercel|vc[piark])_[A-Za-z0-9]{24,}\b`), priority: 100},
		{class: ClassSupabaseKey, pattern: regexp.MustCompile(`(?i)\bsb_secret_[A-Za-z0-9_-]{22}_(?:[A-Za-z0-9_-]{7}[A-Za-z0-9_]\b|[A-Za-z0-9_-]{7}-\B)`), priority: 100},
		{class: ClassDatabricksPAT, pattern: regexp.MustCompile(`(?i)\bdapi[0-9a-f]{32,}\b`), priority: 100},
		{class: ClassOpenAIAPIKey, pattern: regexp.MustCompile(`sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b`), priority: 100},
		{class: ClassAnthropicKey, pattern: regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}\b`), priority: 100},
		{class: ClassNPMToken, pattern: regexp.MustCompile(`(?i)\bnpm_[A-Za-z0-9]{36,}\b`), priority: 100},
		// PyPI API tokens use the stable "pypi-AgE" prefix for v2 macaroons
		// with empty location. Update this if PyPI rotates token format.
		{class: ClassPyPIToken, pattern: regexp.MustCompile(`(?i)\bpypi-AgE[A-Za-z0-9_-]{90,}`), priority: 100},
		{class: ClassLinearAPIKey, pattern: regexp.MustCompile(`(?i)\blin_api_[A-Za-z0-9]{40,}\b`), priority: 100},
		{class: ClassNotionAPIKey, pattern: regexp.MustCompile(`(?i)\bntn_[A-Za-z0-9]{40,}\b`), priority: 100},
		{class: ClassSentryAuthToken, pattern: regexp.MustCompile(`(?i)\bsntrys_[A-Za-z0-9]{40,}\b`), priority: 100},
		{class: ClassTelegramToken, pattern: regexp.MustCompile(`\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b`), priority: 100},
		{class: ClassDiscordToken, pattern: regexp.MustCompile(`\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b`), priority: 100},
		// Twilio API Key SID: SK + 32 hex (34 total). Boundaries match the
		// tightened DLP default so an allowlisted host gets a placeholder
		// rather than the leaked SID passing through raw.
		{class: ClassTwilioAPIKey, pattern: regexp.MustCompile(`(?i)\bSK[a-f0-9]{32}\b`), priority: 100},
		// Mailgun private API key: "key-" + 32 alphanumeric. Boundaries match
		// the tightened DLP default.
		{class: ClassMailgunAPIKey, pattern: regexp.MustCompile(`(?i)\bkey-[A-Za-z0-9]{32}\b`), priority: 100},
		{class: ClassBearer, pattern: regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}\b`), priority: 95},
		// JWT: three base64url segments separated by dots; first segment
		// starts with `eyJ` (decodes to '{"').
		{class: ClassJWT, pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), priority: 100},
		// The key-type qualifier is optional so a bare PKCS#8 PEM header (the
		// one with no RSA/EC/DSA/OpenSSH qualifier before the key label), as
		// used by GCP service-account JSON private_key fields, is recognised
		// alongside the qualified forms.
		{class: ClassSSHPrivateKey, pattern: regexp.MustCompile(`-----BEGIN (?:(?:OPENSSH|RSA|DSA|EC|PGP) )?PRIVATE KEY(?: BLOCK)?-----`), priority: 100},
	}
}

// hashClasses is the fixed-length hex digest category. Longer digests must
// win over shorter-hash prefixes, hence the descending priorities. NTLM
// and MD5 share hex32; disambiguation needs context we don't have at
// regex time, so we expose MD5 and leave NTLM as a reserved label.
//
// Each pattern REQUIRES a contextual keyword prefix (sha256, sha-256,
// hash-sha256, md5, etc.) followed by a separator (whitespace, colon, or
// equals) before the hex digest. The earlier unprefixed form was an
// excessive false-positive source: any 64-char hex string matched the
// SHA-256 class, including legitimate OAuth client_secret values that
// happened to be 64 hex chars (various SaaS providers, GitLab) and opaque session
// tokens of the same shape. The PR #635 allowlist_unparseable contract
// fix surfaced this: redaction kept mangling a SaaS OAuth client_secret in
// form-urlencoded OAuth bodies even after the host was on the trust
// list, because the bare-hex matcher was rewriting the secret value to
// a placeholder before the upstream saw it. Tightening the matcher to
// require a self-labeled prefix preserves the DLP signal on values that
// present as hashes (integrity attestations, debug logs that name the
// digest scheme, manifest entries) while letting opaque hex blobs
// through.
func hashClasses() []classPattern {
	return []classPattern{
		{class: ClassHashSHA512, pattern: regexp.MustCompile(`(?i)\b(?:sha[-_]?512|hash[-_]?sha[-_]?512)[\s:=]+` + hex128 + `\b`), priority: 90},
		{class: ClassHashSHA256, pattern: regexp.MustCompile(`(?i)\b(?:sha[-_]?256|hash[-_]?sha[-_]?256)[\s:=]+` + hex64 + `\b`), priority: 85},
		{class: ClassHashSHA1, pattern: regexp.MustCompile(`(?i)\b(?:sha[-_]?1|hash[-_]?sha[-_]?1)[\s:=]+` + hex40 + `\b`), priority: 80},
		{class: ClassHashMD5, pattern: regexp.MustCompile(`(?i)\b(?:md5|hash[-_]?md5)[\s:=]+` + hex32 + `\b`), priority: 75},
	}
}

// networkClasses covers IP addresses (v4/v6), CIDR blocks, and MAC
// addresses. CIDR priority is above IPv4 so CIDR absorbs the embedded
// address; IPv6 priority is above MAC so the `::`-compressed form wins
// over the 6-group hex-with-colons shape.
func networkClasses() []classPattern {
	return []classPattern{
		{class: ClassIPv4, pattern: regexp.MustCompile(ipv4Str + `\b`), priority: 70},
		// CIDR = IPv4 followed by /N. Match before IPv4 so the /prefix is
		// included.
		{class: ClassCIDR, pattern: regexp.MustCompile(ipv4Str + cidrMask), priority: 72},
		// Pragmatic IPv6: either full 8-group form, OR a run with `::`
		// zero-compression that has at least one hex digit adjacent. The
		// hex-digit requirement keeps `std::cout` and bare `::` from
		// matching while still catching `::1`, `fe80::`, `2001:db8::1`.
		{class: ClassIPv6, pattern: regexp.MustCompile(`\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b[A-Fa-f0-9]+(?::[A-Fa-f0-9]*)*::(?:[A-Fa-f0-9]*:?)*[A-Fa-f0-9]*\b|::[A-Fa-f0-9]+(?::[A-Fa-f0-9]*)*\b`), priority: 68},
		{class: ClassMAC, pattern: regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`), priority: 65},
	}
}

// identityClasses covers email, FQDN, and AD user forms. FQDN is last
// (lowest priority among the three) so email wins on a shared span and a
// bare FQDN match only fires when no stricter class already claimed it.
func identityClasses() []classPattern {
	return []classPattern{
		{class: ClassEmail, pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), priority: 60},
		// Conservative FQDN: two-or-more labels, final TLD 2-24 letters.
		// Avoids version strings ("1.2.3") and most file paths.
		{class: ClassFQDN, pattern: regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,24}\b`), priority: 50},
		// AD user: CONTOSO\user shape. DOMAIN must be uppercase-ish to
		// avoid matching Windows paths with mixed case.
		{class: ClassADUser, pattern: regexp.MustCompile(`\b[A-Z][A-Z0-9_-]{1,20}\\[A-Za-z0-9._-]{2,}\b`), priority: 95},
	}
}

// personalClasses is the US-centric PII category. Operators in other
// locales supplement via dictionaries in v1.1. AmEx is 15 digits
// (4-6-5 split, 3[47] prefix); other supported brands are 16 digits
// (4-4-4-4). Folding both under the same template misses AmEx -
// regression reported in review (2026-04-19).
func personalClasses() []classPattern {
	return []classPattern{
		// SSN shape XXX-XX-XXXX. Matches on invalid area codes too; redacting
		// a non-SSN that happens to share the shape is safe. RE2 has no
		// negative lookahead so the area-code filter can't be encoded here.
		{class: ClassSSN, pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), priority: 95},
		{class: ClassCreditCard, pattern: regexp.MustCompile(`\b(?:3[47]\d{2}[ -]?\d{6}[ -]?\d{5}|(?:4\d{3}|5[1-5]\d{2}|6011|65\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})\b`), priority: 90},
	}
}

// compiledRegistry caches the compiled registry so each call to
// NewDefaultMatcher doesn't pay the regex compile cost.
var (
	compiledRegistryOnce sync.Once
	compiledRegistryVal  []classPattern
)

// defaultRegistry returns the shipped registry, compiled once.
func defaultRegistry() []classPattern {
	compiledRegistryOnce.Do(func() {
		compiledRegistryVal = classRegistry()
		// Sort highest-priority first so span overlap resolution picks the
		// most specific class first.
		sort.SliceStable(compiledRegistryVal, func(i, j int) bool {
			return compiledRegistryVal[i].priority > compiledRegistryVal[j].priority
		})
	})
	return compiledRegistryVal
}
