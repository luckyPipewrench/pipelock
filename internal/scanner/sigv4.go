// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// AWS Signature Version 4 (SigV4) credential carve-out.
//
// AWS signed requests carry an access-key ID in two operating-mechanism
// forms. A presigned URL embeds it in the X-Amz-Credential query parameter.
// A live SDK/CLI call puts it in the Authorization header:
//
//	Authorization: AWS4-HMAC-SHA256 Credential=AKIA.../<scope>,
//	               SignedHeaders=host;x-amz-date, Signature=<64 hex>
//
// Pipelock's core AWS Access ID DLP pattern matches that AKIA and would
// otherwise block every signed request, even though the request is going
// to the issuer's own AWS endpoint and the credential is the signing
// envelope, not a leaked long-lived key.
//
// The carve-out is intentionally narrow:
//
//   - Presigned URLs: all six mandatory SigV4 query parameters must validate
//     structurally and appear exactly once: X-Amz-Algorithm, X-Amz-Credential,
//     X-Amz-Date, X-Amz-Signature, X-Amz-Expires, X-Amz-SignedHeaders. The
//     signed-header list must be well-formed and include host. Duplicate
//     structural fields fall back to normal DLP scanning so a duplicate
//     credential cannot be hidden by the scrub pass and an attacker cannot
//     silence the long-expiry warn by pinning the scanner's view to a short
//     value.
//   - Authorization headers: the value must be a well-formed AWS4-HMAC-SHA256
//     envelope whose Credential, SignedHeaders, and Signature fields each
//     appear exactly once and pass the same structural checks as the query
//     form (minus X-Amz-Expires, which is a presigned-URL lifetime, not a
//     header field). Malformed, truncated, duplicated, or partial envelopes
//     stay under core DLP. The carve-out applies only to the Authorization
//     header, never Proxy-Authorization or a lookalike in another header.
//   - The destination host must match an AWS-published amazonaws.com
//     hostname. The carve-out is for legitimate requests to the issuer's
//     own AWS endpoint; a SigV4-shaped URL or header to an attacker host is
//     not evidence of legitimacy because pipelock cannot verify the HMAC.
//   - The AKIA exemption applies ONLY to the access-key component of a
//     parsed credential scope. AKIA anywhere else (path, hostname, other
//     query params, other headers, subsequence-concatenated values) still
//     blocks with ClassThreat.
//   - The carve-out result is ClassStructuralExemption - adaptive-neutral,
//     not clean-decay. A burst of legitimate presigned fetches must not
//     drive a session's threat score down.
//   - X-Amz-Expires above sigV4LongExpiryThreshold attaches a warn-tier
//     finding for audit visibility. The fetch is still allowed; the real
//     control against long-lived presigned URLs is preventing the URL
//     from being transcribed elsewhere, not blocking the issuer GET.
//
// AWS only in this implementation. Azure SAS, GCS V4 signed URLs, and
// CloudFront signed URLs are the same false-positive class but each has
// different structural rules and bypass surfaces; they are deliberately
// out of scope here.

const (
	// sigV4AlgorithmValue is the canonical SigV4 algorithm identifier.
	sigV4AlgorithmValue = "AWS4-HMAC-SHA256"

	// sigV4CredentialScopeTerminator is the fixed trailing segment of an
	// X-Amz-Credential scope: <key>/<date>/<region>/<service>/aws4_request.
	sigV4CredentialScopeTerminator = "aws4_request"

	// sigV4MaxScopeComponentLen bounds a region or service segment. The
	// longest published AWS region and service names are well under this, so
	// it refuses a padded blob without being close to any real value. A bound
	// is needed because the shape alone accepts any length.
	sigV4MaxScopeComponentLen = 64

	// sigV4CredentialScopeSegments is the required segment count after
	// splitting an X-Amz-Credential value on "/".
	sigV4CredentialScopeSegments = 5

	// sigV4AccessKeyLength is the exact length of AWS access key IDs:
	// 20 characters. AWS uses both 4-char prefixes (AKIA, ASIA, AGPA, AIDA,
	// AROA, AIPA, ANPA, ANVA) and the 3-char A3T prefix; in all cases the
	// total key length is 20. The immutable core DLP regex intentionally
	// accepts longer runs so it catches secrets embedded in surrounding
	// text. The carve-out must be stricter so it never scrubs
	// attacker-appended suffix material.
	sigV4AccessKeyLength = 20

	// sigV4LongExpiryThreshold is the X-Amz-Expires value (in seconds)
	// above which a SigV4 carve-out attaches a warn-tier finding. AWS's
	// default presigned URL expiry is 3600s; anything beyond 24h is
	// operationally unusual and worth surfacing.
	sigV4LongExpiryThreshold = 86400

	// sigV4MaxExpirySeconds is AWS S3's maximum presigned URL lifetime.
	// Values above seven days cannot represent a valid S3 presigned URL.
	sigV4MaxExpirySeconds = 604800

	// WarnPatternSigV4LongExpiry is the warn-match pattern name emitted
	// when a SigV4 carve-out fires with an unusually long X-Amz-Expires.
	WarnPatternSigV4LongExpiry = "SigV4 Long Expiry"

	// sigV4AccessKeyPlaceholderRune is the byte used to fill the AKIA
	// span when scrubbing a credential value for re-scan. Lowercase
	// ASCII does not match the core AWS Access ID regex, which anchors
	// on uppercase prefixes (AKIA, ASIA, …).
	sigV4AccessKeyPlaceholderRune = 'a'

	// SigV4 Authorization header field names. Exact case; a lowercase or
	// mixed-case lookalike is not a well-formed envelope and stays under
	// core DLP.
	sigV4AuthFieldCredential    = "Credential"
	sigV4AuthFieldSignedHeaders = "SignedHeaders"
	sigV4AuthFieldSignature     = "Signature"
)

// sigV4CredentialQueryKey is the URL-encoded representation of the
// X-Amz-Credential parameter as it appears in a raw query string.
// Used by the order-preserving scrubber to locate the right pair
// without going through url.Values (which sorts on Encode()).
// Built at runtime to keep gosec G101 from flagging the literal as
// a hardcoded credential.
var sigV4CredentialQueryKey = "X-Amz-" + "Credential"

var (
	// sigV4AccessKeyAnchored mirrors the AWS Access ID shape but is exact.
	// Every alternation yields a 20-character access-key ID: 4-char prefixes
	// plus 16 trailing alphanumerics, or the 3-char A3T prefix plus a 4th
	// alphanumeric plus 16 more (also 20 total). The immutable core DLP
	// pattern is deliberately wider ({16,}) because it scans arbitrary text.
	sigV4AccessKeyAnchored = regexp.MustCompile(`^(AKIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$`)

	// sigV4DateValueRe matches the X-Amz-Date format: YYYYMMDDTHHMMSSZ.
	// Structural only; we do not validate that the date is real.
	sigV4DateValueRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

	// sigV4SignatureRe matches the hex-encoded HMAC-SHA256 signature
	// (case-insensitive). Some SDKs emit upper-case hex, others lower.
	sigV4SignatureRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

	// sigV4ScopeDateRe matches the YYYYMMDD prefix of a credential scope.
	sigV4ScopeDateRe = regexp.MustCompile(`^[0-9]{8}$`)

	// sigV4ScopeComponentRe matches the region and service segments of a
	// credential scope. AWS's SigV4 signing reference specifies the scope as
	// date/region/service/aws4_request with lowercase region and service
	// names, and every published region ("us-east-1", "ap-southeast-2",
	// "eu-central-1", "il-central-1") and service ("s3", "execute-api",
	// "dynamodb") fits this shape.
	//
	// It is deliberately the SHAPE rather than an enumeration. A list of
	// regions and services is a value that rots: AWS adds both, and a
	// carve-out that refuses a real new region would make Pipelock block a
	// legitimate signed request to the customer's own endpoint, which is the
	// availability failure an operator responds to by turning the check off.
	//
	// WHAT THIS BUYS, stated precisely because an earlier round got it wrong:
	// correctness and a smaller accepted-input surface, NOT secret
	// containment. The parser previously accepted any non-empty region and
	// service, so it admitted values AWS itself would never produce. It is
	// TEMPTING to call that a secret-containment fix, because a 40-character
	// secret-shaped value fits either field. It is not one: the same value
	// also travels as "Bearer <value>" and bare, so tightening this grammar
	// closes one field while every other route stays open. ACCEPTED RESIDUAL,
	// recorded rather than discovered later: an all-lowercase-hex
	// 40-character value still fits this shape, and one of 64 hex characters
	// still fits the Signature field. Containment is a different control.
	sigV4ScopeComponentRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

	// sigV4SignedHeaderNameRe accepts the lowercase header-name shape used
	// in SigV4 canonical requests. Empty or malformed list members invalidate
	// the carve-out and leave the credential for immutable DLP enforcement.
	sigV4SignedHeaderNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

	// sigV4AmazonHostSuffixes lists DNS suffixes for AWS-issued endpoints
	// that legitimately emit presigned URLs. The carve-out only fires when
	// parsed.Hostname() matches one of these (case-insensitive). Pipelock
	// cannot verify the HMAC of a SigV4 URL, so structural validity alone
	// is not evidence of legitimacy: a presigned-looking URL pointing at
	// an attacker host would let an attacker exfiltrate an AKIA-shaped
	// value via the scrub-then-fetch path. The suffix is registered to AWS,
	// so a third party cannot claim the DOMAIN - but this gate is weaker
	// than that fact suggests, and the difference matters. S3 bucket names
	// become hostnames under it and anyone with an AWS account can register
	// one, so a request to a bucket an attacker controls satisfies this
	// gate. What the gate rules out is an arbitrary attacker-operated
	// origin; it does not establish that the destination belongs to the
	// operator. Deciding WHICH AWS destinations an agent may reach is
	// destination policy, not DLP. Path-style and virtual-hosted S3, FIPS,
	// and access-point hostnames all live under this suffix, which is why
	// the gate cannot simply demand a service-shaped hostname.
	sigV4AmazonHostSuffixes = []string{
		".amazonaws.com",
		".amazonaws.com.cn", // AWS China regions
	}
)

// sigV4Detection captures the result of structurally validating a presigned
// URL's SigV4 query parameters. KeyID is the AKIA/ASIA portion extracted
// from X-Amz-Credential when Valid is true; otherwise it is empty.
type sigV4Detection struct {
	Valid   bool
	KeyID   string
	Expires int
}

// detectValidSigV4 returns the access-key inside the X-Amz-Credential value
// when the URL carries a structurally valid AWS Signature Version 4 query
// set hosted on an AWS-issued amazonaws.com endpoint. Strict by design:
// all six mandatory parameters must pass their format check and appear
// exactly once, and the destination host must be AWS-owned. An invalid or
// partial set returns Valid=false and leaves the caller to fall through
// to the normal core DLP scan.
//
// This function does NOT prove the signature is cryptographically valid;
// pipelock has no AWS credentials to compute the HMAC, and verifying
// would require a network call defeating the purpose. The structural
// check plus the AWS-host gate is sufficient to distinguish "AKIA living
// inside a SigV4-shaped presigned URL fetched from AWS S3" (carve-out)
// from "AKIA appearing bare or wrapped in arbitrary URL content"
// (block).
func detectValidSigV4(parsed *url.URL) sigV4Detection {
	if parsed == nil {
		return sigV4Detection{}
	}
	if !isAWSEndpointHost(parsed.Hostname()) {
		return sigV4Detection{}
	}

	params, ok := extractSigV4FieldsLiteralKeyed(parsed.RawQuery)
	if !ok {
		return sigV4Detection{}
	}

	if params["X-Amz-Algorithm"] != sigV4AlgorithmValue {
		return sigV4Detection{}
	}
	date := params["X-Amz-Date"]
	if !sigV4DateValueRe.MatchString(date) {
		return sigV4Detection{}
	}
	if !sigV4SignatureRe.MatchString(params["X-Amz-Signature"]) {
		return sigV4Detection{}
	}
	if !validSigV4SignedHeaders(params["X-Amz-SignedHeaders"]) {
		return sigV4Detection{}
	}

	keyID, credDate, ok := parseSigV4Credential(params["X-Amz-Credential"])
	if !ok {
		return sigV4Detection{}
	}
	if credDate != date[:8] {
		return sigV4Detection{}
	}

	// X-Amz-Expires is mandatory and must be a positive integer. Real
	// presigned URLs always carry it; making it optional would let an
	// attacker omit the field to silence the long-expiry audit warn
	// while still earning the carve-out.
	expRaw := params["X-Amz-Expires"]
	if expRaw == "" {
		return sigV4Detection{}
	}
	expires, err := strconv.Atoi(expRaw)
	if err != nil || expires <= 0 || expires > sigV4MaxExpirySeconds {
		return sigV4Detection{}
	}

	return sigV4Detection{Valid: true, KeyID: keyID, Expires: expires}
}

// parseSigV4Credential validates the five-segment SigV4 credential scope
// shared by X-Amz-Credential query values and Authorization Credential=
// fields: <key>/<date>/<region>/<service>/aws4_request. Empty region or
// service, the wrong segment count, or a non-exact access-key ID fail
// closed so the caller leaves the value for core DLP.
func parseSigV4Credential(cred string) (keyID, date string, ok bool) {
	if cred == "" {
		return "", "", false
	}
	parts := strings.Split(cred, "/")
	if len(parts) != sigV4CredentialScopeSegments {
		return "", "", false
	}
	if parts[sigV4CredentialScopeSegments-1] != sigV4CredentialScopeTerminator {
		return "", "", false
	}
	if !sigV4AccessKeyAnchored.MatchString(parts[0]) {
		return "", "", false
	}
	if !sigV4ScopeDateRe.MatchString(parts[1]) {
		return "", "", false
	}
	if !sigV4ScopeComponentRe.MatchString(parts[2]) || !sigV4ScopeComponentRe.MatchString(parts[3]) {
		return "", "", false
	}
	if len(parts[2]) > sigV4MaxScopeComponentLen || len(parts[3]) > sigV4MaxScopeComponentLen {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func validSigV4SignedHeaders(raw string) bool {
	if raw == "" {
		return false
	}
	hasHost := false
	previous := ""
	for _, name := range strings.Split(raw, ";") {
		if !sigV4SignedHeaderNameRe.MatchString(name) {
			return false
		}
		if previous != "" && name <= previous {
			return false
		}
		previous = name
		if name == "host" {
			hasHost = true
		}
	}
	return hasHost
}

// extractSigV4FieldsLiteralKeyed walks RawQuery and returns a map of
// the six mandatory SigV4 parameter values keyed by their canonical
// literal names (X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date,
// X-Amz-Signature, X-Amz-Expires, X-Amz-SignedHeaders).
//
// Keys are compared byte-for-byte against the canonical literal - no
// percent-decoding on the key side. This keeps the detector and the
// order-preserving scrubber in lockstep: an attacker who crafts a URL
// with percent-encoded SigV4 key names (e.g. X%2DAmz%2DCredential)
// would otherwise pass the detector (which used parsed.Query() to
// canonicalize keys before lookup) while the scrubber's literal-key
// match in RawQuery missed the pair entirely, leaving the AKIA
// un-scrubbed and the result still flagged ClassStructuralExemption.
//
// Returns ok=false on any duplicate of a known SigV4 field or on a
// value whose percent-encoding is malformed. Unknown query keys are
// ignored. Missing SigV4 fields are reported as zero-length strings;
// the caller is responsible for rejecting empties.
func extractSigV4FieldsLiteralKeyed(rawQuery string) (map[string]string, bool) {
	known := map[string]struct{}{
		"X-Amz-Algorithm":     {},
		"X-Amz-Credential":    {},
		"X-Amz-Date":          {},
		"X-Amz-Signature":     {},
		"X-Amz-Expires":       {},
		"X-Amz-SignedHeaders": {},
	}
	out := map[string]string{}
	if rawQuery == "" {
		return out, true
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		rawKey, rawValue, ok := strings.Cut(pair, "=")
		if !ok {
			if _, isKnown := known[rawKey]; isKnown {
				return nil, false
			}
			continue
		}
		if _, isKnown := known[rawKey]; !isKnown {
			continue
		}
		if _, dup := out[rawKey]; dup {
			return nil, false
		}
		decodedValue, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, false
		}
		out[rawKey] = decodedValue
	}
	return out, true
}

// isAWSEndpointHost reports whether hostname terminates in one of the
// known AWS-issued DNS suffixes. The match is case-insensitive and
// requires a true suffix (not a substring), so attacker-controlled hosts
// like example.com.evil.tld cannot impersonate an AWS endpoint.
// sigV4EncryptedScheme reports whether the destination scheme protects the
// forwarded Authorization header in transit. An empty, unknown, or cleartext
// scheme is not evidence of protection and fails closed.
func sigV4EncryptedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "https", "wss":
		return true
	default:
		return false
	}
}

func isAWSEndpointHost(hostname string) bool {
	if hostname == "" {
		return false
	}
	h := strings.ToLower(hostname)
	for _, suf := range sigV4AmazonHostSuffixes {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

// scrubSigV4Credential returns a clone of parsed with the access-key
// component of X-Amz-Credential replaced by a same-length lowercase
// placeholder. The rest of the credential value (date / region / service /
// aws4_request) is preserved verbatim. All other URL components - path,
// hostname, other query parameters, AND their order - are left untouched
// so any AKIA living outside the credential field is still scanned and
// blocked, including by the ordered-subsequence detector in
// querySubsequenceCoreDLP which reads pairs from RawQuery in iteration
// order.
//
// Callers must only invoke this with akia equal to a value previously
// returned by detectValidSigV4 against the same parsed URL. The function
// returns the original parsed pointer unchanged when the credential
// value does not start with the expected access-key prefix, so a stale
// or mismatched detection cannot accidentally widen the carve-out.
//
// The scrub does NOT use url.Values.Encode() because Encode() sorts
// query keys alphabetically. Re-ordering breaks the ordered-subsequence
// DLP detector: an attacker could split a non-AKIA secret across two
// query params whose iteration order in the original RawQuery yields a
// matching concatenation but whose alphabetical order does not. Walking
// RawQuery as &-split pairs and rewriting only the credential value's
// access-key span preserves every other byte verbatim.
func scrubSigV4Credential(parsed *url.URL, akia string) *url.URL {
	if parsed == nil || akia == "" {
		return parsed
	}
	if parsed.RawQuery == "" {
		return parsed
	}

	pairs := strings.Split(parsed.RawQuery, "&")
	credPairs := 0
	credIdx := -1
	for i, pair := range pairs {
		k, _, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if k == sigV4CredentialQueryKey {
			credPairs++
			credIdx = i
		}
	}
	// Duplicate-credential defence: detectValidSigV4 already rejects this
	// case, but a future caller might invoke scrub without the gate. Bail
	// out rather than silently scrubbing only the first occurrence.
	if credPairs != 1 || credIdx < 0 {
		return parsed
	}

	pair := pairs[credIdx]
	_, encodedValue, _ := strings.Cut(pair, "=")
	decodedValue, err := url.QueryUnescape(encodedValue)
	if err != nil {
		return parsed
	}
	scopeParts := strings.SplitN(decodedValue, "/", 2)
	if len(scopeParts) == 0 || len(scopeParts[0]) != sigV4AccessKeyLength || scopeParts[0] != akia {
		return parsed
	}

	placeholder := strings.Repeat(string(sigV4AccessKeyPlaceholderRune), len(scopeParts[0]))
	rebuiltDecoded := placeholder
	if len(scopeParts) == 2 {
		rebuiltDecoded = placeholder + "/" + scopeParts[1]
	}
	pairs[credIdx] = sigV4CredentialQueryKey + "=" + url.QueryEscape(rebuiltDecoded)

	clone := *parsed
	clone.RawQuery = strings.Join(pairs, "&")
	return &clone
}

// scrubEmbeddedSigV4Credentials applies the structural portion of the
// presigned-URL carve-out to complete URL tokens embedded in inspected text.
// Destination authorization is deliberately outside this helper.
//
// Only a URL that passes detectValidSigV4 is changed, and only the access-key
// component of its X-Amz-Credential value is replaced. A credential elsewhere
// in the text or URL, a malformed SigV4 field set, duplicate fields, or a URL
// on a non-AWS host remains untouched for the immutable DLP floor to block.
func scrubEmbeddedSigV4Credentials(text string) (string, []sigV4Detection) {
	if !strings.Contains(text, "://") || !strings.Contains(text, sigV4CredentialQueryKey) {
		return text, nil
	}

	var detections []sigV4Detection
	scrubbed := textURLTokenRe.ReplaceAllStringFunc(text, func(token string) string {
		parsed, err := url.Parse(token)
		if err != nil {
			return token
		}
		detection := detectValidSigV4(parsed)
		if !detection.Valid {
			return token
		}
		detections = append(detections, detection)
		return scrubSigV4Credential(parsed, detection.KeyID).String()
	})
	return scrubbed, detections
}

// ScrubSigV4AuthorizationForTarget returns a scan-only copy of value with the
// access-key ID replaced by a same-length lowercase placeholder when target
// is an AWS-issued endpoint and value is a structurally valid SigV4
// Authorization envelope. Callers must keep the original value for
// forwarding. Any other destination or any malformed envelope is returned
// unchanged so core DLP still sees the access-key ID.
func ScrubSigV4AuthorizationForTarget(value, target string) string {
	host := ""
	scheme := ""
	if target != "" {
		parsed, err := url.Parse(target)
		if err == nil {
			host = parsed.Hostname()
			scheme = parsed.Scheme
		}
	}
	// A real AWS API call is always over TLS. Over cleartext the forwarded
	// header would put the access-key ID on the wire in the clear, so an
	// http:// or ws:// destination keeps the value under core DLP even when
	// the hostname is AWS-issued.
	if !sigV4EncryptedScheme(scheme) {
		return value
	}
	if !isAWSEndpointHost(host) {
		return value
	}
	detection := detectValidSigV4Authorization(value)
	if !detection.Valid {
		return value
	}
	return scrubSigV4Authorization(value, detection.KeyID)
}

// detectValidSigV4Authorization reports whether value is a well-formed SigV4
// Authorization envelope. Strict by design: the scheme must be the canonical
// AWS4-HMAC-SHA256 token, and Credential, SignedHeaders, and Signature must
// each appear exactly once with no unknown fields. This does not prove the
// HMAC; pipelock has no AWS credentials to verify it.
func detectValidSigV4Authorization(value string) sigV4Detection {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, sigV4AlgorithmValue) {
		return sigV4Detection{}
	}
	rest := value[len(sigV4AlgorithmValue):]
	if rest == "" {
		return sigV4Detection{}
	}
	switch rest[0] {
	case ' ', '\t':
	default:
		return sigV4Detection{}
	}
	rest = strings.TrimSpace(rest)
	fields, ok := extractSigV4AuthorizationFields(rest)
	if !ok || len(fields) != 3 {
		return sigV4Detection{}
	}
	// extractSigV4AuthorizationFields admits only the three known keys and
	// rejects duplicates, so exactly three fields means all three are present.
	cred := fields[sigV4AuthFieldCredential]
	signed := fields[sigV4AuthFieldSignedHeaders]
	sig := fields[sigV4AuthFieldSignature]
	if !sigV4SignatureRe.MatchString(sig) {
		return sigV4Detection{}
	}
	if !validSigV4SignedHeaders(signed) {
		return sigV4Detection{}
	}
	keyID, _, ok := parseSigV4Credential(cred)
	if !ok {
		return sigV4Detection{}
	}
	return sigV4Detection{Valid: true, KeyID: keyID}
}

// extractSigV4AuthorizationFields walks the comma-separated k=v tail of a
// SigV4 Authorization value. Keys are compared byte-for-byte against the
// canonical field names. Duplicate known fields, unknown fields, missing
// equals, or empty names/values fail closed.
func extractSigV4AuthorizationFields(rest string) (map[string]string, bool) {
	known := map[string]struct{}{
		sigV4AuthFieldCredential:    {},
		sigV4AuthFieldSignedHeaders: {},
		sigV4AuthFieldSignature:     {},
	}
	out := map[string]string{}
	if rest == "" {
		return nil, false
	}
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, false
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return nil, false
		}
		if _, isKnown := known[key]; !isKnown {
			return nil, false
		}
		if _, dup := out[key]; dup {
			return nil, false
		}
		out[key] = value
	}
	return out, true
}

// scrubSigV4Authorization replaces the single access-key ID span in a
// previously validated Authorization envelope. If the key ID is absent,
// duplicated, or the wrong length, the original value is returned so core
// DLP still sees it.
func scrubSigV4Authorization(value, akia string) string {
	if value == "" || akia == "" || len(akia) != sigV4AccessKeyLength {
		return value
	}
	if strings.Count(value, akia) != 1 {
		return value
	}
	placeholder := strings.Repeat(string(sigV4AccessKeyPlaceholderRune), len(akia))
	return strings.Replace(value, akia, placeholder, 1)
}
