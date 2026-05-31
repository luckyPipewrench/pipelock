// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// AWS Signature Version 4 (SigV4) presigned URL carve-out.
//
// A presigned URL embeds an AWS access-key ID inside the X-Amz-Credential
// query parameter. The full URL is a scoped bearer capability for a single
// S3 object until X-Amz-Expires elapses. Pipelock's core AWS Access ID DLP
// pattern matches that AKIA and blocks the GET, even though the request is
// going to the issuer's own S3 host and the credential is the operating
// mechanism, not a leaked long-lived key.
//
// The carve-out is intentionally narrow:
//
//   - All five mandatory SigV4 query parameters must validate structurally
//     and appear exactly once: X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date,
//     X-Amz-Signature, X-Amz-Expires. Duplicate structural fields fall back
//     to normal DLP scanning so a duplicate credential cannot be hidden by
//     the scrub pass and an attacker cannot silence the long-expiry warn
//     by pinning the scanner's view to a short value.
//   - The destination host must match an AWS-published amazonaws.com
//     hostname. The carve-out is for legitimate fetches to the issuer's
//     own S3 endpoint; a SigV4-shaped URL to an attacker host is not
//     evidence of legitimacy because pipelock cannot verify the HMAC.
//   - The AKIA exemption applies ONLY to the access-key component of a
//     parsed X-Amz-Credential value. AKIA anywhere else in the URL (path,
//     hostname, other query params, subsequence-concatenated values) still
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

	// WarnPatternSigV4LongExpiry is the warn-match pattern name emitted
	// when a SigV4 carve-out fires with an unusually long X-Amz-Expires.
	WarnPatternSigV4LongExpiry = "SigV4 Long Expiry"

	// sigV4AccessKeyPlaceholderRune is the byte used to fill the AKIA
	// span when scrubbing a credential value for re-scan. Lowercase
	// ASCII does not match the core AWS Access ID regex, which anchors
	// on uppercase prefixes (AKIA, ASIA, …).
	sigV4AccessKeyPlaceholderRune = 'a'
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

	// sigV4AmazonHostSuffixes lists DNS suffixes for AWS-issued endpoints
	// that legitimately emit presigned URLs. The carve-out only fires when
	// parsed.Hostname() matches one of these (case-insensitive). Pipelock
	// cannot verify the HMAC of a SigV4 URL, so structural validity alone
	// is not evidence of legitimacy: a presigned-looking URL pointing at
	// an attacker host would let an attacker exfiltrate an AKIA-shaped
	// value via the scrub-then-fetch path. *.amazonaws.com is registered
	// to AWS and cannot be claimed by a third party, so the suffix gate is
	// effective. Path-style and virtual-hosted S3, FIPS, and access-point
	// hostnames all live under this suffix.
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
// all five mandatory parameters must pass their format check and appear
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

	cred := params["X-Amz-Credential"]
	if cred == "" {
		return sigV4Detection{}
	}
	parts := strings.Split(cred, "/")
	if len(parts) != sigV4CredentialScopeSegments {
		return sigV4Detection{}
	}
	if parts[sigV4CredentialScopeSegments-1] != sigV4CredentialScopeTerminator {
		return sigV4Detection{}
	}
	if !sigV4AccessKeyAnchored.MatchString(parts[0]) {
		return sigV4Detection{}
	}
	if !sigV4ScopeDateRe.MatchString(parts[1]) {
		return sigV4Detection{}
	}
	if parts[1] != date[:8] {
		return sigV4Detection{}
	}
	if parts[2] == "" || parts[3] == "" {
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
	if err != nil || expires <= 0 {
		return sigV4Detection{}
	}

	return sigV4Detection{Valid: true, KeyID: parts[0], Expires: expires}
}

// extractSigV4FieldsLiteralKeyed walks RawQuery and returns a map of
// the five mandatory SigV4 parameter values keyed by their canonical
// literal names (X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date,
// X-Amz-Signature, X-Amz-Expires).
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
		"X-Amz-Algorithm":  {},
		"X-Amz-Credential": {},
		"X-Amz-Date":       {},
		"X-Amz-Signature":  {},
		"X-Amz-Expires":    {},
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
