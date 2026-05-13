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
//   - All four mandatory SigV4 query parameters must validate structurally:
//     X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Signature.
//     These fields must be singletons. Duplicate structural fields fall back
//     to normal DLP scanning so a duplicate credential cannot be hidden by
//     the scrub pass.
//   - The AKIA exemption applies ONLY to the access-key component of a
//     parsed X-Amz-Credential value. AKIA anywhere else in the URL (path,
//     hostname, other query params, subsequence-concatenated values) still
//     blocks with ClassThreat.
//   - The carve-out result is ClassStructuralExemption — adaptive-neutral,
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
	// four-character prefix plus sixteen uppercase alphanumeric characters.
	// The immutable core DLP regex intentionally accepts longer runs so it
	// catches secrets embedded in surrounding text. The carve-out must be
	// stricter so it never scrubs attacker-appended suffix material.
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

var (
	// sigV4AccessKeyAnchored mirrors the AWS Access ID shape but is exact.
	// The core pattern is deliberately wider ({16,}) because it scans
	// arbitrary text. The carve-out is a structural exemption and must only
	// scrub the exact key ID field length used by SigV4 credential scopes.
	sigV4AccessKeyAnchored = regexp.MustCompile(`^(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$`)

	// sigV4DateValueRe matches the X-Amz-Date format: YYYYMMDDTHHMMSSZ.
	// Structural only; we do not validate that the date is real.
	sigV4DateValueRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

	// sigV4SignatureRe matches the hex-encoded HMAC-SHA256 signature
	// (case-insensitive). Some SDKs emit upper-case hex, others lower.
	sigV4SignatureRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

	// sigV4ScopeDateRe matches the YYYYMMDD prefix of a credential scope.
	sigV4ScopeDateRe = regexp.MustCompile(`^[0-9]{8}$`)
)

// sigV4Detection captures the result of structurally validating a presigned
// URL's SigV4 query parameters. KeyID is the AKIA/ASIA portion extracted
// from X-Amz-Credential when Valid is true; otherwise it is empty.
type sigV4Detection struct {
	Valid   bool
	KeyID   string
	Expires int // 0 when absent or unparseable
}

// detectValidSigV4 returns the AKIA inside the X-Amz-Credential value when
// the URL carries a structurally valid AWS Signature Version 4 query set.
// Strict by design: all four mandatory parameters must pass their format
// check. An invalid or partial set returns Valid=false and leaves the
// caller to fall through to the normal core DLP scan.
//
// This function does NOT prove the signature is cryptographically valid;
// pipelock has no AWS credentials to compute the HMAC, and verifying
// would require a network call defeating the purpose. The structural
// check is sufficient to distinguish "AKIA living inside a SigV4-shaped
// presigned URL" (carve-out) from "AKIA appearing bare in arbitrary URL
// content" (block).
func detectValidSigV4(parsed *url.URL) sigV4Detection {
	if parsed == nil {
		return sigV4Detection{}
	}
	q := parsed.Query()

	alg, ok := sigV4Singleton(q, "X-Amz-Algorithm")
	if !ok || alg != sigV4AlgorithmValue {
		return sigV4Detection{}
	}
	date, ok := sigV4Singleton(q, "X-Amz-Date")
	if !ok || !sigV4DateValueRe.MatchString(date) {
		return sigV4Detection{}
	}
	signature, ok := sigV4Singleton(q, "X-Amz-Signature")
	if !ok || !sigV4SignatureRe.MatchString(signature) {
		return sigV4Detection{}
	}

	cred, ok := sigV4Singleton(q, "X-Amz-Credential")
	if !ok || cred == "" {
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

	det := sigV4Detection{Valid: true, KeyID: parts[0]}

	// X-Amz-Expires is optional, but if present must be a singleton: a
	// second value can let an attacker silence the long-expiry warn by
	// pinning the carve-out check to a short value while AWS SDKs that
	// honour the last value still issue a long-lived URL.
	if expValues, ok := q["X-Amz-Expires"]; ok {
		if len(expValues) != 1 {
			return sigV4Detection{}
		}
		if v, err := strconv.Atoi(expValues[0]); err == nil && v > 0 {
			det.Expires = v
		}
	}
	return det
}

func sigV4Singleton(q url.Values, key string) (string, bool) {
	values, ok := q[key]
	if !ok || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

// scrubSigV4Credential returns a clone of parsed with the access-key
// component of X-Amz-Credential replaced by a same-length lowercase
// placeholder. The rest of the credential value (date / region / service /
// aws4_request) is preserved verbatim. All other URL components — path,
// hostname, other query parameters — are left untouched so any AKIA
// living outside the credential field is still scanned and blocked.
//
// Callers must only invoke this with akia equal to a value previously
// returned by detectValidSigV4 against the same parsed URL. The function
// returns the original parsed pointer unchanged when the credential
// value does not start with the expected access-key prefix, so a stale
// or mismatched detection cannot accidentally widen the carve-out.
func scrubSigV4Credential(parsed *url.URL, akia string) *url.URL {
	if parsed == nil || akia == "" {
		return parsed
	}
	q := parsed.Query()
	values := q["X-Amz-Credential"]
	if len(values) != 1 {
		return parsed
	}
	cred := values[0]
	if cred == "" {
		return parsed
	}
	parts := strings.SplitN(cred, "/", 2)
	if len(parts) == 0 || len(parts[0]) != sigV4AccessKeyLength || parts[0] != akia {
		return parsed
	}

	placeholder := strings.Repeat(string(sigV4AccessKeyPlaceholderRune), len(parts[0]))
	rebuilt := placeholder
	if len(parts) == 2 {
		rebuilt = placeholder + "/" + parts[1]
	}

	clone := *parsed
	cq := clone.Query()
	cq["X-Amz-Credential"] = []string{rebuilt}
	// cq.Encode() sorts keys alphabetically and percent-encodes the "/"
	// inside the credential value. The scrubbed URL is only used as the
	// scan target for DLP and entropy checks; the actual network fetch
	// uses the original RawQuery. IterativeDecode in checkCoreDLP
	// normalises %2F back, so the byte-level divergence does not affect
	// pattern matching.
	clone.RawQuery = cq.Encode()
	return &clone
}
