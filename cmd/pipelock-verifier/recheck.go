// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const transformProfileV1 = "pipelock-transform-v1"

// Recheck location strengths. A recheck that matched at the signed coordinates
// is a strictly stronger claim than one that only found the sample somewhere in
// the reproduced view, so the two are reported separately instead of collapsing
// into a single boolean.
const (
	recheckLocationExact      = "exact_coordinates"
	recheckLocationOccurrence = "occurrence_only"
	recheckLocationFailed     = "failed"
)

// Recheck signature stages. A recheck says nothing about who produced the
// receipt; that is the signature stage's job. Reported as a sibling of the
// location result. A positive location is withheld entirely when the
// producer is unauthenticated, so it cannot be read as a pass.
const (
	recheckSignatureVerified   = "verified"
	recheckSignatureNotChecked = "not_checked"
)

// Recheck overall verdicts.
const (
	recheckOverallVerified   = "verified"
	recheckOverallIncomplete = "incomplete"
	recheckOverallFailed     = "failed"
)

type recheckResult struct {
	// Location is the strength of the positional claim, not an overall
	// verdict. It is deliberately not a bool: a substring hit and a match at
	// the signed coordinates are different facts.
	Location string
	View     string
}

func recheckEvidenceReceiptSpan(r contractreceipt.EvidenceReceipt, sourcePath string, spanIndex int) (recheckResult, error) {
	if r.PayloadKind != contractreceipt.PayloadProxyDecisionWithSpans {
		return recheckResult{Location: recheckLocationFailed}, fmt.Errorf("--recheck-source requires payload_kind=%s", contractreceipt.PayloadProxyDecisionWithSpans)
	}
	if spanIndex < 0 {
		return recheckResult{Location: recheckLocationFailed}, fmt.Errorf("--recheck-span-index must be non-negative")
	}
	var payload contractreceipt.PayloadProxyDecisionWithSpansStruct
	if err := json.Unmarshal(r.Payload, &payload); err != nil {
		return recheckResult{Location: recheckLocationFailed}, fmt.Errorf("decode spanned payload: %w", err)
	}
	if spanIndex >= len(payload.SourceSpans) {
		return recheckResult{Location: recheckLocationFailed}, fmt.Errorf("--recheck-span-index=%d outside source_spans length %d", spanIndex, len(payload.SourceSpans))
	}
	span := payload.SourceSpans[spanIndex]
	if span.TransformProfile != transformProfileV1 {
		return recheckResult{Location: recheckLocationFailed}, fmt.Errorf("unsupported transform_profile %q", span.TransformProfile)
	}
	if span.RedactedSample == "" {
		return recheckResult{Location: recheckLocationFailed}, fmt.Errorf("source_spans[%d].redacted_sample is required for recheck", spanIndex)
	}
	source, err := readVerifierFile(sourcePath)
	if err != nil {
		return recheckResult{Location: recheckLocationFailed}, fmt.Errorf("read recheck source: %w", err)
	}
	view, err := reproduceSpanView(string(source), span.NormalizedView)
	if err != nil {
		return recheckResult{Location: recheckLocationFailed}, err
	}
	if span.CharOffset != nil && span.CharLength != nil {
		runes := []rune(view)
		end := *span.CharOffset + *span.CharLength
		if *span.CharOffset < 0 || end > len(runes) {
			return recheckResult{Location: recheckLocationFailed, View: span.NormalizedView}, fmt.Errorf("source_spans[%d] coordinates outside reproduced view", spanIndex)
		}
		if string(runes[*span.CharOffset:end]) != span.RedactedSample {
			return recheckResult{Location: recheckLocationFailed, View: span.NormalizedView}, fmt.Errorf("source_spans[%d] redacted_sample mismatch at signed coordinates", spanIndex)
		}
		return recheckResult{Location: recheckLocationExact, View: span.NormalizedView}, nil
	}
	if !strings.Contains(view, span.RedactedSample) {
		return recheckResult{Location: recheckLocationFailed, View: span.NormalizedView}, fmt.Errorf("source_spans[%d] redacted_sample not found in reproduced view", spanIndex)
	}
	return recheckResult{Location: recheckLocationOccurrence, View: span.NormalizedView}, nil
}

// recheckReport is the staged, machine-readable recheck outcome.
//
// Only `overall` is authoritative for a gating decision. A positive positional
// result is structurally UNAVAILABLE at the authoritative path unless the
// producing signature was verified: when the receipt is unauthenticated the
// location moves into UnauthenticatedDiagnostic and the top-level Location is
// empty. Documenting "read signature too" is not enough, because an automation
// consumer keying off `location != "failed"` would still accept an
// attacker-supplied unpinned receipt paired with an attacker-chosen source
// file. Removing the field is what actually prevents that.
type recheckReport struct {
	View string `json:"view,omitempty"`
	// Location is populated ONLY when Signature is verified.
	Location  string `json:"location,omitempty"`
	Signature string `json:"signature"`
	Overall   string `json:"overall"`
	// UnauthenticatedDiagnostic carries the positional result for an
	// unauthenticated receipt. It is explicitly non-authoritative and must
	// never be used for a pass/fail decision.
	UnauthenticatedDiagnostic *recheckDiagnostic `json:"unauthenticated_diagnostic,omitempty"`
}

// recheckDiagnostic is human-facing detail about an UNAUTHENTICATED recheck.
// It exists so an operator running --allow-unpinned can still see what was
// found, without exposing a positive result under a field name an automated
// gate would trust.
type recheckDiagnostic struct {
	Location string `json:"location"`
}

// newRecheckReport stages a recheck outcome against whether the receipt's
// signature was authenticated.
//
// Overall is "verified" ONLY when the sample matched at the signed coordinates
// AND a trusted key authenticated the producer. An unpinned recheck is at best
// "incomplete", never "verified": locating bytes in a caller-supplied file
// proves nothing about who asserted them, so a positive location on an
// unauthenticated receipt must not read as a passing result.
func newRecheckReport(result recheckResult, signatureVerified bool) recheckReport {
	sig := recheckSignatureNotChecked
	if signatureVerified {
		sig = recheckSignatureVerified
	}
	var overall string
	switch {
	case result.Location == recheckLocationFailed:
		overall = recheckOverallFailed
	case !signatureVerified:
		overall = recheckOverallIncomplete
	case result.Location == recheckLocationExact:
		overall = recheckOverallVerified
	default:
		// Located by occurrence only: the sample exists somewhere in the
		// reproduced view but not provably at the signed position.
		// Authenticated, but not a complete positional claim.
		overall = recheckOverallIncomplete
	}
	if !signatureVerified {
		// Withhold the positive location from the authoritative field. An
		// unauthenticated recheck can still be inspected by a human via the
		// diagnostic, but there is no field an automated gate would read as a
		// pass.
		return recheckReport{
			View:                      result.View,
			Signature:                 sig,
			Overall:                   overall,
			UnauthenticatedDiagnostic: &recheckDiagnostic{Location: result.Location},
		}
	}
	return recheckReport{View: result.View, Location: result.Location, Signature: sig, Overall: overall}
}

func reproduceSpanView(source, view string) (string, error) {
	switch {
	case view == contractreceipt.NormalizedViewSanitizedTarget:
		return source, nil
	case view == contractreceipt.NormalizedViewForMatching:
		return normalize.ForMatching(source), nil
	case view == contractreceipt.NormalizedViewInvisibleSpaced:
		return normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(source)), nil
	case view == contractreceipt.NormalizedViewLeetspeak:
		return normalize.Leetspeak(normalize.ForMatching(source)), nil
	case view == contractreceipt.NormalizedViewVowelFold:
		return normalize.FoldVowels(normalize.ForMatching(source)), nil
	case view == contractreceipt.NormalizedViewDLPNormalized || strings.HasPrefix(view, "dlp_normalized:"):
		return normalize.ForDLP(source), nil
	case view == contractreceipt.NormalizedViewBase64Decoded:
		decoded, err := decodeWholeBase64(source)
		if err != nil {
			return "", err
		}
		return normalize.ForMatching(decoded), nil
	case view == contractreceipt.NormalizedViewHexDecoded:
		decoded, err := decodeWholeHex(source)
		if err != nil {
			return "", err
		}
		return normalize.ForMatching(decoded), nil
	default:
		return "", fmt.Errorf("unsupported normalized_view %q", view)
	}
}

func decodeWholeBase64(source string) (string, error) {
	clean := strings.TrimSpace(source)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(clean); err == nil {
			return string(decoded), nil
		}
	}
	return "", fmt.Errorf("base64_decoded recheck source is not valid base64")
}

func decodeWholeHex(source string) (string, error) {
	clean := strings.TrimSpace(source)
	decoded, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("hex_decoded recheck source is not valid hex: %w", err)
	}
	return string(decoded), nil
}
