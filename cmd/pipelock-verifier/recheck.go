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

type recheckResult struct {
	Valid bool
	View  string
}

func recheckEvidenceReceiptSpan(r contractreceipt.EvidenceReceipt, sourcePath string, spanIndex int) (recheckResult, error) {
	if r.PayloadKind != contractreceipt.PayloadProxyDecisionWithSpans {
		return recheckResult{}, fmt.Errorf("--recheck-source requires payload_kind=%s", contractreceipt.PayloadProxyDecisionWithSpans)
	}
	if spanIndex < 0 {
		return recheckResult{}, fmt.Errorf("--recheck-span-index must be non-negative")
	}
	var payload contractreceipt.PayloadProxyDecisionWithSpansStruct
	if err := json.Unmarshal(r.Payload, &payload); err != nil {
		return recheckResult{}, fmt.Errorf("decode spanned payload: %w", err)
	}
	if spanIndex >= len(payload.SourceSpans) {
		return recheckResult{}, fmt.Errorf("--recheck-span-index=%d outside source_spans length %d", spanIndex, len(payload.SourceSpans))
	}
	span := payload.SourceSpans[spanIndex]
	if span.TransformProfile != transformProfileV1 {
		return recheckResult{}, fmt.Errorf("unsupported transform_profile %q", span.TransformProfile)
	}
	if span.RedactedSample == "" {
		return recheckResult{}, fmt.Errorf("source_spans[%d].redacted_sample is required for recheck", spanIndex)
	}
	source, err := readVerifierFile(sourcePath)
	if err != nil {
		return recheckResult{}, fmt.Errorf("read recheck source: %w", err)
	}
	view, err := reproduceSpanView(string(source), span.NormalizedView)
	if err != nil {
		return recheckResult{}, err
	}
	if span.CharOffset != nil && span.CharLength != nil {
		runes := []rune(view)
		end := *span.CharOffset + *span.CharLength
		if *span.CharOffset < 0 || end > len(runes) {
			return recheckResult{Valid: false, View: span.NormalizedView}, fmt.Errorf("source_spans[%d] coordinates outside reproduced view", spanIndex)
		}
		if string(runes[*span.CharOffset:end]) != span.RedactedSample {
			return recheckResult{Valid: false, View: span.NormalizedView}, fmt.Errorf("source_spans[%d] redacted_sample mismatch at signed coordinates", spanIndex)
		}
		return recheckResult{Valid: true, View: span.NormalizedView}, nil
	}
	if !strings.Contains(view, span.RedactedSample) {
		return recheckResult{Valid: false, View: span.NormalizedView}, fmt.Errorf("source_spans[%d] redacted_sample not found in reproduced view", spanIndex)
	}
	return recheckResult{Valid: true, View: span.NormalizedView}, nil
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
