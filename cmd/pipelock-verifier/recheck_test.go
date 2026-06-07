// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

func TestTransformProfileV1Fixtures(t *testing.T) {
	t.Parallel()
	path := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "transform-profile", "pipelock-transform-v1.json"))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var profile struct {
		Profile  string `json:"profile"`
		Fixtures []struct {
			Name           string `json:"name"`
			NormalizedView string `json:"normalized_view"`
			Input          string `json:"input"`
			Output         string `json:"output"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if profile.Profile != transformProfileV1 {
		t.Fatalf("profile=%q want %q", profile.Profile, transformProfileV1)
	}
	for _, fixture := range profile.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			got, err := reproduceSpanView(fixture.Input, fixture.NormalizedView)
			if err != nil {
				t.Fatalf("reproduceSpanView: %v", err)
			}
			if got != fixture.Output {
				t.Fatalf("output=%q want %q", got, fixture.Output)
			}
		})
	}
}

func TestRecheckEvidenceReceiptSpan(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("alpha [redacted-value] omega"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	span := recheckSourceSpanFixture()
	offset := strings.Index("alpha [redacted-value] omega", "[redacted-value]")
	length := len("[redacted-value]")
	span.CharOffset = &offset
	span.CharLength = &length
	receipt := recheckReceiptFixture(t, span)

	result, err := recheckEvidenceReceiptSpan(receipt, sourcePath, 0)
	if err != nil {
		t.Fatalf("recheckEvidenceReceiptSpan: %v", err)
	}
	if !result.Valid || result.View != contractreceipt.NormalizedViewSanitizedTarget {
		t.Fatalf("result = %+v", result)
	}
}

func TestRecheckEvidenceReceiptSpanRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("alpha [redacted-value] omega"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	tests := map[string]struct {
		receipt contractreceipt.EvidenceReceipt
		path    string
		index   int
		want    string
	}{
		"wrong payload kind": {
			receipt: contractreceipt.EvidenceReceipt{PayloadKind: contractreceipt.PayloadProxyDecision},
			path:    sourcePath,
			want:    "requires payload_kind",
		},
		"negative span index": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path:    sourcePath,
			index:   -1,
			want:    "non-negative",
		},
		"bad payload json": {
			receipt: contractreceipt.EvidenceReceipt{
				PayloadKind: contractreceipt.PayloadProxyDecisionWithSpans,
				Payload:     []byte(`{`),
			},
			path: sourcePath,
			want: "decode spanned payload",
		},
		"span index outside payload": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path:    sourcePath,
			index:   1,
			want:    "outside source_spans length",
		},
		"unsupported transform profile": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				span.TransformProfile = "pipelock-transform-v2"
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "unsupported transform_profile",
		},
		"missing redacted sample": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				span.RedactedSample = ""
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "redacted_sample is required",
		},
		"source read error": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path:    filepath.Join(dir, "missing.txt"),
			want:    "read recheck source",
		},
		"unsupported normalized view": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				span.NormalizedView = "unknown_view"
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "unsupported normalized_view",
		},
		"coordinates outside view": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				offset := 999
				length := 1
				span.CharOffset = &offset
				span.CharLength = &length
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "coordinates outside",
		},
		"coordinate mismatch": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				offset := 0
				length := 5
				span.CharOffset = &offset
				span.CharLength = &length
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "redacted_sample mismatch",
		},
		"sample not found without coordinates": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path: func() string {
				path := filepath.Join(dir, "no-sample.txt")
				if err := os.WriteFile(path, []byte("alpha beta"), 0o600); err != nil {
					t.Fatalf("write source: %v", err)
				}
				return path
			}(),
			want: "redacted_sample not found",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := recheckEvidenceReceiptSpan(tc.receipt, tc.path, tc.index)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestReproduceSpanViewDecodedInputs(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		source string
		view   string
		want   string
		errSub string
	}{
		"hex decoded": {
			source: "68656c6c6f",
			view:   contractreceipt.NormalizedViewHexDecoded,
			want:   "hello",
		},
		"hex decoded invalid": {
			source: "not-hex",
			view:   contractreceipt.NormalizedViewHexDecoded,
			errSub: "not valid hex",
		},
		"base64 invalid": {
			source: "%%%",
			view:   contractreceipt.NormalizedViewBase64Decoded,
			errSub: "not valid base64",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := reproduceSpanView(tc.source, tc.view)
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err = %v, want substring %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("reproduceSpanView: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func recheckSourceSpanFixture() contractreceipt.SourceSpan {
	return contractreceipt.SourceSpan{
		SourceID:             "request-url",
		SourceKind:           contractreceipt.SourceKindHTTPRequestURL,
		NormalizedView:       contractreceipt.NormalizedViewSanitizedTarget,
		PipelockBinaryDigest: "sha256:" + strings.Repeat("1", 64),
		RulesBundleDigest:    "sha256:" + strings.Repeat("2", 64),
		TransformProfile:     transformProfileV1,
		PolicyHash:           "sha256:" + strings.Repeat("3", 64),
		RuleID:               "aws_access_key",
		MatchHash:            "hmac-sha256:" + strings.Repeat("4", 64),
		MatchHashAlg:         contractreceipt.SourceSpanMatchHashAlgHMACSHA256,
		MatchClass:           "secret:aws_access_key",
		RedactedSample:       "[redacted-value]",
	}
}

func recheckReceiptFixture(t *testing.T, span contractreceipt.SourceSpan) contractreceipt.EvidenceReceipt {
	t.Helper()
	payload := contractreceipt.PayloadProxyDecisionWithSpansStruct{
		ActionType:    "block",
		Target:        "https://example.com/[redacted-value]",
		Verdict:       "block",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "scanner",
		SourceSpans:   []contractreceipt.SourceSpan{span},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return contractreceipt.EvidenceReceipt{
		PayloadKind: contractreceipt.PayloadProxyDecisionWithSpans,
		Payload:     body,
	}
}
