// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// dlpLayerLabel is the scanner layer label that DLP-stage blocks emit. Used
// as the expected value across multiple table cases here.
const dlpLayerLabel = "dlp"

func TestReasonFromScanner_AllMappedLayers(t *testing.T) {
	t.Parallel()
	cases := map[string]blockreason.Reason{
		scanner.ScannerScheme:           blockreason.SchemeBlocked,
		scanner.ScannerBlocklist:        blockreason.DomainBlocklist,
		scanner.ScannerSSRF:             blockreason.SSRFPrivateIP,
		scanner.ScannerSSRFMetadata:     blockreason.SSRFMetadata,
		scanner.ScannerEntropy:          blockreason.PathEntropy,
		scanner.ScannerSubdomainEntropy: blockreason.SubdomainEntropy,
		scanner.ScannerLength:           blockreason.URLLength,
		scanner.ScannerRateLimit:        blockreason.RateLimit,
		scanner.ScannerDataBudget:       blockreason.DataBudget,
		scanner.ScannerDLP:              blockreason.DLPMatch,
		scanner.ScannerCoreDLP:          blockreason.DLPMatch,
		scanner.ScannerParser:           blockreason.ParseError,
		scannerLabelBodyDLP:             blockreason.DLPMatch,
		scannerLabelBodyPromptInjection: blockreason.PromptInjection,
		scannerLabelAddressProtection:   blockreason.DLPMatch,
		scannerLabelRedaction:           blockreason.RedactionFailure,
		scannerLabelUnavailable:         blockreason.PatternUnavailable,
	}
	for label, want := range cases {
		t.Run(label, func(t *testing.T) {
			got := reasonFromScanner(label)
			if got != want {
				t.Errorf("reasonFromScanner(%q) = %q, want %q", label, got, want)
			}
		})
	}
}

func TestReasonFromScanner_UnknownLayerReturnsParseError(t *testing.T) {
	t.Parallel()
	// Unknown layer must not return an empty Reason; that would emit an
	// empty header on the wire. ParseError is the documented sentinel.
	got := reasonFromScanner("nonexistent_layer")
	if got != blockreason.ParseError {
		t.Errorf("unknown layer = %q, want ParseError", got)
	}
}

func TestBlockInfo_DerivesTripleAndLayer(t *testing.T) {
	t.Parallel()
	for _, scannerLabel := range []string{scanner.ScannerDLP, scanner.ScannerCoreDLP} {
		t.Run(scannerLabel, func(t *testing.T) {
			got := blockInfo(scannerLabel)
			if got.Reason != blockreason.DLPMatch {
				t.Errorf("Reason = %q, want %q", got.Reason, blockreason.DLPMatch)
			}
			if got.Severity != blockreason.SeverityCritical {
				t.Errorf("Severity = %q, want %q", got.Severity, blockreason.SeverityCritical)
			}
			if got.Retry != blockreason.RetryNone {
				t.Errorf("Retry = %q, want %q", got.Retry, blockreason.RetryNone)
			}
			if got.Layer != scannerLabel {
				t.Errorf("Layer = %q, want %q", got.Layer, scannerLabel)
			}
		})
	}
}

func TestBlockInfoFor_NoLayerWhenEmpty(t *testing.T) {
	t.Parallel()
	got := blockInfoFor(blockreason.AirlockActive, "")
	if got.Reason != blockreason.AirlockActive {
		t.Errorf("Reason = %q, want %q", got.Reason, blockreason.AirlockActive)
	}
	if got.Severity != blockreason.SeverityCritical {
		t.Errorf("Severity = %q, want %q", got.Severity, blockreason.SeverityCritical)
	}
	if got.Retry != blockreason.RetryTransient {
		t.Errorf("Retry = %q, want %q", got.Retry, blockreason.RetryTransient)
	}
	if got.Layer != "" {
		t.Errorf("Layer = %q, want empty", got.Layer)
	}
}

func TestBlockInfoFor_LayerSetWhenProvided(t *testing.T) {
	t.Parallel()
	got := blockInfoFor(blockreason.EnvelopeVerifyFailed, "mediation_envelope")
	if got.Layer != "mediation_envelope" {
		t.Errorf("Layer = %q, want mediation_envelope", got.Layer)
	}
}

func TestWriteBlockedError_SetsHeadersBeforeStatus(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	info := blockInfoFor(blockreason.DLPMatch, scanner.ScannerDLP)
	writeBlockedError(w, info, "blocked: dlp", 403)

	if got := w.Code; got != 403 {
		t.Errorf("status = %d, want 403", got)
	}
	if got := w.Header().Get(blockreason.HeaderReason); got != "dlp_match" {
		t.Errorf("HeaderReason = %q, want dlp_match", got)
	}
	if got := w.Header().Get(blockreason.HeaderVersion); got != "1" {
		t.Errorf("HeaderVersion = %q, want 1", got)
	}
	if got := w.Header().Get(blockreason.HeaderSeverity); got != "critical" {
		t.Errorf("HeaderSeverity = %q, want critical", got)
	}
	if got := w.Header().Get(blockreason.HeaderRetry); got != string(blockreason.RetryNone) {
		t.Errorf("HeaderRetry = %q, want none", got)
	}
	if got := w.Header().Get(blockreason.HeaderLayer); got != dlpLayerLabel {
		t.Errorf("HeaderLayer = %q, want %s", got, dlpLayerLabel)
	}
	// Body still carries the human-readable message; headers are additive.
	if w.Body.String() == "" {
		t.Errorf("body empty; expected human-readable block message")
	}
}
