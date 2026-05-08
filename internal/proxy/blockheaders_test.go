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

func TestSeverityFromReason_FullVocabulary(t *testing.T) {
	t.Parallel()
	cases := map[blockreason.Reason]blockreason.Severity{
		// info
		blockreason.NotEnabled: blockreason.SeverityInfo,
		blockreason.BadRequest: blockreason.SeverityInfo,
		// warn
		blockreason.SchemeBlocked:         blockreason.SeverityWarn,
		blockreason.PathEntropy:           blockreason.SeverityWarn,
		blockreason.SubdomainEntropy:      blockreason.SeverityWarn,
		blockreason.URLLength:             blockreason.SeverityWarn,
		blockreason.RateLimit:             blockreason.SeverityWarn,
		blockreason.DataBudget:            blockreason.SeverityWarn,
		blockreason.MediaPolicy:           blockreason.SeverityWarn,
		blockreason.ParseError:            blockreason.SeverityWarn,
		blockreason.Timeout:               blockreason.SeverityWarn,
		blockreason.PatternUnavailable:    blockreason.SeverityWarn,
		blockreason.CompressedResponse:    blockreason.SeverityWarn,
		blockreason.BrowserShieldOversize: blockreason.SeverityWarn,
		// critical
		blockreason.DomainBlocklist:        blockreason.SeverityCritical,
		blockreason.SSRFPrivateIP:          blockreason.SeverityCritical,
		blockreason.DLPMatch:               blockreason.SeverityCritical,
		blockreason.PromptInjection:        blockreason.SeverityCritical,
		blockreason.RedactionFailure:       blockreason.SeverityCritical,
		blockreason.ToolPolicyDeny:         blockreason.SeverityCritical,
		blockreason.ToolChainBlocked:       blockreason.SeverityCritical,
		blockreason.ToolPoisoning:          blockreason.SeverityCritical,
		blockreason.SessionBinding:         blockreason.SeverityCritical,
		blockreason.AirlockActive:          blockreason.SeverityCritical,
		blockreason.KillSwitchActive:       blockreason.SeverityCritical,
		blockreason.EnvelopeVerifyFailed:   blockreason.SeverityCritical,
		blockreason.OutboundEnvelopeFailed: blockreason.SeverityCritical,
		blockreason.RedirectScanDenied:     blockreason.SeverityCritical,
		blockreason.AuthorityMismatch:      blockreason.SeverityCritical,
		blockreason.EscalationLevel:        blockreason.SeverityCritical,
		blockreason.SessionAnomaly:         blockreason.SeverityCritical,
		blockreason.CrossRequestDeny:       blockreason.SeverityCritical,
	}
	for r, want := range cases {
		t.Run(string(r), func(t *testing.T) {
			got := severityFromReason(r)
			if got != want {
				t.Errorf("severityFromReason(%q) = %q, want %q", r, got, want)
			}
		})
	}
}

func TestRetryFromReason_FullVocabulary(t *testing.T) {
	t.Parallel()
	cases := map[blockreason.Reason]blockreason.Retry{
		// transient
		blockreason.SSRFDNSRebind:          blockreason.RetryTransient,
		blockreason.RateLimit:              blockreason.RetryTransient,
		blockreason.AirlockActive:          blockreason.RetryTransient,
		blockreason.KillSwitchActive:       blockreason.RetryTransient,
		blockreason.EscalationLevel:        blockreason.RetryTransient,
		blockreason.RedactionFailure:       blockreason.RetryTransient,
		blockreason.Timeout:                blockreason.RetryTransient,
		blockreason.PatternUnavailable:     blockreason.RetryTransient,
		blockreason.SessionAnomaly:         blockreason.RetryTransient,
		blockreason.OutboundEnvelopeFailed: blockreason.RetryTransient,
		// policy
		blockreason.DomainBlocklist:       blockreason.RetryPolicy,
		blockreason.PathEntropy:           blockreason.RetryPolicy,
		blockreason.SubdomainEntropy:      blockreason.RetryPolicy,
		blockreason.URLLength:             blockreason.RetryPolicy,
		blockreason.DataBudget:            blockreason.RetryPolicy,
		blockreason.MediaPolicy:           blockreason.RetryPolicy,
		blockreason.ToolPolicyDeny:        blockreason.RetryPolicy,
		blockreason.SessionBinding:        blockreason.RetryPolicy,
		blockreason.AuthorityMismatch:     blockreason.RetryPolicy,
		blockreason.NotEnabled:            blockreason.RetryPolicy,
		blockreason.CompressedResponse:    blockreason.RetryPolicy,
		blockreason.BrowserShieldOversize: blockreason.RetryPolicy,
		// none (default)
		blockreason.DLPMatch:             blockreason.RetryNone,
		blockreason.SSRFPrivateIP:        blockreason.RetryNone,
		blockreason.SSRFMetadata:         blockreason.RetryNone,
		blockreason.PromptInjection:      blockreason.RetryNone,
		blockreason.ToolChainBlocked:     blockreason.RetryNone,
		blockreason.ToolPoisoning:        blockreason.RetryNone,
		blockreason.EnvelopeVerifyFailed: blockreason.RetryNone,
		blockreason.RedirectScanDenied:   blockreason.RetryNone,
		blockreason.CrossRequestDeny:     blockreason.RetryNone,
		blockreason.SchemeBlocked:        blockreason.RetryNone,
		blockreason.ParseError:           blockreason.RetryNone,
		blockreason.BadRequest:           blockreason.RetryNone,
	}
	for r, want := range cases {
		t.Run(string(r), func(t *testing.T) {
			got := retryFromReason(r)
			if got != want {
				t.Errorf("retryFromReason(%q) = %q, want %q", r, got, want)
			}
		})
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
	if got := w.Header().Get(blockreason.HeaderRetry); got != "none" {
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
