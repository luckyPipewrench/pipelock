// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package blockreason_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// TestSeverityFor_FullVocabulary pins the Reason -> Severity table for every
// production Reason. The table is the single source of truth used by
// blockheaders, the public spec doc, and the receipt schema; pinning it here
// catches any silent drift in the canonical helper.
func TestSeverityFor_FullVocabulary(t *testing.T) {
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
		blockreason.ResponseSize:          blockreason.SeverityWarn,
		blockreason.MediaPolicy:           blockreason.SeverityWarn,
		blockreason.ParseError:            blockreason.SeverityWarn,
		blockreason.Timeout:               blockreason.SeverityWarn,
		blockreason.PatternUnavailable:    blockreason.SeverityWarn,
		blockreason.CompressedResponse:    blockreason.SeverityWarn,
		blockreason.BrowserShieldOversize: blockreason.SeverityWarn,
		// critical
		blockreason.DomainBlocklist:        blockreason.SeverityCritical,
		blockreason.SSRFPrivateIP:          blockreason.SeverityCritical,
		blockreason.SSRFMetadata:           blockreason.SeverityCritical,
		blockreason.SSRFDNSRebind:          blockreason.SeverityCritical,
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
		blockreason.RequestPolicyDeny:      blockreason.SeverityCritical,
	}
	for r, want := range cases {
		t.Run(string(r), func(t *testing.T) {
			got := blockreason.SeverityFor(r)
			if got != want {
				t.Errorf("SeverityFor(%q) = %q, want %q", r, got, want)
			}
		})
	}
}

// TestRetryFor_FullVocabulary pins the Reason -> Retry table for every
// production Reason. Same rationale as TestSeverityFor_FullVocabulary.
func TestRetryFor_FullVocabulary(t *testing.T) {
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
		blockreason.ResponseSize:          blockreason.RetryPolicy,
		blockreason.MediaPolicy:           blockreason.RetryPolicy,
		blockreason.ToolPolicyDeny:        blockreason.RetryPolicy,
		blockreason.SessionBinding:        blockreason.RetryPolicy,
		blockreason.AuthorityMismatch:     blockreason.RetryPolicy,
		blockreason.NotEnabled:            blockreason.RetryPolicy,
		blockreason.CompressedResponse:    blockreason.RetryPolicy,
		blockreason.BrowserShieldOversize: blockreason.RetryPolicy,
		blockreason.RequestPolicyDeny:     blockreason.RetryPolicy,
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
			got := blockreason.RetryFor(r)
			if got != want {
				t.Errorf("RetryFor(%q) = %q, want %q", r, got, want)
			}
		})
	}
}
