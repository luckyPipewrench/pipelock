// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const credentialAudienceReceiptExtensionKey = "dlp_credential_audience_allow"

// recordCredentialAudienceAllow records the bounded observability side effect
// shared by forward, intercept, reverse, and WebSocket DLP. It has no verdict
// effect: telemetry failures must never turn an audience match into a bypass.
func recordCredentialAudienceAllow(logger *audit.Logger, metric *metrics.Metrics, ctx audit.LogContext, allow scanner.CredentialAudienceAllow) {
	if logger != nil {
		logger.LogDLPCredentialAudienceAllow(ctx, allow.PatternName, allow.Surface, allow.Destination)
	}
	if metric != nil {
		metric.RecordDLPCredentialAudienceAllow(allow.PatternName, allow.Surface)
	}
}

// recordCredentialAudienceAllow emits an advisory extension when this proxy has
// a v1 receipt channel. The stable signed receipt schema deliberately remains
// unchanged: the extension records that the DLP match was allowed for the
// declared audience without becoming a signed authorization claim.
func (p *Proxy) recordCredentialAudienceAllow(ctx audit.LogContext, allow scanner.CredentialAudienceAllow, transport, method, target, requestID, agent string) {
	if p == nil {
		return
	}
	recordCredentialAudienceAllow(p.logger, p.metrics, ctx, allow)
	extension, err := json.Marshal(map[string]scanner.CredentialAudienceAllow{
		credentialAudienceReceiptExtensionKey: allow,
	})
	if err != nil {
		return
	}
	_ = p.emitReceipt(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Layer:     credentialAudienceReceiptExtensionKey,
		Pattern:   allow.PatternName,
		Transport: transport,
		Method:    method,
		Target:    target,
		RequestID: requestID,
		Agent:     agent,
		Extension: extension,
	})
}

func (p *Proxy) recordCredentialAudienceAllows(ctx audit.LogContext, allows []scanner.CredentialAudienceAllow, transport, method, target, requestID, agent string) {
	for _, allow := range uniqueCredentialAudienceAllows(allows) {
		p.recordCredentialAudienceAllow(ctx, allow, transport, method, target, requestID, agent)
	}
}

func (rp *ReverseProxyHandler) recordCredentialAudienceAllow(ctx audit.LogContext, allow scanner.CredentialAudienceAllow, method, target, requestID, agent string) {
	if rp == nil {
		return
	}
	recordCredentialAudienceAllow(rp.logger, rp.metrics, ctx, allow)
	extension, err := json.Marshal(map[string]scanner.CredentialAudienceAllow{
		credentialAudienceReceiptExtensionKey: allow,
	})
	if err != nil {
		return
	}
	_ = rp.emitReceipt(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Layer:     credentialAudienceReceiptExtensionKey,
		Pattern:   allow.PatternName,
		Transport: "reverse",
		Method:    method,
		Target:    target,
		RequestID: requestID,
		Agent:     agent,
		Extension: extension,
	})
}

func (rp *ReverseProxyHandler) recordCredentialAudienceAllows(ctx audit.LogContext, allows []scanner.CredentialAudienceAllow, method, target, requestID, agent string) {
	for _, allow := range uniqueCredentialAudienceAllows(allows) {
		rp.recordCredentialAudienceAllow(ctx, allow, method, target, requestID, agent)
	}
}
