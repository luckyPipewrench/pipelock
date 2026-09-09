// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const credentialAudienceReceiptExtensionKey = "dlp_credential_audience_allow" // #nosec G101 -- receipt extension identifier, not credential material

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
	p.emitCredentialAudienceReceipt(receipt.EmitOpts{
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

// emitCredentialAudienceReceipt preserves the signed allow record when its
// unsigned advisory extension is malformed. The extension never decides a
// verdict, and losing the entire receipt is a worse failure direction than
// omitting that optional metadata.
func (p *Proxy) emitCredentialAudienceReceipt(opts receipt.EmitOpts) {
	if p == nil {
		return
	}
	if cfg := p.cfgPtr.Load(); cfg != nil {
		opts = withReceiptPolicyHash(opts, cfg.CanonicalPolicyHash())
	}
	e := p.receiptEmitterPtr.Load()
	if e == nil {
		return
	}
	emitCredentialAudienceReceiptWithFallback(
		opts,
		e.Emit,
		p.emitV2Receipt,
		p.logReceiptEmissionFailure,
		func(fallback receipt.EmitOpts) {
			logCredentialAudienceReceiptExtensionDropped(p.logger, fallback)
		},
	)
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
	rp.emitCredentialAudienceReceipt(receipt.EmitOpts{
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

func (rp *ReverseProxyHandler) emitCredentialAudienceReceipt(opts receipt.EmitOpts) {
	if rp == nil {
		return
	}
	if rp.cfgPtr != nil {
		if cfg := rp.cfgPtr.Load(); cfg != nil {
			opts = withReceiptPolicyHash(opts, cfg.CanonicalPolicyHash())
		}
	}
	e := rp.receiptEmitter()
	if e == nil {
		return
	}
	emitCredentialAudienceReceiptWithFallback(
		opts,
		e.Emit,
		func(v2Opts receipt.EmitOpts) error {
			return emitV2(rp.v2EmitterPtr, v2Opts, func(err error) {
				recordV2ReceiptEmitFailure(rp.metrics)
				logV2EmitFailure(rp.logger, v2Opts, err)
			})
		},
		rp.logReceiptEmissionFailure,
		func(fallback receipt.EmitOpts) {
			logCredentialAudienceReceiptExtensionDropped(rp.logger, fallback)
		},
	)
}

func emitCredentialAudienceReceiptWithFallback(
	opts receipt.EmitOpts,
	emitV1 func(receipt.EmitOpts) error,
	emitV2 func(receipt.EmitOpts) error,
	logFailure func(receipt.EmitOpts, error),
	logDropped func(receipt.EmitOpts),
) {
	if err := emitV1(opts); err == nil {
		_ = emitV2(opts)
		return
	} else if !errors.Is(err, receipt.ErrExtensionMerge) {
		logFailure(opts, err)
		return
	}

	fallback := opts
	fallback.Extension = nil
	if err := emitV1(fallback); err != nil {
		logFailure(fallback, err)
		return
	}
	logDropped(fallback)
	_ = emitV2(fallback)
}

func logCredentialAudienceReceiptExtensionDropped(logger *audit.Logger, opts receipt.EmitOpts) {
	if logger == nil {
		return
	}
	logger.LogError(audit.NewRequestLogContext(opts.RequestID), errors.New("credential audience receipt extension could not be merged; signed receipt emitted without the extension"))
}

func (rp *ReverseProxyHandler) recordCredentialAudienceAllows(ctx audit.LogContext, allows []scanner.CredentialAudienceAllow, method, target, requestID, agent string) {
	for _, allow := range uniqueCredentialAudienceAllows(allows) {
		rp.recordCredentialAudienceAllow(ctx, allow, method, target, requestID, agent)
	}
}
