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

const (
	// blockLayerCredentialAudienceReceipt is the distinct block layer used
	// when flight_recorder.require_receipts is on and the credential
	// audience allow receipt could not be durably confirmed before the
	// request was forwarded. It is kept separate from the generic
	// blockLayerReceiptEmission layer used by admission receipts so
	// operators and receipts can tell the two failure sources apart.
	blockLayerCredentialAudienceReceipt  = "credential_audience_receipt"                           // #nosec G101 -- block-reason layer identifier, not credential material
	credentialAudienceReceiptBlockReason = "credential audience allow receipt confirmation failed" // #nosec G101 -- operator-facing block reason text, not credential material
)

// errCredentialAudienceReceiptEmitterUnavailable is returned when no receipt
// emitter is configured and flight_recorder.require_receipts is on, so the
// audience-allow record cannot be durably confirmed before forwarding.
var errCredentialAudienceReceiptEmitterUnavailable = errors.New("credential audience receipt emitter unavailable")

// newCredentialAudienceReceiptBlockedRequest builds the typed block error for
// a require_receipts failure on the credential-audience-allow path. It
// mirrors newReceiptEmissionBlockedRequest's shape but names receipt
// confirmation explicitly rather than reusing the generic admission-receipt
// reason, so a block here is never confused with an admission-receipt
// failure in logs, metrics, or the block-reason layer header.
func newCredentialAudienceReceiptBlockedRequest(err error) *blockedRequestError {
	return newBlockedRequestError(
		blockLayerCredentialAudienceReceipt,
		credentialAudienceReceiptBlockReason,
		credentialAudienceReceiptBlockReason+": "+err.Error(),
	)
}

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
//
// Under flight_recorder.require_receipts, the caller MUST treat a non-nil
// return as a fail-closed signal and block the request before any upstream
// bytes are sent: this is the durable evidence that a credential was allowed
// through to its declared audience, so require_receipts covers it the same
// way it covers every other allow receipt. With require_receipts off the
// returned error is always nil; emission stays best-effort (log + metric),
// matching the historical behavior.
func (p *Proxy) recordCredentialAudienceAllow(ctx audit.LogContext, allow scanner.CredentialAudienceAllow, transport, method, target, requestID, agent string) error {
	if p == nil {
		return nil
	}
	recordCredentialAudienceAllow(p.logger, p.metrics, ctx, allow)
	requireReceipts := false
	if cfg := p.cfgPtr.Load(); cfg != nil {
		requireReceipts = cfg.FlightRecorder.RequireReceipts
	}
	extension, err := json.Marshal(map[string]scanner.CredentialAudienceAllow{
		credentialAudienceReceiptExtensionKey: allow,
	})
	if err != nil {
		if requireReceipts {
			return err
		}
		return nil
	}
	emitErr := p.emitCredentialAudienceReceipt(receipt.EmitOpts{
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
	if requireReceipts && emitErr != nil {
		return emitErr
	}
	return nil
}

// emitCredentialAudienceReceipt preserves the signed allow record when its
// unsigned advisory extension is malformed. The extension never decides a
// verdict, and losing the entire receipt is a worse failure direction than
// omitting that optional metadata. The returned error is non-nil only when
// the signed receipt itself (not just the advisory extension) could not be
// recorded; callers under require_receipts treat that as fail-closed.
func (p *Proxy) emitCredentialAudienceReceipt(opts receipt.EmitOpts) error {
	if p == nil {
		return errCredentialAudienceReceiptEmitterUnavailable
	}
	if cfg := p.cfgPtr.Load(); cfg != nil {
		opts = withReceiptPolicyHash(opts, cfg.CanonicalPolicyHash())
	}
	e := p.receiptEmitterPtr.Load()
	if e == nil {
		return errCredentialAudienceReceiptEmitterUnavailable
	}
	return emitCredentialAudienceReceiptWithFallback(
		opts,
		e.Emit,
		p.emitV2Receipt,
		p.logReceiptEmissionFailure,
		func(fallback receipt.EmitOpts) {
			logCredentialAudienceReceiptExtensionDropped(p.logger, fallback)
		},
	)
}

// recordCredentialAudienceAllows records every distinct allow and, when
// flight_recorder.require_receipts is on, returns the first receipt
// confirmation failure. It still attempts every allow so the audit log and
// metrics stay complete even though the request is blocked once any one
// confirmation fails.
func (p *Proxy) recordCredentialAudienceAllows(ctx audit.LogContext, allows []scanner.CredentialAudienceAllow, transport, method, target, requestID, agent string) error {
	var firstErr error
	for _, allow := range uniqueCredentialAudienceAllows(allows) {
		if err := p.recordCredentialAudienceAllow(ctx, allow, transport, method, target, requestID, agent); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (rp *ReverseProxyHandler) recordCredentialAudienceAllow(ctx audit.LogContext, allow scanner.CredentialAudienceAllow, method, target, requestID, agent string) error {
	if rp == nil {
		return nil
	}
	recordCredentialAudienceAllow(rp.logger, rp.metrics, ctx, allow)
	requireReceipts := false
	if rp.cfgPtr != nil {
		if cfg := rp.cfgPtr.Load(); cfg != nil {
			requireReceipts = cfg.FlightRecorder.RequireReceipts
		}
	}
	extension, err := json.Marshal(map[string]scanner.CredentialAudienceAllow{
		credentialAudienceReceiptExtensionKey: allow,
	})
	if err != nil {
		if requireReceipts {
			return err
		}
		return nil
	}
	emitErr := rp.emitCredentialAudienceReceipt(receipt.EmitOpts{
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
	if requireReceipts && emitErr != nil {
		return emitErr
	}
	return nil
}

func (rp *ReverseProxyHandler) emitCredentialAudienceReceipt(opts receipt.EmitOpts) error {
	if rp == nil {
		return errCredentialAudienceReceiptEmitterUnavailable
	}
	if rp.cfgPtr != nil {
		if cfg := rp.cfgPtr.Load(); cfg != nil {
			opts = withReceiptPolicyHash(opts, cfg.CanonicalPolicyHash())
		}
	}
	e := rp.receiptEmitter()
	if e == nil {
		return errCredentialAudienceReceiptEmitterUnavailable
	}
	return emitCredentialAudienceReceiptWithFallback(
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

// emitCredentialAudienceReceiptWithFallback emits the signed receipt with the
// advisory extension and returns the error only when the signed receipt
// itself could not be recorded (extension-merge failures fall back to an
// unextended receipt and return nil, matching the historical best-effort
// behavior for that narrow case).
func emitCredentialAudienceReceiptWithFallback(
	opts receipt.EmitOpts,
	emitV1 func(receipt.EmitOpts) error,
	emitV2 func(receipt.EmitOpts) error,
	logFailure func(receipt.EmitOpts, error),
	logDropped func(receipt.EmitOpts),
) error {
	if err := emitV1(opts); err == nil {
		_ = emitV2(opts)
		return nil
	} else if !errors.Is(err, receipt.ErrExtensionMerge) {
		logFailure(opts, err)
		return err
	}

	fallback := opts
	fallback.Extension = nil
	if err := emitV1(fallback); err != nil {
		logFailure(fallback, err)
		return err
	}
	logDropped(fallback)
	_ = emitV2(fallback)
	return nil
}

func logCredentialAudienceReceiptExtensionDropped(logger *audit.Logger, opts receipt.EmitOpts) {
	if logger == nil {
		return
	}
	logger.LogError(audit.NewRequestLogContext(opts.RequestID), errors.New("credential audience receipt extension could not be merged; signed receipt emitted without the extension"))
}

// recordCredentialAudienceAllows records every distinct allow for the reverse
// proxy and, when flight_recorder.require_receipts is on, returns the first
// receipt confirmation failure. See (*Proxy).recordCredentialAudienceAllows.
func (rp *ReverseProxyHandler) recordCredentialAudienceAllows(ctx audit.LogContext, allows []scanner.CredentialAudienceAllow, method, target, requestID, agent string) error {
	var firstErr error
	for _, allow := range uniqueCredentialAudienceAllows(allows) {
		if err := rp.recordCredentialAudienceAllow(ctx, allow, method, target, requestID, agent); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
