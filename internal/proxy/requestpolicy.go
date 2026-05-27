// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
)

// blockLayerRequestPolicy labels request_policy decisions on receipts and audit
// events. It is the audit/receipt layer dimension only — distinct from the
// X-Pipelock-Block-Reason-Layer HTTP header, which request_policy deliberately
// leaves UNSET (request_policy is not a scanner.Scanner* pipeline layer, so the
// reason code conveys the layer; see requestPolicyBlockInfo).
const blockLayerRequestPolicy = "request_policy"

// headerContentType is the request Content-Type header, used to populate
// RequestMeta.ContentType for content_type-scoped rules.
const headerContentType = "Content-Type"

// setupRequestPolicy compiles the request_policy ruleset at startup and stores
// the matcher. NewMatcher always returns a usable (possibly disabled) matcher,
// so a nil pointer never reaches the request path. An error here means a
// path_pattern failed to compile; config validation already compiles the same
// patterns, so this is defense in depth and fails startup closed.
func (p *Proxy) setupRequestPolicy(cfg *config.Config) error {
	m, err := reqpolicy.NewMatcher(&cfg.RequestPolicy)
	if err != nil {
		return fmt.Errorf("request_policy matcher build: %w", err)
	}
	p.reqPolicyPtr.Store(m)
	return nil
}

const defaultRequestPolicyMaxBodyBytes = 5 * 1024 * 1024

// requestPolicyInput is the per-request data a transport hands to
// applyRequestPolicy. BodyRead reports whether Body is a complete copy of the
// request body after any in-path redaction. When BodyRead is false and a
// route-matched operation predicate needs a body, applyRequestPolicy treats the
// operation as opaque and applies request_policy.on_opaque_operation.
type requestPolicyInput struct {
	Host        string
	Method      string // base HTTP method as seen on the wire
	Path        string
	Query       string // URL raw query, for GraphQL-over-GET operation extraction
	ContentType string
	Headers     http.Header // resolved for method-override detection
	Body        []byte
	BodyRead    bool

	Transport string
	Target    string // full URL or host:port, for receipt/audit correlation
	RequestID string
	Agent     string
	AuditCtx  audit.LogContext
	Emit      func(receipt.EmitOpts) // transport's receipt emitter (e.g. p.emitReceipt)
}

// requestPolicyResult tells the calling transport what to do. Block is true
// only for an enforced (non-shadow) block; warn and shadow matches return
// Block=false after being logged and counted, so the request forwards.
type requestPolicyResult struct {
	Block  bool
	Info   blockreason.Info
	Reason string // operator-facing reason from the matched rule, safe to surface
}

// evaluateRequestPolicy evaluates the active ruleset against a request. It
// resolves method-override headers and evaluates against BOTH the base and the
// overridden method, returning the stricter result, so a request cannot dodge
// a method-scoped rule by tunnelling the real method through an override header
// the upstream may ignore (per reqpolicy.EffectiveMethod's documented caveat).
func (p *Proxy) requestPolicyMatcher() *reqpolicy.Matcher {
	m := p.reqPolicyPtr.Load()
	if m == nil {
		return nil
	}
	return m
}

func requestPolicyMeta(host, method, path, contentType string, ops []reqpolicy.RequestOperation) reqpolicy.RequestMeta {
	return reqpolicy.RequestMeta{Host: host, Method: method, Path: path, ContentType: contentType, Operations: ops}
}

func (p *Proxy) evaluateRequestPolicy(host, baseMethod string, headers http.Header, path, contentType string, ops []reqpolicy.RequestOperation) reqpolicy.Decision {
	m := p.requestPolicyMatcher()
	if m == nil {
		return reqpolicy.Decision{}
	}
	eff := reqpolicy.EffectiveMethod(baseMethod, headers)
	d := m.Evaluate(requestPolicyMeta(host, eff, path, contentType, ops))
	base := strings.ToUpper(strings.TrimSpace(baseMethod))
	if eff != base {
		alt := m.Evaluate(requestPolicyMeta(host, base, path, contentType, ops))
		d = reqpolicy.Stricter(d, alt)
	}
	return d
}

func (p *Proxy) requestPolicyNeedsOperations(in requestPolicyInput) bool {
	m := p.requestPolicyMatcher()
	if m == nil {
		return false
	}
	eff := reqpolicy.EffectiveMethod(in.Method, in.Headers)
	if m.NeedsOperations(requestPolicyMeta(in.Host, eff, in.Path, in.ContentType, nil)) {
		return true
	}
	base := strings.ToUpper(strings.TrimSpace(in.Method))
	return eff != base && m.NeedsOperations(requestPolicyMeta(in.Host, base, in.Path, in.ContentType, nil))
}

func (p *Proxy) evaluateRequestPolicyUninspectable(in requestPolicyInput, action string) reqpolicy.Decision {
	m := p.requestPolicyMatcher()
	if m == nil {
		return reqpolicy.Decision{}
	}
	eff := reqpolicy.EffectiveMethod(in.Method, in.Headers)
	d := m.EvaluateUninspectable(requestPolicyMeta(in.Host, eff, in.Path, in.ContentType, nil), action)
	base := strings.ToUpper(strings.TrimSpace(in.Method))
	if eff != base {
		alt := m.EvaluateUninspectable(requestPolicyMeta(in.Host, base, in.Path, in.ContentType, nil), action)
		d = reqpolicy.Stricter(d, alt)
	}
	return d
}

// requestPolicyMatchesBatch reports whether the request route-matches a
// configured batch endpoint, under either the base or the overridden method.
func (p *Proxy) requestPolicyMatchesBatch(in requestPolicyInput) bool {
	m := p.requestPolicyMatcher()
	if m == nil {
		return false
	}
	eff := reqpolicy.EffectiveMethod(in.Method, in.Headers)
	if m.MatchesBatch(requestPolicyMeta(in.Host, eff, in.Path, in.ContentType, nil)) {
		return true
	}
	base := strings.ToUpper(strings.TrimSpace(in.Method))
	return eff != base && m.MatchesBatch(requestPolicyMeta(in.Host, base, in.Path, in.ContentType, nil))
}

// evaluateRequestPolicyBatch parses the request body as a batch envelope and
// evaluates each sub-request against the rule set, under both the base and
// overridden method. parseOK is false when a matched batch envelope cannot be
// parsed or is over-cap (the caller then applies on_parse_error).
func (p *Proxy) evaluateRequestPolicyBatch(in requestPolicyInput) (reqpolicy.Decision, bool) {
	m := p.requestPolicyMatcher()
	if m == nil {
		return reqpolicy.Decision{}, true
	}
	eff := reqpolicy.EffectiveMethod(in.Method, in.Headers)
	d, parseOK := m.EvaluateBatch(requestPolicyMeta(in.Host, eff, in.Path, in.ContentType, nil), in.Body)
	base := strings.ToUpper(strings.TrimSpace(in.Method))
	if eff != base {
		bd, ok := m.EvaluateBatch(requestPolicyMeta(in.Host, base, in.Path, in.ContentType, nil), in.Body)
		d = reqpolicy.Stricter(d, bd)
		parseOK = parseOK && ok
	}
	return d, parseOK
}

// evaluateRequestPolicyUninspectableBatch applies a fail-closed action to a
// batch endpoint whose body could not be inspected, under both the base and
// overridden method. Unlike evaluateRequestPolicyUninspectable (graphql rules
// only), this covers a batch endpoint that has no graphql operation rule.
func (p *Proxy) evaluateRequestPolicyUninspectableBatch(in requestPolicyInput, action string) reqpolicy.Decision {
	m := p.requestPolicyMatcher()
	if m == nil {
		return reqpolicy.Decision{}
	}
	eff := reqpolicy.EffectiveMethod(in.Method, in.Headers)
	d := m.UninspectableBatch(requestPolicyMeta(in.Host, eff, in.Path, in.ContentType, nil), action)
	base := strings.ToUpper(strings.TrimSpace(in.Method))
	if eff != base {
		d = reqpolicy.Stricter(d, m.UninspectableBatch(requestPolicyMeta(in.Host, base, in.Path, in.ContentType, nil), action))
	}
	return d
}

func (p *Proxy) requestPolicyBodyLimit() int {
	cfg := p.cfgPtr.Load()
	if cfg != nil && cfg.RequestBodyScanning.MaxBodyBytes > 0 {
		return cfg.RequestBodyScanning.MaxBodyBytes
	}
	return defaultRequestPolicyMaxBodyBytes
}

// prepareRequestPolicyBody reads and re-wraps a request body only when a
// route-matched operation predicate needs it and no earlier scanner already
// buffered it. This keeps request_policy independent of
// request_body_scanning.enabled without draining bodies for route-only rules.
func (p *Proxy) prepareRequestPolicyBody(r *http.Request, in *requestPolicyInput) requestPolicyResult {
	if in.BodyRead || (!p.requestPolicyNeedsOperations(*in) && !p.requestPolicyMatchesBatch(*in)) {
		return requestPolicyResult{}
	}
	if r.Body == nil || r.Body == http.NoBody {
		in.BodyRead = true
		return requestPolicyResult{}
	}
	limit := p.requestPolicyBodyLimit()
	buf, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return p.requestPolicyReadBlocked(*in, fmt.Sprintf("request body could not be inspected: %v", err))
	}
	if len(buf) > limit {
		return p.requestPolicyReadBlocked(*in, fmt.Sprintf("request body exceeds max_body_bytes (%d)", limit))
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	bufCopy := buf
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bufCopy)), nil
	}
	in.Body = buf
	in.BodyRead = true
	return requestPolicyResult{}
}

// requestPolicyReadBlocked handles a request body that cannot be read or
// exceeds the size limit. The bounded read has already consumed — and thus
// destroyed — the body stream, so the request can no longer be forwarded
// intact. It is therefore always blocked, never downgraded by a configured
// on_parse_error: warn/allow (those apply only to a fully-read body that
// fails to parse, which is still forwardable). The block is routed through the
// shared finalizer so it is metered, audited, and receipted like any other
// match. reason is logged as bounded audit context for the failure cause.
func (p *Proxy) requestPolicyReadBlocked(in requestPolicyInput, reason string) requestPolicyResult {
	m := p.requestPolicyMatcher()
	if m == nil {
		return requestPolicyResult{}
	}
	p.logger.LogAnomaly(in.AuditCtx, blockLayerRequestPolicy, reason, 0)
	d := p.evaluateRequestPolicyUninspectable(in, config.ActionBlock)
	d = reqpolicy.Stricter(d, p.evaluateRequestPolicyUninspectableBatch(in, config.ActionBlock))
	return p.finalizeRequestPolicyDecision(in, d)
}

// applyRequestPolicy evaluates request_policy for a request and acts on the
// outcome. On a matched rule it records the decision metric and an audit event;
// on an enforced block it also emits a receipt (when an emitter is configured)
// and returns Block=true with the block-reason Info for the transport to write.
// Warn and shadow matches return Block=false so the request forwards.
//
// Transports MUST call this BEFORE EvaluateGate so a contract allow can never
// suppress a request_policy block.
func (p *Proxy) applyRequestPolicy(in requestPolicyInput) requestPolicyResult {
	d := p.evaluateRequestPolicy(in.Host, in.Method, in.Headers, in.Path, in.ContentType, nil)
	if p.requestPolicyNeedsOperations(in) {
		m := p.requestPolicyMatcher()
		if !in.BodyRead {
			d = reqpolicy.Stricter(d, p.evaluateRequestPolicyUninspectable(in, m.OnOpaqueOperation()))
		} else {
			ops, parseOK, opaque := extractRequestPolicyOperations(in)
			if !parseOK {
				d = reqpolicy.Stricter(d, p.evaluateRequestPolicyUninspectable(in, m.OnParseError()))
			} else {
				d = reqpolicy.Stricter(d, p.evaluateRequestPolicy(in.Host, in.Method, in.Headers, in.Path, in.ContentType, ops))
				if opaque {
					d = reqpolicy.Stricter(d, p.evaluateRequestPolicyUninspectable(in, m.OnOpaqueOperation()))
				}
			}
		}
	}
	if p.requestPolicyMatchesBatch(in) {
		m := p.requestPolicyMatcher()
		if !in.BodyRead {
			// Body unavailable for a batch endpoint: cannot inspect the
			// sub-requests, so fail closed via on_opaque_operation.
			d = reqpolicy.Stricter(d, p.evaluateRequestPolicyUninspectableBatch(in, m.OnOpaqueOperation()))
		} else {
			bd, parseOK := p.evaluateRequestPolicyBatch(in)
			d = reqpolicy.Stricter(d, bd)
			if !parseOK {
				// Unparseable or over-cap envelope: fail closed via on_parse_error.
				d = reqpolicy.Stricter(d, p.evaluateRequestPolicyUninspectableBatch(in, m.OnParseError()))
			}
		}
	}
	return p.finalizeRequestPolicyDecision(in, d)
}

// finalizeRequestPolicyDecision records the decision metric and audit event for
// a matched rule and, for an enforced block, emits a correlated receipt and
// returns the block Info. A no-match, warn, or shadow decision returns
// Block=false so the request forwards. Both the route/operation path and the
// body-inspection-failure path funnel through here so every matched decision is
// metered, audited, and receipted identically.
func (p *Proxy) finalizeRequestPolicyDecision(in requestPolicyInput, d reqpolicy.Decision) requestPolicyResult {
	if !d.Matched() {
		return requestPolicyResult{}
	}
	p.metrics.RecordRequestPolicyDecision(d.RuleName, d.Action)

	if !d.Enforced() || d.Action != config.ActionBlock {
		// Warn or shadow: log the would-be action and forward. Detail carries
		// only bounded, operator-defined labels — never body or matched content.
		p.logger.LogAnomaly(in.AuditCtx, blockLayerRequestPolicy,
			fmt.Sprintf("rule=%s action=%s shadow=%t", d.RuleName, d.Action, d.Shadow), 0)
		return requestPolicyResult{}
	}

	// Enforced block.
	p.logger.LogBlocked(in.AuditCtx, blockLayerRequestPolicy, d.RuleName)
	actionID := ""
	if in.Emit != nil && p.receiptEmitterPtr.Load() != nil {
		actionID = receipt.NewActionID()
		in.Emit(receipt.EmitOpts{
			ActionID:  actionID,
			Verdict:   config.ActionBlock,
			Layer:     blockLayerRequestPolicy,
			Pattern:   d.RuleName,
			Transport: in.Transport,
			Method:    in.Method,
			Target:    in.Target,
			RequestID: in.RequestID,
			Agent:     in.Agent,
		})
	}
	reason := d.Reason
	if reason == "" {
		reason = d.RuleName
	}
	return requestPolicyResult{Block: true, Info: p.requestPolicyBlockInfo(actionID), Reason: reason}
}

// requestPolicyBlockInfo builds the X-Pipelock-Block-Reason metadata for a
// request_policy_deny block — the operation safety rail's enforced-block path.
//
// The request_policy layer is not a scanner.Scanner* pipeline constant, so the
// X-Pipelock-Block-Reason-Layer header is intentionally left unset: per
// docs/specs/block-reason-header.md non-scanner enforcement layers omit the
// layer header and let the reason code convey the layer (the same convention
// the MCP and contract layers follow).
//
// Receipt correlation is gated on a configured receipt emitter, mirroring
// emitReceipt's nil check. When an emitter is configured, actionID — which MUST
// be the real receipt action_id (receipt.NewActionID) recorded for this same
// block — is stamped into the receipt header so the agent can fetch the
// matching receipt. A decorrelated identifier must never be passed here: an
// action_id that points at no emitted receipt would make the header lie. When
// no emitter is configured, or actionID is empty or malformed, the receipt slot
// stays unset and the block still emits its required headers — the receipt is
// optional metadata, so dropping it never weakens the block itself.
func (p *Proxy) requestPolicyBlockInfo(actionID string) blockreason.Info {
	info := blockInfoFor(blockreason.RequestPolicyDeny, "")
	if actionID == "" || p.receiptEmitterPtr.Load() == nil {
		return info
	}
	withReceipt, err := info.WithReceipt(actionID)
	if err != nil {
		// Malformed action_id: keep the block, drop the optional receipt.
		return info
	}
	return withReceipt
}
