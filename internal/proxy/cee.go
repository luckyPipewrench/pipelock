// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// CeeSessionKey builds a consistent session identity for cross-request
// exfiltration detection. Exported for use by the session reset admin API.
//
// This is the RAW constructor: it trusts the agent string as given. Request
// handlers that accumulate CEE state must instead build the key via
// ceeSessionKey, which folds attacker-controlled agent identities into the
// client IP. CeeSessionKey is retained for the reset/terminate admin path,
// which round-trips an already-stored key back through classifySessionKey, so
// whatever (possibly folded) key was written is the key that gets cleared.
func CeeSessionKey(agent, clientIP string) string {
	return sessionKeyFor(agent, clientIP)
}

// ceeKeyAgent returns the agent-identity component that is safe to use for
// namespacing CEE accumulation buckets (entropy tracker and fragment buffer).
//
// The X-Pipelock-Agent header and ?agent= query parameter are self-declared
// and therefore attacker-controllable. If the agent name narrows the CEE
// bucket below the client IP, an attacker can rotate the identifier per
// request, sending each fragment of a split secret (or each high-entropy
// payload) under a different agent name, so no single bucket ever holds two
// fragments or exceeds the entropy budget. The secret then leaks split across
// per-agent buckets. This is the "session-key partitioning" bypass.
//
// The client IP (RemoteAddr, with forwarded-header spoofing stripped on
// egress) is the only trustworthy anchor. The agent name is trustworthy ONLY
// when it is NOT attacker-variable:
//   - ActorAuthBound: identity injected by infrastructure via a spoof-proof
//     per-listener context override; the caller cannot change it.
//   - ActorAuthConfigDefault: a single fixed value from config; constant per
//     deployment, so it cannot be used to partition.
//
// ActorAuthMatched and ActorAuthSelfDeclared both originate from the request
// header/query (matched merely means the supplied name equals a configured
// profile, but it is still attacker-supplied), so they are folded to the empty
// agent and the bucket key collapses to the client IP. Operators who need
// spoof-proof per-agent CEE separation use per-listener binding
// (ActorAuthBound), not header-based identity.
func ceeKeyAgent(agent string, auth envelope.ActorAuth) string {
	return identitykey.CEESafeAgent(agent, auth)
}

// ceeSessionKey builds the partition-resistant CEE accumulation key. Untrusted
// (attacker-variable) agent identities collapse to the client IP so a rotating
// agent identifier cannot split a secret across buckets. See ceeKeyAgent.
func ceeSessionKey(agent, clientIP string, auth envelope.ActorAuth) string {
	return identitykey.CEESafeKey(agent, clientIP, auth)
}

// maxCaptureSessionKeyLen aliases the writer-side ceiling so the
// proxy-side sanitization decision and the writer-side reason metric stay
// in lockstep. Source of truth: capture.MaxSessionKeyLen.
const maxCaptureSessionKeyLen = capture.MaxSessionKeyLen

// captureSessionKey returns the CEE session identity when it is safe to use as
// a recorder directory name. Self-declared agent names are untrusted, so unsafe
// or overlength keys are mapped to a bounded hash instead of being dropped by
// the writer.
func captureSessionKey(agent, clientIP string) string {
	safe, _ := captureSessionKeyAndOriginal(agent, clientIP)
	return safe
}

// captureSessionKeyAndOriginal returns the safe directory-name session key and
// the original logical key. When the two differ, the safe value was derived
// via SHA-256 to escape an unsafe or overlength input. Capture call sites
// stamp the original into the record so audit/incident response can map an
// opaque "capture-<hex>" directory back to its self-attested agent identity.
func captureSessionKeyAndOriginal(agent, clientIP string) (safe, original string) {
	key := CeeSessionKey(agent, clientIP)
	if key == "" {
		key = agentAnonymous
	}
	if strings.ContainsAny(key, `/\`) || strings.Contains(key, "..") || len(key) > maxCaptureSessionKeyLen {
		sum := sha256.Sum256([]byte(key))
		return "capture-" + hex.EncodeToString(sum[:]), key
	}
	return key, key
}

// captureSessionKeyOriginal returns the unsanitized logical session key when
// the safe directory-name key was derived via hashing, and the empty string
// otherwise. Capture call sites assign the result to record.SessionIDOriginal
// (omitempty), so on the clean path no IP-bearing identity leaks into every
// capture record; the field appears only when a sanitized "capture-<hex>"
// directory needs an audit trail back to its raw logical key.
func captureSessionKeyOriginal(agent, clientIP string) string {
	safe, original := captureSessionKeyAndOriginal(agent, clientIP)
	if safe == original {
		return ""
	}
	return original
}

// ResetCEEState clears entropy and fragment state for a session identity.
// Entropy tracker: clears CeeSessionKey(agent, ip) (base key only).
// Fragment buffer: clears every stream for that identity, so an operator reset
// leaves no accumulated fragment state behind on any of them.
// Safe to call with nil trackers (CEE disabled).
func ResetCEEState(agent, clientIP string, et *scanner.EntropyTracker, fb *scanner.FragmentBuffer) {
	key := CeeSessionKey(agent, clientIP)
	if et != nil {
		et.Delete(key)
	}
	if fb != nil {
		fb.Delete(key)
		for _, suffix := range ceeFragmentStreamSuffixes {
			fb.Delete(key + suffix)
		}
	}
}

// CEE fragment streams are buffered separately so unrelated text cannot
// interrupt a reassembled secret. Each stream is the base session key plus its
// suffix. ceeFragmentStreamSuffixes lists every non-base stream so an operator
// reset clears all of them; a new stream must be added here as well.
const (
	ceeStreamKeysSuffix = "|keys"
	ceeStreamPathSuffix = "|path"
)

var ceeFragmentStreamSuffixes = []string{ceeStreamKeysSuffix, ceeStreamPathSuffix}

// ceePathPayload carries parsed path segments plus the bounded-parser result.
// A path deeper than scanner.MaxPathPositions must be denied before forwarding:
// silently ignoring the tail would let it bypass cross-request inspection.
type ceePathPayload struct {
	segments      [][]byte
	depthExceeded bool
}

// maxCEEBodyRead limits the body bytes read for CEE payload extraction.
// Larger bodies are unlikely to be fragment-based exfiltration attempts.
const maxCEEBodyRead = 65536 // 64KB

// queryParamPayload extracts query values from a URL in wire order (the order
// tokens appear in RawQuery). For key=value pairs, only the value is extracted.
// Bare tokens (no '=') are included in full because an agent can embed secret
// fragments as valueless query params (e.g. ?AKIA + IOSFODNN7EXAMPLE).
//
// Keys are intentionally excluded from the output because including them
// (e.g. "data=AKIA" + "data=IOSF") would break fragment reconstruction by
// inserting non-secret text ("data=") between value fragments. Secrets embedded
// in key names are caught by per-request DLP, which scans the full URL on every
// individual request. CEE fragment reconstruction only needs contiguous values.
func queryParamPayload(u *url.URL) []byte {
	raw := u.RawQuery
	if raw == "" {
		return nil
	}
	var buf bytes.Buffer
	for raw != "" {
		var pair string
		if idx := strings.IndexByte(raw, '&'); idx >= 0 {
			pair, raw = raw[:idx], raw[idx+1:]
		} else {
			pair, raw = raw, ""
		}
		if pair == "" {
			continue
		}
		// For key=value: extract only the value (contiguous across requests).
		// For bare items (no '='): include the entire item.
		var val string
		if eqIdx := strings.IndexByte(pair, '='); eqIdx >= 0 {
			val = pair[eqIdx+1:]
		} else {
			val = pair
		}
		if val == "" {
			continue
		}
		decoded, err := url.QueryUnescape(val)
		if err != nil {
			decoded = val
		}
		buf.WriteString(decoded)
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// queryParamKeys extracts query parameter keys (names) from a URL in wire
// order. For key=value pairs, only the key is extracted. Bare tokens (no '=')
// are excluded (they are already covered by queryParamPayload as full tokens).
// Used as a second fragment stream so secrets split across parameter names
// (e.g. ?AKIA=1 then ?IOSFODNN7EXAMPLE=2) are reconstructed and DLP-scanned.
func queryParamKeys(u *url.URL) []byte {
	raw := u.RawQuery
	if raw == "" {
		return nil
	}
	var buf bytes.Buffer
	for raw != "" {
		var pair string
		if idx := strings.IndexByte(raw, '&'); idx >= 0 {
			pair, raw = raw[:idx], raw[idx+1:]
		} else {
			pair, raw = raw, ""
		}
		if pair == "" {
			continue
		}
		// For key=value: extract only the key.
		// Bare tokens (no '='): skip (handled by queryParamPayload).
		eqIdx := strings.IndexByte(pair, '=')
		if eqIdx < 0 {
			continue
		}
		key := pair[:eqIdx]
		if key == "" {
			continue
		}
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			decoded = key
		}
		buf.WriteString(decoded)
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// urlPayload extracts query parameter values in wire order from a parsed URL.
// Path components are excluded here and carried by pathSegments instead, on a
// separate fragment stream: concatenating whole paths into this stream would
// interleave static route text between the halves of a split secret and would
// spend the per-session byte cap on requests that carry no data.
// Used by the fetch handler where the request body is always empty (GET-only).
func urlPayload(u *url.URL) []byte {
	return queryParamPayload(u)
}

// pathSegments splits a URL path into decoded, non-empty segments in wire
// order. It stops after scanner.MaxPathPositions segments without allocating a
// slice for the remainder. The returned depth flag makes the CEE admission
// fail closed rather than silently leaving a secret-bearing tail uninspected.
//
// CEE reassembles only equal absolute positions across requests. A fragment
// that shifts from one position to another is deliberately not joined: there
// is no route-independent ordering proof that it belongs in the same stream.
func pathSegments(u *url.URL) *ceePathPayload {
	if u == nil {
		return nil
	}
	// Split the ESCAPED path, then decode each segment. u.Path is already
	// percent-decoded, so splitting it treats an encoded slash as a separator:
	// "/upload/value%2Ftail" would become three positions when the wire carried
	// two, shifting every later position and breaking reassembly against the
	// same route seen without the escape.
	raw := u.EscapedPath()
	if raw == "" {
		raw = u.RawPath
	}
	if raw == "" {
		raw = u.Path
	}
	if raw == "" || raw == "/" {
		return nil
	}
	payload := &ceePathPayload{}
	for raw != "" {
		part := raw
		if slash := strings.IndexByte(raw, '/'); slash >= 0 {
			part, raw = raw[:slash], raw[slash+1:]
		} else {
			raw = ""
		}
		if part == "" {
			continue
		}
		if len(payload.segments) == scanner.MaxPathPositions {
			payload.depthExceeded = true
			break
		}
		// Decode after splitting so an encoded slash stays inside its segment.
		decoded, err := url.PathUnescape(part)
		if err != nil {
			decoded = part
		}
		payload.segments = append(payload.segments, []byte(decoded))
	}
	if len(payload.segments) == 0 && !payload.depthExceeded {
		return nil
	}
	return payload
}

// extractOutboundPayload extracts the outbound data visible to the proxy for
// ceeEntropyExempt returns true if the target URL's hostname matches any
// domain in the exempt list. Uses scanner.MatchDomain for consistent
// wildcard behavior (trailing-dot normalization, *.example.com also
// matches example.com itself, IP exact match only).
func ceeEntropyExempt(targetURL string, exemptDomains []string) bool {
	if len(exemptDomains) == 0 {
		return false
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	for _, d := range exemptDomains {
		if scanner.MatchDomain(host, d) {
			return true
		}
	}
	return false
}

// entropy measurement and fragment buffering. Includes query parameter values
// in wire order and request body content. The URL path is excluded here and
// carried separately by pathSegments, so static route text cannot interleave
// with this stream. Re-wraps r.Body after reading so downstream handlers can
// still consume it.
func extractOutboundPayload(r *http.Request) []byte {
	var parts []string

	// Query parameter values in wire order for accurate fragment reconstruction.
	if qp := queryParamPayload(r.URL); len(qp) > 0 {
		parts = append(parts, string(qp))
	}

	// Request body (limited read to bound memory). Re-wrap after reading
	// so the forwarded request still has body data for the upstream.
	// Preserve the original closer so downstream cleanup still closes the
	// real request body (io.NopCloser would drop it, leaking resources).
	if r.Body != nil && r.ContentLength != 0 {
		origBody := r.Body
		limited := io.LimitReader(origBody, maxCEEBodyRead)
		bodyBytes, err := io.ReadAll(limited)
		if err == nil && len(bodyBytes) > 0 {
			parts = append(parts, string(bodyBytes))
		}
		// Concatenate read bytes with any remaining body data beyond the limit.
		r.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), origBody),
			Closer: origBody,
		}
	}

	return []byte(strings.Join(parts, ""))
}

// ceeEffectiveConfig returns a copy of the CEE config with actions downgraded
// to warn when global enforcement is disabled. This ensures ceeAdmit uses
// LogAnomaly (not LogBlocked) in detect-only mode, keeping the audit log
// consistent with the actual traffic decision.
func ceeEffectiveConfig(ceeCfg config.CrossRequestDetection, enforcing bool) config.CrossRequestDetection {
	if !enforcing {
		ceeCfg.Action = config.ActionWarn
		ceeCfg.EntropyBudget.Action = config.ActionWarn
	}
	return ceeCfg
}

// ceeResult holds the outcome of a CEE admission check.
type ceeResult struct {
	Blocked     bool
	Reason      string
	EntropyHit  bool // entropy budget exceeded (for metrics/signals)
	FragmentHit bool // fragment DLP match (for metrics/signals)
}

// ceeAdmit runs cross-request exfiltration detection on outbound payload data.
// It checks entropy budget and fragment reassembly DLP, returning a ceeResult
// indicating whether the request should be blocked. Callers are responsible for
// writing the HTTP response and recording metrics/signals based on the result.
//
// Three fragment streams are scanned independently:
//   - outbound (values + bare tokens + body): reconstructs secrets split
//     across parameter values or request bodies
//   - keyPayload (query parameter names only): reconstructs secrets split across
//     parameter names (e.g. ?AKIA=1 then ?IOSFODNN7EXAMPLE=2)
//   - pathPayload (absolute URL path positions): reconstructs path fragments
//     without repeated static route text interrupting the dynamic position
//
// Parameters:
//   - sessionKey: the session identity from CeeSessionKey()
//   - outbound: payload bytes (query values + bare tokens + body)
//   - keyPayload: query parameter keys only (nil for WebSocket/MCP)
//   - targetURL: the destination URL (for audit logging)
//   - ceeCfg: cross-request detection config section
//   - et: entropy tracker (may be nil if budget tracking disabled)
//   - fb: fragment buffer (may be nil if fragment reassembly disabled)
//   - sc: scanner for DLP pattern matching in fragment buffer
//   - logger: audit logger for event recording
//   - m: metrics recorder
//
// ceeAdmitOptions groups the admission inputs. A positional list this long
// invites argument-order errors, and every added stream lengthened it further
// (see the options-struct convention in CLAUDE.md).
type ceeAdmitOptions struct {
	SessionKey  string
	Outbound    []byte
	KeyPayload  []byte
	PathPayload *ceePathPayload
	TargetURL   string
	Agent       string
	ClientIP    string
	RequestID   string
	Config      config.CrossRequestDetection
	Entropy     *scanner.EntropyTracker
	Fragments   *scanner.FragmentBuffer
	Scanner     *scanner.Scanner
	Logger      *audit.Logger
	Metrics     *metrics.Metrics
}

func ceeAdmit(ctx context.Context, opts ceeAdmitOptions) ceeResult {
	sessionKey := opts.SessionKey
	outbound, keyPayload := opts.Outbound, opts.KeyPayload
	pathPayload := opts.PathPayload
	targetURL, agent := opts.TargetURL, opts.Agent
	clientIP, requestID := opts.ClientIP, opts.RequestID
	ceeCfg := opts.Config
	et, fb, sc := opts.Entropy, opts.Fragments, opts.Scanner
	logger, m := opts.Logger, opts.Metrics
	if len(outbound) == 0 && len(keyPayload) == 0 && (pathPayload == nil || (len(pathPayload.segments) == 0 && !pathPayload.depthExceeded)) {
		return ceeResult{}
	}

	var result ceeResult

	// Entropy budget check (values + bare tokens + body + keys).
	// Skip recording for exempt domains (e.g. API polling endpoints with
	// tokens in URLs that would exhaust the budget on normal traffic).
	entropyExempt := ceeEntropyExempt(targetURL, ceeCfg.EntropyBudget.ExemptDomains)
	if et != nil && ceeCfg.EntropyBudget.Enabled && !entropyExempt && (len(outbound) > 0 || len(keyPayload) > 0) {
		if len(outbound) > 0 {
			et.Record(sessionKey, outbound)
		}
		if len(keyPayload) > 0 {
			et.Record(sessionKey, keyPayload)
		}
		if et.BudgetExceeded(sessionKey) {
			result.EntropyHit = true
			m.RecordCrossRequestEntropyExceeded()
			detail := fmt.Sprintf("entropy budget exceeded: %.0f/%.0f bits",
				et.CurrentUsage(sessionKey), et.Budget())
			actx := newHTTPAuditContext(logger, "CEE", targetURL, clientIP, requestID, agent)
			if ceeCfg.EntropyBudget.Action == config.ActionBlock {
				logger.LogBlocked(actx, "cross_request_entropy", detail)
				result.Blocked = true
				result.Reason = "cross-request entropy budget exceeded"
				return result
			}
			logger.LogAnomaly(actx, "cross_request_entropy", detail, 0)
		}
	}

	// Depth enforcement is INDEPENDENT of fragment reassembly. A path deeper
	// than the cap cannot be fully represented, so forwarding it merely because
	// reassembly is disabled or unavailable would forward an uninspected
	// request: a fail-open in the one direction this stream exists to close.
	if pathPayload != nil && pathPayload.depthExceeded {
		m.RecordCrossRequestPathDepthExceeded()
		detail := fmt.Sprintf("URL path exceeds CEE depth cap (%d segments); request cannot be safely inspected",
			scanner.MaxPathPositions)
		actx := newHTTPAuditContext(logger, "CEE", targetURL, clientIP, requestID, agent)
		logger.LogBlocked(actx, "cross_request_path_depth", detail)
		result.Blocked = true
		result.FragmentHit = true
		result.Reason = detail
		return result
	}

	// Fragment reassembly DLP check (three independent streams).
	sctx := ceeStreamContext{
		TargetURL: targetURL, Agent: agent, ClientIP: clientIP, RequestID: requestID,
		Config: ceeCfg, Fragments: fb, Scanner: sc, Logger: logger, Metrics: m,
	}
	if fb != nil && ceeCfg.FragmentReassembly.Enabled {
		// Stream 1: values + bare tokens + body.
		if res := ceeFragmentScan(ctx, sessionKey, outbound, sctx); res != nil {
			result.FragmentHit = true
			if res.Blocked {
				result.Blocked = true
				result.Reason = res.Reason
				return result
			}
		}

		// Stream 2: query parameter keys (separate buffer, catches secrets
		// split across param names like ?AKIA=1 then ?IOSFODNN7EXAMPLE=2).
		if len(keyPayload) > 0 {
			keySessionKey := sessionKey + ceeStreamKeysSuffix
			if res := ceeFragmentScan(ctx, keySessionKey, keyPayload, sctx); res != nil {
				result.FragmentHit = true
				if res.Blocked {
					result.Blocked = true
					result.Reason = res.Reason
					return result
				}
			}
		}

		// Stream 3: URL path positions. Static route positions contribute once;
		// a position that varies keeps every value in arrival order.
		if pathPayload != nil && (len(pathPayload.segments) > 0 || pathPayload.depthExceeded) {
			pathSessionKey := sessionKey + ceeStreamPathSuffix
			if res := ceeFragmentScanSegments(ctx, pathSessionKey, pathPayload, sctx); res != nil {
				result.FragmentHit = true
				if res.Blocked {
					result.Blocked = true
					result.Reason = res.Reason
					return result
				}
			}
		}
	}

	return result
}

// ceeFragmentScan appends data to a fragment buffer stream and scans for DLP
// matches. Returns non-nil result if a match is found (blocked or warned).
// ceeStreamContext carries the per-request identifiers and collaborators that
// every fragment stream needs. It exists so adding a stream does not lengthen
// three positional signatures again (CLAUDE.md options-struct convention).
type ceeStreamContext struct {
	TargetURL string
	Agent     string
	ClientIP  string
	RequestID string
	Config    config.CrossRequestDetection
	Fragments *scanner.FragmentBuffer
	Scanner   *scanner.Scanner
	Logger    *audit.Logger
	Metrics   *metrics.Metrics
}

func ceeFragmentScan(ctx context.Context, bufferKey string, data []byte, sctx ceeStreamContext) *ceeResult {
	fb := sctx.Fragments
	if len(data) == 0 {
		return nil
	}
	return ceeFragmentEvaluate(ctx, bufferKey, fb.Append(bufferKey, data), false, sctx)
}

// ceeFragmentScanSegments is ceeFragmentScan for a position-aware path stream.
// Static positions contribute once; changing positions retain every later
// value, including repeats, so priming cannot suppress a completing suffix.
func ceeFragmentScanSegments(ctx context.Context, bufferKey string, payload *ceePathPayload, sctx ceeStreamContext) *ceeResult {
	fb := sctx.Fragments
	if payload == nil {
		return nil
	}
	// Over-depth paths are denied earlier in ceeAdmit, before the
	// fragment-reassembly gate, so they never reach this point.
	appendResult := fb.AppendPathSegments(bufferKey, payload.segments)
	return ceeFragmentEvaluate(ctx, bufferKey, appendResult, true, sctx)
}

// ceeFragmentEvaluate turns an append outcome into a CEE result: it fails
// closed on capacity exhaustion, then scans the reassembled stream for DLP
// matches. Shared so every fragment stream reports identically.
func ceeFragmentEvaluate(ctx context.Context, bufferKey string, appendResult scanner.FragmentAppendResult, pathStream bool, sctx ceeStreamContext) *ceeResult {
	targetURL, agent := sctx.TargetURL, sctx.Agent
	clientIP, requestID := sctx.ClientIP, sctx.RequestID
	ceeCfg := sctx.Config
	fb, sc := sctx.Fragments, sctx.Scanner
	logger, m := sctx.Logger, sctx.Metrics
	if appendResult.PathDepthExceeded {
		m.RecordCrossRequestPathDepthExceeded()
		detail := fmt.Sprintf("URL path exceeds CEE depth cap (%d segments); request cannot be safely inspected", scanner.MaxPathPositions)
		actx := newHTTPAuditContext(logger, "CEE", targetURL, clientIP, requestID, agent)
		logger.LogBlocked(actx, "cross_request_path_depth", detail)
		return &ceeResult{
			Blocked:     true,
			FragmentHit: true,
			Reason:      detail,
		}
	}
	if appendResult.CapacityExceeded {
		m.RecordCrossRequestFragmentCapacityExceeded()
		detail := "fragment reassembly session capacity exhausted; request cannot be safely inspected"
		actx := newHTTPAuditContext(logger, "CEE", targetURL, clientIP, requestID, agent)
		logger.LogBlocked(actx, "cross_request_fragment_capacity", detail)
		return &ceeResult{
			Blocked:     true,
			FragmentHit: true,
			Reason:      detail,
		}
	}
	matches := fb.ScanForSecrets(ctx, bufferKey, sc)
	if pathStream {
		matches = fb.ScanPathForSecrets(ctx, bufferKey, sc)
	}
	if len(matches) == 0 {
		return nil
	}
	m.RecordCrossRequestDLPMatch()
	detail := fmt.Sprintf("fragment reassembly DLP match: %s", matches[0].PatternName)
	actx := newHTTPAuditContext(logger, "CEE", targetURL, clientIP, requestID, agent)
	if ceeCfg.Action == config.ActionBlock {
		logger.LogBlocked(actx, "cross_request_fragment", detail)
		return &ceeResult{
			Blocked:     true,
			FragmentHit: true,
			Reason:      fmt.Sprintf("cross-request secret detected: %s", matches[0].PatternName),
		}
	}
	logger.LogAnomaly(actx, "cross_request_fragment", detail, 0)
	return &ceeResult{FragmentHit: true}
}

// ceeRecordSignals fires adaptive enforcement signals for CEE findings.
// Called after ceeAdmit when session profiling is active.
func ceeRecordSignals(result ceeResult, sm *SessionManager, sessionKey string, threshold float64, logger *audit.Logger, m *metrics.Metrics, clientIP, requestID string) {
	if sm == nil || (!result.EntropyHit && !result.FragmentHit) {
		return
	}
	sess := sm.GetOrCreate(sessionKey)
	ep := decide.EscalationParams{
		Threshold: threshold,
		Logger:    logger,
		Metrics:   m,
		Session:   sessionKey,
		ClientIP:  clientIP,
		RequestID: requestID,
	}
	if result.EntropyHit {
		decide.RecordSignal(sess, session.SignalEntropyBudget, ep)
	}
	if result.FragmentHit {
		// Fragment DLP match is high-confidence (reconstructed secret from fragments).
		// Use SignalFragmentDLP (3 points, same as SignalBlock) for strong escalation.
		decide.RecordSignal(sess, session.SignalFragmentDLP, ep)
	}
}

// ceeSignalParams groups the inputs for ceeRecordSignalsAndBlockAll. A struct
// keeps the call sites readable and avoids a long positional signature (see the
// options-struct convention in CLAUDE.md).
type ceeSignalParams struct {
	Result      ceeResult
	Sessions    *SessionManager
	SessionKey  string // the folded CEE key (see ceeSessionKey)
	AdaptiveCfg *config.AdaptiveEnforcement
	Logger      *audit.Logger
	Metrics     *metrics.Metrics
	ClientIP    string
	RequestID   string
}

// ceeRecordSignalsAndBlockAll records CEE adaptive signals and checks session
// deny against the same folded CEE key. Do not check a separately-created raw
// per-agent recorder here: for self-declared agent names, CEE intentionally
// collapses the key to client IP to prevent partitioning.
func ceeRecordSignalsAndBlockAll(p ceeSignalParams) (session.Recorder, bool) {
	if p.Sessions == nil || p.AdaptiveCfg == nil || !p.AdaptiveCfg.Enabled {
		return nil, false
	}
	ceeRecordSignals(p.Result, p.Sessions, p.SessionKey, p.AdaptiveCfg.EscalationThreshold, p.Logger, p.Metrics, p.ClientIP, p.RequestID)
	rec := p.Sessions.GetOrCreate(p.SessionKey)
	return rec, decide.UpgradeAction("", rec.EscalationLevel(), p.AdaptiveCfg) == config.ActionBlock
}
