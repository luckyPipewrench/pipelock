// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// CeeSessionKey builds a consistent session identity for cross-request
// exfiltration detection. Exported for use by the session reset admin API.
func CeeSessionKey(agent, clientIP string) string {
	if agent != "" && agent != agentAnonymous {
		return agent + "|" + clientIP
	}
	return clientIP
}

// ResetCEEState clears entropy and fragment state for a session identity.
// Entropy tracker: clears CeeSessionKey(agent, ip) (base key only).
// Fragment buffer: clears both CeeSessionKey(agent, ip) and CeeSessionKey(agent, ip)+"|keys".
// Safe to call with nil trackers (CEE disabled).
func ResetCEEState(agent, clientIP string, et *scanner.EntropyTracker, fb *scanner.FragmentBuffer) {
	key := CeeSessionKey(agent, clientIP)
	if et != nil {
		et.Delete(key)
	}
	if fb != nil {
		fb.Delete(key)
		fb.Delete(key + "|keys")
	}
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
// Path components are intentionally excluded: repeated paths across requests
// break DLP regex contiguity in the fragment buffer (e.g. "/get" inserted
// between fragments makes "AKIA" + "IOSFODNN7EXAMPLE" become
// "/getAKIA.../getIOSF..." which DLP cannot match). Path-based exfiltration
// is already caught by per-request DLP (layer 3) and path entropy (layer 4).
// Used by the fetch handler where the request body is always empty (GET-only).
func urlPayload(u *url.URL) []byte {
	return queryParamPayload(u)
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
// in wire order and request body content. URL path is intentionally excluded:
// repeated paths across requests break DLP regex contiguity in the fragment
// buffer. Path-based exfiltration is already caught by per-request DLP (layer
// 3) and path entropy (layer 4). Re-wraps r.Body after reading so downstream
// handlers can still consume it.
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
// Two fragment streams are scanned independently:
//   - outbound (values + bare tokens + body): reconstructs secrets split
//     across parameter values or request bodies
//   - keyPayload (query parameter names only): reconstructs secrets split across
//     parameter names (e.g. ?AKIA=1 then ?IOSFODNN7EXAMPLE=2)
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
func ceeAdmit(
	ctx context.Context,
	sessionKey string,
	outbound, keyPayload []byte,
	targetURL, agent, clientIP, requestID string,
	ceeCfg config.CrossRequestDetection,
	et *scanner.EntropyTracker,
	fb *scanner.FragmentBuffer,
	sc *scanner.Scanner,
	logger *audit.Logger,
	m *metrics.Metrics,
) ceeResult {
	if len(outbound) == 0 && len(keyPayload) == 0 {
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
			if ceeCfg.EntropyBudget.Action == config.ActionBlock {
				logger.LogBlocked("CEE", targetURL, "cross_request_entropy", detail, clientIP, requestID, agent)
				result.Blocked = true
				result.Reason = "cross-request entropy budget exceeded"
				return result
			}
			logger.LogAnomaly("CEE", targetURL, "cross_request_entropy", detail, clientIP, requestID, agent, 0)
		}
	}

	// Fragment reassembly DLP check (two independent streams).
	if fb != nil && ceeCfg.FragmentReassembly.Enabled {
		// Stream 1: values + bare tokens + body.
		if res := ceeFragmentScan(ctx, sessionKey, outbound, targetURL, agent, clientIP, requestID, ceeCfg, fb, sc, logger, m); res != nil {
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
			keySessionKey := sessionKey + "|keys"
			if res := ceeFragmentScan(ctx, keySessionKey, keyPayload, targetURL, agent, clientIP, requestID, ceeCfg, fb, sc, logger, m); res != nil {
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
func ceeFragmentScan(
	ctx context.Context,
	bufferKey string,
	data []byte,
	targetURL, agent, clientIP, requestID string,
	ceeCfg config.CrossRequestDetection,
	fb *scanner.FragmentBuffer,
	sc *scanner.Scanner,
	logger *audit.Logger,
	m *metrics.Metrics,
) *ceeResult {
	if len(data) == 0 {
		return nil
	}
	fb.Append(bufferKey, data)
	matches := fb.ScanForSecrets(ctx, bufferKey, sc)
	if len(matches) == 0 {
		return nil
	}
	m.RecordCrossRequestDLPMatch()
	detail := fmt.Sprintf("fragment reassembly DLP match: %s", matches[0].PatternName)
	if ceeCfg.Action == config.ActionBlock {
		logger.LogBlocked("CEE", targetURL, "cross_request_fragment", detail, clientIP, requestID, agent)
		return &ceeResult{
			Blocked:     true,
			FragmentHit: true,
			Reason:      fmt.Sprintf("cross-request secret detected: %s", matches[0].PatternName),
		}
	}
	logger.LogAnomaly("CEE", targetURL, "cross_request_fragment", detail, clientIP, requestID, agent, 0)
	return &ceeResult{FragmentHit: true}
}

// ceeRecordSignals fires adaptive enforcement signals for CEE findings.
// Called after ceeAdmit when session profiling is active.
func ceeRecordSignals(result ceeResult, sm *SessionManager, sessionKey string, threshold float64, logger *audit.Logger, m *metrics.Metrics, clientIP, requestID string) {
	if sm == nil || (!result.EntropyHit && !result.FragmentHit) {
		return
	}
	sess := sm.GetOrCreate(sessionKey)
	if result.EntropyHit {
		decide.RecordEscalation(sess, session.SignalEntropyBudget, decide.EscalationParams{
			Threshold: threshold,
			Logger:    logger,
			Metrics:   m,
			Session:   sessionKey,
			ClientIP:  clientIP,
			RequestID: requestID,
		})
	}
	if result.FragmentHit {
		// Fragment DLP match is high-confidence (reconstructed secret from fragments).
		// Use SignalFragmentDLP (3 points, same as SignalBlock) for strong escalation.
		decide.RecordEscalation(sess, session.SignalFragmentDLP, decide.EscalationParams{
			Threshold: threshold,
			Logger:    logger,
			Metrics:   m,
			Session:   sessionKey,
			ClientIP:  clientIP,
			RequestID: requestID,
		})
	}
}
