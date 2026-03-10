// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ceeSessionKey builds a consistent session identity for cross-request
// exfiltration detection. When an agent name is available, the key is
// "agent|clientIP". Otherwise, just the client IP.
func ceeSessionKey(agent, clientIP string) string {
	if agent != "" && agent != agentAnonymous {
		return agent + "|" + clientIP
	}
	return clientIP
}

// maxCEEBodyRead limits the body bytes read for CEE payload extraction.
// Larger bodies are unlikely to be fragment-based exfiltration attempts.
const maxCEEBodyRead = 65536 // 64KB

// queryParamPayload extracts query parameter values from a URL in sorted key
// order for deterministic concatenation. Only values are included (not key
// names) so DLP pattern matching sees contiguous secret data when fragments
// are reassembled across requests.
func queryParamPayload(u *url.URL) []byte {
	qv := u.Query()
	if len(qv) == 0 {
		return nil
	}
	keys := make([]string, 0, len(qv))
	for k := range qv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, qv[k]...)
	}
	return []byte(strings.Join(parts, ""))
}

// extractOutboundPayload extracts the outbound data visible to the proxy
// for entropy measurement and fragment buffering. Includes query parameter
// values and request body content. Re-wraps r.Body after reading so
// downstream handlers can still consume it.
func extractOutboundPayload(r *http.Request) []byte {
	var parts []string

	// Query parameter values in sorted key order for deterministic concatenation.
	if qp := queryParamPayload(r.URL); len(qp) > 0 {
		parts = append(parts, string(qp))
	}

	// Request body (limited read to bound memory). Re-wrap after reading
	// so the forwarded request still has body data for the upstream.
	if r.Body != nil && r.ContentLength != 0 {
		limited := io.LimitReader(r.Body, maxCEEBodyRead)
		bodyBytes, err := io.ReadAll(limited)
		if err == nil && len(bodyBytes) > 0 {
			parts = append(parts, string(bodyBytes))
		}
		// Concatenate read bytes with any remaining body data beyond the limit.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
	}

	return []byte(strings.Join(parts, ""))
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
// Parameters:
//   - sessionKey: the session identity from ceeSessionKey()
//   - outbound: payload bytes to analyze (query params + body)
//   - targetURL: the destination URL (for audit logging)
//   - ceeCfg: cross-request detection config section
//   - et: entropy tracker (may be nil if budget tracking disabled)
//   - fb: fragment buffer (may be nil if fragment reassembly disabled)
//   - sc: scanner for DLP pattern matching in fragment buffer
//   - logger: audit logger for event recording
//   - m: metrics recorder
func ceeAdmit(
	sessionKey string,
	outbound []byte,
	targetURL, agent, clientIP, requestID string,
	ceeCfg config.CrossRequestDetection,
	et *scanner.EntropyTracker,
	fb *scanner.FragmentBuffer,
	sc *scanner.Scanner,
	logger *audit.Logger,
	m *metrics.Metrics,
) ceeResult {
	if len(outbound) == 0 {
		return ceeResult{}
	}

	var result ceeResult

	// Entropy budget check.
	if et != nil && ceeCfg.EntropyBudget.Enabled {
		et.Record(sessionKey, outbound)
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

	// Fragment reassembly DLP check.
	if fb != nil && ceeCfg.FragmentReassembly.Enabled {
		fb.Append(sessionKey, outbound)
		if matches := fb.ScanForSecrets(sessionKey, sc); len(matches) > 0 {
			result.FragmentHit = true
			m.RecordCrossRequestDLPMatch()
			detail := fmt.Sprintf("fragment reassembly DLP match: %s", matches[0].PatternName)
			if ceeCfg.Action == config.ActionBlock {
				logger.LogBlocked("CEE", targetURL, "cross_request_fragment", detail, clientIP, requestID, agent)
				result.Blocked = true
				result.Reason = fmt.Sprintf("cross-request secret detected: %s", matches[0].PatternName)
				return result
			}
			logger.LogAnomaly("CEE", targetURL, "cross_request_fragment", detail, clientIP, requestID, agent, 0)
		}
	}

	return result
}

// ceeRecordSignals fires adaptive enforcement signals for CEE findings.
// Called after ceeAdmit when session profiling is active.
func ceeRecordSignals(result ceeResult, sm *SessionManager, sessionKey string, threshold float64, logger *audit.Logger, m *metrics.Metrics, clientIP, requestID string) {
	if sm == nil {
		return
	}
	sess := sm.GetOrCreate(sessionKey)
	if result.EntropyHit {
		if escalated, from, to := sess.RecordSignal(SignalEntropyBudget, threshold); escalated {
			logger.LogAdaptiveEscalation(sessionKey, from, to, clientIP, requestID, sess.ThreatScore())
			m.RecordSessionEscalation(from, to)
		}
	}
	if result.FragmentHit {
		// Fragment DLP match is high-confidence (reconstructed secret from fragments).
		// Use SignalFragmentDLP (3 points, same as SignalBlock) for strong escalation.
		if escalated, from, to := sess.RecordSignal(SignalFragmentDLP, threshold); escalated {
			logger.LogAdaptiveEscalation(sessionKey, from, to, clientIP, requestID, sess.ThreatScore())
			m.RecordSessionEscalation(from, to)
		}
	}
}
