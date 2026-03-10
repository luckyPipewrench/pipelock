// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// queryParamPayload extracts query parameter values from a URL as a single
// byte slice. Keys are not included (they are not agent-controlled data).
func queryParamPayload(u *url.URL) []byte {
	qv := u.Query()
	if len(qv) == 0 {
		return nil
	}
	var parts []string
	for _, values := range qv {
		parts = append(parts, values...)
	}
	return []byte(strings.Join(parts, ""))
}

// extractOutboundPayload extracts the outbound data visible to the proxy
// for entropy measurement and fragment buffering. Includes query parameter
// values and request body content. Re-wraps r.Body after reading so
// downstream handlers can still consume it.
func extractOutboundPayload(r *http.Request) []byte {
	var parts []string

	// Query parameter values (keys are not agent-controlled data).
	for _, values := range r.URL.Query() {
		parts = append(parts, values...)
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
			logger.LogBlocked("CEE", targetURL, "cross_request_entropy",
				fmt.Sprintf("entropy budget exceeded: %.0f/%.0f bits",
					et.CurrentUsage(sessionKey), et.Budget()),
				clientIP, requestID, agent)
			if ceeCfg.EntropyBudget.Action == config.ActionBlock {
				result.Blocked = true
				result.Reason = "cross-request entropy budget exceeded"
				return result
			}
		}
	}

	// Fragment reassembly DLP check.
	if fb != nil && ceeCfg.FragmentReassembly.Enabled {
		fb.Append(sessionKey, outbound)
		if matches := fb.ScanForSecrets(sessionKey, sc); len(matches) > 0 {
			result.FragmentHit = true
			m.RecordCrossRequestDLPMatch()
			logger.LogBlocked("CEE", targetURL, "cross_request_fragment",
				fmt.Sprintf("fragment reassembly DLP match: %s", matches[0].PatternName),
				clientIP, requestID, agent)
			if ceeCfg.Action == config.ActionBlock {
				result.Blocked = true
				result.Reason = fmt.Sprintf("cross-request secret detected: %s", matches[0].PatternName)
				return result
			}
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
