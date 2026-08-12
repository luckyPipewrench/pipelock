// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// CEEDeps holds optional cross-request exfiltration detection dependencies.
// All fields are nil-safe: nil disables the feature. Passed to MCP proxy
// functions so they can record outbound payloads for entropy and fragment
// analysis without adding individual parameters to already-complex signatures.
type CEEDeps struct {
	Tracker *scanner.EntropyTracker
	Buffer  *scanner.FragmentBuffer
	Metrics *metrics.Metrics
	Config  *config.CrossRequestDetection
	runtime *ceeRuntime
}

// ceeRuntime binds CEE policy and mutable tracking state under one lock. A
// request always reads both from the same generation; reload waits for an
// active check instead of pairing its old action with a newly changed limit.
type ceeRuntime struct {
	mu      sync.RWMutex
	tracker *scanner.EntropyTracker
	buffer  *scanner.FragmentBuffer
	metrics *metrics.Metrics
	config  config.CrossRequestDetection
}

// NewCEEDeps creates reload-safe MCP CEE dependencies from a config snapshot.
func NewCEEDeps(ceeCfg config.CrossRequestDetection, m *metrics.Metrics) *CEEDeps {
	runtime := &ceeRuntime{config: ceeCfg, metrics: m}
	if ceeCfg.Enabled && ceeCfg.EntropyBudget.Enabled {
		runtime.tracker = scanner.NewEntropyTracker(ceeCfg.EntropyBudget.BitsPerWindow, ceeCfg.EntropyBudget.WindowMinutes*60)
	}
	if ceeCfg.Enabled && ceeCfg.FragmentReassembly.Enabled {
		runtime.buffer = scanner.NewFragmentBuffer(ceeCfg.FragmentReassembly.MaxBufferBytes, 10000, ceeCfg.FragmentReassembly.WindowMinutes*60)
	}
	return &CEEDeps{
		runtime: runtime,
	}
}

// Reconfigure applies a new CEE policy while preserving state for components
// that remain enabled. It waits for in-flight checks so no request can combine
// a policy from one reload generation with limits from another.
func (cee *CEEDeps) Reconfigure(ceeCfg config.CrossRequestDetection, m *metrics.Metrics) {
	if cee == nil || cee.runtime == nil {
		return
	}
	runtime := cee.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	if ceeCfg.Enabled && ceeCfg.EntropyBudget.Enabled {
		if runtime.tracker == nil {
			runtime.tracker = scanner.NewEntropyTracker(ceeCfg.EntropyBudget.BitsPerWindow, ceeCfg.EntropyBudget.WindowMinutes*60)
		} else {
			runtime.tracker.UpdateConfig(ceeCfg.EntropyBudget.BitsPerWindow, ceeCfg.EntropyBudget.WindowMinutes*60)
		}
	} else {
		if runtime.tracker != nil {
			runtime.tracker.Close()
		}
		runtime.tracker = nil
	}
	if ceeCfg.Enabled && ceeCfg.FragmentReassembly.Enabled {
		if runtime.buffer == nil {
			runtime.buffer = scanner.NewFragmentBuffer(ceeCfg.FragmentReassembly.MaxBufferBytes, 10000, ceeCfg.FragmentReassembly.WindowMinutes*60)
		} else {
			runtime.buffer.UpdateConfig(ceeCfg.FragmentReassembly.MaxBufferBytes, ceeCfg.FragmentReassembly.WindowMinutes*60)
		}
	} else {
		if runtime.buffer != nil {
			runtime.buffer.Close()
		}
		runtime.buffer = nil
	}
	runtime.config = ceeCfg
	runtime.metrics = m
}

// Close retires all stateful detectors and clears buffered request data.
func (cee *CEEDeps) Close() {
	if cee == nil || cee.runtime == nil {
		return
	}
	runtime := cee.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.tracker != nil {
		runtime.tracker.Close()
		runtime.tracker = nil
	}
	if runtime.buffer != nil {
		runtime.buffer.Close()
		runtime.buffer = nil
	}
	runtime.config = config.CrossRequestDetection{}
}

// Components returns the currently active stateful detectors. Callers must not
// retain the returned pointers across a concurrent Reconfigure call.
func (cee *CEEDeps) Components() (*scanner.EntropyTracker, *scanner.FragmentBuffer) {
	tracker, buffer, _, _, release := cee.snapshot()
	defer release()
	return tracker, buffer
}

func (cee *CEEDeps) snapshot() (*scanner.EntropyTracker, *scanner.FragmentBuffer, *metrics.Metrics, config.CrossRequestDetection, func()) {
	if cee == nil || cee.runtime == nil {
		if cee == nil || cee.Config == nil {
			return nil, nil, nil, config.CrossRequestDetection{}, func() {}
		}
		return cee.Tracker, cee.Buffer, cee.Metrics, *cee.Config, func() {}
	}
	runtime := cee.runtime
	runtime.mu.RLock()
	return runtime.tracker, runtime.buffer, runtime.metrics, runtime.config, runtime.mu.RUnlock
}

// ceeSessionKeyMCP builds a CEE session key for MCP traffic. The agent
// identifier distinguishes traffic when multiple agents share a proxy.
func ceeSessionKeyMCP(agent, sessionOrIP string) string {
	if agent != "" {
		return agent + "|" + sessionOrIP
	}
	return sessionOrIP
}

// mcpCEEFragmentPayload returns the text-bearing tool argument values in a
// stable order for fragment reassembly. CEE previously buffered the entire
// JSON-RPC envelope, which placed protocol syntax and unrelated fields between
// chunks from consecutive tools/call requests. That makes a secret split over
// calls non-contiguous to the fragment DLP scanner even though the tool server
// receives contiguous argument data.
//
// Entropy accounting continues to use the raw frame. This reduction is only
// for fragment reassembly. Non-tool frames, malformed arguments, and argument
// values with no scalar content fall back to the raw frame so an unexpected
// shape cannot skip cross-request evaluation.
func mcpCEEFragmentPayload(frame MCPFrame) []byte {
	if !frame.IsToolsCall() || len(frame.Args) == 0 {
		return frame.Raw
	}

	decoder := json.NewDecoder(bytes.NewReader(frame.Args))
	decoder.UseNumber()
	var arguments any
	if err := decoder.Decode(&arguments); err != nil {
		return frame.Raw
	}

	var payload bytes.Buffer
	if !appendMCPCEEArgumentText(&payload, arguments) || payload.Len() == 0 {
		return frame.Raw
	}
	return payload.Bytes()
}

// appendMCPCEEArgumentText emits every scalar argument value without JSON
// scaffolding. Map keys are sorted so semantically equivalent MCP argument
// objects produce the same stream regardless of Go map iteration order. Array
// order remains significant and is retained.
func appendMCPCEEArgumentText(dst *bytes.Buffer, value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		dst.WriteString(v)
		return true
	case json.Number:
		dst.WriteString(v.String())
		return true
	case bool:
		dst.WriteString(strconv.FormatBool(v))
		return true
	case []any:
		for _, item := range v {
			if !appendMCPCEEArgumentText(dst, item) {
				return false
			}
		}
		return true
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !appendMCPCEEArgumentText(dst, v[key]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// ceeRecordMCP runs cross-request exfiltration checks on outbound MCP payload.
// Returns a non-empty reason string if the request should be blocked.
// Returns "" if clean or CEE is disabled.
func ceeRecordMCP(
	sessionKey string,
	entropyPayload []byte,
	fragmentPayload []byte,
	cee *CEEDeps,
	sc *scanner.Scanner,
	logW io.Writer,
	logger *audit.Logger,
) string {
	if cee == nil || (len(entropyPayload) == 0 && len(fragmentPayload) == 0) {
		return ""
	}
	if len(entropyPayload) == 0 {
		entropyPayload = fragmentPayload
	}
	if len(fragmentPayload) == 0 {
		fragmentPayload = entropyPayload
	}
	tracker, buffer, m, ceeCfg, release := cee.snapshot()
	defer release()

	// Entropy budget check.
	if tracker != nil && ceeCfg.EntropyBudget.Enabled {
		tracker.Record(sessionKey, entropyPayload)
		if tracker.BudgetExceeded(sessionKey) {
			if m != nil {
				m.RecordCrossRequestEntropyExceeded()
			}
			reason := fmt.Sprintf("cross-request entropy budget exceeded: %.0f/%.0f bits",
				tracker.CurrentUsage(sessionKey), tracker.Budget())
			_, _ = fmt.Fprintf(logW, "pipelock: CEE: %s (session=%s)\n", reason, sessionKey)
			if ceeCfg.EntropyBudget.Action == config.ActionBlock {
				if logger != nil {
					logger.LogBlocked(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_entropy", reason)
				}
				return reason
			}
			// Warn mode: emit structured anomaly event for audit trail.
			if logger != nil {
				logger.LogAnomaly(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_entropy", reason, 0)
			}
		}
	}

	// Fragment reassembly DLP check.
	if buffer != nil && ceeCfg.FragmentReassembly.Enabled {
		buffer.Append(sessionKey, fragmentPayload)
		if matches := buffer.ScanForSecrets(context.Background(), sessionKey, sc); len(matches) > 0 {
			if m != nil {
				m.RecordCrossRequestDLPMatch()
			}
			reason := fmt.Sprintf("cross-request fragment DLP match: %s; remove the secret from tool arguments, or lower cross_request_detection.fragment_reassembly.max_buffer_bytes for a narrower window (reduces protection against long chunk sequences)", matches[0].PatternName)
			_, _ = fmt.Fprintf(logW, "pipelock: CEE: %s (session=%s)\n", reason, sessionKey)
			if ceeCfg.Action == config.ActionBlock {
				if logger != nil {
					logger.LogBlocked(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_fragment", reason)
				}
				return reason
			}
			// Warn mode: emit structured anomaly event for audit trail.
			if logger != nil {
				logger.LogAnomaly(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_fragment", reason, 0)
			}
		}
	}

	return ""
}
