// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
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

// mcpCEEFragmentPayloads returns text-bearing tool argument values partitioned
// by their argument path for fragment reassembly. CEE previously buffered the
// entire JSON-RPC envelope, which placed protocol syntax and unrelated fields
// between chunks from consecutive tools/call requests. That makes a secret
// split over calls non-contiguous to the fragment DLP scanner even though the
// tool server receives contiguous argument data. Flattening all argument
// values has the same defect when a benign sibling field (for example a page
// number or progress label) appears alongside each data chunk, so each leaf
// argument receives its own rolling stream.
//
// Entropy accounting continues to use the raw frame. This reduction is only
// for fragment reassembly. Non-tool frames, malformed arguments, and argument
// values with no scalar content fall back to the raw frame so an unexpected
// shape cannot skip cross-request evaluation.
func mcpCEEFragmentPayloads(frame MCPFrame) map[string][]byte {
	if !frame.IsToolsCall() || len(frame.Args) == 0 {
		return map[string][]byte{"": frame.Raw}
	}
	decoder := json.NewDecoder(bytes.NewReader(frame.Args))
	decoder.UseNumber()
	payloads := make(map[string][]byte)
	if !appendMCPCEEArgumentText(decoder, payloads, "$") || len(payloads) == 0 {
		return map[string][]byte{"": frame.Raw}
	}
	if _, err := decoder.Token(); err != io.EOF {
		return map[string][]byte{"": frame.Raw}
	}
	return payloads
}

// appendMCPCEEArgumentText walks a JSON value in wire order and appends each
// scalar to its JSON-pointer-like argument path. A decoder, instead of a Go
// map, preserves array and object ordering without reintroducing JSON syntax
// between values. Object keys identify a stream but are not themselves mixed
// into data values: a server receives alpha and progress as distinct arguments.
func appendMCPCEEArgumentText(decoder *json.Decoder, payloads map[string][]byte, path string) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return false
				}
				keyString, ok := key.(string)
				if !ok || !appendMCPCEEArgumentText(decoder, payloads, path+"/"+mcpCEEPathEscape(keyString)) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for index := 0; decoder.More(); index++ {
				if !appendMCPCEEArgumentText(decoder, payloads, path+"/"+strconv.Itoa(index)) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	case nil:
		return true
	case string:
		payloads[path] = append(payloads[path], value...)
		return true
	case json.Number:
		payloads[path] = append(payloads[path], value.String()...)
		return true
	case bool:
		payloads[path] = append(payloads[path], strconv.FormatBool(value)...)
		return true
	default:
		return false
	}
}

func mcpCEEPathEscape(part string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(part)
}

// mcpCEEFragmentSessionKey isolates one argument path's fragment history from
// its siblings. Hashing keeps attacker-controlled paths bounded in tracker
// keys without preserving a plaintext tool schema in memory or logs.
func mcpCEEFragmentSessionKey(sessionKey, path string) string {
	if path == "" {
		return sessionKey
	}
	digest := sha256.Sum256([]byte(path))
	return sessionKey + "|mcp-arg|" + fmt.Sprintf("%x", digest[:])
}

// ceeRecordMCP runs cross-request exfiltration checks on outbound MCP payload.
// Returns a non-empty reason string if the request should be blocked.
// Returns "" if clean or CEE is disabled.
func ceeRecordMCP(
	sessionKey string,
	entropyPayload []byte,
	fragmentPayloads map[string][]byte,
	cee *CEEDeps,
	sc *scanner.Scanner,
	logW io.Writer,
	logger *audit.Logger,
) string {
	if cee == nil || (len(entropyPayload) == 0 && len(fragmentPayloads) == 0) {
		return ""
	}
	if len(entropyPayload) == 0 {
		for _, payload := range fragmentPayloads {
			entropyPayload = payload
			break
		}
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
		for path, payload := range fragmentPayloads {
			if len(payload) == 0 {
				continue
			}
			fragmentKey := mcpCEEFragmentSessionKey(sessionKey, path)
			buffer.Append(fragmentKey, payload)
			if matches := buffer.ScanForSecrets(context.Background(), fragmentKey, sc); len(matches) > 0 {
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
	}

	return ""
}
