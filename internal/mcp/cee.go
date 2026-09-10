// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
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
		runtime.buffer = scanner.NewFragmentBuffer(ceeCfg.FragmentReassembly.MaxBufferBytes, ceeCfg.FragmentReassembly.ResolvedMaxSessions(), ceeCfg.FragmentReassembly.WindowMinutes*60)
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
			runtime.buffer = scanner.NewFragmentBuffer(ceeCfg.FragmentReassembly.MaxBufferBytes, ceeCfg.FragmentReassembly.ResolvedMaxSessions(), ceeCfg.FragmentReassembly.WindowMinutes*60)
		} else {
			runtime.buffer.UpdateConfig(ceeCfg.FragmentReassembly.MaxBufferBytes, ceeCfg.FragmentReassembly.ResolvedMaxSessions(), ceeCfg.FragmentReassembly.WindowMinutes*60)
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

const (
	// mcpCEEArgumentMaxDepth bounds recursive token walking independently from
	// encoding/json's object decoding depth limit, which Decoder.Token does not
	// apply.
	mcpCEEArgumentMaxDepth = extract.DefaultJSONLeafMaxDepth

	// mcpCEEArgumentMaxStreams limits FragmentBuffer sessions created by one
	// tools/call frame. An overflow falls back to the complete raw frame.
	mcpCEEArgumentMaxStreams = extract.DefaultJSONLeafMaxStreams

	// mcpCEEArgumentMaxPathBytes bounds one escaped JSON argument path and the
	// cumulative allocation used by recursive descent.
	mcpCEEArgumentMaxPathBytes = extract.DefaultJSONLeafMaxPathBytes

	// mcpCEEArgumentMaxStreamKeyBytes also bounds the complete tool-qualified
	// stream key when an attacker supplies an unusually long tool identity.
	mcpCEEArgumentMaxStreamKeyBytes = 640
)

const (
	mcpCEEToolStreamPrefix      = "@tool/"
	mcpCEEArgumentStreamSuffix  = "/args"
	mcpCEESingletonStreamSuffix = "/singleton"
)

var mcpCEEPathEscaper = strings.NewReplacer("~", "~0", "/", "~1")

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
// A tools/call with exactly one non-empty argument also gets one synthetic
// stream scoped to its tool name. This covers field-name rotation: an attacker
// can choose a different (even fresh) argument name for every fragment, but
// cannot make those singleton values stop being the sole payload for the same
// tool. Multi-value calls deliberately do not join this stream, preserving the
// sibling isolation above. The extra stream adds at most one bounded fragment
// buffer per distinct tool name; FragmentBuffer's existing global session cap
// still bounds the total buffered state.
//
// Entropy accounting continues to use the raw frame. This reduction is only
// for fragment reassembly. Non-tool frames, malformed arguments, and argument
// values with no scalar content fall back to the raw frame so an unexpected
// shape cannot skip cross-request evaluation.
// mcpCEEFragmentPayloads reason values mirror the closed set enforced by
// metrics.RecordCrossRequestJSONPartitionFallback. An empty reason means the
// frame was either partitioned successfully or is genuinely out of scope for
// per-argument partitioning (not a tools/call), which is not a fallback.
const (
	// mcpCEEPartitionReasonMalformed marks a tools/call whose arguments would
	// not parse into complete leaf streams, so only the raw frame is scanned.
	mcpCEEPartitionReasonMalformed = "malformed"
	// mcpCEEPartitionReasonLimit marks a tools/call that parsed but exceeded a
	// per-frame bound (tool-qualified stream key length or stream count), so it
	// falls back to the raw frame. It maps to the "other" bucket.
	mcpCEEPartitionReasonLimit = "other"
)

// mcpCEEFragmentPayloads returns the per-argument fragment streams and a fallback
// reason. reason is non-empty only when a tools/call frame that COULD have been
// partitioned instead fell back to the raw frame, so callers can emit the same
// operator-visible partition-fallback counter the forward proxy uses. A frame
// that is simply not a partitionable tools/call reports no reason.
func mcpCEEFragmentPayloads(frame MCPFrame) (map[string][]byte, string) {
	if !frame.IsToolsCall() || len(frame.Args) == 0 || frame.ToolCallName == "" {
		return map[string][]byte{"": frame.Raw}, ""
	}
	toolPrefix, ok := mcpCEEToolStreamPrefixFor(frame.ToolCallName)
	if !ok {
		return map[string][]byte{"": frame.Raw}, mcpCEEPartitionReasonLimit
	}
	argumentPayloads, complete := extract.JSONLeafPayloads(frame.Args, extract.JSONLeafLimits{
		MaxDepth: mcpCEEArgumentMaxDepth, MaxStreams: mcpCEEArgumentMaxStreams, MaxPathBytes: mcpCEEArgumentMaxPathBytes,
	})
	if !complete {
		return map[string][]byte{"": frame.Raw}, mcpCEEPartitionReasonMalformed
	}
	payloads := make(map[string][]byte, len(argumentPayloads)+1)
	for path, value := range argumentPayloads {
		stream := toolPrefix + mcpCEEArgumentStreamSuffix + path
		if len(stream) > mcpCEEArgumentMaxStreamKeyBytes {
			return map[string][]byte{"": frame.Raw}, mcpCEEPartitionReasonLimit
		}
		payloads[stream] = value
	}
	if toolStream, value, ok := mcpCEEUnambiguousToolValue(toolPrefix, payloads); ok {
		if len(payloads) >= mcpCEEArgumentMaxStreams {
			return map[string][]byte{"": frame.Raw}, mcpCEEPartitionReasonLimit
		}
		payloads[toolStream] = append(payloads[toolStream], value...)
	}
	return payloads, ""
}

func mcpCEEToolStreamPrefixFor(toolName string) (string, bool) {
	if toolName == "" {
		return "", false
	}
	prefix := mcpCEEToolStreamPrefix + mcpCEEPathEscape(toolName)
	return prefix, len(prefix)+len(mcpCEEArgumentStreamSuffix)+1 <= mcpCEEArgumentMaxStreamKeyBytes
}

// mcpCEEUnambiguousToolValue returns the synthetic stream and value for a
// tools/call with exactly one non-empty argument leaf. Empty sibling values do
// not carry tool input, while two non-empty values are intentionally kept in
// their independent path streams to avoid inventing a concatenation between
// unrelated arguments.
func mcpCEEUnambiguousToolValue(toolPrefix string, payloads map[string][]byte) (string, []byte, bool) {
	if toolPrefix == "" {
		return "", nil, false
	}
	var value []byte
	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		if value != nil {
			return "", nil, false
		}
		value = payload
	}
	if len(value) == 0 {
		return "", nil, false
	}
	return toolPrefix + mcpCEESingletonStreamSuffix, value, true
}

// mcpCEEPathEscape escapes one tool-name or argument-path segment with RFC
// 6901 rules ('~' -> '~0', '/' -> '~1') so a segment containing those
// characters cannot forge a deeper path and collide two distinct streams.
func mcpCEEPathEscape(part string) string {
	return mcpCEEPathEscaper.Replace(part)
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

type ceeRecordMCPOptions struct {
	sessionKey       string
	entropyPayload   []byte
	fragmentPayloads map[string][]byte
	frame            MCPFrame
	cee              *CEEDeps
	sc               *scanner.Scanner
	logW             io.Writer
	logger           *audit.Logger
}

// ceeRecordMCP runs cross-request exfiltration checks on outbound MCP payload.
// Returns a non-empty reason string if the request should be blocked.
// Returns "" if clean or CEE is disabled.
func ceeRecordMCP(opts ceeRecordMCPOptions) string {
	if opts.cee == nil {
		return ""
	}
	tracker, buffer, m, ceeCfg, release := opts.cee.snapshot()
	defer release()
	if tracker == nil && (buffer == nil || !ceeCfg.FragmentReassembly.Enabled) {
		return ""
	}

	fragmentPayloads := opts.fragmentPayloads
	if buffer != nil && ceeCfg.FragmentReassembly.Enabled && fragmentPayloads == nil {
		var fallbackReason string
		fragmentPayloads, fallbackReason = mcpCEEFragmentPayloads(opts.frame)
		// A tools/call frame that could not be partitioned into per-argument
		// streams falls back to scanning the whole raw frame. Record the same
		// partition-fallback counter the forward proxy uses so operators see the
		// degraded-inspection signal on the MCP transport too.
		if fallbackReason != "" && m != nil {
			m.RecordCrossRequestJSONPartitionFallback(fallbackReason)
		}
	}
	if len(opts.entropyPayload) == 0 && len(fragmentPayloads) == 0 {
		return ""
	}
	if len(opts.entropyPayload) == 0 {
		for _, path := range mcpCEEFragmentPayloadPaths(fragmentPayloads) {
			payload := fragmentPayloads[path]
			if len(payload) == 0 {
				continue
			}
			opts.entropyPayload = payload
			break
		}
	}

	// Entropy budget check.
	if tracker != nil && ceeCfg.EntropyBudget.Enabled {
		tracker.Record(opts.sessionKey, opts.entropyPayload)
		if tracker.BudgetExceeded(opts.sessionKey) {
			if m != nil {
				m.RecordCrossRequestEntropyExceeded()
			}
			reason := fmt.Sprintf("cross-request entropy budget exceeded: %.0f/%.0f bits",
				tracker.CurrentUsage(opts.sessionKey), tracker.Budget())
			_, _ = fmt.Fprintf(opts.logW, "pipelock: CEE: %s (session=%s)\n", reason, opts.sessionKey)
			if ceeCfg.EntropyBudget.Action == config.ActionBlock {
				if opts.logger != nil {
					opts.logger.LogBlocked(mustMCPAuditContext(opts.logger, "CEE", "mcp-input"), "cross_request_entropy", reason)
				}
				return reason
			}
			// Warn mode: emit structured anomaly event for audit trail.
			if opts.logger != nil {
				opts.logger.LogAnomaly(mustMCPAuditContext(opts.logger, "CEE", "mcp-input"), "cross_request_entropy", reason, 0)
			}
		}
	}

	// Fragment reassembly DLP check.
	if buffer != nil && ceeCfg.FragmentReassembly.Enabled {
		seenSingletonFindings := make(map[string]struct{})
		seenArgumentFindings := make(map[string]struct{})
		for _, path := range mcpCEEFragmentPayloadPaths(fragmentPayloads) {
			payload := fragmentPayloads[path]
			if len(payload) == 0 {
				continue
			}
			fragmentKey := mcpCEEFragmentSessionKey(opts.sessionKey, path)
			// Every stream this frame opens belongs to one logical identity and
			// shares that identity's single ledger slot. Charging the ledger per
			// stream made an ordinary one-argument call cost two slots, so a
			// small max_sessions denied a first call outright, and let one
			// client's streams crowd out unrelated clients.
			owner := opts.sessionKey
			if owner == "" {
				owner = fragmentKey
			}
			// Capacity exhaustion always blocks, regardless of the configured
			// cross-request action, because the request is no longer inspectable.
			// Argument streams are the class whose cardinality the frame
			// chooses, so they share one byte budget. The raw-frame fallback
			// stream keeps its own cap: a session accumulates both over time,
			// and a large raw frame sharing the budget would evict the small
			// argument evidence a split secret is reassembled from.
			budgetGroup := fragmentKey
			if path != "" {
				budgetGroup = owner + mcpCEEArgumentStreamSuffix
			}
			appendResult := buffer.AppendOwnedInGroup(owner, budgetGroup, fragmentKey, payload)
			if appendResult.OwnerMismatch {
				if m != nil {
					m.RecordCrossRequestFragmentOwnerMismatch()
				}
				// Names no tunable: no configuration permits joining two
				// identities' fragments.
				reason := "cross-request fragment stream belongs to another identity; request cannot be safely inspected"
				_, _ = fmt.Fprintf(opts.logW, "pipelock: CEE: %s (session=%s)\n", reason, opts.sessionKey)
				if opts.logger != nil {
					opts.logger.LogBlocked(mustMCPAuditContext(opts.logger, "CEE", "mcp-input"), "cross_request_fragment_owner_mismatch", reason)
				}
				return reason
			}
			if appendResult.CapacityExceeded {
				if m != nil {
					m.RecordCrossRequestFragmentCapacityExceeded()
				}
				reason := "cross-request fragment session capacity exhausted; request cannot be safely inspected"
				_, _ = fmt.Fprintf(opts.logW, "pipelock: CEE: %s (session=%s)\n", reason, opts.sessionKey)
				if opts.logger != nil {
					opts.logger.LogBlocked(mustMCPAuditContext(opts.logger, "CEE", "mcp-input"), "cross_request_fragment_capacity", reason)
				}
				return reason
			}
			if matches := buffer.ScanForSecrets(context.Background(), fragmentKey, opts.sc); len(matches) > 0 {
				findingKey, kind := mcpCEEFragmentFindingKey(path, payload, matches[0].PatternName)
				if mcpCEEFragmentFindingAlreadyRecorded(kind, findingKey, seenSingletonFindings, seenArgumentFindings) {
					continue
				}
				if m != nil {
					m.RecordCrossRequestDLPMatch()
				}
				reason := fmt.Sprintf("cross-request fragment DLP match: %s; remove the secret from tool arguments, or lower cross_request_detection.fragment_reassembly.max_buffer_bytes for a narrower window (reduces protection against long chunk sequences)", matches[0].PatternName)
				_, _ = fmt.Fprintf(opts.logW, "pipelock: CEE: %s (session=%s)\n", reason, opts.sessionKey)
				if ceeCfg.Action == config.ActionBlock {
					if opts.logger != nil {
						opts.logger.LogBlocked(mustMCPAuditContext(opts.logger, "CEE", "mcp-input"), "cross_request_fragment", reason)
					}
					return reason
				}
				// Warn mode: emit structured anomaly event for audit trail.
				if opts.logger != nil {
					opts.logger.LogAnomaly(mustMCPAuditContext(opts.logger, "CEE", "mcp-input"), "cross_request_fragment", reason, 0)
				}
			}
		}
	}

	return ""
}

func mcpCEEFragmentPayloadPaths(payloads map[string][]byte) []string {
	paths := make([]string, 0, len(payloads))
	for path := range payloads {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

type mcpCEEFragmentStreamKind uint8

const (
	mcpCEEFragmentRawStream mcpCEEFragmentStreamKind = iota
	mcpCEEFragmentArgumentStream
	mcpCEEFragmentSingletonStream
)

func mcpCEEFragmentFindingKey(stream string, payload []byte, patternName string) (string, mcpCEEFragmentStreamKind) {
	if strings.HasSuffix(stream, mcpCEESingletonStreamSuffix) {
		digest := sha256.Sum256(payload)
		return strings.TrimSuffix(stream, mcpCEESingletonStreamSuffix) + "|" + fmt.Sprintf("%x", digest[:]) + "|" + patternName, mcpCEEFragmentSingletonStream
	}
	if index := strings.Index(stream, mcpCEEArgumentStreamSuffix+"$"); index >= 0 {
		digest := sha256.Sum256(payload)
		return stream[:index] + "|" + fmt.Sprintf("%x", digest[:]) + "|" + patternName, mcpCEEFragmentArgumentStream
	}
	return "", mcpCEEFragmentRawStream
}

func mcpCEEFragmentFindingAlreadyRecorded(kind mcpCEEFragmentStreamKind, findingKey string, singletonFindings, argumentFindings map[string]struct{}) bool {
	switch kind {
	case mcpCEEFragmentSingletonStream:
		_, duplicate := argumentFindings[findingKey]
		singletonFindings[findingKey] = struct{}{}
		return duplicate
	case mcpCEEFragmentArgumentStream:
		_, duplicate := singletonFindings[findingKey]
		argumentFindings[findingKey] = struct{}{}
		return duplicate
	default:
		return false
	}
}
