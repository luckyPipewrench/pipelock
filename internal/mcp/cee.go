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
	"sort"
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

const (
	// mcpCEEArgumentMaxDepth bounds recursive token walking independently from
	// encoding/json's object decoding depth limit, which Decoder.Token does not
	// apply.
	mcpCEEArgumentMaxDepth = 64

	// mcpCEEArgumentMaxStreams limits FragmentBuffer sessions created by one
	// tools/call frame. An overflow falls back to the complete raw frame.
	mcpCEEArgumentMaxStreams = 128

	// mcpCEEArgumentMaxPathBytes bounds one escaped JSON argument path and the
	// cumulative allocation used by recursive descent.
	mcpCEEArgumentMaxPathBytes = 512

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
func mcpCEEFragmentPayloads(frame MCPFrame) map[string][]byte {
	if !frame.IsToolsCall() || len(frame.Args) == 0 || frame.ToolCallName == "" {
		return map[string][]byte{"": frame.Raw}
	}
	toolPrefix, ok := mcpCEEToolStreamPrefixFor(frame.ToolCallName)
	if !ok {
		return map[string][]byte{"": frame.Raw}
	}
	decoder := json.NewDecoder(bytes.NewReader(frame.Args))
	decoder.UseNumber()
	payloads := make(map[string][]byte)
	if !appendMCPCEEArgumentText(decoder, payloads, toolPrefix, []byte("$"), 0) || len(payloads) == 0 {
		return map[string][]byte{"": frame.Raw}
	}
	if _, err := decoder.Token(); err != io.EOF {
		return map[string][]byte{"": frame.Raw}
	}
	if toolStream, value, ok := mcpCEEUnambiguousToolValue(toolPrefix, payloads); ok {
		if len(payloads) >= mcpCEEArgumentMaxStreams {
			return map[string][]byte{"": frame.Raw}
		}
		payloads[toolStream] = append(payloads[toolStream], value...)
	}
	return payloads
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

// appendMCPCEEArgumentText walks a JSON value in wire order and appends each
// scalar to its JSON-pointer-like argument path. A decoder, instead of a Go
// map, preserves array and object ordering without reintroducing JSON syntax
// between values. Object keys identify a stream but are not themselves mixed
// into data values: a server receives alpha and progress as distinct arguments.
// The mutable path buffer avoids allocating a new cumulative path at each
// nested object key or array element.
func appendMCPCEEArgumentText(decoder *json.Decoder, payloads map[string][]byte, toolPrefix string, path []byte, depth int) bool {
	if depth > mcpCEEArgumentMaxDepth {
		return false
	}
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
				if !ok {
					return false
				}
				pathLen := len(path)
				path, ok = mcpCEEAppendPathPart(path, keyString)
				if !ok || !appendMCPCEEArgumentText(decoder, payloads, toolPrefix, path, depth+1) {
					return false
				}
				path = path[:pathLen]
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		default:
			// json.Decoder only yields '{' or '[' as an opening delimiter.
			// A different delimiter reaches the same fail-closed end-token check.
			for index := 0; decoder.More(); index++ {
				pathLen := len(path)
				var ok bool
				path, ok = mcpCEEAppendPathPart(path, strconv.Itoa(index))
				if !ok || !appendMCPCEEArgumentText(decoder, payloads, toolPrefix, path, depth+1) {
					return false
				}
				path = path[:pathLen]
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		}
	case nil:
		return true
	case string:
		return mcpCEEAppendArgumentPayload(payloads, toolPrefix, path, value)
	case json.Number:
		return mcpCEEAppendArgumentPayload(payloads, toolPrefix, path, value.String())
	case bool:
		return mcpCEEAppendArgumentPayload(payloads, toolPrefix, path, strconv.FormatBool(value))
	default:
		return false
	}
}

func mcpCEEAppendPathPart(path []byte, part string) ([]byte, bool) {
	pathBytes := len(path) + 1
	for i := 0; i < len(part); i++ {
		pathBytes++
		if part[i] == '~' || part[i] == '/' {
			pathBytes++
		}
	}
	if pathBytes > mcpCEEArgumentMaxPathBytes {
		return nil, false
	}
	path = append(path, '/')
	for i := 0; i < len(part); i++ {
		switch part[i] {
		case '~':
			path = append(path, '~', '0')
		case '/':
			path = append(path, '~', '1')
		default:
			path = append(path, part[i])
		}
	}
	return path, true
}

func mcpCEEAppendArgumentPayload(payloads map[string][]byte, toolPrefix string, path []byte, value string) bool {
	stream := toolPrefix + mcpCEEArgumentStreamSuffix + string(path)
	if len(stream) > mcpCEEArgumentMaxStreamKeyBytes {
		return false
	}
	if _, exists := payloads[stream]; !exists && len(payloads) >= mcpCEEArgumentMaxStreams {
		return false
	}
	payloads[stream] = append(payloads[stream], value...)
	return true
}

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
		fragmentPayloads = mcpCEEFragmentPayloads(opts.frame)
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
			buffer.Append(fragmentKey, payload)
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
