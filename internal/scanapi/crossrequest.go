// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// maxScanAPISessionIDBytes bounds the caller-supplied context.session_id
// field. There is no existing session-key length bound elsewhere in the Scan
// API to inherit, so this uses the same order of magnitude as other
// server-derived identity ceilings in the codebase (for example
// scanner.MaxFragmentSourceRequestIDBytes at 128).
const maxScanAPISessionIDBytes = 128

// validScanAPISessionID matches one or more visible, non-whitespace ASCII
// bytes (0x21-0x7e). This excludes space, tab, newline, other control
// characters, and any non-ASCII byte, so a session_id can never collide with
// identitykey's scanAPIIdentityNamespace separator (0x1f) or contain content
// that would be awkward to log or use as a map/metrics key.
var validScanAPISessionID = regexp.MustCompile(`^[\x21-\x7e]+$`)

// validateSessionID rejects a malformed context.session_id. An empty or
// absent session_id is valid and means "no cross-request accumulation for
// this request" (today's stateless behavior, unchanged).
func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return nil
	}
	if len(sessionID) > maxScanAPISessionIDBytes {
		return errSessionIDTooLong
	}
	if !validScanAPISessionID.MatchString(sessionID) {
		return errSessionIDInvalidChars
	}
	return nil
}

var (
	errSessionIDTooLong      = errors.New("context.session_id exceeds 128 bytes")
	errSessionIDInvalidChars = errors.New("context.session_id must contain only visible ASCII characters with no whitespace")
)

// callerKeyForToken derives the caller-identity component of a Scan API CEE
// key from the authenticated bearer token. The token itself is never used
// directly: it is a live credential, and CEE identities appear in operator
// logs, metrics label values are avoided but the identity is not, and in
// buffer-internal maps kept for the buffer's configured retention window. A
// SHA-256 digest of the full token authenticates the same caller across
// requests (the same token always yields the same digest) without retaining
// the credential itself anywhere the session state lives.
func callerKeyForToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// crossRequestFragments is this Handler's cross-request DLP fragment
// reassembly state. It is deliberately a separate FragmentBuffer instance
// from the forward-proxy and MCP proxy buffers (see internal/proxy/cee.go
// and internal/mcp/cee.go, which each already keep their own instance too):
// the Scan API is a distinct transport with its own request shape, and
// identitykey.NewScanAPIIdentity's namespace only has to be collision-safe
// against the OTHER transports' key shapes, not against a shared buffer's
// unrelated capacity accounting.
//
// The buffer is lazily built on this Handler from the live
// config.CrossRequestDetection.FragmentReassembly. A request that observes
// a changed size, session cap, or window applies it in place through
// UpdateConfig on the same instance (the buffer enforces the new bounds on
// its next append); disabling fragment reassembly closes and drops the
// buffer, and re-enabling starts empty.
//
// The state is process-local. A deployment that runs more than one Scan API
// instance behind a load balancer must route a caller's session to one
// instance; two halves of a secret that land on different instances are
// each a first fragment. The public docs state this precondition.
type crossRequestFragments struct {
	mu     sync.Mutex
	buffer *scanner.FragmentBuffer
	cfg    config.CrossRequestFragments
	built  bool
	// lastConfig is the config object the buffer was last resolved against.
	// A reload swaps the live config pointer, so a different pointer means
	// at least one reload happened since the last session-bearing request.
	// The buffer is dropped on every reload, matching the forward proxy and
	// MCP paths, so a disable-then-enable interval with no request in
	// between cannot carry fragments across it.
	lastConfig *config.Config
}

// currentFor resolves the live buffer for the config a request was admitted
// under. Generations move forward only: live is the handler's current config
// at the moment of the append, so a request still holding an earlier config
// after a reload is stale and gets no buffer (its single-request scan still
// ran; it simply retains nothing), and it can never roll the buffer back to
// its own generation. The whole resolution runs under one lock so two
// requests from different generations cannot interleave a close and a
// rebuild between them.
func (c *crossRequestFragments) currentFor(cfg *config.Config, liveFn func() *config.Config) *scanner.FragmentBuffer {
	if c == nil || cfg == nil || liveFn == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The live config is sampled UNDER the lock: a request that sampled it
	// before a reload and paused cannot present a stale (cfg, live) pair
	// that still compares equal and roll the buffer back to its own
	// generation. A request holding the old config keeps that object alive,
	// so the pointer can never be reused for a newer generation.
	live := liveFn()
	if c.lastConfig != live {
		c.lastConfig = live
		c.closeLocked()
	}
	if cfg != live {
		return nil
	}
	return c.currentLocked(cfg.CrossRequestDetection)
}

func (c *crossRequestFragments) closeLocked() {
	if c.buffer != nil {
		c.buffer.Close()
		c.buffer = nil
		c.built = false
	}
}

// current returns the live buffer for cfg, rebuilding it if this is the
// first call or the resolved fragment-reassembly configuration changed.
// Returns nil when fragment reassembly (or cross-request detection as a
// whole) is disabled.
func (c *crossRequestFragments) current(ceeCfg config.CrossRequestDetection) *scanner.FragmentBuffer {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentLocked(ceeCfg)
}

// currentLocked is current's body. Callers hold c.mu.
func (c *crossRequestFragments) currentLocked(ceeCfg config.CrossRequestDetection) *scanner.FragmentBuffer {
	if !ceeCfg.Enabled || !ceeCfg.FragmentReassembly.Enabled {
		c.closeLocked()
		return nil
	}

	frag := ceeCfg.FragmentReassembly
	if !c.built {
		c.buffer = scanner.NewFragmentBuffer(frag.MaxBufferBytes, frag.ResolvedMaxSessions(), frag.WindowMinutes*60)
		c.cfg = frag
		c.built = true
		return c.buffer
	}
	if c.cfg.MaxBufferBytes != frag.MaxBufferBytes ||
		c.cfg.ResolvedMaxSessions() != frag.ResolvedMaxSessions() ||
		c.cfg.WindowMinutes != frag.WindowMinutes {
		c.buffer.UpdateConfig(frag.MaxBufferBytes, frag.ResolvedMaxSessions(), frag.WindowMinutes*60)
		c.cfg = frag
	}
	return c.buffer
}

// crossRequestOutcome describes the effect of feeding one request's content
// into cross-request fragment reassembly.
type crossRequestOutcome struct {
	// Blocked means this request cannot be safely inspected (capacity
	// exhausted or an identity/stream ownership conflict) and must fail
	// closed regardless of the configured action, matching the MCP and
	// forward-proxy CEE paths (internal/mcp/cee.go, internal/proxy/cee.go):
	// an uninspectable request is never treated as a clean allow.
	Blocked     bool
	BlockReason string
	BlockRuleID string
	// Matched means accumulated fragments completed at least one DLP pattern
	// match; Matches carries every completed pattern with its contributors.
	Matched bool
	Matches []crossRequestMatch
	Action  string // config.ActionBlock or config.ActionWarn
}

// crossRequestMatch is one completed cross-request DLP pattern match.
type crossRequestMatch struct {
	PatternName  string
	Contributors []string
}

// checkCrossRequestFragment appends payload to the caller's Scan API
// fragment session (namespaced by callerKey + sessionID, see
// identitykey.NewScanAPIIdentity) and scans the reassembled buffer for a DLP
// match. scanID is this request's own generated scan_id: it is retained as
// the fragment's SourceRequestID so a LATER request's completing match can
// report which earlier scan_id(s) contributed, mirroring the MCP path's
// per-fragment RPC-ID provenance (internal/mcp/cee.go).
//
// sessionID == "" is the caller's signal for "no cross-request accumulation"
// and must not reach here (callers check this first): callerKeyForToken
// always produces a non-empty value.
func checkCrossRequestFragment(
	ctx context.Context,
	buffer *scanner.FragmentBuffer,
	sc *scanner.Scanner,
	m *metrics.Metrics,
	ceeCfg config.CrossRequestDetection,
	callerKey, sessionID, scanID string,
	payload []byte,
) crossRequestOutcome {
	if buffer == nil || len(payload) == 0 {
		return crossRequestOutcome{}
	}
	// The CALLER is the owner the buffer's capacity ledger admits, and each
	// session is a stream inside that caller's one budget group. That is what
	// keeps one caller from denying every other caller service: max_sessions
	// bounds distinct callers with live state, not freely chosen session IDs,
	// and a caller that opens many sessions evicts only its own oldest
	// fragments once its shared max_buffer_bytes budget is spent. The empty
	// group name cannot collide with a session because session IDs are
	// validated non-empty.
	identity := identitykey.NewScanAPIIdentity(callerKey)
	group := identity.Stream("")
	stream := identity.Stream(sessionID)
	result, batchMatches := buffer.AppendAndScanOwnedBatch(ctx, identity, []scanner.FragmentAppend{{
		Group:           group,
		Stream:          stream,
		Payload:         payload,
		SourceRequestID: []byte(scanID),
	}}, sc)
	if err := ctx.Err(); err != nil {
		// The reassembled scan did not complete. An uninspected request is
		// never a clean allow, the same direction the per-request scans
		// take when their context ends.
		return crossRequestOutcome{
			Blocked:     true,
			BlockRuleID: "CEE-scan-cancelled",
			BlockReason: "cross-request fragment scan did not complete: " + err.Error(),
		}
	}
	var matches []scanner.DLPMatch
	if len(batchMatches) > 0 {
		matches = batchMatches[0]
	}

	if result.OwnerMismatch {
		if m != nil {
			m.RecordCrossRequestFragmentOwnerMismatch()
		}
		return crossRequestOutcome{
			Blocked:     true,
			BlockRuleID: "CEE-owner-mismatch",
			BlockReason: "cross-request fragment stream belongs to another identity; request cannot be safely inspected",
		}
	}
	if result.CapacityExceeded {
		if m != nil {
			m.RecordCrossRequestFragmentCapacityExceeded()
		}
		return crossRequestOutcome{
			Blocked:     true,
			BlockRuleID: "CEE-capacity-exceeded",
			BlockReason: "cross-request fragment capacity exhausted: the number of callers with live fragment state reached cross_request_detection.fragment_reassembly.max_sessions; request cannot be safely inspected; capacity recovers when a caller's fragments expire (fragment_reassembly.window_minutes), when the config is reloaded with a larger max_sessions, or on restart",
		}
	}
	if len(matches) == 0 {
		return crossRequestOutcome{}
	}
	if m != nil {
		m.RecordCrossRequestDLPMatch()
	}
	out := crossRequestOutcome{Matched: true, Action: ceeCfg.Action, Matches: make([]crossRequestMatch, 0, len(matches))}
	for _, match := range matches {
		// The documented contract is the EARLIER requests whose retained
		// bytes contributed; the completing request is the one carrying
		// this finding and is not listed among its own contributors.
		contributors := make([]string, 0, len(match.Contributors))
		for _, c := range match.Contributors {
			if string(c) == scanID {
				continue
			}
			contributors = append(contributors, string(c))
		}
		out.Matches = append(out.Matches, crossRequestMatch{PatternName: match.PatternName, Contributors: contributors})
	}
	return out
}

// runCrossRequest is the entry point scan.go's kind handlers call after their
// own single-request scan is clean. It resolves this Handler's live fragment
// buffer from cfg and is a no-op (empty outcome, no state written) when
// cross-request detection is disabled or the request carried no
// context.session_id — the caller's signal that today's stateless behavior
// applies unchanged.
func (h *Handler) runCrossRequest(ctx context.Context, cfg *config.Config, sc *scanner.Scanner, req *Request, payload []byte, scanID string) crossRequestOutcome {
	if cfg == nil {
		return crossRequestOutcome{}
	}
	// Resolve the buffer before the session check so a reload is observed,
	// and stale state dropped, by the next request of any kind rather than
	// only the next session-bearing one.
	buffer := h.crossRequest.currentFor(cfg, h.currentConfig)
	if buffer == nil || req.Context == nil || req.Context.SessionID == "" || len(payload) == 0 {
		return crossRequestOutcome{}
	}
	callerKey := callerKeyForToken(req.callerToken)
	return checkCrossRequestFragment(ctx, buffer, sc, h.metrics, cfg.CrossRequestDetection, callerKey, req.Context.SessionID, scanID, payload)
}

// applyCrossRequestOutcome folds a crossRequestOutcome into an in-progress
// Response. scannerName labels the finding ("dlp" or "tool_call") so it
// matches the vocabulary the sibling per-request findings already use.
// A blocked outcome always escalates to deny, regardless of the configured
// cross_request_detection.action: an uninspectable request is never reported
// as allow or warn (see crossRequestOutcome.Blocked doc comment). A matched
// outcome escalates to deny only when the configured action is block; in
// warn mode it escalates a clean result to warn (matching the tool_call
// policy-warn precedent already in this package: decide.go / scanToolCall's
// "a decision only escalates" rule) without overriding an existing deny.
func applyCrossRequestOutcome(resp *Response, outcome crossRequestOutcome, scannerName string) {
	switch {
	case outcome.Blocked:
		resp.Decision = DecisionDeny
		resp.Findings = append(resp.Findings, Finding{
			Scanner:  scannerName,
			RuleID:   outcome.BlockRuleID,
			Severity: "critical",
			Message:  outcome.BlockReason,
		})
	case outcome.Matched:
		for _, m := range outcome.Matches {
			finding := Finding{
				Scanner:      "cross_request_fragment",
				RuleID:       "CEE-fragment-" + m.PatternName,
				Severity:     "critical",
				Message:      "Cross-request fragment DLP match: secret reassembled across multiple requests in this session (" + m.PatternName + ")",
				Contributors: m.Contributors,
			}
			if outcome.Action == config.ActionWarn {
				finding.Severity = "medium"
			}
			resp.Findings = append(resp.Findings, finding)
		}
		if outcome.Action == config.ActionWarn {
			if resp.Decision == "" || resp.Decision == DecisionAllow {
				resp.Decision = DecisionWarn
			}
			return
		}
		resp.Decision = DecisionDeny
	}
}
