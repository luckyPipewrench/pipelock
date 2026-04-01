// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ErrA2AStreamFinding is returned by ScanA2AStream when a scanning finding
// (injection, DLP) is detected in an SSE event. Callers can distinguish this
// from internal/IO errors via errors.Is to decide whether warn mode should
// allow the stream to continue.
var ErrA2AStreamFinding = errors.New("a2a stream finding")

// A2AScanResult describes the outcome of scanning A2A protocol traffic.
type A2AScanResult struct {
	Clean          bool
	Action         string
	Reason         string
	URLFindings    []scanner.Result        // SSRF/URL scanner findings
	DLPFindings    []scanner.TextDLPMatch  // DLP pattern matches
	InjectFindings []scanner.ResponseMatch // injection pattern matches
	BudgetExceeded bool                    // true if walker hit node budget
}

// rollingTailSize is the number of bytes kept across SSE events for
// cross-event injection detection. 4KB covers realistic injection
// patterns (20-80 characters) with margin.
const rollingTailSize = 4096

// ScanA2ARequestBody runs field-aware scanning on an A2A request body.
// Classifies JSON leaves by field name, routes URLs through SSRF scanner,
// text/opaque through injection + DLP. Falls back to raw DLP for split-secret
// detection when the walker completes within budget.
func ScanA2ARequestBody(ctx context.Context, body []byte, sc *scanner.Scanner, cfg *config.A2AScanning) A2AScanResult {
	if cfg == nil || !cfg.Enabled || len(body) == 0 {
		return A2AScanResult{Clean: true}
	}
	return scanA2ABody(ctx, body, sc, cfg)
}

// ScanA2AResponseBody runs field-aware scanning on an A2A response body.
func ScanA2AResponseBody(ctx context.Context, body []byte, sc *scanner.Scanner, cfg *config.A2AScanning) A2AScanResult {
	if cfg == nil || !cfg.Enabled || len(body) == 0 {
		return A2AScanResult{Clean: true}
	}
	return scanA2ABody(ctx, body, sc, cfg)
}

// scanA2ABody is the shared implementation for request and response scanning.
func scanA2ABody(ctx context.Context, body []byte, sc *scanner.Scanner, cfg *config.A2AScanning) A2AScanResult {
	result := A2AScanResult{Clean: true}
	budgetExceeded := false

	// Pass 1: field-aware walker — classifies and routes each leaf.
	WalkA2AJSON(json.RawMessage(body), func(path, value string, class FieldClass) {
		if class == FieldBudgetExceeded {
			budgetExceeded = true
			return
		}
		if value == "" {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		switch class {
		case FieldURL:
			urlResult := sc.Scan(ctx, value)
			if !urlResult.Allowed {
				result.Clean = false
				result.URLFindings = append(result.URLFindings, urlResult)
			}

		case FieldText, FieldOpaque:
			// Injection scanning
			injectResult := sc.ScanResponse(ctx, value)
			if !injectResult.Clean {
				result.Clean = false
				result.InjectFindings = append(result.InjectFindings, injectResult.Matches...)
			}
			// DLP scanning
			dlpResult := sc.ScanTextForDLP(ctx, value)
			if !dlpResult.Clean {
				result.Clean = false
				result.DLPFindings = append(result.DLPFindings, dlpResult.Matches...)
			}

		case FieldSecret:
			dlpResult := sc.ScanTextForDLP(ctx, value)
			if !dlpResult.Clean {
				result.Clean = false
				result.DLPFindings = append(result.DLPFindings, dlpResult.Matches...)
			}
		}
	})

	// Budget exceeded: use configured action, skip raw fallback.
	// Operators who set action=warn get a warning, not a silent override to block.
	if budgetExceeded {
		action := cfg.Action
		if action == "" {
			action = config.ActionWarn
		}
		return A2AScanResult{
			Clean:          false,
			Action:         action,
			Reason:         "a2a: payload exceeded node budget",
			BudgetExceeded: true,
		}
	}

	// Pass 2: raw DLP fallback for split-secret detection.
	// Only runs when walker completed within budget.
	if result.Clean {
		texts := extract.AllStringsFromJSON(json.RawMessage(body))
		if len(texts) > 0 {
			joined := strings.Join(texts, "\n")
			dlpResult := sc.ScanTextForDLP(ctx, joined)
			if !dlpResult.Clean {
				result.Clean = false
				result.DLPFindings = append(result.DLPFindings, dlpResult.Matches...)
			}
		}
	}

	if !result.Clean && result.Action == "" {
		result.Action = cfg.Action
		result.Reason = buildA2AReason(result)
	}

	return result
}

// ScanA2AHeaders scans A2A service parameter headers.
// A2A-Extensions: comma-separated URIs → SSRF-scan each.
// A2A-Version: passed through without scanning.
func ScanA2AHeaders(ctx context.Context, headers http.Header, sc *scanner.Scanner, cfg *config.A2AScanning) A2AScanResult {
	if cfg == nil || !cfg.Enabled {
		return A2AScanResult{Clean: true}
	}

	ext := headers.Get("A2A-Extensions")
	if ext == "" {
		return A2AScanResult{Clean: true}
	}

	result := A2AScanResult{Clean: true}
	for _, uri := range strings.Split(ext, ",") {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		urlResult := sc.Scan(ctx, uri)
		if !urlResult.Allowed {
			result.Clean = false
			result.URLFindings = append(result.URLFindings, urlResult)
		}
	}

	if !result.Clean {
		result.Action = cfg.Action
		result.Reason = "a2a: A2A-Extensions header contains blocked URI"
	}

	return result
}

// --- Agent Card Scanning ---

// cardCacheKey identifies a unique Agent Card baseline.
type cardCacheKey struct {
	cardURL         string // full URL including tenant path
	authFingerprint string // SHA256(Authorization)[:16], "" for unauthenticated
}

// CardCacheKeyFromRequest builds a card cache key from the request URL and auth.
func CardCacheKeyFromRequest(cardURL string, authHeader string) cardCacheKey {
	fp := ""
	if authHeader != "" {
		h := sha256.Sum256([]byte(authHeader))
		fp = hex.EncodeToString(h[:8]) // 16 hex chars
	}
	return cardCacheKey{cardURL: cardURL, authFingerprint: fp}
}

// cardEntry stores a single Agent Card baseline.
type cardEntry struct {
	hash       string
	skillNames []string
}

// CardBaseline tracks Agent Card hashes by origin, for drift detection.
// Thread-safe, LRU eviction at maxSize.
type CardBaseline struct {
	mu      sync.Mutex
	entries map[cardCacheKey]*cardEntry
	order   []cardCacheKey // LRU order, most recent at end
	maxSize int
}

// NewCardBaseline creates a card baseline cache with the given capacity.
func NewCardBaseline(maxSize int) *CardBaseline {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &CardBaseline{
		entries: make(map[cardCacheKey]*cardEntry, maxSize),
		maxSize: maxSize,
	}
}

// Check compares a card hash against the baseline for the given key.
// Returns (driftDetected, isFirstSeen). First-seen cards are accepted (TOFU).
func (cb *CardBaseline) Check(key cardCacheKey, hash string, skillNames []string) (bool, bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	existing, ok := cb.entries[key]
	if !ok {
		// First-seen: store baseline (TOFU).
		cb.evictIfFull()
		cb.entries[key] = &cardEntry{hash: hash, skillNames: skillNames}
		cb.touchLocked(key)
		return false, true
	}

	// Update LRU position.
	cb.touchLocked(key)

	if existing.hash == hash {
		return false, false
	}

	// Drift detected — do NOT auto-promote the baseline. The existing
	// baseline is preserved so repeated fetches of a drifted card
	// continue to report drift until explicitly reset. Operators must
	// call ResetBaseline to accept the new card.
	return true, false
}

// ResetBaseline explicitly updates the stored baseline for a key.
// Use after reviewing and accepting a drifted Agent Card. This is the
// only path that promotes a new hash; Check never auto-promotes.
func (cb *CardBaseline) ResetBaseline(key cardCacheKey, hash string, skillNames []string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	existing, ok := cb.entries[key]
	if ok {
		existing.hash = hash
		existing.skillNames = skillNames
		cb.touchLocked(key)
		return
	}

	// Key not present (evicted or never seen): insert as new baseline.
	cb.evictIfFull()
	cb.entries[key] = &cardEntry{hash: hash, skillNames: skillNames}
	cb.touchLocked(key)
}

// touchLocked moves a key to the end of the LRU order. Must hold mu.
func (cb *CardBaseline) touchLocked(key cardCacheKey) {
	// Remove existing position.
	for i, k := range cb.order {
		if k == key {
			cb.order = append(cb.order[:i], cb.order[i+1:]...)
			break
		}
	}
	cb.order = append(cb.order, key)
}

// evictIfFull removes the least-recently-used entry if at capacity. Must hold mu.
func (cb *CardBaseline) evictIfFull() {
	if len(cb.entries) < cb.maxSize {
		return
	}
	if len(cb.order) > 0 {
		oldest := cb.order[0]
		cb.order = cb.order[1:]
		delete(cb.entries, oldest)
	}
}

// AgentCardScanResult describes the outcome of scanning an Agent Card.
type AgentCardScanResult struct {
	Clean         bool
	Action        string
	Reason        string
	DriftDetected bool
	FirstSeen     bool
	Findings      A2AScanResult // field-level scan findings
}

// ScanAgentCard parses and scans an Agent Card response for skill poisoning
// and drift detection. Reuses the field walker for URL and injection scanning.
func ScanAgentCard(ctx context.Context, body []byte, sc *scanner.Scanner, baseline *CardBaseline, key cardCacheKey, cfg *config.A2AScanning) AgentCardScanResult {
	if cfg == nil || !cfg.Enabled {
		return AgentCardScanResult{Clean: true}
	}

	var card A2AAgentCard
	if err := json.Unmarshal(body, &card); err != nil {
		// Unparseable card: fail closed for card-specific checks,
		// but still run generic field scanning.
		findings := scanA2ABody(ctx, body, sc, cfg)
		return AgentCardScanResult{
			Clean:    findings.Clean,
			Action:   findings.Action,
			Reason:   "a2a: unparseable Agent Card",
			Findings: findings,
		}
	}

	result := AgentCardScanResult{Clean: true}

	// Card content scanning via field walker.
	if cfg.ScanAgentCards {
		result.Findings = scanA2ABody(ctx, body, sc, cfg)
		if !result.Findings.Clean {
			result.Clean = false
			result.Action = result.Findings.Action
			result.Reason = result.Findings.Reason
		}
	}

	// Drift detection.
	if cfg.DetectCardDrift && baseline != nil {
		hash := HashAgentCard(card)
		var skillNames []string
		for _, s := range card.Skills {
			skillNames = append(skillNames, s.Name)
		}
		drift, firstSeen := baseline.Check(key, hash, skillNames)
		result.DriftDetected = drift
		result.FirstSeen = firstSeen
		if drift {
			result.Clean = false
			if result.Action == "" {
				result.Action = cfg.Action
			}
			result.Reason = "a2a: Agent Card drift detected"
		}
	}

	return result
}

// --- Context Tracking (Session Smuggling Detection) ---

// ContextTracker maintains A2A context sessions for smuggling detection.
// Thread-safe.
type ContextTracker struct {
	mu       sync.Mutex
	contexts map[string]*contextSession
	taskMap  map[string]string   // taskID → contextID
	evicted  map[string]struct{} // IDs that were evicted (taint on re-entry)
	order    []string            // LRU order of context IDs
	cfg      *config.A2AScanning
}

// contextSession tracks accumulated text within a single A2A context.
type contextSession struct {
	texts   []string
	tainted bool // true if message cap was hit
}

// NewContextTracker creates a context tracker with the given config.
func NewContextTracker(cfg *config.A2AScanning) *ContextTracker {
	return &ContextTracker{
		contexts: make(map[string]*contextSession),
		taskMap:  make(map[string]string),
		evicted:  make(map[string]struct{}),
		cfg:      cfg,
	}
}

// TrackAndScan adds message text to the context and runs accumulated
// injection scanning. Returns a non-empty reason if smuggling is detected.
func (ct *ContextTracker) TrackAndScan(ctx context.Context, contextID, taskID string, texts []string, sc *scanner.Scanner) (smuggling bool, reason string) {
	if ct.cfg == nil || !ct.cfg.SessionSmugglingDetection {
		return false, ""
	}

	ct.mu.Lock()
	canonicalID := ct.resolveContextLocked(contextID, taskID)
	sess := ct.getOrCreateLocked(canonicalID)

	// Track task → context mapping.
	if taskID != "" {
		ct.taskMap[taskID] = canonicalID
	}

	// Add texts to session.
	sess.texts = append(sess.texts, texts...)

	// Check message cap — taint on overflow.
	maxMsgs := ct.cfg.MaxContextMessages
	if maxMsgs <= 0 {
		maxMsgs = 100
	}
	if len(sess.texts) > maxMsgs {
		sess.texts = sess.texts[len(sess.texts)-maxMsgs:]
		sess.tainted = true
	}

	// Copy texts for scanning outside the lock.
	accumulated := make([]string, len(sess.texts))
	copy(accumulated, sess.texts)
	tainted := sess.tainted
	ct.mu.Unlock()

	// Scan individual texts first — if any single message has injection,
	// that's not smuggling, it's direct injection (handled by per-message scanning).
	// Smuggling = injection visible ONLY in concatenation.
	joined := strings.Join(accumulated, " ")
	concatResult := sc.ScanResponse(ctx, joined)
	if !concatResult.Clean {
		// Check if any individual text also triggers.
		individualHit := false
		for _, t := range texts {
			r := sc.ScanResponse(ctx, t)
			if !r.Clean {
				individualHit = true
				break
			}
		}
		if !individualHit {
			reason = "a2a: session smuggling detected — injection visible only in accumulated context"
			if tainted {
				reason += " (context tainted: message limit reached)"
			}
			return true, reason
		}
	}

	return false, ""
}

// resolveContextLocked resolves the canonical context ID.
// Must hold ct.mu.
func (ct *ContextTracker) resolveContextLocked(contextID, taskID string) string {
	if contextID != "" {
		return contextID
	}
	if taskID != "" {
		if cid, ok := ct.taskMap[taskID]; ok {
			return cid
		}
		return "task:" + taskID
	}
	return "anon:" + fmt.Sprintf("%d", len(ct.contexts))
}

// getOrCreateLocked gets or creates a context session. Must hold ct.mu.
func (ct *ContextTracker) getOrCreateLocked(id string) *contextSession {
	sess, ok := ct.contexts[id]
	if ok {
		ct.touchOrderLocked(id)
		return sess
	}

	// Evict if at capacity.
	maxCtx := ct.cfg.MaxContexts
	if maxCtx <= 0 {
		maxCtx = 1000
	}
	for len(ct.contexts) >= maxCtx && len(ct.order) > 0 {
		oldest := ct.order[0]
		ct.order = ct.order[1:]
		delete(ct.contexts, oldest)
		ct.evicted[oldest] = struct{}{} // track for re-entry tainting
	}

	sess = &contextSession{}
	// Taint only if this specific context was previously evicted.
	// First-seen contexts at capacity are NOT tainted.
	if _, wasEvicted := ct.evicted[id]; wasEvicted {
		sess.tainted = true
		delete(ct.evicted, id)
	}
	ct.contexts[id] = sess
	ct.order = append(ct.order, id)

	return sess
}

// touchOrderLocked moves a context to the end of the LRU order. Must hold ct.mu.
func (ct *ContextTracker) touchOrderLocked(id string) {
	for i, k := range ct.order {
		if k == id {
			ct.order = append(ct.order[:i], ct.order[i+1:]...)
			break
		}
	}
	ct.order = append(ct.order, id)
}

// --- SSE Stream Scanning ---

// ScanA2AStream handles SSE streaming responses with per-event field-aware
// scanning and a rolling tail for cross-event injection detection.
//
// Contract:
// - Caller copies response headers to w BEFORE calling this function.
// - Clean events are flushed immediately via flusher.
// - On detection: returns error (caller should close the connection).
// - Compressed responses must be rejected BEFORE calling this function.
func ScanA2AStream(ctx context.Context, body io.Reader, w io.Writer, flusher http.Flusher, sc *scanner.Scanner, cfg *config.A2AScanning) error {
	if cfg == nil || !cfg.Enabled {
		// A2A scanning disabled — pass through raw.
		_, err := io.Copy(w, body)
		return err
	}

	reader := transport.NewSSEReader(body)
	var tail string

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		event, err := reader.ReadMessage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("a2a stream read: %w", err)
		}

		// Field-walk the event data payload.
		eventResult := scanA2ABody(ctx, event, sc, cfg)
		if !eventResult.Clean {
			return fmt.Errorf("%w: %s", ErrA2AStreamFinding, eventResult.Reason)
		}

		// Rolling tail: concatenate tail + current text, scan for
		// cross-event injection.
		currentText := extractTextFromEvent(event)
		if tail != "" && currentText != "" {
			combined := tail + " " + currentText
			tailResult := sc.ScanResponse(ctx, combined)
			if !tailResult.Clean {
				return fmt.Errorf("%w: cross-event injection detected", ErrA2AStreamFinding)
			}
		}

		// Update rolling tail.
		if currentText != "" {
			if len(currentText) >= rollingTailSize {
				tail = currentText[len(currentText)-rollingTailSize:]
			} else if len(tail)+len(currentText) > rollingTailSize {
				combined := tail + currentText
				tail = combined[len(combined)-rollingTailSize:]
			} else {
				tail += currentText
			}
		}

		// Forward clean event. Preserve id, event, and retry fields from the
		// SSE reader so downstream consumers can correlate events, handle
		// typed dispatching, and respect reconnection timing.
		writeSSEEvent(w, event, reader.LastEventID(), reader.LastEventType(), reader.LastRetry())
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// extractTextFromEvent extracts scannable text from an SSE event payload.
// The payload is JSON — extract all string values for the rolling tail.
func extractTextFromEvent(event []byte) string {
	if len(event) == 0 {
		return ""
	}
	texts := extract.AllStringsFromJSON(json.RawMessage(event))
	if len(texts) == 0 {
		return ""
	}
	return strings.Join(texts, " ")
}

// writeSSEEvent writes a single SSE event to the writer, preserving the
// id, event type, and retry fields for downstream correlation, typed
// dispatching, and reconnection support.
func writeSSEEvent(w io.Writer, data []byte, eventID, eventType, retry string) {
	if eventType != "" {
		_, _ = fmt.Fprintf(w, "event: %s\n", eventType)
	}
	if eventID != "" {
		_, _ = fmt.Fprintf(w, "id: %s\n", eventID)
	}
	if retry != "" {
		_, _ = fmt.Fprintf(w, "retry: %s\n", retry)
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
}

// IsConfigMismatch reports whether every finding in this A2A scan result is a
// config-mismatch SSRF block (domain in api_allowlist but not trusted_domains).
// Returns false when clean, when non-URL findings exist, or when any URL
// finding is a real threat.
func (r A2AScanResult) IsConfigMismatch() bool {
	if r.Clean {
		return false
	}
	if len(r.DLPFindings) > 0 || len(r.InjectFindings) > 0 {
		return false
	}
	if len(r.URLFindings) == 0 {
		return false
	}
	for _, f := range r.URLFindings {
		if !f.IsConfigMismatch() {
			return false
		}
	}
	return true
}

// --- Helpers ---

// buildA2AReason constructs a human-readable reason string from scan findings.
func buildA2AReason(result A2AScanResult) string {
	var parts []string
	if len(result.URLFindings) > 0 {
		parts = append(parts, fmt.Sprintf("%d URL/SSRF finding(s)", len(result.URLFindings)))
	}
	if len(result.InjectFindings) > 0 {
		names := make([]string, 0, len(result.InjectFindings))
		for _, m := range result.InjectFindings {
			names = append(names, m.PatternName)
		}
		parts = append(parts, "injection: "+strings.Join(names, ", "))
	}
	if len(result.DLPFindings) > 0 {
		names := make([]string, 0, len(result.DLPFindings))
		for _, m := range result.DLPFindings {
			names = append(names, m.PatternName)
		}
		parts = append(parts, "DLP: "+strings.Join(names, ", "))
	}
	if len(parts) == 0 {
		return "a2a: finding detected"
	}
	return "a2a: " + strings.Join(parts, "; ")
}
