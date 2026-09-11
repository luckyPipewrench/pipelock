// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
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
	"github.com/luckyPipewrench/pipelock/internal/contententropy"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ErrA2AStreamFinding is returned by ScanA2AStream when a scanning finding
// (injection, DLP) is detected in an SSE event. Callers can distinguish this
// from internal/IO errors via errors.Is to decide whether warn mode should
// allow the stream to continue.
var ErrA2AStreamFinding = errors.New("a2a stream finding")

// ErrCardBaselineCapacity reports that a card baseline cannot accept a new
// card without losing another trusted baseline.
var ErrCardBaselineCapacity = errors.New("agent card baseline capacity exhausted")

// A2AScanResult describes the outcome of scanning A2A protocol traffic.
type A2AScanResult struct {
	Clean          bool
	Action         string
	Reason         string
	ScanError      string
	URLFindings    []scanner.Result        // SSRF/URL scanner findings
	DLPFindings    []scanner.TextDLPMatch  // DLP pattern matches
	InjectFindings []scanner.ResponseMatch // injection pattern matches
	EntropyFinding *contententropy.Finding // opaque high-entropy string leaf
	BudgetExceeded bool                    // true if walker hit node budget
}

// A2AContentEntropyOptions carries the request-body entropy policy into A2A
// scans when the caller has a concrete upstream destination host.
type A2AContentEntropyOptions = contententropy.Options

// rollingTailSize is the number of bytes kept across SSE events for
// cross-event scanning. A2A and generic SSE use it for response injection and
// DLP detection.
const rollingTailSize = 4096

// ScanA2ARequestBody runs field-aware scanning on an A2A request body.
// Classifies JSON leaves by field name, routes URLs through SSRF scanner,
// text/opaque through injection + DLP. Falls back to raw DLP for split-secret
// detection when the walker completes within budget.
func ScanA2ARequestBody(ctx context.Context, body []byte, sc *scanner.Scanner, cfg *config.A2AScanning, entropyOpts ...A2AContentEntropyOptions) A2AScanResult {
	if cfg == nil || !cfg.Enabled {
		return A2AScanResult{Clean: true}
	}
	return scanA2ABody(ctx, body, sc, cfg, firstA2AContentEntropyOptions(entropyOpts))
}

// ScanA2AResponseBody runs field-aware scanning on an A2A response body.
func ScanA2AResponseBody(ctx context.Context, body []byte, sc *scanner.Scanner, cfg *config.A2AScanning) A2AScanResult {
	if cfg == nil || !cfg.Enabled {
		return A2AScanResult{Clean: true}
	}
	return scanA2ABody(ctx, body, sc, cfg, nil)
}

// scanA2ABody is the shared implementation for request and response scanning.
func scanA2ABody(ctx context.Context, body []byte, sc *scanner.Scanner, cfg *config.A2AScanning, entropyOpts *A2AContentEntropyOptions) A2AScanResult {
	if err := ctx.Err(); err != nil {
		return A2AScanResult{Action: config.ActionBlock, ScanError: err.Error(), Reason: "a2a: response scan incomplete: " + err.Error()}
	}
	result := A2AScanResult{Clean: true}
	budgetExceeded := false
	var entropyTexts []string
	var entropyKeys []string
	action := ""
	defaultFindingAction := a2aDefaultAction(cfg)

	// Reject unparseable JSON and duplicate JSON object keys before WalkA2AJSON
	// decodes the body into a map[string]interface{}, which silently keeps only
	// the last value for a repeated key. A malicious peer can hide an injection,
	// secret, or exfil URL in the first occurrence - which a first-wins consumer
	// acts on - behind a benign duplicate, evading every walker pass (Pass 2 is
	// DLP-only). Parser-integrity failures hard-block, matching the MCP response
	// scan guard in ScanResponseOpts and the existing inspect-depth hard block.
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return A2AScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: "a2a: invalid JSON: empty body",
		}
	}
	if err := redact.NoDuplicateJSONKeys(trimmed); err != nil {
		reason := fmt.Sprintf("a2a: invalid JSON: %v", err)
		if redact.IsDuplicateKeyBlock(err) {
			reason = fmt.Sprintf("a2a: duplicate JSON object key: %v", err)
		}
		return A2AScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: reason,
		}
	}

	// Pass 1: field-aware walker - classifies and routes each leaf.
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
			result.Clean = false
			result.ScanError = ctx.Err().Error()
			return
		default:
		}

		switch class {
		case FieldURL:
			urlResult := sc.Scan(ctx, value)
			if !urlResult.Allowed {
				result.Clean = false
				result.URLFindings = append(result.URLFindings, urlResult)
				if a2aURLResultForcesBlock(urlResult) {
					action = config.StrongestAction(action, config.ActionBlock)
				} else {
					action = config.StrongestAction(action, defaultFindingAction)
				}
			}

		case FieldText, FieldOpaque:
			if entropyOpts != nil {
				entropyTexts = append(entropyTexts, value)
			}
			// Injection scanning
			injectResult := sc.ScanResponse(ctx, value)
			if injectResult.Failed() {
				result.Clean = false
				result.ScanError = injectResult.ScanError
				return
			}
			if !injectResult.Clean {
				result.Clean = false
				result.InjectFindings = append(result.InjectFindings, injectResult.Matches...)
				action = config.StrongestAction(action, defaultFindingAction)
			}
			// DLP scanning
			dlpResult := sc.ScanTextForDLP(ctx, value)
			if !dlpResult.Clean {
				result.Clean = false
				result.DLPFindings = append(result.DLPFindings, dlpResult.Matches...)
				if a2aDLPForcesBlock(dlpResult.Matches) {
					action = config.StrongestAction(action, config.ActionBlock)
				} else {
					action = config.StrongestAction(action, defaultFindingAction)
				}
			}

		case FieldSecret:
			if entropyOpts != nil {
				entropyTexts = append(entropyTexts, value)
			}
			dlpResult := sc.ScanTextForDLP(ctx, value)
			if !dlpResult.Clean {
				result.Clean = false
				result.DLPFindings = append(result.DLPFindings, dlpResult.Matches...)
				if a2aDLPForcesBlock(dlpResult.Matches) {
					action = config.StrongestAction(action, config.ActionBlock)
				} else {
					action = config.StrongestAction(action, defaultFindingAction)
				}
			}

		case FieldKeyEntropy:
			if entropyOpts != nil {
				entropyKeys = append(entropyKeys, value)
			}
		}
	})

	if entropyOpts != nil {
		if finding := contententropy.ScanTexts(entropyTexts, *entropyOpts); finding != nil && result.EntropyFinding == nil {
			result.Clean = false
			result.EntropyFinding = finding
			action = config.StrongestAction(action, entropyOpts.Action)
		}
		if !budgetExceeded {
			if finding := contententropy.ScanTexts(entropyKeys, *entropyOpts); finding != nil && result.EntropyFinding == nil {
				result.Clean = false
				result.EntropyFinding = finding
				action = config.StrongestAction(action, entropyOpts.Action)
			}
		}
	}

	// Budget exceeded participates in the same strongest-action resolution as
	// scanner findings, then skips raw fallback because the payload is too wide
	// for another complete pass.
	if budgetExceeded {
		result.Clean = false
		result.BudgetExceeded = true
		action = config.StrongestAction(action, defaultFindingAction)
	}

	// Pass 2: raw DLP fallback for split-secret detection. It runs whenever the
	// walker completed within budget, even when an earlier leaf already produced
	// a finding: a core credential split across JSON values must still reach the
	// immutable floor, and a prior non-core warn finding must not shadow it.
	// When the result was already dirty, fold in every new match and deduplicate
	// it against the per-leaf findings. Raw-pass evidence must not disappear just
	// because an earlier leaf was already dirty.
	if !budgetExceeded {
		extracted := extract.AllStringsFromJSONResult(json.RawMessage(body))
		if extracted.Truncated {
			return A2AScanResult{
				Clean:  false,
				Action: config.ActionBlock,
				Reason: "a2a: input exceeds maximum inspectable nesting depth",
			}
		}
		texts := extracted.Strings
		if len(texts) > 0 {
			joined := strings.Join(texts, "\n")
			dlpResult := sc.ScanTextForDLP(ctx, joined)
			if !dlpResult.Clean {
				result.Clean = false
				result.DLPFindings = appendUniqueA2ADLPFindings(result.DLPFindings, dlpResult.Matches)
				if a2aDLPForcesBlock(dlpResult.Matches) {
					action = config.StrongestAction(action, config.ActionBlock)
				} else {
					action = config.StrongestAction(action, defaultFindingAction)
				}
			}
		}
	}

	if err := ctx.Err(); err != nil {
		result.Clean = false
		result.ScanError = err.Error()
	}
	if !result.Clean {
		if result.ScanError != "" {
			result.Action = config.ActionBlock
			result.Reason = "a2a: response scan incomplete: " + result.ScanError
		} else {
			result.Action = action
			if result.Action == "" {
				result.Action = defaultFindingAction
			}
			result.Reason = buildA2AReason(result)
		}
	}

	return result
}

func firstA2AContentEntropyOptions(opts []A2AContentEntropyOptions) *A2AContentEntropyOptions {
	if len(opts) == 0 {
		return nil
	}
	return &opts[0]
}

// a2aDLPForcesBlock reports whether a set of DLP matches must hard-block the
// A2A body regardless of the configured a2a_scanning.action. It elevates both
// structural hostname-exfil matches and the immutable core credential floor,
// so a core credential in an A2A body blocks even when body scanning is
// disabled and the A2A branch alone carries the floor. Fail direction: a match
// the core predicate cannot classify falls through to the configured action;
// a positive core match only ever raises the action to block.
func a2aDLPForcesBlock(matches []scanner.TextDLPMatch) bool {
	return scanner.ContainsHostnameExfilMatch(matches) || scanner.ContainsCoreCriticalMatch(matches)
}

// appendUniqueA2ADLPFindings mirrors the scanner's match identity at the A2A
// cross-pass boundary. The scanner deduplicates within one scan; A2A also has
// to deduplicate across its per-leaf and joined-raw scans.
func appendUniqueA2ADLPFindings(existing, incoming []scanner.TextDLPMatch) []scanner.TextDLPMatch {
	type matchKey struct {
		name    string
		encoded string
	}

	seen := make(map[matchKey]struct{}, len(existing)+len(incoming))
	result := make([]scanner.TextDLPMatch, 0, len(existing)+len(incoming))
	for _, match := range append(existing, incoming...) {
		key := matchKey{name: match.PatternName, encoded: match.Encoded}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, match)
	}
	return result
}

// a2aURLResultForcesBlock reports whether a blocked URL-leaf scan result must
// hard-block the A2A body or header regardless of the configured
// a2a_scanning.action. It is the URL analog of a2aDLPForcesBlock: a structural
// hostname-exfil URL and the immutable core credential floor both elevate to
// block, so a core credential carried inside a URL field (query, path) blocks
// even under warn, matching the text-DLP leaves. Fail direction: a blocked URL
// the predicate cannot classify as core or hostname-exfil keeps following the
// configured action; a positive match only ever raises the action to block.
func a2aURLResultForcesBlock(r scanner.Result) bool {
	return scanner.IsHostnameExfilResult(r) || scanner.IsCoreCriticalResult(r)
}

func a2aDefaultAction(cfg *config.A2AScanning) string {
	if cfg == nil || cfg.Action == "" {
		return config.ActionWarn
	}
	return cfg.Action
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
	forceBlock := false
	for _, uri := range strings.Split(ext, ",") {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		urlResult := sc.Scan(ctx, uri)
		if !urlResult.Allowed {
			result.Clean = false
			result.URLFindings = append(result.URLFindings, urlResult)
			// Immutable floor: a core credential or structural hostname-exfil
			// carried in a header URI must hard-block regardless of the
			// configured a2a_scanning.action, matching the body URL leaves.
			if a2aURLResultForcesBlock(urlResult) {
				forceBlock = true
			}
		}
	}

	if !result.Clean {
		result.Action = cfg.Action
		if forceBlock {
			result.Action = config.ActionBlock
		}
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

// cardEntry stores a single Agent Card baseline as two views: the
// endpoint/structural digest (any change blocks) and the descriptive free text
// (a change is adopted when it introduces no cue class). Splitting the record is
// what lets a benign description edit update the baseline while an endpoint or
// auth change still fails closed.
type cardEntry struct {
	// descriptiveDigest is the EQUALITY identity (framed, unambiguous);
	// descriptive is the flattened text cue detection diffs against. They are
	// separate because a delimiter-joined string cannot serve as an identity.
	descriptiveDigest string
	structuralDigest  string
	descriptive       string
	skillNames        []string
}

// cardDriftOutcome reports how a card compares to its baseline. changed drives
// observability (DriftDetected); block is the enforcement decision. When block
// is set, exactly one of structuralChange or introducedCues explains it; when
// adopted is set, a benign descriptive change updated the baseline in place.
type cardDriftOutcome struct {
	firstSeen        bool
	capacityExceeded bool
	changed          bool
	block            bool
	adopted          bool
	structuralChange bool
	introducedCues   []string
}

// CardBaseline tracks Agent Card hashes by origin, for drift detection.
// Thread-safe. A trusted baseline is a security ledger, not a disposable
// cache: capacity preserves existing entries and refuses a new one.
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

// Check compares a card's structural digest and descriptive text against the
// baseline for the given key. First-seen cards are accepted only when the
// baseline has room to preserve them (TOFU).
//
// Enforcement, in fail-closed order:
//   - a changed structural/endpoint digest ALWAYS blocks and never auto-promotes
//     (url, auth, capabilities, skill ids/schemas, modes moved);
//   - with the structure unchanged, a descriptive change that introduces a cue
//     class (tool-poison, egress, directive, concealment, cross-tool) blocks and
//     never auto-promotes;
//   - a descriptive change that introduces no cue class is adopted as the new
//     baseline in place and does not block, which is the false-positive the whole
//     mechanism exists to remove.
//
// A blocked change preserves the existing baseline so repeated fetches keep
// blocking until an operator ResetBaseline accepts it. Auto-promotion is scoped
// strictly to the benign descriptive case; every other change holds the ledger.
// The descriptive digest is a PARAMETER rather than something this function
// derives, and that is deliberate. An earlier version hashed the flattened text
// here while ScanAgentCard hashed the card's fields, so the two produced
// different values for the same card: a baseline seeded or reset through this
// API then reported the unchanged card as drifted and adopted it again. There
// is exactly one canonical derivation, cardDescriptiveDigest, and every writer
// of a cardEntry must pass the value it produced.
func (cb *CardBaseline) Check(key cardCacheKey, structuralDigest, descriptiveDigest, descriptive string, skillNames []string) cardDriftOutcome {
	outcome := cb.Evaluate(key, structuralDigest, descriptiveDigest, descriptive, skillNames)
	if outcome.firstSeen || outcome.adopted {
		// If the baseline moved in between, the decision is stale. Re-evaluate
		// rather than reporting an adoption that did not happen.
		if !cb.Commit(key, structuralDigest, descriptiveDigest, descriptive, skillNames) {
			return cb.Evaluate(key, structuralDigest, descriptiveDigest, descriptive, skillNames)
		}
	}
	return outcome
}

// Evaluate decides what a card's digests mean against the baseline WITHOUT
// changing it. Trusting a card is a decision the drift check alone cannot make:
// the same scan also runs field scanning and signature verification, and a card
// those reject must not leave its text behind as the trusted baseline. So the
// mutation is split out into Commit, which the caller runs only once the whole
// verdict is clean. Splitting it this way is what stops a rejected card - an
// unsigned one under require_signed_agent_cards, one with an invalid signature,
// or one carrying a scanner finding - from replacing the baseline that every
// later comparison is measured against.
//
// The LRU position IS updated here, on purpose and for every card including a
// blocked one: a card under repeated attack must stay resident so it keeps
// blocking instead of aging out and being re-accepted as first-seen.
func (cb *CardBaseline) Evaluate(key cardCacheKey, structuralDigest, descriptiveDigest, descriptive string, skillNames []string) cardDriftOutcome {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	existing, ok := cb.entries[key]
	if !ok {
		if len(cb.entries) >= cb.maxSize {
			return cardDriftOutcome{capacityExceeded: true}
		}
		return cardDriftOutcome{firstSeen: true}
	}

	cb.touchLocked(key)

	if existing.structuralDigest != structuralDigest {
		// Endpoint/structural change: fail closed, preserve baseline.
		return cardDriftOutcome{changed: true, block: true, structuralChange: true}
	}
	// Compare the framed digest, not the flattened text: the text is ambiguous
	// across field boundaries and would report "unchanged" for a changed card.
	if existing.descriptiveDigest == descriptiveDigest {
		return cardDriftOutcome{}
	}

	// Structure unchanged, descriptive text changed: block only if the change
	// introduced a cue class; otherwise the caller may adopt the new text.
	introduced := tools.IntroducedDescriptionCues(existing.descriptive, descriptive)
	if len(introduced) > 0 {
		return cardDriftOutcome{changed: true, block: true, introducedCues: introduced}
	}
	return cardDriftOutcome{changed: true, adopted: true}
}

// Commit writes the baseline change a preceding Evaluate found acceptable, and
// is called only after the card's full verdict came back clean. It re-derives
// the decision under the lock rather than trusting the caller's outcome, so a
// concurrent fetch that moved the entry in between cannot be overwritten on the
// strength of a stale read: a first-seen insert happens only while the key is
// still absent and there is still room, and a descriptive adoption happens only
// while the structure still matches and the change still introduces no cue.
func (cb *CardBaseline) Commit(key cardCacheKey, structuralDigest, descriptiveDigest, descriptive string, skillNames []string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	existing, ok := cb.entries[key]
	if !ok {
		if len(cb.entries) >= cb.maxSize {
			return false
		}
		cb.entries[key] = &cardEntry{
			structuralDigest:  structuralDigest,
			descriptiveDigest: descriptiveDigest,
			descriptive:       descriptive,
			skillNames:        skillNames,
		}
		cb.touchLocked(key)
		return true
	}
	if existing.structuralDigest != structuralDigest || existing.descriptiveDigest == descriptiveDigest {
		return false
	}
	if len(tools.IntroducedDescriptionCues(existing.descriptive, descriptive)) > 0 {
		return false
	}
	existing.descriptiveDigest = descriptiveDigest
	existing.descriptive = descriptive
	existing.skillNames = skillNames
	cb.touchLocked(key)
	return true
}

// ResetBaseline explicitly updates the stored baseline for a key.
// Use after reviewing and accepting a drifted Agent Card. This is the operator
// path that promotes a change Check refused (a structural/endpoint change or a
// cue-introducing descriptive change). Resetting a missing entry at capacity is
// refused so an operator action cannot discard a different trusted baseline.
// The caller supplies the canonical descriptive digest for the same reason Check
// does: a reviewed baseline stored under a differently-derived digest reports
// drift on the very card the operator just accepted.
func (cb *CardBaseline) ResetBaseline(key cardCacheKey, structuralDigest, descriptiveDigest, descriptive string, skillNames []string) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	existing, ok := cb.entries[key]
	if ok {
		existing.structuralDigest = structuralDigest
		existing.descriptiveDigest = descriptiveDigest
		existing.descriptive = descriptive
		existing.skillNames = skillNames
		cb.touchLocked(key)
		return nil
	}

	if len(cb.entries) >= cb.maxSize {
		return ErrCardBaselineCapacity
	}
	// Key not present: insert as a reviewed baseline.
	cb.entries[key] = &cardEntry{
		structuralDigest:  structuralDigest,
		descriptiveDigest: descriptiveDigest,
		descriptive:       descriptive,
		skillNames:        skillNames,
	}
	cb.touchLocked(key)
	return nil
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

// AgentCardScanResult describes the outcome of scanning an Agent Card.
type AgentCardScanResult struct {
	Clean         bool
	Action        string
	Reason        string
	DriftDetected bool
	// DriftAdopted is true when a benign descriptive change was adopted as the
	// new baseline without blocking. DriftDetected is still set (the card
	// changed, which observability records), but the change did not enforce.
	// Distinguishes an adopted change from a blocked one for downstream audit.
	DriftAdopted bool
	FirstSeen    bool
	// BaselineCapacityExceeded reports that this card could not be safely
	// verified without replacing a different trusted baseline.
	BaselineCapacityExceeded bool
	Findings                 A2AScanResult // field-level scan findings

	// SignatureVerified is true when the card carried a signature that verified
	// against a trusted key scoped to the card's origin. SignatureKeyID is the
	// verifying key_id, for the positive attestation receipt. A signature that
	// failed to verify is reported via Clean=false + Reason, not these fields.
	SignatureVerified bool
	SignatureKeyID    string
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
		findings := scanA2ABody(ctx, body, sc, cfg, nil)
		unparseable := AgentCardScanResult{
			Clean:    findings.Clean,
			Action:   findings.Action,
			Reason:   "a2a: unparseable Agent Card",
			Findings: findings,
		}
		// Still enforce signature policy: an unparseable body is not a validly
		// signed card, so require_signed_agent_cards (and any claimed-but-
		// invalid signature) must fail closed here too, not be skipped by the
		// early return.
		applyCardSignatureVerification(&unparseable, body, key, cfg)
		return unparseable
	}

	result := AgentCardScanResult{Clean: true}

	// driftCommit writes the baseline change the drift evaluation found
	// acceptable. It runs only after the FULL verdict is known, so a card the
	// scanner or the signature check rejects leaves the trusted baseline alone.
	driftCommit := func(bool) {}
	var driftOutcome cardDriftOutcome

	// Card content scanning via field walker.
	if cfg.ScanAgentCards {
		result.Findings = scanA2ABody(ctx, body, sc, cfg, nil)
		if !result.Findings.Clean {
			result.Clean = false
			result.Action = result.Findings.Action
			result.Reason = result.Findings.Reason
		}
	}

	// Drift detection. A change to an endpoint/structural field always blocks;
	// a descriptive change blocks only when it introduces a cue class, and is
	// otherwise adopted as the new baseline (the false positive this removes).
	if cfg.DetectCardDrift && baseline != nil {
		var skillNames []string
		for _, s := range card.Skills {
			skillNames = append(skillNames, s.Name)
		}
		structural := cardStructuralDigest(card)
		descriptive := cardDescriptiveText(card)
		descriptiveDigest := cardDescriptiveDigest(card)
		// Evaluate now, commit at the end: the baseline must not learn a card
		// that field scanning or signature verification is about to reject.
		outcome := baseline.Evaluate(key, structural, descriptiveDigest, descriptive, skillNames)
		driftCommit = func(accepted bool) {
			if !accepted {
				return
			}
			// Commit reports whether it applied. It declines when the baseline
			// moved between Evaluate and Commit, which makes the decision this
			// scan is carrying stale. Re-evaluate against the CURRENT baseline
			// and correct the result rather than reporting an adoption or a
			// first-seen that never happened; if the fresh evaluation now
			// blocks, the response must say so.
			if baseline.Commit(key, structural, descriptiveDigest, descriptive, skillNames) {
				return
			}
			fresh := baseline.Evaluate(key, structural, descriptiveDigest, descriptive, skillNames)
			result.DriftDetected = fresh.changed
			result.DriftAdopted = fresh.adopted
			result.FirstSeen = fresh.firstSeen
			result.BaselineCapacityExceeded = fresh.capacityExceeded
			if fresh.block || fresh.capacityExceeded {
				result.Clean = false
				if result.Action == "" {
					result.Action = cfg.Action
				}
				if fresh.capacityExceeded {
					result.Reason = "a2a: Agent Card baseline capacity exhausted; card cannot be safely verified"
				} else if fresh.structuralChange {
					result.Reason = "a2a: Agent Card drift introduced: endpoint or structural change"
				} else {
					result.Reason = "a2a: Agent Card drift introduced: " + strings.Join(fresh.introducedCues, ", ")
				}
			}
		}
		driftOutcome = outcome
		result.DriftDetected = outcome.changed
		result.DriftAdopted = outcome.adopted
		result.FirstSeen = outcome.firstSeen
		result.BaselineCapacityExceeded = outcome.capacityExceeded
		if outcome.capacityExceeded {
			result.Clean = false
			result.Action = config.ActionBlock
			result.Reason = "a2a: Agent Card baseline capacity exhausted; card cannot be safely verified"
		}
		if outcome.block {
			result.Clean = false
			if result.Action == "" {
				result.Action = cfg.Action
			}
			if outcome.structuralChange {
				// Name the axis (endpoint/structural), not the specific field, so
				// the reason does not map the card's configuration surface.
				result.Reason = "a2a: Agent Card drift introduced: endpoint or structural change"
			} else {
				result.Reason = "a2a: Agent Card drift introduced: " + strings.Join(outcome.introducedCues, ", ")
			}
		}
	}

	// Independent attestation: cryptographically verify the card's signature
	// against the operator's trusted, origin-scoped keys. This runs in addition
	// to (not instead of) content scanning and drift detection.
	applyCardSignatureVerification(&result, body, key, cfg)

	// The verdict is final here. Learn the card only if nothing rejected it;
	// otherwise the baseline keeps what it already trusted, and the result must
	// not claim an adoption that never happened (the audit event and the
	// OnCardDriftAdopted callback both read DriftAdopted).
	if result.Clean {
		driftCommit(true)
	} else if driftOutcome.adopted || driftOutcome.firstSeen {
		result.DriftAdopted = false
		result.FirstSeen = false
	}

	return result
}

// applyCardSignatureVerification verifies the card's signature (when verification
// is active) and updates result in place. It is fail-closed: a claimed-but-
// invalid signature blocks; an unsigned card blocks only when
// require_signed_agent_cards is set; a verified signature records the attesting
// key_id. Called from both the normal and unparseable-card paths so the
// require-signed invariant cannot be skipped by an early return.
func applyCardSignatureVerification(result *AgentCardScanResult, body []byte, key cardCacheKey, cfg *config.A2AScanning) {
	if !CardSignatureVerificationActive(cfg) {
		return
	}
	switch sig := VerifyAgentCardSignatures(body, CardOriginFromURL(key.cardURL), cfg); sig.Outcome {
	case SigOutcomeVerified:
		result.SignatureVerified = true
		result.SignatureKeyID = sig.KeyID
	case SigOutcomeFailed:
		result.Clean = false
		if result.Action == "" {
			result.Action = cfg.Action
		}
		if result.Reason == "" {
			result.Reason = sig.Reason
		}
	case SigOutcomeUnsigned:
		if cfg.RequireSignedAgentCards {
			result.Clean = false
			if result.Action == "" {
				result.Action = cfg.Action
			}
			if result.Reason == "" {
				result.Reason = "a2a: unsigned Agent Card rejected (require_signed_agent_cards)"
			}
		}
	}
}

// --- Context Tracking (Session Smuggling Detection) ---

// ContextTracker maintains A2A context sessions for smuggling detection.
// Thread-safe.
type ContextTracker struct {
	mu       sync.Mutex
	contexts map[string]*contextSession
	taskMap  map[string]string // taskID → contextID
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
	if taskID != "" {
		if _, known := ct.taskMap[taskID]; !known && len(ct.taskMap) >= ct.maxContextsLocked() {
			ct.mu.Unlock()
			return true, "a2a: task alias capacity exceeded"
		}
	}
	sess, admitted := ct.getOrCreateLocked(canonicalID)
	if !admitted {
		ct.mu.Unlock()
		return true, "a2a: context capacity exceeded"
	}

	// Track task → context mapping.
	if taskID != "" {
		ct.taskMap[taskID] = canonicalID
	}

	// Add texts to session.
	sess.texts = append(sess.texts, texts...)

	// Check message cap - taint on overflow.
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

	// Scan individual texts first - if any single message has injection,
	// that's not smuggling, it's direct injection (handled by per-message scanning).
	// Smuggling = injection visible ONLY in concatenation.
	joined := strings.Join(accumulated, " ")
	concatResult := sc.ScanResponse(ctx, joined)
	if !concatResult.Clean {
		if concatResult.Failed() {
			return true, "a2a: response scan incomplete: " + concatResult.ScanError
		}
		// Check if any individual text also triggers.
		individualHit := false
		for _, t := range texts {
			r := sc.ScanResponse(ctx, t)
			if r.Failed() {
				return true, "a2a: response scan incomplete: " + r.ScanError
			}
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
func (ct *ContextTracker) getOrCreateLocked(id string) (*contextSession, bool) {
	sess, ok := ct.contexts[id]
	if ok {
		return sess, true
	}

	// Existing context state is security evidence. Admission pressure must not
	// discard it and let an old identifier re-enter as a fresh session.
	if len(ct.contexts) >= ct.maxContextsLocked() {
		return nil, false
	}

	sess = &contextSession{}
	ct.contexts[id] = sess
	return sess, true
}

func (ct *ContextTracker) maxContextsLocked() int {
	if ct.cfg.MaxContexts > 0 {
		return ct.cfg.MaxContexts
	}
	return 1000
}

// --- SSE Stream Scanning ---

// ScanA2AStream handles SSE streaming responses with per-event field-aware
// scanning and rolling tails for cross-event injection and DLP detection.
//
// Contract:
// - Caller copies response headers to w BEFORE calling this function.
// - Clean events are flushed immediately via flusher.
// - On detection: returns error (caller should close the connection).
// - Compressed responses must be rejected BEFORE calling this function.
func ScanA2AStream(ctx context.Context, body io.Reader, w io.Writer, flusher http.Flusher, sc *scanner.Scanner, cfg *config.A2AScanning) error {
	if cfg == nil || !cfg.Enabled {
		// A2A scanning disabled: share the generic-SSE chunked
		// passthrough so per-read flushing preserves SSE TTFB. After the
		// SSE-streaming activation gate was decoupled from
		// response_scanning.enabled, this branch is now reachable for
		// disabled-A2A SSE responses; bare io.Copy would let the server's
		// bufio.Writer batch chunks and reintroduce the TTFB stall the
		// decoupling was meant to fix.
		return passthroughSSE(ctx, body, w, flusher)
	}

	reader := transport.NewSSEReader(body)
	var injectionTail string
	var dlpTail string

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
		eventResult := scanA2ABody(ctx, event, sc, cfg, nil)
		if !eventResult.Clean {
			if eventResult.ScanError != "" {
				return fmt.Errorf("%w: response scan incomplete: %s", ErrSSEStreamScanError, eventResult.ScanError)
			}
			return fmt.Errorf("%w: %s", ErrA2AStreamFinding, eventResult.Reason)
		}

		// Scan the canonical full-event text (event:/id:/retry: plus the
		// data: payload). scanA2ABody only inspects the JSON data payload,
		// so metadata-field injection (prompt-injection in id:, DLP in
		// event:) would otherwise slip through - same class of bypass as
		// external review finding #2 on the generic SSE path.
		canonical := canonicalSSEEventText(event, reader)
		if injResult := sc.ScanResponse(ctx, canonical); !injResult.Clean {
			if injResult.Failed() {
				return fmt.Errorf("%w: response scan incomplete: %s", ErrSSEStreamScanError, injResult.ScanError)
			}
			return fmt.Errorf("%w: injection in sse metadata: %s",
				ErrA2AStreamFinding, sseInjectionNames(injResult.Matches))
		}
		if dlpResult := sc.ScanTextForDLP(ctx, canonical); !dlpResult.Clean {
			return fmt.Errorf("%w: dlp in sse metadata: %s",
				ErrA2AStreamFinding, sseDLPMatchNames(dlpResult.Matches))
		}

		// Rolling tails: injection keeps word boundaries; DLP does not insert a
		// separator so a credential split exactly at an event boundary is visible
		// to the same detectors that caught per-event data.
		currentText, currentTruncated := extractTextFromEvent(event)
		if currentTruncated {
			return fmt.Errorf("%w: input exceeds maximum inspectable nesting depth", ErrA2AStreamFinding)
		}
		if injectionTail != "" && currentText != "" {
			combined := injectionTail + " " + currentText
			tailResult := sc.ScanResponse(ctx, combined)
			if !tailResult.Clean {
				if tailResult.Failed() {
					return fmt.Errorf("%w: response scan incomplete: %s", ErrSSEStreamScanError, tailResult.ScanError)
				}
				return fmt.Errorf("%w: cross-event injection detected", ErrA2AStreamFinding)
			}
		}
		if dlpTail != "" && currentText != "" {
			combined := dlpTail + currentText
			dlpResult := sc.ScanTextForDLP(ctx, combined)
			if !dlpResult.Clean {
				return fmt.Errorf("%w: cross-event dlp detected: %s",
					ErrA2AStreamFinding, sseDLPMatchNames(dlpResult.Matches))
			}
		}

		// Update rolling tails.
		if currentText != "" {
			current := []byte(currentText)
			injectionTail = advanceSSERollingTail(injectionTail, current, false, " ")
			dlpTail = advanceSSERollingTail(dlpTail, current, false, "")
		}

		// Forward clean event. Preserve id, event, and retry fields from the
		// SSE reader so downstream consumers can correlate events, handle
		// typed dispatching, and respect reconnection timing.
		if werr := writeSSEEvent(w, event, reader.LastEventID(), reader.LastEventType(), reader.LastRetry()); werr != nil {
			return fmt.Errorf("a2a stream write: %w", werr)
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// extractTextFromEvent extracts scannable text from an SSE event payload.
// The payload is JSON - extract all string values for the rolling tail.
func extractTextFromEvent(event []byte) (string, bool) {
	if len(event) == 0 {
		return "", false
	}
	extracted := extract.AllStringsFromJSONResult(json.RawMessage(event))
	texts := extracted.Strings
	if len(texts) == 0 {
		return "", extracted.Truncated
	}
	return strings.Join(texts, " "), extracted.Truncated
}

// writeSSEEvent writes a single SSE event to the writer, preserving the
// id, event type, and retry fields for downstream correlation, typed
// dispatching, and reconnection support. Returns the first write error
// so callers can break their event loops promptly when the downstream
// consumer goes away (e.g. an io.Pipe closed by the client).
func writeSSEEvent(w io.Writer, data []byte, eventID, eventType, retry string) error {
	if eventType != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", eventType); err != nil {
			return err
		}
	}
	if eventID != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", eventID); err != nil {
			return err
		}
	}
	if retry != "" {
		if _, err := fmt.Fprintf(w, "retry: %s\n", retry); err != nil {
			return err
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	return nil
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

// IsInfrastructureError reports whether every finding in this A2A scan result
// is an infrastructure error (e.g., DNS resolver timeout on an embedded URL).
// Returns false when clean, when non-URL findings exist, or when any URL
// finding is a real threat or config mismatch. When true, callers should treat
// the block as score-neutral for adaptive enforcement - resolver wobble from
// embedded URL fields is not evidence of agent misbehavior.
func (r A2AScanResult) IsInfrastructureError() bool {
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
		if !f.IsInfrastructureError() {
			return false
		}
	}
	return true
}

// IsAdaptiveNeutral reports whether this A2A result should be score-neutral
// for adaptive enforcement. Mirrors scanner.Result.IsAdaptiveNeutral(): covers
// protective enforcement plus infrastructure errors, but NOT config mismatch
// (which remains a bounded NearMiss signal).
func (r A2AScanResult) IsAdaptiveNeutral() bool {
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
		if !f.IsAdaptiveNeutral() {
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
	if result.EntropyFinding != nil {
		parts = append(parts, contententropy.Reason(result.EntropyFinding))
	}
	if result.BudgetExceeded {
		parts = append(parts, "payload exceeded node budget")
	}
	if len(parts) == 0 {
		return "a2a: finding detected"
	}
	return "a2a: " + strings.Join(parts, "; ")
}
