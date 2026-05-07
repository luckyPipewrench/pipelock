// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package runtime resolves active learn-and-lock contracts for live sessions
// and evaluates contract-aware decisions without coupling the proxy runtime to
// the contract store.
package runtime

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/normalize"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// Lifecycle constants alias the canonical schema-package values so the
// runtime and the contract validator share one source of truth. Adding
// a new lifecycle state must happen in the contract package.
const (
	LifecycleProposed    = contract.LifecycleProposed
	LifecycleCaptureOnly = contract.LifecycleCaptureOnly
	LifecycleEnforce     = contract.LifecycleEnforce
	LifecycleExpired     = contract.LifecycleExpired
	LifecycleDemoted     = contract.LifecycleDemoted
)

const (
	// PolicySourceScanner identifies the regular scanner/config path.
	PolicySourceScanner = "scanner"
	// PolicySourceBundle identifies bundled static policy.
	PolicySourceBundle = "bundle"
	// PolicySourceContract identifies an active learn-and-lock contract.
	PolicySourceContract = "contract"
	// PolicySourceKillSwitch identifies the global fail-closed kill switch.
	PolicySourceKillSwitch = "kill_switch"
)

const (
	// WinningSourceScanner means the scanner/config path decided the verdict.
	WinningSourceScanner = PolicySourceScanner
	// WinningSourceContract means the active contract decided the verdict.
	WinningSourceContract = PolicySourceContract
	// WinningSourceKillSwitch means the kill switch decided the verdict.
	WinningSourceKillSwitch = PolicySourceKillSwitch
)

// Rule-kind aliases keep the runtime in lock-step with the validator's
// EnforceableRuleKinds() registry. Adding a new kind requires updating
// both the contract package's enforceable list AND the runtime evaluator
// dispatch in the same change; otherwise validation rejects enforced
// rules of that kind.
const (
	ruleKindHTTPDestination = contract.RuleKindHTTPDestination
	ruleKindHTTPAction      = contract.RuleKindHTTPAction

	DriftKindPositive = "positive"
	DriftKindNegative = "negative"
)

var (
	// ErrNoResolvedContract is returned when a caller asks for evaluation
	// without an active contract pin.
	ErrNoResolvedContract = errors.New("contract runtime: no resolved contract")
	// ErrUnsupportedLifecycle aliases the contract package's lifecycle
	// error so a single sentinel works for validation-time and
	// evaluation-time rejection.
	ErrUnsupportedLifecycle = contract.ErrUnsupportedLifecycle
	// ErrInvalidDecisionInput is returned for malformed request/evaluation input.
	ErrInvalidDecisionInput = errors.New("contract runtime: invalid decision input")
	// ErrInvalidSelector is returned when an active-set selector cannot be used safely.
	ErrInvalidSelector = errors.New("contract runtime: invalid selector")
)

// ActiveSet is the immutable in-memory view derived from store.State.
type ActiveSet struct {
	manifestHash string
	generation   uint64
	selectors    []contract.ManifestSelector
	contracts    map[string]contract.ContractEnvelope
}

// NewActiveSet builds an immutable active set from a validated store state.
func NewActiveSet(state store.State) (*ActiveSet, error) {
	if state.ManifestHash == "" {
		return nil, fmt.Errorf("%w: manifest_hash", ErrInvalidDecisionInput)
	}
	if state.Envelope.Body.Generation == 0 {
		return nil, fmt.Errorf("%w: generation", ErrInvalidDecisionInput)
	}
	selectors := append([]contract.ManifestSelector(nil), state.Envelope.Body.Selectors...)
	contracts := make(map[string]contract.ContractEnvelope, len(state.Contracts))
	for selectorID, env := range state.Contracts {
		contracts[selectorID] = env
	}
	for _, selector := range selectors {
		if selector.AgentGlob != "" {
			if _, err := path.Match(selector.AgentGlob, ""); err != nil {
				return nil, fmt.Errorf("%w: selector %q agent_glob: %w", ErrInvalidSelector, selector.SelectorID, err)
			}
		}
		env, ok := contracts[selector.SelectorID]
		if !ok {
			return nil, fmt.Errorf("%w: selector %q missing contract", ErrNoResolvedContract, selector.SelectorID)
		}
		if env.Body.ContractHash != selector.ContractHash {
			return nil, fmt.Errorf("%w: selector %q contract_hash mismatch", ErrInvalidDecisionInput, selector.SelectorID)
		}
	}
	return &ActiveSet{
		manifestHash: state.ManifestHash,
		generation:   state.Envelope.Body.Generation,
		selectors:    selectors,
		contracts:    contracts,
	}, nil
}

// ManifestHash returns the active manifest hash stamped into receipts.
func (a *ActiveSet) ManifestHash() string {
	if a == nil {
		return ""
	}
	return a.manifestHash
}

// Generation returns the active manifest generation.
func (a *ActiveSet) Generation() uint64 {
	if a == nil {
		return 0
	}
	return a.generation
}

// Resolve picks the active contract for an agent/session. Exact agent matches
// win over glob selectors, and glob selectors win over the default selector.
func (a *ActiveSet) Resolve(agent string) (*ResolvedContract, bool) {
	if a == nil {
		return nil, false
	}
	agent = strings.TrimSpace(agent)
	candidates := make([]selectorCandidate, 0, len(a.selectors))
	for i, selector := range a.selectors {
		priority, ok := selectorPriority(selector, agent)
		if !ok {
			continue
		}
		env, exists := a.contracts[selector.SelectorID]
		if !exists {
			continue
		}
		candidates = append(candidates, selectorCandidate{
			priority: priority,
			index:    i,
			selector: selector,
			env:      env,
		})
	}
	if len(candidates) == 0 {
		return nil, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority > candidates[j].priority
		}
		return candidates[i].index < candidates[j].index
	})
	winner := candidates[0]
	return &ResolvedContract{
		ActiveManifestHash: a.manifestHash,
		ContractHash:       winner.selector.ContractHash,
		SelectorID:         winner.selector.SelectorID,
		ContractGeneration: a.generation,
		Contract:           winner.env.Body,
	}, true
}

type selectorCandidate struct {
	priority int
	index    int
	selector contract.ManifestSelector
	env      contract.ContractEnvelope
}

func selectorPriority(selector contract.ManifestSelector, agent string) (int, bool) {
	if selector.Agent != "" {
		return 3, selector.Agent == agent
	}
	if selector.AgentGlob != "" {
		matched, err := path.Match(selector.AgentGlob, agent)
		return 2, err == nil && matched
	}
	if selector.Default {
		return 1, true
	}
	return 0, false
}

// ResolvedContract is the per-session contract pin. Pass this by value to keep
// in-flight requests bound to the contract selected at request start.
type ResolvedContract struct {
	ActiveManifestHash string
	ContractHash       string
	SelectorID         string
	ContractGeneration uint64
	Contract           contract.Contract
}

// ReceiptContext is the subset stamped into every EvidenceReceipt v2 emitted
// under an active contract.
type ReceiptContext struct {
	ActiveManifestHash string
	ContractHash       string
	SelectorID         string
	ContractGeneration uint64
}

// ReceiptContext returns the v2 receipt stamping fields for this pin.
func (r ResolvedContract) ReceiptContext() ReceiptContext {
	return ReceiptContext{
		ActiveManifestHash: r.ActiveManifestHash,
		ContractHash:       r.ContractHash,
		SelectorID:         r.SelectorID,
		ContractGeneration: r.ContractGeneration,
	}
}

// StampReceipt returns a copy of receipt with the active contract context set.
func (c ReceiptContext) StampReceipt(receipt contractreceipt.EvidenceReceipt) contractreceipt.EvidenceReceipt {
	receipt.ActiveManifestHash = c.ActiveManifestHash
	receipt.ContractHash = c.ContractHash
	receipt.SelectorID = c.SelectorID
	receipt.ContractGeneration = c.ContractGeneration
	return receipt
}

// Mode describes whether a contract decision can affect live enforcement.
type Mode string

const (
	ModeLive    Mode = "live"
	ModeShadow  Mode = "shadow"
	ModeCapture Mode = "capture"
)

// HTTPRequest is the normalized input needed to evaluate HTTP contract rules.
type HTTPRequest struct {
	URL             string
	Method          string
	EffectiveAction string
}

// EvaluateOptions control one request evaluation.
type EvaluateOptions struct {
	Resolved         *ResolvedContract
	Request          HTTPRequest
	Mode             Mode
	KillSwitchActive bool
	ScannerVerdict   string
	ScannerMatched   bool
	PolicySources    []string
}

// Decision is the contract-aware verdict metadata for a request.
//
// Verdict is what the proxy MUST act on for this request — block or allow.
// LiveVerdict is what live mode WOULD have done given the same inputs:
// in ModeLive these are equal; in ModeShadow / ModeCapture, Verdict
// reflects the scanner-floor result (so the proxy never blocks more than
// scanner already would) while LiveVerdict surfaces the contract's
// would-have-been verdict for drift signalling and audit.
//
// WinningSource names the source that decided Verdict (kill_switch,
// scanner, contract). Drift carries the contract-attributed event when
// the contract path produced a non-allow verdict in any mode.
type Decision struct {
	Verdict       string
	LiveVerdict   string
	PolicySources []string
	WinningSource string
	RuleID        string
	Drift         *DriftEvent
	Signal        *session.SignalType
	Suppressed    bool
	Reason        string
}

// EvaluateHTTP returns the runtime verdict for an HTTP request under the
// active learn-and-lock contract. The decision sequence is:
//
//  1. Mode is required and must enumerate. Empty Mode is fail-closed input.
//  2. Kill switch active → block in every mode (absolute floor).
//  3. Scanner block → block in every mode (security floor; contract may not
//     resurrect a scanner-blocked request, including a signed allow rule).
//  4. No resolved contract → return the scanner verdict.
//  5. Contract resolved → evaluate enforce rules:
//     - Allow rule matches → contract annotates the (already-allowed)
//     scanner verdict; WinningSource = contract.
//     - Contract has zero enforce rules anywhere → fall through to
//     scanner (observation-only contract; no jurisdiction).
//     - Otherwise → contract default-deny (the contract claims
//     jurisdiction once any rule is in enforce; traffic outside the
//     enumerated allow set is denied).
//  6. Mode gate. ModeLive enforces the contract verdict directly.
//     ModeShadow / ModeCapture surface the scanner verdict as Verdict
//     (so the proxy never blocks more than scanner already would) while
//     LiveVerdict carries what live mode would have done, plus the drift
//     event for observation pipelines.
//
// The proxy MUST act on Decision.Verdict. LiveVerdict and Drift are
// audit/telemetry surface; using them for enforcement breaks the mode
// guarantee.
func EvaluateHTTP(opts EvaluateOptions) (Decision, error) {
	if opts.Mode == "" {
		return Decision{}, fmt.Errorf("%w: mode required", ErrInvalidDecisionInput)
	}
	if !validMode(opts.Mode) {
		return Decision{}, fmt.Errorf("%w: mode %q", ErrInvalidDecisionInput, opts.Mode)
	}

	sources := normalizePolicySources(opts.PolicySources)
	if opts.ScannerMatched || opts.ScannerVerdict != "" {
		sources = appendPolicySource(sources, PolicySourceScanner)
	}

	// 1. Kill switch is the absolute floor. Block in every mode.
	if opts.KillSwitchActive {
		sources = appendPolicySource(sources, PolicySourceKillSwitch)
		return Decision{
			Verdict:       config.ActionBlock,
			LiveVerdict:   config.ActionBlock,
			PolicySources: sources,
			WinningSource: WinningSourceKillSwitch,
			Suppressed:    true,
			Reason:        decisionReasonKillSwitchActive,
		}, nil
	}

	// Resolve scanner verdict (fail-closed if scanner did not decide).
	scannerVerdict := opts.ScannerVerdict
	scannerMissing := scannerVerdict == ""
	if scannerMissing {
		scannerVerdict = config.ActionBlock
	}

	// 2. Scanner block is the security floor. Wins in every mode, including
	// over a signed contract-allow rule. Without this, a contract becomes a
	// signed bypass of DLP / SSRF / blocklist.
	if scannerVerdict == config.ActionBlock {
		sources = appendPolicySource(sources, PolicySourceScanner)
		decision := Decision{
			Verdict:       config.ActionBlock,
			LiveVerdict:   config.ActionBlock,
			PolicySources: sources,
			WinningSource: WinningSourceScanner,
		}
		if scannerMissing {
			decision.Reason = decisionReasonScannerDecisionMissing
		}
		return decision, nil
	}

	// 3. No resolved contract → scanner verdict stands.
	if opts.Resolved == nil {
		return Decision{
			Verdict:       scannerVerdict,
			LiveVerdict:   scannerVerdict,
			PolicySources: sources,
			WinningSource: WinningSourceScanner,
		}, nil
	}

	sources = appendPolicySource(sources, PolicySourceContract)

	// 4 + 5. Compute the live verdict from the contract.
	live, err := evaluateContractLive(opts, sources, scannerVerdict)
	if err != nil {
		return Decision{}, err
	}

	// 6. Mode gate.
	return applyModeGate(live, opts.Mode, scannerVerdict, sources), nil
}

// evaluateContractLive returns what live mode would do for opts given a
// resolved contract, after kill-switch and scanner-block have been ruled out.
// Scanner verdict at this point is non-block; it is passed in so a contract
// allow can correctly annotate the scanner verdict instead of asserting an
// allow that scanner did not approve.
func evaluateContractLive(opts EvaluateOptions, sources []string, scannerVerdict string) (Decision, error) {
	u, err := url.Parse(opts.Request.URL)
	if err != nil || u.Hostname() == "" {
		return Decision{}, fmt.Errorf("%w: url", ErrInvalidDecisionInput)
	}

	hostHasEnforceRule := false
	contractHasEnforceRule := false
	hasComparableEvidence := false
	hostRuleIDs := make([]string, 0)
	seenRuleIDs := map[string]struct{}{}
	for _, rule := range opts.Resolved.Contract.Rules {
		if !isHTTPRule(rule) {
			continue
		}
		if err := validateLifecycle(rule.LifecycleState); err != nil {
			return Decision{}, err
		}
		if rule.LifecycleState != LifecycleEnforce {
			continue
		}
		contractHasEnforceRule = true
		if !ruleHostMatches(rule, u.Hostname()) {
			continue
		}
		hostHasEnforceRule = true
		hostRuleIDs = appendRuleID(hostRuleIDs, seenRuleIDs, rule.RuleID)
		if !usesDefaultHTTPPort(u) {
			return contractBlockDecision(opts, sources, rule.RuleID, decisionReasonContractNonDefaultPort), nil
		}
		matches, canCompare, invalidPath := ruleMatchesHTTP(rule, u, opts.Request)
		if invalidPath {
			return contractBlockDecision(opts, sources, rule.RuleID, decisionReasonContractInvalidPath), nil
		}
		if !canCompare {
			continue
		}
		hasComparableEvidence = true
		if matches {
			// Contract allow annotates the scanner-allowed verdict.
			// Scanner block has already been resolved upstream and
			// cannot reach this point, so it is impossible for an
			// allow rule to override a scanner block here.
			return Decision{
				Verdict:       scannerVerdict,
				LiveVerdict:   scannerVerdict,
				PolicySources: sources,
				WinningSource: WinningSourceContract,
				RuleID:        rule.RuleID,
			}, nil
		}
	}

	// No allow rule matched.
	if !contractHasEnforceRule {
		// Contract is observation-only (zero enforce rules anywhere). It
		// claims no jurisdiction; scanner verdict stands.
		return Decision{
			Verdict:       scannerVerdict,
			LiveVerdict:   scannerVerdict,
			PolicySources: sources,
			WinningSource: WinningSourceScanner,
		}, nil
	}

	reason := decisionReasonContractDefaultDeny
	ruleID := ""
	if hostHasEnforceRule && hasComparableEvidence {
		reason = decisionReasonContractEnforceDefault
		ruleID = firstString(hostRuleIDs)
	}
	return contractBlockDecision(opts, sources, ruleID, reason), nil
}

// applyModeGate adapts a live-mode decision to the configured mode.
// ModeLive returns it unchanged. ModeShadow and ModeCapture surface the
// scanner verdict as the enforced Verdict (so the proxy never blocks more
// than scanner already would) and carry the live verdict + drift event
// for telemetry. SignalForDrift gates the adaptive signal on
// DriftEvent.Mode == ModeLive directly, so shadow/capture never emit
// the live block signal even when Drift is populated.
func applyModeGate(live Decision, mode Mode, scannerVerdict string, sources []string) Decision {
	if mode == ModeLive {
		return live
	}
	out := Decision{
		Verdict:       scannerVerdict,
		LiveVerdict:   live.Verdict,
		PolicySources: sources,
		WinningSource: WinningSourceScanner,
		RuleID:        live.RuleID,
		Drift:         live.Drift,
	}
	if live.WinningSource == WinningSourceContract && live.Verdict != scannerVerdict {
		out.Reason = decisionReasonContractObservedOnly
	}
	return out
}

func validMode(mode Mode) bool {
	switch mode {
	case ModeLive, ModeShadow, ModeCapture:
		return true
	default:
		return false
	}
}

func contractBlockDecision(opts EvaluateOptions, sources []string, ruleID, reason string) Decision {
	event := DriftEvent{
		ContractHash: opts.Resolved.ContractHash,
		RuleID:       ruleID,
		Kind:         DriftKindPositive,
		Mode:         opts.Mode,
		Action:       config.ActionBlock,
	}
	decision := Decision{
		Verdict:       config.ActionBlock,
		LiveVerdict:   config.ActionBlock,
		PolicySources: sources,
		WinningSource: WinningSourceContract,
		RuleID:        ruleID,
		Drift:         &event,
		Reason:        reason,
	}
	decision.Signal = SignalForDrift(event)
	return decision
}

func isHTTPRule(rule contract.Rule) bool {
	return rule.RuleKind == ruleKindHTTPDestination || rule.RuleKind == ruleKindHTTPAction
}

func validateLifecycle(state string) error {
	switch state {
	case LifecycleProposed, LifecycleCaptureOnly, LifecycleEnforce, LifecycleExpired, LifecycleDemoted:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedLifecycle, state)
	}
}

func ruleHostMatches(rule contract.Rule, host string) bool {
	ruleHost := normalizeHost(selectorString(rule.Selector, "host"))
	return ruleHost != "" && ruleHost == normalizeHost(host)
}

func ruleMatchesHTTP(rule contract.Rule, u *url.URL, req HTTPRequest) (bool, bool, bool) {
	matchedConstraint := selectorString(rule.Selector, "host") != ""
	if methods := selectorMethods(rule.Selector); len(methods) > 0 {
		matchedConstraint = true
		if !containsFolded(methods, req.Method) {
			return false, true, false
		}
	}
	if paths := selectorPathValues(rule.Selector); len(paths) > 0 {
		matchedConstraint = true
		matches, canCompare := pathMatchesAny(u.EscapedPath(), paths)
		if !canCompare {
			return false, false, true
		}
		if !matches {
			return false, true, false
		}
	}
	if action := selectorRawString(rule.Selector, "effective_action"); action != "" {
		matchedConstraint = true
		if action != req.EffectiveAction {
			return false, true, false
		}
	}
	return matchedConstraint, true, false
}

func selectorString(selector map[string]any, key string) string {
	value, ok := selector[key].(map[string]any)
	if !ok {
		return ""
	}
	raw, _ := value["value"].(string)
	return raw
}

func selectorRawString(selector map[string]any, key string) string {
	value, _ := selector[key].(string)
	return value
}

func selectorMethods(selector map[string]any) []string {
	values, ok := selector["methods"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if ok {
			out = append(out, text)
		}
	}
	return out
}

func selectorPathValues(selector map[string]any) []string {
	values, ok := selector["paths"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		text, ok := item["value"].(string)
		if ok {
			out = append(out, text)
		}
	}
	return out
}

func containsFolded(values []string, target string) bool {
	target = strings.ToUpper(strings.TrimSpace(target))
	for _, value := range values {
		if strings.ToUpper(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func usesDefaultHTTPPort(u *url.URL) bool {
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "https":
		return u.Port() == "" || u.Port() == "443"
	case "http":
		return u.Port() == "" || u.Port() == "80"
	default:
		return false
	}
}

func pathMatchesAny(escapedPath string, values []string) (bool, bool) {
	if escapedPath == "" {
		escapedPath = "/"
	}
	canonicalPath, _, err := normalize.Canonicalize(escapedPath)
	if err != nil {
		return false, false
	}
	for _, value := range values {
		if value == canonicalPath {
			return true, true
		}
	}
	return false, true
}

func appendRuleID(ruleIDs []string, seen map[string]struct{}, ruleID string) []string {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return ruleIDs
	}
	if _, ok := seen[ruleID]; ok {
		return ruleIDs
	}
	seen[ruleID] = struct{}{}
	return append(ruleIDs, ruleID)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func normalizePolicySources(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func appendPolicySource(values []string, source string) []string {
	for _, value := range values {
		if value == source {
			return values
		}
	}
	return append(values, source)
}

// ProxyDecisionPayload builds the typed EvidenceReceipt v2 proxy_decision
// payload from a runtime decision.
//
// LiveVerdict is omitted from the wire payload when it equals Verdict (the
// ModeLive case) so receipts stay compact for the common path. ModeShadow
// and ModeCapture surface the divergence by setting LiveVerdict to what
// the contract path would have enforced under ModeLive while Verdict
// reflects the scanner-floor result the proxy actually applied.
func ProxyDecisionPayload(decision Decision, actionType, target, transport string) contractreceipt.PayloadProxyDecisionStruct {
	live := decision.LiveVerdict
	if live == decision.Verdict {
		live = ""
	}
	return contractreceipt.PayloadProxyDecisionStruct{
		ActionType:    actionType,
		Target:        target,
		Verdict:       decision.Verdict,
		LiveVerdict:   live,
		Transport:     transport,
		PolicySources: append([]string(nil), decision.PolicySources...),
		WinningSource: decision.WinningSource,
		RuleID:        decision.RuleID,
	}
}
