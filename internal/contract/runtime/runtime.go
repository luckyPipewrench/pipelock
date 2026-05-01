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

const (
	// LifecycleProposed means the rule is visible to operators but not active.
	LifecycleProposed = "proposed"
	// LifecycleCaptureOnly records telemetry without changing live enforcement.
	LifecycleCaptureOnly = "capture_only"
	// LifecycleEnforce allows the rule to affect live decisions.
	LifecycleEnforce = "enforce"
	// LifecycleExpired marks a rule as no longer active.
	LifecycleExpired = "expired"
	// LifecycleDemoted marks a rule removed from enforcement by drift handling.
	LifecycleDemoted = "demoted"
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

const (
	ruleKindHTTPDestination = "http_destination"
	ruleKindHTTPAction      = "http_action"

	DriftKindPositive = "positive"
	DriftKindNegative = "negative"
)

var (
	// ErrNoResolvedContract is returned when a caller asks for evaluation
	// without an active contract pin.
	ErrNoResolvedContract = errors.New("contract runtime: no resolved contract")
	// ErrUnsupportedLifecycle is returned for non-enumerated rule states.
	ErrUnsupportedLifecycle = errors.New("contract runtime: unsupported lifecycle state")
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
type Decision struct {
	Verdict       string
	PolicySources []string
	WinningSource string
	RuleID        string
	Drift         *DriftEvent
	Signal        *session.SignalType
	Suppressed    bool
	Reason        string
}

// EvaluateHTTP evaluates active HTTP destination/action rules. It implements
// host-scoped deny-default: only hosts with comparable enforce rules can be
// denied by contract default.
func EvaluateHTTP(opts EvaluateOptions) (Decision, error) {
	sources := normalizePolicySources(opts.PolicySources)
	if opts.ScannerMatched || opts.ScannerVerdict != "" {
		sources = appendPolicySource(sources, PolicySourceScanner)
	}
	if opts.KillSwitchActive {
		sources = appendPolicySource(sources, PolicySourceKillSwitch)
		return Decision{
			Verdict:       config.ActionBlock,
			PolicySources: sources,
			WinningSource: WinningSourceKillSwitch,
			Suppressed:    true,
			Reason:        "kill_switch_active",
		}, nil
	}
	if opts.Resolved == nil {
		return scannerDecision(opts.ScannerVerdict, sources), nil
	}
	sources = appendPolicySource(sources, PolicySourceContract)
	u, err := url.Parse(opts.Request.URL)
	if err != nil || u.Hostname() == "" {
		return Decision{}, fmt.Errorf("%w: url", ErrInvalidDecisionInput)
	}

	hostHasEnforceRule := false
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
		if !ruleHostMatches(rule, u.Hostname()) {
			continue
		}
		hostHasEnforceRule = true
		hostRuleIDs = appendRuleID(hostRuleIDs, seenRuleIDs, rule.RuleID)
		if !usesDefaultHTTPPort(u) {
			return contractBlockDecision(opts, sources, rule.RuleID, "contract_non_default_port"), nil
		}
		matches, canCompare, invalidPath := ruleMatchesHTTP(rule, u, opts.Request)
		if invalidPath {
			return contractBlockDecision(opts, sources, rule.RuleID, "contract_invalid_path"), nil
		}
		if !canCompare {
			continue
		}
		hasComparableEvidence = true
		if matches {
			return Decision{
				Verdict:       config.ActionAllow,
				PolicySources: sources,
				WinningSource: WinningSourceContract,
				RuleID:        rule.RuleID,
			}, nil
		}
	}
	if hostHasEnforceRule && hasComparableEvidence {
		return contractBlockDecision(opts, sources, firstString(hostRuleIDs), "contract_enforce_default"), nil
	}
	return scannerDecision(opts.ScannerVerdict, sources), nil
}

func scannerDecision(scannerVerdict string, sources []string) Decision {
	missing := scannerVerdict == ""
	if scannerVerdict == "" {
		scannerVerdict = config.ActionBlock
	}
	sources = appendPolicySource(sources, PolicySourceScanner)
	decision := Decision{
		Verdict:       scannerVerdict,
		PolicySources: sources,
		WinningSource: WinningSourceScanner,
	}
	if missing {
		decision.Reason = "scanner_decision_missing"
	}
	return decision
}

func contractBlockDecision(opts EvaluateOptions, sources []string, ruleID, reason string) Decision {
	event := DriftEvent{
		ContractHash: opts.Resolved.ContractHash,
		RuleID:       ruleID,
		Kind:         DriftKindPositive,
		Mode:         effectiveMode(opts.Mode),
		Action:       config.ActionBlock,
	}
	decision := Decision{
		Verdict:       config.ActionBlock,
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
func ProxyDecisionPayload(decision Decision, actionType, target, transport string) contractreceipt.PayloadProxyDecisionStruct {
	return contractreceipt.PayloadProxyDecisionStruct{
		ActionType:    actionType,
		Target:        target,
		Verdict:       decision.Verdict,
		Transport:     transport,
		PolicySources: append([]string(nil), decision.PolicySources...),
		WinningSource: decision.WinningSource,
		RuleID:        decision.RuleID,
	}
}
