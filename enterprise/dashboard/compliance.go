//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	CoverageCovered    CoverageStatus = "covered"
	CoveragePartial    CoverageStatus = "partial"
	CoverageNotCovered CoverageStatus = "not-covered"

	complianceFleetAgentLimit = 500
	fleetAgentIDMaxBytes      = 256
	complianceLimitation      = "Coverage is LIMITED to mediated egress observed inside the declared Pipelock boundary; it does not prove that unmediated actions did not occur."
)

// CoverageStatus is the bounded status vocabulary for Pipelock's control
// mapping. Unknown input never becomes a status.
type CoverageStatus string

// EvidenceRequirement is one declared backing fact in a mapping definition.
// Definitions are Go data so framework claims remain reviewable and testable.
type EvidenceRequirement struct {
	Key   string
	Kind  string
	Label string
}

type ControlDefinition struct {
	ID          string
	Title       string
	Description string
	Evidence    []EvidenceRequirement
}

type FrameworkDefinition struct {
	ID       string
	Name     string
	Version  string
	Controls []ControlDefinition
}

// EvidenceSignal is a source-grounded fact assembled from the existing
// receipt scorecards, verified coverage summaries, or loaded config.
type EvidenceSignal struct {
	Present bool
	Detail  string
}

type MappedEvidence struct {
	Kind    string
	Label   string
	Present bool
	Detail  string
}

type ControlMapping struct {
	ID          string
	Title       string
	Description string
	Status      CoverageStatus
	Evidence    []MappedEvidence
}

type FrameworkMapping struct {
	ID       string
	Name     string
	Version  string
	Controls []ControlMapping
}

// FleetAgentCoverage is a read-only, already-verified coverage-certificate
// summary supplied by a live fleet implementation. The dashboard does not
// sign, mutate, or infer missing values.
type FleetAgentCoverage struct {
	AgentID                     string
	CoverageCertificateVerified bool
	SessionsCovered             int
	ChainGaps                   uint64
}

// FleetCoverageDataSource is an optional extension to FleetDataSource. A
// FleetSource that does not implement it is honestly treated as unconfigured
// for compliance coverage rather than synthesized from follower health.
type FleetCoverageDataSource interface {
	ListFleetAgentCoverage(ctx context.Context, orgID, fleetID string, limit int) ([]FleetAgentCoverage, error)
}

type FleetAgentCoverageRow struct {
	AgentID         string
	Status          CoverageStatus
	SessionsCovered int
	ChainGaps       uint64
	Certificate     string
}

type FleetCoverageRollup struct {
	SourceConfigured bool
	OrgID            string
	FleetID          string
	Agents           []FleetAgentCoverageRow
	Covered          int
	Partial          int
	NotCovered       int
	Truncated        bool
	Limitation       string
}

type CompliancePage struct {
	Frameworks []FrameworkMapping
	LegalHolds []LegalHold
	Fleet      FleetCoverageRollup
	Limitation string
}

// frameworkDefinitions is Pipelock's mapping, not a certification or an
// endorsement by a framework body. Requirements deliberately name concrete
// evidence instead of granting green status from product capability claims.
func frameworkDefinitions() []FrameworkDefinition {
	return []FrameworkDefinition{
		{
			ID:      "aarm-v1",
			Name:    "AARM",
			Version: "v1.0 — Pipelock's mapping",
			Controls: []ControlDefinition{
				{ID: "R1", Title: "Pre-execution interception", Description: "Intercept agent-initiated actions before execution without a bypass path.", Evidence: []EvidenceRequirement{
					{Key: "config.enforce", Kind: "config knob", Label: "enforce"},
					{Key: "receipt.action", Kind: "receipt type", Label: "action receipt"},
					{Key: "deployment.complete_mediation", Kind: "deployment evidence", Label: "complete mediation"},
				}},
				{ID: "R2", Title: "Context accumulation", Description: "Maintain task and prior-action context for policy evaluation.", Evidence: []EvidenceRequirement{
					{Key: "config.session_profiling", Kind: "config knob", Label: "session_profiling.enabled"},
					{Key: "config.tool_chain", Kind: "config knob", Label: "tool_chain_detection.enabled"},
					{Key: "receipt.action", Kind: "receipt type", Label: "action receipt"},
					{Key: "evidence.intent_context", Kind: "receipt evidence", Label: "intent and conversation context supplied to policy"},
				}},
				{ID: "R3", Title: "Policy evaluation with intent alignment", Description: "Evaluate actions against policy and stated intent.", Evidence: []EvidenceRequirement{
					{Key: "config.tool_policy", Kind: "config knob", Label: "mcp_tool_policy.enabled"},
					{Key: "config.adaptive", Kind: "config knob", Label: "adaptive_enforcement.enabled"},
					{Key: "receipt.action", Kind: "receipt type", Label: "action receipt"},
					{Key: "evidence.intent_alignment", Kind: "receipt evidence", Label: "intent-alignment evaluation"},
				}},
				{ID: "R4", Title: "Five authorization decisions", Description: "Support ALLOW, DENY, MODIFY, STEP_UP, and DEFER outcomes.", Evidence: []EvidenceRequirement{
					{Key: "config.tool_policy", Kind: "config knob", Label: "mcp_tool_policy.enabled"},
					{Key: "config.defer", Kind: "config knob", Label: "defer.enabled"},
					{Key: "evidence.five_decisions", Kind: "receipt evidence", Label: "all five decision types observed"},
				}},
				{ID: "R5", Title: "Tamper-evident receipts", Description: "Produce verifiable receipts for evaluated actions.", Evidence: []EvidenceRequirement{
					{Key: "receipt.action", Kind: "receipt type", Label: "action_receipt_v1"},
					{Key: "receipt.trusted_signature", Kind: "scorecard", Label: "trusted signature verification"},
					{Key: "receipt.chain", Kind: "scorecard", Label: "hash-chain integrity"},
					{Key: "config.require_receipts", Kind: "config knob", Label: "flight_recorder.require_receipts"},
				}},
				{ID: "R6", Title: "Identity binding", Description: "Cryptographically bind each receipt to an agent identity.", Evidence: []EvidenceRequirement{
					{Key: "config.bound_identity", Kind: "config knob", Label: "bind_default_agent_identity"},
					{Key: "receipt.trusted_signature", Kind: "scorecard", Label: "trusted signature verification"},
					{Key: "receipt.action", Kind: "receipt type", Label: "signed actor field"},
					{Key: "evidence.bound_actor", Kind: "receipt evidence", Label: "non-empty actor bound to the configured identity"},
				}},
				{ID: "R7", Title: "Semantic distance tracking", Description: "Track and flag drift from the original intent over time.", Evidence: []EvidenceRequirement{
					{Key: "config.behavioral_baseline", Kind: "config knob", Label: "behavioral_baseline.enabled"},
					{Key: "config.adaptive", Kind: "config knob", Label: "adaptive_enforcement.enabled"},
					{Key: "evidence.semantic_distance", Kind: "receipt evidence", Label: "semantic-distance measurement"},
				}},
				{ID: "R8", Title: "Telemetry export", Description: "Export interoperable action telemetry for observability systems.", Evidence: []EvidenceRequirement{
					{Key: "config.otlp", Kind: "config knob", Label: "emit.otlp.endpoint"},
					{Key: "receipt.action", Kind: "receipt type", Label: "action receipt"},
					{Key: "evidence.telemetry_delivery", Kind: "runtime evidence", Label: "successful telemetry delivery"},
				}},
				{ID: "R9", Title: "Least privilege enforcement", Description: "Scope agent tool and credential authority at action time.", Evidence: []EvidenceRequirement{
					{Key: "config.tool_policy", Kind: "config knob", Label: "mcp_tool_policy.enabled"},
					{Key: "config.session_binding", Kind: "config knob", Label: "mcp_session_binding.enabled"},
					{Key: "config.agent_profiles", Kind: "config knob", Label: "agent profiles with tool-policy rules"},
					{Key: "evidence.credential_scope", Kind: "runtime evidence", Label: "per-action credential scope"},
				}},
			},
		},
		{
			ID:      "soc2-style",
			Name:    "Generic SOC 2-style controls",
			Version: "illustrative — Pipelock's mapping, not an auditor opinion",
			Controls: []ControlDefinition{
				{ID: "CC6.1-style", Title: "Logical access controls", Description: "Restrict agent actions to operator-defined policy.", Evidence: []EvidenceRequirement{
					{Key: "config.enforce", Kind: "config knob", Label: "enforce"},
					{Key: "config.tool_policy", Kind: "config knob", Label: "mcp_tool_policy.enabled"},
				}},
				{ID: "CC6.6-style", Title: "System boundary protection", Description: "Inspect mediated traffic at the declared boundary.", Evidence: []EvidenceRequirement{
					{Key: "receipt.action", Kind: "receipt type", Label: "action receipt"},
					{Key: "deployment.complete_mediation", Kind: "deployment evidence", Label: "complete mediation"},
				}},
				{ID: "CC7.2-style", Title: "Security-event monitoring", Description: "Record and export security decisions.", Evidence: []EvidenceRequirement{
					{Key: "receipt.action", Kind: "receipt type", Label: "action receipt"},
					{Key: "config.otlp", Kind: "config knob", Label: "emit.otlp.endpoint"},
					{Key: "evidence.telemetry_delivery", Kind: "runtime evidence", Label: "successful telemetry delivery"},
				}},
				{ID: "CC7.3-style", Title: "Evidence integrity", Description: "Retain independently verifiable decision evidence.", Evidence: []EvidenceRequirement{
					{Key: "receipt.trusted_signature", Kind: "scorecard", Label: "trusted signature verification"},
					{Key: "receipt.chain", Kind: "scorecard", Label: "hash-chain integrity"},
					{Key: "coverage.cert", Kind: "coverage-cert", Label: "verified fleet coverage certificate"},
				}},
				{ID: "CC8.1-style", Title: "Retention preservation", Description: "Preserve operator-declared evidence under legal hold.", Evidence: []EvidenceRequirement{
					{Key: "legal_hold.active", Kind: "legal-hold metadata", Label: "active legal hold"},
					{Key: "evidence.retention_verified", Kind: "runtime evidence", Label: "held evidence remains present and readable"},
				}},
			},
		},
	}
}

func evaluateControlMapping(control ControlDefinition, signals map[string]EvidenceSignal) ControlMapping {
	mapping := ControlMapping{ID: control.ID, Title: control.Title, Description: control.Description, Status: CoverageNotCovered}
	if len(control.Evidence) == 0 {
		return mapping
	}
	present := 0
	for _, requirement := range control.Evidence {
		signal, ok := signals[requirement.Key]
		backed := ok && signal.Present
		if backed {
			present++
		}
		detail := "Not observed in the configured evidence sources."
		if ok && strings.TrimSpace(signal.Detail) != "" {
			detail = signal.Detail
		}
		mapping.Evidence = append(mapping.Evidence, MappedEvidence{
			Kind: requirement.Kind, Label: requirement.Label, Present: backed, Detail: detail,
		})
	}
	switch {
	case present == len(control.Evidence):
		mapping.Status = CoverageCovered
	case present > 0:
		mapping.Status = CoveragePartial
	}
	return mapping
}

func evaluateFrameworks(signals map[string]EvidenceSignal) []FrameworkMapping {
	definitions := frameworkDefinitions()
	out := make([]FrameworkMapping, 0, len(definitions))
	for _, framework := range definitions {
		mapped := FrameworkMapping{ID: framework.ID, Name: framework.Name, Version: framework.Version}
		for _, control := range framework.Controls {
			mapped.Controls = append(mapped.Controls, evaluateControlMapping(control, signals))
		}
		out = append(out, mapped)
	}
	return out
}

// Compliance assembles a disposable read model from current evidence sources.
// No mapping, rollup, or coverage status is persisted.
func (m *ReadModel) Compliance(ctx context.Context, orgID, fleetID string) (CompliancePage, error) {
	sessions, err := m.Sessions()
	if err != nil {
		return CompliancePage{}, err
	}
	fleet, err := m.complianceFleetRollup(ctx, orgID, fleetID)
	if err != nil {
		return CompliancePage{}, err
	}
	holds := []LegalHold(nil)
	if m.legalHoldStore != nil {
		holds, err = m.legalHoldStore.Snapshot()
		if err != nil {
			return CompliancePage{}, fmt.Errorf("read legal holds: %w", err)
		}
	}
	signals := complianceSignals(m.cfg, sessions, fleet, holds)
	return CompliancePage{
		Frameworks: evaluateFrameworks(signals),
		LegalHolds: holds,
		Fleet:      fleet,
		Limitation: complianceLimitation,
	}, nil
}

func complianceSignals(cfg *config.Config, sessions []SessionSummary, fleet FleetCoverageRollup, holds []LegalHold) map[string]EvidenceSignal {
	signals := map[string]EvidenceSignal{}
	totalReceipts := uint64(0)
	validReceiptCounts := true
	trusted, intact := 0, 0
	for _, session := range sessions {
		if session.ReceiptCount < 0 {
			validReceiptCounts = false
		} else {
			totalReceipts += uint64(session.ReceiptCount)
		}
		if hasSingleVerifiedPip(session.Pips, "A") {
			trusted++
		}
		if hasSingleVerifiedPip(session.Pips, "U") {
			intact++
		}
	}
	signals["receipt.action"] = EvidenceSignal{Present: validReceiptCounts && totalReceipts > 0, Detail: fmt.Sprintf("%d mediated action receipts across %d sessions.", totalReceipts, len(sessions))}
	signals["receipt.trusted_signature"] = EvidenceSignal{Present: len(sessions) > 0 && trusted == len(sessions), Detail: fmt.Sprintf("%d/%d session scorecards verify against operator-trusted keys.", trusted, len(sessions))}
	signals["receipt.chain"] = EvidenceSignal{Present: len(sessions) > 0 && intact == len(sessions), Detail: fmt.Sprintf("%d/%d session scorecards report intact receipt chains.", intact, len(sessions))}
	allFleetCovered := fleet.SourceConfigured && len(fleet.Agents) > 0 && !fleet.Truncated && fleet.Covered == len(fleet.Agents)
	signals["coverage.cert"] = EvidenceSignal{Present: allFleetCovered, Detail: fmt.Sprintf("%d/%d fleet agent coverage certificates verify with no reported chain gaps; truncated=%t.", fleet.Covered, len(fleet.Agents), fleet.Truncated)}
	activeHolds := 0
	for _, hold := range holds {
		if hold.Released == nil {
			activeHolds++
		}
	}
	signals["legal_hold.active"] = EvidenceSignal{Present: activeHolds > 0, Detail: fmt.Sprintf("%d active operator-authored legal holds.", activeHolds)}
	if cfg == nil {
		return signals
	}
	signals["config.enforce"] = EvidenceSignal{Present: cfg.EnforceEnabled(), Detail: fmt.Sprintf("enforce effective value: %t.", cfg.EnforceEnabled())}
	signals["config.require_receipts"] = EvidenceSignal{Present: cfg.FlightRecorder.Enabled && cfg.FlightRecorder.RequireReceipts, Detail: fmt.Sprintf("flight_recorder.enabled=%t, require_receipts=%t.", cfg.FlightRecorder.Enabled, cfg.FlightRecorder.RequireReceipts)}
	signals["config.session_profiling"] = boolSignal(cfg.SessionProfiling.Enabled, "session_profiling.enabled")
	signals["config.tool_chain"] = boolSignal(cfg.ToolChainDetection.Enabled, "tool_chain_detection.enabled")
	signals["config.tool_policy"] = boolSignal(cfg.MCPToolPolicy.Enabled && len(cfg.MCPToolPolicy.Rules) > 0, "mcp_tool_policy enabled with at least one rule")
	signals["config.adaptive"] = boolSignal(cfg.AdaptiveEnforcement.Enabled, "adaptive_enforcement.enabled")
	signals["config.defer"] = boolSignal(cfg.Defer.Enabled, "defer.enabled")
	signals["config.bound_identity"] = boolSignal(cfg.BindDefaultAgentIdentity && strings.TrimSpace(cfg.DefaultAgentIdentity) != "", "operator-bound default agent identity")
	signals["config.behavioral_baseline"] = boolSignal(cfg.BehavioralBaseline.Enabled, "behavioral_baseline.enabled")
	signals["config.otlp"] = boolSignal(strings.TrimSpace(cfg.Emit.OTLP.Endpoint) != "", "emit.otlp.endpoint configured")
	signals["config.session_binding"] = boolSignal(cfg.MCPSessionBinding.Enabled, "mcp_session_binding.enabled")
	signals["config.agent_profiles"] = boolSignal(hasScopedAgentProfile(cfg.Agents), "one or more agent profiles with enabled tool-policy rules")
	return signals
}

func hasSingleVerifiedPip(pips []SummaryPip, label string) bool {
	found := 0
	verified := false
	for _, pip := range pips {
		if pip.Label != label {
			continue
		}
		found++
		verified = pip.State == StateVerify
	}
	return found == 1 && verified
}

func hasScopedAgentProfile(profiles map[string]config.AgentProfile) bool {
	for _, profile := range profiles {
		if profile.MCPToolPolicy != nil && profile.MCPToolPolicy.Enabled && len(profile.MCPToolPolicy.Rules) > 0 {
			return true
		}
	}
	return false
}

func boolSignal(present bool, label string) EvidenceSignal {
	return EvidenceSignal{Present: present, Detail: fmt.Sprintf("%s: %t.", label, present)}
}

func (m *ReadModel) complianceFleetSource() (FleetCoverageDataSource, bool) {
	if m.fleetSource == nil {
		return nil, false
	}
	source, ok := m.fleetSource.(FleetCoverageDataSource)
	if !ok || isNilFleetCoverageSource(source) {
		return nil, false
	}
	return source, true
}

func isNilFleetCoverageSource(source FleetCoverageDataSource) bool {
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (m *ReadModel) complianceFleetRollup(ctx context.Context, orgID, fleetID string) (FleetCoverageRollup, error) {
	source, configured := m.complianceFleetSource()
	rollup := FleetCoverageRollup{SourceConfigured: configured, OrgID: strings.TrimSpace(orgID), FleetID: strings.TrimSpace(fleetID), Limitation: complianceLimitation}
	if !configured {
		return rollup, nil
	}
	if err := validateFleetScope(rollup.OrgID, rollup.FleetID, true); err != nil {
		return FleetCoverageRollup{}, err
	}
	coverage, err := source.ListFleetAgentCoverage(ctx, rollup.OrgID, rollup.FleetID, complianceFleetAgentLimit+1)
	if err != nil {
		return FleetCoverageRollup{}, fmt.Errorf("list fleet agent coverage: %w", err)
	}
	if len(coverage) >= complianceFleetAgentLimit {
		rollup.Truncated = true
		if len(coverage) > complianceFleetAgentLimit {
			coverage = coverage[:complianceFleetAgentLimit]
		}
	}
	seenAgentIDs := make(map[string]struct{}, len(coverage))
	for _, agent := range coverage {
		agentID := strings.TrimSpace(agent.AgentID)
		if validFleetAgentID(agentID) {
			if _, exists := seenAgentIDs[agentID]; exists {
				return FleetCoverageRollup{}, fmt.Errorf("duplicate fleet agent coverage identity %q", agentID)
			}
			seenAgentIDs[agentID] = struct{}{}
		}
		row := normalizeFleetAgentCoverage(agent)
		rollup.Agents = append(rollup.Agents, row)
		switch row.Status {
		case CoverageCovered:
			rollup.Covered++
		case CoveragePartial:
			rollup.Partial++
		default:
			rollup.NotCovered++
		}
	}
	sort.Slice(rollup.Agents, func(i, j int) bool { return rollup.Agents[i].AgentID < rollup.Agents[j].AgentID })
	return rollup, nil
}

func normalizeFleetAgentCoverage(agent FleetAgentCoverage) FleetAgentCoverageRow {
	id := strings.TrimSpace(agent.AgentID)
	row := FleetAgentCoverageRow{
		AgentID: id, SessionsCovered: agent.SessionsCovered, ChainGaps: agent.ChainGaps,
		Status: CoverageNotCovered, Certificate: "not verified",
	}
	if !validFleetAgentID(id) || agent.SessionsCovered < 0 {
		row.AgentID = "(invalid agent identity)"
		row.Certificate = "invalid coverage record"
		return row
	}
	if agent.CoverageCertificateVerified {
		row.Certificate = "verified"
	}
	switch {
	case agent.CoverageCertificateVerified && agent.SessionsCovered > 0 && agent.ChainGaps == 0:
		row.Status = CoverageCovered
	case agent.CoverageCertificateVerified || agent.SessionsCovered > 0 || agent.ChainGaps > 0:
		row.Status = CoveragePartial
	}
	return row
}

func validFleetAgentID(id string) bool {
	return id != "" && len(id) <= fleetAgentIDMaxBytes && strings.IndexFunc(id, unicode.IsControl) < 0
}
