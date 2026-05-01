// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"strconv"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// DriftObservation is one per-rule window summary from live evaluation.
type DriftObservation struct {
	Rule                  contract.Rule
	ContractHash          string
	Mode                  Mode
	KillSwitchActive      bool
	OpportunityObserved   bool
	ExpectedObserved      bool
	UnexpectedObserved    bool
	MissedWindows         uint64
	RequiredMissedWindows uint64
	OpportunityHealthy    bool
	HistoricalRate        string
	CurrentRate           string
	Window                string
	ParentContext         string
}

// DriftResult contains telemetry produced from a DriftObservation.
type DriftResult struct {
	Suppressed        bool
	Drift             *DriftEvent
	OpportunityAlert  *OpportunityMissing
	AdaptiveSignal    *session.SignalType
	ShouldAutoDemote  bool
	ShouldEmitReceipt bool
}

// DriftEvent describes a contract_drift receipt candidate.
type DriftEvent struct {
	ContractHash       string
	RuleID             string
	Kind               string
	Mode               Mode
	Action             string
	ObservationSummary string
	MissedWindows      uint64
	OpportunityStatus  string
}

// OpportunityMissing describes an opportunity_missing receipt candidate.
type OpportunityMissing struct {
	ContractHash              string
	RuleID                    string
	ParentContext             string
	HistoricalOpportunityRate string
	CurrentOpportunityRate    string
	Window                    string
}

// EvaluateDrift applies the drift state machine. Negative drift is gated on
// three clauses: enough missed windows, observed opportunity, and healthy
// opportunity telemetry. Opportunity suppression emits opportunity_missing and
// deliberately does not auto-demote.
func EvaluateDrift(obs DriftObservation) (DriftResult, error) {
	if obs.KillSwitchActive {
		return DriftResult{Suppressed: true}, nil
	}
	if err := validateLifecycle(obs.Rule.LifecycleState); err != nil {
		return DriftResult{}, err
	}
	if obs.ContractHash == "" {
		return DriftResult{}, fmt.Errorf("%w: contract_hash", ErrInvalidDecisionInput)
	}
	if obs.Rule.RuleID == "" {
		return DriftResult{}, fmt.Errorf("%w: rule_id", ErrInvalidDecisionInput)
	}
	switch obs.Rule.LifecycleState {
	case LifecycleExpired, LifecycleDemoted, LifecycleProposed:
		return DriftResult{}, nil
	}

	if !obs.OpportunityHealthy {
		alert := OpportunityMissing{
			ContractHash:              obs.ContractHash,
			RuleID:                    obs.Rule.RuleID,
			ParentContext:             obs.ParentContext,
			HistoricalOpportunityRate: obs.HistoricalRate,
			CurrentOpportunityRate:    obs.CurrentRate,
			Window:                    obs.Window,
		}
		return DriftResult{
			OpportunityAlert:  &alert,
			ShouldEmitReceipt: true,
		}, nil
	}

	if obs.UnexpectedObserved {
		event := DriftEvent{
			ContractHash:       obs.ContractHash,
			RuleID:             obs.Rule.RuleID,
			Kind:               DriftKindPositive,
			Mode:               effectiveMode(obs.Mode),
			Action:             config.ActionBlock,
			ObservationSummary: "unexpected observation outside enforced contract",
			OpportunityStatus:  "healthy",
		}
		return driftResult(event), nil
	}

	required := obs.RequiredMissedWindows
	if required == 0 {
		required = observationUint(obs.Rule.RecurringSupport, "windows_floor")
	}
	if required == 0 {
		required = 3
	}
	if obs.OpportunityObserved && !obs.ExpectedObserved && obs.MissedWindows >= required {
		event := DriftEvent{
			ContractHash:      obs.ContractHash,
			RuleID:            obs.Rule.RuleID,
			Kind:              DriftKindNegative,
			Mode:              effectiveMode(obs.Mode),
			MissedWindows:     obs.MissedWindows,
			OpportunityStatus: "healthy",
		}
		return driftResult(event), nil
	}
	return DriftResult{}, nil
}

func driftResult(event DriftEvent) DriftResult {
	signal := SignalForDrift(event)
	return DriftResult{
		Drift:             &event,
		AdaptiveSignal:    signal,
		ShouldAutoDemote:  false,
		ShouldEmitReceipt: true,
	}
}

func observationUint(m map[string]any, key string) uint64 {
	if len(m) == 0 {
		return 0
	}
	switch value := m[key].(type) {
	case uint64:
		return value
	case uint:
		return uint64(value)
	case int:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case int64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case float64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case string:
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

func effectiveMode(mode Mode) Mode {
	if mode == "" {
		return ModeLive
	}
	return mode
}

// SignalForDrift returns the live adaptive signal implied by a drift event.
func SignalForDrift(event DriftEvent) *session.SignalType {
	if event.Kind == DriftKindPositive && effectiveMode(event.Mode) == ModeLive && event.Action == config.ActionBlock {
		sig := session.SignalBlock
		return &sig
	}
	return nil
}

// ContractDriftPayload converts a DriftEvent into the typed receipt payload.
func ContractDriftPayload(event DriftEvent) contractreceipt.PayloadContractDriftStruct {
	return contractreceipt.PayloadContractDriftStruct{
		ContractHash:       event.ContractHash,
		RuleID:             event.RuleID,
		DriftKind:          event.Kind,
		ObservationSummary: event.ObservationSummary,
		MissedWindows:      event.MissedWindows,
		OpportunityStatus:  event.OpportunityStatus,
	}
}

// OpportunityMissingPayload converts an OpportunityMissing event into the typed
// receipt payload.
func OpportunityMissingPayload(event OpportunityMissing) contractreceipt.PayloadOpportunityMissingStruct {
	return contractreceipt.PayloadOpportunityMissingStruct{
		ContractHash:              event.ContractHash,
		RuleID:                    event.RuleID,
		ParentContext:             event.ParentContext,
		HistoricalOpportunityRate: event.HistoricalOpportunityRate,
		CurrentOpportunityRate:    event.CurrentOpportunityRate,
		Window:                    event.Window,
	}
}
