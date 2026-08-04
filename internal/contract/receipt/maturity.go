// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

// PayloadMaturity describes whether a registered EvidenceReceipt v2 payload
// kind has a production producer.
type PayloadMaturity string

const (
	// PayloadMaturityLive means a non-test production path emits this kind.
	PayloadMaturityLive PayloadMaturity = "live"
	// PayloadMaturityFixtureOnly means schema and verifier support exists, but
	// no production path emits this kind.
	PayloadMaturityFixtureOnly PayloadMaturity = "fixture_only"
	// PayloadMaturityReserved means the registry knows this kind but rejects it
	// with ErrPayloadKindNotImplemented.
	PayloadMaturityReserved PayloadMaturity = "reserved"
)

type payloadProducerReference struct {
	packagePath string
	function    string
}

type payloadMaturityDeclaration struct {
	maturity PayloadMaturity
	producer *payloadProducerReference
}

// payloadMaturity is the machine-readable capability declaration for every
// registered EvidenceReceipt v2 payload kind. Live entries name the concrete
// non-test producer function that the maturity test statically traces to the
// corresponding PayloadKind reference.
var payloadMaturity = map[PayloadKind]payloadMaturityDeclaration{
	PayloadProxyDecision: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/contract/proxydecision", function: "(*Emitter).Emit",
	}},
	PayloadProxyDecisionWithSpans: {maturity: PayloadMaturityFixtureOnly},
	PayloadContractRatified: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/cli/learn", function: "runRatify",
	}},
	PayloadContractPromoteIntent: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/cli/learn", function: "runPromote",
	}},
	PayloadContractPromoteCommitted: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/cli/learn", function: "runPromote",
	}},
	PayloadContractRollbackAuthorized: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/cli/learn", function: "runRollback",
	}},
	PayloadContractRollbackCommitted: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/cli/learn", function: "runRollback",
	}},
	PayloadContractDemoted: {maturity: PayloadMaturityFixtureOnly},
	PayloadContractExpired: {maturity: PayloadMaturityFixtureOnly},
	PayloadContractDrift:   {maturity: PayloadMaturityFixtureOnly},
	PayloadShadowDelta: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/contract/shadow", function: "(*Emitter).EmitBatch",
	}},
	PayloadOpportunityMissing: {maturity: PayloadMaturityFixtureOnly},
	PayloadKeyRotation:        {maturity: PayloadMaturityFixtureOnly},
	PayloadContractRedactionRequest: {maturity: PayloadMaturityLive, producer: &payloadProducerReference{
		packagePath: "github.com/luckyPipewrench/pipelock/internal/cli/learn", function: "runForget",
	}},
	PayloadDeferOpened:   {maturity: PayloadMaturityReserved},
	PayloadDeferResolved: {maturity: PayloadMaturityReserved},
}
