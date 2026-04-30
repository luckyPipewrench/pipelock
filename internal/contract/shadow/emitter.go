// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package shadow aggregates contract shadow-evaluation deltas and emits signed
// EvidenceReceipt v2 shadow_delta records into the recorder chain.
package shadow

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	defaultWindowDuration = time.Minute
	defaultSampleCount    = 3

	evidenceReceiptEntryType = "evidence_receipt"
	recorderSessionID        = "proxy"
	shadowTransport          = "shadow"
	signatureAlgorithm       = "ed25519"
	signaturePrefix          = "ed25519:"
	keyPurposeReceiptSigning = "receipt-signing"
)

var (
	jsonMarshal = json.Marshal
	receiptHash = contractreceipt.ReceiptHash
	newUUIDV7   = uuid.NewV7
)

var (
	// ErrInvalidConfig rejects unusable aggregation or emission settings.
	ErrInvalidConfig = errors.New("shadow: invalid config")
	// ErrInvalidDelta rejects incomplete shadow delta observations.
	ErrInvalidDelta = errors.New("shadow: invalid delta")
)

// Delta is one shadow evaluation comparison before window aggregation.
type Delta struct {
	ContractHash     string
	RuleID           string
	OriginalVerdict  string
	CandidateVerdict string
	ExemplarID       string
	ObservedAt       time.Time
}

// AggregateConfig controls shadow delta windowing and sampling.
type AggregateConfig struct {
	WindowDuration time.Duration
	SampleCount    int
}

// DefaultAggregateConfig returns the standard window and sample settings.
func DefaultAggregateConfig() AggregateConfig {
	return AggregateConfig{
		WindowDuration: defaultWindowDuration,
		SampleCount:    defaultSampleCount,
	}
}

// Validate reports invalid aggregation settings.
func (cfg AggregateConfig) Validate() error {
	if cfg.WindowDuration <= 0 {
		return fmt.Errorf("%w: window_duration=%s", ErrInvalidConfig, cfg.WindowDuration)
	}
	if cfg.SampleCount <= 0 {
		return fmt.Errorf("%w: sample_count=%d", ErrInvalidConfig, cfg.SampleCount)
	}
	return nil
}

// Batch is one deterministic shadow_delta receipt payload before signing.
type Batch struct {
	ContractHash     string
	RuleID           string
	OriginalVerdict  string
	CandidateVerdict string
	WindowStart      time.Time
	WindowEnd        time.Time
	LosslessCount    uint64
	ExemplarIDs      []string
}

// Aggregate groups deltas by contract, rule, verdict pair, and time window.
func Aggregate(deltas []Delta, cfg AggregateConfig) ([]Batch, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	input := append([]Delta(nil), deltas...)
	sort.SliceStable(input, func(i, j int) bool {
		if !input[i].ObservedAt.Equal(input[j].ObservedAt) {
			return input[i].ObservedAt.Before(input[j].ObservedAt)
		}
		if input[i].ContractHash != input[j].ContractHash {
			return input[i].ContractHash < input[j].ContractHash
		}
		if input[i].RuleID != input[j].RuleID {
			return input[i].RuleID < input[j].RuleID
		}
		return input[i].ExemplarID < input[j].ExemplarID
	})

	batches := map[batchKey]*Batch{}
	for _, delta := range input {
		if err := validateDelta(delta); err != nil {
			return nil, err
		}
		start := delta.ObservedAt.UTC().Truncate(cfg.WindowDuration)
		key := batchKey{
			contractHash:     delta.ContractHash,
			ruleID:           delta.RuleID,
			originalVerdict:  delta.OriginalVerdict,
			candidateVerdict: delta.CandidateVerdict,
			windowStart:      start,
		}
		batch := batches[key]
		if batch == nil {
			batch = &Batch{
				ContractHash:     delta.ContractHash,
				RuleID:           delta.RuleID,
				OriginalVerdict:  delta.OriginalVerdict,
				CandidateVerdict: delta.CandidateVerdict,
				WindowStart:      start,
				WindowEnd:        start.Add(cfg.WindowDuration),
			}
			batches[key] = batch
		}
		batch.LosslessCount++
		if delta.ExemplarID != "" && len(batch.ExemplarIDs) < cfg.SampleCount {
			batch.ExemplarIDs = append(batch.ExemplarIDs, delta.ExemplarID)
		}
	}

	out := make([]Batch, 0, len(batches))
	for _, batch := range batches {
		out = append(out, *batch)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].WindowStart.Equal(out[j].WindowStart) {
			return out[i].WindowStart.Before(out[j].WindowStart)
		}
		if out[i].ContractHash != out[j].ContractHash {
			return out[i].ContractHash < out[j].ContractHash
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].OriginalVerdict != out[j].OriginalVerdict {
			return out[i].OriginalVerdict < out[j].OriginalVerdict
		}
		return out[i].CandidateVerdict < out[j].CandidateVerdict
	})
	return out, nil
}

type batchKey struct {
	contractHash     string
	ruleID           string
	originalVerdict  string
	candidateVerdict string
	windowStart      time.Time
}

func validateDelta(delta Delta) error {
	switch {
	case delta.ContractHash == "":
		return fmt.Errorf("%w: contract_hash", ErrInvalidDelta)
	case delta.RuleID == "":
		return fmt.Errorf("%w: rule_id", ErrInvalidDelta)
	case delta.OriginalVerdict == "":
		return fmt.Errorf("%w: original_verdict", ErrInvalidDelta)
	case delta.CandidateVerdict == "":
		return fmt.Errorf("%w: candidate_verdict", ErrInvalidDelta)
	case delta.ObservedAt.IsZero():
		return fmt.Errorf("%w: observed_at", ErrInvalidDelta)
	default:
		return nil
	}
}

// Signer signs EvidenceReceipt v2 preimages.
type Signer interface {
	KeyID() string
	Sign([]byte) ([]byte, error)
}

// Recorder is the recorder subset used by Emitter.
type Recorder interface {
	Record(recorder.Entry) error
}

// EmitterConfig configures signed shadow_delta emission.
type EmitterConfig struct {
	Recorder           Recorder
	Signer             Signer
	SessionID          string
	Principal          string
	Actor              string
	ActiveManifestHash string
	SelectorID         string
	ContractGeneration uint64
	Clock              func() time.Time
	EventID            func() (string, error)
}

// Emitter signs aggregated shadow_delta receipts and records them.
type Emitter struct {
	recorder           Recorder
	signer             Signer
	sessionID          string
	principal          string
	actor              string
	activeManifestHash string
	selectorID         string
	contractGeneration uint64
	clock              func() time.Time
	eventID            func() (string, error)

	mu            sync.Mutex
	chainSeq      uint64
	chainPrevHash string
}

// NewEmitter returns nil when recorder or signer is missing, matching the
// legacy receipt emitter's no-op behavior.
func NewEmitter(cfg EmitterConfig) *Emitter {
	if cfg.Recorder == nil || cfg.Signer == nil {
		return nil
	}
	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = recorderSessionID
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	eventID := cfg.EventID
	if eventID == nil {
		eventID = newEventID
	}
	return &Emitter{
		recorder:           cfg.Recorder,
		signer:             cfg.Signer,
		sessionID:          sessionID,
		principal:          cfg.Principal,
		actor:              cfg.Actor,
		activeManifestHash: cfg.ActiveManifestHash,
		selectorID:         cfg.SelectorID,
		contractGeneration: cfg.ContractGeneration,
		clock:              clock,
		eventID:            eventID,
		chainPrevHash:      recorder.GenesisHash,
	}
}

// EmitBatch signs and records one aggregated shadow_delta receipt.
func (e *Emitter) EmitBatch(batch Batch) error {
	if e == nil {
		return nil
	}
	if err := validateBatch(batch); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	payload := contractreceipt.PayloadShadowDeltaStruct{
		ContractHash:     batch.ContractHash,
		RuleID:           batch.RuleID,
		OriginalVerdict:  batch.OriginalVerdict,
		CandidateVerdict: batch.CandidateVerdict,
		Aggregation: contractreceipt.ShadowDeltaAggregation{
			WindowStart:      batch.WindowStart.UTC().Format(time.RFC3339Nano),
			WindowEnd:        batch.WindowEnd.UTC().Format(time.RFC3339Nano),
			LosslessCount:    batch.LosslessCount,
			DeltaSampleCount: uint64(len(batch.ExemplarIDs)),
			ExemplarIDs:      append([]string(nil), batch.ExemplarIDs...),
		},
	}
	payloadJSON, err := jsonMarshal(payload)
	if err != nil {
		return fmt.Errorf("marshal shadow delta payload: %w", err)
	}
	eventID, err := e.eventID()
	if err != nil {
		return fmt.Errorf("generate shadow delta event id: %w", err)
	}

	rcpt := contractreceipt.EvidenceReceipt{
		RecordType:         contractreceipt.RecordTypeEvidenceV2,
		ReceiptVersion:     2,
		PayloadKind:        contractreceipt.PayloadShadowDelta,
		EventID:            eventID,
		Timestamp:          e.clock().UTC(),
		Principal:          e.principal,
		Actor:              e.actor,
		ChainSeq:           e.chainSeq,
		ChainPrevHash:      e.chainPrevHash,
		ActiveManifestHash: e.activeManifestHash,
		ContractHash:       batch.ContractHash,
		SelectorID:         e.selectorID,
		ContractGeneration: e.contractGeneration,
		Payload:            payloadJSON,
	}
	preimage, err := rcpt.SignablePreimage()
	if err != nil {
		return fmt.Errorf("build shadow delta preimage: %w", err)
	}
	signature, err := e.signer.Sign(preimage)
	if err != nil {
		return fmt.Errorf("sign shadow delta receipt: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("sign shadow delta receipt: signature size=%d", len(signature))
	}
	rcpt.Signature = contractreceipt.SignatureProof{
		SignerKeyID: e.signer.KeyID(),
		KeyPurpose:  keyPurposeReceiptSigning,
		Algorithm:   signatureAlgorithm,
		Signature:   signaturePrefix + hex.EncodeToString(signature),
	}
	if err := rcpt.Validate(); err != nil {
		return fmt.Errorf("validate shadow delta receipt: %w", err)
	}

	receiptHash, err := receiptHash(rcpt)
	if err != nil {
		return fmt.Errorf("hash shadow delta receipt: %w", err)
	}
	receiptJSON, err := jsonMarshal(rcpt)
	if err != nil {
		return fmt.Errorf("marshal shadow delta receipt: %w", err)
	}

	if err := e.recorder.Record(recorder.Entry{
		SessionID: e.sessionID,
		Type:      evidenceReceiptEntryType,
		EventKind: string(contractreceipt.PayloadShadowDelta),
		Transport: shadowTransport,
		Summary: fmt.Sprintf("shadow_delta: %s %s->%s x%d",
			batch.RuleID, batch.OriginalVerdict, batch.CandidateVerdict, batch.LosslessCount),
		Detail: json.RawMessage(receiptJSON),
	}); err != nil {
		return fmt.Errorf("record shadow delta receipt: %w", err)
	}
	e.chainPrevHash = receiptHash
	e.chainSeq++
	return nil
}

func validateBatch(batch Batch) error {
	if err := validateDelta(Delta{
		ContractHash:     batch.ContractHash,
		RuleID:           batch.RuleID,
		OriginalVerdict:  batch.OriginalVerdict,
		CandidateVerdict: batch.CandidateVerdict,
		ObservedAt:       batch.WindowStart,
	}); err != nil {
		return err
	}
	if batch.WindowEnd.IsZero() || !batch.WindowEnd.After(batch.WindowStart) {
		return fmt.Errorf("%w: window_end", ErrInvalidDelta)
	}
	if batch.LosslessCount == 0 {
		return fmt.Errorf("%w: lossless_count", ErrInvalidDelta)
	}
	if uint64(len(batch.ExemplarIDs)) > batch.LosslessCount {
		return fmt.Errorf("%w: exemplar_ids", ErrInvalidDelta)
	}
	for i, id := range batch.ExemplarIDs {
		if id == "" {
			return fmt.Errorf("%w: exemplar_ids[%d]", ErrInvalidDelta, i)
		}
	}
	return nil
}

func newEventID() (string, error) {
	id, err := newUUIDV7()
	if err != nil {
		return "", fmt.Errorf("uuid v7: %w", err)
	}
	return id.String(), nil
}
