// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// EvidenceReceiptContentKind is the content-boundary kind of a signed v2
// evidence receipt as written to the recorder.
const EvidenceReceiptContentKind = "pipelock.evidence_receipt.v2"

// evidenceReceiptProducer is the only capability that may exclude a v2
// envelope's generated fields. Payload members are all content: every
// registered payload kind is scanned, and an unknown member is scanned too.
var evidenceReceiptProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind:        EvidenceReceiptContentKind,
	Fields:      evidenceReceiptFields(),
	Outer:       evidenceReceiptOuter,
	FixedValues: evidenceReceiptFixedValues,
})

// evidenceReceiptFixedValues are the producer constants of a v2 receipt:
// each may stand as the one fixed piece of a fragment combination.
var evidenceReceiptFixedValues = map[string][]string{
	"payload_kind":             {string(PayloadProxyDecision), string(PayloadProxyDecisionWithSpans), string(PayloadSecretEgressDecisionV1), string(PayloadContractRatified), string(PayloadContractPromoteIntent), string(PayloadContractPromoteCommitted), string(PayloadContractRollbackAuthorized), string(PayloadContractRollbackCommitted), string(PayloadContractDemoted), string(PayloadContractExpired), string(PayloadContractDrift), string(PayloadShadowDelta), string(PayloadOpportunityMissing), string(PayloadKeyRotation), string(PayloadContractRedactionRequest), string(PayloadDeferOpened), string(PayloadDeferResolved)},
	"payload.transport":        {"proxy", "fetch", "forward", "connect", "intercept", "websocket", "mcp_http", "mcp_stdio", "reverse"},
	"payload.action_type":      {"read", "write", "http_request", "mcp_tool_call", "websocket_frame"},
	"payload.verdict":          {"allow", "block", "warn", "ask", "strip", "forward", "defer"},
	"payload.live_verdict":     {"allow", "block", "warn", "ask", "strip", "forward", "defer"},
	"payload.winning_source":   {"scanner", "kill_switch", "contract", "policy"},
	"payload.policy_sources[]": {"scanner", "kill_switch", "contract", "policy"},
}

func evidenceReceiptFields() map[string]receiptcontent.Class {
	f := map[string]receiptcontent.Class{
		"record_type":          receiptcontent.Generated,
		"receipt_version":      receiptcontent.Generated,
		"payload_kind":         receiptcontent.Content,
		"canonicalization":     receiptcontent.Generated,
		"crit":                 receiptcontent.Generated,
		"event_id":             receiptcontent.ProvenID,
		"timestamp":            receiptcontent.Generated,
		"principal":            receiptcontent.Content,
		"actor":                receiptcontent.Content,
		"delegation_chain":     receiptcontent.Content,
		"delegation_chain[]":   receiptcontent.Content,
		"signature":            receiptcontent.Generated,
		"chain_seq":            receiptcontent.Generated,
		"chain_prev_hash":      receiptcontent.Generated,
		"active_manifest_hash": receiptcontent.ComputedDigest,
		"contract_hash":        receiptcontent.ComputedDigest,
		"policy_hash":          receiptcontent.ComputedDigest,
		"selector_id":          receiptcontent.Content,
		"contract_generation":  receiptcontent.Content,
		"payload":              receiptcontent.Content,
	}
	// Declared payload members have fixed names; unknown members remain key
	// atoms. Payload values remain content.
	for _, name := range []string{
		"action_type", "target", "transport", "verdict", "live_verdict", "policy_sources", "winning_source",
	} {
		f["payload."+name] = receiptcontent.Content
	}
	// The rule ID carries Pipelock's formatted decision text (an outcome line
	// interpolates status, size and reason). It is scanned alone, in the
	// structured projection and in the joined values, but does not multiply
	// the fragment search.
	f["payload.rule_id"] = receiptcontent.Standalone
	f["payload.policy_sources[]"] = receiptcontent.Content
	return f
}

// evidenceReceiptOuter derives the recorder mirror fields of a v2 receipt
// from its exact detail, reading only content values.
func evidenceReceiptOuter(detail []byte) (receiptcontent.Outer, error) {
	// This is a partial content projection: producer representations and unknown
	// members remain content. Validate the whole document before typed selection.
	var fields map[string]json.RawMessage
	if err := contract.DecodeStrictJSON(detail, &fields); err != nil {
		return receiptcontent.Outer{}, fmt.Errorf("decode evidence receipt mirror fields: %w", err)
	}
	var d struct {
		PayloadKind PayloadKind `json:"payload_kind"`
		Payload     struct {
			Transport     string `json:"transport"`
			ActionType    string `json:"action_type"`
			Verdict       string `json:"verdict"`
			WinningSource string `json:"winning_source"`
		} `json:"payload"`
	}
	if err := jsonscan.RejectStructAliases(detail, reflect.TypeOf(d)); err != nil {
		return receiptcontent.Outer{}, fmt.Errorf("decode evidence receipt mirror fields: %w", err)
	}
	if err := json.Unmarshal(detail, &d); err != nil {
		return receiptcontent.Outer{}, fmt.Errorf("decode evidence receipt mirror fields: %w", err)
	}
	p := d.Payload
	summary := string(d.PayloadKind)
	if strings.HasPrefix(string(d.PayloadKind), string(PayloadProxyDecision)) {
		summary = fmt.Sprintf("%s: %s %s via %s", d.PayloadKind, p.ActionType, p.Verdict, p.WinningSource)
	}
	return receiptcontent.Outer{
		Type:      EvidenceEntryType,
		EventKind: string(d.PayloadKind),
		Transport: p.Transport,
		Summary:   summary,
	}, nil
}

// contentRecorder is the recorder surface that binds receipt content to the
// exact bytes written. *recorder.Recorder implements it.
type contentRecorder interface {
	ScanReceiptContent(context.Context, *receiptcontent.Producer, []byte) (receiptcontent.Report, *recorder.ContentScan, error)
	BindReceiptContent(*recorder.ContentScan, *receiptcontent.Producer, []byte) (recorder.ReceiptScan, error)
	RecordWithReceiptScan(recorder.Entry, *recorder.ReceiptScan) error
	RecordDurableWithReceiptScan(recorder.Entry, *recorder.ReceiptScan) error
}

// EntryRecorder is the minimal recorder an evidence emitter writes through.
type EntryRecorder interface {
	Record(recorder.Entry) error
}

// ErrNoDurableRecorder means a durable write was requested from a recorder
// that cannot confirm durability.
var ErrNoDurableRecorder = errors.New("evidence recorder does not support durable writes")

// ErrNoStamper means a v2 receipt was recorded without its producer's Stamper.
var ErrNoStamper = errors.New("evidence receipt recorded without a producer stamper")

// Stamper is one v2 receipt producer's capability to record the receipts it
// built, stamped and signed itself. Only a Stamper's receipts are projected
// with the producer schema, under which the envelope fields the producer
// generated (event ID, timestamp, chain position, signature) are excluded
// from content. A Stamper records a receipt value, never bytes, so serialized
// receipt bytes have no path to that classification. NewStamper returns it
// once per producer, which keeps it private to the producing package.
type Stamper struct {
	name string
	// producer is the schema capability, narrowed by WithRetained; nil means
	// the registered v2 producer.
	producer *receiptcontent.Producer
}

var (
	stampersMu sync.Mutex
	stampers   = map[string]struct{}{}
)

// NewStamper returns the recording capability for producer. It panics on an
// empty or duplicate name; both are programming errors caught at
// initialization.
func NewStamper(producer string) *Stamper {
	if producer == "" {
		panic("contract receipt: stamper producer name is required")
	}
	stampersMu.Lock()
	defer stampersMu.Unlock()
	if _, dup := stampers[producer]; dup {
		panic(fmt.Sprintf("contract receipt: stamper %q created twice", producer))
	}
	stampers[producer] = struct{}{}
	return &Stamper{name: producer}
}

// WithRetained derives a stamper whose producer treats the emitter's own
// configured principal and actor as fixed values, as the v1 emitter does.
// Those values are still scanned in every view and can still complete a
// split as the one fixed piece of a combination; they no longer combine with
// each other. Pass only values the emitter stamps from its configuration,
// never per-request text. Empty values are ignored.
func (s *Stamper) WithRetained(principal, actor string) *Stamper {
	if s == nil {
		return nil
	}
	values := map[string][]string{}
	if principal != "" {
		values["principal"] = []string{principal}
	}
	if actor != "" {
		values["actor"] = []string{actor}
	}
	return &Stamper{name: s.name, producer: s.contentProducer().WithFixedValues(values)}
}

func (s *Stamper) contentProducer() *receiptcontent.Producer {
	if s.producer != nil {
		return s.producer
	}
	return evidenceReceiptProducer
}

// Record writes one signed v2 receipt that this stamper's producer built.
// On a content-binding recorder the receipt's content is validated with the
// recorder's own detector and the result is bound to the exact serialized
// bytes, so generated fields are never scanned; content is validate-or-fail
// and is never redacted after signing. The entry's mirror fields are derived
// from those bytes. A *receiptcontent.RejectionError is deterministic for its
// input: callers must not treat it as a storage failure.
func (s *Stamper) Record(ctx context.Context, rec EntryRecorder, session string, rcpt EvidenceReceipt, durable bool) error {
	return s.RecordPrescanned(ctx, rec, session, rcpt, durable, nil)
}

// Prescan is a content scan of an evidence receipt taken before its generated
// fields (chain position, timestamp, signature) are final. Content does not
// depend on them, so a producer can scan outside its chain lock and bind the
// result to the final bytes under it.
type Prescan struct{ cs *recorder.ContentScan }

// Prescan scans rcpt's content. A rejection is returned as an error, exactly
// as Record would return it. A recorder that does not scan content needs no
// prescan, and gets an empty one.
func (s *Stamper) Prescan(ctx context.Context, rec EntryRecorder, rcpt EvidenceReceipt) (*Prescan, error) {
	if s == nil || s.name == "" {
		return nil, ErrNoStamper
	}
	cr, ok := rec.(contentRecorder)
	if !ok {
		return &Prescan{}, nil
	}
	rcptJSON, err := json.Marshal(rcpt)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence receipt: %w", err)
	}
	rep, cs, err := cr.ScanReceiptContent(ctx, s.contentProducer(), rcptJSON)
	if err == nil && cs == nil {
		err = rep.Err()
	}
	if err != nil {
		return nil, err
	}
	return &Prescan{cs: cs}, nil
}

// RecordPrescanned records rcpt using a scan from Prescan. The recorder binds
// the scan only when the final bytes project to the scanned content; if they
// do not, the final bytes are scanned again here, so a stale scan is never
// trusted. A nil prescan scans in place, as Record does.
func (s *Stamper) RecordPrescanned(ctx context.Context, rec EntryRecorder, session string, rcpt EvidenceReceipt, durable bool, pre *Prescan) error {
	if s == nil || s.name == "" {
		return ErrNoStamper
	}
	rcptJSON, err := json.Marshal(rcpt)
	if err != nil {
		return fmt.Errorf("marshal evidence receipt: %w", err)
	}
	var cs *recorder.ContentScan
	if pre != nil {
		cs = pre.cs
	}
	return recordEvidenceAs(ctx, s.contentProducer(), rec, evidenceWrite{session: session, rcptJSON: rcptJSON, durable: durable, pre: cs})
}

func recordEvidence(ctx context.Context, rec EntryRecorder, session string, rcptJSON []byte, durable bool) error {
	return recordEvidenceAs(ctx, evidenceReceiptProducer, rec, evidenceWrite{session: session, rcptJSON: rcptJSON, durable: durable})
}

// evidenceWrite is one serialized v2 receipt and how to persist it.
type evidenceWrite struct {
	session  string
	rcptJSON []byte
	durable  bool
	pre      *recorder.ContentScan
}

func recordEvidenceAs(ctx context.Context, producer *receiptcontent.Producer, rec EntryRecorder, w evidenceWrite) error {
	session, rcptJSON, durable, pre := w.session, w.rcptJSON, w.durable, w.pre
	outer, err := evidenceReceiptOuter(rcptJSON)
	if err != nil {
		return err
	}
	entry := recorder.Entry{
		SessionID: session,
		Type:      outer.Type,
		EventKind: outer.EventKind,
		Transport: outer.Transport,
		Summary:   outer.Summary,
		Detail:    json.RawMessage(rcptJSON),
	}
	cr, ok := rec.(contentRecorder)
	if !ok {
		if !durable {
			return rec.Record(entry)
		}
		dr, ok := rec.(interface{ RecordDurable(recorder.Entry) error })
		if !ok {
			return ErrNoDurableRecorder
		}
		return dr.RecordDurable(entry)
	}
	scan, err := bindEvidenceContent(ctx, cr, producer, rcptJSON, pre)
	if err != nil {
		return err
	}
	if durable {
		return cr.RecordDurableWithReceiptScan(entry, &scan)
	}
	return cr.RecordWithReceiptScan(entry, &scan)
}

// bindEvidenceContent binds pre to rcptJSON, or scans rcptJSON when there is
// no prescan or its content no longer matches the final bytes.
func bindEvidenceContent(ctx context.Context, cr contentRecorder, producer *receiptcontent.Producer, rcptJSON []byte, pre *recorder.ContentScan) (recorder.ReceiptScan, error) {
	if pre != nil {
		scan, err := cr.BindReceiptContent(pre, producer, rcptJSON)
		if !errors.Is(err, recorder.ErrContentChanged) {
			return scan, err
		}
	}
	rep, cs, err := cr.ScanReceiptContent(ctx, producer, rcptJSON)
	if err == nil && cs == nil {
		err = rep.Err()
	}
	if err != nil {
		return recorder.ReceiptScan{}, err
	}
	return cr.BindReceiptContent(cs, producer, rcptJSON)
}
