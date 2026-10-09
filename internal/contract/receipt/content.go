// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	Kind: EvidenceReceiptContentKind,
	Fields: map[string]receiptcontent.Class{
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
		"active_manifest_hash": receiptcontent.Content,
		"contract_hash":        receiptcontent.Content,
		"policy_hash":          receiptcontent.Content,
		"selector_id":          receiptcontent.Content,
		"contract_generation":  receiptcontent.Content,
		"payload":              receiptcontent.Content,
	},
	Outer: evidenceReceiptOuter,
})

// evidenceReceiptOuter derives the recorder mirror fields of a v2 receipt
// from its exact detail, reading only content values.
func evidenceReceiptOuter(detail []byte) (receiptcontent.Outer, error) {
	var d struct {
		PayloadKind PayloadKind `json:"payload_kind"`
		Payload     struct {
			Transport     string `json:"transport"`
			ActionType    string `json:"action_type"`
			Verdict       string `json:"verdict"`
			WinningSource string `json:"winning_source"`
		} `json:"payload"`
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

// RecordEvidence writes one signed v2 receipt. On a content-binding recorder
// the receipt's content is validated with the recorder's own detector and the
// result is bound to rcptJSON, so generated fields are never scanned; content
// is validate-or-fail and is never redacted after signing. The entry's mirror
// fields are derived from rcptJSON. A *receiptcontent.RejectionError is
// deterministic for its input: callers must not treat it as a storage failure.
func RecordEvidence(ctx context.Context, rec EntryRecorder, session string, rcptJSON []byte, durable bool) error {
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
	rep, cs, err := cr.ScanReceiptContent(ctx, evidenceReceiptProducer, rcptJSON)
	if err == nil && cs == nil {
		err = rep.Err()
	}
	if err != nil {
		return err
	}
	scan, err := cr.BindReceiptContent(cs, evidenceReceiptProducer, rcptJSON)
	if err != nil {
		return err
	}
	if durable {
		return cr.RecordDurableWithReceiptScan(entry, &scan)
	}
	return cr.RecordWithReceiptScan(entry, &scan)
}
