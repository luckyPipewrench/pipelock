// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"encoding/json"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

// DecisionRecordContentKind is the content-boundary kind of a signed
// DecisionRecord entry.
const DecisionRecordContentKind = "pipelock.decision_record.v1"

// decisionRecordProducer excludes only the record's own signature, version
// and timestamp. Everything else, including the matched text, is content:
// a signed record is validate-or-fail and is never redacted after signing.
var decisionRecordProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind: DecisionRecordContentKind,
	Fields: map[string]receiptcontent.Class{
		"version":                   receiptcontent.Generated,
		"timestamp":                 receiptcontent.Generated,
		"signature":                 receiptcontent.Generated,
		"type":                      receiptcontent.Content,
		"session_id":                receiptcontent.RunSession,
		"manifest_ref":              receiptcontent.Content,
		"verdict":                   receiptcontent.Content,
		"scanner_result":            receiptcontent.Content,
		"scanner_result.layer":      receiptcontent.Content,
		"scanner_result.pattern":    receiptcontent.Content,
		"scanner_result.match_text": receiptcontent.Content,
		"scanner_result.confidence": receiptcontent.Content,
		"policy_rule":               receiptcontent.Content,
		"policy_rule.source":        receiptcontent.Content,
		"policy_rule.section":       receiptcontent.Content,
		"policy_rule.action":        receiptcontent.Content,
		"request_context":           receiptcontent.Content,
		"request_context.transport": receiptcontent.Content,
		"request_context.tool_name": receiptcontent.Content,
		"request_context.direction": receiptcontent.Content,
	},
	Outer: decisionRecordOuter,
})

// decisionRecordOuter derives a decision entry's mirror fields from its
// exact detail, reading only content values.
func decisionRecordOuter(detail []byte) (receiptcontent.Outer, error) {
	var dr DecisionRecord
	if err := json.Unmarshal(detail, &dr); err != nil {
		return receiptcontent.Outer{}, fmt.Errorf("decode decision record mirror fields: %w", err)
	}
	layer := dr.ScannerResult.Layer
	if layer == "" {
		layer = "unknown"
	}
	summary := fmt.Sprintf("%s: %s", dr.Verdict, layer)
	if dr.ScannerResult.Pattern != "" {
		summary = fmt.Sprintf("%s (%s)", summary, dr.ScannerResult.Pattern)
	}
	return receiptcontent.Outer{
		Type:      decisionEntryType,
		EventKind: eventKindProxyDecision,
		Transport: dr.RequestContext.Transport,
		Summary:   summary,
	}, nil
}

// TranscriptRootEntryType is the recorder entry type of a transcript root.
// A root seals a chain, so it is validate-or-fail and never redacted.
const TranscriptRootEntryType = "transcript_root"

// GroupGateContentKind is the content-boundary kind of a receipt group
// opening gate entry.
const GroupGateContentKind = "pipelock.receipt_group_gate.v1"

// GroupGateFields classifies a receipt group gate detail. Every member is
// produced by the group opener from its own manifest, key and generated group
// identity; only the shard session embeds the operator's session base. Its
// proven run suffix is excluded and the base is an identity: validated, never
// redacted.
func GroupGateFields() map[string]receiptcontent.Class {
	return map[string]receiptcontent.Class{
		"group_id":                      receiptcontent.Generated,
		"shard_index":                   receiptcontent.Generated,
		"session_id":                    receiptcontent.RunSession,
		"open_manifest_sha256":          receiptcontent.Generated,
		"signer_key":                    receiptcontent.Generated,
		"previous_group_id":             receiptcontent.Generated,
		"previous_open_manifest_sha256": receiptcontent.Generated,
	}
}

// GroupGateOuter derives a group gate entry's fixed mirror fields.
func GroupGateOuter([]byte) (receiptcontent.Outer, error) {
	return receiptcontent.Outer{Type: GroupGateEntryType, EventKind: GroupGateEntryType, Summary: "receipt group opening gate"}, nil
}

// isBoundEntryType reports whether an entry type carries signed or
// lifecycle evidence. Such details are never redacted by the generic pass:
// they are validated through the content boundary and either bound to their
// exact bytes or refused.
func isBoundEntryType(t string) bool {
	switch t {
	case recorderTypeReceipt, recorderTypeEvidenceReceipt, GroupGateEntryType, decisionEntryType, TranscriptRootEntryType:
		return true
	}
	return false
}
