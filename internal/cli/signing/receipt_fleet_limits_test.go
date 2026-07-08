// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidence"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

const fleetLimitL1NoReplay = "L1 does not replay raw audit-batch payloads during offline verification."

// fleetReportStatementWithLimits builds a valid L1 fleet-report statement at the
// given verification level, carrying the supplied predicate limits. It mirrors
// the canonical fixture in writeFleetReportFixtureSigned but lets the A3 test
// exercise the Limits output and a non-L1 rejection without mutating the shared
// helper other tests assert against.
func fleetReportStatementWithLimits(level string, limits []string) fleetreceipt.Statement {
	return fleetreceipt.Statement{
		Type: fleetreceipt.StatementType,
		Subject: []fleetreceipt.Subject{{
			Name:   "conductor-audit-batch:pipelab/dogfood/pl-1/audit-1",
			Digest: fleetreceipt.Digest{SHA256: testHexSHA256("envelope")},
		}},
		PredicateType: fleetreceipt.PredicateType,
		Predicate: fleetreceipt.Predicate{
			SchemaVersion:     1,
			ReportID:          "01934e1c-cd60-7abc-823a-d6f5e6f7a8b9",
			GeneratedAt:       "2026-06-13T12:00:00Z",
			OrgID:             "pipelab",
			FleetID:           "dogfood",
			ReportWindow:      fleetreceipt.TimeWindow{Start: "2026-06-13T11:00:00Z", End: "2026-06-13T12:00:00Z"},
			VerificationLevel: level,
			Conductor:         fleetreceipt.Conductor{ID: "conductor"},
			Limits:            limits,
			SourceBatches: []fleetreceipt.SourceBatch{{
				OrgID:           "pipelab",
				FleetID:         "dogfood",
				InstanceID:      "pl-1",
				BatchID:         "audit-1",
				SeqStart:        1,
				SeqEnd:          2,
				EventCount:      2,
				PayloadSHA256:   testHexSHA256("payload"),
				PayloadBytes:    512,
				EnvelopeHash:    testHexSHA256("envelope"),
				SegmentTailHash: testHexSHA256("tail"),
				EmittedAt:       "2026-06-13T12:00:00Z",
				ReceivedAt:      "2026-06-13T12:00:00Z",
				SignatureKeyIDs: []string{"audit-key"},
			}},
			Summary: fleetreceipt.Summary{
				TotalActions: 2,
				ByFollower:   map[string]uint64{"pl-1": 2},
				ByVerdict:    map[string]uint64{"allow": 1, "block": 1},
			},
			Completeness: fleetreceipt.Completeness{
				ObservedActions:  2,
				MediatedActions:  2,
				MediatedFraction: "1",
				Basis:            "included_signed_audit_batches",
				Claim:            "fraction of observed fleet action records in included signed audit batches that were mediated by Pipelock",
				NonClaim:         "does not prove no bypass occurred outside Pipelock, outside enrolled followers, or outside the report window",
			},
		},
	}
}

func writeFleetReportStatement(t *testing.T, stmt fleetreceipt.Statement) (ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	env, err := fleetreceipt.SignStatement(stmt, hex.EncodeToString(pub), priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	data, err := fleetreceipt.MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "fleet-receipt.dsse.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return pub, path
}

// A passing L1 fleet report must surface its declared verification limits so an
// operator cannot over-read the PASS. Without printing Limits, a verified L1
// report looks like full replay verification when L1 only checks the signed
// report, anchors, ordering, and arithmetic.
func TestVerifyReceiptCmd_FleetReportPrintsLimits(t *testing.T) {
	t.Parallel()

	stmt := fleetReportStatementWithLimits(fleetreceipt.VerificationLevelL1, []string{
		"L1 verifies the signed report, source-batch anchors, ordering, summary arithmetic, and completeness arithmetic.",
		fleetLimitL1NoReplay,
		string(evidence.LimitMetadataPrivacy),
	})
	pub, path := writeFleetReportStatement(t, stmt)

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--fleet-report", "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "FLEET RECEIPT OK:") {
		t.Fatalf("expected a passing L1 verification, got:\n%s", output)
	}
	if !strings.Contains(output, "Limit:") {
		t.Errorf("verifier output omitted the Limit block:\n%s", output)
	}
	if !strings.Contains(output, fleetLimitL1NoReplay) {
		t.Errorf("verifier output omitted the L1 non-replay limit %q:\n%s", fleetLimitL1NoReplay, output)
	}
	if !strings.Contains(output, string(evidence.LimitMetadataPrivacy)+": Fingerprints/headers/session-id/timestamps/signer-keys") {
		t.Errorf("verifier output did not resolve canonical evidence limit id:\n%s", output)
	}
}

// Adding the Limits output must not weaken level enforcement: a non-L1 report is
// still rejected fail-closed (the print loop only runs after a successful L1
// verification). SignStatement itself rejects a non-L1 level, so an L2 envelope
// is constructed by re-encoding a signed L1 payload at level L2 and reusing the
// signature; the verifier validates the level before the signature, so the cli
// verify path must reject it.
func TestVerifyReceiptCmd_FleetReportL2StillRejected(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	l1 := fleetReportStatementWithLimits(fleetreceipt.VerificationLevelL1, []string{fleetLimitL1NoReplay})
	signed, err := fleetreceipt.SignStatement(l1, hex.EncodeToString(pub), priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	l2 := l1
	l2.Predicate.VerificationLevel = "L2"
	raw, err := json.Marshal(l2)
	if err != nil {
		t.Fatalf("marshal L2 statement: %v", err)
	}
	tamperedEnv := fleetreceipt.Envelope{
		PayloadType: signed.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(raw),
		Signatures:  signed.Signatures,
	}
	data, err := fleetreceipt.MarshalEnvelope(tamperedEnv)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "fleet-l2.dsse.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--fleet-report", "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected non-L1 fleet report to be rejected, got success:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "FLEET RECEIPT OK:") {
		t.Errorf("non-L1 report must not print a passing banner:\n%s", buf.String())
	}
}
