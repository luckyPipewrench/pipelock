// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
)

type receiptOptions struct {
	signerKey string
	evidenceBindingOptions
	jsonOutput bool
}

func newReceiptCmd() *cobra.Command {
	var opts receiptOptions

	cmd := &cobra.Command{
		Use:   "receipt PATH",
		Short: "Verify a single Pipelock receipt",
		Long: `Verifies a single Pipelock receipt written as JSON.

Legacy ActionReceipt v1 files verify against their embedded signer_key unless
--key is supplied. EvidenceReceipt v2 files do not embed a public key, so
without --key the verifier checks structure and canonical hashability only;
with --key it verifies the Ed25519 signature against the pinned key.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReceipt(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.signerKey, "key", "", "expected signer public key (hex, public-key text, or file path)")
	cmd.Flags().StringVar(&opts.expectSignerKeyID, "expect-signer-id", "", "EvidenceReceipt v2: require signer_key_id")
	cmd.Flags().StringVar(&opts.expectContractHash, "expect-contract", "", "EvidenceReceipt v2: require contract_hash")
	cmd.Flags().StringVar(&opts.expectManifestHash, "expect-manifest", "", "EvidenceReceipt v2: require active_manifest_hash")
	cmd.Flags().StringVar(&opts.expectPayloadKind, "expect-payload-kind", "", "EvidenceReceipt v2: require payload_kind")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")

	return cmd
}

type receiptReport struct {
	Path               string `json:"path"`
	RecordType         string `json:"record_type,omitempty"`
	Valid              bool   `json:"valid"`
	SignaturesVerified bool   `json:"signatures_verified"`
	ActionID           string `json:"action_id,omitempty"`
	Verdict            string `json:"verdict,omitempty"`
	Transport          string `json:"transport,omitempty"`
	SignerKey          string `json:"signer_key,omitempty"`
	SignerKeyID        string `json:"signer_key_id,omitempty"`
	PolicyHash         string `json:"policy_hash,omitempty"`
	PayloadKind        string `json:"payload_kind,omitempty"`
	ContractHash       string `json:"contract_hash,omitempty"`
	ActiveManifestHash string `json:"active_manifest_hash,omitempty"`
	ChainSeq           uint64 `json:"chain_seq,omitempty"`
	Error              string `json:"error,omitempty"`
}

func runReceipt(stdout, stderr io.Writer, target string, opts receiptOptions) error {
	keyHex, err := resolveSignerKey(strings.TrimSpace(opts.signerKey))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
	}

	clean := filepath.Clean(target)
	data, err := os.ReadFile(clean)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read receipt: %w", err))
	}

	recordType, detectErr := detectSingleReceiptRecordType(data)
	if detectErr != nil {
		report := receiptReport{Path: clean, Valid: false, Error: detectErr.Error()}
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, detectErr)
	}

	switch recordType {
	case recordTypeEvidenceV2:
		return runEvidenceReceipt(stdout, stderr, clean, data, keyHex, opts)
	case recordTypeActionV1, "":
		if opts.anySet() {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("EvidenceReceipt expectation flags require record_type=%s", recordTypeEvidenceV2))
		}
		return runActionReceipt(stdout, stderr, clean, data, keyHex, opts)
	default:
		report := receiptReport{Path: clean, Valid: false, Error: "unsupported receipt record_type"}
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("unsupported receipt record_type"))
	}
}

func runActionReceipt(stdout, stderr io.Writer, clean string, data []byte, keyHex string, opts receiptOptions) error {
	r, err := actionreceipt.Unmarshal(data)
	if err != nil {
		report := receiptReport{Path: clean, Valid: false, Error: err.Error()}
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("parse receipt: %w", err))
	}

	report := receiptReport{
		Path:       clean,
		RecordType: recordTypeActionV1,
		ActionID:   r.ActionRecord.ActionID,
		Verdict:    r.ActionRecord.Verdict,
		Transport:  r.ActionRecord.Transport,
		SignerKey:  r.SignerKey,
		PolicyHash: r.ActionRecord.PolicyHash,
		ChainSeq:   r.ActionRecord.ChainSeq,
	}

	if err := actionreceipt.VerifyWithKey(r, keyHex); err != nil {
		report.Valid = false
		report.Error = err.Error()
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("verify: %w", err))
	}
	report.Valid = true
	// Provenance only when an out-of-band key is pinned; an empty key
	// verifies against the receipt's embedded signer (self-consistency).
	report.SignaturesVerified = keyHex != ""
	emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
	return nil
}

func runEvidenceReceipt(stdout, stderr io.Writer, clean string, data []byte, keyHex string, opts receiptOptions) error {
	r, err := decodeEvidenceReceipt(data)
	if err != nil {
		report := receiptReport{Path: clean, RecordType: recordTypeEvidenceV2, Valid: false, Error: err.Error()}
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("parse evidence receipt: %w", err))
	}
	report := receiptReport{
		Path:               clean,
		RecordType:         recordTypeEvidenceV2,
		SignerKeyID:        r.Signature.SignerKeyID,
		PayloadKind:        string(r.PayloadKind),
		ContractHash:       r.ContractHash,
		ActiveManifestHash: r.ActiveManifestHash,
		ChainSeq:           r.ChainSeq,
	}
	sigVerified, err := verifyEvidenceReceipt(r, keyHex, opts.evidenceBindingOptions)
	if err != nil {
		report.Valid = false
		report.Error = err.Error()
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("verify evidence receipt: %w", err))
	}
	report.Valid = true
	report.SignaturesVerified = sigVerified
	emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
	return nil
}
