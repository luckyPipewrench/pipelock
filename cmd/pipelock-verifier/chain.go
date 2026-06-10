// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
)

// chainOptions holds resolved CLI flags for the chain subcommand.
type chainOptions struct {
	signerKey string
	sessionID string
	evidenceBindingOptions
	jsonOutput    bool
	asDir         bool
	allowUnpinned bool
}

func newChainCmd() *cobra.Command {
	var opts chainOptions

	cmd := &cobra.Command{
		Use:     "chain PATH",
		Aliases: []string{"evidence"},
		Short:   "Verify a Pipelock receipt chain",
		Long: `Verifies the hash linkage of a Pipelock receipt chain. PATH may be a
single .jsonl evidence file or a session directory when --dir is set.

Legacy ActionReceipt v1 and EvidenceReceipt v2 chains require --key for
trusted provenance. Pass --allow-unpinned for loud structural-only
verification. Self-consistency does not prove provenance.

With --key the verifier requires every receipt to be signed by the named
key.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChain(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.signerKey, "key", "", "expected signer public key (hex, public-key text, or file path)")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside the evidence directory (--dir)")
	cmd.Flags().StringVar(&opts.expectSignerKeyID, "expect-signer-id", "", "EvidenceReceipt v2: require signer_key_id")
	cmd.Flags().StringVar(&opts.expectContractHash, "expect-contract", "", "EvidenceReceipt v2: require contract_hash")
	cmd.Flags().StringVar(&opts.expectManifestHash, "expect-manifest", "", "EvidenceReceipt v2: require active_manifest_hash")
	cmd.Flags().StringVar(&opts.expectPayloadKind, "expect-payload-kind", "", "EvidenceReceipt v2: require payload_kind")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")
	cmd.Flags().BoolVar(&opts.asDir, "dir", false, "treat PATH as a session directory rather than a single file")
	cmd.Flags().BoolVar(&opts.allowUnpinned, "allow-unpinned", false, "allow structural-only verification without a trusted signer key")

	return cmd
}

// chainReport is the structured form emitted by --json on the chain
// subcommand.
type chainReport struct {
	Path               string `json:"path"`
	RecordType         string `json:"record_type,omitempty"`
	Valid              bool   `json:"valid"`
	ReceiptCount       uint64 `json:"receipt_count"`
	FinalSeq           uint64 `json:"final_seq"`
	RootHash           string `json:"root_hash,omitempty"`
	SignaturesVerified bool   `json:"signatures_verified"`
	Unpinned           bool   `json:"unpinned,omitempty"`
	SignerKeyID        string `json:"signer_key_id,omitempty"`
	Error              string `json:"error,omitempty"`
	BrokenAtSeq        uint64 `json:"broken_at_seq,omitempty"`
}

func runChain(stdout, stderr io.Writer, target string, opts chainOptions) error {
	keyHex, err := resolveSignerKey(strings.TrimSpace(opts.signerKey))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
	}

	var label string
	if opts.asDir {
		clean := filepath.Clean(target)
		label = fmt.Sprintf("%s (session %s)", clean, opts.sessionID)
		if handled, handleErr := runEvidenceChainFromDir(stdout, stderr, clean, label, keyHex, opts); handled || handleErr != nil {
			return handleErr
		}
		receipts, extractErr := actionreceipt.ExtractReceiptsFromSessionDir(clean, opts.sessionID)
		if extractErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("extract receipts: %w", extractErr))
		}
		return verifyActionChain(stdout, stderr, label, receipts, keyHex, opts)
	} else {
		clean := filepath.Clean(target)
		info, statErr := os.Stat(clean)
		if statErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("stat %q: %w", target, statErr))
		}
		if info.IsDir() {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("%q is a directory; pass --dir to verify a session directory", target))
		}
		label = clean
		if handled, handleErr := runEvidenceChainFromFile(stdout, stderr, clean, label, keyHex, opts); handled || handleErr != nil {
			return handleErr
		}
		receipts, extractErr := actionreceipt.ExtractReceipts(clean)
		if extractErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("extract receipts: %w", extractErr))
		}
		return verifyActionChain(stdout, stderr, label, receipts, keyHex, opts)
	}
}

func verifyActionChain(stdout, stderr io.Writer, label string, receipts []actionreceipt.Receipt, keyHex string, opts chainOptions) error {
	if opts.anySet() {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("EvidenceReceipt expectation flags require record_type=%s", recordTypeEvidenceV2))
	}
	if len(receipts) == 0 {
		report := chainReport{Path: label, Valid: false, Error: "no receipts in chain"}
		emitChainReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("empty chain"))
	}

	res := actionreceipt.VerifyChain(receipts, keyHex)
	report := chainReport{
		Path:         label,
		RecordType:   recordTypeActionV1,
		Valid:        res.Valid,
		ReceiptCount: res.ReceiptCount,
		FinalSeq:     res.FinalSeq,
		RootHash:     res.RootHash,
		// Provenance only when an out-of-band key is pinned AND every
		// signature verified; an empty key is self-consistency only.
		SignaturesVerified: res.Valid && keyHex != "",
		Unpinned:           res.Valid && keyHex == "",
		Error:              res.Error,
		BrokenAtSeq:        res.BrokenAtSeq,
	}
	if res.Valid && keyHex == "" {
		report.Error = unpinnedReceiptBanner
		report.Valid = opts.allowUnpinned
	}
	emitChainReport(stdout, stderr, report, opts.jsonOutput)
	if !res.Valid {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("chain rejected at seq %d: %s", res.BrokenAtSeq, res.Error))
	}
	if keyHex == "" && !opts.allowUnpinned {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("chain verification unpinned"))
	}
	return nil
}

// evidenceExtractorFunc is the signature for functions that extract evidence
// receipts from a path. Both file-based and dir-based extractors conform.
type evidenceExtractorFunc func() ([]contractreceipt.EvidenceReceipt, error)

func runEvidenceChainWith(stdout, stderr io.Writer, label, keyHex string, opts chainOptions, extract evidenceExtractorFunc) (bool, error) {
	receipts, err := extract()
	if err != nil {
		return true, cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("extract evidence receipts: %w", err))
	}
	if len(receipts) == 0 {
		return false, nil
	}
	return true, verifyEvidenceChain(stdout, stderr, label, receipts, keyHex, opts)
}

func runEvidenceChainFromFile(stdout, stderr io.Writer, clean, label, keyHex string, opts chainOptions) (bool, error) {
	return runEvidenceChainWith(stdout, stderr, label, keyHex, opts, func() ([]contractreceipt.EvidenceReceipt, error) {
		return contractreceipt.ExtractEvidenceReceipts(clean)
	})
}

func runEvidenceChainFromDir(stdout, stderr io.Writer, clean, label, keyHex string, opts chainOptions) (bool, error) {
	return runEvidenceChainWith(stdout, stderr, label, keyHex, opts, func() ([]contractreceipt.EvidenceReceipt, error) {
		return contractreceipt.ExtractEvidenceReceiptsFromSessionDir(clean, opts.sessionID)
	})
}

func verifyEvidenceChain(stdout, stderr io.Writer, label string, receipts []contractreceipt.EvidenceReceipt, keyHex string, opts chainOptions) error {
	chainOpts, err := opts.chainVerifyOptions(keyHex)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve evidence verification options: %w", err))
	}
	res := contractreceipt.VerifyChain(receipts, chainOpts)
	report := chainReport{
		Path:               label,
		RecordType:         recordTypeEvidenceV2,
		Valid:              res.Valid,
		ReceiptCount:       res.ReceiptCount,
		FinalSeq:           res.FinalSeq,
		RootHash:           res.RootHash,
		SignaturesVerified: res.SignaturesVerified,
		Unpinned:           res.Valid && !res.SignaturesVerified,
		SignerKeyID:        res.SignerKeyID,
		Error:              res.Error,
		BrokenAtSeq:        res.BrokenAtSeq,
	}
	if res.Valid && !res.SignaturesVerified {
		report.Error = unpinnedReceiptBanner
		report.Valid = opts.allowUnpinned
	}
	emitChainReport(stdout, stderr, report, opts.jsonOutput)
	if !res.Valid {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("evidence chain rejected at seq %d: %s", res.BrokenAtSeq, res.Error))
	}
	if !res.SignaturesVerified && !opts.allowUnpinned {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("evidence chain verification unpinned"))
	}
	return nil
}
