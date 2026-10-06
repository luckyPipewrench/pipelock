// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type independentOptions struct {
	bundlePath   string
	signerKeys   []string
	rekorLogKeys []string
	logPath      string
	logID        string
	sessionID    string
	// sessionExplicit records that --session was passed, so the default does
	// not override the operator's choice.
	sessionExplicit bool
	locationID      string
	asDir           bool
	jsonOutput      bool
	// requireFullCoverage fails verification when the anchor covers fewer
	// receipts than the supplied chain holds.
	requireFullCoverage bool
}

func newIndependentCmd() *cobra.Command {
	var opts independentOptions
	cmd := &cobra.Command{
		Use:   "independent PATH",
		Short: "Verify an anchored receipt-chain checkpoint",
		Long: `Verifies a receipt chain against an anchor bundle and backend proof
material. The local backend is a deterministic test backend; it proves the
checkpoint/proof mechanics but is not an operator-independent witness.

Honest limit: anchoring does not prove real-time truth by whoever held the
receipt signing key. Rekor verification requires a pinned Rekor log public key
and verifies the recorded SET, signed checkpoint, and inclusion proof offline.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.sessionExplicit = cmd.Flags().Changed("session")
			return runIndependent(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)
	cmd.Flags().StringVar(&opts.bundlePath, "bundle", "", "anchor bundle JSON path")
	cmd.Flags().StringArrayVar(&opts.signerKeys, "key", nil, "trusted signer public key (hex, public-key text, or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&opts.logPath, "local-log", "", "local fake-log JSONL path")
	cmd.Flags().StringVar(&opts.logID, "log-id", anchor.DefaultLocalLogID, "local fake-log identifier")
	cmd.Flags().StringArrayVar(&opts.rekorLogKeys, "rekor-log-key", nil, "trusted Rekor log public key (PEM, Pipelock Ed25519 key, raw hex, or file path); repeat for rotations")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside the evidence directory when --dir is set (default: the session the bundle anchored, else proxy)")
	cmd.Flags().StringVar(&opts.locationID, "location", "", "location path relative to the evidence directory when --dir is set")
	cmd.Flags().BoolVar(&opts.asDir, "dir", false, "treat PATH as a session directory rather than a single evidence file")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")
	cmd.Flags().BoolVar(&opts.requireFullCoverage, "require-full-coverage", false, "fail when the anchor covers fewer receipts than the supplied chain holds (covered_receipts < chain_length)")
	return cmd
}

func runIndependent(stdout, stderr io.Writer, target string, opts independentOptions) error {
	if strings.TrimSpace(opts.bundlePath) == "" {
		return cliutil.ExitCodeError(exitUsage, fmt.Errorf("--bundle is required"))
	}
	if len(opts.signerKeys) == 0 {
		return cliutil.ExitCodeError(exitUsage, fmt.Errorf("at least one --key is required"))
	}
	keyHexes, err := resolveSignerKeys(opts.signerKeys)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
	}
	if !opts.asDir {
		resolved, resolveErr := filepath.EvalSymlinks(target)
		if resolveErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve %q: %w", target, resolveErr))
		}
		target = resolved
	}
	bundle, err := anchor.LoadBundle(opts.bundlePath)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	opts.sessionID = independentSession(opts, bundle)
	receipts, err := independentReceipts(target, opts)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("extract receipts: %w", err))
	}
	backend, exitCode, err := independentBackend(bundle, opts)
	if err != nil {
		return cliutil.ExitCodeError(exitCode, err)
	}
	// An anchor commits to the receipts it covered at submission time. The
	// live chain keeps growing afterwards, so the checkpoint is recomputed over
	// the covered prefix; comparing it with the whole chain made every
	// bundle fail once one more receipt was written.
	covered, err := coveredReceipts(bundle, receipts)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("independent verification failed: %w", err))
	}
	report := independentReport{
		VerifyReport:    anchor.VerifyBundle(bundle, covered, keyHexes, backend),
		CoveredReceipts: len(covered),
		ChainLength:     len(receipts),
	}
	if report.Valid && len(covered) < len(receipts) {
		// The anchor vouches for the prefix only. Receipts after it must still
		// verify as a chain (hash linkage and signatures) or the verdict is
		// not valid; an honest early bundle whose later receipts verify stays
		// valid and the coverage split is reported.
		if tail := receipt.VerifyChainTrusted(receipts, keyHexes); !tail.Valid {
			report.Valid = false
			report.Error = fmt.Sprintf("receipts after the anchored prefix (%d..%d) failed chain verification: %s", len(covered), len(receipts)-1, tail.Error)
		} else {
			report.TailChainVerified = true
		}
	}
	if opts.requireFullCoverage && report.Valid && len(covered) < len(receipts) {
		// Opt-in strict stance: receipts after the anchor are chain-verified
		// only under the supplied keys, which a holder of the signing key can
		// forge, so no anchor vouches for them.
		report.Valid = false
		report.Error = fmt.Sprintf("anchor covers %d of %d receipts and --require-full-coverage needs every receipt anchored (%d unanchored)", len(covered), len(receipts), len(receipts)-len(covered))
	}
	emitIndependentReport(stdout, stderr, filepath.Clean(target), report, opts.jsonOutput)
	if report.Valid && len(covered) < len(receipts) {
		// Keep a stderr note for operators; the JSON verdict carries the same
		// split in structured fields.
		_, _ = fmt.Fprintf(stderr, "note: the anchor covers receipts 0..%d of %d in this chain; the %d later receipts are chain-verified but not anchored\n",
			len(covered)-1, len(receipts), len(receipts)-len(covered))
	}
	if !report.Valid {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("independent verification failed: %s", report.Error))
	}
	return nil
}

// independentReport is the anchor verdict plus how much of the supplied chain
// the anchor covers. The embedded fields keep their existing meaning; the
// three added ones are additive.
type independentReport struct {
	anchor.VerifyReport
	// CoveredReceipts is how many leading receipts the anchor commits to.
	CoveredReceipts int `json:"covered_receipts"`
	// ChainLength is how many receipts were supplied.
	ChainLength int `json:"chain_length"`
	// TailChainVerified is true when receipts after the anchored prefix exist
	// and verified as a chain.
	TailChainVerified bool `json:"tail_chain_verified"`
}

// coveredReceipts returns the leading receipts a bundle's checkpoint covers. A
// chain shorter than the checkpoint claims is refused: that is truncation, not
// a stale anchor.
func coveredReceipts(bundle anchor.Bundle, receipts []receipt.Receipt) ([]receipt.Receipt, error) {
	if len(receipts) == 0 {
		// Let verification report the empty chain itself.
		return receipts, nil
	}
	count := bundle.Checkpoint.ReceiptCount
	if count == 0 {
		return nil, fmt.Errorf("anchor bundle covers no receipts")
	}
	if count > uint64(len(receipts)) {
		return nil, fmt.Errorf("anchor bundle covers %d receipts but the supplied chain has only %d", count, len(receipts))
	}
	return receipts[:count], nil
}

// independentCoverage names which receipts the anchor commits to and which were
// only chain-verified.
func independentCoverage(report independentReport) string {
	if report.CoveredReceipts >= report.ChainLength {
		return fmt.Sprintf("receipts 0..%d of %d anchored", report.CoveredReceipts-1, report.ChainLength)
	}
	return fmt.Sprintf("receipts 0..%d of %d anchored, %d..%d chain-verified",
		report.CoveredReceipts-1, report.ChainLength, report.CoveredReceipts, report.ChainLength-1)
}

func independentBackend(bundle anchor.Bundle, opts independentOptions) (anchor.Backend, int, error) {
	if bundle.Backend != bundle.Proof.Backend {
		return nil, cliutil.ExitConfig, fmt.Errorf("anchor bundle backend %q does not match proof backend %q", bundle.Backend, bundle.Proof.Backend)
	}
	switch bundle.Backend {
	case anchor.LocalBackend:
		if strings.TrimSpace(opts.logPath) == "" {
			return nil, exitUsage, fmt.Errorf("--local-log is required for local anchor verification")
		}
		return anchor.LocalLog{
			Path:  opts.logPath,
			LogID: opts.logID,
		}, cliutil.ExitOK, nil
	case anchor.RekorBackend:
		keys, err := anchor.LoadRekorPublicKeys(opts.rekorLogKeys)
		if err != nil {
			return nil, cliutil.ExitConfig, fmt.Errorf("resolve --rekor-log-key: %w", err)
		}
		return anchor.RekorLog{TrustedLogKeys: keys}, cliutil.ExitOK, nil
	default:
		return nil, cliutil.ExitConfig, fmt.Errorf("unsupported anchor backend %q", bundle.Backend)
	}
}

// independentSession picks the session whose receipts an evidence directory
// is read for. The bundle names the chain it anchored, and the recorder names a
// run's chain proxy.run.<id>, so the flag's default of proxy matches a
// directory of per-run chains only by accident: an anchor of one run could
// never verify against it. Unless --session was passed, the bundle's own
// session is used. A bundle from a single evidence file carries no directory
// session ("file" or empty), and keeps the flag's value.
func independentSession(opts independentOptions, bundle anchor.Bundle) string {
	named := bundle.Checkpoint.SessionID
	if !opts.asDir || opts.sessionExplicit || named == "" || named == anchorFileSession {
		return opts.sessionID
	}
	return named
}

// anchorFileSession is the session ID the anchor command records for a chain
// read from a single evidence file rather than a session directory.
const anchorFileSession = "file"

func independentReceipts(target string, opts independentOptions) ([]receipt.Receipt, error) {
	if opts.asDir {
		location, err := recorder.ResolveEvidenceLocation(target, opts.locationID)
		if err != nil {
			return nil, fmt.Errorf("resolve evidence location: %w", err)
		}
		return receipt.ExtractReceiptsFromResolvedSessionDir(location, opts.sessionID)
	}
	if opts.locationID != "" {
		return nil, fmt.Errorf("--location requires --dir")
	}
	return receipt.ExtractReceipts(target)
}

func resolveSignerKeys(inputs []string) ([]string, error) {
	out := make([]string, 0, len(inputs))
	for _, input := range inputs {
		keyHex, err := resolveSignerKey(input)
		if err != nil {
			return nil, err
		}
		if keyHex != "" {
			out = append(out, keyHex)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one non-empty --key is required")
	}
	return out, nil
}

func emitIndependentReport(stdout, stderr io.Writer, path string, report independentReport, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, report)
		return
	}
	if report.Valid {
		_, _ = fmt.Fprintf(stdout, "INDEPENDENT VERIFY OK: %s (%s)\n", path, independentCoverage(report))
		_, _ = fmt.Fprintf(stdout, "  Backend:       %s\n", report.Backend)
		_, _ = fmt.Fprintf(stdout, "  Session:       %s\n", report.SessionID)
		_, _ = fmt.Fprintf(stdout, "  Receipts:      %d\n", report.ReceiptCount)
		_, _ = fmt.Fprintf(stdout, "  Coverage:      %s\n", independentCoverage(report))
		_, _ = fmt.Fprintf(stdout, "  Final seq:     %d\n", report.FinalSeq)
		_, _ = fmt.Fprintf(stdout, "  Root hash:     %s\n", report.RootHash)
		_, _ = fmt.Fprintf(stdout, "  Log index:     %d\n", report.Proof.LogIndex)
		for _, limit := range report.Limits {
			_, _ = fmt.Fprintf(stdout, "  Limit:         %s\n", limit)
		}
		return
	}
	_, _ = fmt.Fprintf(stderr, "INDEPENDENT VERIFY FAILED: %s\n", path)
	if report.Error != "" {
		_, _ = fmt.Fprintf(stderr, "  error: %s\n", report.Error)
	}
}
