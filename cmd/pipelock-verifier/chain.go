// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// chainTrust is the resolved trust material for one chain verification, with
// the same meaning as in verify-receipt: every pinned key is trusted, and a
// rotation endorsement authorizes a successor key only under a pinned root
// key and only for the session it names.
type chainTrust struct {
	keys         []string
	endorsements []actionreceipt.RotationEndorsement
	session      string
}

func (t chainTrust) pinned() bool { return len(t.keys) > 0 }

// chainOptions holds resolved CLI flags for the chain subcommand.
type chainOptions struct {
	signerKeys       []string
	endorsementPaths []string
	sessionID        string
	locationID       string
	evidenceBindingOptions
	jsonOutput    bool
	asDir         bool
	allowUnpinned bool
	// sessionExplicit records that --session was given. Without it, a
	// directory whose base has per-run chains is verified as a whole.
	sessionExplicit bool
}

func newChainCmd() *cobra.Command {
	var opts chainOptions

	cmd := &cobra.Command{
		Use:     "chain PATH",
		Aliases: []string{"evidence"},
		Short:   "Verify a Pipelock receipt chain",
		Long: `Verifies the hash linkage of a Pipelock receipt chain. PATH may be a
single .jsonl evidence file or a session directory when --dir is set.

Evidence that holds both an ActionReceipt v1 chain and an EvidenceReceipt
v2 chain is valid only when both verify. Both require --key for trusted
provenance. Pass --allow-unpinned for loud structural-only verification.
Self-consistency does not prove provenance.

With --key the verifier requires every receipt to be signed by a named key.
Repeat --key to trust each key of a rotated chain, or pass
--rotation-endorsement for each old-key-signed rotation authorization and
pin only the root key; an endorsement never uses trust-on-first-use, so it
requires --key.

With --dir, a directory holding per-run chains ("<base>.run.<id>") is
verified run by run, followed by the base's restart continuity. --session
names one run to report; the whole base is still checked and any finding in
it fails the result. A symlinked file inside the directory is refused. A
single file named on the command line is read as given; its entries must all
belong to the session its file name claims, and its recorder entry hash chain
must hold from genesis.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.sessionExplicit = cmd.Flags().Changed("session")
			return runChain(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringArrayVar(&opts.signerKeys, "key", nil, "trusted signer public key (hex, public-key text, or file path); repeat for rotated chains")
	cmd.Flags().StringArrayVar(&opts.endorsementPaths, "rotation-endorsement", nil, "old-key-signed rotation endorsement JSON; repeat for each endorsed boundary (requires --key)")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside the evidence directory (--dir)")
	cmd.Flags().StringVar(&opts.locationID, "location", "", "location path relative to the evidence directory (--dir)")
	cmd.Flags().StringVar(&opts.expectSignerKeyID, "expect-signer-id", "", "EvidenceReceipt v2: require signer_key_id")
	cmd.Flags().StringVar(&opts.expectContractHash, "expect-contract", "", "EvidenceReceipt v2: require contract_hash")
	cmd.Flags().StringVar(&opts.expectManifestHash, "expect-manifest", "", "EvidenceReceipt v2: require active_manifest_hash")
	cmd.Flags().StringVar(&opts.expectPayloadKind, "expect-payload-kind", "", "EvidenceReceipt v2: require payload_kind")
	cmd.Flags().StringVar(&opts.expectHeadHash, "expect-head", "", "EvidenceReceipt v2: require the chain tip to equal this receipt hash, which is the only check that detects dropped trailing entries; source it from trusted context outside the chain")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")
	cmd.Flags().BoolVar(&opts.asDir, "dir", false, "treat PATH as a session directory rather than a single file")
	cmd.Flags().BoolVar(&opts.allowUnpinned, "allow-unpinned", false, "allow structural-only verification without a trusted signer key")

	return cmd
}

// chainReport is the structured form emitted by --json on the chain
// subcommand.
type chainReport struct {
	Path               string     `json:"path"`
	RecordType         string     `json:"record_type,omitempty"`
	Valid              bool       `json:"valid"`
	ReceiptCount       uint64     `json:"receipt_count"`
	FinalSeq           uint64     `json:"final_seq"`
	RootHash           string     `json:"root_hash,omitempty"`
	SignaturesVerified bool       `json:"signatures_verified"`
	HeadVerified       bool       `json:"head_verified"`
	Unpinned           bool       `json:"unpinned,omitempty"`
	SignerKeyID        string     `json:"signer_key_id,omitempty"`
	Error              string     `json:"error,omitempty"`
	BrokenAtSeq        uint64     `json:"broken_at_seq,omitempty"`
	Scorecard          *scorecard `json:"scorecard,omitempty"`
}

func runChain(stdout, stderr io.Writer, target string, opts chainOptions) error {
	trust, err := resolveChainTrust(opts)
	if err != nil {
		return err
	}

	var label string
	if opts.asDir {
		clean := filepath.Clean(target)
		location, locationErr := recorder.ResolveEvidenceLocation(clean, opts.locationID)
		if locationErr != nil {
			return evidenceLocationError(fmt.Errorf("resolve evidence location: %w", locationErr))
		}
		clean = location.Dir
		if handled, setErr := runChainSetIfRuns(stdout, stderr, location, trust, opts); handled || setErr != nil {
			return setErr
		}
		label = fmt.Sprintf("%s (session %s)", clean, opts.sessionID)
		if handled, handleErr := runEvidenceChainFromDir(stdout, stderr, location, label, trust, opts); handled || handleErr != nil {
			return handleErr
		}
		receipts, extractErr := actionreceipt.ExtractReceiptsFromResolvedSessionDir(location, opts.sessionID)
		if extractErr != nil {
			return evidenceContentError(fmt.Errorf("extract receipts: %w", extractErr))
		}
		return verifyActionChain(stdout, stderr, label, receipts, trust, opts)
	}
	if opts.locationID != "" {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("--location requires --dir"))
	}
	clean := filepath.Clean(target)
	info, statErr := os.Stat(target)
	if statErr != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("stat %q: %w", target, statErr))
	}
	if info.IsDir() {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("%q is a directory; pass --dir to verify a session directory", target))
	}
	// A file the operator names is read as given, even through a symlink:
	// the symlink refusal protects a directory scan from redirection, and an
	// explicit path has no scan to redirect.
	resolved, evalErr := filepath.EvalSymlinks(target)
	if evalErr != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve %q: %w", target, evalErr))
	}
	label = target
	isBareV1, bareData, detectErr := isBareActionReceiptJSONL(resolved)
	if detectErr != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, detectErr)
	}
	if isBareV1 {
		// Verify the exact bytes the routing decision was made on. Reopening
		// the path here would let a file replaced between the two reads be
		// verified under a decision taken about different evidence.
		receipts, extractErr := actionreceipt.ExtractReceiptsBytes(bareData)
		if extractErr != nil {
			return evidenceContentError(fmt.Errorf("extract receipts: %w", extractErr))
		}
		return verifyActionChain(stdout, stderr, label, receipts, trust, opts)
	}
	if fileErr := checkRecorderFileBytes(filepath.Base(clean), bareData, trust); fileErr != nil {
		emitChainReport(stdout, stderr, chainReport{Path: label, Error: fileErr.Error()}, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fileErr)
	}
	if handled, handleErr := runEvidenceChainFromFile(stdout, stderr, bareData, label, trust, opts); handled || handleErr != nil {
		return handleErr
	}
	receipts, extractErr := actionreceipt.ExtractReceiptsBytes(bareData)
	if extractErr != nil {
		return evidenceContentError(fmt.Errorf("extract receipts: %w", extractErr))
	}
	return verifyActionChain(stdout, stderr, label, receipts, trust, opts)
}

// resolveChainTrust resolves every --key and loads every
// --rotation-endorsement. No key means unpinned verification.
func resolveChainTrust(opts chainOptions) (chainTrust, error) {
	trust := chainTrust{session: opts.sessionID}
	for _, input := range opts.signerKeys {
		keyHex, err := resolveSignerKey(strings.TrimSpace(input))
		if err != nil {
			return chainTrust{}, cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
		}
		if keyHex != "" {
			trust.keys = append(trust.keys, keyHex)
		}
	}
	for _, p := range opts.endorsementPaths {
		e, err := actionreceipt.LoadRotationEndorsementFile(p)
		if err != nil {
			return chainTrust{}, cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("loading --rotation-endorsement %q: %w", p, err))
		}
		trust.endorsements = append(trust.endorsements, e)
	}
	if len(trust.endorsements) > 0 && !trust.pinned() {
		return chainTrust{}, cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("--rotation-endorsement requires --key: an endorsement is authority only under a pinned root key"))
	}
	return trust, nil
}

// checkRecorderFileBytes applies the rules one evidence file must meet on its
// own, as verify-receipt does: its entries belong to the session its name
// claims, and its recorder entry hash chain holds from genesis. Bytes that
// are not recorder output are left to the extractors. With endorsements, the
// file must be the session the endorsements are bound to.
func checkRecorderFileBytes(name string, data []byte, trust chainTrust) error {
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	if len(trust.endorsements) > 0 && len(entries) > 0 && entries[0].SessionID != trust.session {
		return fmt.Errorf("endorsed receipt session %q does not match evidence session %q", trust.session, entries[0].SessionID)
	}
	_, _, _, err = actionreceipt.RecorderFileChains(name, entries)
	return err
}

// evidenceLocationError classifies a failure to resolve an evidence
// directory: a refused symlink is a verification failure (exit 1), any other
// failure, such as a missing directory, a configuration error (exit 2).
func evidenceLocationError(err error) error {
	if errors.Is(err, recorder.ErrEvidenceRefused) {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	return cliutil.ExitCodeError(cliutil.ExitConfig, err)
}

// evidenceContentError is a failure reading or parsing the evidence itself: a
// verification failure (exit 1), as in verify-receipt.
func evidenceContentError(err error) error {
	return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
}

// isBareActionReceiptJSONL identifies the legacy compatibility format without
// treating malformed or mixed input as an action chain. Recorder-backed v1 and
// all v2 input keep the v2-first route below, which preserves its strict
// recorder validation before the v1 fallback.
// It returns the bytes it classified so the caller can verify those exact bytes
// rather than reopening the path.
func isBareActionReceiptJSONL(path string) (bool, []byte, error) {
	data, err := readVerifierFile(path)
	if err != nil {
		return false, nil, fmt.Errorf("read evidence file: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), 10<<20)
	found := false
	for scanner.Scan() {
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		r, unmarshalErr := actionreceipt.Unmarshal(raw)
		if unmarshalErr != nil || r.Version != actionreceipt.ReceiptVersion || r.Signature == "" || r.SignerKey == "" {
			return false, data, nil
		}
		found = true
	}
	// Defensive only while readVerifierFile's total-size bound stays below this
	// scanner's per-line bound: a single line cannot exceed the line limit when
	// the whole file is already capped lower. It is kept so that raising the
	// reader's cap cannot silently turn an oversized line into a parse attempt.
	if err := scanner.Err(); err != nil {
		return false, nil, fmt.Errorf("scan evidence file: %w", err)
	}
	return found, data, nil
}

func verifyActionChain(stdout, stderr io.Writer, label string, receipts []actionreceipt.Receipt, trust chainTrust, opts chainOptions) error {
	if opts.anySet() {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("EvidenceReceipt expectation flags require record_type=%s", recordTypeEvidenceV2))
	}
	report, err := actionChainReport(label, receipts, trust, opts)
	emitChainReport(stdout, stderr, report, opts.jsonOutput)
	return err
}

// actionChainReport verifies an ActionReceipt v1 chain and returns its report
// and the command error, without printing.
func actionChainReport(label string, receipts []actionreceipt.Receipt, trust chainTrust, opts chainOptions) (chainReport, error) {
	if len(receipts) == 0 {
		report := chainReport{Path: label, Valid: false, Error: "no receipts in chain"}
		return report, cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("empty chain"))
	}

	var res actionreceipt.ChainResult
	if len(trust.endorsements) > 0 {
		res = actionreceipt.VerifyChainWithEndorsements(trust.session, receipts, trust.endorsements, trust.keys)
	} else {
		res = actionreceipt.VerifyChainTrusted(receipts, trust.keys)
	}
	pinned := trust.pinned()
	completenessReport := completeness.Analyze(receipts, res)
	report := chainReport{
		Path:         label,
		RecordType:   recordTypeActionV1,
		Valid:        res.Valid,
		ReceiptCount: res.ReceiptCount,
		FinalSeq:     res.FinalSeq,
		RootHash:     res.RootHash,
		// Provenance only when an out-of-band key is pinned AND every
		// signature verified; an empty key is self-consistency only.
		SignaturesVerified: res.Valid && pinned,
		Unpinned:           res.Valid && !pinned,
		Error:              res.Error,
		BrokenAtSeq:        res.BrokenAtSeq,
	}
	sc := newActionScorecard(res, pinned, completenessReport)
	report.Scorecard = &sc
	if res.Valid && !pinned {
		report.Error = unpinnedReceiptBanner
		report.Valid = opts.allowUnpinned
	}
	if res.Valid && completenessReport.Status == completeness.StatusBroken {
		report.Valid = false
		report.Unpinned = false
		report.BrokenAtSeq = completenessReport.BrokenAtSeq
		report.Error = "lifecycle: " + string(completenessReport.Reason)
		if completenessReport.Error != "" {
			report.Error += ": " + completenessReport.Error
		}
	}
	if res.Valid {
		if lintErr := lintDeferredCascadeReceipts(receipts); lintErr != nil {
			report.Valid = false
			report.Error = lintErr.Error()
			return report, cliutil.ExitCodeError(cliutil.ExitGeneral, lintErr)
		}
	}
	if !res.Valid {
		return report, cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("chain rejected at seq %d: %s", res.BrokenAtSeq, res.Error))
	}
	if completenessReport.Status == completeness.StatusBroken {
		return report, cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("chain lifecycle broken: %s", completenessReport.Error))
	}
	if !pinned && !opts.allowUnpinned {
		return report, cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("chain verification unpinned"))
	}
	return report, nil
}

// evidenceExtractorFunc is the signature for functions that extract evidence
// receipts from a path. Both file-based and dir-based extractors conform.
type evidenceExtractorFunc func() ([]contractreceipt.EvidenceReceipt, error)

// actionExtractorFunc extracts the ActionReceipt v1 chain from the same
// evidence the paired evidenceExtractorFunc reads.
type actionExtractorFunc func() ([]actionreceipt.Receipt, error)

func runEvidenceChainWith(stdout, stderr io.Writer, label string, trust chainTrust, opts chainOptions, extract evidenceExtractorFunc, extractAction actionExtractorFunc) (bool, error) {
	receipts, err := extract()
	if err != nil {
		return true, evidenceContentError(fmt.Errorf("extract evidence receipts: %w", err))
	}
	if len(receipts) == 0 {
		return false, nil
	}
	actionReceipts, err := extractAction()
	if err != nil {
		return true, evidenceContentError(fmt.Errorf("extract receipts: %w", err))
	}
	return true, verifyEvidenceChain(stdout, stderr, label, receipts, actionReceipts, trust, opts)
}

func runEvidenceChainFromFile(stdout, stderr io.Writer, data []byte, label string, trust chainTrust, opts chainOptions) (bool, error) {
	if int64(len(data)) > maxVerifierInputBytes {
		return true, cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("evidence input exceeds %d bytes", maxVerifierInputBytes))
	}
	return runEvidenceChainWith(stdout, stderr, label, trust, opts, func() ([]contractreceipt.EvidenceReceipt, error) {
		return contractreceipt.ExtractEvidenceReceiptsBytes(data)
	}, func() ([]actionreceipt.Receipt, error) {
		if !hasActionReceiptEntry(data) {
			return nil, nil
		}
		return actionreceipt.ExtractReceiptsBytes(data)
	})
}

func runEvidenceChainFromDir(stdout, stderr io.Writer, location recorder.EvidenceLocation, label string, trust chainTrust, opts chainOptions) (bool, error) {
	return runEvidenceChainWith(stdout, stderr, label, trust, opts, func() ([]contractreceipt.EvidenceReceipt, error) {
		return contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir(location, opts.sessionID)
	}, func() ([]actionreceipt.Receipt, error) {
		return sessionActionReceipts(location, opts.sessionID)
	})
}

// actionReceiptEntryType is the recorder entry type of an ActionReceipt v1.
const actionReceiptEntryType = "action_receipt"

// hasActionReceiptEntry reports whether evidence bytes hold an action_receipt
// entry. It reads each line's type the way the EvidenceReceipt v2 extractor
// does, so the two agree on what every line is. Evidence without one has no
// ActionReceipt v1 chain whatever its format: a v2-only file written as bare
// entry lines is not recorder output, and the v1 extractor rejects it rather
// than returning an empty chain. A scan error answers true, so the strict
// extractor runs and reports it.
func hasActionReceiptEntry(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), 10<<20)
	for scanner.Scan() {
		var probe struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(bytes.TrimSpace(scanner.Bytes()), &probe) == nil && probe.Type == actionReceiptEntryType {
			return true
		}
	}
	return scanner.Err() != nil
}

// sessionActionReceipts returns the ActionReceipt v1 chain of one session in a
// directory, or none when no file of that session holds an action_receipt
// entry. Membership is the parsed session name, as the v2 extractor uses.
func sessionActionReceipts(location recorder.EvidenceLocation, session string) ([]actionreceipt.Receipt, error) {
	entries, err := recorder.ReadEvidenceLocationEntries(location)
	if err != nil {
		return nil, fmt.Errorf("read evidence directory: %w", err)
	}
	want := filepath.Base(session)
	found := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name, _, ok := recorder.ParseEvidenceFilename(e.Name())
		if !ok || name != want {
			continue
		}
		data, readErr := recorder.ReadEvidenceFileBounded(filepath.Join(location.Dir, e.Name()), recorder.MaxEvidenceReadFileBytes)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), readErr)
		}
		if hasActionReceiptEntry(data) {
			found = true
			break
		}
	}
	if !found {
		return nil, nil
	}
	return actionreceipt.ExtractReceiptsFromResolvedSessionDir(location, session)
}

// verifyEvidenceChain verifies the EvidenceReceipt v2 chain and, when the same
// evidence also holds one, the ActionReceipt v1 chain.
func verifyEvidenceChain(stdout, stderr io.Writer, label string, receipts []contractreceipt.EvidenceReceipt, actionReceipts []actionreceipt.Receipt, trust chainTrust, opts chainOptions) error {
	report, verifyErr := evidenceChainReport(label, receipts, trust, opts)
	report, verifyErr = withActionChain(report, verifyErr, label, actionReceipts, trust, opts)
	emitChainReport(stdout, stderr, report, opts.jsonOutput)
	return verifyErr
}

// withActionChain folds the ActionReceipt v1 chain into an EvidenceReceipt v2
// report. A current run writes both chains into the same files, each signed on
// its own, so a forged receipt in one leaves the other intact: verifying only
// the v2 chain reported a session valid while its action chain was forged.
// Both chains must verify. The v2 report stays the primary one, so a session
// whose chains both pass prints exactly what it did before, and a failure
// names the chain it came from.
func withActionChain(report chainReport, reportErr error, label string, actionReceipts []actionreceipt.Receipt, trust chainTrust, opts chainOptions) (chainReport, error) {
	if len(actionReceipts) == 0 {
		return report, reportErr
	}
	action, actionErr := actionChainReport(label, actionReceipts, trust, opts)
	actionOK := actionErr == nil && action.Valid
	reportOK := reportErr == nil && report.Valid
	if actionOK && reportOK {
		return report, reportErr
	}
	// Without a key and without --allow-unpinned both chains fail only for
	// being unpinned; the v2 report already says so.
	if report.Error == unpinnedReceiptBanner && action.Error == unpinnedReceiptBanner {
		return report, reportErr
	}
	var reasons []string
	if !reportOK {
		reasons = append(reasons, "evidence receipt chain: "+report.Error)
	} else {
		report.BrokenAtSeq = action.BrokenAtSeq
	}
	if !actionOK {
		reasons = append(reasons, "action receipt chain: "+action.Error)
	}
	report.Valid = false
	report.Unpinned = false
	report.Error = strings.Join(reasons, "; ")
	return report, cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New(report.Error))
}

// evidenceChainReport verifies an EvidenceReceipt v2 chain and returns its
// report and the command error, without printing.
// The chain is keyed as every verifier keys it (actionreceipt.EvidenceChainPin):
// its declared signer must be one of the pinned keys.
func evidenceChainReport(label string, receipts []contractreceipt.EvidenceReceipt, trust chainTrust, opts chainOptions) (chainReport, error) {
	chainOpts, err := opts.chainVerifyOptions("")
	if err != nil {
		return chainReport{Path: label, Error: err.Error()}, cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	res := actionreceipt.VerifyEvidenceChainTrusted(receipts, trust.keys, chainOpts)
	report := chainReport{
		Path:               label,
		RecordType:         recordTypeEvidenceV2,
		Valid:              res.Valid,
		ReceiptCount:       res.ReceiptCount,
		FinalSeq:           res.FinalSeq,
		RootHash:           res.RootHash,
		SignaturesVerified: res.SignaturesVerified,
		HeadVerified:       res.HeadVerified,
		Unpinned:           res.Valid && !res.SignaturesVerified,
		SignerKeyID:        res.SignerKeyID,
		Error:              res.Error,
		BrokenAtSeq:        res.BrokenAtSeq,
	}
	if res.Valid && !res.SignaturesVerified {
		report.Error = unpinnedReceiptBanner
		report.Valid = opts.allowUnpinned
	}
	if !res.Valid {
		return report, cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("evidence chain rejected at seq %d: %s", res.BrokenAtSeq, res.Error))
	}
	if !res.SignaturesVerified && !opts.allowUnpinned {
		return report, cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("evidence chain verification unpinned"))
	}
	return report, nil
}
