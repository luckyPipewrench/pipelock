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
	groupID          string
	locationID       string
	evidenceBindingOptions
	jsonOutput      bool
	asDir           bool
	allowUnpinned   bool
	excludeGroups   bool
	groupForBase    bool
	groupJSONSpool  io.Writer
	legacyJSONSpool io.Writer
	groupJSONCount  *uint64
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
	cmd.Flags().StringVar(&opts.groupID, "group", "", "verify a complete signed receipt group by its 32-hex ID (requires --dir and --key)")
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
	if !opts.asDir || !opts.jsonOutput || opts.groupID != "" {
		return runChainInner(stdout, stderr, target, opts)
	}
	groupSpool, err := os.CreateTemp("", "pipelock-chain-groups-*.jsonl")
	if err != nil {
		return fmt.Errorf("create group report spool: %w", err)
	}
	defer func() {
		_ = groupSpool.Close()
		_ = os.Remove(groupSpool.Name())
	}()
	legacySpool, err := os.CreateTemp("", "pipelock-chain-legacy-*.json")
	if err != nil {
		return fmt.Errorf("create legacy report spool: %w", err)
	}
	defer func() {
		_ = legacySpool.Close()
		_ = os.Remove(legacySpool.Name())
	}()
	var groupCount uint64
	opts.groupJSONSpool = groupSpool
	opts.legacyJSONSpool = legacySpool
	opts.groupJSONCount = &groupCount
	innerErr := runChainInner(io.Discard, stderr, target, opts)
	if groupCount == 0 {
		if _, err := legacySpool.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind legacy report spool: %w", err)
		}
		if _, err := io.Copy(stdout, legacySpool); err != nil {
			return err
		}
		return innerErr
	}
	return emitGroupedChainJSON(stdout, groupSpool, legacySpool, innerErr)
}

func writeGroupJSONSpool(opts chainOptions, result actionreceipt.ReceiptGroupResult) error {
	if opts.groupJSONSpool == nil || opts.groupJSONCount == nil {
		return errors.New("group JSON report spool is unavailable")
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := opts.groupJSONSpool.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		*opts.groupJSONCount++
	}
	return err
}

func emitGroupedChainJSON(stdout io.Writer, groups, legacy *os.File, innerErr error) error {
	var legacyReport json.RawMessage
	if _, err := legacy.Seek(0, io.SeekStart); err != nil {
		innerErr = errors.Join(innerErr, fmt.Errorf("rewind legacy JSON report: %w", err))
	} else {
		decoder := json.NewDecoder(legacy)
		if err := decoder.Decode(&legacyReport); err != nil {
			if !errors.Is(err, io.EOF) {
				innerErr = errors.Join(innerErr, fmt.Errorf("decode legacy JSON report: %w", err))
			}
			legacyReport = nil
		} else {
			var extra json.RawMessage
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				if err == nil {
					err = errors.New("multiple legacy JSON reports")
				}
				innerErr = errors.Join(innerErr, err)
				legacyReport = nil
			}
		}
	}
	combined, err := os.CreateTemp("", "pipelock-chain-report-*.json")
	if err != nil {
		return fmt.Errorf("create combined JSON report: %w", err)
	}
	defer func() { _ = os.Remove(combined.Name()) }()
	valid := innerErr == nil
	if _, err := fmt.Fprintf(combined, `{"valid":%t,"groups":[`, valid); err != nil {
		return err
	}
	if _, err := groups.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind group JSON reports: %w", err)
	}
	scanner := bufio.NewScanner(groups)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	first := true
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if !json.Valid(line) {
			return errors.New("group JSON report spool contains malformed JSON")
		}
		if !first {
			if _, err := io.WriteString(combined, ","); err != nil {
				return err
			}
		}
		if _, err := combined.Write(line); err != nil {
			return err
		}
		first = false
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read group JSON report spool: %w", err)
	}
	if _, err := io.WriteString(combined, `],"legacy":`); err != nil {
		return err
	}
	if len(legacyReport) == 0 {
		if _, err := io.WriteString(combined, "null"); err != nil {
			return err
		}
	} else if _, err := combined.Write(legacyReport); err != nil {
		return err
	}
	if innerErr != nil {
		encoded, err := json.Marshal(innerErr.Error())
		if err != nil {
			return err
		}
		if _, err := combined.Write(append([]byte(`,"error":`), encoded...)); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(combined, "}\n"); err != nil {
		return err
	}
	if _, err := combined.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind combined JSON report: %w", err)
	}
	if _, err := io.Copy(stdout, combined); err != nil {
		return err
	}
	return innerErr
}

func runChainInner(stdout, stderr io.Writer, target string, opts chainOptions) error {
	trust, err := resolveChainTrust(opts)
	if err != nil {
		return err
	}
	if opts.groupID != "" {
		if !opts.asDir || opts.sessionExplicit || !trust.pinned() || opts.allowUnpinned || len(opts.endorsementPaths) > 0 || opts.anySet() {
			return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("--group requires --dir and pinned --key without session, endorsement, or shard-only checks"))
		}
		location, locationErr := recorder.ResolveEvidenceLocation(target, opts.locationID)
		if locationErr != nil {
			return evidenceLocationError(fmt.Errorf("resolve evidence location: %w", locationErr))
		}
		result := actionreceipt.VerifyReceiptGroup(location.Dir, opts.groupID, trust.keys)
		if opts.jsonOutput {
			writeJSON(stdout, result)
		} else {
			_, _ = fmt.Fprintf(stdout, "%s %s: %d shards; open=%s close=%s\n", result.Verdict, result.GroupID, result.ShardCount, result.OpenManifestSHA, result.CloseManifestSHA)
		}
		if result.Verdict != actionreceipt.GroupValid {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New(result.Error))
		}
		if result.Error != "" && !opts.jsonOutput {
			_, _ = fmt.Fprintln(stdout, result.Error)
		}
		return nil
	}
	if opts.asDir {
		groupLocation, locationErr := recorder.ResolveEvidenceLocation(target, opts.locationID)
		if locationErr != nil {
			return evidenceLocationError(fmt.Errorf("resolve evidence location: %w", locationErr))
		}
		base := opts.sessionID
		if b, ok := actionreceipt.RunSessionBase(base); ok {
			base = b
		}
		var groupForBase bool
		groupSummary, groupErr := actionreceipt.VerifyReceiptGroups(groupLocation.Dir, trust.keys, func(result actionreceipt.ReceiptGroupResult) error {
			if result.BaseSession == base {
				groupForBase = true
			}
			if opts.jsonOutput {
				return writeGroupJSONSpool(opts, result)
			}
			_, err := fmt.Fprintf(stdout, "%s %s: %d shards; open=%s close=%s\n", result.Verdict, result.GroupID, result.ShardCount, result.OpenManifestSHA, result.CloseManifestSHA)
			return err
		})
		if groupErr != nil {
			verdict := actionreceipt.GroupInvalid
			if errors.Is(groupErr, recorder.ErrEvidenceChanged) {
				verdict = actionreceipt.GroupIncomplete
			}
			if opts.jsonOutput {
				if err := writeGroupJSONSpool(opts, actionreceipt.ReceiptGroupResult{Verdict: verdict, Error: groupErr.Error()}); err != nil {
					return err
				}
			} else {
				_, _ = fmt.Fprintf(stdout, "%s inventory: %v\n", verdict, groupErr)
			}
			return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("receipt group inventory failed: %w", groupErr))
		}
		if groupSummary.Incomplete > 0 || groupSummary.Invalid > 0 {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("receipt group verification failed: %d incomplete and %d invalid group result(s)", groupSummary.Incomplete, groupSummary.Invalid))
		}
		opts.excludeGroups = groupSummary.Groups > 0
		opts.groupForBase = groupForBase
		if opts.legacyJSONSpool != nil {
			stdout = opts.legacyJSONSpool
		}
	}

	var label string
	if opts.asDir {
		// Pass the operator's path unchanged: evidence location resolution
		// checks it for symlinks as the operating system walks it.
		location, locationErr := recorder.ResolveEvidenceLocation(target, opts.locationID)
		if locationErr != nil {
			return evidenceLocationError(fmt.Errorf("resolve evidence location: %w", locationErr))
		}
		clean := location.Dir
		if opts.excludeGroups {
			legacy, legacyErr := actionreceipt.ResolveBaseSessionsExcludingReceiptGroups(clean, opts.sessionID)
			if legacyErr != nil {
				return evidenceLocationError(fmt.Errorf("listing legacy receipt chains: %w", legacyErr))
			}
			if len(legacy) == 0 && opts.groupForBase {
				return nil
			}
		}
		if handled, setErr := runChainSetIfRuns(stdout, stderr, location, trust, opts); handled || setErr != nil {
			return setErr
		}
		label = fmt.Sprintf("%s (session %s)", clean, opts.sessionID)
		receipts, evidence, extractErr := readChainSessionInput(location, opts.sessionID)
		if extractErr != nil {
			err := fmt.Errorf("extract receipts: %w", extractErr)
			// Report the failure the way every other chain outcome is
			// reported, so --json never leaves a consumer with empty output.
			// Changed evidence reached no verdict; anything else, such as an
			// ambiguous sequence start, is a broken chain.
			switch {
			case opts.jsonOutput:
				writeJSON(stdout, chainReport{Path: label, Error: err.Error()})
			case errors.Is(extractErr, recorder.ErrEvidenceChanged):
				_, _ = fmt.Fprintf(stderr, "VERIFICATION INCOMPLETE: %s\n  error:      %s\n", label, err)
			default:
				emitChainReport(stdout, stderr, chainReport{Path: label, Error: err.Error()}, false)
			}
			return evidenceContentError(err)
		}
		if len(evidence) > 0 {
			return verifyEvidenceChain(stdout, stderr, label, evidence, receipts, trust, opts)
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
	actions, evidence, readErr := readChainFileInput(filepath.Base(clean), resolved, trust)
	if readErr != nil {
		emitChainReport(stdout, stderr, chainReport{Path: label, Error: readErr.Error()}, opts.jsonOutput)
		return evidenceContentError(readErr)
	}
	if len(evidence) > 0 {
		return verifyEvidenceChain(stdout, stderr, label, evidence, actions, trust, opts)
	}
	return verifyActionChain(stdout, stderr, label, actions, trust, opts)
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

// readChainFileInput keeps format detection and extraction inside one secured
// file snapshot. Only per-line format limits apply, not an artifact byte budget.
func readChainFileInput(name, path string, trust chainTrust) ([]actionreceipt.Receipt, []contractreceipt.EvidenceReceipt, error) {
	var actions []actionreceipt.Receipt
	var evidence []contractreceipt.EvidenceReceipt
	err := recorder.WalkEvidenceFileReader(path, func(input io.ReadSeeker) error {
		bare, rawReceipts, err := parseBareActionReceiptJSONL(input)
		if err != nil {
			return err
		}
		if bare {
			actions = rawReceipts
			return nil
		}
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			return err
		}
		entries, entryErr := recorder.ReadHistoryEntriesFromReader(input)
		if entryErr == nil {
			if len(trust.endorsements) > 0 && len(entries) > 0 && entries[0].SessionID != trust.session {
				return fmt.Errorf("endorsed receipt session %q does not match evidence session %q", trust.session, entries[0].SessionID)
			}
			var isRecorder bool
			actions, evidence, isRecorder, err = actionreceipt.RecorderFileChains(name, entries)
			if err != nil {
				return err
			}
			if isRecorder {
				if _, err := input.Seek(-1, io.SeekEnd); err != nil {
					return err
				}
				var last [1]byte
				if _, err := io.ReadFull(input, last[:]); err != nil {
					return err
				}
				if last[0] != '\n' {
					return fmt.Errorf("%w: recorder file has an unterminated final record", recorder.ErrTornTail)
				}
				return nil
			}
		}
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			return err
		}
		evidence, err = contractreceipt.ExtractEvidenceReceiptsFromReader(input)
		if err != nil {
			return err
		}
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if len(evidence) > 0 && !hasActionReceiptEntry(input) {
			return nil
		}
		// The legacy extractor retains its raw-receipt compatibility. The outer
		// snapshot check binds this read to the descriptor used for classification.
		actions, err = actionreceipt.ExtractReceipts(path)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return actions, evidence, nil
}

// isBareActionReceiptJSONL is for bounded audit-packet evidence artifacts.
// Complete standalone history uses readChainFileInput instead.
func isBareActionReceiptJSONL(path string) (bool, []byte, error) {
	data, err := readVerifierFile(path)
	if err != nil {
		return false, nil, fmt.Errorf("read evidence file: %w", err)
	}
	bare, _, err := parseBareActionReceiptJSONL(bytes.NewReader(data))
	return bare, data, err
}

func parseBareActionReceiptJSONL(input io.Reader) (bool, []actionreceipt.Receipt, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64<<10), 10<<20)
	var receipts []actionreceipt.Receipt
	for scanner.Scan() {
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		r, err := actionreceipt.Unmarshal(raw)
		if err != nil || r.Version != actionreceipt.ReceiptVersion || r.Signature == "" || r.SignerKey == "" {
			return false, nil, nil
		}
		receipts = append(receipts, r)
	}
	if err := scanner.Err(); err != nil {
		return false, nil, fmt.Errorf("scan evidence file: %w", err)
	}
	return len(receipts) > 0, receipts, nil
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
	return runEvidenceChainWith(stdout, stderr, label, trust, opts, func() ([]contractreceipt.EvidenceReceipt, error) {
		return contractreceipt.ExtractEvidenceReceiptsBytes(data)
	}, func() ([]actionreceipt.Receipt, error) {
		if !hasActionReceiptEntry(bytes.NewReader(data)) {
			return nil, nil
		}
		return actionreceipt.ExtractReceiptsBytes(data)
	})
}

func readChainSessionInput(location recorder.EvidenceLocation, session string) ([]actionreceipt.Receipt, []contractreceipt.EvidenceReceipt, error) {
	var actions []actionreceipt.Receipt
	var evidence []contractreceipt.EvidenceReceipt
	err := recorder.WithSessionHistorySnapshot(location, session, func() error {
		var readErr error
		evidence, readErr = contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir(location, session)
		if readErr != nil {
			return readErr
		}
		if len(evidence) > 0 {
			actions, readErr = sessionActionReceipts(location, session)
		} else {
			actions, readErr = actionreceipt.ExtractReceiptsFromResolvedSessionDir(location, session)
		}
		return readErr
	})
	if err != nil {
		return nil, nil, err
	}
	return actions, evidence, nil
}

// actionReceiptEntryType is the recorder entry type of an ActionReceipt v1.
const actionReceiptEntryType = "action_receipt"

// hasActionReceiptEntry reports whether evidence holds an action_receipt
// entry. It reads each line's type the way the EvidenceReceipt v2 extractor
// does, so the two agree on what every line is. Evidence without one has no
// ActionReceipt v1 chain whatever its format: a v2-only file written as bare
// entry lines is not recorder output, and the v1 extractor rejects it rather
// than returning an empty chain. A scan error answers true, so the strict
// extractor runs and reports it.
func hasActionReceiptEntry(r io.Reader) bool {
	scanner := bufio.NewScanner(r)
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
//
// The probe uses the recorder's authoritative session walk, so the session's
// length and unrelated files in the directory cannot hide its action chain.
func sessionActionReceipts(location recorder.EvidenceLocation, session string) ([]actionreceipt.Receipt, error) {
	want := filepath.Base(session)
	errFound := errors.New("action receipt found")
	err := recorder.WalkSessionHistoryFiles(location, want, func(_ recorder.SessionHistoryShard, r io.Reader) error {
		if hasActionReceiptEntry(r) {
			return errFound
		}
		return nil
	})
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, errFound) {
		return nil, fmt.Errorf("read evidence session %s: %w", want, err)
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
