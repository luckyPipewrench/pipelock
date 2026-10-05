// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidence"
	"github.com/luckyPipewrench/pipelock/internal/evidence/display"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	sigutil "github.com/luckyPipewrench/pipelock/internal/signing"
)

const unpinnedReceiptBanner = "UNPINNED — signature is self-consistent but the signer was NOT checked against a trusted key"

var errUnsealedRecorder = errors.New("whole-recorder verification incomplete: no transcript_root seal")

// VerifyReceiptCmd returns the "verify-receipt" cobra command.
func VerifyReceiptCmd() *cobra.Command {
	var expectedKeys []string
	var chainDir string
	var sessionID string
	var locationID string
	var allowUnpinned bool
	var allowUnanchoredSeal bool
	var fleetReport bool
	var cleanReport string
	var showRaw bool
	var hexdump bool
	var posturePath string
	var postureKey string
	var endorsementPaths []string
	var wholeRecorder bool
	var requireSeal bool

	cmd := &cobra.Command{
		Use:   "verify-receipt [file]",
		Short: "Verify a signed action receipt or receipt chain",
		Long: `Verifies Ed25519 signatures on action receipts and Fleet Receipt Reports.

For a single receipt JSON file: verifies the signature and prints details.
For a flight recorder JSONL file: extracts all receipts and verifies the
receipt hash chain (prev_hash linkage, seq continuity, signatures). Pass
--whole-recorder to also verify every recorder entry present, its taxonomy,
and the transcript_root seal. For a multi-file chain spanning restarts or
rotations, pass --chain DIR.

A current run writes an ActionReceipt v1 chain and an EvidenceReceipt v2
chain into the same files; every mode verifies both, and the result is valid
only when every chain present verifies. A single file must hold the session
its name claims, and its recorder entry hash chain must hold from genesis.

Each process run records its own chain ("<base>.run.<id>"). With --chain and
no --session, every chain of the base is verified, then restart continuity:
each optional signed link file beside the chains must name the exact tail of
the run it continues, under a trusted or endorsed key. Runs no link file
continues are listed as unlinked. That is normal for a first run or for
concurrent runs, and it is also what a deleted link file looks like, so a
passing result does not prove no run's evidence is missing. Pass --session
to verify one chain; continuity for its base is still verified, and any
finding in the base, including two runs that share a signed run nonce, fails
the result.

Full chain verification (--chain, --whole-recorder) is for a recorder that is
not being written while it is verified: stop the writer, or copy the recorder
directory and verify the copy. A change during verification is detected on a
best-effort basis: a shard or link file added, removed, replaced, or resized,
or a link file's bytes changed, fails the result as a recorder that changed
while being verified. A same-size in-place rewrite of a shard by a process
with write access to the evidence directory is outside what an offline
verifier can rule out. For a check of a live recorder, run
"pipelock evidence doctor DIR".
For a Fleet Receipt Report DSSE envelope, pass --fleet-report.

Signing-key rotation: a chain that rotated its signing key splits into
segments. Each segment's key must be trusted. Pass --key once per trusted
key to verify across a rotation; the offending key is named if a segment is
signed by an untrusted key. With no --key, the first segment's key is trusted
on first use and any rotation is flagged for you to confirm. Unpinned
verification is structural-only and exits non-zero unless --allow-unpinned is
passed explicitly. Alternatively, pass --rotation-endorsement for each
old-key-signed rotation authorization and pin only the genesis root key. The
endorsement path never uses trust-on-first-use: at least one --key is required.

Exit 0 = the receipt is valid and the requested report was delivered; exit 1 = invalid, malformed, refused (a symlink inside an evidence directory, an entry filed under the wrong session), or report delivery failed; exit 2 = usage or configuration error, such as a malformed --key or a missing directory.

Examples:
  pipelock verify-receipt receipt.json
  pipelock verify-receipt evidence-proxy.run.<id>-0.jsonl
  pipelock verify-receipt --chain /var/lib/pipelock/evidence
  pipelock verify-receipt receipt.json --key 70b991eb...
  pipelock verify-receipt --chain DIR --key old.key --key new.key
  pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --key fleet-report.pub
  pipelock verify-receipt receipt.json --allow-unpinned`,
		Args: func(_ *cobra.Command, args []string) error {
			return validateReceiptSourceArgs(args, chainDir)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			out := &firstOutputErrWriter{w: cmd.OutOrStdout()}
			if requireSeal && !wholeRecorder {
				return configError(errors.New("--require-seal requires --whole-recorder"))
			}
			trustedKeys, err := resolveExpectedKeyHexes(expectedKeys)
			if err != nil {
				return configError(fmt.Errorf("loading public key: %w", err))
			}
			if len(expectedKeys) > 0 && len(trustedKeys) == 0 {
				return configError(fmt.Errorf("--key was provided but no valid signer keys were resolved"))
			}
			var resolvedLocation *recorder.EvidenceLocation
			if chainDir != "" && !fleetReport {
				location, locationErr := recorder.ResolveEvidenceLocation(chainDir, locationID)
				if locationErr != nil {
					return evidenceReadError(fmt.Errorf("extracting session receipts: resolve evidence location: %w", locationErr))
				}
				resolvedLocation = &location
				chainDir = location.Dir
			}
			if cleanReport != "" {
				protected := cliutil.ExistingFileLabels("--key", expectedKeys)
				maps.Copy(protected, cliutil.ExistingFileLabels("the receipt input", args))
				if resolvedLocation != nil {
					maps.Copy(protected, cliutil.ExistingRegularFiles("the receipt input", resolvedLocation.Dir))
				}
				if err := cliutil.RefuseOutputAliases(
					protected,
					map[string]string{"--clean-report": cleanReport},
				); err != nil {
					return err
				}
			}
			if len(endorsementPaths) > 0 {
				switch {
				case fleetReport:
					return configError(fmt.Errorf("--rotation-endorsement cannot be combined with --fleet-report"))
				case cleanReport != "":
					return configError(fmt.Errorf("--rotation-endorsement cannot be combined with --clean-report"))
				case chainDir == "" && !strings.HasSuffix(args[0], ".jsonl"):
					return configError(fmt.Errorf("--rotation-endorsement requires --chain or a JSONL receipt file"))
				case len(trustedKeys) == 0:
					return configError(errors.New("--rotation-endorsement requires --key: an endorsement is authority only under a trusted root key"))
				}
			}
			if wholeRecorder && cleanReport != "" {
				return configError(fmt.Errorf("--whole-recorder cannot be combined with --clean-report"))
			}
			verifyOpts := verifyReceiptOptions{
				AllowUnpinned:       allowUnpinned,
				AllowUnanchoredSeal: allowUnanchoredSeal,
				SessionID:           sessionID,
				Print: receiptPrintOptions{
					ShowRaw: showRaw,
					Hexdump: hexdump,
				},
				Posture: receiptPostureOptions{
					Path:   posturePath,
					KeyHex: postureKey,
				},
			}
			for _, endorsementPath := range endorsementPaths {
				endorsement, loadErr := receipt.LoadRotationEndorsementFile(endorsementPath)
				if loadErr != nil {
					return configError(fmt.Errorf("loading --rotation-endorsement %q: %w", endorsementPath, loadErr))
				}
				verifyOpts.RotationEndorsements = append(verifyOpts.RotationEndorsements, endorsement)
			}
			if fleetReport {
				if wholeRecorder {
					return configError(fmt.Errorf("--whole-recorder cannot be combined with --fleet-report"))
				}
				if locationID != "" {
					return configError(fmt.Errorf("--location requires --chain"))
				}
				if chainDir != "" {
					return configError(fmt.Errorf("--fleet-report cannot be combined with --chain"))
				}
				if cmd.Flags().Changed("session") {
					return configError(fmt.Errorf("--fleet-report cannot be combined with --session"))
				}
				return outputResult(out, verifyFleetReportWithOptions(out, args[0], trustedKeys, allowUnpinned))
			}
			if resolvedLocation != nil {
				if cleanReport == "" {
					if wholeRecorder {
						verifyOpts.RequireSeal = requireSeal
						return outputResult(out, verifyWholeRecorderDir(out, *resolvedLocation, sessionID, cmd.Flags().Changed("session"), trustedKeys, verifyOpts))
					}
					return outputResult(out, verifyChainDirWithContinuity(out, *resolvedLocation, sessionID, cmd.Flags().Changed("session"), trustedKeys, verifyOpts))
				}
				if !cmd.Flags().Changed("session") {
					sessionID, err = resolveOneReceiptSession(*resolvedLocation, sessionID)
					if err != nil {
						return err
					}
				}
				receipts, extractErr := receipt.ExtractReceiptsFromResolvedSessionDir(*resolvedLocation, sessionID)
				if extractErr != nil {
					return evidenceReadError(fmt.Errorf("extracting session receipts: %w", extractErr))
				}
				evidenceReceipts, evidenceErr := contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir(*resolvedLocation, sessionID)
				if evidenceErr != nil {
					return evidenceReadError(fmt.Errorf("extracting session evidence receipts: %w", evidenceErr))
				}
				label := fmt.Sprintf("%s (session %s)", resolvedLocation.Dir, sessionID)
				return outputResult(out, verifyCleanReport(out, label, receipts, evidenceReceipts, trustedKeys, allowUnpinned, cleanReport))
			}
			if locationID != "" {
				return configError(fmt.Errorf("--location requires --chain"))
			}

			// Resolve the operator's path before any reader cleans it. Cleaning
			// symlink/.. first can select a different file from the one opened by
			// normal filesystem path traversal. The file is read at the resolved
			// path, but a recorder file is bound to the session named by the
			// operator's own filename: a link named for one run that points at
			// another run's file must not take the target's name.
			path, resolveErr := filepath.EvalSymlinks(args[0])
			name := filepath.Base(args[0])
			if resolveErr != nil {
				if wholeRecorder && strings.HasSuffix(args[0], ".jsonl") {
					return configError(fmt.Errorf("reading recorder file: resolve %q: %w", args[0], resolveErr))
				}
				return configError(fmt.Errorf("reading receipt: resolve %q: %w", args[0], resolveErr))
			}

			// JSONL files: extract receipts and verify the full chain.
			if strings.HasSuffix(args[0], ".jsonl") {
				if cleanReport != "" {
					receipts, evidenceReceipts, extractErr := extractFileChains(name, path)
					if extractErr != nil {
						return fmt.Errorf("extracting receipts: %w", extractErr)
					}
					return outputResult(out, verifyCleanReport(out, path, receipts, evidenceReceipts, trustedKeys, allowUnpinned, cleanReport))
				}
				if wholeRecorder {
					return outputResult(out, verifyWholeRecorderFromFile(out, name, path, trustedKeys, verifyOpts))
				}
				return outputResult(out, verifyChainFromFileDetailed(out, name, path, trustedKeys, verifyOpts))
			}

			if cleanReport != "" {
				return configError(fmt.Errorf("--clean-report requires --chain or a JSONL receipt file"))
			}
			if wholeRecorder {
				return configError(fmt.Errorf("--whole-recorder requires a recorder JSONL file or --chain directory"))
			}
			// Single receipt JSON file: a lone receipt has no chain to walk,
			// so it verifies against the first supplied key (or its own).
			return outputResult(out, verifySingleReceiptDetailed(out, path, firstOrEmpty(trustedKeys), verifyOpts))
		},
	}

	cmd.Flags().StringArrayVar(&expectedKeys, "key", nil, "trusted signer public key (hex or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&chainDir, "chain", "", "verify the full receipt chain from an evidence directory")
	cmd.Flags().StringVar(&sessionID, "session", "proxy", "receipt chain session ID inside the evidence directory")
	cmd.Flags().StringVar(&locationID, "location", "", "location path relative to the evidence directory")
	cmd.Flags().BoolVar(&wholeRecorder, "whole-recorder", false, "verify every present recorder entry and transcript-root seal")
	cmd.Flags().BoolVar(&requireSeal, "require-seal", false, "with --whole-recorder, fail if any run lacks a transcript-root seal")
	cmd.Flags().BoolVar(&allowUnpinned, "allow-unpinned", false, "allow structural-only verification without a trusted signer key")
	cmd.Flags().BoolVar(&allowUnanchoredSeal, "allow-unanchored-seal", false, "with --whole-recorder, accept a recorder whose transcript_root seal is not covered by a signed checkpoint (recorder entries after the last signed checkpoint that are not receipts are then hash-linked but not authenticated; every action and evidence receipt is still signature-verified)")
	cmd.Flags().BoolVar(&fleetReport, "fleet-report", false, "verify a Fleet Receipt Report DSSE envelope")
	cmd.Flags().StringVar(&cleanReport, "clean-report", "", "write minimal offline-verifiable action report after chain and defer-pair validation")
	cmd.Flags().BoolVar(&showRaw, "show-raw", false, "append raw display fields in human output")
	cmd.Flags().BoolVar(&hexdump, "hexdump", false, "append canonical raw field hexdumps in human output")
	cmd.Flags().StringVar(&posturePath, "posture", "", "signed posture capsule JSON to assess containment")
	cmd.Flags().StringVar(&postureKey, "posture-key", "", "trusted posture capsule public key (hex)")
	cmd.Flags().StringArrayVar(&endorsementPaths, "rotation-endorsement", nil,
		"old-key-signed rotation endorsement JSON; repeat for each endorsed boundary")
	return cmd
}

// firstOutputErrWriter records the first write failure from a command report.
// Individual renderers intentionally ignore fmt write results so they can emit
// all diagnostics to healthy streams; the command boundary returns this error
// only after the requested semantic operation has otherwise succeeded.
type firstOutputErrWriter struct {
	w   io.Writer
	err error
}

func (w *firstOutputErrWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
	}
	return n, err
}

func outputResult(out *firstOutputErrWriter, semanticErr error) error {
	if semanticErr != nil {
		return semanticErr
	}
	return out.err
}

// configError marks a usage or configuration error: exit 2, distinct from a
// verification failure (exit 1).
func configError(err error) error {
	return cliutil.ExitCodeError(cliutil.ExitConfig, err)
}

// evidenceReadError classifies a failure to read evidence. A refusal of the
// evidence itself (a symlink in the evidence root, an entry filed under the
// wrong session) is a verification failure; any other read failure, such as
// a missing directory, is a configuration error.
func evidenceReadError(err error) error {
	if errors.Is(err, recorder.ErrEvidenceRefused) {
		return err
	}
	return configError(err)
}

func firstOrEmpty(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

type receiptPrintOptions struct {
	ShowRaw bool
	Hexdump bool
}

type receiptPostureOptions struct {
	Path   string
	KeyHex string
}

type verifyReceiptOptions struct {
	AllowUnpinned        bool
	RequireSeal          bool
	AllowUnanchoredSeal  bool
	SessionID            string
	Print                receiptPrintOptions
	Posture              receiptPostureOptions
	RotationEndorsements []receipt.RotationEndorsement
}

// resolveOneReceiptSession keeps single-chain outputs unambiguous. The clean
// report has one chain summary, so a base with several runs needs an explicit
// run session rather than silently reporting only one of them.
func resolveOneReceiptSession(location recorder.EvidenceLocation, base string) (string, error) {
	sessions, err := receipt.ResolveBaseSessions(location.Dir, base)
	if err != nil {
		return "", fmt.Errorf("listing receipt chains: %w", err)
	}
	switch len(sessions) {
	case 0:
		return "", fmt.Errorf("no receipt chains found for base %q", base)
	case 1:
		return sessions[0], nil
	default:
		return "", fmt.Errorf("base %q has %d receipt chains; pass --session with a run session for this single-chain output", base, len(sessions))
	}
}

func verifyWholeRecorderDir(out io.Writer, location recorder.EvidenceLocation, sessionID string, explicit bool, trustedKeys []string, opts verifyReceiptOptions) error {
	base := sessionID
	if b, ok := receipt.RunSessionBase(sessionID); ok {
		base = b
	}
	sessions, err := receipt.ResolveBaseSessions(location.Dir, base)
	if err != nil {
		return fmt.Errorf("listing receipt chains: %w", err)
	}
	if len(sessions) == 0 {
		return fmt.Errorf("no recorder chains found for base %q", base)
	}
	report, err := receipt.VerifyBase(location.Dir, base, receipt.BaseVerifyOptions{
		TrustedKeys: trustedKeys, Endorsements: opts.RotationEndorsements,
	})
	if err != nil {
		return fmt.Errorf("restart continuity check incomplete: %w", err)
	}
	if explicit {
		sessions = []string{sessionID}
	}
	var failed []string
	var incomplete []string
	var firstErr error
	for _, session := range sessions {
		chainOpts, chainKeys := chainScopedTrust(report, session, trustedKeys, opts)
		if verifyErr := verifyWholeRecorderFromResolvedSessionDir(out, location, session, chainKeys, chainOpts); verifyErr != nil {
			if errors.Is(verifyErr, errUnsealedRecorder) {
				incomplete = append(incomplete, session)
				if opts.RequireSeal || explicit {
					failed = append(failed, session)
					if firstErr == nil {
						firstErr = verifyErr
					}
				}
			} else {
				failed = append(failed, session)
				if firstErr == nil {
					firstErr = verifyErr
				}
			}
		}
		_, _ = fmt.Fprintln(out)
	}
	printRestartContinuity(out, report)
	if len(incomplete) > 0 {
		_, _ = fmt.Fprintf(out, "INCOMPLETE RUNS (%d): %s\n", len(incomplete), strings.Join(incomplete, ", "))
	}
	if report.EvidenceChangedDuringVerification() {
		return recorderChangedError(location.Dir)
	}
	if len(failed) > 0 {
		if len(sessions) == 1 {
			return firstErr
		}
		return fmt.Errorf("whole-recorder verification failed for %d of %d chain(s): %s", len(failed), len(sessions), strings.Join(failed, ", "))
	}
	if !report.Healthy() {
		return fmt.Errorf("restart continuity: %d link finding(s)", len(report.Findings))
	}
	return nil
}

// Whole-recorder verification runs every check while the recorder is read,
// one entry at a time, and decides only when the read is complete. Each check
// keeps its own first failure, and the report applies them in the fixed
// order the checks have always had, so a recorder gets the same verdict and
// the same message it got when every entry was loaded first. What the scan
// holds is bounded by the shape of the evidence rather than its length: the
// receipt chain walkers' segment and run state, the last transcript_root and
// the at-most-two entries after it, and the signed checkpoints waiting for
// the next receipt's signer (see anchorWalker).

// verifyWholeRecorderFromFile verifies every entry of one recorder file. name
// is the filename the operator gave, which may differ from the base of the
// resolved path when the operator named a symlink.
func verifyWholeRecorderFromFile(out io.Writer, name, path string, trustedKeys []string, opts verifyReceiptOptions) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading recorder file: %w", err)
	}
	defer func() { _ = file.Close() }()
	scan := newWholeRecorderScan(trustedKeys, opts)
	defer scan.close()
	// A file named for a session holds only that session's entries. The
	// refusal is decided after the whole file reads cleanly, as before.
	fileSession, _, named := recorder.ParseEvidenceFilename(name)
	var sessionErr error
	// Stream the handle so the reader's bounded-read limits apply and the
	// file is never held in memory.
	if err := recorder.WalkEntriesFromReader(file, func(e recorder.Entry) error {
		if named && sessionErr == nil && e.SessionID != fileSession {
			sessionErr = recorder.EntrySessionError(e, fileSession)
		}
		scan.add(e)
		return nil
	}); err != nil {
		return fmt.Errorf("whole-recorder verification failed: not a recorder file or recorder integrity error: %w", err)
	}
	if sessionErr != nil {
		_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n  Error:    %s: %v\n", path, name, sessionErr)
		return fmt.Errorf("whole-recorder verification failed: %s: %w", name, sessionErr)
	}
	if err := scan.whole.Err(); err != nil {
		return fmt.Errorf("whole-recorder verification failed: not a recorder file or recorder integrity error: %w", err)
	}
	return scan.report(out, path)
}

func verifyWholeRecorderFromResolvedSessionDir(out io.Writer, location recorder.EvidenceLocation, sessionID string, trustedKeys []string, opts verifyReceiptOptions) error {
	scan := newWholeRecorderScan(trustedKeys, opts)
	defer scan.close()
	query, err := recorder.WalkSessionResolved(location, sessionID, func(e recorder.Entry) error {
		scan.add(e)
		return nil
	})
	if err != nil {
		return fmt.Errorf("reading recorder session: %w", err)
	}
	if query.Truncated {
		_, _ = fmt.Fprintf(out, "INCOMPLETE: evidence session %s exceeded bounded read limits\n", sessionID)
		return fmt.Errorf("whole-recorder verification failed: evidence session %s exceeded bounded read limits", sessionID)
	}
	if err := scan.whole.Err(); err != nil {
		return fmt.Errorf("whole-recorder verification failed: %w", err)
	}
	label := fmt.Sprintf("%s (session %s)", location.Dir, sessionID)
	return scan.report(out, label)
}

// entryMark is the part of an entry the report names.
type entryMark struct {
	typ string
	seq uint64
}

// wholeRecorderScan carries every whole-recorder check through one read.
type wholeRecorderScan struct {
	trustedKeys []string
	opts        verifyReceiptOptions

	whole    receipt.WholeRecorderWalker
	index    int
	receipts int
	chain    receipt.ChainAccumulator
	posture  receiptPostureSummary

	evidenceErr error
	evidence    *receipt.EvidenceChainWalker

	// The last transcript_root, as the in-memory check read it: each root
	// decodes into the same value, the last one wins, and the first that
	// fails to decode is the error.
	rootErr          error
	rootFound        bool
	root             receipt.TranscriptRoot
	rootIndex        int
	rootSessionID    string
	rootReceiptCount int
	rootChain        receipt.ChainResult
	// afterRoot counts the entries after the last root; the first two are
	// all the unsealed-tail check reads.
	afterRoot   int
	afterFirst  entryMark
	afterSecond entryMark

	anchors anchorWalker
}

func newWholeRecorderScan(trustedKeys []string, opts verifyReceiptOptions) *wholeRecorderScan {
	var chain receipt.ChainAccumulator
	if len(opts.RotationEndorsements) > 0 {
		chain = receipt.NewEndorsedChainWalker(opts.SessionID, opts.RotationEndorsements, trustedKeys)
	} else {
		chain = receipt.NewChainWalker(trustedKeys)
	}
	return &wholeRecorderScan{
		trustedKeys: trustedKeys,
		opts:        opts,
		chain:       chain,
		evidence:    receipt.NewEvidenceChainWalker(trustedKeys, contractreceipt.ChainVerifyOptions{}),
		rootIndex:   -1,
		anchors:     anchorWalker{anchor: checkpointAnchor{lastSignedIndex: -1}},
	}
}

// close releases the scan's spill file. report may return before the
// checkpoint anchors are settled (an unsealed or broken recorder never
// reaches them, as before); every caller closes the scan however it ends.
func (s *wholeRecorderScan) close() { s.anchors.close() }

func (s *wholeRecorderScan) add(e recorder.Entry) {
	i := s.index
	s.index++
	r, isReceipt := s.whole.Add(e)
	// Once an earlier check has failed, the verdict is that failure whatever
	// follows, so the signature checks stop; the cheap ones and the reader
	// keep going, because a read failure later in the recorder outranks them.
	failed := s.whole.Err() != nil

	if s.evidenceErr == nil && !failed {
		ev, isEvidence, err := contractreceipt.EvidenceReceiptFromEntry(i, e)
		switch {
		case err != nil:
			s.evidenceErr = err
		case isEvidence:
			s.evidence.Add(ev)
		}
	}
	failed = failed || s.evidenceErr != nil

	if isReceipt {
		s.receipts++
		if !failed {
			s.chain.Add(r)
			s.posture.add(r)
		}
		s.anchors.addReceipt(r)
	}
	s.anchors.addEntry(i, e)

	if s.rootFound {
		switch s.afterRoot {
		case 0:
			s.afterFirst = entryMark{typ: e.Type, seq: e.Sequence}
		case 1:
			s.afterSecond = entryMark{typ: e.Type, seq: e.Sequence}
		}
		s.afterRoot++
	}
	if e.Type == "transcript_root" && s.rootErr == nil {
		s.addRoot(i, e, failed)
	}
}

func (s *wholeRecorderScan) addRoot(i int, e recorder.Entry, failed bool) {
	data := e.RawDetail
	if len(data) == 0 {
		var err error
		data, err = json.Marshal(e.Detail)
		if err != nil {
			s.rootErr = fmt.Errorf("marshal transcript_root detail: %w", err)
			return
		}
	}
	if err := json.Unmarshal(data, &s.root); err != nil {
		s.rootErr = fmt.Errorf("parse transcript_root detail: %w", err)
		return
	}
	s.rootFound = true
	s.rootIndex = i
	s.rootSessionID = e.SessionID
	s.rootReceiptCount = s.receipts
	s.afterRoot = 0
	s.rootChain = receipt.ChainResult{}
	if !failed && s.receipts > 0 {
		// The seal covers the receipt chain up to here. The walker's result
		// now is the verified result of exactly that prefix.
		s.rootChain = s.chain.Result()
	}
}

// report renders the verdict in the order of the checks: evidence receipt
// extraction, the receipt chain, the evidence chain, the seal, the entries
// after the seal, and the checkpoint anchors.
func (s *wholeRecorderScan) report(out io.Writer, label string) error {
	_, _ = fmt.Fprintf(out, "WHOLE-RECORDER: %s\n", label)
	_, _ = fmt.Fprintf(out, "  Mode:      whole-recorder\n")
	_, _ = fmt.Fprintf(out, "  Entries:   %d recorder entries hash-chain-verified and in-taxonomy\n", s.whole.EntryCount())
	if s.evidenceErr != nil {
		_, _ = fmt.Fprintf(out, "  EVIDENCE CHAIN BROKEN: %v\n", s.evidenceErr)
		return fmt.Errorf("evidence receipt chain: %w", s.evidenceErr)
	}
	trustedKeys, opts := s.trustedKeys, s.opts
	evidenceCount := s.evidence.Count()
	if s.receipts == 0 && evidenceCount > 0 {
		// Evidence receipts alone: verify them, but the transcript_root seal
		// covers an action receipt chain, so there is nothing it can seal.
		if err := verifyEvidenceChainResultDetailed(out, label, s.evidence.Result(), trustedKeys, opts); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out, "  INCOMPLETE: no action receipt chain, so no transcript_root seal covers this recorder")
		return errUnsealedRecorder
	}
	chain := s.chain.Result()
	if !chain.Valid || (len(trustedKeys) == 0 && !opts.AllowUnpinned) {
		return verifyChainSummaryDetailed(out, label, s.posture, chain, trustedKeys, opts)
	}
	// Both receipt chains are authenticated by their own signatures. A
	// checkpoint anchors only the entries that are not receipts, so a forged
	// EvidenceReceipt v2 must fail here even when the anchor is waived.
	var evidenceChain contractreceipt.ChainResult
	if evidenceCount > 0 {
		evidenceChain = s.evidence.Result()
		if !evidenceChain.Valid {
			_, _ = fmt.Fprintf(out, "  EVIDENCE CHAIN BROKEN: %s\n", evidenceChain.Error)
			return fmt.Errorf("evidence receipt chain verification failed at seq %d: %s", evidenceChain.BrokenAtSeq, evidenceChain.Error)
		}
	}
	if s.rootErr != nil {
		_, _ = fmt.Fprintf(out, "  SEAL MISMATCH: %v\n", s.rootErr)
		return fmt.Errorf("seal verification failed: %w", s.rootErr)
	}
	if !s.rootFound {
		_, _ = fmt.Fprintln(out, "  INCOMPLETE: no transcript_root seal (recorder still running or tail truncated)")
		return errUnsealedRecorder
	}
	if s.rootReceiptCount == 0 || s.rootReceiptCount > s.receipts {
		_, _ = fmt.Fprintln(out, "  SEAL MISMATCH")
		return fmt.Errorf("seal verification failed: transcript_root has no matching receipt prefix")
	}
	if !s.rootChain.Valid || !transcriptRootMatchesChainSegment(s.root, s.rootSessionID, s.rootChain) {
		_, _ = fmt.Fprintln(out, "  SEAL MISMATCH")
		return fmt.Errorf("seal verification failed: transcript_root does not match its verified receipt-chain segment")
	}
	// The recorder writes exactly one checkpoint after the root on clean
	// shutdown (either the threshold checkpoint the root itself triggers or
	// the final one Close writes, never both), so a sealed recorder may carry
	// at most one entry past the seal and it must be a checkpoint. Anything
	// else there is evidence the seal never committed to.
	if unsealed, ok := s.firstUnsealedAfterRoot(); ok {
		_, _ = fmt.Fprintf(out, "  INCOMPLETE: transcript_root seal precedes later unsealed entries (first: %s at seq %d)\n", unsealed.typ, unsealed.seq)
		return fmt.Errorf("whole-recorder verification incomplete: transcript_root seal precedes later unsealed %s entry at seq %d", unsealed.typ, unsealed.seq)
	}
	// The receipt chain already verified every signer, including a successor
	// authorized by a rotation endorsement. A checkpoint must be signed by the
	// key that was active where it sits, so each one is checked against the
	// signer of the receipt segment it belongs to rather than the union of
	// every key that ever signed.
	anchor, err := s.anchors.finish()
	if err != nil {
		_, _ = fmt.Fprintf(out, "  ANCHOR MISMATCH: %v\n", err)
		return fmt.Errorf("checkpoint anchor verification failed: %w", err)
	}
	rootIndex := s.rootIndex
	// A signed checkpoint authenticates only the entries before it. The seal
	// is the last thing that matters, so the checkpoint that covers it must
	// come after it: with at most one entry allowed past the root, that is
	// the trailing checkpoint, signed. A recorder that signs checkpoints (the
	// default) can have that trailing checkpoint removed, or every signature
	// stripped, by whoever rewrites the file, and an older checkpoint would
	// still verify while everything after it was rewritten. So a seal not
	// covered by a signed checkpoint is refused unless the operator accepts
	// it explicitly. The writer can also legitimately end a session without a
	// trailing checkpoint when its last entry filled a shard, and a recorder
	// configured not to sign never has one; both states go through the same
	// explicit flag and are named in the output.
	if anchor.lastSignedIndex <= rootIndex && !opts.AllowUnanchoredSeal {
		_, _ = fmt.Fprintln(out, "  UNANCHORED: no signed checkpoint covers the transcript_root seal; recorder entries after the last signed checkpoint that are not receipts are hash-linked but not authenticated")
		return fmt.Errorf("whole-recorder verification unanchored: no signed checkpoint covers the transcript_root seal (checkpoints absent, unsigned, or none after the seal); pass --allow-unanchored-seal to accept hash linkage only for the non-receipt entries after the last anchor")
	}
	if err := verifyChainSummaryDetailed(out, label, s.posture, chain, trustedKeys, opts); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "  Receipts:  %d receipts verified\n", chain.ReceiptCount)
	if evidenceCount > 0 {
		_, _ = fmt.Fprintf(out, "  Evidence:  %d evidence receipts verified\n", evidenceChain.ReceiptCount)
	}
	_, _ = fmt.Fprintf(out, "  Seal:      sealed at seq %d\n", s.root.FinalSeq)
	switch {
	case anchor.lastSignedIndex > rootIndex && len(trustedKeys) == 0:
		// Unpinned: the signer came from the receipts in this same file, so it
		// says nothing about provenance. Do not call it trusted.
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified against the file's own signer, which was NOT checked against a trusted key\n", anchor.signed)
	case anchor.lastSignedIndex > rootIndex:
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified; every entry through the seal is committed by a trusted key\n", anchor.signed)
	case anchor.signed > 0:
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified, none after the seal (accepted by --allow-unanchored-seal); recorder entries after seq %d that are not action or evidence receipts are hash-linked but not authenticated\n", anchor.signed, s.anchors.lastSignedSeq)
	default:
		_, _ = fmt.Fprintln(out, "  Anchor:    no signed checkpoint (accepted by --allow-unanchored-seal); recorder entries other than action and evidence receipts are hash-linked but not authenticated; both receipt chains were signature-verified")
	}
	_, _ = fmt.Fprintln(out, "  Limit:     the seal covers the final signing segment; only the recorder's trailing checkpoint may follow it, hash-chain-verified but not sealed")
	return nil
}

// firstUnsealedAfterRoot returns the first entry after the last
// transcript_root that the seal does not account for: the first entry when
// it is not a checkpoint, otherwise the second.
func (s *wholeRecorderScan) firstUnsealedAfterRoot() (entryMark, bool) {
	switch {
	case s.afterRoot == 0:
		return entryMark{}, false
	case s.afterFirst.typ != "checkpoint":
		return s.afterFirst, true
	case s.afterRoot > 1:
		return s.afterSecond, true
	default:
		return entryMark{}, false
	}
}

// checkpointAnchor summarizes how many checkpoints carried a signature that
// verified against a trusted key, how many carried none, and where the last
// verified signature sits (-1 when there is none). Entries after that index
// are covered by no signature.
type checkpointAnchor struct {
	signed          int
	unsigned        int
	lastSignedIndex int
}

// anchorWalker checks every checkpoint entry's span and, when it carries a
// signature, verifies that signature against the key that was active where
// the checkpoint sits: the signer of the most recent receipt before it, or,
// for a checkpoint written in the gap between two signing segments, either
// that key or the signer of the next receipt, since a new writer instance
// can checkpoint before its first receipt. Scoping to the segment means a
// retired key cannot re-sign checkpoints after its rotation and a successor
// cannot sign before its activation. A signed checkpoint commits the chain
// hash of every entry before it, so it is the only authenticated anchor for
// entries that are not receipts; an unsigned checkpoint proves nothing beyond
// hash linkage and is not an anchor. A session may legitimately mix the two
// when sign_checkpoints changed between restarts; that costs nothing, because
// a stripped earlier signature changes that entry's hash and breaks every
// later checkpoint's signature, and a stripped trailing signature leaves the
// seal uncovered. The span must match the checkpoint's position: it ends at
// the preceding entry, starts after the previous checkpoint, and counts
// exactly the entries between; it need not start right after the previous
// checkpoint, because a crash resume starts a new span at the first resumed
// entry, and the span is metadata the signature does not depend on. A
// checkpoint whose detail does not parse, whose span disagrees with its
// position, or whose signature does not verify under its segment's key fails
// closed. What this cannot catch: on a recorder that never signed, a
// rewritten trailing entry with a self-consistent span; the output reports
// that state as unanchored.
//
// The next receipt's signer is unknown when a checkpoint is read, so only a
// signature the previous receipt's signer did not make waits, and it is
// settled at the next receipt. The walker therefore holds just the signed
// checkpoints of one receipt gap that the earlier signer did not sign, which
// for an honest recorder is a new writer's checkpoints before its first
// receipt. The verdict is the failure at the earliest entry, which is the
// failure the in-order check reported.
type anchorWalker struct {
	anchor        checkpointAnchor
	lastSignedSeq uint64

	err      error
	errIndex int
	stopped  bool

	havePrev       bool
	prevSeq        uint64
	havePrevCP     bool
	prevCPSeq      uint64
	seenReceipts   int
	lastReceiptKey string
	// pending holds the signed checkpoints of the current receipt gap that
	// lastReceiptKey (or no key, before the first receipt) did not verify.
	pending pendingCheckpoints
	// maxPending overrides maxPendingCheckpoints when set; tests only.
	maxPending int
}

func (a *anchorWalker) fail(index int, err error) {
	if a.err == nil || index < a.errIndex {
		a.err, a.errIndex = err, index
	}
}

func (a *anchorWalker) signedAt(index int, seq uint64) {
	a.anchor.signed++
	if index > a.anchor.lastSignedIndex {
		a.anchor.lastSignedIndex = index
		a.lastSignedSeq = seq
	}
}

// addReceipt settles the checkpoints waiting for this receipt's signer.
func (a *anchorWalker) addReceipt(r receipt.Receipt) {
	// Every waiting checkpoint was tried under lastReceiptKey, or under no
	// key when no receipt preceded it.
	tried := a.lastReceiptKey
	pub, keyErr := decodeSegmentSignerKey(r.SignerKey)
	a.drainPending(func(p pendingCheckpoint) {
		// The next receipt is a candidate only when its signer differs from
		// the one already tried.
		if tried != "" && r.SignerKey == tried {
			a.fail(p.index, fmt.Errorf("checkpoint at seq %d: signature does not verify under the signer of its receipt segment", p.seq))
			return
		}
		if keyErr != nil {
			a.fail(p.index, fmt.Errorf("checkpoint at seq %d: %w", p.seq, keyErr))
			return
		}
		if !ed25519.Verify(pub, []byte(p.prevHash), p.sig) {
			a.fail(p.index, fmt.Errorf("checkpoint at seq %d: signature does not verify under the signer of its receipt segment", p.seq))
			return
		}
		a.signedAt(p.index, p.seq)
	})
	a.seenReceipts++
	a.lastReceiptKey = r.SignerKey
}

// drainPending settles every waiting checkpoint through settle. Checkpoints
// that could not be read back exactly as held fail verification at the first
// of them, and stop the walk.
func (a *anchorWalker) drainPending(settle func(pendingCheckpoint)) {
	first := a.pending.firstSpilled
	if err := a.pending.drain(settle); err != nil {
		a.fail(first, fmt.Errorf("checkpoint at entry %d: %w", first, err))
		a.stopped = true
	}
}

// close releases what the walker holds outside memory.
func (a *anchorWalker) close() { a.pending.close() }

// addEntry checks entry i when it is a checkpoint. Call it after addReceipt
// for the same entry.
func (a *anchorWalker) addEntry(i int, e recorder.Entry) {
	defer func() {
		a.havePrev = true
		a.prevSeq = e.Sequence
	}()
	// The first failure ended the in-order check, so later checkpoints cannot
	// change the verdict. Waiting checkpoints before it still can.
	if e.Type != "checkpoint" || a.stopped {
		return
	}
	stop := func(err error) {
		a.fail(i, err)
		a.stopped = true
	}
	detailJSON, err := json.Marshal(e.Detail)
	if err != nil {
		stop(fmt.Errorf("checkpoint at seq %d: encoding detail: %w", e.Sequence, err))
		return
	}
	var detail recorder.CheckpointDetail
	if err := json.Unmarshal(detailJSON, &detail); err != nil {
		stop(fmt.Errorf("checkpoint at seq %d: malformed detail: %w", e.Sequence, err))
		return
	}
	if !a.havePrev || detail.LastSeq != a.prevSeq {
		var preceding uint64
		if a.havePrev {
			preceding = a.prevSeq
		}
		stop(fmt.Errorf("checkpoint at seq %d: span ends at seq %d but the preceding entry is seq %d", e.Sequence, detail.LastSeq, preceding))
		return
	}
	// EntryCount-1 == LastSeq-FirstSeq avoids the +1 that would wrap at the
	// top of the sequence space; FirstSeq <= LastSeq is checked first so
	// the subtraction cannot wrap either.
	if detail.FirstSeq > detail.LastSeq || detail.EntryCount == 0 || detail.EntryCount-1 != detail.LastSeq-detail.FirstSeq {
		stop(fmt.Errorf("checkpoint at seq %d: span %d-%d does not hold %d entries", e.Sequence, detail.FirstSeq, detail.LastSeq, detail.EntryCount))
		return
	}
	if a.havePrevCP && detail.FirstSeq <= a.prevCPSeq {
		stop(fmt.Errorf("checkpoint at seq %d: span starts at seq %d, inside the previous checkpoint at seq %d", e.Sequence, detail.FirstSeq, a.prevCPSeq))
		return
	}
	a.havePrevCP = true
	a.prevCPSeq = e.Sequence
	if detail.Signature == "" {
		a.anchor.unsigned++
		return
	}
	var prevPub ed25519.PublicKey
	if a.seenReceipts > 0 {
		prevPub, err = decodeSegmentSignerKey(a.lastReceiptKey)
		if err != nil {
			stop(fmt.Errorf("checkpoint at seq %d: %w", e.Sequence, err))
			return
		}
	}
	sig, err := hex.DecodeString(detail.Signature)
	if err != nil {
		stop(fmt.Errorf("checkpoint at seq %d: decoding signature: %w", e.Sequence, err))
		return
	}
	if prevPub != nil && ed25519.Verify(prevPub, []byte(e.PrevHash), sig) {
		a.signedAt(i, e.Sequence)
		return
	}
	limit := a.maxPending
	if limit <= 0 {
		limit = maxPendingCheckpoints
	}
	if a.pending.len() >= limit {
		// Unreachable by an honest recorder (see maxPendingCheckpoints).
		// Refuse rather than skip: the verdict is a failure, never a pass.
		stop(fmt.Errorf("checkpoint at seq %d: %w", e.Sequence, errTooManyPendingCheckpoints))
		return
	}
	if err := a.pending.add(pendingCheckpoint{index: i, seq: e.Sequence, prevHash: e.PrevHash, sig: sig}); err != nil {
		stop(fmt.Errorf("checkpoint at seq %d: holding it for the next receipt's signer: %w", e.Sequence, err))
	}
}

// finish settles the checkpoints still waiting: with no receipt after them
// the only candidate signer already failed, and with no receipt at all there
// is no signer to name. It releases the spill file.
func (a *anchorWalker) finish() (checkpointAnchor, error) {
	defer a.close()
	a.drainPending(func(p pendingCheckpoint) {
		if a.seenReceipts == 0 {
			a.fail(p.index, fmt.Errorf("checkpoint at seq %d: %w", p.seq, errNoSegmentSigner))
			return
		}
		a.fail(p.index, fmt.Errorf("checkpoint at seq %d: signature does not verify under the signer of its receipt segment", p.seq))
	})
	return a.anchor, a.err
}

var errNoSegmentSigner = errors.New("signed checkpoint present but the recorder holds no receipts to name its signer")

// decodeSegmentSignerKey decodes a receipt signer key for checkpoint
// verification.
func decodeSegmentSignerKey(key string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("decode segment signer key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("segment signer key length=%d want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func transcriptRootMatchesChainSegment(root receipt.TranscriptRoot, sessionID string, chain receipt.ChainResult) bool {
	if root.SessionID != sessionID || len(chain.Segments) == 0 {
		return false
	}
	segment := chain.Segments[len(chain.Segments)-1]
	return root.FinalSeq == chain.FinalSeq && root.RootHash == chain.RootHash && root.ReceiptCount == segment.Count
}

func verifiedChainResult(receipts []receipt.Receipt, trustedKeys []string, opts verifyReceiptOptions) receipt.ChainResult {
	if len(opts.RotationEndorsements) > 0 {
		return receipt.VerifyChainWithEndorsements(opts.SessionID, receipts, opts.RotationEndorsements, trustedKeys)
	}
	return receipt.VerifyChainTrusted(receipts, trustedKeys)
}

func verifySingleReceiptDetailed(out io.Writer, path, expectedKey string, opts verifyReceiptOptions) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading receipt: %w", err)
	}

	r, err := receipt.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("parsing receipt: %w", err)
	}

	if expectedKey == "" {
		if err := receipt.VerifyInternalConsistencyOnly(r); err != nil {
			_, _ = fmt.Fprintf(out, "FAILED: %s: %v\n", path, err)
			return fmt.Errorf("verification failed: %w", err)
		}
		_, _ = fmt.Fprintf(out, "UNPINNED: %s\n", path)
		_, _ = fmt.Fprintln(out, unpinnedReceiptBanner)
		if !opts.AllowUnpinned {
			printReceiptDetails(out, r, opts.Print)
			printReceiptLimits(out)
			if err := printContainmentForReceipts(out, []receipt.Receipt{r}, opts.Posture); err != nil {
				return err
			}
			return fmt.Errorf("verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
		}
		printReceiptDetails(out, r, opts.Print)
		printReceiptLimits(out)
		if err := printContainmentForReceipts(out, []receipt.Receipt{r}, opts.Posture); err != nil {
			return err
		}
		return nil
	}

	if err := receipt.VerifyWithKey(r, expectedKey); err != nil {
		_, _ = fmt.Fprintf(out, "FAILED: %s: %v\n", path, err)
		return fmt.Errorf("verification failed: %w", err)
	}

	_, _ = fmt.Fprintf(out, "OK: %s\n", path)
	printReceiptDetails(out, r, opts.Print)
	printReceiptLimits(out)
	if err := printContainmentForReceipts(out, []receipt.Receipt{r}, opts.Posture); err != nil {
		return err
	}
	return nil
}

func verifyFleetReportWithOptions(out io.Writer, path string, trustedKeys []string, allowUnpinned bool) error {
	data, err := readOperatorFile(path)
	if err != nil {
		return fmt.Errorf("reading fleet receipt: %w", err)
	}
	env, err := fleetreceipt.UnmarshalEnvelope(data)
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED: %s: %v\n", path, err)
		return fmt.Errorf("fleet receipt verification failed: %w", err)
	}
	keyMap, err := fleetTrustedKeyMap(env, trustedKeys)
	if err != nil {
		return err
	}
	result, err := fleetreceipt.VerifyEnvelope(env, keyMap)
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED: %s: %v\n", path, err)
		return fmt.Errorf("fleet receipt verification failed: %w", err)
	}
	if result.Unpinned {
		_, _ = fmt.Fprintf(out, "FLEET RECEIPT UNPINNED: %s\n", path)
		_, _ = fmt.Fprintln(out, unpinnedReceiptBanner)
	} else {
		_, _ = fmt.Fprintf(out, "FLEET RECEIPT OK: %s\n", path)
	}
	_, _ = fmt.Fprintf(out, "  Signer:           %s\n", result.SignerKeyID)
	_, _ = fmt.Fprintf(out, "  Payload SHA-256:  %s\n", result.PayloadSHA256)
	_, _ = fmt.Fprintf(out, "  Org/Fleet:        %s/%s\n", result.Statement.Predicate.OrgID, result.Statement.Predicate.FleetID)
	_, _ = fmt.Fprintf(out, "  Report ID:        %s\n", result.Statement.Predicate.ReportID)
	_, _ = fmt.Fprintf(out, "  Level:            %s\n", result.Statement.Predicate.VerificationLevel)
	_, _ = fmt.Fprintf(out, "  Source batches:   %d\n", result.SourceBatches)
	_, _ = fmt.Fprintf(out, "  Total actions:    %d\n", result.TotalActions)
	_, _ = fmt.Fprintf(out, "  Mediated fraction: %s\n", result.MediatedFraction)
	// Print the predicate's declared verification limits (e.g. "L1 does not
	// replay raw audit-batch payloads during offline verification") so an
	// operator reading a passing report cannot over-read what the level proves.
	// Without this, a PASS looks like full replay verification when L1 only
	// checks the signed report, anchors, ordering, and arithmetic.
	for _, limit := range result.Statement.Predicate.Limits {
		_, _ = fmt.Fprintf(out, "  Limit:            %s\n", resolvedLimitString(limit))
	}
	if result.Unpinned && !allowUnpinned {
		return fmt.Errorf("fleet receipt verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
	}
	return nil
}

func resolvedLimitString(raw string) string {
	return evidence.MustSummary(evidence.LimitID(raw))
}

// fleetTrustedKeyMap builds the verifier's trusted-key map from the operator's
// --key hex public keys. The verifier resolves the trusted public key by the
// envelope's signer key id, which is an operator-chosen label (e.g.
// "fleet-report-2026") that is NOT the hex of the public key. So a supplied key
// is registered under BOTH the envelope's actual signer key id and its own hex
// string: the former is what makes a real, human-labelled key id verify; the
// latter preserves the historical hex-keyid convention. This stays fail-closed
// because the signature must still verify against the resolved public key
// (ed25519.Verify), so trusting a key for the wrong report id only succeeds if
// the bytes genuinely signed the payload.
func fleetTrustedKeyMap(env fleetreceipt.Envelope, keys []string) (map[string]ed25519.PublicKey, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	// A Fleet Receipt Report carries exactly one signature. Bind a lone --key to
	// that signature's key id so a human-labelled key id verifies; with multiple
	// keys we cannot pick which one the label maps to, so we register only by
	// hex and leave id-binding to the historical hex==keyid convention.
	var signerKeyID string
	if len(keys) == 1 && len(env.Signatures) == 1 {
		signerKeyID = strings.TrimSpace(env.Signatures[0].KeyID)
	}
	out := make(map[string]ed25519.PublicKey, len(keys)+1)
	for _, key := range keys {
		raw, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("decode trusted fleet report key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted fleet report key length=%d want %d", len(raw), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(raw)
		out[key] = pub
		if signerKeyID != "" {
			out[signerKeyID] = pub
		}
	}
	return out, nil
}

// readOperatorFile reads a file argument as the operating system opens it:
// symlinks are resolved before any lexical cleaning, so "link/../f" names the
// file beside the link's target rather than the lexical f.
func readOperatorFile(path string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Clean(resolved))
}

func verifyChainFromFile(out io.Writer, path string, trustedKeys []string) error {
	return verifyChainFromFileWithOptions(out, path, trustedKeys, false)
}

func verifyChainFromFileWithOptions(out io.Writer, path string, trustedKeys []string, allowUnpinned bool) error {
	return verifyChainFromFileDetailed(out, filepath.Base(path), path, trustedKeys, verifyReceiptOptions{AllowUnpinned: allowUnpinned})
}

// verifyChainFromFileDetailed verifies the receipt chains of one JSONL file
// read at path. name is the filename the operator gave; a recorder file is
// bound to the session that name claims.
func verifyChainFromFileDetailed(out io.Writer, name, path string, trustedKeys []string, opts verifyReceiptOptions) error {
	// Recorder output: both receipt chains the file holds, after the checks a
	// single file must pass on its own (entries belong to the session its
	// name claims, and the recorder entry hash chain holds). The path the
	// operator named is read as given.
	if entries, readErr := recorder.ReadEntries(filepath.Clean(path)); readErr == nil {
		if len(opts.RotationEndorsements) > 0 && len(entries) > 0 && entries[0].SessionID != opts.SessionID {
			return fmt.Errorf("endorsed receipt session %q does not match evidence session %q", opts.SessionID, entries[0].SessionID)
		}
		actions, evidenceReceipts, isRecorder, chainsErr := receipt.RecorderFileChains(name, entries)
		if chainsErr != nil {
			_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n", path)
			_, _ = fmt.Fprintf(out, "  Error:    %v\n", chainsErr)
			return fmt.Errorf("chain verification failed: %w", chainsErr)
		}
		if isRecorder {
			return verifyTypedChainDetailed(out, path, actions, evidenceReceipts, trustedKeys, opts)
		}
	}
	var (
		receipts []receipt.Receipt
		err      error
	)
	if len(opts.RotationEndorsements) > 0 {
		var evidenceSessionID string
		receipts, evidenceSessionID, err = receipt.ExtractReceiptsWithSessionID(path)
		if err == nil && evidenceSessionID != opts.SessionID {
			return fmt.Errorf("endorsed receipt session %q does not match evidence session %q", opts.SessionID, evidenceSessionID)
		}
	} else {
		receipts, err = receipt.ExtractReceipts(path)
	}
	if err != nil {
		return fmt.Errorf("extracting receipts: %w", err)
	}
	return verifyChainDetailed(out, path, receipts, trustedKeys, opts)
}

// verifyChainDirWithContinuity verifies receipt chains in an evidence
// directory. When the directory holds no run chains of the session's base it
// is exactly the single-session verification. Otherwise it verifies every
// chain of the base (or only the named one when --session was given) and then
// the base's restart continuity, and fails when any chain fails or any link
// file does not verify.
func verifyChainDirWithContinuity(out io.Writer, location recorder.EvidenceLocation, sessionID string, explicit bool, trustedKeys []string, opts verifyReceiptOptions) error {
	base := sessionID
	if b, ok := receipt.RunSessionBase(sessionID); ok {
		base = b
	}
	chains, err := receipt.ResolveBaseSessions(location.Dir, base)
	if err != nil {
		return fmt.Errorf("listing receipt chains: %w", err)
	}
	hasRuns := false
	for _, s := range chains {
		if _, ok := receipt.RunSessionBase(s); ok {
			hasRuns = true
			break
		}
	}
	if !hasRuns {
		return verifyChainFromResolvedSessionDirDetailed(out, location, sessionID, trustedKeys, opts)
	}
	report, err := receipt.VerifyBase(location.Dir, base, receipt.BaseVerifyOptions{
		TrustedKeys:  trustedKeys,
		Endorsements: opts.RotationEndorsements,
	})
	if err != nil {
		_, _ = fmt.Fprintf(out, "RESTART CONTINUITY INCOMPLETE: %s: %v\n", location.Dir, err)
		return fmt.Errorf("restart continuity check incomplete: %w", err)
	}
	targets := chains
	if explicit {
		targets = []string{sessionID}
	}
	var failed []string
	var firstErr error
	for _, s := range targets {
		chainOpts, chainKeys := chainScopedTrust(report, s, trustedKeys, opts)
		if verifyErr := verifyChainFromResolvedSessionDirDetailed(out, location, s, chainKeys, chainOpts); verifyErr != nil {
			failed = append(failed, s)
			if firstErr == nil {
				firstErr = verifyErr
			}
		}
		_, _ = fmt.Fprintln(out)
	}
	printRestartContinuity(out, report)
	if report.EvidenceChangedDuringVerification() {
		// Any chain failure above may be the change itself, so the change
		// is the verdict.
		return recorderChangedError(location.Dir)
	}
	if len(failed) > 0 {
		return fmt.Errorf("chain verification failed for %d of %d chain(s): %s (first: %w)", len(failed), len(targets), strings.Join(failed, ", "), firstErr)
	}
	if !report.Healthy() {
		f := report.Findings[0]
		return fmt.Errorf("restart continuity: %d link finding(s), first %s on %s: %s", len(report.Findings), f.Kind, f.Session, f.Detail)
	}
	return nil
}

// recorderChangedError is the verdict when the recorder directory changed
// while it was verified. It is not a continuity finding: the verifier cannot
// say what the evidence holds, only that it did not hold still.
func recorderChangedError(dir string) error {
	return fmt.Errorf("the recorder in %s changed while it was being verified, so no verdict on its evidence was reached; "+
		"stop the process writing to it, or copy the recorder directory and verify the copy; "+
		"for a check of a live recorder, run `pipelock evidence doctor %s`", dir, dir)
}

// chainScopedTrust narrows the operator's endorsements and keys to one chain.
// A restart-time key change is authorized by an endorsement bound to the
// PREDECESSOR run's tail, which only the link check can place; handing it to
// the single-chain verifier of either run would be rejected as unused. So a
// chain gets only endorsements for its own in-chain rotations, plus the
// successor key when the base check verified an endorsed link into it.
func chainScopedTrust(report receipt.BaseReport, session string, trustedKeys []string, opts verifyReceiptOptions) (verifyReceiptOptions, []string) {
	keys, own := receipt.ScopedChainTrust(report, session, trustedKeys, opts.RotationEndorsements)
	chainOpts := opts
	chainOpts.SessionID = session
	chainOpts.RotationEndorsements = own
	return chainOpts, keys
}

// printRestartContinuity prints a base report. Unlinked runs are always
// listed, because a passing result must not read as proof of continuity.
func printRestartContinuity(out io.Writer, report receipt.BaseReport) {
	label := "RESTART CONTINUITY OK"
	if !report.Healthy() {
		label = "RESTART CONTINUITY FAILED"
	}
	unlinked := report.Unlinked()
	if report.EvidenceChangedDuringVerification() {
		_, _ = fmt.Fprintln(out, "RECORDER CHANGED DURING VERIFICATION: shards or link files were added, removed, replaced, resized, or rewritten while they were read; the findings below describe the change, not the evidence")
	}
	_, _ = fmt.Fprintf(out, "%s: base %q: %d chain(s), %d linked, %d unlinked, %d link finding(s)\n",
		label, report.Base, len(report.Chains), report.LinkCount(), len(unlinked), len(report.Findings))
	for _, c := range report.Chains {
		if s := c.RecoverySeal; s != nil {
			_, _ = fmt.Fprintf(out, "  linked across attested discontinuity: %s continues %s; shard %s byte %d (damage remains)\n", c.Session, s.PredecessorSession, s.Shard, s.DamageOffset)
		}
		if c.Link != nil {
			trust := c.LinkTrust
			if trust == "" {
				trust = "untrusted"
			}
			_, _ = fmt.Fprintf(out, "  linked:   %s continues %s at seq %d (%s)\n", c.Session, c.Link.PredecessorSession, c.Link.PredecessorTailSeq, trust)
		}
	}
	for _, s := range unlinked {
		_, _ = fmt.Fprintf(out, "  unlinked: %s\n", s)
	}
	for _, f := range report.Findings {
		_, _ = fmt.Fprintf(out, "  - %s: %s: %s\n", f.Kind, f.Session, f.Detail)
	}
	_, _ = fmt.Fprintln(out, "  Note: an unlinked run claims no predecessor. That is normal for a first run or concurrent runs,")
	_, _ = fmt.Fprintln(out, "  and it is also what a deleted link file looks like: this does not prove no run's evidence is missing.")
}

func verifyChainFromResolvedSessionDirDetailed(out io.Writer, location recorder.EvidenceLocation, sessionID string, trustedKeys []string, opts verifyReceiptOptions) error {
	label := fmt.Sprintf("%s (session %s)", location.Dir, sessionID)
	receipts, err := receipt.ExtractReceiptsFromResolvedSessionDir(location, sessionID)
	if err != nil {
		_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n  Error:    %v\n", label, err)
		return fmt.Errorf("extracting session receipts: %w", err)
	}
	evidenceReceipts, err := contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir(location, sessionID)
	if err != nil {
		_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n  Error:    %v\n", label, err)
		return fmt.Errorf("extracting session evidence receipts: %w", err)
	}
	return verifyTypedChainDetailed(out, label, receipts, evidenceReceipts, trustedKeys, opts)
}

// extractFileChains reads both receipt chains of a JSONL file: recorder output
// through the per-file checks, else the raw receipt JSONL compatibility path,
// which has no EvidenceReceipt v2 chain.
// name is the operator's filename, which binds a recorder file to its session.
func extractFileChains(name, path string) ([]receipt.Receipt, []contractreceipt.EvidenceReceipt, error) {
	if entries, readErr := recorder.ReadEntries(filepath.Clean(path)); readErr == nil {
		actions, evidenceReceipts, isRecorder, err := receipt.RecorderFileChains(name, entries)
		if err != nil || isRecorder {
			return actions, evidenceReceipts, err
		}
	}
	actions, err := receipt.ExtractReceipts(path)
	return actions, nil, err
}

// verifyTypedChainDetailed verifies every receipt chain one session or file
// holds. A current run writes an ActionReceipt v1 chain and an EvidenceReceipt
// v2 chain into the same files, each signed on its own, so a forged receipt in
// one leaves the other intact: both must verify. Evidence holding only v2
// receipts is verified as a v2 chain. Evidence with no v2 receipts prints
// exactly what the action chain verification always printed.
func verifyTypedChainDetailed(out io.Writer, label string, receipts []receipt.Receipt, evidenceReceipts []contractreceipt.EvidenceReceipt, trustedKeys []string, opts verifyReceiptOptions) error {
	if len(evidenceReceipts) == 0 {
		return verifyChainDetailed(out, label, receipts, trustedKeys, opts)
	}
	var actionErr error
	if len(receipts) > 0 {
		actionErr = verifyChainDetailed(out, label, receipts, trustedKeys, opts)
	}
	evidenceErr := verifyEvidenceChainDetailed(out, label, evidenceReceipts, trustedKeys, opts)
	if actionErr != nil {
		return actionErr
	}
	return evidenceErr
}

// verifyEvidenceChainDetailed verifies and prints an EvidenceReceipt v2 chain.
func verifyEvidenceChainDetailed(out io.Writer, label string, evidenceReceipts []contractreceipt.EvidenceReceipt, trustedKeys []string, opts verifyReceiptOptions) error {
	res := receipt.VerifyEvidenceChainTrusted(evidenceReceipts, trustedKeys, contractreceipt.ChainVerifyOptions{})
	return verifyEvidenceChainResultDetailed(out, label, res, trustedKeys, opts)
}

func verifyEvidenceChainResultDetailed(out io.Writer, label string, res contractreceipt.ChainResult, trustedKeys []string, opts verifyReceiptOptions) error {
	if !res.Valid {
		_, _ = fmt.Fprintf(out, "EVIDENCE CHAIN BROKEN: %s\n", label)
		_, _ = fmt.Fprintf(out, "  Error:    %s\n", res.Error)
		_, _ = fmt.Fprintf(out, "  Broke at: seq %d\n", res.BrokenAtSeq)
		return fmt.Errorf("evidence receipt chain verification failed at seq %d: %s", res.BrokenAtSeq, res.Error)
	}
	unpinned := len(trustedKeys) == 0
	if unpinned {
		_, _ = fmt.Fprintf(out, "EVIDENCE CHAIN UNPINNED: %s\n", label)
	} else {
		_, _ = fmt.Fprintf(out, "EVIDENCE CHAIN VALID: %s\n", label)
	}
	_, _ = fmt.Fprintf(out, "  Evidence receipts: %d\n", res.ReceiptCount)
	_, _ = fmt.Fprintf(out, "  Final seq: %d\n", res.FinalSeq)
	_, _ = fmt.Fprintf(out, "  Root hash: %s\n", res.RootHash)
	_, _ = fmt.Fprintf(out, "  Signer:    %s\n", res.SignerKeyID)
	if unpinned {
		_, _ = fmt.Fprintln(out, unpinnedReceiptBanner)
		if !opts.AllowUnpinned {
			return fmt.Errorf("evidence receipt chain verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
		}
	}
	return nil
}

func verifyChain(out io.Writer, label string, receipts []receipt.Receipt, trustedKeys []string) error {
	return verifyChainWithOptions(out, label, receipts, trustedKeys, false)
}

func verifyChainWithOptions(out io.Writer, label string, receipts []receipt.Receipt, trustedKeys []string, allowUnpinned bool) error {
	return verifyChainDetailed(out, label, receipts, trustedKeys, verifyReceiptOptions{AllowUnpinned: allowUnpinned})
}

func verifyChainDetailed(out io.Writer, label string, receipts []receipt.Receipt, trustedKeys []string, opts verifyReceiptOptions) error {
	if len(receipts) == 0 {
		_, _ = fmt.Fprintf(out, "No receipts found in %s\n", label)
		return fmt.Errorf("no receipts in %s", label)
	}

	result := verifiedChainResult(receipts, trustedKeys, opts)
	return verifyChainResultDetailed(out, label, receipts, result, trustedKeys, opts)
}

func verifyChainResultDetailed(out io.Writer, label string, receipts []receipt.Receipt, result receipt.ChainResult, trustedKeys []string, opts verifyReceiptOptions) error {
	return verifyChainSummaryDetailed(out, label, summarizeReceiptsForPosture(receipts), result, trustedKeys, opts)
}

func verifyChainSummaryDetailed(out io.Writer, label string, posture receiptPostureSummary, result receipt.ChainResult, trustedKeys []string, opts verifyReceiptOptions) error {
	if !result.Valid {
		_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n", label)
		_, _ = fmt.Fprintf(out, "  Error:    %s\n", result.Error)
		_, _ = fmt.Fprintf(out, "  Broke at: seq %d\n", result.BrokenAtSeq)
		if result.UntrustedSignerKey != "" {
			_, _ = fmt.Fprintf(out, "  Untrusted signer key: %s\n", result.UntrustedSignerKey)
			if len(result.EndorsementGaps) > 0 {
				_, _ = fmt.Fprintln(out, "  Rotation endorsement: missing, invalid, or not bound to this chain boundary.")
			} else {
				_, _ = fmt.Fprintln(out, "  If this is a legitimate key rotation, re-run with --key for each trusted key.")
			}
		}
		return fmt.Errorf("chain verification failed at seq %d: %s", result.BrokenAtSeq, result.Error)
	}

	unpinned := len(trustedKeys) == 0
	if unpinned {
		_, _ = fmt.Fprintf(out, "CHAIN UNPINNED: %s\n", label)
	} else {
		_, _ = fmt.Fprintf(out, "CHAIN VALID: %s\n", label)
	}
	_, _ = fmt.Fprintf(out, "  Receipts:  %d\n", result.ReceiptCount)
	_, _ = fmt.Fprintf(out, "  Final seq: %d\n", result.FinalSeq)
	_, _ = fmt.Fprintf(out, "  Root hash: %s\n", result.RootHash)
	_, _ = fmt.Fprintf(out, "  Start:     %s\n", result.StartTime.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(out, "  End:       %s\n", result.EndTime.Format("2006-01-02T15:04:05Z"))
	printSignerKeys(out, result)
	for i, basis := range result.TrustBasis {
		if i < len(result.Segments) {
			_, _ = fmt.Fprintf(out, "  Segment trust: %s (%s)\n", result.Segments[i].SignerKey, basis)
		}
	}
	printReceiptLimits(out)
	if err := printContainmentForSummary(out, posture, opts.Posture); err != nil {
		return err
	}
	if unpinned {
		_, _ = fmt.Fprintln(out, unpinnedReceiptBanner)
		if !opts.AllowUnpinned {
			return fmt.Errorf("chain verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
		}
	}
	return nil
}

type cleanActionReport struct {
	SchemaVersion    string             `json:"schema_version"`
	VerificationMode string             `json:"verification_mode"`
	Chain            cleanChainSummary  `json:"chain"`
	Actions          []cleanActionEntry `json:"actions"`
}

type cleanChainSummary struct {
	Label        string   `json:"label"`
	ReceiptCount uint64   `json:"receipt_count"`
	FinalSeq     uint64   `json:"final_seq"`
	RootHash     string   `json:"root_hash"`
	SignerKeys   []string `json:"signer_keys"`
}

type cleanActionEntry struct {
	ActionID         string `json:"action_id"`
	ParentActionID   string `json:"parent_action_id,omitempty"`
	DeferID          string `json:"defer_id,omitempty"`
	DecisionPhase    string `json:"decision_phase,omitempty"`
	FinalDecision    string `json:"final_decision"`
	ActionType       string `json:"action_type"`
	Target           string `json:"target"`
	Transport        string `json:"transport"`
	Method           string `json:"method,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
	Principal        string `json:"principal,omitempty"`
	Actor            string `json:"actor,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
	PolicyHash       string `json:"policy_hash,omitempty"`
	Layer            string `json:"layer,omitempty"`
	Pattern          string `json:"pattern,omitempty"`
	Severity         string `json:"severity,omitempty"`
	Timestamp        string `json:"timestamp"`
	ResolutionPolicy string `json:"resolution_policy,omitempty"`
	ResolutionSource string `json:"resolution_source,omitempty"`
}

func verifyCleanReport(out io.Writer, label string, receipts []receipt.Receipt, evidenceReceipts []contractreceipt.EvidenceReceipt, trustedKeys []string, allowUnpinned bool, reportPath string) error {
	if len(receipts) == 0 {
		return fmt.Errorf("no receipts found in %s", label)
	}
	result := receipt.VerifyChainTrusted(receipts, trustedKeys)
	if !result.Valid {
		return fmt.Errorf("chain verification failed at seq %d: %s", result.BrokenAtSeq, result.Error)
	}
	// The report lists actions only, but the evidence it is drawn from must
	// verify whole: a forged EvidenceReceipt v2 beside intact actions fails.
	if len(evidenceReceipts) > 0 {
		if res := receipt.VerifyEvidenceChainTrusted(evidenceReceipts, trustedKeys, contractreceipt.ChainVerifyOptions{}); !res.Valid {
			return fmt.Errorf("evidence receipt chain verification failed at seq %d: %s", res.BrokenAtSeq, res.Error)
		}
	}
	if len(trustedKeys) == 0 && !allowUnpinned {
		return fmt.Errorf("chain verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
	}
	report, err := buildCleanActionReport(label, receipts, result)
	if err != nil {
		return err
	}
	report.SchemaVersion = "pipelock.clean_report.v1"
	report.VerificationMode = "pinned_provenance"
	if len(trustedKeys) == 0 {
		report.VerificationMode = "unpinned_structural"
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal clean report: %w", err)
	}
	if err := atomicfile.Write(filepath.Clean(reportPath), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write clean report: %w", err)
	}
	if report.VerificationMode == "unpinned_structural" {
		_, _ = fmt.Fprintf(out, "CLEAN REPORT UNPINNED (structural verification only): %s\n", label)
	} else {
		_, _ = fmt.Fprintf(out, "CLEAN REPORT VALID (pinned provenance): %s\n", label)
	}
	_, _ = fmt.Fprintf(out, "  Actions:   %d\n", len(report.Actions))
	_, _ = fmt.Fprintf(out, "  Report:    %s\n", reportPath)
	return nil
}

func buildCleanActionReport(label string, receipts []receipt.Receipt, result receipt.ChainResult) (cleanActionReport, error) {
	entries := make([]cleanActionEntry, 0, len(receipts))
	deferByID := map[string]receipt.ActionRecord{}
	resolutions := map[string][]receipt.ActionRecord{}
	for _, rcpt := range receipts {
		ar := rcpt.ActionRecord
		if ar.DecisionPhase == receipt.DecisionPhaseDefer {
			if ar.DeferID == "" {
				return cleanActionReport{}, fmt.Errorf("defer receipt %s missing defer_id", ar.ActionID)
			}
			// A defer_id identifies exactly one held action, so two defer
			// receipts sharing it is never legitimate. Rejecting fails closed:
			// silently overwriting would let a duplicate pass the per-defer
			// resolution-pairing check below against only the last record.
			if prior, exists := deferByID[ar.DeferID]; exists {
				return cleanActionReport{}, fmt.Errorf(
					"duplicate defer_id %s in receipts %s and %s",
					ar.DeferID, prior.ActionID, ar.ActionID,
				)
			}
			deferByID[ar.DeferID] = ar
		}
		if ar.DecisionPhase == receipt.DecisionPhaseResolution {
			if ar.DeferID == "" || ar.ParentActionID == "" {
				return cleanActionReport{}, fmt.Errorf("resolution receipt %s missing defer linkage", ar.ActionID)
			}
			resolutions[ar.DeferID] = append(resolutions[ar.DeferID], ar)
		}
		entries = append(entries, cleanActionEntry{
			ActionID:         ar.ActionID,
			ParentActionID:   ar.ParentActionID,
			DeferID:          ar.DeferID,
			DecisionPhase:    ar.DecisionPhase,
			FinalDecision:    ar.Verdict,
			ActionType:       string(ar.ActionType),
			Target:           ar.Target,
			Transport:        ar.Transport,
			Method:           ar.Method,
			RequestID:        ar.RequestID,
			Principal:        ar.Principal,
			Actor:            ar.Actor,
			SessionID:        ar.SessionID,
			PolicyHash:       ar.PolicyHash,
			Layer:            ar.Layer,
			Pattern:          ar.Pattern,
			Severity:         ar.Severity,
			Timestamp:        ar.Timestamp.Format("2006-01-02T15:04:05Z"),
			ResolutionPolicy: ar.ResolutionPolicy,
			ResolutionSource: ar.ResolutionSource,
		})
	}
	for deferID, deferRecord := range deferByID {
		matches := resolutions[deferID]
		if len(matches) != 1 {
			return cleanActionReport{}, fmt.Errorf("defer %s has %d resolution receipts", deferID, len(matches))
		}
		resolution := matches[0]
		if resolution.ParentActionID != deferRecord.ActionID {
			return cleanActionReport{}, fmt.Errorf("defer %s resolution parent mismatch", deferID)
		}
		if resolution.ChainSeq <= deferRecord.ChainSeq {
			return cleanActionReport{}, fmt.Errorf("defer %s resolution appears before defer receipt", deferID)
		}
		if resolution.Principal != deferRecord.Principal || resolution.Actor != deferRecord.Actor || resolution.SessionID != deferRecord.SessionID {
			return cleanActionReport{}, fmt.Errorf("defer %s resolution identity changed", deferID)
		}
		switch resolution.Verdict {
		case "allow", "block", "ask":
		default:
			return cleanActionReport{}, fmt.Errorf("defer %s resolved to non-terminal verdict %q", deferID, resolution.Verdict)
		}
	}
	for deferID := range resolutions {
		if _, ok := deferByID[deferID]; !ok {
			return cleanActionReport{}, fmt.Errorf("resolution for unknown defer %s", deferID)
		}
	}
	return cleanActionReport{
		Chain: cleanChainSummary{
			Label:        label,
			ReceiptCount: result.ReceiptCount,
			FinalSeq:     result.FinalSeq,
			RootHash:     result.RootHash,
			SignerKeys:   append([]string(nil), result.SignerKeys...),
		},
		Actions: entries,
	}, nil
}

// printSignerKeys reports the per-segment signer keys for a verified chain. When
// the chain rotated keys, this is the operator's confirmation surface: the
// verifier proved the segments are cryptographically linked via valid
// KeyTransition boundaries, but ONLY the operator knows whether every key is one
// of theirs. A chain that verifies but lists an unexpected key is a signal to
// investigate, not a pass.
func printSignerKeys(out io.Writer, result receipt.ChainResult) {
	if len(result.SignerKeys) <= 1 {
		if len(result.SignerKeys) == 1 {
			_, _ = fmt.Fprintf(out, "  Signer:    %s\n", result.SignerKeys[0])
		}
		return
	}
	_, _ = fmt.Fprintf(out, "  Segments:  %d (signing key rotated)\n", len(result.Segments))
	_, _ = fmt.Fprintf(out, "  CONFIRM every signer key below is one of yours:\n")
	for i, seg := range result.Segments {
		_, _ = fmt.Fprintf(out, "    segment %d: seq %d-%d  signer %s%s\n",
			i, seg.FirstSeq, seg.FinalSeq, seg.SignerKey, boundaryNote(seg.Boundary))
	}
}

func boundaryNote(boundary bool) string {
	if boundary {
		return "  (key rotation)"
	}
	return ""
}

func printReceiptDetails(out io.Writer, r receipt.Receipt, opts receiptPrintOptions) {
	_, _ = fmt.Fprintf(out, "  Action ID:   %s\n", r.ActionRecord.ActionID)
	_, _ = fmt.Fprintf(out, "  Action Type: %s\n", r.ActionRecord.ActionType)
	_, _ = fmt.Fprintf(out, "  Verdict:     %s\n", r.ActionRecord.Verdict)
	printReceiptDisplayField(out, "  Target:      ", r.ActionRecord.Target, opts)
	_, _ = fmt.Fprintf(out, "  Transport:   %s\n", r.ActionRecord.Transport)
	_, _ = fmt.Fprintf(out, "  Timestamp:   %s\n", r.ActionRecord.Timestamp.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(out, "  Signer:      %s\n", r.SignerKey)
	_, _ = fmt.Fprintf(out, "  Chain seq:   %d\n", r.ActionRecord.ChainSeq)
	printReceiptDisplayField(out, "  Chain prev:  ", r.ActionRecord.ChainPrevHash, opts)

	if r.ActionRecord.Principal != "" {
		printReceiptDisplayField(out, "  Principal:   ", r.ActionRecord.Principal, opts)
	}
	if r.ActionRecord.Actor != "" {
		printReceiptDisplayField(out, "  Actor:       ", r.ActionRecord.Actor, opts)
	}
	if r.ActionRecord.PolicyHash != "" {
		printReceiptDisplayField(out, "  Policy Hash: ", r.ActionRecord.PolicyHash, opts)
	}

	if r.ActionRecord.Method != "" || r.ActionRecord.Layer != "" {
		record, err := sanitizedActionRecordForDisplay(r.ActionRecord)
		if err != nil {
			return
		}
		pretty, err := json.MarshalIndent(record, "  ", "  ")
		if err == nil {
			_, _ = fmt.Fprintf(out, "\n  Full record:\n  %s\n", string(pretty))
		}
	}
}

func sanitizedActionRecordForDisplay(record receipt.ActionRecord) (receipt.ActionRecord, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return receipt.ActionRecord{}, err
	}
	var out receipt.ActionRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return receipt.ActionRecord{}, err
	}
	sanitizeDisplayStrings(reflect.ValueOf(&out).Elem())
	return out, nil
}

func sanitizeDisplayStrings(v reflect.Value) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			sanitizeDisplayStrings(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.CanSet() || field.Kind() == reflect.Pointer || field.Kind() == reflect.Slice || field.Kind() == reflect.Struct {
				sanitizeDisplayStrings(field)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			sanitizeDisplayStrings(v.Index(i))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(display.Sanitize(v.String()).Safe)
		}
	}
}

func printReceiptDisplayField(out io.Writer, prefix, raw string, opts receiptPrintOptions) {
	res := display.Sanitize(raw)
	_, _ = fmt.Fprintf(out, "%s%s\n", prefix, res.Safe)
	if res.Suspicious {
		for _, ann := range res.Annotations {
			_, _ = fmt.Fprintf(out, "    ⚠ display anomaly: %s at byte %d: %s\n", ann.Class, ann.Offset, ann.Detail)
		}
	}
	if opts.ShowRaw {
		_, _ = fmt.Fprintf(out, "    raw: %q\n", raw)
	}
	if opts.Hexdump {
		_, _ = fmt.Fprintf(out, "    hexdump:\n%s\n", display.Hexdump(raw))
	}
}

func printReceiptLimits(out io.Writer) {
	for _, id := range []evidence.LimitID{
		evidence.LimitKeyholderOmit,
		evidence.LimitForgedKey,
		evidence.LimitRecorderBinary,
		evidence.LimitRecorderDisabled,
		evidence.LimitVerifierDrift,
		evidence.LimitContainmentUnproven,
		evidence.LimitConcurrentWriters,
		evidence.LimitRestartContinuity,
	} {
		limit, _ := evidence.ByID(id)
		_, _ = fmt.Fprintf(out, "  Limit:      %s: %s\n", limit.ID, limit.Summary)
	}
}

func printContainmentForReceipts(out io.Writer, receipts []receipt.Receipt, opts receiptPostureOptions) error {
	return printContainmentForSummary(out, summarizeReceiptsForPosture(receipts), opts)
}

func printContainmentForSummary(out io.Writer, summary receiptPostureSummary, opts receiptPostureOptions) error {
	assessment, err := containmentAssessmentForSummary(summary, opts)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, evidence.FormatContainmentAssessment(assessment))
	for _, reason := range assessment.Reasons {
		_, _ = fmt.Fprintf(out, "  containment reason: %s\n", reason)
	}
	return nil
}

// receiptPostureSummary is what a containment assessment reads from a
// receipt chain: its time window and the first session_open's posture
// binding. It can be built one receipt at a time.
type receiptPostureSummary struct {
	count      int
	from, to   time.Time
	binding    receiptPostureBindingInfo
	hasBinding bool
}

func (s *receiptPostureSummary) add(r receipt.Receipt) {
	ts := r.ActionRecord.Timestamp
	if s.count == 0 {
		s.from, s.to = ts, ts
	} else {
		if ts.Before(s.from) {
			s.from = ts
		}
		if ts.After(s.to) {
			s.to = ts
		}
	}
	s.count++
	if !s.hasBinding && r.ActionRecord.SessionControl != nil && r.ActionRecord.SessionControl.Open != nil {
		open := r.ActionRecord.SessionControl.Open
		s.binding = receiptPostureBindingInfo{
			containedUID:         open.ContainedUID,
			postureCapsuleSHA256: open.PostureCapsuleSHA256,
			postureSignerKeyID:   open.PostureSignerKeyID,
		}
		s.hasBinding = true
	}
}

func summarizeReceiptsForPosture(receipts []receipt.Receipt) receiptPostureSummary {
	var s receiptPostureSummary
	for i := range receipts {
		s.add(receipts[i])
	}
	return s
}

func containmentAssessmentForSummary(summary receiptPostureSummary, opts receiptPostureOptions) (evidence.ContainmentAssessment, error) {
	if opts.Path == "" {
		return evidence.AssessContainment(evidence.ContainmentAssessmentOptions{}), nil
	}
	if strings.TrimSpace(opts.KeyHex) == "" {
		return evidence.ContainmentAssessment{}, fmt.Errorf("--posture-key is required when --posture is supplied")
	}
	data, err := readOperatorFile(opts.Path)
	if err != nil {
		return evidence.ContainmentAssessment{}, fmt.Errorf("reading posture capsule: %w", err)
	}
	var capsule posture.Capsule
	if err := json.Unmarshal(data, &capsule); err != nil {
		return evidence.ContainmentAssessment{}, fmt.Errorf("parsing posture capsule: %w", err)
	}
	key, err := evidence.DecodePostureKey(opts.KeyHex)
	if err != nil {
		return evidence.ContainmentAssessment{}, fmt.Errorf("decode posture key: %w", err)
	}
	from, to := summary.from, summary.to
	binding := summary.binding
	capsuleHash, err := postureCapsuleSHA256(&capsule)
	if err != nil {
		return evidence.ContainmentAssessment{}, fmt.Errorf("hash posture capsule: %w", err)
	}
	return evidence.AssessContainment(evidence.ContainmentAssessmentOptions{
		Capsule:              &capsule,
		TrustedKey:           key,
		ReceiptFrom:          from,
		ReceiptTo:            to,
		ActorUID:             binding.containedUID,
		CapsuleSHA256:        capsuleHash,
		ReceiptCapsuleSHA256: binding.postureCapsuleSHA256,
		ReceiptSignerKeyID:   binding.postureSignerKeyID,
	}), nil
}

// receiptWindow returns the earliest and latest receipt timestamps, or zero
// bounds for no receipts.
func receiptWindow(receipts []receipt.Receipt) (time.Time, time.Time) {
	s := summarizeReceiptsForPosture(receipts)
	return s.from, s.to
}

type receiptPostureBindingInfo struct {
	containedUID         string
	postureCapsuleSHA256 string
	postureSignerKeyID   string
}

func postureCapsuleSHA256(capsule *posture.Capsule) (string, error) {
	data, err := json.Marshal(capsule)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// TranscriptRootCmd returns the "transcript-root" cobra command.
func TranscriptRootCmd() *cobra.Command {
	var expectedKeys []string
	var chainDir string
	var sessionID string
	var locationID string

	cmd := &cobra.Command{
		Use:   "transcript-root [file]",
		Short: "Compute and verify a transcript root from a receipt chain",
		Long: `Reads a flight recorder JSONL file or a receipt-chain directory,
extracts all action receipts, verifies the hash chain, and prints the
transcript root.

The transcript root is the hash of the final receipt in the chain,
serving as a tamper-evident summary of the entire session. For a chain that
rotated its signing key, pass --key once per trusted segment key.

Examples:
  pipelock transcript-root --chain /var/lib/pipelock/evidence --key pub.key
  pipelock transcript-root evidence-proxy.run.<id>-0.jsonl --key 70b991eb...
  pipelock transcript-root --chain DIR --key old.key --key new.key`,
		Args: func(_ *cobra.Command, args []string) error {
			return validateReceiptSourceArgs(args, chainDir)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(expectedKeys) == 0 {
				return fmt.Errorf("--key is required: transcript roots must be verified against a trusted signer key")
			}
			resolvedKeys, err := resolveExpectedKeyHexes(expectedKeys)
			if err != nil {
				return fmt.Errorf("loading public key: %w", err)
			}
			if len(resolvedKeys) == 0 {
				return fmt.Errorf("--key is required: transcript roots must be verified against a trusted signer key")
			}
			out := &firstOutputErrWriter{w: cmd.OutOrStdout()}
			var label string
			var receipts []receipt.Receipt
			if chainDir != "" {
				location, locationErr := recorder.ResolveEvidenceLocation(chainDir, locationID)
				if locationErr != nil {
					return fmt.Errorf("extracting session receipts: resolve evidence location: %w", locationErr)
				}
				chainDir = location.Dir
				if !cmd.Flags().Changed("session") {
					sessionID, err = resolveOneReceiptSession(location, sessionID)
					if err != nil {
						return err
					}
				}
				receipts, err = receipt.ExtractReceiptsFromResolvedSessionDir(location, sessionID)
				if err != nil {
					return fmt.Errorf("extracting session receipts: %w", err)
				}
				label = fmt.Sprintf("%s (session %s)", chainDir, sessionID)
			} else {
				if locationID != "" {
					return fmt.Errorf("--location requires --chain")
				}
				path := args[0]
				label = path
				var fileSessionID string
				receipts, fileSessionID, err = receipt.ExtractReceiptsWithSessionID(path)
				if err != nil {
					return fmt.Errorf("extracting receipts: %w", err)
				}
				// Derive session ID from the file entries when available,
				// falling back to the --session flag default.
				if fileSessionID != "" {
					sessionID = fileSessionID
				}
			}

			if len(receipts) == 0 {
				return fmt.Errorf("no receipts found in %s", label)
			}

			root, err := receipt.ComputeTranscriptRootTrusted(sessionID, receipts, resolvedKeys)
			if err != nil {
				return fmt.Errorf("computing transcript root: %w", err)
			}

			_, _ = fmt.Fprintf(out, "Transcript Root: %s\n", label)
			_, _ = fmt.Fprintf(out, "  Session:       %s\n", root.SessionID)
			_, _ = fmt.Fprintf(out, "  Root hash:     %s\n", root.RootHash)
			_, _ = fmt.Fprintf(out, "  Receipt count: %d\n", root.ReceiptCount)
			_, _ = fmt.Fprintf(out, "  Final seq:     %d\n", root.FinalSeq)
			_, _ = fmt.Fprintf(out, "  Start:         %s\n", root.StartTime.Format("2006-01-02T15:04:05Z"))
			_, _ = fmt.Fprintf(out, "  End:           %s\n", root.EndTime.Format("2006-01-02T15:04:05Z"))
			return outputResult(out, nil)
		},
	}

	cmd.Flags().StringArrayVar(&expectedKeys, "key", nil, "trusted signer public key (hex or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&chainDir, "chain", "", "read the receipt chain from an evidence directory")
	cmd.Flags().StringVar(&sessionID, "session", "proxy", "receipt chain session ID inside the evidence directory")
	cmd.Flags().StringVar(&locationID, "location", "", "location path relative to the evidence directory")
	return cmd
}

func resolveExpectedKeyHex(expectedKey string) (string, error) {
	if strings.TrimSpace(expectedKey) == "" {
		return "", nil
	}
	key, err := sigutil.LoadPublicKeyAsOpened(expectedKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// resolveExpectedKeyHexes resolves each --key value (hex or file path) to a hex
// signer key. Empty/blank entries are skipped. The order is preserved so the
// first entry can serve as the single-receipt pin.
func resolveExpectedKeyHexes(keys []string) ([]string, error) {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		resolved, err := resolveExpectedKeyHex(k)
		if err != nil {
			return nil, fmt.Errorf("resolving --key %q: %w", k, err)
		}
		if resolved != "" {
			out = append(out, resolved)
		}
	}
	return out, nil
}

func validateReceiptSourceArgs(args []string, chainDir string) error {
	if chainDir != "" {
		if len(args) != 0 {
			return fmt.Errorf("cannot pass a file argument together with --chain")
		}
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("accepts 1 arg(s), received %d", len(args))
	}
	return nil
}
