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

Each process run records its own chain ("<base>.run.<id>"). With --chain and
no --session, every chain of the base is verified, then restart continuity:
each optional signed link file beside the chains must name the exact tail of
the run it continues, under a trusted or endorsed key. Runs no link file
continues are listed as unlinked. That is normal for a first run or for
concurrent runs, and it is also what a deleted link file looks like, so a
passing result does not prove no run's evidence is missing. Pass --session
to verify one chain; continuity for its base is still reported.
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

Exit 0 = the receipt is valid and the requested report was delivered; exit 1 = invalid, malformed, or report delivery failed.

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
				return errors.New("--require-seal requires --whole-recorder")
			}
			trustedKeys, err := resolveExpectedKeyHexes(expectedKeys)
			if err != nil {
				return fmt.Errorf("loading public key: %w", err)
			}
			if len(expectedKeys) > 0 && len(trustedKeys) == 0 {
				return fmt.Errorf("--key was provided but no valid signer keys were resolved")
			}
			var resolvedLocation *recorder.EvidenceLocation
			if chainDir != "" && !fleetReport {
				location, locationErr := recorder.ResolveEvidenceLocation(chainDir, locationID)
				if locationErr != nil {
					return fmt.Errorf("extracting session receipts: resolve evidence location: %w", locationErr)
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
					return fmt.Errorf("--rotation-endorsement cannot be combined with --fleet-report")
				case cleanReport != "":
					return fmt.Errorf("--rotation-endorsement cannot be combined with --clean-report")
				case chainDir == "" && !strings.HasSuffix(args[0], ".jsonl"):
					return fmt.Errorf("--rotation-endorsement requires --chain or a JSONL receipt file")
				}
			}
			if wholeRecorder && cleanReport != "" {
				return fmt.Errorf("--whole-recorder cannot be combined with --clean-report")
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
					return fmt.Errorf("loading --rotation-endorsement %q: %w", endorsementPath, loadErr)
				}
				verifyOpts.RotationEndorsements = append(verifyOpts.RotationEndorsements, endorsement)
			}
			if fleetReport {
				if wholeRecorder {
					return fmt.Errorf("--whole-recorder cannot be combined with --fleet-report")
				}
				if locationID != "" {
					return fmt.Errorf("--location requires --chain")
				}
				if chainDir != "" {
					return fmt.Errorf("--fleet-report cannot be combined with --chain")
				}
				if cmd.Flags().Changed("session") {
					return fmt.Errorf("--fleet-report cannot be combined with --session")
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
					return fmt.Errorf("extracting session receipts: %w", extractErr)
				}
				label := fmt.Sprintf("%s (session %s)", resolvedLocation.Dir, sessionID)
				return outputResult(out, verifyCleanReport(out, label, receipts, trustedKeys, allowUnpinned, cleanReport))
			}
			if locationID != "" {
				return fmt.Errorf("--location requires --chain")
			}

			path := args[0]

			// JSONL files: extract receipts and verify the full chain.
			if strings.HasSuffix(path, ".jsonl") {
				if cleanReport != "" {
					receipts, extractErr := receipt.ExtractReceipts(path)
					if extractErr != nil {
						return fmt.Errorf("extracting receipts: %w", extractErr)
					}
					return outputResult(out, verifyCleanReport(out, path, receipts, trustedKeys, allowUnpinned, cleanReport))
				}
				if wholeRecorder {
					return outputResult(out, verifyWholeRecorderFromFile(out, path, trustedKeys, verifyOpts))
				}
				return outputResult(out, verifyChainFromFileDetailed(out, path, trustedKeys, verifyOpts))
			}

			if cleanReport != "" {
				return fmt.Errorf("--clean-report requires --chain or a JSONL receipt file")
			}
			if wholeRecorder {
				return fmt.Errorf("--whole-recorder requires a recorder JSONL file or --chain directory")
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
	cmd.Flags().BoolVar(&allowUnanchoredSeal, "allow-unanchored-seal", false, "with --whole-recorder, accept a recorder whose transcript_root seal is not covered by a signed checkpoint (entries after the last signed checkpoint are then hash-linked but not authenticated)")
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

func verifyWholeRecorderFromFile(out io.Writer, path string, trustedKeys []string, opts verifyReceiptOptions) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading recorder file: %w", err)
	}
	defer func() { _ = file.Close() }()
	// Stream the handle so the reader's bounded-read limits apply before the
	// whole file is held in memory.
	entries, err := recorder.ReadEntriesFromReader(file)
	if err != nil {
		return fmt.Errorf("whole-recorder verification failed: not a recorder file or recorder integrity error: %w", err)
	}
	result, err := receipt.VerifyWholeRecorderEntries(entries)
	if err != nil {
		return fmt.Errorf("whole-recorder verification failed: not a recorder file or recorder integrity error: %w", err)
	}
	return verifyWholeRecorderDetailed(out, path, entries, result, trustedKeys, opts)
}

func verifyWholeRecorderFromResolvedSessionDir(out io.Writer, location recorder.EvidenceLocation, sessionID string, trustedKeys []string, opts verifyReceiptOptions) error {
	query, err := recorder.QuerySessionResolved(location, sessionID, nil)
	if err != nil {
		return fmt.Errorf("reading recorder session: %w", err)
	}
	if query.Truncated {
		_, _ = fmt.Fprintf(out, "INCOMPLETE: evidence session %s exceeded bounded read limits\n", sessionID)
		return fmt.Errorf("whole-recorder verification failed: evidence session %s exceeded bounded read limits", sessionID)
	}
	result, err := receipt.VerifyWholeRecorderEntries(query.Entries)
	if err != nil {
		return fmt.Errorf("whole-recorder verification failed: %w", err)
	}
	label := fmt.Sprintf("%s (session %s)", location.Dir, sessionID)
	return verifyWholeRecorderDetailed(out, label, query.Entries, result, trustedKeys, opts)
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

func verifyWholeRecorderDetailed(out io.Writer, label string, entries []recorder.Entry, whole receipt.WholeRecorderResult, trustedKeys []string, opts verifyReceiptOptions) error {
	_, _ = fmt.Fprintf(out, "WHOLE-RECORDER: %s\n", label)
	_, _ = fmt.Fprintf(out, "  Mode:      whole-recorder\n")
	_, _ = fmt.Fprintf(out, "  Entries:   %d recorder entries hash-chain-verified and in-taxonomy\n", whole.EntryCount)
	chain := verifiedChainResult(whole.Receipts, trustedKeys, opts)
	if !chain.Valid || (len(trustedKeys) == 0 && !opts.AllowUnpinned) {
		return verifyChainResultDetailed(out, label, whole.Receipts, chain, trustedKeys, opts)
	}
	root, rootIndex, rootSessionID, found, err := transcriptRootFromEntries(entries)
	if err != nil {
		_, _ = fmt.Fprintf(out, "  SEAL MISMATCH: %v\n", err)
		return fmt.Errorf("seal verification failed: %w", err)
	}
	if !found {
		_, _ = fmt.Fprintln(out, "  INCOMPLETE: no transcript_root seal (recorder still running or tail truncated)")
		return errUnsealedRecorder
	}
	rootReceiptCount := receiptEntriesBefore(entries, rootIndex)
	if rootReceiptCount == 0 || rootReceiptCount > len(whole.Receipts) {
		_, _ = fmt.Fprintln(out, "  SEAL MISMATCH")
		return fmt.Errorf("seal verification failed: transcript_root has no matching receipt prefix")
	}
	rootChain := verifiedChainResult(whole.Receipts[:rootReceiptCount], trustedKeys, opts)
	if !rootChain.Valid || !transcriptRootMatchesChainSegment(root, rootSessionID, rootChain) {
		_, _ = fmt.Fprintln(out, "  SEAL MISMATCH")
		return fmt.Errorf("seal verification failed: transcript_root does not match its verified receipt-chain segment")
	}
	if unsealed, ok := firstUnsealedEntryAfter(entries, rootIndex); ok {
		_, _ = fmt.Fprintf(out, "  INCOMPLETE: transcript_root seal precedes later unsealed entries (first: %s at seq %d)\n", unsealed.Type, unsealed.Sequence)
		return fmt.Errorf("whole-recorder verification incomplete: transcript_root seal precedes later unsealed %s entry at seq %d", unsealed.Type, unsealed.Sequence)
	}
	// The receipt chain already verified every signer, including a successor
	// authorized by a rotation endorsement. A checkpoint must be signed by the
	// key that was active where it sits, so each one is checked against the
	// signer of the receipt segment it belongs to rather than the union of
	// every key that ever signed.
	anchor, err := verifyCheckpointAnchors(entries, whole.Receipts)
	if err != nil {
		_, _ = fmt.Fprintf(out, "  ANCHOR MISMATCH: %v\n", err)
		return fmt.Errorf("checkpoint anchor verification failed: %w", err)
	}
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
		_, _ = fmt.Fprintln(out, "  UNANCHORED: no signed checkpoint covers the transcript_root seal; entries after the last signed checkpoint are hash-linked but not authenticated")
		return fmt.Errorf("whole-recorder verification unanchored: no signed checkpoint covers the transcript_root seal (checkpoints absent, unsigned, or none after the seal); pass --allow-unanchored-seal to accept hash linkage only for the entries after the last anchor")
	}
	if err := verifyChainResultDetailed(out, label, whole.Receipts, chain, trustedKeys, opts); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "  Receipts:  %d receipts verified\n", chain.ReceiptCount)
	_, _ = fmt.Fprintf(out, "  Seal:      sealed at seq %d\n", root.FinalSeq)
	switch {
	case anchor.lastSignedIndex > rootIndex && len(trustedKeys) == 0:
		// Unpinned: the signer came from the receipts in this same file, so it
		// says nothing about provenance. Do not call it trusted.
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified against the file's own signer, which was NOT checked against a trusted key\n", anchor.signed)
	case anchor.lastSignedIndex > rootIndex:
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified; every entry through the seal is committed by a trusted key\n", anchor.signed)
	case anchor.signed > 0:
		_, _ = fmt.Fprintf(out, "  Anchor:    %d signed checkpoints verified, none after the seal (accepted by --allow-unanchored-seal); entries after seq %d are hash-linked but not authenticated\n", anchor.signed, entries[anchor.lastSignedIndex].Sequence)
	default:
		_, _ = fmt.Fprintln(out, "  Anchor:    no signed checkpoint (accepted by --allow-unanchored-seal); recorder entries other than receipts are hash-linked but not authenticated")
	}
	_, _ = fmt.Fprintln(out, "  Limit:     the seal covers the final signing segment; only the recorder's trailing checkpoint may follow it, hash-chain-verified but not sealed")
	return nil
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

// verifyCheckpointAnchors checks every checkpoint entry's span and, when it
// carries a signature, verifies that signature against the key that was
// active where the checkpoint sits: the signer of the most recent receipt
// before it, or, for a checkpoint written in the gap between two signing
// segments, either that key or the signer of the next receipt, since a new
// writer instance can checkpoint before its first receipt. The receipts are
// the already-verified chain, so every signer in them is trusted or endorsed,
// and scoping to the segment means a retired key cannot re-sign checkpoints
// after its rotation and a successor cannot sign before its activation. A
// signed checkpoint commits the chain hash of every entry before it, so it
// is the only authenticated anchor for entries that are not receipts; an
// unsigned checkpoint proves nothing beyond hash linkage and is not an
// anchor. A session may legitimately mix the two when sign_checkpoints
// changed between restarts; that costs nothing, because a stripped earlier
// signature changes that entry's hash and breaks every later checkpoint's
// signature, and a stripped trailing signature leaves the seal uncovered.
// The span must match the checkpoint's position: it ends at the preceding
// entry, starts after the previous checkpoint, and counts exactly the
// entries between; it need not start right after the previous checkpoint,
// because a crash resume starts a new span at the first resumed entry, and
// the span is metadata the signature does not depend on. A checkpoint whose
// detail does not parse, whose span disagrees with its position, or whose
// signature does not verify under its segment's key fails closed. What this
// cannot catch: on a recorder that never signed, a rewritten trailing entry
// with a self-consistent span; the output reports that state as unanchored.
func verifyCheckpointAnchors(entries []recorder.Entry, receipts []receipt.Receipt) (checkpointAnchor, error) {
	anchor := checkpointAnchor{lastSignedIndex: -1}
	var prevCheckpoint *recorder.Entry
	seenReceipts := 0
	for i := range entries {
		entry := entries[i]
		if entry.Type == "action_receipt" {
			seenReceipts++
			continue
		}
		if entry.Type != "checkpoint" {
			continue
		}
		detailJSON, err := json.Marshal(entry.Detail)
		if err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: encoding detail: %w", entry.Sequence, err)
		}
		var detail recorder.CheckpointDetail
		if err := json.Unmarshal(detailJSON, &detail); err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: malformed detail: %w", entry.Sequence, err)
		}
		if i == 0 || detail.LastSeq != entries[i-1].Sequence {
			return anchor, fmt.Errorf("checkpoint at seq %d: span ends at seq %d but the preceding entry is seq %d", entry.Sequence, detail.LastSeq, precedingSequence(entries, i))
		}
		// EntryCount-1 == LastSeq-FirstSeq avoids the +1 that would wrap at the
		// top of the sequence space; FirstSeq <= LastSeq is checked first so
		// the subtraction cannot wrap either.
		if detail.FirstSeq > detail.LastSeq || detail.EntryCount == 0 || detail.EntryCount-1 != detail.LastSeq-detail.FirstSeq {
			return anchor, fmt.Errorf("checkpoint at seq %d: span %d-%d does not hold %d entries", entry.Sequence, detail.FirstSeq, detail.LastSeq, detail.EntryCount)
		}
		if prevCheckpoint != nil && detail.FirstSeq <= prevCheckpoint.Sequence {
			return anchor, fmt.Errorf("checkpoint at seq %d: span starts at seq %d, inside the previous checkpoint at seq %d", entry.Sequence, detail.FirstSeq, prevCheckpoint.Sequence)
		}
		prevCheckpoint = &entries[i]
		if detail.Signature == "" {
			anchor.unsigned++
			continue
		}
		pubs, err := segmentSignerKeys(receipts, seenReceipts)
		if err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: %w", entry.Sequence, err)
		}
		sig, err := hex.DecodeString(detail.Signature)
		if err != nil {
			return anchor, fmt.Errorf("checkpoint at seq %d: decoding signature: %w", entry.Sequence, err)
		}
		verified := false
		for _, pub := range pubs {
			if ed25519.Verify(pub, []byte(entry.PrevHash), sig) {
				verified = true
				break
			}
		}
		if !verified {
			return anchor, fmt.Errorf("checkpoint at seq %d: signature does not verify under the signer of its receipt segment", entry.Sequence)
		}
		anchor.signed++
		anchor.lastSignedIndex = i
	}
	return anchor, nil
}

func precedingSequence(entries []recorder.Entry, i int) uint64 {
	if i == 0 {
		return 0
	}
	return entries[i-1].Sequence
}

// segmentSignerKeys returns the public keys that may sign a checkpoint with
// seenReceipts receipts before it: the signer of the last of those (or of
// the first receipt when none precede it), plus the signer of the next
// receipt when it differs, because a checkpoint in the gap between two
// signing segments can legitimately come from either writer instance.
func segmentSignerKeys(receipts []receipt.Receipt, seenReceipts int) ([]ed25519.PublicKey, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("signed checkpoint present but the recorder holds no receipts to name its signer")
	}
	prev := seenReceipts - 1
	if prev < 0 {
		prev = 0
	}
	if prev >= len(receipts) {
		prev = len(receipts) - 1
	}
	hexKeys := []string{receipts[prev].SignerKey}
	if next := seenReceipts; next < len(receipts) && next != prev && receipts[next].SignerKey != receipts[prev].SignerKey {
		hexKeys = append(hexKeys, receipts[next].SignerKey)
	}
	pubs := make([]ed25519.PublicKey, 0, len(hexKeys))
	for _, key := range hexKeys {
		raw, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("decode segment signer key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("segment signer key length=%d want %d", len(raw), ed25519.PublicKeySize)
		}
		pubs = append(pubs, ed25519.PublicKey(raw))
	}
	return pubs, nil
}

func transcriptRootFromEntries(entries []recorder.Entry) (receipt.TranscriptRoot, int, string, bool, error) {
	var root receipt.TranscriptRoot
	rootIndex := -1
	var rootSessionID string
	found := false
	for index, entry := range entries {
		if entry.Type != "transcript_root" {
			continue
		}
		data := entry.RawDetail
		if len(data) == 0 {
			var err error
			data, err = json.Marshal(entry.Detail)
			if err != nil {
				return receipt.TranscriptRoot{}, -1, "", false, fmt.Errorf("marshal transcript_root detail: %w", err)
			}
		}
		if err := json.Unmarshal(data, &root); err != nil {
			return receipt.TranscriptRoot{}, -1, "", false, fmt.Errorf("parse transcript_root detail: %w", err)
		}
		rootIndex = index
		rootSessionID = entry.SessionID
		found = true
	}
	return root, rootIndex, rootSessionID, found, nil
}

func receiptEntriesBefore(entries []recorder.Entry, index int) int {
	count := 0
	for _, entry := range entries[:index] {
		if entry.Type == "action_receipt" {
			count++
		}
	}
	return count
}

// firstUnsealedEntryAfter returns the first entry after the transcript_root
// seal that the seal does not account for. The recorder writes exactly one
// checkpoint after the root on clean shutdown (either the threshold
// checkpoint the root itself triggers or the final one Close writes, never
// both), so a sealed recorder may carry at most one entry past the seal and
// it must be a checkpoint. Anything else there is evidence the seal never
// committed to, and the file is incomplete.
func firstUnsealedEntryAfter(entries []recorder.Entry, index int) (recorder.Entry, bool) {
	tail := entries[index+1:]
	if len(tail) == 0 {
		return recorder.Entry{}, false
	}
	if tail[0].Type != "checkpoint" {
		return tail[0], true
	}
	if len(tail) > 1 {
		return tail[1], true
	}
	return recorder.Entry{}, false
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
	data, err := os.ReadFile(filepath.Clean(path))
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

func verifyChainFromFile(out io.Writer, path string, trustedKeys []string) error {
	return verifyChainFromFileWithOptions(out, path, trustedKeys, false)
}

func verifyChainFromFileWithOptions(out io.Writer, path string, trustedKeys []string, allowUnpinned bool) error {
	return verifyChainFromFileDetailed(out, path, trustedKeys, verifyReceiptOptions{AllowUnpinned: allowUnpinned})
}

func verifyChainFromFileDetailed(out io.Writer, path string, trustedKeys []string, opts verifyReceiptOptions) error {
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
	for _, s := range targets {
		chainOpts, chainKeys := chainScopedTrust(report, s, trustedKeys, opts)
		if verifyErr := verifyChainFromResolvedSessionDirDetailed(out, location, s, chainKeys, chainOpts); verifyErr != nil {
			failed = append(failed, s)
		}
		_, _ = fmt.Fprintln(out)
	}
	printRestartContinuity(out, report)
	if len(failed) > 0 {
		return fmt.Errorf("chain verification failed for %d of %d chain(s): %s", len(failed), len(targets), strings.Join(failed, ", "))
	}
	if !report.Healthy() {
		return fmt.Errorf("restart continuity: %d link finding(s)", len(report.Findings))
	}
	return nil
}

// chainScopedTrust narrows the operator's endorsements and keys to one chain.
// A restart-time key change is authorized by an endorsement bound to the
// PREDECESSOR run's tail, which only the link check can place; handing it to
// the single-chain verifier of either run would be rejected as unused. So a
// chain gets only endorsements for its own in-chain rotations, plus the
// successor key when the base check verified an endorsed link into it.
func chainScopedTrust(report receipt.BaseReport, session string, trustedKeys []string, opts verifyReceiptOptions) (verifyReceiptOptions, []string) {
	chainOpts := opts
	chainOpts.SessionID = session
	chainOpts.RotationEndorsements = nil
	for _, e := range opts.RotationEndorsements {
		if e.SessionID != session {
			continue
		}
		crossChain := false
		for _, c := range report.Chains {
			if c.Link != nil && receipt.VerifyCrossChainEndorsement(e, *c.Link) == nil {
				crossChain = true
				break
			}
		}
		if !crossChain {
			chainOpts.RotationEndorsements = append(chainOpts.RotationEndorsements, e)
		}
	}
	keys := trustedKeys
	for _, c := range report.Chains {
		if c.Session == session && c.Link != nil && c.LinkTrust == receipt.LinkTrustEndorsed {
			keys = append(append([]string(nil), trustedKeys...), c.Link.SuccessorSignerKey)
		}
	}
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
	_, _ = fmt.Fprintf(out, "%s: base %q: %d chain(s), %d linked, %d unlinked, %d link finding(s)\n",
		label, report.Base, len(report.Chains), report.LinkCount(), len(unlinked), len(report.Findings))
	for _, c := range report.Chains {
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
	receipts, err := receipt.ExtractReceiptsFromResolvedSessionDir(location, sessionID)
	if err != nil {
		return fmt.Errorf("extracting session receipts: %w", err)
	}
	label := fmt.Sprintf("%s (session %s)", location.Dir, sessionID)
	return verifyChainDetailed(out, label, receipts, trustedKeys, opts)
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
	if err := printContainmentForReceipts(out, receipts, opts.Posture); err != nil {
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
	Chain   cleanChainSummary  `json:"chain"`
	Actions []cleanActionEntry `json:"actions"`
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

func verifyCleanReport(out io.Writer, label string, receipts []receipt.Receipt, trustedKeys []string, allowUnpinned bool, reportPath string) error {
	if len(receipts) == 0 {
		return fmt.Errorf("no receipts found in %s", label)
	}
	result := receipt.VerifyChainTrusted(receipts, trustedKeys)
	if !result.Valid {
		return fmt.Errorf("chain verification failed at seq %d: %s", result.BrokenAtSeq, result.Error)
	}
	if len(trustedKeys) == 0 && !allowUnpinned {
		return fmt.Errorf("chain verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
	}
	report, err := buildCleanActionReport(label, receipts, result)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal clean report: %w", err)
	}
	if err := atomicfile.Write(filepath.Clean(reportPath), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write clean report: %w", err)
	}
	_, _ = fmt.Fprintf(out, "CLEAN REPORT VALID: %s\n", label)
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
	assessment, err := containmentAssessmentForReceipts(receipts, opts)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, evidence.FormatContainmentAssessment(assessment))
	for _, reason := range assessment.Reasons {
		_, _ = fmt.Fprintf(out, "  containment reason: %s\n", reason)
	}
	return nil
}

func containmentAssessmentForReceipts(receipts []receipt.Receipt, opts receiptPostureOptions) (evidence.ContainmentAssessment, error) {
	if opts.Path == "" {
		return evidence.AssessContainment(evidence.ContainmentAssessmentOptions{}), nil
	}
	if strings.TrimSpace(opts.KeyHex) == "" {
		return evidence.ContainmentAssessment{}, fmt.Errorf("--posture-key is required when --posture is supplied")
	}
	data, err := os.ReadFile(filepath.Clean(opts.Path))
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
	from, to := receiptWindow(receipts)
	binding := receiptPostureBinding(receipts)
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

func receiptWindow(receipts []receipt.Receipt) (time.Time, time.Time) {
	if len(receipts) == 0 {
		return time.Time{}, time.Time{}
	}
	start := receipts[0].ActionRecord.Timestamp
	end := receipts[0].ActionRecord.Timestamp
	for _, r := range receipts[1:] {
		ts := r.ActionRecord.Timestamp
		if ts.Before(start) {
			start = ts
		}
		if ts.After(end) {
			end = ts
		}
	}
	return start, end
}

type receiptPostureBindingInfo struct {
	containedUID         string
	postureCapsuleSHA256 string
	postureSignerKeyID   string
}

func receiptPostureBinding(receipts []receipt.Receipt) receiptPostureBindingInfo {
	for _, r := range receipts {
		if r.ActionRecord.SessionControl != nil && r.ActionRecord.SessionControl.Open != nil {
			open := r.ActionRecord.SessionControl.Open
			return receiptPostureBindingInfo{
				containedUID:         open.ContainedUID,
				postureCapsuleSHA256: open.PostureCapsuleSHA256,
				postureSignerKeyID:   open.PostureSignerKeyID,
			}
		}
	}
	return receiptPostureBindingInfo{}
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
	key, err := sigutil.LoadPublicKey(expectedKey)
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
