// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	sigutil "github.com/luckyPipewrench/pipelock/internal/signing"
)

const unpinnedReceiptBanner = "UNPINNED — signature is self-consistent but the signer was NOT checked against a trusted key"

// VerifyReceiptCmd returns the "verify-receipt" cobra command.
func VerifyReceiptCmd() *cobra.Command {
	var expectedKeys []string
	var chainDir string
	var sessionID string
	var allowUnpinned bool
	var fleetReport bool
	var cleanReport string

	cmd := &cobra.Command{
		Use:   "verify-receipt [file]",
		Short: "Verify a signed action receipt or receipt chain",
		Long: `Verifies Ed25519 signatures on action receipts and Fleet Receipt Reports.

For a single receipt JSON file: verifies the signature and prints details.
For a flight recorder JSONL file: extracts all receipts and verifies the
full hash chain (prev_hash linkage, seq continuity, signatures). For a
multi-file chain spanning restarts or rotations, pass --chain DIR.
For a Fleet Receipt Report DSSE envelope, pass --fleet-report.

Signing-key rotation: a chain that rotated its signing key splits into
segments. Each segment's key must be trusted. Pass --key once per trusted
key to verify across a rotation; the offending key is named if a segment is
signed by an untrusted key. With no --key, the first segment's key is trusted
on first use and any rotation is flagged for you to confirm. Unpinned
verification is structural-only and exits non-zero unless --allow-unpinned is
passed explicitly.

Exit 0 = valid, exit 1 = invalid or malformed.

Examples:
  pipelock verify-receipt receipt.json
  pipelock verify-receipt evidence-proxy-0.jsonl
  pipelock verify-receipt --chain /var/lib/pipelock/evidence
  pipelock verify-receipt receipt.json --key 70b991eb...
  pipelock verify-receipt --chain DIR --key old.key --key new.key
  pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --key fleet-report.pub
  pipelock verify-receipt receipt.json --allow-unpinned`,
		Args: func(_ *cobra.Command, args []string) error {
			return validateReceiptSourceArgs(args, chainDir)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			trustedKeys, err := resolveExpectedKeyHexes(expectedKeys)
			if err != nil {
				return fmt.Errorf("loading public key: %w", err)
			}
			if len(expectedKeys) > 0 && len(trustedKeys) == 0 {
				return fmt.Errorf("--key was provided but no valid signer keys were resolved")
			}
			if fleetReport {
				if chainDir != "" {
					return fmt.Errorf("--fleet-report cannot be combined with --chain")
				}
				if cmd.Flags().Changed("session") {
					return fmt.Errorf("--fleet-report cannot be combined with --session")
				}
				return verifyFleetReportWithOptions(out, args[0], trustedKeys, allowUnpinned)
			}
			if chainDir != "" {
				if cleanReport == "" {
					return verifyChainFromSessionDirWithOptions(out, chainDir, sessionID, trustedKeys, allowUnpinned)
				}
				receipts, extractErr := receipt.ExtractReceiptsFromSessionDir(chainDir, sessionID)
				if extractErr != nil {
					return fmt.Errorf("extracting session receipts: %w", extractErr)
				}
				label := fmt.Sprintf("%s (session %s)", chainDir, sessionID)
				return verifyCleanReport(out, label, receipts, trustedKeys, allowUnpinned, cleanReport)
			}

			path := args[0]

			// JSONL files: extract receipts and verify the full chain.
			if strings.HasSuffix(path, ".jsonl") {
				if cleanReport != "" {
					receipts, extractErr := receipt.ExtractReceipts(path)
					if extractErr != nil {
						return fmt.Errorf("extracting receipts: %w", extractErr)
					}
					return verifyCleanReport(out, path, receipts, trustedKeys, allowUnpinned, cleanReport)
				}
				return verifyChainFromFileWithOptions(out, path, trustedKeys, allowUnpinned)
			}

			if cleanReport != "" {
				return fmt.Errorf("--clean-report requires --chain or a JSONL receipt file")
			}
			// Single receipt JSON file: a lone receipt has no chain to walk,
			// so it verifies against the first supplied key (or its own).
			return verifySingleReceiptWithOptions(out, path, firstOrEmpty(trustedKeys), allowUnpinned)
		},
	}

	cmd.Flags().StringArrayVar(&expectedKeys, "key", nil, "trusted signer public key (hex or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&chainDir, "chain", "", "verify the full receipt chain from an evidence directory")
	cmd.Flags().StringVar(&sessionID, "session", "proxy", "receipt chain session ID inside the evidence directory")
	cmd.Flags().BoolVar(&allowUnpinned, "allow-unpinned", false, "allow structural-only verification without a trusted signer key")
	cmd.Flags().BoolVar(&fleetReport, "fleet-report", false, "verify a Fleet Receipt Report DSSE envelope")
	cmd.Flags().StringVar(&cleanReport, "clean-report", "", "write minimal offline-verifiable action report after chain and defer-pair validation")
	return cmd
}

func firstOrEmpty(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func verifySingleReceiptWithOptions(out io.Writer, path, expectedKey string, allowUnpinned bool) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading receipt: %w", err)
	}

	r, err := receipt.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("parsing receipt: %w", err)
	}

	if err := receipt.VerifyWithKey(r, expectedKey); err != nil {
		_, _ = fmt.Fprintf(out, "FAILED: %s: %v\n", path, err)
		return fmt.Errorf("verification failed: %w", err)
	}

	if expectedKey == "" {
		_, _ = fmt.Fprintf(out, "UNPINNED: %s\n", path)
		_, _ = fmt.Fprintln(out, unpinnedReceiptBanner)
		if !allowUnpinned {
			printReceiptDetails(out, r)
			return fmt.Errorf("verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
		}
	} else {
		_, _ = fmt.Fprintf(out, "OK: %s\n", path)
	}
	printReceiptDetails(out, r)
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
		_, _ = fmt.Fprintf(out, "  Limit:            %s\n", limit)
	}
	if result.Unpinned && !allowUnpinned {
		return fmt.Errorf("fleet receipt verification unpinned: pass --key for provenance or --allow-unpinned for structural-only verification")
	}
	return nil
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
	receipts, err := receipt.ExtractReceipts(path)
	if err != nil {
		return fmt.Errorf("extracting receipts: %w", err)
	}
	return verifyChainWithOptions(out, path, receipts, trustedKeys, allowUnpinned)
}

func verifyChainFromSessionDirWithOptions(out io.Writer, dir, sessionID string, trustedKeys []string, allowUnpinned bool) error {
	receipts, err := receipt.ExtractReceiptsFromSessionDir(dir, sessionID)
	if err != nil {
		return fmt.Errorf("extracting session receipts: %w", err)
	}
	label := fmt.Sprintf("%s (session %s)", dir, sessionID)
	return verifyChainWithOptions(out, label, receipts, trustedKeys, allowUnpinned)
}

func verifyChain(out io.Writer, label string, receipts []receipt.Receipt, trustedKeys []string) error {
	return verifyChainWithOptions(out, label, receipts, trustedKeys, false)
}

func verifyChainWithOptions(out io.Writer, label string, receipts []receipt.Receipt, trustedKeys []string, allowUnpinned bool) error {
	if len(receipts) == 0 {
		_, _ = fmt.Fprintf(out, "No receipts found in %s\n", label)
		return fmt.Errorf("no receipts in %s", label)
	}

	result := receipt.VerifyChainTrusted(receipts, trustedKeys)
	if !result.Valid {
		_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n", label)
		_, _ = fmt.Fprintf(out, "  Error:    %s\n", result.Error)
		_, _ = fmt.Fprintf(out, "  Broke at: seq %d\n", result.BrokenAtSeq)
		if result.UntrustedSignerKey != "" {
			_, _ = fmt.Fprintf(out, "  Untrusted signer key: %s\n", result.UntrustedSignerKey)
			_, _ = fmt.Fprintf(out, "  If this is a legitimate key rotation, re-run with --key for each trusted key.\n")
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
	if unpinned {
		_, _ = fmt.Fprintln(out, unpinnedReceiptBanner)
		if !allowUnpinned {
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
	if err := os.WriteFile(filepath.Clean(reportPath), append(data, '\n'), 0o600); err != nil {
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

func printReceiptDetails(out io.Writer, r receipt.Receipt) {
	_, _ = fmt.Fprintf(out, "  Action ID:   %s\n", r.ActionRecord.ActionID)
	_, _ = fmt.Fprintf(out, "  Action Type: %s\n", r.ActionRecord.ActionType)
	_, _ = fmt.Fprintf(out, "  Verdict:     %s\n", r.ActionRecord.Verdict)
	_, _ = fmt.Fprintf(out, "  Target:      %s\n", r.ActionRecord.Target)
	_, _ = fmt.Fprintf(out, "  Transport:   %s\n", r.ActionRecord.Transport)
	_, _ = fmt.Fprintf(out, "  Timestamp:   %s\n", r.ActionRecord.Timestamp.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(out, "  Signer:      %s\n", r.SignerKey)
	_, _ = fmt.Fprintf(out, "  Chain seq:   %d\n", r.ActionRecord.ChainSeq)
	_, _ = fmt.Fprintf(out, "  Chain prev:  %s\n", r.ActionRecord.ChainPrevHash)

	if r.ActionRecord.Principal != "" {
		_, _ = fmt.Fprintf(out, "  Principal:   %s\n", r.ActionRecord.Principal)
	}
	if r.ActionRecord.Actor != "" {
		_, _ = fmt.Fprintf(out, "  Actor:       %s\n", r.ActionRecord.Actor)
	}
	if r.ActionRecord.PolicyHash != "" {
		_, _ = fmt.Fprintf(out, "  Policy Hash: %s\n", r.ActionRecord.PolicyHash)
	}

	if r.ActionRecord.Method != "" || r.ActionRecord.Layer != "" {
		pretty, err := json.MarshalIndent(r.ActionRecord, "  ", "  ")
		if err == nil {
			_, _ = fmt.Fprintf(out, "\n  Full record:\n  %s\n", string(pretty))
		}
	}
}

// TranscriptRootCmd returns the "transcript-root" cobra command.
func TranscriptRootCmd() *cobra.Command {
	var expectedKeys []string
	var chainDir string
	var sessionID string

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
  pipelock transcript-root evidence-proxy-0.jsonl --key 70b991eb...
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
			out := cmd.OutOrStdout()
			var label string
			var receipts []receipt.Receipt
			if chainDir != "" {
				receipts, err = receipt.ExtractReceiptsFromSessionDir(chainDir, sessionID)
				if err != nil {
					return fmt.Errorf("extracting session receipts: %w", err)
				}
				label = fmt.Sprintf("%s (session %s)", chainDir, sessionID)
			} else {
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
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&expectedKeys, "key", nil, "trusted signer public key (hex or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&chainDir, "chain", "", "read the receipt chain from an evidence directory")
	cmd.Flags().StringVar(&sessionID, "session", "proxy", "receipt chain session ID inside the evidence directory")
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
