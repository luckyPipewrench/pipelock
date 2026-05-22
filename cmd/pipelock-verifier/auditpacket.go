// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

// Stable status labels emitted in the textual report and the JSON
// schema_check / chain_check / cross_check fields.
const (
	statusPass    = "pass"
	statusFail    = "fail"
	statusSkipped = "skipped"
)

// auditPacketOptions holds resolved CLI flags for the audit-packet command.
type auditPacketOptions struct {
	signerKey   string
	jsonOutput  bool
	offline     bool
	allowSCO    bool
	relaxTrust  bool
	expectedSHA string
}

func newAuditPacketCmd() *cobra.Command {
	var opts auditPacketOptions

	cmd := &cobra.Command{
		Use:   "audit-packet PATH",
		Short: "Verify a Pipelock Audit Packet (v0)",
		Long: `Validates an Audit Packet against the locked pipelock.audit_packet.v0
schema, then re-verifies the embedded receipt chain and confirms that the
packet's claimed verdict, receipt_count, and totals match the chain's
actual contents.

PATH may be either:

  - A directory containing packet.json plus its sibling artifacts.
  - A path to packet.json directly. Sibling artifacts are resolved
    relative to the file's parent directory.

Without --offline, the verifier reads artifacts.evidence (as recorded in
the packet) and re-verifies the chain. With --offline, only the packet
itself is validated.

Without --key the verifier confirms internal chain self-consistency
(prev-hash linkage, signer agreement) but cannot prove provenance. A
packet that claims verdict=valid AND trusted=true MUST carry signer_key,
and --key (or the packet's own signer_key) must match.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditPacket(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.signerKey, "key", "", "expected signer public key (hex, public-key text, or file path)")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")
	cmd.Flags().BoolVar(&opts.offline, "offline", false, "validate only the packet schema; skip chain re-verification")
	cmd.Flags().BoolVar(&opts.allowSCO, "allow-self-consistent-only", false, "do not fail when the packet's verdict is self_consistent_only")
	cmd.Flags().BoolVar(&opts.relaxTrust, "no-trust-required", false, "do not require trusted=true; report verdict as-is")
	cmd.Flags().StringVar(&opts.expectedSHA, "expect-sha256", "", "if set, fail when packet.json's SHA-256 does not match this hex digest")

	return cmd
}

// auditPacketReport is the structured form emitted by --json. Field names are
// deliberately stable so external CI checks can grep them.
type auditPacketReport struct {
	Path        string         `json:"path"`
	Verdict     string         `json:"verdict"`
	Trusted     bool           `json:"trusted"`
	Valid       bool           `json:"valid"`
	Summary     auditPktDigest `json:"summary"`
	Posture     posturePeek    `json:"posture"`
	Run         runPeek        `json:"run"`
	Errors      []string       `json:"errors,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
	SchemaCheck string         `json:"schema_check"`
	ChainCheck  string         `json:"chain_check"`
	CrossCheck  string         `json:"cross_check"`
}

type auditPktDigest struct {
	ReceiptCount int            `json:"receipt_count"`
	Totals       map[string]int `json:"totals"`
}

type posturePeek struct {
	EnforcementMode  string   `json:"enforcement_mode"`
	UnsupportedPaths []string `json:"unsupported_paths"`
}

type runPeek struct {
	Provider      string `json:"provider"`
	Repository    string `json:"repository,omitempty"`
	SHA           string `json:"sha,omitempty"`
	AgentIdentity string `json:"agent_identity"`
}

func runAuditPacket(stdout, stderr io.Writer, target string, opts auditPacketOptions) error {
	packetPath, baseDir, err := resolvePacketPath(target)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}

	report := auditPacketReport{
		Path:        packetPath,
		SchemaCheck: statusSkipped,
		ChainCheck:  statusSkipped,
		CrossCheck:  statusSkipped,
	}

	rawPacket, err := os.ReadFile(filepath.Clean(packetPath))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read packet: %w", err))
	}

	if opts.expectedSHA != "" {
		if err := verifyExpectedSHA(rawPacket, opts.expectedSHA); err != nil {
			report.Errors = append(report.Errors, err.Error())
			emitReport(stdout, stderr, report, opts.jsonOutput)
			return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
		}
	}

	var packet auditpacket.Packet
	if err := json.Unmarshal(rawPacket, &packet); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("packet json: %v", err))
		emitReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("unmarshal packet: %w", err))
	}

	report.Verdict = packet.Verifier.Verdict
	report.Trusted = packet.Verifier.Trusted
	populateReportFromPacket(&report, &packet)

	if err := packet.Validate(); err != nil {
		report.SchemaCheck = statusFail
		report.Errors = append(report.Errors, fmt.Sprintf("schema: %v", err))
		emitReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("packet schema: %w", err))
	}
	report.SchemaCheck = statusPass

	if opts.offline {
		report.Valid = trustVerdict(&packet, opts)
		emitReport(stdout, stderr, report, opts.jsonOutput)
		if !report.Valid {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("packet not trusted"))
		}
		return nil
	}

	chainResult, chainReceipts, chainErr := reverifyChain(baseDir, &packet, opts.signerKey)
	if chainErr != nil {
		report.ChainCheck = statusFail
		report.Errors = append(report.Errors, fmt.Sprintf("chain: %v", chainErr))
		emitReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, chainErr)
	}
	report.ChainCheck = chainStatusLabel(chainResult)

	if crossErrs := crossCheck(&packet, chainResult, chainReceipts); len(crossErrs) > 0 {
		report.CrossCheck = statusFail
		for _, e := range crossErrs {
			report.Errors = append(report.Errors, fmt.Sprintf("cross-check: %v", e))
		}
		emitReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("packet vs chain mismatch"))
	}
	report.CrossCheck = statusPass

	report.Valid = chainResult.Valid && trustVerdict(&packet, opts)
	emitReport(stdout, stderr, report, opts.jsonOutput)
	if !report.Valid {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("packet not trusted"))
	}
	return nil
}

func populateReportFromPacket(r *auditPacketReport, p *auditpacket.Packet) {
	totals := map[string]int{
		"allow":    p.Summary.Totals.Allow,
		"block":    p.Summary.Totals.Block,
		"warn":     p.Summary.Totals.Warn,
		"ask":      p.Summary.Totals.Ask,
		"strip":    p.Summary.Totals.Strip,
		"forward":  p.Summary.Totals.Forward,
		"redirect": p.Summary.Totals.Redirect,
		"other":    p.Summary.Totals.Other,
	}
	r.Summary = auditPktDigest{
		ReceiptCount: p.Summary.ReceiptCount,
		Totals:       totals,
	}
	r.Posture = posturePeek{
		EnforcementMode:  p.Posture.EnforcementMode,
		UnsupportedPaths: append([]string(nil), p.Posture.UnsupportedPaths...),
	}
	r.Run = runPeek{
		Provider:      p.Run.Provider,
		Repository:    p.Run.Repository,
		SHA:           p.Run.SHA,
		AgentIdentity: p.Run.AgentIdentity,
	}
}

// resolvePacketPath accepts either a directory or a packet.json path and
// returns (packet.json path, sibling-artifact base directory).
func resolvePacketPath(target string) (string, string, error) {
	clean := filepath.Clean(target)
	info, err := os.Stat(clean)
	if err != nil {
		return "", "", fmt.Errorf("stat %q: %w", target, err)
	}
	if info.IsDir() {
		return filepath.Join(clean, "packet.json"), clean, nil
	}
	return clean, filepath.Dir(clean), nil
}

// verifyExpectedSHA compares the SHA-256 of raw against the user-supplied
// hex digest. Useful when an out-of-band trust anchor pins the packet bytes.
func verifyExpectedSHA(raw []byte, want string) error {
	want = strings.TrimSpace(strings.ToLower(want))
	got := sha256Hex(raw)
	if got != want {
		return fmt.Errorf("packet sha256 mismatch: got %s, want %s", got, want)
	}
	return nil
}

// resolveArtifactPath joins base + relative artifact path with a containment
// check, mirroring the schema's $defs/artifact_path validation.
func resolveArtifactPath(baseDir, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("artifact path is empty")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("artifact path must be relative: %q", rel)
	}
	if strings.Contains(rel, "\\") || strings.Contains(rel, ":") {
		return "", fmt.Errorf("artifact path contains forbidden character: %q", rel)
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path escapes packet directory: %q", rel)
	}
	full := filepath.Join(baseDir, clean)
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolve base dir: %w", err)
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("resolve artifact: %w", err)
	}
	rel2, err := filepath.Rel(absBase, absFull)
	if err != nil || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) || rel2 == ".." {
		return "", fmt.Errorf("artifact path escapes packet directory after resolution: %q", rel)
	}
	// Re-check containment after symlink resolution. filepath.Rel inspects
	// the path string only; a packet whose evidence.jsonl is itself a
	// symlink to /etc/passwd would pass the path check and read outside the
	// packet dir at open time. EvalSymlinks fails when the target does not
	// yet exist, which is fine: downstream open will still fail.
	if resolved, evalErr := filepath.EvalSymlinks(absFull); evalErr == nil {
		rel3, relErr := filepath.Rel(absBase, resolved)
		if relErr != nil || rel3 == ".." || strings.HasPrefix(rel3, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("artifact path escapes packet directory via symlink: %q", rel)
		}
	}
	return full, nil
}

func reverifyChain(baseDir string, packet *auditpacket.Packet, signerOverride string) (receipt.ChainResult, []receipt.Receipt, error) {
	evidencePath, err := resolveArtifactPath(baseDir, packet.Artifacts.Evidence)
	if err != nil {
		return receipt.ChainResult{}, nil, fmt.Errorf("evidence: %w", err)
	}
	receipts, err := receipt.ExtractReceipts(evidencePath)
	if err != nil {
		return receipt.ChainResult{}, nil, fmt.Errorf("extract receipts: %w", err)
	}
	keyHex := strings.TrimSpace(signerOverride)
	if keyHex == "" {
		keyHex = strings.TrimSpace(packet.Verifier.SignerKey)
	}
	resolvedKey, err := resolveSignerKey(keyHex)
	if err != nil {
		return receipt.ChainResult{}, nil, fmt.Errorf("resolve signer key: %w", err)
	}
	return receipt.VerifyChain(receipts, resolvedKey), receipts, nil
}

// crossCheck enforces that the packet's claimed totals, receipt_count, and
// root_hash match the chain's actual contents. This is the post-emission
// tamper-detection layer: a packet whose totals were edited after writing
// will fail here even if both the schema and the chain individually verify.
func crossCheck(packet *auditpacket.Packet, chain receipt.ChainResult, receipts []receipt.Receipt) []error {
	var errs []error

	if packet.Summary.ReceiptCount < 0 || chain.ReceiptCount != uint64(packet.Summary.ReceiptCount) {
		errs = append(errs, fmt.Errorf("chain receipt_count %d != packet.summary.receipt_count %d", chain.ReceiptCount, packet.Summary.ReceiptCount))
	}

	expectedTotals := computeTotals(receipts)
	gotTotals := map[string]int{
		"allow":    packet.Summary.Totals.Allow,
		"block":    packet.Summary.Totals.Block,
		"warn":     packet.Summary.Totals.Warn,
		"ask":      packet.Summary.Totals.Ask,
		"strip":    packet.Summary.Totals.Strip,
		"forward":  packet.Summary.Totals.Forward,
		"redirect": packet.Summary.Totals.Redirect,
		"other":    packet.Summary.Totals.Other,
	}
	for _, k := range sortedKeys(expectedTotals) {
		if expectedTotals[k] != gotTotals[k] {
			errs = append(errs, fmt.Errorf("totals[%s]: chain=%d packet=%d", k, expectedTotals[k], gotTotals[k]))
		}
	}

	// root_hash + final_seq are optional in v0. Cross-check only when set.
	if packet.Verifier.RootHash != "" && packet.Verifier.RootHash != chain.RootHash {
		errs = append(errs, fmt.Errorf("root_hash mismatch: chain=%s packet=%s", chain.RootHash, packet.Verifier.RootHash))
	}
	if packet.Verifier.FinalSeq != 0 && (packet.Verifier.FinalSeq < 0 || uint64(packet.Verifier.FinalSeq) != chain.FinalSeq) {
		errs = append(errs, fmt.Errorf("final_seq mismatch: chain=%d packet=%d", chain.FinalSeq, packet.Verifier.FinalSeq))
	}

	// verdict-vs-chain agreement: chain.Valid must align with verdict
	// semantics. valid+trusted requires Valid; invalid requires !Valid; error
	// and not_run carry no chain claim. self_consistent_only requires Valid
	// (the chain hashed up) but no trust claim.
	switch packet.Verifier.Verdict {
	case auditpacket.VerdictValid, auditpacket.VerdictSelfConsistentOnly:
		if !chain.Valid {
			errs = append(errs, fmt.Errorf("verdict=%s but chain rejected: %s", packet.Verifier.Verdict, chain.Error))
		}
	case auditpacket.VerdictInvalid:
		if chain.Valid {
			errs = append(errs, errors.New("verdict=invalid but chain re-verified successfully"))
		}
	}

	return errs
}

func computeTotals(receipts []receipt.Receipt) map[string]int {
	totals := map[string]int{
		"allow":    0,
		"block":    0,
		"warn":     0,
		"ask":      0,
		"strip":    0,
		"forward":  0,
		"redirect": 0,
		"other":    0,
	}
	for _, r := range receipts {
		v := strings.ToLower(strings.TrimSpace(r.ActionRecord.Verdict))
		if _, ok := totals[v]; ok {
			totals[v]++
			continue
		}
		totals["other"]++
	}
	return totals
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// trustVerdict applies the verifier's trust policy. Valid+trusted is always
// trusted. self_consistent_only is opt-in via --allow-self-consistent-only;
// the schema requires Trusted=false on it. --no-trust-required degrades the
// check to "did the schema and chain both pass".
func trustVerdict(packet *auditpacket.Packet, opts auditPacketOptions) bool {
	if opts.relaxTrust {
		return true
	}
	switch packet.Verifier.Verdict {
	case auditpacket.VerdictValid:
		return packet.Verifier.Trusted
	case auditpacket.VerdictSelfConsistentOnly:
		return opts.allowSCO
	default:
		return false
	}
}

func chainStatusLabel(c receipt.ChainResult) string {
	if c.Valid {
		return statusPass
	}
	return statusFail
}
