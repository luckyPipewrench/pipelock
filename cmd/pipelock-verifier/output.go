// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	sigutil "github.com/luckyPipewrench/pipelock/internal/signing"
)

const unpinnedReceiptBanner = "UNPINNED — signature is self-consistent but the signer was NOT checked against a trusted key"

// emitReport writes the audit-packet report to stdout in either JSON or
// human-readable form. The human form is loosely structured so script
// consumers should prefer --json.
func emitReport(stdout, stderr io.Writer, r auditPacketReport, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, r)
		return
	}
	verdict := r.Verdict
	if verdict == "" {
		verdict = "(unset)"
	}
	_, _ = fmt.Fprintf(stdout, "Audit Packet:   %s\n", r.Path)
	_, _ = fmt.Fprintf(stdout, "  schema:       %s\n", r.SchemaCheck)
	_, _ = fmt.Fprintf(stdout, "  chain:        %s\n", r.ChainCheck)
	_, _ = fmt.Fprintf(stdout, "  cross-check:  %s\n", r.CrossCheck)
	_, _ = fmt.Fprintf(stdout, "  verdict:      %s\n", verdict)
	_, _ = fmt.Fprintf(stdout, "  trusted:      %t\n", r.Trusted)
	_, _ = fmt.Fprintf(stdout, "  receipts:     %d\n", r.Summary.ReceiptCount)
	if r.Run.Provider != "" {
		_, _ = fmt.Fprintf(stdout, "  provider:     %s\n", r.Run.Provider)
	}
	if r.Run.Repository != "" {
		_, _ = fmt.Fprintf(stdout, "  repository:   %s\n", r.Run.Repository)
	}
	if r.Run.SHA != "" {
		_, _ = fmt.Fprintf(stdout, "  sha:          %s\n", r.Run.SHA)
	}
	if r.Run.AgentIdentity != "" {
		_, _ = fmt.Fprintf(stdout, "  agent:        %s\n", r.Run.AgentIdentity)
	}
	if r.Posture.EnforcementMode != "" {
		_, _ = fmt.Fprintf(stdout, "  enforcement:  %s\n", r.Posture.EnforcementMode)
	}
	if len(r.Posture.UnsupportedPaths) > 0 {
		_, _ = fmt.Fprintf(stdout, "  unsupported:  %s\n", strings.Join(r.Posture.UnsupportedPaths, ", "))
	}
	for _, e := range r.Errors {
		_, _ = fmt.Fprintf(stderr, "ERROR: %s\n", e)
	}
	for _, w := range r.Warnings {
		_, _ = fmt.Fprintf(stderr, "WARN:  %s\n", w)
	}
	if r.Valid {
		_, _ = fmt.Fprintln(stdout, "  result:       VALID")
	} else {
		_, _ = fmt.Fprintln(stdout, "  result:       INVALID")
	}
}

// emitChainReport mirrors emitReport for the chain subcommand.
func emitChainReport(stdout, stderr io.Writer, r chainReport, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, r)
		return
	}
	if r.Valid {
		if r.Unpinned {
			_, _ = fmt.Fprintf(stdout, "CHAIN UNPINNED: %s\n", r.Path)
			_, _ = fmt.Fprintf(stdout, "  warning:    %s\n", unpinnedReceiptBanner)
		} else {
			_, _ = fmt.Fprintf(stdout, "CHAIN VALID: %s\n", r.Path)
		}
		if r.RecordType != "" {
			_, _ = fmt.Fprintf(stdout, "  record_type: %s\n", r.RecordType)
		}
		_, _ = fmt.Fprintf(stdout, "  receipts:   %d\n", r.ReceiptCount)
		_, _ = fmt.Fprintf(stdout, "  final seq:  %d\n", r.FinalSeq)
		_, _ = fmt.Fprintf(stdout, "  root hash:  %s\n", r.RootHash)
		if r.RecordType == recordTypeEvidenceV2 {
			_, _ = fmt.Fprintf(stdout, "  signer:     %s\n", r.SignerKeyID)
			if r.SignaturesVerified {
				_, _ = fmt.Fprintln(stdout, "  signatures: verified")
			} else {
				_, _ = fmt.Fprintln(stdout, "  signatures: not checked (self-consistency only; pass --key for provenance)")
			}
		}
		return
	}
	if r.Unpinned {
		_, _ = fmt.Fprintf(stderr, "CHAIN UNPINNED: %s\n", r.Path)
		_, _ = fmt.Fprintf(stderr, "  warning:    %s\n", unpinnedReceiptBanner)
		return
	}
	_, _ = fmt.Fprintf(stderr, "CHAIN BROKEN: %s\n", r.Path)
	if r.Error != "" {
		_, _ = fmt.Fprintf(stderr, "  error:      %s\n", r.Error)
	}
	if r.BrokenAtSeq != 0 || r.Error != "" {
		_, _ = fmt.Fprintf(stderr, "  broken at:  seq %d\n", r.BrokenAtSeq)
	}
}

// emitReceiptReport mirrors emitReport for the receipt subcommand.
func emitReceiptReport(stdout, stderr io.Writer, r receiptReport, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, r)
		return
	}
	if r.Valid {
		if r.Unpinned {
			_, _ = fmt.Fprintf(stdout, "RECEIPT UNPINNED: %s\n", r.Path)
			_, _ = fmt.Fprintf(stdout, "  warning:      %s\n", unpinnedReceiptBanner)
		} else {
			_, _ = fmt.Fprintf(stdout, "RECEIPT VALID: %s\n", r.Path)
		}
		if r.RecordType != "" {
			_, _ = fmt.Fprintf(stdout, "  record_type:  %s\n", r.RecordType)
		}
		if r.RecordType == recordTypeEvidenceV2 {
			_, _ = fmt.Fprintf(stdout, "  payload_kind: %s\n", r.PayloadKind)
			_, _ = fmt.Fprintf(stdout, "  signer:       %s\n", r.SignerKeyID)
			if r.ContractHash != "" {
				_, _ = fmt.Fprintf(stdout, "  contract:     %s\n", r.ContractHash)
			}
			if r.ActiveManifestHash != "" {
				_, _ = fmt.Fprintf(stdout, "  manifest:     %s\n", r.ActiveManifestHash)
			}
			if r.PolicyHash != "" {
				_, _ = fmt.Fprintf(stdout, "  policy_hash:  %s\n", r.PolicyHash)
			}
			if r.SignaturesVerified {
				_, _ = fmt.Fprintln(stdout, "  signature:    verified")
			} else {
				_, _ = fmt.Fprintln(stdout, "  signature:    not checked (pass --key for provenance)")
			}
			_, _ = fmt.Fprintf(stdout, "  chain_seq:    %d\n", r.ChainSeq)
			return
		}
		_, _ = fmt.Fprintf(stdout, "  action_id:    %s\n", r.ActionID)
		_, _ = fmt.Fprintf(stdout, "  verdict:      %s\n", r.Verdict)
		_, _ = fmt.Fprintf(stdout, "  transport:    %s\n", r.Transport)
		_, _ = fmt.Fprintf(stdout, "  signer:       %s\n", r.SignerKey)
		_, _ = fmt.Fprintf(stdout, "  policy_hash:  %s\n", r.PolicyHash)
		_, _ = fmt.Fprintf(stdout, "  chain_seq:    %d\n", r.ChainSeq)
		return
	}
	if r.Unpinned {
		_, _ = fmt.Fprintf(stderr, "RECEIPT UNPINNED: %s\n", r.Path)
		_, _ = fmt.Fprintf(stderr, "  warning: %s\n", unpinnedReceiptBanner)
		return
	}
	_, _ = fmt.Fprintf(stderr, "RECEIPT INVALID: %s\n", r.Path)
	if r.Error != "" {
		_, _ = fmt.Fprintf(stderr, "  error: %s\n", r.Error)
	}
}

// writeJSON marshals v to stdout. Marshal failures degrade to a
// machine-readable error envelope. The envelope is itself produced via
// json.Marshal so quotes / backslashes / control bytes in the inner error
// text round-trip safely; falling back to fmt.Sprintf would have produced
// invalid JSON for any error containing those characters.
func writeJSON(out io.Writer, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		envelope, mErr := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: "json marshal failed: " + err.Error()})
		if mErr != nil {
			envelope = []byte(`{"error":"json marshal failed"}`)
		}
		_, _ = out.Write(envelope)
		_, _ = fmt.Fprintln(out)
		return
	}
	_, _ = out.Write(data)
	_, _ = fmt.Fprintln(out)
}

// resolveSignerKey accepts a key as raw hex, Pipelock public-key text form,
// or a file path holding either, and returns the canonical lowercase hex.
// An empty input yields an empty hex string, which downstream verification
// interprets as self-consistent mode.
func resolveSignerKey(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil
	}
	key, err := sigutil.LoadPublicKey(input)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// sha256Hex returns the lowercase hex digest of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// exitCodeFor maps an error to a verifier exit code. ExitError carries an
// explicit code; cobra usage errors map to exitUsage. Other bare errors
// default to ExitGeneral.
func exitCodeFor(err error) int {
	if err == nil {
		return cliutil.ExitOK
	}
	var ee *cliutil.ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	if isCobraUsageError(err) {
		return exitUsage
	}
	return cliutil.ExitGeneral
}

// isCobraUsageError matches the four prefixes cobra emits today for
// usage-class failures. Flag errors are routed through SetFlagErrorFunc
// directly, so they never reach this matcher; this exists only to map the
// remaining unknown-command and missing-arg paths to exit code 64. Cobra
// version bumps may shift wording; if a future cobra changes a prefix the
// CLI degrades to ExitGeneral, not to a wrong exit code.
func isCobraUsageError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "unknown command ") ||
		strings.HasPrefix(msg, "unknown flag:") ||
		strings.HasPrefix(msg, "accepts ") ||
		strings.HasPrefix(msg, "requires at least ")
}
