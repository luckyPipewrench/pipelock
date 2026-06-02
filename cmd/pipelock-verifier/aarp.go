// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// aarpOptions holds resolved CLI flags for the aarp subcommand.
type aarpOptions struct {
	trustPath  string
	jsonOutput bool
	chain      bool
}

// trustFile is the on-disk trust input shared by all four reference verifiers.
// It carries ONLY pinned, operator-controlled trust — never anything fetched
// live. trusted_keys maps a key id to its Ed25519 public key (64-hex); a
// signature whose key id is absent is reported unknown_key and never verifies.
// trust_entries maps a key id to the authority namespace it is authorized to
// assert, so a verified signature can confirm the mediator_key_pinned claim.
type trustFile struct {
	TrustedKeys  map[string]string         `json:"trusted_keys"`
	TrustEntries map[string]trustEntryFile `json:"trust_entries,omitempty"`
}

type trustEntryFile struct {
	MediatorID  string `json:"mediator_id"`
	Role        string `json:"role,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"`
}

// envelopeFatal is the --json body the verifier prints when the envelope is
// fatal to appraise at all (schema violation, profile/canon mismatch, unknown
// critical extension). It carries no appraisal because none was produced; the
// non-zero exit code is the cross-language signal the gate compares.
type envelopeFatal struct {
	EnvelopeFatal bool   `json:"envelope_fatal"`
	Error         string `json:"error,omitempty"`
}

func newAARPCmd() *cobra.Command {
	var opts aarpOptions

	cmd := &cobra.Command{
		Use:   "aarp PATH",
		Short: "Appraise an AARP v0.1 assurance envelope",
		Long: `Appraises an AARP (Agent Action Receipt Profile) v0.1 assurance envelope
against a pinned trust file. PATH points at a JSON envelope.

The appraisal reports which claims the verifier could cryptographically confirm,
grouped by axis, plus the fixed does_not_assert list. It never emits a "trusted"
or "safe" verdict. Per-signature problems (unknown suite, untrusted key, bad
signature) are reported per signature, never as an envelope rejection, so one
bad parallel signature cannot mask a good one.

Exit codes: 0 the envelope was appraised; 1 the envelope is fatal to appraise
(schema violation, profile/canon mismatch, unknown critical extension); 2 an
I/O or trust-file error; 64 a usage error. With --json the verifier prints the
cross-language comparable appraisal on stdout (or {"envelope_fatal":true} when
the envelope is fatal).`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAARP(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.trustPath, "trust", "", "path to the pinned trust JSON (trusted_keys + trust_entries)")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit the comparable appraisal JSON on stdout")
	cmd.Flags().BoolVar(&opts.chain, "chain", false, "PATH is a JSONL stream of envelopes; verify Rung-1 chain linkage")

	return cmd
}

func runAARP(stdout, stderr io.Writer, target string, opts aarpOptions) error {
	verifyOpts, err := loadTrustFile(opts.trustPath)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("load trust: %w", err))
	}

	clean := filepath.Clean(target)
	data, err := os.ReadFile(clean)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read envelope: %w", err))
	}

	if opts.chain {
		return runAARPChain(stdout, stderr, data, opts.jsonOutput)
	}

	env, err := aarp.Unmarshal(data)
	if err != nil {
		return emitFatal(stdout, stderr, opts.jsonOutput, err)
	}

	ap, err := aarp.Verify(env, verifyOpts)
	if err != nil {
		return emitFatal(stdout, stderr, opts.jsonOutput, err)
	}

	comparableBytes, err := aarp.ComparableAppraisal(ap)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("render appraisal: %w", err))
	}
	if opts.jsonOutput {
		_, _ = stdout.Write(comparableBytes)
		_, _ = fmt.Fprintln(stdout)
	} else {
		emitAARPHuman(stdout, ap)
	}
	return nil
}

// runAARPChain verifies a JSONL stream of envelopes for Rung-1 chain linkage.
// A line that fails to parse, or a stream that is not contiguously hash-linked
// under a single issuer, is fatal (non-zero exit). Signature validity is NOT
// checked here — VerifyChain checks only the linkage that makes backdating,
// insertion, and reorder detectable; per-envelope signatures are appraised
// separately via the single-envelope path.
func runAARPChain(stdout, stderr io.Writer, data []byte, jsonMode bool) error {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	envs := make([]aarp.Envelope, 0, len(lines))
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		e, err := aarp.Unmarshal(line)
		if err != nil {
			return emitFatal(stdout, stderr, jsonMode, fmt.Errorf("chain line %d: %w", i, err))
		}
		envs = append(envs, e)
	}

	comparableBytes, err := aarp.ComparableChain(envs)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("render chain: %w", err))
	}
	if jsonMode {
		_, _ = stdout.Write(comparableBytes)
		_, _ = fmt.Fprintln(stdout)
	} else {
		_, _ = fmt.Fprintf(stdout, "AARP chain: %d envelopes\n", len(envs))
	}
	if aarp.VerifyChain(envs) != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("chain not linked"))
	}
	return nil
}

// emitFatal prints the envelope-fatal marker (or human text) and returns the
// exit-1 error. Fatal means the verifier could not safely appraise the envelope
// at all; it is distinct from an appraisal that reports unverified claims.
func emitFatal(stdout, stderr io.Writer, jsonMode bool, cause error) error {
	if jsonMode {
		writeJSON(stdout, envelopeFatal{EnvelopeFatal: true, Error: cause.Error()})
	} else {
		_, _ = fmt.Fprintf(stderr, "ENVELOPE FATAL: %s\n", cause.Error())
	}
	return cliutil.ExitCodeError(cliutil.ExitGeneral, cause)
}

func emitAARPHuman(stdout io.Writer, ap *aarp.Appraisal) {
	_, _ = fmt.Fprintf(stdout, "AARP appraisal (%s)\n", ap.Profile)
	_, _ = fmt.Fprintf(stdout, "  assertion_signed:   %t\n", ap.AssertionSigned)
	_, _ = fmt.Fprintf(stdout, "  verified_claims:    %v\n", ap.VerifiedClaims)
	_, _ = fmt.Fprintf(stdout, "  claimed_unverified: %v\n", ap.ClaimedUnverified)
	for _, s := range ap.Signatures {
		_, _ = fmt.Fprintf(stdout, "  signature %s/%s: %s\n", s.KeyID, s.Alg, s.Status)
	}
	_, _ = fmt.Fprintf(stdout, "  does_not_assert:    %v\n", ap.DoesNotAssert)
}

// loadTrustFile reads the pinned trust JSON into VerifyOptions. A missing path
// yields empty trust (every signature is reported unknown_key) so the verifier
// still runs and the gate can exercise the no-trust path.
func loadTrustFile(path string) (aarp.VerifyOptions, error) {
	opts := aarp.VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{},
		Trust:       map[string]aarp.TrustEntry{},
	}
	if path == "" {
		return opts, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return aarp.VerifyOptions{}, fmt.Errorf("read trust file: %w", err)
	}
	var tf trustFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tf); err != nil {
		return aarp.VerifyOptions{}, fmt.Errorf("parse trust file: %w", err)
	}
	for keyID, keyHex := range tf.TrustedKeys {
		raw, err := hex.DecodeString(keyHex)
		if err != nil {
			return aarp.VerifyOptions{}, fmt.Errorf("trusted_keys[%q]: not hex: %w", keyID, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return aarp.VerifyOptions{}, fmt.Errorf("trusted_keys[%q]: %d bytes, want %d", keyID, len(raw), ed25519.PublicKeySize)
		}
		opts.TrustedKeys[keyID] = ed25519.PublicKey(raw)
	}
	for keyID, e := range tf.TrustEntries {
		opts.Trust[keyID] = aarp.TrustEntry{
			MediatorID:  e.MediatorID,
			Role:        e.Role,
			TrustDomain: e.TrustDomain,
		}
	}
	return opts, nil
}
