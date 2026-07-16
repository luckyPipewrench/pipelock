//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/coveragecert"
	"github.com/luckyPipewrench/pipelock/internal/coveragecertverify"
	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/signingflag"
)

const coverageCertReceiptReadLimit = 100000

// coverageCertCmd returns the `coverage-cert` command group with generate + verify.
func coverageCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "coverage-cert",
		Short: "Coverage certificate operations (generate, verify)",
	}
	cmd.AddCommand(coverageCertGenerateCmd())
	cmd.AddCommand(coverageCertVerifyCmd())
	return cmd
}

type coverageCertGenerateOptions struct {
	agent                 string
	receiptDir            string
	signingKeyFile        string
	trustedReceiptSigners []string
	windowStart           string
	windowEnd             string
	outFile               string
	licenseCRLFile        string
}

func coverageCertGenerateCmd() *cobra.Command {
	opts := coverageCertGenerateOptions{}
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a signed coverage certificate for an agent (Pro)",
		Long: `Generate a signed coverage certificate for a single agent over a time
window. The certificate summarizes per-session receipt chain integrity and
completeness from the flight-recorder evidence directory.

Requires a Pro license (agents feature). The certificate is signed with
the Ed25519 private key specified by --signing-key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate: fail closed before any file IO.
			_, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{
				CRLFile: opts.licenseCRLFile,
			})
			if err != nil {
				return err
			}
			return runCoverageCertGenerate(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.agent, "agent", "", "agent identifier for the certificate")
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "",
		"flight-recorder evidence directory holding action receipts")
	cmd.Flags().StringVar(&opts.signingKeyFile, "signing-key", "",
		"Ed25519 private key file for signing the certificate")
	cmd.Flags().StringArrayVar(&opts.trustedReceiptSigners, "trusted-receipt-signer", nil,
		"trusted receipt signing key as comma-separated kv pairs: "+
			"'(inline=HEX_OR_VERSIONED_PUBLIC_KEY|file=/path)[,source=LABEL]'; repeatable")
	cmd.Flags().StringVar(&opts.windowStart, "window-start", "",
		"coverage window start (RFC3339)")
	cmd.Flags().StringVar(&opts.windowEnd, "window-end", "",
		"coverage window end (RFC3339)")
	cmd.Flags().StringVar(&opts.outFile, "out", "",
		"output file path; defaults to stdout")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "",
		"signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	_ = cmd.MarkFlagRequired("agent")
	_ = cmd.MarkFlagRequired("receipt-dir")
	_ = cmd.MarkFlagRequired("signing-key")
	_ = cmd.MarkFlagRequired("window-start")
	_ = cmd.MarkFlagRequired("window-end")
	return cmd
}

func runCoverageCertGenerate(cmd *cobra.Command, opts coverageCertGenerateOptions) error {
	windowStart, err := time.Parse(time.RFC3339, opts.windowStart)
	if err != nil {
		return fmt.Errorf("--window-start: %w", err)
	}
	windowEnd, err := time.Parse(time.RFC3339, opts.windowEnd)
	if err != nil {
		return fmt.Errorf("--window-end: %w", err)
	}

	// Normalize the CLI-provided agent once so incidental whitespace cannot
	// bypass the control-actor exception or actor matching in
	// sessionBelongsToAgent, and so the signed certificate body records the same
	// normalized identity that was matched against.
	agent := strings.TrimSpace(opts.agent)
	if agent == "" {
		return fmt.Errorf("--agent must not be empty")
	}

	cleanDir := filepath.Clean(opts.receiptDir)
	info, dirErr := os.Stat(cleanDir)
	if dirErr != nil {
		return fmt.Errorf("--receipt-dir: %w", dirErr)
	}
	if !info.IsDir() {
		return fmt.Errorf("--receipt-dir %q is not a directory", opts.receiptDir)
	}

	priv, err := signing.LoadPrivateKeyFile(opts.signingKeyFile)
	if err != nil {
		return fmt.Errorf("--signing-key: %w", err)
	}

	sessions, err := recorder.ListSessions(cleanDir)
	if err != nil {
		return fmt.Errorf("listing sessions: %w", err)
	}

	// priv.Public() has dynamic type ed25519.PublicKey (whose underlying type is
	// []byte); a direct []byte type assertion matches the wrong concrete type and
	// panics, so assert the exact type.
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("--signing-key: not an Ed25519 private key")
	}
	pubHex := hex.EncodeToString(pub)
	trustedReceiptKeys, err := parseCoverageCertTrustedReceiptSigners(opts.trustedReceiptSigners)
	if err != nil {
		return err
	}
	receiptChainSummary := "self-consistent only"
	if len(trustedReceiptKeys) > 0 {
		receiptChainSummary = "verified against trusted signer set"
	}

	var sessionCoverages []coveragecert.SessionCoverage
	var totalReceipts uint64
	var chainGaps uint64
	var chainsIntact, chainsBroken int

	for _, sid := range sessions {
		receipts, extractErr := loadCoverageCertSessionReceipts(cleanDir, sid, coverageCertReceiptReadLimit)
		if extractErr != nil {
			return extractErr
		}
		receipts = filterReceiptsToWindow(receipts, windowStart, windowEnd)
		if len(receipts) == 0 {
			continue
		}
		include, filterErr := sessionBelongsToAgent(sid, receipts, agent)
		if filterErr != nil {
			return filterErr
		}
		if !include {
			continue
		}

		chainResult := receipt.VerifyChainTrusted(receipts, trustedReceiptKeys)
		report := completeness.Analyze(receipts, chainResult)

		intact := chainResult.Valid
		sc := coveragecert.SessionCoverage{
			ID:                 sid,
			ReceiptCount:       report.ReceiptCount,
			ChainIntact:        intact,
			Anchored:           "local",
			CompletenessStatus: string(report.Status),
			CompletenessReason: string(report.Reason),
		}
		sessionCoverages = append(sessionCoverages, sc)
		totalReceipts += report.ReceiptCount
		if intact {
			chainsIntact++
		} else {
			chainsBroken++
			chainGaps++
		}
	}

	body := coveragecert.Body{
		Schema:             coveragecert.Schema,
		KeyPurpose:         coveragecert.KeyPurpose,
		Agent:              agent,
		WindowStart:        windowStart,
		WindowEnd:          windowEnd,
		Sessions:           sessionCoverages,
		TotalReceipts:      totalReceipts,
		ChainGaps:          chainGaps,
		SessionsCovered:    len(sessionCoverages),
		ChainsIntact:       chainsIntact,
		ChainsBroken:       chainsBroken,
		TrustedSignerKey:   pubHex,
		Boundary:           coveragecert.DefaultBoundary(),
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}
	if len(body.Sessions) == 0 {
		return fmt.Errorf("no receipts found for agent %q in %s", agent, cleanDir)
	}

	cert, err := coveragecert.Sign(body, priv)
	if err != nil {
		return fmt.Errorf("signing coverage certificate: %w", err)
	}

	data, err := coveragecert.Marshal(cert)
	if err != nil {
		return fmt.Errorf("marshaling coverage certificate: %w", err)
	}

	if opts.outFile != "" {
		cleanOut := filepath.Clean(opts.outFile)
		if writeErr := os.WriteFile(cleanOut, data, 0o600); writeErr != nil {
			return fmt.Errorf("--out: %w", writeErr)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "coverage certificate written to %s\n", cleanOut)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "receipt chains: %s\n", receiptChainSummary)
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", data)
	return nil
}

func parseCoverageCertTrustedReceiptSigners(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(raw))
	keys := make([]string, 0, len(raw))
	for _, value := range raw {
		keyHex, _, err := signingflag.ParseTrustedSignerSpec(value)
		if err != nil {
			return nil, fmt.Errorf("--trusted-receipt-signer %q: %w", value, err)
		}
		if _, ok := seen[keyHex]; ok {
			return nil, fmt.Errorf("--trusted-receipt-signer %q: duplicate key %s", value, keyHex)
		}
		seen[keyHex] = struct{}{}
		keys = append(keys, keyHex)
	}
	sort.Strings(keys)
	return keys, nil
}

func loadCoverageCertSessionReceipts(dir, sessionID string, limit int) ([]receipt.Receipt, error) {
	receipts, readLimited, err := receipt.ExtractReceiptsFromSessionDirBounded(dir, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("reading receipts for session %q: %w", sessionID, err)
	}
	if readLimited {
		return nil, fmt.Errorf("reading receipts for session %q: receipt read limit %d reached; refusing partial coverage certificate", sessionID, limit)
	}
	return receipts, nil
}

func filterReceiptsToWindow(receipts []receipt.Receipt, start, end time.Time) []receipt.Receipt {
	filtered := receipts[:0]
	for _, r := range receipts {
		ts := r.ActionRecord.Timestamp
		if ts.Before(start) || !ts.Before(end) {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// coverageCertAnonymousActor is pipelock's default actor for unattributed
// requests (no agent identity bound). It is tolerated only when generating the
// default proxy certificate whose declared actor is the session-control actor.
// For any other named agent, counting anonymous receipts would silently
// overstate that agent's covered traffic in the signed certificate body.
const coverageCertAnonymousActor = "anonymous"

// coverageCertControlActor is the proxy's built-in session-control actor. It is
// the only agent for which unattributed (anonymous) receipts are folded into a
// certificate, because a default single-agent deployment's traffic is
// legitimately unattributed under the proxy itself. This relies on "pipelock"
// and "anonymous" being reserved proxy actor names that an operator cannot bind
// to a named agent; enforcing that reservation at agent-config load (so a named
// agent can never masquerade as the control actor) is tracked as follow-up
// hardening and pairs with per-agent identity on receipts.
const coverageCertControlActor = "pipelock"

func sessionBelongsToAgent(sessionID string, receipts []receipt.Receipt, agent string) (bool, error) {
	if len(receipts) == 0 {
		return false, nil
	}
	hasDeclaredAgent := false
	otherActor := ""
	hasOtherActor := false
	for _, r := range receipts {
		actor := strings.TrimSpace(r.ActionRecord.Actor)
		// A missing actor is UNATTRIBUTED traffic, not an identity. Never derive
		// an actor from the session id: a session id is not an authenticated
		// agent identity, and treating it as one would falsely attribute
		// unattributed receipts to a named agent whose name happened to match a
		// session id (over-counting that agent's certified coverage). Fold empty
		// into anonymous so it is skipped only for the default control-actor
		// certificate and fails closed for every named agent.
		if actor == "" {
			actor = coverageCertAnonymousActor
		}
		if actor == coverageCertAnonymousActor {
			if agent == coverageCertControlActor {
				continue
			}
			if !hasOtherActor {
				otherActor = actor
				hasOtherActor = true
			}
			continue
		}
		if actor == agent {
			hasDeclaredAgent = true
			continue
		}
		if !hasOtherActor {
			otherActor = actor
			hasOtherActor = true
		}
	}
	if hasDeclaredAgent && hasOtherActor {
		return false, fmt.Errorf("session %q contains mixed actors: %q and %q", sessionID, agent, otherActor)
	}
	return hasDeclaredAgent, nil
}

type coverageCertVerifyOptions struct {
	certFile       string
	trustedSigners []string
	allowUnpinned  bool
}

func coverageCertVerifyCmd() *cobra.Command {
	opts := coverageCertVerifyOptions{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a coverage certificate offline",
		Long: `Verify a coverage certificate's Ed25519 signature and check the signer
against the trusted-signer set. Re-derives aggregate counts from the sessions
and flags any mismatch. Fully offline: no license, no server.

Fails closed with a non-zero exit if the signature is invalid, the aggregate
counts do not match, the certificate signer is not in the trusted-signer set,
or no trusted-signer set is supplied. Pass --allow-unpinned only
for an explicit structural-only check whose signer is not trusted.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCoverageCertVerify(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.certFile, "cert", "", "coverage certificate JSON file")
	cmd.Flags().StringArrayVar(&opts.trustedSigners, "trusted-signer", nil,
		"trusted signing key as comma-separated kv pairs: "+
			"'(inline=HEX_OR_VERSIONED_PUBLIC_KEY|file=/path)[,source=LABEL]'; repeatable")
	cmd.Flags().BoolVar(&opts.allowUnpinned, "allow-unpinned", false,
		"allow structural-only verification when no trusted-signer set is supplied")
	_ = cmd.MarkFlagRequired("cert")
	return cmd
}

func runCoverageCertVerify(cmd *cobra.Command, opts coverageCertVerifyOptions) error {
	return coveragecertverify.Run(coveragecertverify.Options{
		CertFile:       opts.certFile,
		TrustedSigners: opts.trustedSigners,
		AllowUnpinned:  opts.allowUnpinned,
		Out:            cmd.OutOrStdout(),
	})
}
