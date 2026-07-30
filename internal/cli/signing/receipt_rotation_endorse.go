// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

func receiptRotationGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "receipt-rotation",
		Short: "Prepare receipt signing-key rotation artifacts",
		Long: `Prepare offline artifacts for an old-key-endorsed receipt
signing-key rotation. The ceremony is intentionally deployment-neutral:
stop Pipelock first, prepare and verify the endorsement, replace the configured
key through your deployment system, then restart Pipelock.`,
	}
	cmd.AddCommand(receiptRotationEndorseCmd(time.Now))
	return cmd
}

func receiptRotationEndorseCmd(now func() time.Time) *cobra.Command {
	var chainDir string
	var sessionID string
	var priorKeyFile string
	var newKeyFile string
	var rootKeys []string
	var priorEndorsementPaths []string
	var outPath string

	cmd := &cobra.Command{
		Use:   "endorse",
		Short: "Authorize a successor receipt-signing key with the retiring key",
		Long: `Creates a rotation endorsement signed by the retiring receipt key.

Pipelock MUST be stopped cleanly before this command runs. The command fails
closed unless the presented chain verifies from an explicitly pinned root and
ends in a signed graceful-shutdown session_close receipt. It holds an exclusive
evidence-directory ceremony lock through publication and refuses an active
recorder. For a chain that has rotated before, pass each earlier endorsement in
order with --rotation-endorsement.

This command does not replace either key or restart Pipelock. After it succeeds,
install --new-key-file at the configured flight_recorder.signing_key_path and
restart Pipelock. Verify the resulting chain with the pinned root and every
endorsement. The successor must be a purpose-bound JSON key generated with
"pipelock signing key generate --purpose receipt-signing". A legacy retiring
key remains accepted so existing recorder deployments can migrate.

Example:
  pipelock signing receipt-rotation endorse \
    --chain /var/lib/pipelock/evidence \
    --session proxy \
    --prior-key-file /etc/pipelock/keys/flight-recorder-signing.key \
    --new-key-file /etc/pipelock/keys/flight-recorder-signing.next.key \
    --root-key /etc/pipelock/keys/flight-recorder-signing.root.pub \
    --out /etc/pipelock/keys/rotation-2026-07-30.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !filepath.IsAbs(outPath) {
				return fmt.Errorf("--out must be absolute, got %q", outPath)
			}
			cleanOut := filepath.Clean(outPath)
			ceremonyLock, err := recorder.AcquireEvidenceCeremonyLock(filepath.Clean(chainDir))
			if err != nil {
				return fmt.Errorf("lock stopped receipt chain: %w", err)
			}
			defer func() { _ = ceremonyLock.Close() }()

			priorKey, err := domsigning.LoadPrivateKeyFileForPurpose(
				filepath.Clean(priorKeyFile),
				domsigning.PurposeReceiptSigning,
			)
			if err != nil {
				return fmt.Errorf("load --prior-key-file: %w", err)
			}
			newKey, err := domsigning.LoadPrivateKeyFileForPurposeStrict(
				filepath.Clean(newKeyFile),
				domsigning.PurposeReceiptSigning,
			)
			if err != nil {
				return fmt.Errorf("load --new-key-file: %w", err)
			}
			newKeyHex, err := domsigning.PublicKeyHexFromPrivateKey(newKey)
			if err != nil {
				return fmt.Errorf("derive successor public key: %w", err)
			}

			trustedRoots, err := resolveExpectedKeyHexes(rootKeys)
			if err != nil {
				return fmt.Errorf("load --root-key: %w", err)
			}
			if len(trustedRoots) == 0 {
				return errors.New("at least one non-empty --root-key is required; trust-on-first-use is unsafe for a rotation ceremony")
			}

			priorEndorsements := make([]receipt.RotationEndorsement, 0, len(priorEndorsementPaths))
			for _, path := range priorEndorsementPaths {
				endorsement, loadErr := receipt.LoadRotationEndorsementFile(filepath.Clean(path))
				if loadErr != nil {
					return fmt.Errorf("load prior rotation endorsement %q: %w", path, loadErr)
				}
				priorEndorsements = append(priorEndorsements, endorsement)
			}

			receipts, err := receipt.ExtractReceiptsFromSessionDir(filepath.Clean(chainDir), sessionID)
			if err != nil {
				return fmt.Errorf("extract receipt chain: %w", err)
			}
			if len(receipts) == 0 {
				return errors.New("receipt chain is empty")
			}
			result := receipt.VerifyChainWithEndorsements(sessionID, receipts, priorEndorsements, trustedRoots)
			if !result.Valid {
				return fmt.Errorf("receipt chain is not valid from the pinned root: %s", result.Error)
			}

			tail := receipts[len(receipts)-1]
			if !isCleanSessionClose(tail) {
				return errors.New("receipt chain lacks a graceful shutdown seal: stop Pipelock cleanly and require a final signed session_close before rotation")
			}
			priorKeyHex, err := domsigning.PublicKeyHexFromPrivateKey(priorKey)
			if err != nil {
				return fmt.Errorf("derive retiring public key: %w", err)
			}
			if tail.SignerKey != priorKeyHex {
				return fmt.Errorf("retiring key does not sign the chain tail: tail=%s retiring=%s", tail.SignerKey, priorKeyHex)
			}
			if priorKeyHex == newKeyHex {
				return errors.New("successor key must differ from the retiring key")
			}
			for _, chainReceipt := range receipts {
				if chainReceipt.SignerKey == newKeyHex {
					return errors.New("successor key already signed this chain; retired keys must not be reinstated")
				}
			}
			if successorAppearsInPriorEndorsements(newKeyHex, priorEndorsements) {
				return errors.New("successor key appears in an earlier rotation endorsement; retired keys must not be reinstated")
			}
			tailHash, err := receipt.ReceiptHash(tail)
			if err != nil {
				return fmt.Errorf("hash receipt chain tail: %w", err)
			}

			endorsement, err := receipt.SignRotationEndorsement(receipt.RotationEndorsement{
				SessionID:     sessionID,
				PriorFinalSeq: tail.ActionRecord.ChainSeq,
				PriorTailHash: tailHash,
				NewSignerKey:  newKeyHex,
				RotatedAt:     now().UTC().Format(time.RFC3339Nano),
			}, priorKey)
			if err != nil {
				return fmt.Errorf("sign rotation endorsement: %w", err)
			}
			if err := receipt.VerifyRotationEndorsement(endorsement); err != nil {
				return fmt.Errorf("self-verify rotation endorsement: %w", err)
			}
			if err := confirmRotationTailStable(chainDir, sessionID, tail); err != nil {
				return err
			}
			data, err := json.MarshalIndent(endorsement, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal rotation endorsement: %w", err)
			}
			if err := atomicfile.WriteNew(cleanOut, append(data, '\n'), 0o600); errors.Is(err, os.ErrExist) {
				return fmt.Errorf("output file %q already exists; refusing to overwrite a signed ceremony artifact", cleanOut)
			} else if err != nil {
				return fmt.Errorf("write rotation endorsement: %w", err)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Rotation endorsement created\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  session:       %s\n", sessionID)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  prior signer:  %s\n", priorKeyHex)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  successor:     %s\n", newKeyHex)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  prior tail:    seq=%d hash=%s\n", tail.ActionRecord.ChainSeq, tailHash)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  out:           %s\n", cleanOut)
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Pipelock remains stopped; install the successor key, restart, then verify the new boundary.")
			return nil
		},
	}

	cmd.Flags().StringVar(&chainDir, "chain", "", "flight-recorder evidence directory")
	cmd.Flags().StringVar(&sessionID, "session", "proxy", "recorder session/writer ID")
	cmd.Flags().StringVar(&priorKeyFile, "prior-key-file", "", "retiring receipt-signing private key file")
	cmd.Flags().StringVar(&newKeyFile, "new-key-file", "", "purpose-bound JSON successor receipt-signing private key file")
	cmd.Flags().StringArrayVar(&rootKeys, "root-key", nil, "pinned root public key (hex or file path); repeat if needed")
	cmd.Flags().StringArrayVar(&priorEndorsementPaths, "rotation-endorsement", nil, "earlier rotation endorsement; repeat in chain order")
	cmd.Flags().StringVar(&outPath, "out", "", "absolute path for the new endorsement JSON")
	_ = cmd.MarkFlagRequired("chain")
	_ = cmd.MarkFlagRequired("prior-key-file")
	_ = cmd.MarkFlagRequired("new-key-file")
	_ = cmd.MarkFlagRequired("root-key")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func confirmRotationTailStable(chainDir, sessionID string, expected receipt.Receipt) error {
	receipts, err := receipt.ExtractReceiptsFromSessionDir(filepath.Clean(chainDir), sessionID)
	if err != nil {
		return fmt.Errorf("re-read receipt chain before publishing endorsement: %w", err)
	}
	if len(receipts) == 0 {
		return errors.New("receipt chain disappeared before endorsement publication")
	}
	actual := receipts[len(receipts)-1]
	expectedHash, err := receipt.ReceiptHash(expected)
	if err != nil {
		return fmt.Errorf("hash expected receipt chain tail: %w", err)
	}
	actualHash, err := receipt.ReceiptHash(actual)
	if err != nil {
		return fmt.Errorf("hash re-read receipt chain tail: %w", err)
	}
	if expectedHash != actualHash {
		return fmt.Errorf(
			"receipt chain changed during rotation preparation (tail seq %d became %d); keep Pipelock stopped and retry",
			expected.ActionRecord.ChainSeq,
			actual.ActionRecord.ChainSeq,
		)
	}
	return nil
}

func isCleanSessionClose(r receipt.Receipt) bool {
	return receipt.IsGracefulSessionCloseSeal(r)
}

func successorAppearsInPriorEndorsements(
	successor string,
	priorEndorsements []receipt.RotationEndorsement,
) bool {
	for _, priorEndorsement := range priorEndorsements {
		if priorEndorsement.PriorSignerKey == successor ||
			priorEndorsement.NewSignerKey == successor {
			return true
		}
	}
	return false
}
