// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// VerifyReceiptCmd returns the "verify-receipt" cobra command.
func VerifyReceiptCmd() *cobra.Command {
	var expectedKey string

	cmd := &cobra.Command{
		Use:   "verify-receipt <file>",
		Short: "Verify a signed action receipt",
		Long: `Verifies the Ed25519 signature on an action receipt JSON file and prints
the action record details.

Exit 0 = valid signature, exit 1 = invalid or malformed.

The file must contain a JSON receipt with version, action_record, signature,
and signer_key fields. Use --key to verify against a specific public key
(hex-encoded) instead of trusting the embedded signer_key.

Examples:
  pipelock verify-receipt receipt.json
  pipelock verify-receipt receipt.json --key 70b991eb...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			out := cmd.OutOrStdout()

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
				return fmt.Errorf("verification failed")
			}

			_, _ = fmt.Fprintf(out, "OK: %s\n", path)
			_, _ = fmt.Fprintf(out, "  Action ID:   %s\n", r.ActionRecord.ActionID)
			_, _ = fmt.Fprintf(out, "  Action Type: %s\n", r.ActionRecord.ActionType)
			_, _ = fmt.Fprintf(out, "  Verdict:     %s\n", r.ActionRecord.Verdict)
			_, _ = fmt.Fprintf(out, "  Target:      %s\n", r.ActionRecord.Target)
			_, _ = fmt.Fprintf(out, "  Transport:   %s\n", r.ActionRecord.Transport)
			_, _ = fmt.Fprintf(out, "  Timestamp:   %s\n", r.ActionRecord.Timestamp.Format("2006-01-02T15:04:05Z"))
			_, _ = fmt.Fprintf(out, "  Signer:      %s\n", r.SignerKey)

			if r.ActionRecord.Principal != "" {
				_, _ = fmt.Fprintf(out, "  Principal:   %s\n", r.ActionRecord.Principal)
			}
			if r.ActionRecord.Actor != "" {
				_, _ = fmt.Fprintf(out, "  Actor:       %s\n", r.ActionRecord.Actor)
			}
			if r.ActionRecord.PolicyHash != "" {
				_, _ = fmt.Fprintf(out, "  Policy Hash: %s\n", r.ActionRecord.PolicyHash)
			}

			// Print full JSON if verbose (more than basic info)
			if r.ActionRecord.Method != "" || r.ActionRecord.Layer != "" {
				pretty, err := json.MarshalIndent(r.ActionRecord, "  ", "  ")
				if err == nil {
					_, _ = fmt.Fprintf(out, "\n  Full record:\n  %s\n", string(pretty))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&expectedKey, "key", "", "expected signer public key (hex)")
	return cmd
}
