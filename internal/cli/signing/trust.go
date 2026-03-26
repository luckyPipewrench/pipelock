// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// TrustCmd returns the "trust" cobra command.
func TrustCmd() *cobra.Command {
	var keystoreDir string

	cmd := &cobra.Command{
		Use:   "trust <agent-name> <pubkey-file>",
		Short: "Add an agent's public key to the trusted keystore",
		Long: `Copies an agent's Ed25519 public key into the trusted keystore
(~/.pipelock/trusted_keys/<name>.pub). The key is validated before storing.

After trusting, you can verify that agent's signatures with 'pipelock verify'.

Examples:
  pipelock trust buster /path/to/buster.pub
  pipelock trust claude-code ~/.pipelock/agents/claude-code/id_ed25519.pub`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			pubKeyPath := args[1]
			out := cmd.OutOrStdout()

			dir, err := cliutil.ResolveKeystoreDir(keystoreDir)
			if err != nil {
				return err
			}
			ks := domsigning.NewKeystore(dir)

			if err := ks.TrustKey(name, pubKeyPath); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(out, "Trusted agent %q\n", name)
			_, _ = fmt.Fprintf(out, "Verify with: pipelock verify <file> --agent %s\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	return cmd
}
