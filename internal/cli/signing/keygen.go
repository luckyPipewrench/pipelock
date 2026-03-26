// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// KeygenCmd returns the "keygen" cobra command.
func KeygenCmd() *cobra.Command {
	var keystoreDir string
	var force bool

	cmd := &cobra.Command{
		Use:   "keygen <agent-name>",
		Short: "Generate an Ed25519 key pair for an agent",
		Long: `Generates an Ed25519 signing key pair and stores it in the pipelock
keystore (~/.pipelock/agents/<name>/). The public key can be shared with other
agents via 'pipelock trust'.

Examples:
  pipelock keygen claude-code
  pipelock keygen buster --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			out := cmd.OutOrStdout()

			dir, err := cliutil.ResolveKeystoreDir(keystoreDir)
			if err != nil {
				return err
			}
			ks := domsigning.NewKeystore(dir)

			if force {
				_, err = ks.ForceGenerateAgent(name)
			} else {
				_, err = ks.GenerateAgent(name)
			}
			if err != nil {
				return err
			}

			pubPath := ks.PublicKeyPath(name)
			_, _ = fmt.Fprintf(out, "Key pair generated for agent %q\n", name)
			_, _ = fmt.Fprintf(out, "Public key: %s\n", pubPath)
			_, _ = fmt.Fprintf(out, "Share with: pipelock trust %s %s\n", name, pubPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing keys")
	return cmd
}
