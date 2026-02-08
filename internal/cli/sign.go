package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func signCmd() *cobra.Command {
	var keystoreDir string
	var agent string

	cmd := &cobra.Command{
		Use:   "sign <file>",
		Short: "Sign a file with an agent's Ed25519 key",
		Long: `Creates a detached Ed25519 signature (<file>.sig) using the specified
agent's private key.

Agent resolution order: --agent flag, PIPELOCK_AGENT env var.

Examples:
  pipelock sign manifest.json --agent claude-code
  PIPELOCK_AGENT=buster pipelock sign handoff.md`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			out := cmd.OutOrStdout()

			agentName, err := resolveAgentName(agent)
			if err != nil {
				return err
			}

			dir, err := resolveKeystoreDir(keystoreDir)
			if err != nil {
				return err
			}
			ks := signing.NewKeystore(dir)

			privKey, err := ks.LoadPrivateKey(agentName)
			if err != nil {
				return fmt.Errorf("loading key for agent %q: %w", agentName, err)
			}

			sig, err := signing.SignFile(path, privKey)
			if err != nil {
				return err
			}

			sigPath := path + signing.SigExtension
			if err := signing.SaveSignature(sig, sigPath); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(out, "Signed %s (agent: %s)\n", path, agentName)
			_, _ = fmt.Fprintf(out, "Signature: %s\n", sigPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "dir", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().StringVar(&agent, "agent", "", "agent name (or set PIPELOCK_AGENT)")
	return cmd
}

func verifyCmd() *cobra.Command {
	var keystoreDir string
	var agent string
	var sigPath string

	cmd := &cobra.Command{
		Use:   "verify <file>",
		Short: "Verify a file's Ed25519 signature",
		Long: `Verifies a file against its detached signature (<file>.sig or --sig path)
using the specified agent's public key. Checks both the agent's own keys and
trusted keys.

Exit 0 = valid signature, exit 1 = invalid or missing.

Examples:
  pipelock verify manifest.json --agent claude-code
  pipelock verify handoff.md --agent buster --sig handoff.md.sig`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			out := cmd.OutOrStdout()

			agentName, err := resolveAgentName(agent)
			if err != nil {
				return err
			}

			dir, err := resolveKeystoreDir(keystoreDir)
			if err != nil {
				return err
			}
			ks := signing.NewKeystore(dir)

			pubKey, err := ks.ResolvePublicKey(agentName)
			if err != nil {
				return fmt.Errorf("loading key for agent %q: %w", agentName, err)
			}

			if err := signing.VerifyFile(path, sigPath, pubKey); err != nil {
				_, _ = fmt.Fprintf(out, "FAILED: %s (agent: %s): %v\n", path, agentName, err)
				return fmt.Errorf("verification failed")
			}

			_, _ = fmt.Fprintf(out, "OK: %s (agent: %s)\n", path, agentName)
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "dir", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().StringVar(&agent, "agent", "", "agent name (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&sigPath, "sig", "", "signature file path (default <file>.sig)")
	return cmd
}

func resolveAgentName(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv("PIPELOCK_AGENT"); env != "" {
		return env, nil
	}
	return "", fmt.Errorf("agent name required: use --agent or set PIPELOCK_AGENT")
}
