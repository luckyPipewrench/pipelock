// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// ed25519PubKeyHexLen is the expected hex-encoded length of a 32-byte
// Ed25519 public key: 32 bytes = 64 hex characters.
const ed25519PubKeyHexLen = 64

// SigningSubtreeCmd returns the "signing" parent cobra command hosting
// offline ceremony verification subcommands: roster show, roster verify,
// recovery verify, and transition verify.
func SigningSubtreeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signing",
		Short: "Offline ceremony verification for key rosters and trust roots",
		Long: `Verify signed key rosters, recovery authorizations, and root
transition documents offline. These commands are used during key
ceremonies to confirm that signed artifacts are authentic before
trusting them in production.

Subcommand groups:
  roster      Show and verify key rosters
  recovery    Verify recovery authorizations
  transition  Verify root transition documents`,
	}

	roster := &cobra.Command{
		Use:   "roster",
		Short: "Show and verify key rosters",
	}
	roster.AddCommand(rosterShowCmd())
	roster.AddCommand(rosterVerifyCmd())

	recovery := &cobra.Command{
		Use:   "recovery",
		Short: "Verify recovery authorizations",
	}
	recovery.AddCommand(recoveryVerifyCmd())

	transition := &cobra.Command{
		Use:   "transition",
		Short: "Verify root transition documents",
	}
	transition.AddCommand(transitionVerifyCmd())

	cmd.AddCommand(roster, recovery, transition)
	return cmd
}

func rosterShowCmd() *cobra.Command {
	var path string
	var rootFingerprint string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Load and verify a key roster, then pretty-print its body",
		Long: `Loads a signed key roster from disk, verifies the signature
against the pinned root fingerprint, and prints the roster body as
indented JSON.

Examples:
  pipelock signing roster show --path roster.json --root-fingerprint sha256:abc123...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, err := domsigning.LoadRoster(filepath.Clean(path), rootFingerprint)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "load failed: %v\n", err)
				return err
			}

			data, err := json.MarshalIndent(loaded.Body, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal roster body: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to roster file (.json/.yaml/.yml)")
	cmd.Flags().StringVar(&rootFingerprint, "root-fingerprint", "", "pinned root fingerprint (sha256:...)")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("root-fingerprint")
	return cmd
}

func rosterVerifyCmd() *cobra.Command {
	var path string
	var rootFingerprint string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a key roster's signature and print a summary",
		Long: `Loads and verifies a signed key roster against the pinned root
fingerprint. On success prints the key count and signing key ID.
Exit 0 on success, non-zero on failure.

Examples:
  pipelock signing roster verify --path roster.json --root-fingerprint sha256:abc123...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, err := domsigning.LoadRoster(filepath.Clean(path), rootFingerprint)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"roster verified: %d keys, root_signed_by=%s\n",
				len(loaded.Body.Keys), loaded.Body.RosterSignedBy)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to roster file (.json/.yaml/.yml)")
	cmd.Flags().StringVar(&rootFingerprint, "root-fingerprint", "", "pinned root fingerprint (sha256:...)")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("root-fingerprint")
	return cmd
}

func recoveryVerifyCmd() *cobra.Command {
	var path string
	var recoveryPubkeyHex string
	var pinnedFingerprint string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a recovery authorization file",
		Long: `Loads and verifies a recovery authorization against the
specified recovery-root public key and pinned fingerprint. Checks
the signature, time window, and structural validity.
Exit 0 on success, non-zero on failure.

Examples:
  pipelock signing recovery verify --path recovery.json --recovery-pubkey <64-char-hex> --pinned-fingerprint sha256:abc123...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pubBytes, err := decodeHexPubkey(recoveryPubkeyHex)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			loaded, err := domsigning.LoadRecoveryAuthorization(
				filepath.Clean(path), pubBytes, pinnedFingerprint, time.Now())
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"recovery authorization verified: reason=%s, expires_at=%s, operator=%s\n",
				loaded.Body.Reason, loaded.Body.ExpiresAt, loaded.Body.OperatorIdentity)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to recovery authorization file")
	cmd.Flags().StringVar(&recoveryPubkeyHex, "recovery-pubkey", "", "recovery-root public key (64-char hex)")
	cmd.Flags().StringVar(&pinnedFingerprint, "pinned-fingerprint", "", "operator-pinned recovery-root fingerprint (sha256:...)")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("recovery-pubkey")
	_ = cmd.MarkFlagRequired("pinned-fingerprint")
	return cmd
}

func transitionVerifyCmd() *cobra.Command {
	var path string
	var oldPubkeyHex string
	var newPubkeyHex string
	var pinnedFingerprint string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a root transition document's dual signatures",
		Long: `Loads and verifies a root transition document against both
the old and new public keys. Both signatures must be valid. When
--pinned is supplied, the old fingerprint in the document must
match it.
Exit 0 on success, non-zero on failure.

Examples:
  pipelock signing transition verify --path transition.json --old-pubkey <hex> --new-pubkey <hex>
  pipelock signing transition verify --path transition.json --old-pubkey <hex> --new-pubkey <hex> --pinned sha256:abc123...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			oldPub, err := decodeHexPubkey(oldPubkeyHex)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: invalid old-pubkey: %v\n", err)
				return fmt.Errorf("invalid old-pubkey: %w", err)
			}

			newPub, err := decodeHexPubkey(newPubkeyHex)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: invalid new-pubkey: %v\n", err)
				return fmt.Errorf("invalid new-pubkey: %w", err)
			}

			loaded, err := domsigning.LoadRootTransition(
				filepath.Clean(path), oldPub, newPub, pinnedFingerprint)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verify failed: %v\n", err)
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"transition verified: kind=%s, old=%s, new=%s, effective_at=%s\n",
				loaded.Body.RootKind, loaded.Body.OldFingerprint,
				loaded.Body.NewFingerprint, loaded.Body.EffectiveAt)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to root transition file")
	cmd.Flags().StringVar(&oldPubkeyHex, "old-pubkey", "", "old root public key (64-char hex)")
	cmd.Flags().StringVar(&newPubkeyHex, "new-pubkey", "", "new root public key (64-char hex)")
	cmd.Flags().StringVar(&pinnedFingerprint, "pinned", "", "operator-pinned old fingerprint (sha256:..., optional)")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("old-pubkey")
	_ = cmd.MarkFlagRequired("new-pubkey")
	return cmd
}

// decodeHexPubkey decodes a 64-character hex string into a 32-byte Ed25519
// public key. Returns a descriptive error on invalid input.
func decodeHexPubkey(hexStr string) ([]byte, error) {
	if len(hexStr) != ed25519PubKeyHexLen {
		return nil, fmt.Errorf("hex public key must be %d characters, got %d", ed25519PubKeyHexLen, len(hexStr))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in public key: %w", err)
	}
	return b, nil
}
