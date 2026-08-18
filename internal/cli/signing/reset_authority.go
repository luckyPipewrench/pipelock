// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// The exported half contains no secret material and is world-readable so a
// proxy running under a different UID can load it. This is a deliberate
// exception to the repository's 0o600 default for generated files.
const resetAuthorityPublicKeyMode os.FileMode = 0o644

func resetAuthorityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Mint and inspect MCP reset authority delegations",
		Long: `Mint short-lived, one-shot reset delegations outside the MCP proxy.
The proxy receives only the exported public key. The authority private key
stays with the operator and never enters the wrapped MCP server.`,
	}
	cmd.AddCommand(resetMintCmd(), resetInspectCmd(), resetRevokeCmd())
	return cmd
}

func keyExportPublicCmd() *cobra.Command {
	var keyPath string
	var outPath string
	var force bool
	cmd := &cobra.Command{
		Use:   "export-public",
		Short: "Export a deployment signing key's public half",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !filepath.IsAbs(keyPath) || !filepath.IsAbs(outPath) {
				return errors.New("--key and --out must be absolute paths")
			}
			cleanOut := filepath.Clean(outPath)
			if !force {
				if _, err := os.Lstat(cleanOut); err == nil {
					return fmt.Errorf("output file %q already exists (use --force to overwrite)", cleanOut)
				} else if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("stat output file %q: %w", cleanOut, err)
				}
			}
			_, publicKey, _, err := loadKeyFile(filepath.Clean(keyPath), "")
			if err != nil {
				return err
			}
			if err := atomicfile.Write(cleanOut, []byte(hex.EncodeToString(publicKey)+"\n"), resetAuthorityPublicKeyMode); err != nil {
				return fmt.Errorf("write public key: %w", err)
			}
			fingerprint, err := domsigning.Fingerprint(publicKey)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Exported public key\n  fingerprint: %s\n  out:         %s\n", fingerprint, cleanOut)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "absolute private deployment key file")
	cmd.Flags().StringVar(&outPath, "out", "", "absolute public-key output path")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing output file")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func resetMintCmd() *cobra.Command {
	var keyPath string
	var kind string
	var target string
	var instanceID string
	var epoch uint64
	var ttl time.Duration
	var outPath string
	var force bool
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint one signed MCP reset delegation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !filepath.IsAbs(keyPath) || !filepath.IsAbs(outPath) {
				return errors.New("--key and --out must be absolute paths")
			}
			if ttl <= 0 {
				return errors.New("--ttl must be positive")
			}
			cleanOut := filepath.Clean(outPath)
			if !force {
				if _, err := os.Lstat(cleanOut); err == nil {
					return fmt.Errorf("output file %q already exists (use --force to overwrite)", cleanOut)
				} else if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("stat output file %q: %w", cleanOut, err)
				}
			}
			key, _, privateKey, err := loadKeyFile(filepath.Clean(keyPath), domsigning.PurposeMCPResetAuthority)
			if err != nil {
				return err
			}
			nonce, err := mcp.NewResetNonce()
			if err != nil {
				return fmt.Errorf("generate reset delegation nonce: %w", err)
			}
			now := time.Now().UTC()
			d, err := mcp.MintResetDelegation(privateKey, mcp.ResetDelegationRequest{Issuer: key.KeyID, Kind: mcp.ResetKind(kind), Target: target, InstanceID: instanceID, Epoch: epoch, IssuedAt: now, ExpiresAt: now.Add(ttl), Nonce: nonce})
			if err != nil {
				return err
			}
			raw, err := mcp.MarshalResetDelegation(d)
			if err != nil {
				return err
			}
			if err := atomicfile.Write(cleanOut, raw, 0o600); err != nil {
				return fmt.Errorf("write reset delegation: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Minted MCP reset delegation\n  issuer:   %s\n  target:   %s\n  instance: %s\n  epoch:    %d\n  expires:  %s\n  nonce:    %s\n  out:      %s\n", d.Issuer, d.Target, d.InstanceID, d.Epoch, time.Unix(d.ExpiresUnix, 0).UTC().Format(time.RFC3339), d.Nonce, cleanOut)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "absolute private mcp-reset-authority key file")
	cmd.Flags().StringVar(&kind, "kind", "", "reset kind: drift or adaptive")
	cmd.Flags().StringVar(&target, "target", "", "live MCP reset target identity")
	cmd.Flags().StringVar(&instanceID, "instance", "", "live proxy instance ID, from the proxy's startup log line 'MCP reset authority'")
	cmd.Flags().Uint64Var(&epoch, "epoch", 0, "current reset epoch: 0 since proxy start, then one higher than the epoch in the last accepted reset audit line")
	cmd.Flags().DurationVar(&ttl, "ttl", 5*time.Minute, "delegation lifetime (maximum 15m)")
	cmd.Flags().StringVar(&outPath, "out", "", "absolute control-file output path")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing output file")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("instance")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func resetInspectCmd() *cobra.Command {
	var path string
	var publicKeyPath string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect and verify a signed MCP reset delegation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			publicKey, err := readResetAuthorityPublicKey(publicKeyPath)
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return fmt.Errorf("read reset delegation: %w", err)
			}
			d, err := mcp.ParseResetDelegation(raw)
			if err != nil {
				return err
			}
			if err := mcp.VerifyResetDelegationSignature(publicKey, d); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "MCP reset delegation verified\n  issuer:   %s\n  target:   %s\n  instance: %s\n  kind:     %s\n  epoch:    %d\n  expires:  %s\n  nonce:    %s\n", d.Issuer, d.Target, d.InstanceID, d.Kind, d.Epoch, time.Unix(d.ExpiresUnix, 0).UTC().Format(time.RFC3339), d.Nonce)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "file", "", "reset delegation file")
	cmd.Flags().StringVar(&publicKeyPath, "public-key-file", "", "exported mcp-reset-authority public-key file")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("public-key-file")
	return cmd
}

func resetRevokeCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Remove an unconsumed MCP reset delegation file",
		Long: `Remove a pending delegation from its configured control-file path.
This cancels that path only. A copied delegation remains valid until expiry;
rotate the configured authority public key to revoke every delegation from the
old issuer.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clean := filepath.Clean(path)
			info, err := os.Lstat(clean)
			if err != nil {
				return fmt.Errorf("inspect reset delegation: %w", err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return errors.New("refuse to revoke a reset delegation path that is not a regular file")
			}
			if err := os.Remove(clean); err != nil {
				return fmt.Errorf("remove reset delegation: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed pending MCP reset delegation %s\n", clean)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "file", "", "reset delegation file to remove")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func readResetAuthorityPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := ReadKeyFileBytes(filepath.Clean(path), false)
	if err != nil {
		return nil, fmt.Errorf("read reset authority public key: %w", err)
	}
	publicKey, err := domsigning.ParsePublicKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("parse reset authority public key: %w", err)
	}
	return publicKey, nil
}
