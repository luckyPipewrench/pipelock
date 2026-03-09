//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/spf13/cobra"
)

const (
	licenseDefaultDir  = ".config/pipelock"
	licensePrivKeyFile = "license.key"
	licensePubKeyFile  = "license.pub"
	licenseLedgerFile  = "licenses.jsonl"
)

// LicenseCmd returns the license command tree: keygen, issue, inspect.
func LicenseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "license",
		Short: "Manage license keys for premium features",
	}
	cmd.AddCommand(
		licenseKeygenCmd(),
		licenseIssueCmd(),
		licenseInspectCmd(),
	)
	return cmd
}

func licenseKeygenCmd() *cobra.Command {
	var outDir string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate Ed25519 keypair for signing license tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if outDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("find home dir: %w", err)
				}
				outDir = filepath.Join(home, licenseDefaultDir)
			}
			if err := os.MkdirAll(outDir, 0o750); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}

			privPath := filepath.Join(outDir, licensePrivKeyFile)
			pubPath := filepath.Join(outDir, licensePubKeyFile)

			// Refuse to overwrite existing keys.
			if _, err := os.Stat(privPath); err == nil {
				return fmt.Errorf("private key already exists at %s (delete it first to regenerate)", privPath)
			}

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generate keypair: %w", err)
			}

			if err := signing.SavePrivateKey(priv, privPath); err != nil {
				return fmt.Errorf("save private key: %w", err)
			}
			if err := signing.SavePublicKey(pub, pubPath); err != nil {
				return fmt.Errorf("save public key: %w", err)
			}

			pubHex := hex.EncodeToString(pub)

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Keypair generated:\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Private key: %s (KEEP SECRET, back up securely)\n", privPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Public key:  %s\n", pubPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nPublic key (hex, for ldflags or config):\n  %s\n", pubHex)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nBuild with embedded key:\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  go build -ldflags \"-X github.com/luckyPipewrench/pipelock/internal/license.PublicKeyHex=%s\" ./cmd/pipelock\n", pubHex)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nFor dev builds, set license_public_key in your config YAML.\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Official releases use the embedded key (ldflags) and ignore the config field.\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&outDir, "out", "", "output directory (default: ~/.config/pipelock)")
	return cmd
}

func licenseIssueCmd() *cobra.Command {
	var (
		keyPath    string
		email      string
		org        string
		expiresStr string
		features   []string
		ledgerPath string
	)

	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a signed license token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keyPath == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("find home dir: %w", err)
				}
				keyPath = filepath.Join(home, licenseDefaultDir, licensePrivKeyFile)
			}
			if email == "" {
				return fmt.Errorf("--email is required")
			}
			if len(features) == 0 {
				features = []string{license.FeatureAgents}
			}

			priv, err := signing.LoadPrivateKeyFile(keyPath)
			if err != nil {
				return fmt.Errorf("load private key: %w", err)
			}

			var expiresAt int64
			if expiresStr != "" {
				t, err := time.Parse(time.DateOnly, expiresStr)
				if err != nil {
					return fmt.Errorf("parse --expires (use YYYY-MM-DD): %w", err)
				}
				expiresAt = t.Unix()
			}

			// Generate a short unique ID from random bytes.
			idBytes := make([]byte, 6) // 12 hex chars
			if _, err := rand.Read(idBytes); err != nil {
				return fmt.Errorf("generate license ID: %w", err)
			}

			lic := license.License{
				ID:        "lic_" + hex.EncodeToString(idBytes),
				Email:     email,
				Org:       org,
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: expiresAt,
				Features:  features,
			}

			token, err := license.Issue(lic, priv)
			if err != nil {
				return fmt.Errorf("issue license: %w", err)
			}

			// Append to ledger for tracking.
			if ledgerPath == "" {
				ledgerPath = filepath.Join(filepath.Dir(keyPath), licenseLedgerFile)
			}
			if err := appendLedger(ledgerPath, lic, token); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: failed to write ledger: %v\n", err)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "License issued:\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  ID:       %s\n", lic.ID)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Email:    %s\n", lic.Email)
			if lic.Org != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Org:      %s\n", lic.Org)
			}
			if lic.ExpiresAt > 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Expires:  %s\n", time.Unix(lic.ExpiresAt, 0).UTC().Format(time.DateOnly))
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Expires:  never\n")
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Features: %v\n", lic.Features)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Ledger:   %s\n", ledgerPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nToken (put this in license_key config field):\n%s\n", token)

			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "", "path to private key (default: ~/.config/pipelock/license.key)")
	cmd.Flags().StringVar(&email, "email", "", "customer email (required)")
	cmd.Flags().StringVar(&org, "org", "", "organization name")
	cmd.Flags().StringVar(&expiresStr, "expires", "", "expiration date YYYY-MM-DD (omit for no expiration)")
	cmd.Flags().StringSliceVar(&features, "features", nil, "feature list (default: [agents])")
	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "ledger file path (default: alongside private key)")
	return cmd
}

func licenseInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect TOKEN",
		Short: "Decode and display a license token (does not verify signature)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lic, err := license.Decode(args[0])
			if err != nil {
				return fmt.Errorf("decode token: %w", err)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "License contents (signature NOT verified):\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  ID:       %s\n", lic.ID)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Email:    %s\n", lic.Email)
			if lic.Org != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Org:      %s\n", lic.Org)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Issued:   %s\n", time.Unix(lic.IssuedAt, 0).UTC().Format(time.RFC3339))
			if lic.ExpiresAt > 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Expires:  %s\n", time.Unix(lic.ExpiresAt, 0).UTC().Format(time.DateOnly))
				if time.Now().Unix() > lic.ExpiresAt {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Status:   EXPIRED (signature not checked)\n")
				} else {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Status:   not expired (signature not checked)\n")
				}
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Expires:  never\n")
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n  WARNING: inspect does not verify the signature.\n"+
				"  This token may be forged or tampered. Run pipelock with this token to verify at startup.\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Features: %v\n", lic.Features)

			return nil
		},
	}
	return cmd
}

// ledgerEntry records an issued license for tracking.
type ledgerEntry struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	Org       string   `json:"org,omitempty"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Features  []string `json:"features"`
	Token     string   `json:"token"`
}

func appendLedger(path string, lic license.License, token string) error {
	entry := ledgerEntry{
		ID:       lic.ID,
		Email:    lic.Email,
		Org:      lic.Org,
		IssuedAt: time.Unix(lic.IssuedAt, 0).UTC().Format(time.RFC3339),
		Features: lic.Features,
		Token:    token,
	}
	if lic.ExpiresAt > 0 {
		entry.ExpiresAt = time.Unix(lic.ExpiresAt, 0).UTC().Format(time.DateOnly)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	cleanPath := filepath.Clean(path)

	// Reject symlinks to prevent writing to unexpected locations.
	if info, err := os.Lstat(cleanPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ledger path %s is a symlink (not allowed for security)", cleanPath)
		}
	}

	f, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		closeErr := f.Close()
		if closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}
	return f.Close()
}
