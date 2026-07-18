//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/spf13/cobra"
)

const (
	intermediateKeyFile  = "intermediate.key"
	intermediateCertFile = "intermediate.json"
	// defaultIntermediateValidity is the default validity window for a minted
	// intermediate. 90 days is the spec's short-lived target; the operator can
	// raise it up to the library's maxIntermediateValidity with --validity.
	defaultIntermediateValidity = 90 * 24 * time.Hour
)

// licenseIntermediateCmd returns the "license intermediate" subcommand group.
func licenseIntermediateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intermediate",
		Short: "Mint and manage root-signed intermediate signing certificates",
		Long: `Manage the intermediate signing tier of the license PKI.

The offline ROOT key signs a short-lived INTERMEDIATE certificate; the online
license service then signs license tokens with the intermediate private key. A
service compromise loses the intermediate, never the root — revoke the
intermediate and mint a new one, the root never leaves the safe.`,
	}
	cmd.AddCommand(licenseIntermediateIssueCmd())
	return cmd
}

func licenseIntermediateIssueCmd() *cobra.Command {
	var (
		rootKeyPath string
		serial      string
		outDir      string
		validity    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Mint a root-signed intermediate signing certificate",
		Long: `Mint a new intermediate signing certificate from the OFFLINE ROOT key.

This generates a fresh Ed25519 intermediate keypair, signs an intermediate
certificate over the public half with the root private key, and writes:

  - intermediate.key  (0600) — the intermediate PRIVATE key; deploy ONLY to the
                       license service (PIPELOCK_LICENSE_KEY signing key).
  - intermediate.json (0600) — the root-signed certificate; distribute to every
                       consumer (license_intermediate_file / the env).

The root private key is read, used to sign, and never copied or logged. Run this
on the offline (air-gapped) host that holds the root key, then move the two
outputs out by hand.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if serial == "" {
				return cliutil.ExitCodeError(1, fmt.Errorf("--serial is required (a unique id; it is the CRL revocation key)"))
			}
			if validity <= 0 {
				return cliutil.ExitCodeError(1, fmt.Errorf("--validity must be positive"))
			}
			if rootKeyPath == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return cliutil.ExitCodeError(1, fmt.Errorf("find home dir: %w", err))
				}
				rootKeyPath = filepath.Join(home, licenseDefaultDir, licensePrivKeyFile)
			}
			if outDir == "" {
				outDir = "."
			}

			rootPriv, err := signing.LoadPrivateKeyFile(rootKeyPath)
			if err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("load root private key: %w", err))
			}

			// Fresh intermediate keypair. The private key goes to the service; the
			// public key is embedded in the cert.
			intPub, intPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("generate intermediate keypair: %w", err))
			}

			now := time.Now().UTC()
			cert, err := license.SignIntermediate(license.IntermediatePayload{
				Serial:    serial,
				Purpose:   license.PurposeLicenseSigning,
				Algorithm: license.AlgorithmEd25519,
				PublicKey: hex.EncodeToString(intPub),
				NotBefore: now.Add(-5 * time.Minute).Unix(), // small backdate for clock skew
				NotAfter:  now.Add(validity).Unix(),
				IssuedAt:  now.Unix(),
			}, rootPriv)
			if err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("sign intermediate certificate: %w", err))
			}
			certBytes, err := cert.MarshalJSON()
			if err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("marshal certificate: %w", err))
			}

			if err := os.MkdirAll(outDir, 0o750); err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("create output dir: %w", err))
			}
			keyPath := filepath.Join(outDir, intermediateKeyFile)
			certPath := filepath.Join(outDir, intermediateCertFile)

			// Refuse to overwrite an existing key so a re-run cannot silently
			// clobber an in-use intermediate private key.
			if _, statErr := os.Stat(keyPath); statErr == nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("intermediate key already exists at %s (move it aside first)", keyPath))
			}

			if err := signing.SavePrivateKey(intPriv, keyPath); err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("save intermediate private key: %w", err))
			}
			if err := os.WriteFile(certPath, certBytes, 0o600); err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("write certificate: %w", err))
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Intermediate certificate issued:\n")
			_, _ = fmt.Fprintf(out, "  Serial:    %s\n", serial)
			_, _ = fmt.Fprintf(out, "  Not before:%s\n", time.Unix(cert.Payload.NotBefore, 0).UTC().Format(time.RFC3339))
			_, _ = fmt.Fprintf(out, "  Not after: %s\n", time.Unix(cert.Payload.NotAfter, 0).UTC().Format(time.RFC3339))
			_, _ = fmt.Fprintf(out, "  Cert:      %s (0600, distribute to consumers)\n", certPath)
			_, _ = fmt.Fprintf(out, "  Key:       %s (0600, deploy ONLY to the license service)\n", keyPath)
			_, _ = fmt.Fprintf(out, "\nThe root private key was used to sign and never copied. Move both outputs\n")
			_, _ = fmt.Fprintf(out, "off this host by hand; keep the root key offline.\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&rootKeyPath, "root-key", "", "path to the OFFLINE root private key (default: ~/.config/pipelock/license.key)")
	cmd.Flags().StringVar(&serial, "serial", "", "unique serial / key id for this intermediate (required; the CRL revocation key)")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory for intermediate.key + intermediate.json (default: current directory)")
	cmd.Flags().DurationVar(&validity, "validity", defaultIntermediateValidity, "validity window (e.g. 2160h for 90 days; capped by the library maximum)")
	return cmd
}
