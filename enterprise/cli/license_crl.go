//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/spf13/cobra"
)

// maxInspectCRLSize bounds the file read for `crl inspect` so a malformed or
// hostile file cannot exhaust memory. Matches the loader's own ceiling.
const maxInspectCRLSize = 256 * 1024

// licenseCRLCmd returns the "license crl" subcommand group for inspecting and
// verifying signed license revocation lists (CRLs).
//
// CRL *issuance* (signing) is deliberately NOT a CLI capability: a CRL is a
// whole-list snapshot with no monotonic generation number, so an offline signer
// that can mint subsets is a revocation-rollback footgun. Revocation issuance
// stays in the cluster license-service, which owns the canonical list. The CLI
// provides only the read-side operations operators need in the field: decode a
// CRL and verify its signature/expiry.
func licenseCRLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crl",
		Short: "Inspect and verify signed license revocation lists (CRLs)",
		Long: `Inspect and verify signed license revocation lists (CRLs).

CRLs are ISSUED (signed) by the cluster license-service, which owns the
canonical revocation list. These commands are the read side: decode a CRL to
see what it revokes, and verify its signature and expiry against a public key.`,
	}
	cmd.AddCommand(
		licenseCRLInspectCmd(),
		licenseCRLVerifyCmd(),
	)
	return cmd
}

// crlInspectReport is the JSON shape for `crl inspect --json`. It carries the
// decoded payload plus the computed digest; it never asserts the signature is
// valid (inspect does not verify).
type crlInspectReport struct {
	SignatureVerified    bool                          `json:"signature_verified"`
	Version              int                           `json:"version"`
	IssuedAt             string                        `json:"issued_at"`
	ExpiresAt            string                        `json:"expires_at"`
	Expired              bool                          `json:"expired"`
	SHA256               string                        `json:"sha256"`
	Revoked              []license.RevokedLicense      `json:"revoked,omitempty"`
	RevokedIntermediates []license.RevokedIntermediate `json:"revoked_intermediates,omitempty"`
}

func readCRLFile(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("stat CRL file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("CRL must be a regular file")
	}
	if info.Size() > maxInspectCRLSize {
		return nil, fmt.Errorf("CRL file too large: %d bytes (max %d)", info.Size(), maxInspectCRLSize)
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("read CRL file: %w", err)
	}
	return data, nil
}

func licenseCRLInspectCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "inspect FILE",
		Short: "Decode and display a CRL without verifying the signature",
		Long: `Decode a signed CRL file and display the revoked license IDs and
intermediate serials it carries. The signature is NOT verified -- use
'license crl verify' for that. Inspect is for seeing what a CRL claims.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readCRLFile(args[0])
			if err != nil {
				return cliutil.ExitCodeError(1, err)
			}
			var crl license.CRL
			if err := json.Unmarshal(data, &crl); err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("decode CRL: %w", err))
			}

			now := time.Now()
			expired := crl.Payload.ExpiresAt > 0 && now.Unix() > crl.Payload.ExpiresAt

			if jsonOutput {
				report := crlInspectReport{
					SignatureVerified:    false,
					Version:              crl.Payload.Version,
					IssuedAt:             time.Unix(crl.Payload.IssuedAt, 0).UTC().Format(time.RFC3339),
					ExpiresAt:            time.Unix(crl.Payload.ExpiresAt, 0).UTC().Format(time.RFC3339),
					Expired:              expired,
					SHA256:               crl.SHA256,
					Revoked:              crl.Payload.Revoked,
					RevokedIntermediates: crl.Payload.RevokedIntermediates,
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return cliutil.ExitCodeError(1, fmt.Errorf("encode CRL JSON: %w", err))
				}
				return nil
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "CRL contents (signature NOT verified):\n")
			_, _ = fmt.Fprintf(out, "  Version:  %d\n", crl.Payload.Version)
			_, _ = fmt.Fprintf(out, "  Issued:   %s\n", time.Unix(crl.Payload.IssuedAt, 0).UTC().Format(time.RFC3339))
			_, _ = fmt.Fprintf(out, "  Expires:  %s\n", time.Unix(crl.Payload.ExpiresAt, 0).UTC().Format(time.RFC3339))
			if expired {
				_, _ = fmt.Fprintf(out, "  Status:   EXPIRED (signature not checked)\n")
			} else {
				_, _ = fmt.Fprintf(out, "  Status:   not expired (signature not checked)\n")
			}
			_, _ = fmt.Fprintf(out, "  SHA256:   %s\n", crl.SHA256)
			_, _ = fmt.Fprintf(out, "  Revoked licenses (%d):\n", len(crl.Payload.Revoked))
			for _, r := range crl.Payload.Revoked {
				_, _ = fmt.Fprintf(out, "    - %s", r.ID)
				if r.Reason != "" {
					_, _ = fmt.Fprintf(out, " (%s)", r.Reason)
				}
				_, _ = fmt.Fprintf(out, "\n")
			}
			if len(crl.Payload.RevokedIntermediates) > 0 {
				_, _ = fmt.Fprintf(out, "  Revoked intermediates (%d):\n", len(crl.Payload.RevokedIntermediates))
				for _, r := range crl.Payload.RevokedIntermediates {
					_, _ = fmt.Fprintf(out, "    - %s", r.Serial)
					if r.Reason != "" {
						_, _ = fmt.Fprintf(out, " (%s)", r.Reason)
					}
					_, _ = fmt.Fprintf(out, "\n")
				}
			}
			_, _ = fmt.Fprintf(out, "\n  WARNING: inspect does not verify the signature.\n"+
				"  Run 'pipelock license crl verify %s' to check it cryptographically.\n", args[0])
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	return cmd
}

func licenseCRLVerifyCmd() *cobra.Command {
	var (
		publicKey  string
		configFile string
	)

	cmd := &cobra.Command{
		Use:   "verify FILE",
		Short: "Verify the signature and expiry of a CRL file",
		Long: `Load a CRL file, verify its Ed25519 signature, and check that it has
not expired. The public key is resolved in this order:

  1. --public-key (a key file path or a raw hex value)
  2. the embedded build key, if the binary was built with one
  3. the configured license public key (config file or PIPELOCK_LICENSE_PUBLIC_KEY)

Exit code 0: valid signature and not expired.
Exit code 1: invalid signature, expired, malformed, or no public key available.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pubKey, err := resolveCRLVerifyKey(publicKey, configFile)
			if err != nil {
				return cliutil.ExitCodeError(1, err)
			}

			crl, err := license.LoadAndVerifyCRL(args[0], pubKey, time.Now())
			if err != nil {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "CRL verification FAILED: %v\n", err)
				return cliutil.ExitCodeError(1, err)
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "CRL verification OK\n")
			_, _ = fmt.Fprintf(out, "  Expires:  %s\n", time.Unix(crl.Payload.ExpiresAt, 0).UTC().Format(time.RFC3339))
			_, _ = fmt.Fprintf(out, "  SHA256:   %s\n", crl.SHA256)
			_, _ = fmt.Fprintf(out, "  Revoked licenses: %d\n", len(crl.Payload.Revoked))
			_, _ = fmt.Fprintf(out, "  Revoked intermediates: %d\n", len(crl.Payload.RevokedIntermediates))
			return nil
		},
	}

	cmd.Flags().StringVar(&publicKey, "public-key", "", "public key file path or hex value (default: embedded key, then configured key)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file used to resolve the license public key")
	return cmd
}

// resolveCRLVerifyKey picks the public key to verify a CRL against. An explicit
// --public-key wins; otherwise it falls back to the same embedded-then-config
// resolution the rest of the license CLI uses.
func resolveCRLVerifyKey(publicKey, configFile string) (ed25519.PublicKey, error) {
	if publicKey != "" {
		key, err := signing.LoadPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("load --public-key: %w", err)
		}
		return key, nil
	}
	cfg, err := loadLicenseStatusConfig(configFile)
	if err != nil {
		return nil, err
	}
	key, err := licenseStatusPublicKey(cfg)
	if err != nil {
		return nil, errors.New("no license public key available: pass --public-key, build with an embedded key, or set PIPELOCK_LICENSE_PUBLIC_KEY")
	}
	return key, nil
}
