//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/enrollmentclient"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type enrollOptions struct {
	emergencyClientOptions
	enrollmentTokenFile string
	auditKeyFile        string
	auditKeyID          string
	licenseCRLFile      string

	transport emergencyTransport
}

func enrollCmd() *cobra.Command {
	opts := enrollOptions{}
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a follower audit-signing key with a Conductor",
		Long: `enroll consumes a one-shot follower enrollment token and registers the
follower's audit-batch public key with the Conductor. The Conductor binds the
enrollment to the identity already scoped into the token; this command sends
only the token, audit key id, and audit public key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runEnroll(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.baseURL, "conductor-url", "", "base URL of the Conductor control plane (required)")
	cmd.Flags().StringVar(&opts.enrollmentTokenFile, "enrollment-token-file", "", "file containing the one-shot follower enrollment token (required)")
	cmd.Flags().StringVar(&opts.auditKeyFile, "audit-key-file", "", "audit-batch-signing key file; JSON key files derive key id unless --audit-key-id is set (required)")
	cmd.Flags().StringVar(&opts.auditKeyID, "audit-key-id", "", "audit key id to enroll; required for raw private key files")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "operator/follower client TLS certificate for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "operator/follower client TLS private key for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.serverCA, "server-ca", "", "CA bundle that signed the Conductor server certificate (required)")
	cmd.Flags().StringVar(&opts.serverName, "server-name", "", "server name to verify in the Conductor TLS certificate (defaults to the host in --conductor-url)")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	_ = cmd.MarkFlagRequired("conductor-url")
	_ = cmd.MarkFlagRequired("enrollment-token-file")
	_ = cmd.MarkFlagRequired("audit-key-file")
	return cmd
}

func runEnroll(cmd *cobra.Command, opts enrollOptions) error {
	token, err := loadEnrollmentToken(opts.enrollmentTokenFile)
	if err != nil {
		return err
	}
	auditKeyID, auditPub, err := loadEnrollmentAuditKey(opts.auditKeyFile, opts.auditKeyID)
	if err != nil {
		return err
	}
	client, err := resolveEmergencyTransport(opts.transport, opts.emergencyClientOptions)
	if err != nil {
		return err
	}
	enroller, err := enrollmentclient.New(enrollmentclient.Config{
		BaseURL: opts.baseURL,
		Client:  client,
	})
	if err != nil {
		return err
	}
	resp, err := enroller.Enroll(cmd.Context(), enrollmentclient.Request{
		Token:          token,
		AuditKeyID:     auditKeyID,
		AuditPublicKey: signing.EncodePublicKey(auditPub),
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"pipelock: conductor follower enrolled org=%s fleet=%s instance=%s env=%s audit_key_id=%s enrolled_at=%s\n",
		resp.OrgID, resp.FleetID, resp.InstanceID, resp.Environment, resp.AuditKeyID, resp.EnrolledAt.UTC().Format(time.RFC3339))
	return nil
}

func loadEnrollmentToken(path string) (string, error) {
	return readSecureTokenFile("--enrollment-token-file", path)
}

func loadEnrollmentAuditKey(path, overrideKeyID string) (string, ed25519.PublicKey, error) {
	overrideKeyID = strings.TrimSpace(overrideKeyID)
	if strings.TrimSpace(path) == "" {
		return "", nil, fmt.Errorf("%s is required", "--audit-key-file")
	}
	key, err := loadSigningKeyFile(path, signing.PurposeAuditBatchSigning)
	if err == nil {
		defer zeroBytes(key.priv)
		keyID := key.id
		if overrideKeyID != "" {
			keyID = overrideKeyID
		}
		if err := validateAuditKeyID(keyID); err != nil {
			return "", nil, err
		}
		pub, ok := key.priv.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return "", nil, errors.New("audit key file does not contain an Ed25519 public key")
		}
		return keyID, pub, nil
	}
	priv, rawErr := signing.LoadPrivateKeyFile(path)
	if rawErr != nil {
		return "", nil, fmt.Errorf("load audit key file as JSON keypair or raw private key: %w", errors.Join(err, rawErr))
	}
	defer zeroBytes(priv)
	if overrideKeyID == "" {
		return "", nil, errors.New("--audit-key-id is required when --audit-key-file is a raw private key")
	}
	if err := validateAuditKeyID(overrideKeyID); err != nil {
		return "", nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return "", nil, errors.New("audit key file does not contain an Ed25519 public key")
	}
	return overrideKeyID, pub, nil
}

func validateAuditKeyID(keyID string) error {
	if strings.TrimSpace(keyID) == "" {
		return errors.New("audit key id is required")
	}
	return conductorcore.ValidateIdentifier("audit_key_id", keyID)
}
