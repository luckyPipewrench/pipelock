//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// enrollmentTokenDefaultTTL is the lifetime applied when --ttl is not set. One
// hour is comfortably long enough to hand a token to a starting follower and
// short enough that a leaked, unconsumed token expires quickly. The token is
// one-shot regardless: the server marks it consumed on first enroll.
const enrollmentTokenDefaultTTL = time.Hour

type enrollmentTokenOptions struct {
	emergencyClientOptions
	adminTokenFile string
	tokenID        string
	orgID          string
	fleetID        string
	instanceID     string
	environment    string
	ttl            time.Duration
	licenseCRLFile string

	now       func() time.Time
	transport emergencyTransport
}

func enrollmentTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enrollment-token",
		Short: "Manage Conductor follower enrollment tokens",
		Long: `enrollment-token manages the narrow, one-shot bearer tokens a follower
presents once to enroll its audit-signing key with the Conductor.

Only "mint" is available today: it issues a single-use token scoped to one
follower identity (org / fleet / instance / environment). The Conductor marks
the token consumed on first successful enroll, so a leaked-but-unused token
cannot enroll a second follower, and an expired token is rejected.`,
	}
	cmd.AddCommand(enrollmentTokenMintCmd())
	return cmd
}

func enrollmentTokenMintCmd() *cobra.Command {
	opts := enrollmentTokenOptions{}
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint a one-shot enrollment token for a follower identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate first: enrollment-token issuance is an Enterprise
			// fleet admin action. Fail closed before any client build or
			// network call.
			if _, err := license.VerifyFleet("", "", opts.licenseCRLFile); err != nil {
				return err
			}
			return runEnrollmentTokenMint(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.baseURL, "conductor-url", "", "base URL of the Conductor control plane (required)")
	cmd.Flags().StringVar(&opts.adminTokenFile, "admin-token-file", "", "file containing the Conductor admin bearer token (required)")
	cmd.Flags().StringVar(&opts.tokenID, "token-id", "", "stable id for the token, used for audit and de-duplication (required)")
	cmd.Flags().StringVar(&opts.orgID, "org", "", "org id the enrolling follower must present (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet", "", "fleet id the enrolling follower must present (required)")
	cmd.Flags().StringVar(&opts.instanceID, "instance", "", "instance id the enrolling follower must present (required)")
	cmd.Flags().StringVar(&opts.environment, "env", "", "environment the enrolling follower must present (required)")
	cmd.Flags().DurationVar(&opts.ttl, "ttl", enrollmentTokenDefaultTTL, "how long the token is valid before it expires unused")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "operator client TLS certificate for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "operator client TLS private key for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.serverCA, "server-ca", "", "CA bundle that signed the Conductor server certificate (required)")
	cmd.Flags().StringVar(&opts.serverName, "server-name", "", "server name to verify in the Conductor TLS certificate")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	_ = cmd.MarkFlagRequired("conductor-url")
	_ = cmd.MarkFlagRequired("token-id")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("fleet")
	_ = cmd.MarkFlagRequired("instance")
	_ = cmd.MarkFlagRequired("env")
	return cmd
}

func runEnrollmentTokenMint(cmd *cobra.Command, opts enrollmentTokenOptions) error {
	now := time.Now().UTC()
	if opts.now != nil {
		now = opts.now().UTC()
	}
	if opts.ttl <= 0 {
		return fmt.Errorf("--ttl must be positive, got %s", opts.ttl)
	}

	reqBody := createEnrollmentTokenRequest{
		TokenID:     strings.TrimSpace(opts.tokenID),
		OrgID:       opts.orgID,
		FleetID:     opts.fleetID,
		InstanceID:  opts.instanceID,
		Environment: opts.environment,
		ExpiresAt:   now.Add(opts.ttl),
	}

	adminToken, err := loadBearerToken(opts.adminTokenFile)
	if err != nil {
		return err
	}
	client, err := resolveEmergencyTransport(opts.transport, opts.emergencyClientOptions)
	if err != nil {
		return err
	}

	var resp createEnrollmentTokenResponse
	if err := postEmergencyJSON(cmd.Context(), client, opts.baseURL, controlplane.EnrollmentTokensPath, adminToken,
		reqBody, &resp); err != nil {
		return err
	}

	// The token is a credential: it goes to stdout (so it can be captured into
	// a follower's secret store via a pipe), while the human-readable summary
	// goes to stderr so a `> token.txt` redirect yields ONLY the token.
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"pipelock: conductor enrollment token minted token_id=%s expires_at=%s\n",
		resp.TokenID, resp.ExpiresAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), resp.Token)
	return nil
}

// createEnrollmentTokenRequest/Response mirror the control-plane handler's
// unexported wire shapes; field tags match exactly.
type createEnrollmentTokenRequest struct {
	TokenID     string    `json:"token_id"`
	OrgID       string    `json:"org_id"`
	FleetID     string    `json:"fleet_id"`
	InstanceID  string    `json:"instance_id"`
	Environment string    `json:"environment"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type createEnrollmentTokenResponse struct {
	TokenID   string    `json:"token_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
