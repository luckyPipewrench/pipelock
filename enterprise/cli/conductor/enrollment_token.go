//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
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

"mint" issues a single-use token scoped to one follower identity (org / fleet /
instance / environment). The Conductor marks the token consumed on first
successful enroll, so a leaked-but-unused token cannot enroll a second follower,
and an expired token is rejected.

"list" and "status" return token lifecycle metadata only (never the token
secret). "revoke" invalidates a pending token by id so a leaked-but-unused token
can be killed before it enrolls a follower.`,
	}
	cmd.AddCommand(enrollmentTokenMintCmd())
	cmd.AddCommand(enrollmentTokenListCmd())
	cmd.AddCommand(enrollmentTokenStatusCmd())
	cmd.AddCommand(enrollmentTokenRevokeCmd())
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
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
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
	cmd.Flags().StringVar(&opts.serverName, "server-name", "", "server name to verify in the Conductor TLS certificate (defaults to the host in --conductor-url)")
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

// enrollmentTokenReadOptions carries the connection + filter flags for the
// metadata-only list/status reads and the revoke action. These admin endpoints
// use the same mTLS + bearer client as the other operator reads (fleet status,
// followers): the bearer is the Conductor admin token.
type enrollmentTokenReadOptions struct {
	client      clientOptions
	tokenID     string
	orgID       string
	fleetID     string
	instanceID  string
	environment string
	limit       int
	jsonOut     bool
}

type enrollmentTokensResponse struct {
	Tokens []controlplane.EnrollmentTokenSummary `json:"tokens"`
	Count  int                                   `json:"count"`
}

func enrollmentTokenListCmd() *cobra.Command {
	opts := enrollmentTokenReadOptions{}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrollment tokens and their lifecycle state (metadata only)",
		Long: `List the enrollment tokens minted on a Conductor with their lifecycle
state (pending / consumed / revoked / expired). The token secret is shown only
once at mint and is NEVER returned here; this is metadata only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.client.licenseCRLFile}); err != nil {
				return err
			}
			return runEnrollmentTokenList(cmd, opts)
		},
	}
	bindEnrollmentTokenReadFlags(cmd, &opts, true)
	return cmd
}

func enrollmentTokenStatusCmd() *cobra.Command {
	opts := enrollmentTokenReadOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the lifecycle state of one enrollment token (metadata only)",
		Long: `Show the lifecycle state of a single enrollment token by its token id.
The token secret is never returned; this is metadata only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.client.licenseCRLFile}); err != nil {
				return err
			}
			return runEnrollmentTokenStatus(cmd, opts)
		},
	}
	bindEnrollmentTokenReadFlags(cmd, &opts, false)
	_ = cmd.MarkFlagRequired("token-id")
	return cmd
}

func enrollmentTokenRevokeCmd() *cobra.Command {
	opts := enrollmentTokenReadOptions{}
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a pending enrollment token by id",
		Long: `Revoke a pending enrollment token so it can no longer enroll a follower.
Only a still-pending token can be revoked; a consumed, already-revoked, or
expired token is rejected. The response is metadata only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.client.licenseCRLFile}); err != nil {
				return err
			}
			return runEnrollmentTokenRevoke(cmd, opts)
		},
	}
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.tokenID, "token-id", "", "id of the token to revoke (required)")
	_ = cmd.MarkFlagRequired("token-id")
	return cmd
}

func bindEnrollmentTokenReadFlags(cmd *cobra.Command, opts *enrollmentTokenReadOptions, includeListFilters bool) {
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.tokenID, "token-id", "", "token id to query")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "emit the raw JSON response instead of a table")
	if includeListFilters {
		cmd.Flags().StringVar(&opts.orgID, "org-id", "", "filter by org id")
		cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "filter by fleet id")
		cmd.Flags().StringVar(&opts.instanceID, "instance-id", "", "filter by instance id")
		cmd.Flags().StringVar(&opts.environment, "environment", "", "filter by environment")
		cmd.Flags().IntVar(&opts.limit, "limit", 0, "maximum number of tokens to list (server rejects values above its configured ceiling)")
	}
}

func runEnrollmentTokenList(cmd *cobra.Command, opts enrollmentTokenReadOptions) error {
	if opts.limit < 0 {
		return fmt.Errorf("--limit must be non-negative")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := fetchEnrollmentTokens(cmd.Context(), client, opts)
	if err != nil {
		return err
	}
	return renderEnrollmentTokens(cmd, body, opts.jsonOut)
}

func runEnrollmentTokenStatus(cmd *cobra.Command, opts enrollmentTokenReadOptions) error {
	if strings.TrimSpace(opts.tokenID) == "" {
		return fmt.Errorf("--token-id is required")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := fetchEnrollmentTokens(cmd.Context(), client, opts)
	if err != nil {
		return err
	}
	var parsed enrollmentTokensResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode enrollment tokens response: %w", err)
	}
	// Check not-found BEFORE the --json early return so `status --json` fails
	// (non-zero exit) on a missing token instead of printing an empty result
	// set and exiting 0, which would silently break scripts.
	if parsed.Count == 0 {
		return fmt.Errorf("no enrollment token found with id %q", opts.tokenID)
	}
	if opts.jsonOut {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return nil
	}
	return writeEnrollmentTokenTable(cmd, parsed)
}

func runEnrollmentTokenRevoke(cmd *cobra.Command, opts enrollmentTokenReadOptions) error {
	if strings.TrimSpace(opts.tokenID) == "" {
		return fmt.Errorf("--token-id is required")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := client.deleteJSON(cmd.Context(), controlplane.EnrollmentTokensPath, map[string]string{
		"token_id": opts.tokenID,
	})
	if err != nil {
		return err
	}
	var summary controlplane.EnrollmentTokenSummary
	if err := json.Unmarshal(body, &summary); err != nil {
		return fmt.Errorf("decode revoke response: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock: enrollment token %s revoked (state=%s)\n", summary.TokenID, summary.State)
	return nil
}

func fetchEnrollmentTokens(ctx context.Context, client *conductorClient, opts enrollmentTokenReadOptions) ([]byte, error) {
	params := map[string]string{
		"token_id":    opts.tokenID,
		"org_id":      opts.orgID,
		"fleet_id":    opts.fleetID,
		"instance_id": opts.instanceID,
		"environment": opts.environment,
	}
	if opts.limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.limit)
	}
	return client.getJSON(ctx, controlplane.EnrollmentTokensPath+encodeQuery(params))
}

func renderEnrollmentTokens(cmd *cobra.Command, body []byte, jsonOut bool) error {
	if jsonOut {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return nil
	}
	var parsed enrollmentTokensResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode enrollment tokens response: %w", err)
	}
	return writeEnrollmentTokenTable(cmd, parsed)
}

func writeEnrollmentTokenTable(cmd *cobra.Command, resp enrollmentTokensResponse) error {
	out := cmd.OutOrStdout()
	if resp.Count == 0 {
		_, _ = fmt.Fprintln(out, "no enrollment tokens match the query")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOKEN_ID\tORG\tFLEET\tINSTANCE\tENVIRONMENT\tSTATE\tCREATED_AT\tEXPIRES_AT")
	for _, tkn := range resp.Tokens {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			tkn.TokenID, tkn.OrgID, tkn.FleetID, tkn.InstanceID, tkn.Environment, tkn.State,
			tkn.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			tkn.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write enrollment token table: %w", err)
	}
	_, _ = fmt.Fprintf(out, "%d token(s)\n", resp.Count)
	return nil
}
