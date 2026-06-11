//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// rollbackDefaultTTL is the validity window applied when --ttl is not set. It
// is under the server's DefaultRollbackMaxValidity so a default-shaped
// authorization is accepted, and bounded so a captured authorization cannot be
// applied indefinitely.
const rollbackDefaultTTL = time.Hour

type rollbackOptions struct {
	emergencyClientOptions
	adminTokenFile  string
	signingKeys     []string
	orgID           string
	fleetID         string
	instanceIDs     []string
	labels          map[string]string
	authorizationID string
	currentBundleID string
	currentVersion  uint64
	targetBundleID  string
	targetVersion   uint64
	counter         uint64
	reason          string
	ttl             time.Duration
	licenseCRLFile  string

	now       func() time.Time
	transport emergencyTransport
}

func rollbackCmd() *cobra.Command {
	opts := rollbackOptions{}
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Publish a signed Conductor authorization to roll a fleet back to a prior policy bundle",
		Long: `rollback publishes a signed, multi-signer rollback authorization to the
Conductor. Followers restore the prior policy bundle (the target version, which
must be lower than the current version). Rollback is catastrophic and requires
at least ` + fmt.Sprintf("%d", conductorcore.RequiredCatastrophicSigners) + ` distinct signers (M-of-N), each holding a key with the
"` + string(signing.PurposePolicyBundleRollback) + `" purpose.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate first: rollback is an Enterprise fleet control
			// action. Fail closed before loading key material or building a
			// client.
			if _, err := license.VerifyFleet("", "", opts.licenseCRLFile); err != nil {
				return err
			}
			return runRollback(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.baseURL, "conductor-url", "", "base URL of the Conductor control plane (required)")
	cmd.Flags().StringVar(&opts.adminTokenFile, "admin-token-file", "", "file containing the Conductor admin bearer token (required)")
	cmd.Flags().StringArrayVar(&opts.signingKeys, "signing-key", nil,
		"path to a policy-bundle-rollback keypair file from `pipelock signing key generate`; repeat to supply the M-of-N signers")
	cmd.Flags().StringVar(&opts.orgID, "org", "", "fleet org id the authorization targets (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet", "", "fleet id the authorization targets (required)")
	cmd.Flags().StringArrayVar(&opts.instanceIDs, "instance", nil, "target follower instance id; repeat for several, or '*' for the whole fleet (mutually exclusive with --label)")
	cmd.Flags().StringToStringVar(&opts.labels, "label", nil, "target followers by label selector key=value (mutually exclusive with --instance)")
	cmd.Flags().StringVar(&opts.authorizationID, "authorization-id", "", "authorization id (defaults to rollback-<current>-to-<target>-<counter>)")
	cmd.Flags().StringVar(&opts.currentBundleID, "current-bundle-id", "", "bundle id currently applied on the followers (required)")
	cmd.Flags().Uint64Var(&opts.currentVersion, "current-version", 0, "version currently applied on the followers (required, must be > target)")
	cmd.Flags().StringVar(&opts.targetBundleID, "target-bundle-id", "", "bundle id to roll back to (required)")
	cmd.Flags().Uint64Var(&opts.targetVersion, "target-version", 0, "version to roll back to (required, must be < current)")
	cmd.Flags().Uint64Var(&opts.counter, "counter", 0, "monotonic counter; defaults to the current Unix time so each publish supersedes the prior one")
	cmd.Flags().StringVar(&opts.reason, "reason", "", "operator reason recorded in the signed authorization")
	cmd.Flags().DurationVar(&opts.ttl, "ttl", rollbackDefaultTTL, "validity window; must not exceed the Conductor's configured rollback max validity")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "operator client TLS certificate for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "operator client TLS private key for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.serverCA, "server-ca", "", "CA bundle that signed the Conductor server certificate (required)")
	cmd.Flags().StringVar(&opts.serverName, "server-name", "", "server name to verify in the Conductor TLS certificate")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	_ = cmd.MarkFlagRequired("conductor-url")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("fleet")
	_ = cmd.MarkFlagRequired("current-bundle-id")
	_ = cmd.MarkFlagRequired("target-bundle-id")
	return cmd
}

func runRollback(cmd *cobra.Command, opts rollbackOptions) error {
	now := time.Now().UTC()
	if opts.now != nil {
		now = opts.now().UTC()
	}

	audience, err := buildAudience(opts.instanceIDs, opts.labels)
	if err != nil {
		return err
	}

	counter := opts.counter
	if counter == 0 {
		// Guard the signed->unsigned conversion: a negative Unix time (skewed
		// clock) would wrap to a huge counter. On a non-negative clock, adopt the
		// seconds; otherwise leave counter 0 so Validate() rejects it and the
		// operator must pass an explicit --counter.
		if u := now.Unix(); u >= 0 {
			counter = uint64(u)
		}
	}

	authID := strings.TrimSpace(opts.authorizationID)
	if authID == "" {
		authID = fmt.Sprintf("rollback-%d-to-%d-%d", opts.currentVersion, opts.targetVersion, counter)
	}

	auth := conductorcore.RollbackAuthorization{
		SchemaVersion:   conductorcore.SchemaVersion,
		AuthorizationID: authID,
		OrgID:           opts.orgID,
		FleetID:         opts.fleetID,
		Audience:        audience,
		CurrentBundleID: opts.currentBundleID,
		CurrentVersion:  opts.currentVersion,
		TargetBundleID:  opts.targetBundleID,
		TargetVersion:   opts.targetVersion,
		Counter:         counter,
		Reason:          opts.reason,
		CreatedAt:       now,
		ExpiresAt:       now.Add(opts.ttl),
	}

	keys, err := loadSigningKeys(opts.signingKeys, conductorcore.RequiredCatastrophicSigners, signing.PurposePolicyBundleRollback)
	if err != nil {
		return err
	}
	defer zeroLoadedSigningKeys(keys)
	auth.Signatures, err = signEmergencyPreimage(auth.SignablePreimage, signing.PurposePolicyBundleRollback, keys)
	if err != nil {
		return err
	}

	// Validate locally before transmitting so the operator gets the exact
	// field error (e.g. target_version >= current_version) immediately.
	if err := auth.Validate(); err != nil {
		return fmt.Errorf("rollback authorization invalid: %w", err)
	}

	adminToken, err := loadBearerToken(opts.adminTokenFile)
	if err != nil {
		return err
	}
	client, err := resolveEmergencyTransport(opts.transport, opts.emergencyClientOptions)
	if err != nil {
		return err
	}

	var resp publishRollbackAuthorizationResponse
	if err := postEmergencyJSON(cmd.Context(), client, opts.baseURL, controlplane.RollbackAuthorizationsPath, adminToken,
		publishRollbackAuthorizationRequest{Authorization: auth}, &resp); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"pipelock: conductor rollback published authorization_id=%s target_version=%d counter=%d hash=%s created=%t\n",
		resp.AuthorizationID, opts.targetVersion, resp.Counter, resp.AuthorizationHash, resp.Created)
	return nil
}

// publishRollbackAuthorizationRequest/Response mirror the control-plane
// handler's unexported wire shapes; field tags match exactly.
type publishRollbackAuthorizationRequest struct {
	Authorization conductorcore.RollbackAuthorization `json:"authorization"`
}

type publishRollbackAuthorizationResponse struct {
	AuthorizationID   string    `json:"authorization_id"`
	AuthorizationHash string    `json:"authorization_hash"`
	Counter           uint64    `json:"counter"`
	PublishedAt       time.Time `json:"published_at"`
	Created           bool      `json:"created"`
}
