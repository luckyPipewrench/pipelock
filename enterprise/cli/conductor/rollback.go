//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"errors"
	"fmt"
	"io"
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
	dryRun          bool
	licenseCRLFile  string

	now       func() time.Time
	transport emergencyTransport
}

func rollbackCmd() *cobra.Command {
	opts := rollbackOptions{}
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Publish a signed Conductor authorization to roll a policy stream back to a prior bundle",
		Long: `rollback publishes a signed, multi-signer rollback authorization to the
Conductor. Followers on the affected policy stream restore the prior policy
bundle (the target version, which must be lower than the current version).
Rollback is catastrophic and stream-wide; per-instance and per-label rollback
are not supported. It requires at least ` + fmt.Sprintf("%d", conductorcore.RequiredCatastrophicSigners) + ` distinct signers (M-of-N), each holding a key with the
"` + string(signing.PurposePolicyBundleRollback) + `" purpose.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate first: rollback is an Enterprise fleet control
			// action. Fail closed before loading key material or building a
			// client.
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runRollback(cmd, opts)
		},
	}
	bindRollbackFlags(cmd, &opts)
	return cmd
}

type rollbackFlagOptions struct {
	includeDryRun bool
	counterHelp   string
}

func bindRollbackFlags(cmd *cobra.Command, opts *rollbackOptions) {
	bindRollbackFlagsWithOptions(cmd, opts, rollbackFlagOptions{
		includeDryRun: true,
		counterHelp:   "monotonic counter; defaults to the current Unix time so each publish supersedes the prior one",
	})
}

func bindRollbackFlagsWithOptions(cmd *cobra.Command, opts *rollbackOptions, flagOpts rollbackFlagOptions) {
	counterHelp := strings.TrimSpace(flagOpts.counterHelp)
	if counterHelp == "" {
		counterHelp = "monotonic counter; defaults to the current Unix time"
	}
	cmd.Flags().StringVar(&opts.baseURL, "conductor-url", "", "base URL of the Conductor control plane (required)")
	cmd.Flags().StringVar(&opts.adminTokenFile, "admin-token-file", "", "file containing the Conductor admin bearer token (required)")
	cmd.Flags().StringArrayVar(&opts.signingKeys, "signing-key", nil,
		"path to a policy-bundle-rollback keypair file from `pipelock signing key generate`; repeat to supply the M-of-N signers")
	cmd.Flags().StringVar(&opts.orgID, "org", "", "fleet org id the authorization targets (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet", "", "fleet id the authorization targets (required)")
	cmd.Flags().StringVar(&opts.authorizationID, "authorization-id", "", "authorization id (defaults to rollback-<current>-to-<target>-<counter>)")
	cmd.Flags().StringVar(&opts.currentBundleID, "current-bundle-id", "", "bundle id currently applied on the followers (required)")
	cmd.Flags().Uint64Var(&opts.currentVersion, "current-version", 0, "version currently applied on the followers (required, must be > target)")
	cmd.Flags().StringVar(&opts.targetBundleID, "target-bundle-id", "", "bundle id to roll back to (required)")
	cmd.Flags().Uint64Var(&opts.targetVersion, "target-version", 0, "version to roll back to (required, must be < current)")
	cmd.Flags().Uint64Var(&opts.counter, "counter", 0, counterHelp)
	cmd.Flags().StringVar(&opts.reason, "reason", "", "operator reason recorded in the signed authorization")
	cmd.Flags().DurationVar(&opts.ttl, "ttl", rollbackDefaultTTL, "validity window; must not exceed the Conductor's configured rollback max validity")
	if flagOpts.includeDryRun {
		cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "evaluate the signed rollback without mutating Conductor state")
	}
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "operator client TLS certificate for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "operator client TLS private key for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.serverCA, "server-ca", "", "CA bundle that signed the Conductor server certificate (required)")
	cmd.Flags().StringVar(&opts.serverName, "server-name", "", "server name to verify in the Conductor TLS certificate (defaults to the host in --conductor-url)")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	_ = cmd.MarkFlagRequired("conductor-url")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("fleet")
	_ = cmd.MarkFlagRequired("current-bundle-id")
	_ = cmd.MarkFlagRequired("target-bundle-id")
}

func runRollback(cmd *cobra.Command, opts rollbackOptions) error {
	auth, err := buildSignedRollbackAuthorization(opts)
	if err != nil {
		return err
	}
	adminToken, err := loadBearerToken(opts.adminTokenFile)
	if err != nil {
		return err
	}
	client, err := resolveEmergencyTransport(opts.transport, opts.emergencyClientOptions)
	if err != nil {
		return err
	}

	if opts.dryRun {
		var eval controlplane.RollbackEvaluation
		status, err := postEmergencyJSONStatus(cmd.Context(), client, opts.baseURL, controlplane.RollbackEvaluatePath, adminToken,
			publishRollbackAuthorizationRequest{Authorization: auth, DryRun: true}, &eval)
		if err != nil {
			return err
		}
		if err := requireEmergencyDryRunStatus("rollback", status); err != nil {
			return err
		}
		if err := requireDryRunEvaluation("rollback", eval.DryRun); err != nil {
			return err
		}
		writeRollbackEvaluation(cmd.OutOrStdout(), "dry-run", eval)
		return nil
	}

	var resp publishRollbackAuthorizationResponse
	status, err := postEmergencyJSONStatus(cmd.Context(), client, opts.baseURL, controlplane.RollbackAuthorizationsPath, adminToken,
		publishRollbackAuthorizationRequest{Authorization: auth}, &resp)
	if err != nil {
		return err
	}
	if err := requireEmergencyMutationStatus("rollback", status, resp.Created); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"pipelock: conductor rollback published authorization_id=%s target_version=%d counter=%d hash=%s created=%t\n",
		resp.AuthorizationID, opts.targetVersion, resp.Counter, resp.AuthorizationHash, resp.Created)
	return nil
}

func buildSignedRollbackAuthorization(opts rollbackOptions) (conductorcore.RollbackAuthorization, error) {
	return buildSignedRollbackAuthorizationWithIntent(opts, "")
}

func buildSignedRollbackAuthorizationWithIntent(opts rollbackOptions, intent conductorcore.ControlIntent) (conductorcore.RollbackAuthorization, error) {
	now := time.Now().UTC()
	if opts.now != nil {
		now = opts.now().UTC()
	}

	if len(opts.instanceIDs) > 0 || len(opts.labels) > 0 {
		return conductorcore.RollbackAuthorization{}, errors.New("rollback is stream-wide; per-instance and per-label rollback are not supported")
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
		Intent:          intent,
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
		return conductorcore.RollbackAuthorization{}, err
	}
	defer zeroLoadedSigningKeys(keys)
	auth.Signatures, err = signEmergencyPreimage(auth.SignablePreimage, signing.PurposePolicyBundleRollback, keys)
	if err != nil {
		return conductorcore.RollbackAuthorization{}, err
	}

	// Validate locally before transmitting so the operator gets the exact
	// field error (e.g. target_version >= current_version) immediately.
	if err := auth.Validate(); err != nil {
		return conductorcore.RollbackAuthorization{}, fmt.Errorf("rollback authorization invalid: %w", err)
	}
	return auth, nil
}

// publishRollbackAuthorizationRequest/Response mirror the control-plane
// handler's unexported wire shapes; field tags match exactly.
type publishRollbackAuthorizationRequest struct {
	Authorization conductorcore.RollbackAuthorization `json:"authorization"`
	DryRun        bool                                `json:"dry_run,omitempty"`
}

type publishRollbackAuthorizationResponse struct {
	AuthorizationID   string    `json:"authorization_id"`
	AuthorizationHash string    `json:"authorization_hash"`
	Counter           uint64    `json:"counter"`
	PublishedAt       time.Time `json:"published_at"`
	Created           bool      `json:"created"`
}

func writeRollbackEvaluation(out io.Writer, label string, eval controlplane.RollbackEvaluation) {
	_, _ = fmt.Fprintf(out,
		"%s rollback valid=%t would_create=%t counter=%d would_roll_to_bundle_id=%s would_roll_to_version=%d would_roll_to_hash=%s noop=%t conflict=%s current_head_version=%d current_head_hash=%s\n",
		label, eval.Valid, eval.WouldCreate, eval.Counter, eval.WouldRollToBundleID, eval.WouldRollToVersion, eval.WouldRollToHash, eval.Noop, eval.Conflict, eval.CurrentHeadVersion, eval.CurrentHeadHash)
}
