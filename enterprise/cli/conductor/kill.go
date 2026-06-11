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

// remoteKillDefaultTTL is the validity window applied when --ttl is not set. It
// is well under the server's DefaultRemoteKillMaxValidity so a default-shaped
// message is always accepted, and short enough that a captured message cannot be
// replayed indefinitely.
const remoteKillDefaultTTL = time.Hour

type killOptions struct {
	emergencyClientOptions
	adminTokenFile string
	signingKeys    []string
	orgID          string
	fleetID        string
	instanceIDs    []string
	labels         map[string]string
	messageID      string
	counter        uint64
	reason         string
	ttl            time.Duration
	licenseCRLFile string

	// now and transport are test seams. Production leaves them nil so the
	// command uses the real clock and an mTLS client built from the flags.
	now       func() time.Time
	transport emergencyTransport
}

func killCmd() *cobra.Command {
	return remoteKillStateCmd(
		"kill",
		"Publish a signed Conductor remote-kill that denies all follower traffic",
		`kill publishes a signed, multi-signer remote-kill message to the Conductor.

Followers polling the Conductor apply the message and fail CLOSED: all traffic
is denied until a matching resume is published. Remote kill is a catastrophic
action and requires at least `+fmt.Sprintf("%d", conductorcore.RequiredCatastrophicSigners)+` distinct signers (M-of-N), each
holding a key with the "`+string(signing.PurposeRemoteKillSigning)+`" purpose.`,
		conductorcore.KillSwitchActive,
	)
}

func resumeCmd() *cobra.Command {
	return remoteKillStateCmd(
		"resume",
		"Publish a signed Conductor remote-kill that clears the kill state",
		`resume publishes a signed, multi-signer remote-kill message with state
"inactive", clearing a prior kill. Followers return to normal enforcement once
they apply it. Like kill, it requires `+fmt.Sprintf("%d", conductorcore.RequiredCatastrophicSigners)+` distinct "`+string(signing.PurposeRemoteKillSigning)+`" signers.`,
		conductorcore.KillSwitchInactive,
	)
}

func remoteKillStateCmd(use, short, long string, state conductorcore.KillSwitchState) *cobra.Command {
	opts := killOptions{}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate first: remote kill is an Enterprise fleet control
			// action. Fail closed before loading any key material or building
			// a client so an unlicensed invocation gets a clear entitlement
			// error, not a partial side effect.
			if _, err := license.VerifyFleet("", "", opts.licenseCRLFile); err != nil {
				return err
			}
			return runRemoteKill(cmd, opts, state)
		},
	}
	bindRemoteKillFlags(cmd, &opts)
	return cmd
}

func bindRemoteKillFlags(cmd *cobra.Command, opts *killOptions) {
	cmd.Flags().StringVar(&opts.baseURL, "conductor-url", "", "base URL of the Conductor control plane, e.g. https://conductor.example:8895 (required)")
	cmd.Flags().StringVar(&opts.adminTokenFile, "admin-token-file", "", "file containing the Conductor admin bearer token (required)")
	cmd.Flags().StringArrayVar(&opts.signingKeys, "signing-key", nil,
		"path to a remote-kill-signing keypair file from `pipelock signing key generate`; repeat to supply the M-of-N signers")
	cmd.Flags().StringVar(&opts.orgID, "org", "", "fleet org id the message targets (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet", "", "fleet id the message targets (required)")
	cmd.Flags().StringArrayVar(&opts.instanceIDs, "instance", nil, "target follower instance id; repeat for several, or pass '*' for the whole fleet (mutually exclusive with --label)")
	cmd.Flags().StringToStringVar(&opts.labels, "label", nil, "target followers by label selector key=value; repeat for several (mutually exclusive with --instance)")
	cmd.Flags().StringVar(&opts.messageID, "message-id", "", "message id (defaults to a generated remote-kill-<state>-<counter> id)")
	cmd.Flags().Uint64Var(&opts.counter, "counter", 0, "monotonic counter; defaults to the current Unix time so each publish supersedes the prior one")
	cmd.Flags().StringVar(&opts.reason, "reason", "", "operator reason recorded in the signed message")
	cmd.Flags().DurationVar(&opts.ttl, "ttl", remoteKillDefaultTTL, "validity window for the message; must not exceed the Conductor's configured remote-kill max validity")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "operator client TLS certificate for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "operator client TLS private key for Conductor mTLS (required)")
	cmd.Flags().StringVar(&opts.serverCA, "server-ca", "", "CA bundle that signed the Conductor server certificate (required)")
	cmd.Flags().StringVar(&opts.serverName, "server-name", "", "server name to verify in the Conductor TLS certificate (defaults to the host in --conductor-url)")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	_ = cmd.MarkFlagRequired("conductor-url")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("fleet")
}

func runRemoteKill(cmd *cobra.Command, opts killOptions, state conductorcore.KillSwitchState) error {
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
		// Default to a wall-clock-derived counter so two operators publishing
		// in sequence without coordinating still produce a monotonically
		// increasing counter the server accepts. Guard the signed->unsigned
		// conversion: a negative Unix time (pre-1970 / skewed clock) would wrap
		// to a huge counter, so only adopt non-negative seconds and otherwise
		// leave counter 0 (the operator must then pass an explicit --counter).
		if u := now.Unix(); u >= 0 {
			counter = uint64(u)
		}
	}

	messageID := strings.TrimSpace(opts.messageID)
	if messageID == "" {
		messageID = fmt.Sprintf("remote-kill-%s-%d", state, counter)
	}

	msg := conductorcore.RemoteKillMessage{
		SchemaVersion: conductorcore.SchemaVersion,
		MessageID:     messageID,
		OrgID:         opts.orgID,
		FleetID:       opts.fleetID,
		Audience:      audience,
		State:         state,
		Counter:       counter,
		Reason:        opts.reason,
		CreatedAt:     now,
		NotBefore:     now.Add(-time.Minute),
		ExpiresAt:     now.Add(opts.ttl),
	}

	keys, err := loadSigningKeys(opts.signingKeys, conductorcore.RequiredCatastrophicSigners, signing.PurposeRemoteKillSigning)
	if err != nil {
		return err
	}
	defer zeroLoadedSigningKeys(keys)
	msg.Signatures, err = signEmergencyPreimage(msg.SignablePreimage, signing.PurposeRemoteKillSigning, keys)
	if err != nil {
		return err
	}

	// Validate locally before transmitting. The server re-validates, but a
	// client-side check gives the operator the exact field error immediately
	// instead of a round-trip and an opaque 4xx.
	if err := msg.Validate(); err != nil {
		return fmt.Errorf("remote-kill message invalid: %w", err)
	}

	adminToken, err := loadBearerToken(opts.adminTokenFile)
	if err != nil {
		return err
	}
	client, err := resolveEmergencyTransport(opts.transport, opts.emergencyClientOptions)
	if err != nil {
		return err
	}

	var resp publishRemoteKillResponse
	if err := postEmergencyJSON(cmd.Context(), client, opts.baseURL, controlplane.RemoteKillPath, adminToken,
		publishRemoteKillRequest{Message: msg}, &resp); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"pipelock: conductor remote-kill published state=%s message_id=%s counter=%d hash=%s created=%t\n",
		state, resp.MessageID, resp.Counter, resp.MessageHash, resp.Created)
	return nil
}

// publishRemoteKillRequest/publishRemoteKillResponse mirror the control-plane
// handler's wire shapes. They are defined here (not imported) because the
// handler keeps them unexported; the field tags match exactly so encode/decode
// round-trips against the server.
type publishRemoteKillRequest struct {
	Message conductorcore.RemoteKillMessage `json:"message"`
}

type publishRemoteKillResponse struct {
	MessageID   string    `json:"message_id"`
	MessageHash string    `json:"message_hash"`
	Counter     uint64    `json:"counter"`
	PublishedAt time.Time `json:"published_at"`
	Created     bool      `json:"created"`
}
