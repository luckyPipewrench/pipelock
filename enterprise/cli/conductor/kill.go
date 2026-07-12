//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"fmt"
	"io"
	"net/http"
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
	dryRun         bool
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
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runRemoteKill(cmd, opts, state)
		},
	}
	bindRemoteKillFlags(cmd, &opts)
	return cmd
}

type remoteKillFlagOptions struct {
	includeDryRun bool
	counterHelp   string
}

func bindRemoteKillFlags(cmd *cobra.Command, opts *killOptions) {
	bindRemoteKillFlagsWithOptions(cmd, opts, remoteKillFlagOptions{
		includeDryRun: true,
		counterHelp:   "monotonic counter; defaults to the current Unix time so each publish supersedes the prior one",
	})
}

func bindRemoteKillFlagsWithOptions(cmd *cobra.Command, opts *killOptions, flagOpts remoteKillFlagOptions) {
	counterHelp := strings.TrimSpace(flagOpts.counterHelp)
	if counterHelp == "" {
		counterHelp = "monotonic counter; defaults to the current Unix time"
	}
	cmd.Flags().StringVar(&opts.baseURL, "conductor-url", "", "base URL of the Conductor control plane, e.g. https://conductor.example:8895 (required)")
	cmd.Flags().StringVar(&opts.adminTokenFile, "admin-token-file", "", "file containing the Conductor admin bearer token (required)")
	cmd.Flags().StringArrayVar(&opts.signingKeys, "signing-key", nil,
		"path to a remote-kill-signing keypair file from `pipelock signing key generate`; repeat to supply the M-of-N signers")
	cmd.Flags().StringVar(&opts.orgID, "org", "", "fleet org id the message targets (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet", "", "fleet id the message targets (required)")
	cmd.Flags().StringArrayVar(&opts.instanceIDs, "instance", nil, "target follower instance id; repeat for several, or pass '*' for the whole fleet (mutually exclusive with --label)")
	cmd.Flags().StringToStringVar(&opts.labels, "label", nil, "target followers by label selector key=value; repeat for several (mutually exclusive with --instance)")
	cmd.Flags().StringVar(&opts.messageID, "message-id", "", "message id (defaults to a generated remote-kill-<state>-<counter> id)")
	cmd.Flags().Uint64Var(&opts.counter, "counter", 0, counterHelp)
	cmd.Flags().StringVar(&opts.reason, "reason", "", "operator reason recorded in the signed message")
	cmd.Flags().DurationVar(&opts.ttl, "ttl", remoteKillDefaultTTL, "validity window for the message; must not exceed the Conductor's configured remote-kill max validity")
	if flagOpts.includeDryRun {
		cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "evaluate the signed remote-kill without mutating Conductor state")
	}
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
	msg, err := buildSignedRemoteKillMessage(opts, state)
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
		var eval controlplane.RemoteKillEvaluation
		status, err := postEmergencyJSONStatus(cmd.Context(), client, opts.baseURL, controlplane.RemoteKillEvaluatePath, adminToken,
			publishRemoteKillRequest{Message: msg, DryRun: true}, &eval)
		if err != nil {
			return err
		}
		if err := requireEmergencyDryRunStatus("remote-kill", status); err != nil {
			return err
		}
		if err := requireDryRunEvaluation("remote-kill", eval.DryRun); err != nil {
			return err
		}
		writeRemoteKillEvaluation(cmd.OutOrStdout(), "dry-run", eval)
		return nil
	}

	var resp publishRemoteKillResponse
	status, err := postEmergencyJSONStatus(cmd.Context(), client, opts.baseURL, controlplane.RemoteKillPath, adminToken,
		publishRemoteKillRequest{Message: msg}, &resp)
	if err != nil {
		return err
	}
	if err := requireEmergencyMutationStatus("remote-kill", status, resp.Created); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"pipelock: conductor remote-kill published state=%s message_id=%s counter=%d hash=%s created=%t\n",
		state, resp.MessageID, resp.Counter, resp.MessageHash, resp.Created)
	return nil
}

func requireEmergencyDryRunStatus(action string, status int) error {
	if status != http.StatusOK {
		return fmt.Errorf("conductor returned HTTP %s for %s dry-run; expected 200 OK and refusing ambiguous response", httpStatusLabel(status), action)
	}
	return nil
}

func requireEmergencyMutationStatus(action string, status int, created bool) error {
	switch {
	case created && status == http.StatusCreated:
		return nil
	case !created && status == http.StatusOK:
		return nil
	case created:
		return fmt.Errorf("conductor returned HTTP %s for newly-created %s; expected 201 Created and refusing ambiguous response", httpStatusLabel(status), action)
	default:
		return fmt.Errorf("conductor returned HTTP %s for idempotent %s; expected 200 OK and refusing ambiguous response", httpStatusLabel(status), action)
	}
}

func httpStatusLabel(status int) string {
	text := http.StatusText(status)
	if text == "" {
		return fmt.Sprintf("%d", status)
	}
	return fmt.Sprintf("%d %s", status, text)
}

func buildSignedRemoteKillMessage(opts killOptions, state conductorcore.KillSwitchState) (conductorcore.RemoteKillMessage, error) {
	return buildSignedRemoteKillMessageWithIntent(opts, state, "")
}

func buildSignedRemoteKillMessageWithIntent(opts killOptions, state conductorcore.KillSwitchState, intent conductorcore.ControlIntent) (conductorcore.RemoteKillMessage, error) {
	now := time.Now().UTC()
	if opts.now != nil {
		now = opts.now().UTC()
	}

	audience, err := buildAudience(opts.instanceIDs, opts.labels)
	if err != nil {
		return conductorcore.RemoteKillMessage{}, err
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
		Intent:        intent,
		State:         state,
		Counter:       counter,
		Reason:        opts.reason,
		CreatedAt:     now,
		NotBefore:     now.Add(-time.Minute),
		ExpiresAt:     now.Add(opts.ttl),
	}

	keys, err := loadSigningKeys(opts.signingKeys, conductorcore.RequiredCatastrophicSigners, signing.PurposeRemoteKillSigning)
	if err != nil {
		return conductorcore.RemoteKillMessage{}, err
	}
	defer zeroLoadedSigningKeys(keys)
	msg.Signatures, err = signEmergencyPreimage(msg.SignablePreimage, signing.PurposeRemoteKillSigning, keys)
	if err != nil {
		return conductorcore.RemoteKillMessage{}, err
	}

	// Validate locally before transmitting. The server re-validates, but a
	// client-side check gives the operator the exact field error immediately
	// instead of a round-trip and an opaque 4xx.
	if err := msg.Validate(); err != nil {
		return conductorcore.RemoteKillMessage{}, fmt.Errorf("remote-kill message invalid: %w", err)
	}
	return msg, nil
}

// publishRemoteKillRequest/publishRemoteKillResponse mirror the control-plane
// handler's wire shapes. They are defined here (not imported) because the
// handler keeps them unexported; the field tags match exactly so encode/decode
// round-trips against the server.
type publishRemoteKillRequest struct {
	Message conductorcore.RemoteKillMessage `json:"message"`
	DryRun  bool                            `json:"dry_run,omitempty"`
}

type publishRemoteKillResponse struct {
	MessageID   string    `json:"message_id"`
	MessageHash string    `json:"message_hash"`
	Counter     uint64    `json:"counter"`
	PublishedAt time.Time `json:"published_at"`
	Created     bool      `json:"created"`
}

func writeRemoteKillEvaluation(out io.Writer, label string, eval controlplane.RemoteKillEvaluation) {
	_, _ = fmt.Fprintf(out,
		"%s remote-kill valid=%t would_create=%t counter=%d message_hash=%s conflict=%s has_current_max_counter=%t current_max_counter=%d\n",
		label, eval.Valid, eval.WouldCreate, eval.Counter, eval.MessageHash, eval.Conflict, eval.HasCurrentMaxCounter, eval.CurrentMaxCounter)
}
