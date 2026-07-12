//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	replayMaxStateSnapshotBytes  = conductorcore.MaxConfigYAMLBytes
	replayMaxBundleArtifactBytes = conductorcore.MaxConfigYAMLBytes * 2

	replayModePolicyBundle = "policy_bundle"
	replayModeRemoteKill   = "remote_kill"
	replayModeRollback     = "rollback"

	replayActionPublish = "publish"
)

type replayOptions struct {
	mode            string
	publish         publishOptions
	kill            killOptions
	rollback        rollbackOptions
	remoteKillState string
	stateSnapshot   string
	bundleArtifact  string
}

func replayCmd() *cobra.Command {
	opts := replayOptions{
		mode:    replayModePolicyBundle,
		publish: publishOptions{validity: defaultPublishValidity},
	}
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Replay a signed Conductor decision artifact against current state",
		Long: `Replay sends a signed policy bundle artifact to the Conductor
decision-replay endpoint to re-derive the publish decision under current fleet
and policy state. Pass --bundle-artifact to replay an exact previously saved
signed bundle. Without --bundle-artifact, replay rebuilds and signs a new
hypothetical bundle from the same inputs as conductor publish.

Pass --state-snapshot to replay the publish preflight against a captured fleet
snapshot instead of the current roster/runtime-status view.

Use the remote-kill and rollback subcommands to replay signed emergency-control
decisions against the same decision-replay endpoint without applying them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.publish.licenseCRL}); err != nil {
				return err
			}
			return runReplay(cmd, opts)
		},
	}
	bindPublishFlags(cmd, &opts.publish, publishFlagOptions{license: true})
	cmd.Flags().StringVar(&opts.bundleArtifact, "bundle-artifact", "", "path to an exact signed policy bundle JSON artifact to replay instead of rebuilding from publish inputs")
	cmd.Flags().StringVar(&opts.stateSnapshot, "state-snapshot", "", "optional JSON fleet state snapshot for bundle replay preflight")
	cmd.AddCommand(replayRemoteKillCmd(), replayRollbackCmd())
	return cmd
}

func runReplay(cmd *cobra.Command, opts replayOptions) error {
	mode := strings.TrimSpace(opts.mode)
	if mode == "" {
		mode = replayModePolicyBundle
	}
	switch mode {
	case replayModePolicyBundle:
		return runPolicyBundleReplay(cmd, opts)
	case replayModeRemoteKill:
		return runRemoteKillReplay(cmd, opts)
	case replayModeRollback:
		return runRollbackReplay(cmd, opts)
	default:
		return fmt.Errorf("unsupported replay mode %q", opts.mode)
	}
}

func replayRemoteKillCmd() *cobra.Command {
	opts := replayOptions{
		mode: replayModeRemoteKill,
		kill: killOptions{ttl: remoteKillDefaultTTL},
	}
	cmd := &cobra.Command{
		Use:     "remote-kill",
		Aliases: []string{"remote_kill"},
		Short:   "Replay a signed Conductor remote-kill decision without applying it",
		Long: `remote-kill builds and signs a remote-kill message from the same inputs
as conductor kill/resume, then posts it to the decision-replay endpoint as a
remote_kill artifact. The Conductor re-derives and compares the decision without
publishing or applying the message.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.kill.licenseCRLFile}); err != nil {
				return err
			}
			return runReplay(cmd, opts)
		},
	}
	bindReplayRemoteKillFlags(cmd, &opts)
	return cmd
}

func replayRollbackCmd() *cobra.Command {
	opts := replayOptions{
		mode:     replayModeRollback,
		rollback: rollbackOptions{ttl: rollbackDefaultTTL},
	}
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Replay a signed Conductor rollback decision without applying it",
		Long: `rollback builds and signs a rollback authorization from the same inputs
as conductor rollback, then posts it to the decision-replay endpoint as a
rollback artifact. The Conductor re-derives and compares the decision without
publishing or applying the authorization.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.rollback.licenseCRLFile}); err != nil {
				return err
			}
			return runReplay(cmd, opts)
		},
	}
	bindReplayRollbackFlags(cmd, &opts.rollback)
	return cmd
}

func bindReplayRemoteKillFlags(cmd *cobra.Command, opts *replayOptions) {
	bindRemoteKillFlagsWithOptions(cmd, &opts.kill, remoteKillFlagOptions{
		counterHelp: "monotonic counter; defaults to the current Unix time so each replay supersedes the prior message shape",
	})
	cmd.Flags().StringVar(&opts.remoteKillState, "state", "", "remote-kill state to replay: active or inactive")
	_ = cmd.MarkFlagRequired("state")
}

func bindReplayRollbackFlags(cmd *cobra.Command, opts *rollbackOptions) {
	bindRollbackFlagsWithOptions(cmd, opts, rollbackFlagOptions{
		counterHelp: "monotonic counter; defaults to the current Unix time so each replay supersedes the prior authorization shape",
	})
}

func runPolicyBundleReplay(cmd *cobra.Command, opts replayOptions) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	token, err := readPublisherToken(opts.publish.publisherTok)
	if err != nil {
		return err
	}
	snapshot, err := readReplayStateSnapshot(opts.stateSnapshot)
	if err != nil {
		return err
	}
	client, err := publishHTTPClient(opts.publish)
	if err != nil {
		return err
	}
	var bundle conductorcore.PolicyBundle
	var priv ed25519.PrivateKey
	if strings.TrimSpace(opts.bundleArtifact) != "" {
		bundle, err = readReplayBundleArtifact(opts.bundleArtifact)
		if err != nil {
			return err
		}
	} else {
		if strings.EqualFold(strings.TrimSpace(opts.publish.previousHash), previousHashAuto) {
			resolved, err := resolveAutoHash(ctx, opts.publish)
			if err != nil {
				return fmt.Errorf("resolve --previous-bundle-hash auto: %w", err)
			}
			opts.publish.previousHash = resolved
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "resolved --previous-bundle-hash auto to %s\n", resolved)
		}
		var err error
		bundle, _, priv, err = buildSignedBundle(opts.publish)
		if err != nil {
			return err
		}
		defer zeroizeKey(priv)
	}
	result, err := postDecisionReplay(ctx, client, opts.publish.conductorURL, token, decisionReplayArtifact{Bundle: &bundle, StateSnapshot: snapshot})
	if err != nil {
		return err
	}
	writeDecisionReplayResult(cmd.OutOrStdout(), result)
	return nil
}

func runRemoteKillReplay(cmd *cobra.Command, opts replayOptions) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := parseReplayRemoteKillState(opts.remoteKillState)
	if err != nil {
		return err
	}
	msg, err := buildSignedRemoteKillMessageWithIntent(opts.kill, state, conductorcore.ControlIntentReplay)
	if err != nil {
		return err
	}
	adminToken, err := loadBearerToken(opts.kill.adminTokenFile)
	if err != nil {
		return err
	}
	client, err := resolveEmergencyTransport(opts.kill.transport, opts.kill.emergencyClientOptions)
	if err != nil {
		return err
	}
	result, err := postDecisionReplay(ctx, client, opts.kill.baseURL, adminToken, decisionReplayArtifact{RemoteKill: &msg})
	if err != nil {
		return err
	}
	writeDecisionReplayResult(cmd.OutOrStdout(), result)
	return nil
}

func runRollbackReplay(cmd *cobra.Command, opts replayOptions) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	auth, err := buildSignedRollbackAuthorizationWithIntent(opts.rollback, conductorcore.ControlIntentReplay)
	if err != nil {
		return err
	}
	adminToken, err := loadBearerToken(opts.rollback.adminTokenFile)
	if err != nil {
		return err
	}
	client, err := resolveEmergencyTransport(opts.rollback.transport, opts.rollback.emergencyClientOptions)
	if err != nil {
		return err
	}
	result, err := postDecisionReplay(ctx, client, opts.rollback.baseURL, adminToken, decisionReplayArtifact{Rollback: &auth})
	if err != nil {
		return err
	}
	writeDecisionReplayResult(cmd.OutOrStdout(), result)
	return nil
}

func parseReplayRemoteKillState(raw string) (conductorcore.KillSwitchState, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", fmt.Errorf("--state is required; pass %q or %q", conductorcore.KillSwitchActive, conductorcore.KillSwitchInactive)
	case string(conductorcore.KillSwitchActive), "kill":
		return conductorcore.KillSwitchActive, nil
	case string(conductorcore.KillSwitchInactive), "resume":
		return conductorcore.KillSwitchInactive, nil
	default:
		return "", fmt.Errorf("--state must be %q or %q", conductorcore.KillSwitchActive, conductorcore.KillSwitchInactive)
	}
}

func readReplayBundleArtifact(path string) (conductorcore.PolicyBundle, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return conductorcore.PolicyBundle{}, fmt.Errorf("read --bundle-artifact: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return conductorcore.PolicyBundle{}, fmt.Errorf("read --bundle-artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return conductorcore.PolicyBundle{}, errors.New("--bundle-artifact must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, replayMaxBundleArtifactBytes+1))
	if err != nil {
		return conductorcore.PolicyBundle{}, fmt.Errorf("read --bundle-artifact: %w", err)
	}
	if len(data) > replayMaxBundleArtifactBytes {
		return conductorcore.PolicyBundle{}, fmt.Errorf("--bundle-artifact exceeds %d bytes", replayMaxBundleArtifactBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var bundle conductorcore.PolicyBundle
	if err := dec.Decode(&bundle); err != nil {
		return conductorcore.PolicyBundle{}, fmt.Errorf("parse --bundle-artifact: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return conductorcore.PolicyBundle{}, errors.New("parse --bundle-artifact: trailing JSON")
	}
	if err := bundle.Validate(); err != nil {
		return conductorcore.PolicyBundle{}, fmt.Errorf("validate --bundle-artifact: %w", err)
	}
	return bundle, nil
}

func readReplayStateSnapshot(path string) (json.RawMessage, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read --state-snapshot: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read --state-snapshot: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("--state-snapshot must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, replayMaxStateSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read --state-snapshot: %w", err)
	}
	if len(data) > replayMaxStateSnapshotBytes {
		return nil, fmt.Errorf("--state-snapshot exceeds %d bytes", replayMaxStateSnapshotBytes)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("--state-snapshot is empty")
	}
	if !json.Valid(trimmed) {
		return nil, errors.New("parse --state-snapshot: invalid JSON")
	}
	return json.RawMessage(trimmed), nil
}

type decisionReplayHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type decisionReplayArtifact struct {
	Bundle        *conductorcore.PolicyBundle          `json:"bundle,omitempty"`
	RemoteKill    *conductorcore.RemoteKillMessage     `json:"remote_kill,omitempty"`
	Rollback      *conductorcore.RollbackAuthorization `json:"rollback,omitempty"`
	StateSnapshot json.RawMessage                      `json:"state_snapshot,omitempty"`
}

func postDecisionReplay(ctx context.Context, client decisionReplayHTTPDoer, baseURL, token string, artifact decisionReplayArtifact) (controlplane.DecisionReplayResult, error) {
	expectedHash, err := validateDecisionReplayArtifact(artifact)
	if err != nil {
		return controlplane.DecisionReplayResult{}, err
	}
	body, err := json.Marshal(artifact)
	if err != nil {
		return controlplane.DecisionReplayResult{}, fmt.Errorf("marshal replay request: %w", err)
	}
	endpoint := strings.TrimRight(baseURL, "/") + controlplane.DecisionReplayPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return controlplane.DecisionReplayResult{}, fmt.Errorf("build replay request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return controlplane.DecisionReplayResult{}, fmt.Errorf("replay request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := readPublishResponseBody(resp.Body)
	if err != nil {
		return controlplane.DecisionReplayResult{}, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var result controlplane.DecisionReplayResult
		if err := json.Unmarshal(respBody, &result); err != nil {
			return controlplane.DecisionReplayResult{}, fmt.Errorf("decode replay response: %w", err)
		}
		if err := validateDecisionReplayResultForArtifact(result, artifact, expectedHash); err != nil {
			return controlplane.DecisionReplayResult{}, err
		}
		return result, nil
	case http.StatusCreated:
		return controlplane.DecisionReplayResult{}, errors.New("conductor returned 201 Created for decision replay; refusing ambiguous mutating response")
	case http.StatusForbidden, http.StatusUnauthorized:
		return controlplane.DecisionReplayResult{}, fmt.Errorf("replay not authorized (HTTP %d): %s", resp.StatusCode, serverErrorDetail(respBody, token))
	default:
		return controlplane.DecisionReplayResult{}, fmt.Errorf("conductor rejected replay (HTTP %d): %s", resp.StatusCode, serverErrorDetail(respBody, token))
	}
}

func validateDecisionReplayArtifact(artifact decisionReplayArtifact) (string, error) {
	expectedAction, err := replayResponseActionForArtifact(artifact)
	if err != nil {
		return "", err
	}
	if len(artifact.StateSnapshot) > 0 && artifact.Bundle == nil {
		return "", errors.New("replay request state_snapshot is only supported with a bundle artifact")
	}
	switch expectedAction {
	case replayActionPublish:
		hash, err := artifact.Bundle.CanonicalHash()
		if err != nil {
			return "", fmt.Errorf("hash replay bundle artifact: %w", err)
		}
		return hash, nil
	case replayModeRemoteKill:
		hash, err := artifact.RemoteKill.CanonicalHash()
		if err != nil {
			return "", fmt.Errorf("hash replay remote-kill artifact: %w", err)
		}
		return hash, nil
	case replayModeRollback:
		hash, err := artifact.Rollback.CanonicalHash()
		if err != nil {
			return "", fmt.Errorf("hash replay rollback artifact: %w", err)
		}
		return hash, nil
	default:
		return "", fmt.Errorf("unsupported replay action %q", expectedAction)
	}
}

func validateDecisionReplayResultForArtifact(result controlplane.DecisionReplayResult, artifact decisionReplayArtifact, expectedHash string) error {
	expectedAction, err := replayResponseActionForArtifact(artifact)
	if err != nil {
		return err
	}
	if result.ActionKind != expectedAction {
		return fmt.Errorf("replay response action_kind=%q does not match requested action %q", result.ActionKind, expectedAction)
	}
	if !strings.EqualFold(result.ArtifactHash, expectedHash) {
		return fmt.Errorf("replay response artifact_hash=%q does not match submitted artifact hash %q", result.ArtifactHash, expectedHash)
	}
	switch expectedAction {
	case replayActionPublish:
		if result.PublishEvaluation == nil {
			return errors.New("replay response missing publish_evaluation")
		}
		if result.RemoteKill != nil || result.Rollback != nil {
			return errors.New("replay response for publish included an emergency evaluation")
		}
	case replayModeRemoteKill:
		if result.RemoteKill == nil {
			return errors.New("replay response missing remote_kill_evaluation")
		}
		if result.PublishEvaluation != nil || result.Rollback != nil {
			return errors.New("replay response for remote_kill included a different evaluation")
		}
	case replayModeRollback:
		if result.Rollback == nil {
			return errors.New("replay response missing rollback_evaluation")
		}
		if result.PublishEvaluation != nil || result.RemoteKill != nil {
			return errors.New("replay response for rollback included a different evaluation")
		}
	default:
		return fmt.Errorf("unsupported replay response action %q", expectedAction)
	}
	return nil
}

func replayResponseActionForArtifact(artifact decisionReplayArtifact) (string, error) {
	var expected string
	seen := 0
	if artifact.Bundle != nil {
		expected = replayActionPublish
		seen++
	}
	if artifact.RemoteKill != nil {
		expected = replayModeRemoteKill
		seen++
	}
	if artifact.Rollback != nil {
		expected = replayModeRollback
		seen++
	}
	if seen != 1 {
		return "", errors.New("replay request must contain exactly one artifact")
	}
	return expected, nil
}

func writeDecisionReplayResult(out io.Writer, result controlplane.DecisionReplayResult) {
	_, _ = fmt.Fprintf(out,
		"decision replay action=%s artifact_hash=%s divergence=%t used_state_snapshot=%t replayed_at=%s\n",
		result.ActionKind, result.ArtifactHash, result.Divergence, result.UsedStateSnapshot, result.ReplayedAt.UTC().Format(time.RFC3339))
	if result.DivergenceReason != "" {
		_, _ = fmt.Fprintf(out, "divergence_reason=%s\n", result.DivergenceReason)
	}
	if result.Recorded != nil {
		_, _ = fmt.Fprintf(out, "recorded present=%t accepted=%t hash=%s\n", result.Recorded.Present, result.Recorded.Accepted, result.Recorded.RecordedHash)
	}
	if result.PublishEvaluation != nil {
		writeReplayPublishEvaluation(out, *result.PublishEvaluation)
	}
	if result.RemoteKill != nil {
		writeRemoteKillEvaluation(out, "replay", *result.RemoteKill)
	}
	if result.Rollback != nil {
		writeRollbackEvaluation(out, "replay", *result.Rollback)
	}
}

func writeReplayPublishEvaluation(out io.Writer, eval controlplane.PublishEvaluation) {
	writePublishEvaluationLabeled(out, "replay publish", eval)
}
