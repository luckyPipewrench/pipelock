//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
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

const replayMaxStateSnapshotBytes = conductorcore.MaxConfigYAMLBytes

type replayOptions struct {
	publish       publishOptions
	stateSnapshot string
}

func replayCmd() *cobra.Command {
	opts := replayOptions{
		publish: publishOptions{validity: defaultPublishValidity},
	}
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Replay a signed Conductor decision artifact against current state",
		Long: `Replay builds and signs a policy bundle with the same inputs as
conductor publish, then asks the Conductor decision-replay endpoint to
re-derive the would-be publish decision under current fleet and policy state.
Pass --state-snapshot to replay the publish preflight against a captured fleet
snapshot instead of the current roster/runtime-status view.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.publish.licenseCRL}); err != nil {
				return err
			}
			return runReplay(cmd, opts)
		},
	}
	bindPublishFlags(cmd, &opts.publish, publishFlagOptions{license: true})
	cmd.Flags().StringVar(&opts.stateSnapshot, "state-snapshot", "", "optional JSON fleet state snapshot for bundle replay preflight")
	return cmd
}

func runReplay(cmd *cobra.Command, opts replayOptions) error {
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
	if strings.EqualFold(strings.TrimSpace(opts.publish.previousHash), previousHashAuto) {
		resolved, err := resolveAutoHash(ctx, opts.publish)
		if err != nil {
			return fmt.Errorf("resolve --previous-bundle-hash auto: %w", err)
		}
		opts.publish.previousHash = resolved
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "resolved --previous-bundle-hash auto to %s\n", resolved)
	}
	bundle, _, priv, err := buildSignedBundle(opts.publish)
	if err != nil {
		return err
	}
	defer zeroizeKey(priv)
	result, err := postDecisionReplay(ctx, client, opts.publish.conductorURL, token, bundle, snapshot)
	if err != nil {
		return err
	}
	writeDecisionReplayResult(cmd.OutOrStdout(), result)
	return nil
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

func postDecisionReplay(ctx context.Context, client *http.Client, baseURL, token string, bundle conductorcore.PolicyBundle, snapshot json.RawMessage) (controlplane.DecisionReplayResult, error) {
	envelope := struct {
		Bundle        conductorcore.PolicyBundle `json:"bundle"`
		StateSnapshot json.RawMessage            `json:"state_snapshot,omitempty"`
	}{
		Bundle:        bundle,
		StateSnapshot: snapshot,
	}
	body, err := json.Marshal(envelope)
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
	case http.StatusOK, http.StatusCreated:
		var result controlplane.DecisionReplayResult
		if err := json.Unmarshal(respBody, &result); err != nil {
			return controlplane.DecisionReplayResult{}, fmt.Errorf("decode replay response: %w", err)
		}
		return result, nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return controlplane.DecisionReplayResult{}, fmt.Errorf("publisher not authorized (HTTP %d): %s", resp.StatusCode, serverErrorDetail(respBody, token))
	default:
		return controlplane.DecisionReplayResult{}, fmt.Errorf("conductor rejected replay (HTTP %d): %s", resp.StatusCode, serverErrorDetail(respBody, token))
	}
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
		writeRemoteKillEvaluation(out, *result.RemoteKill)
	}
	if result.Rollback != nil {
		writeRollbackEvaluation(out, *result.Rollback)
	}
}

func writeReplayPublishEvaluation(out io.Writer, eval controlplane.PublishEvaluation) {
	_, _ = fmt.Fprintf(out, "replay publish valid=%t would_create=%t result_version=%d result_hash=%s conflict=%s\n",
		eval.Valid, eval.WouldCreate, eval.ResultVersion, eval.ResultHash, eval.Conflict)
	if eval.HasCurrentHead {
		_, _ = fmt.Fprintf(out, "current head version=%d hash=%s\n", eval.CurrentHeadVersion, eval.CurrentHeadHash)
	}
	writePublishPreflight(out, eval.Preflight)
}
