//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"

	conductorcli "github.com/luckyPipewrench/pipelock/enterprise/cli/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

type dashboardConductorReadClient interface {
	ListFollowers(ctx context.Context, orgID, fleetID string, limit int) ([]byte, error)
	ReplayDecision(ctx context.Context, orgID, fleetID, artifactHash string) ([]byte, bool, error)
}

type dashboardConductorSource struct {
	client dashboardConductorReadClient
	orgID  string
	fleet  string
}

type dashboardConductorFollowersResponse struct {
	Followers         []controlplane.FollowerFleetStatus `json:"followers"`
	Count             int                                `json:"count"`
	HasMore           *bool                              `json:"has_more,omitempty"`
	Complete          *bool                              `json:"complete,omitempty"`
	CompletenessKnown *bool                              `json:"completeness_known,omitempty"`
}

// dashboardConductorDecisionSource converts a possibly-nil conductor source into
// the read model's interface field. Assigning a nil *dashboardConductorSource
// directly would yield a non-nil interface holding a nil pointer, which the read
// model reads as a configured replay source and then calls on a nil receiver. A
// deployment with no conductor URL must report the source as unconfigured.
func dashboardConductorDecisionSource(source *dashboardConductorSource) dashboard.ConductorDecisionSource {
	if source == nil {
		return nil
	}
	return source
}

func newDashboardConductorSource(opts dashboardServeOptions) (*dashboardConductorSource, error) {
	if err := validateDashboardConductorConfig(opts); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.conductorURL) == "" {
		return nil, nil
	}
	client, err := conductorcli.NewReadClient(conductorcli.ReadClientOptions{
		Server:         opts.conductorURL,
		CAFile:         opts.conductorServerCA,
		ClientCertFile: opts.conductorTLSCert,
		ClientKeyFile:  opts.conductorTLSKey,
		TokenFile:      opts.conductorTokenFile,
	})
	if err != nil {
		return nil, err
	}
	return &dashboardConductorSource{
		client: client,
		orgID:  strings.TrimSpace(opts.conductorOrg),
		fleet:  strings.TrimSpace(opts.conductorFleet),
	}, nil
}

func validateDashboardConductorConfig(opts dashboardServeOptions) error {
	configured := strings.TrimSpace(opts.conductorURL) != ""
	anyConductorOption := configured ||
		strings.TrimSpace(opts.conductorTokenFile) != "" ||
		strings.TrimSpace(opts.conductorTLSCert) != "" ||
		strings.TrimSpace(opts.conductorTLSKey) != "" ||
		strings.TrimSpace(opts.conductorServerCA) != "" ||
		strings.TrimSpace(opts.conductorOrg) != "" ||
		strings.TrimSpace(opts.conductorFleet) != ""
	if !anyConductorOption {
		return nil
	}
	if !configured {
		return errors.New("--conductor-url is required when any conductor dashboard source option is set")
	}
	required := []struct {
		flag  string
		value string
	}{
		{"--conductor-token-file", opts.conductorTokenFile},
		{"--conductor-tls-cert", opts.conductorTLSCert},
		{"--conductor-tls-key", opts.conductorTLSKey},
		{"--conductor-server-ca", opts.conductorServerCA},
		{"--conductor-org", opts.conductorOrg},
		{"--conductor-fleet", opts.conductorFleet},
	}
	for _, req := range required {
		if strings.TrimSpace(req.value) == "" {
			return fmt.Errorf("%s is required with --conductor-url", req.flag)
		}
	}
	return nil
}

func (s *dashboardConductorSource) ListFleetFollowers(ctx context.Context, orgID, fleetID string, limit int) (dashboard.FleetFollowerPage, error) {
	if s == nil || s.client == nil {
		return dashboard.FleetFollowerPage{}, errors.New("conductor source is nil")
	}
	orgID = strings.TrimSpace(orgID)
	fleetID = strings.TrimSpace(fleetID)
	if err := validateDashboardConductorFleetScope(orgID, fleetID, s.orgID, s.fleet); err != nil {
		return dashboard.FleetFollowerPage{}, err
	}
	if limit <= 0 {
		return dashboard.FleetFollowerPage{}, errors.New("follower limit must be positive")
	}
	if limit > conductorcli.ReadClientFollowerLimitMax {
		return dashboard.FleetFollowerPage{}, fmt.Errorf("follower limit exceeds maximum %d", conductorcli.ReadClientFollowerLimitMax)
	}
	body, err := s.client.ListFollowers(ctx, orgID, fleetID, limit)
	if err != nil {
		return dashboard.FleetFollowerPage{}, err
	}
	var resp dashboardConductorFollowersResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&resp); err != nil {
		return dashboard.FleetFollowerPage{}, fmt.Errorf("decode conductor followers response: %w", err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return dashboard.FleetFollowerPage{}, errors.New("decode conductor followers response: trailing JSON data")
	}
	if resp.Count != len(resp.Followers) {
		return dashboard.FleetFollowerPage{}, fmt.Errorf("conductor followers response count=%d len=%d", resp.Count, len(resp.Followers))
	}
	seen := make(map[string]struct{}, len(resp.Followers))
	followers := make([]dashboard.FleetFollowerView, len(resp.Followers))
	for i, follower := range resp.Followers {
		if err := validateDashboardConductorFollower(s.orgID, s.fleet, follower, seen); err != nil {
			return dashboard.FleetFollowerPage{}, err
		}
		followers[i] = dashboardFollowerView(follower)
	}
	page := dashboard.FleetFollowerPage{Followers: followers}
	if err := applyConductorCompleteness(&page, resp, limit); err != nil {
		return dashboard.FleetFollowerPage{}, err
	}
	return page, nil
}

func (s *dashboardConductorSource) ReplayDecision(ctx context.Context, scope dashboard.DecisionScope) (dashboard.DecisionReplayView, bool, error) {
	if s == nil || s.client == nil {
		return dashboard.DecisionReplayView{}, false, errors.New("conductor source is nil")
	}
	scope.OrgID = strings.TrimSpace(scope.OrgID)
	scope.FleetID = strings.TrimSpace(scope.FleetID)
	scope.ArtifactHash = strings.TrimSpace(scope.ArtifactHash)
	if err := validateDashboardConductorFleetScope(scope.OrgID, scope.FleetID, s.orgID, s.fleet); err != nil {
		return dashboard.DecisionReplayView{}, false, err
	}
	if scope.ArtifactHash == "" {
		return dashboard.DecisionReplayView{}, false, errors.New("artifact hash is required")
	}
	body, found, err := s.client.ReplayDecision(ctx, scope.OrgID, scope.FleetID, scope.ArtifactHash)
	if err != nil || !found {
		return dashboard.DecisionReplayView{}, found, err
	}
	view, err := dashboardDecisionReplayView(body, scope.ArtifactHash)
	if err != nil {
		return dashboard.DecisionReplayView{}, false, err
	}
	return view, true, nil
}

func applyConductorCompleteness(page *dashboard.FleetFollowerPage, resp dashboardConductorFollowersResponse, limit int) error {
	if resp.HasMore != nil && resp.Complete != nil {
		return errors.New("conductor followers response has conflicting completeness fields")
	}
	if resp.CompletenessKnown != nil && !*resp.CompletenessKnown && (resp.HasMore != nil || resp.Complete != nil) {
		return errors.New("conductor followers response has unknown completeness with explicit completeness fields")
	}
	if resp.HasMore != nil {
		page.CompletenessKnown = true
		page.HasMore = *resp.HasMore
	}
	if resp.Complete != nil {
		page.CompletenessKnown = true
		page.HasMore = !*resp.Complete
	}
	if resp.CompletenessKnown != nil {
		page.CompletenessKnown = *resp.CompletenessKnown
	}
	if resp.HasMore == nil && resp.Complete == nil && resp.CompletenessKnown == nil {
		page.CompletenessKnown = len(resp.Followers) < limit
		page.HasMore = false
	}
	if !page.CompletenessKnown {
		page.HasMore = false
	}
	return nil
}

func validateDashboardConductorFleetScope(orgID, fleetID, configuredOrgID, configuredFleetID string) error {
	if strings.TrimSpace(orgID) != configuredOrgID || strings.TrimSpace(fleetID) != configuredFleetID {
		return fmt.Errorf("fleet scope %q/%q is not configured for this dashboard", orgID, fleetID)
	}
	return nil
}

func validateDashboardConductorFollower(orgID, fleetID string, f controlplane.FollowerFleetStatus, seen map[string]struct{}) error {
	if strings.TrimSpace(f.OrgID) != f.OrgID || f.OrgID != orgID ||
		strings.TrimSpace(f.FleetID) != f.FleetID || f.FleetID != fleetID {
		return errors.New("conductor returned follower outside configured scope")
	}
	instanceID := strings.TrimSpace(f.InstanceID)
	if instanceID == "" || instanceID != f.InstanceID || len(instanceID) > 256 || strings.IndexFunc(instanceID, unicode.IsControl) >= 0 {
		return errors.New("conductor returned invalid follower identity")
	}
	key := f.OrgID + "\x00" + f.FleetID + "\x00" + instanceID
	if _, ok := seen[key]; ok {
		return fmt.Errorf("conductor returned duplicate follower identity %q", instanceID)
	}
	seen[key] = struct{}{}
	return nil
}

func dashboardFollowerView(f controlplane.FollowerFleetStatus) dashboard.FleetFollowerView {
	view := dashboard.FleetFollowerView{
		OrgID:                      f.OrgID,
		FleetID:                    f.FleetID,
		InstanceID:                 f.InstanceID,
		Environment:                f.Environment,
		AuditKeyID:                 f.AuditKeyID,
		EnrolledAt:                 f.EnrolledAt,
		Active:                     f.Active,
		FleetHealth:                string(f.Health),
		Drift:                      f.Drift,
		ExpectedBundleID:           f.ExpectedBundle.BundleID,
		ExpectedBundleVersion:      f.ExpectedBundle.Version,
		ExpectedBundleHash:         f.ExpectedBundle.BundleHash,
		ExpectedMinPipelockVersion: f.ExpectedBundle.MinPipelockVersion,
		SignedStatePresent:         f.SignedAppliedState != nil,
		Verified:                   f.SignedAppliedState != nil && f.SignedAppliedState.Verified,
	}
	if f.RuntimeStatus != nil {
		view.RuntimeReported = true
		view.RuntimeSeenAt = f.RuntimeStatus.LastSeenAt
		view.ActiveBundleID = f.RuntimeStatus.ActiveBundleID
		view.ActiveBundleVersion = f.RuntimeStatus.ActiveBundleVersion
		view.ActiveBundleHash = f.RuntimeStatus.ActiveBundleHash
		view.ActiveBundleMinPipelockVersion = f.RuntimeStatus.ActiveBundleMinPipelockVersion
		view.PipelockVersion = f.RuntimeStatus.PipelockVersion
		view.GitCommit = f.RuntimeStatus.GitCommit
		view.BuildDate = f.RuntimeStatus.BuildDate
		view.LastPolicyPollAt = f.RuntimeStatus.LastPolicyPollAt
		view.LastSuccessfulApplyAt = f.RuntimeStatus.LastSuccessfulApplyAt
		view.LastApplyErrorCode = f.RuntimeStatus.LastApplyErrorCode
		view.LastApplyErrorMessage = f.RuntimeStatus.LastApplyErrorMessage
	}
	if f.SignedAppliedState != nil {
		applied := f.SignedAppliedState.AppliedState
		view.SignerKeyID = f.SignedAppliedState.SignerKeyID
		view.BatchID = f.SignedAppliedState.BatchID
		view.EnvelopeHash = f.SignedAppliedState.EnvelopeHash
		view.ObservedAt = f.SignedAppliedState.ObservedAt
		view.VerifiedAt = f.SignedAppliedState.VerifiedAt
		if !f.SignedAppliedState.Verified {
			return view
		}
		view.ActiveBundleID = applied.ActiveBundleID
		view.ActiveBundleVersion = applied.ActiveBundleVersion
		view.ActiveBundleHash = applied.ActiveBundleHash
		view.ActiveBundleMinPipelockVersion = applied.ActiveBundleMinPipelockVersion
		view.PipelockVersion = applied.PipelockVersion
		view.GitCommit = applied.GitCommit
		view.BuildDate = applied.BuildDate
		view.LastPolicyPollAt = applied.LastPolicyPollAt
		view.LastSuccessfulApplyAt = applied.LastSuccessfulApplyAt
		view.LastApplyErrorCode = applied.LastApplyErrorCode
		view.LastApplyErrorMessage = applied.LastApplyErrorMessage
	}
	return view
}

func dashboardDecisionReplayView(body []byte, requestedHash string) (dashboard.DecisionReplayView, error) {
	var result controlplane.DecisionReplayResult
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&result); err != nil {
		return dashboard.DecisionReplayView{}, fmt.Errorf("decode conductor decision replay response: %w", err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return dashboard.DecisionReplayView{}, errors.New("decode conductor decision replay response: trailing JSON data")
	}
	if !strings.EqualFold(result.ArtifactHash, strings.TrimSpace(requestedHash)) {
		return dashboard.DecisionReplayView{}, fmt.Errorf("conductor replay response artifact_hash=%q does not match requested artifact hash", result.ArtifactHash)
	}
	if result.Recorded == nil || !result.Recorded.Present {
		return dashboard.DecisionReplayView{}, errors.New("conductor replay response did not include a recorded decision")
	}
	view := dashboard.DecisionReplayView{
		ActionKind:        result.ActionKind,
		ArtifactHash:      result.ArtifactHash,
		UsedStateSnapshot: result.UsedStateSnapshot,
		ReplayedAt:        result.ReplayedAt,
		Divergence:        result.Divergence,
		DivergenceReason:  result.DivergenceReason,
		RecordedPresent:   result.Recorded.Present,
		RecordedAccepted:  result.Recorded.Accepted,
		RecordedHash:      result.Recorded.RecordedHash,
		RecordedAt:        result.Recorded.PublishedAt,
	}
	switch result.ActionKind {
	case controlplane.ActionKindPublish:
		if result.PublishEvaluation == nil || result.RemoteKill != nil || result.Rollback != nil {
			return dashboard.DecisionReplayView{}, errors.New("conductor replay response has invalid publish evaluation shape")
		}
		view.Valid = result.PublishEvaluation.Valid
		view.Conflict = result.PublishEvaluation.Conflict
		view.ResultVersion = result.PublishEvaluation.ResultVersion
		view.ResultHash = result.PublishEvaluation.ResultHash
	case controlplane.ActionKindRemoteKill:
		if result.RemoteKill == nil || result.PublishEvaluation != nil || result.Rollback != nil {
			return dashboard.DecisionReplayView{}, errors.New("conductor replay response has invalid remote-kill evaluation shape")
		}
		view.Valid = result.RemoteKill.Valid
		view.Conflict = result.RemoteKill.Conflict
		view.ResultVersion = result.RemoteKill.Counter
		view.ResultHash = result.RemoteKill.MessageHash
	case controlplane.ActionKindRollback:
		if result.Rollback == nil || result.PublishEvaluation != nil || result.RemoteKill != nil {
			return dashboard.DecisionReplayView{}, errors.New("conductor replay response has invalid rollback evaluation shape")
		}
		view.Valid = result.Rollback.Valid
		view.Conflict = result.Rollback.Conflict
		view.ResultVersion = result.Rollback.WouldRollToVersion
		view.ResultHash = result.Rollback.WouldRollToHash
	default:
		return dashboard.DecisionReplayView{}, fmt.Errorf("conductor replay response action_kind=%q is unsupported", result.ActionKind)
	}
	return view, nil
}

func dashboardConductorFleetScopeAuthorizer(orgID, fleetID string) func(*http.Request, dashboard.DecisionScope, bool) error {
	orgID = strings.TrimSpace(orgID)
	fleetID = strings.TrimSpace(fleetID)
	return func(_ *http.Request, scope dashboard.DecisionScope, _ bool) error {
		return validateDashboardConductorFleetScope(scope.OrgID, scope.FleetID, orgID, fleetID)
	}
}
