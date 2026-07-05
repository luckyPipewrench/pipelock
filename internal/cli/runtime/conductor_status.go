//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const conductorStatusResponseBytes = 64 * 1024

type conductorPolicyStatusReporter struct {
	client   policysync.HTTPDoer
	endpoint string
	cfg      config.Conductor
	identity conductorEnrollmentMarker
	cache    *applycache.Cache
}

func newConductorPolicyStatusReporter(cfg *config.Config, client policysync.HTTPDoer, cache *applycache.Cache) (*conductorPolicyStatusReporter, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil
	}
	if client == nil {
		return nil, errors.New("conductor runtime status reporter HTTP client required")
	}
	marker, ok, err := readConductorEnrollmentMarker(filepath.Join(cfg.Conductor.BundleCacheDir, conductorEnrolledStateFileName), cfg.Conductor)
	if err != nil {
		// Runtime status is best-effort telemetry; a bad marker must not block
		// the core policy bundle poller from starting.
		return nil, nil
	}
	if !ok {
		return nil, nil
	}
	endpoint, err := conductorStatusEndpoint(cfg.Conductor.ConductorURL)
	if err != nil {
		return nil, err
	}
	return &conductorPolicyStatusReporter{
		client:   client,
		endpoint: endpoint,
		cfg:      cfg.Conductor,
		identity: marker,
		cache:    cache,
	}, nil
}

func conductorStatusEndpoint(rawBaseURL string) (string, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse conductor status base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("conductor status base URL must be https with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("conductor status base URL must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("conductor status base URL must not include a path component")
	}
	u.Path = controlplane.FollowerRuntimeStatusPath
	u.RawPath = ""
	return u.String(), nil
}

func (r *conductorPolicyStatusReporter) ReportPolicyStatus(ctx context.Context, ev policysync.StatusEvent) error {
	if r == nil {
		return nil
	}
	status := r.status(ev)
	body, err := json.Marshal(struct {
		Status controlplane.FollowerRuntimeStatus `json:"status"`
	}{Status: status})
	if err != nil {
		return fmt.Errorf("marshal conductor runtime status: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build conductor runtime status request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("post conductor runtime status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, conductorStatusResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("conductor runtime status rejected HTTP %d: %s", resp.StatusCode, statusSnippet(respBody))
	}
	return nil
}

func (r *conductorPolicyStatusReporter) status(ev policysync.StatusEvent) controlplane.FollowerRuntimeStatus {
	pollAt := ev.PollAt
	if pollAt.IsZero() {
		pollAt = time.Now().UTC()
	}
	status := controlplane.FollowerRuntimeStatus{
		OrgID:            r.cfg.OrgID,
		FleetID:          r.cfg.FleetID,
		InstanceID:       r.cfg.InstanceID,
		Environment:      r.identity.Environment,
		PipelockVersion:  cliutil.Version,
		GitCommit:        cliutil.GitCommit,
		BuildDate:        cliutil.BuildDate,
		SchemaVersion:    conductor.SchemaVersion,
		LastPolicyPollAt: pollAt.UTC(),
		LastSeenAt:       pollAt.UTC(),
	}
	if ev.ApplyError != nil {
		status.LastApplyErrorCode = applyErrorCode(ev.ApplyError)
		status.LastApplyErrorMessage = ev.ApplyError.Error()
	}
	if ev.AppliedBundle != nil {
		status.LastSuccessfulApplyAt = pollAt.UTC()
	}
	r.fillActiveBundle(&status)
	return status
}

func (r *conductorPolicyStatusReporter) fillActiveBundle(status *controlplane.FollowerRuntimeStatus) {
	if r.cache == nil || status == nil {
		return
	}
	active, err := r.cache.Active()
	if err != nil {
		return
	}
	status.ActiveBundleID = active.Bundle.BundleID
	status.ActiveBundleVersion = active.Bundle.Version
	status.ActiveBundleHash = active.BundleHash
	status.ActiveBundleMinPipelockVersion = active.Bundle.MinPipelockVersion
}

func applyErrorCode(err error) string {
	switch {
	case errors.Is(err, applycache.ErrUnsupportedMinVersion):
		return "unsupported_min_version"
	case errors.Is(err, conductor.ErrAudienceMismatch):
		return "audience_mismatch"
	case errors.Is(err, conductor.ErrSignatureVerification):
		return "signature_verification"
	case errors.Is(err, applycache.ErrRollbackRequired):
		return "rollback_required"
	case errors.Is(err, applycache.ErrEntitlementLost):
		return "entitlement_lost"
	default:
		return "apply_failed"
	}
}

func statusSnippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	const maxLen = 256
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
