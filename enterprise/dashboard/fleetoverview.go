//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	fleetCompletenessClaim    = "mediated fleet state as reported by enrolled followers"
	fleetCompletenessNonClaim = "does not prove no bypass occurred outside Pipelock, outside enrolled followers, or outside the report window"
	fleetStatusVerified       = "Verified"
	fleetStatusSignedOnly     = "Signed, not verified"
	fleetStatusUnsigned       = "Unsigned/self-reported"
	fleetRedacted             = "redacted"
	fleetEmptyDash            = "-"
)

// FleetDataSource is the dashboard-local read seam for conductor fleet state.
// Implementations must be read-only: the Fleet Overview route has no write or
// control authority.
type FleetDataSource interface {
	ListFleetFollowers(ctx context.Context, orgID, fleetID string) ([]FleetFollowerView, error)
}

// FleetFollowerView is the dashboard-local follower row. It intentionally
// carries only fields rendered by fleetoverview.tmpl.html so tests can use a
// fake source without booting a conductor.
type FleetFollowerView struct {
	OrgID       string
	FleetID     string
	InstanceID  string
	Environment string
	AuditKeyID  string
	EnrolledAt  time.Time
	Active      bool

	FleetHealth string
	Drift       string

	ExpectedBundleID           string
	ExpectedBundleVersion      uint64
	ExpectedBundleHash         string
	ExpectedMinPipelockVersion string

	RuntimeReported bool
	RuntimeSeenAt   time.Time

	SignedStatePresent bool
	Verified           bool
	SignerKeyID        string
	BatchID            string
	EnvelopeHash       string
	ObservedAt         time.Time
	VerifiedAt         time.Time

	ActiveBundleID                 string
	ActiveBundleVersion            uint64
	ActiveBundleHash               string
	ActiveBundleMinPipelockVersion string
	PipelockVersion                string
	GitCommit                      string
	BuildDate                      string
	LastPolicyPollAt               time.Time
	LastSuccessfulApplyAt          time.Time
	LastApplyErrorCode             string
	LastApplyErrorMessage          string
}

type FleetOverview struct {
	SourceConfigured bool
	OrgID            string
	FleetID          string
	Claim            string
	NonClaim         string
	RawAllowed       bool
	Followers        []FleetFollowerView
}

func (m *ReadModel) FleetOverview(ctx context.Context, orgID, fleetID string, rawAllowed bool) (FleetOverview, error) {
	overview := FleetOverview{
		SourceConfigured: m.fleetSource != nil,
		OrgID:            strings.TrimSpace(orgID),
		FleetID:          strings.TrimSpace(fleetID),
		Claim:            fleetCompletenessClaim,
		NonClaim:         fleetCompletenessNonClaim,
		RawAllowed:       rawAllowed,
	}
	if m.fleetSource == nil {
		return overview, nil
	}
	followers, err := m.fleetSource.ListFleetFollowers(ctx, overview.OrgID, overview.FleetID)
	if err != nil {
		return FleetOverview{}, fmt.Errorf("list fleet followers: %w", err)
	}
	if !rawAllowed {
		followers = redactFleetFollowers(followers)
	}
	overview.Followers = followers
	return overview, nil
}

func redactFleetFollowers(in []FleetFollowerView) []FleetFollowerView {
	out := make([]FleetFollowerView, len(in))
	for i, follower := range in {
		follower.InstanceID = hashedFleetValue(follower.InstanceID)
		follower.Environment = redactedFleetString(follower.Environment)
		follower.AuditKeyID = redactedFleetString(follower.AuditKeyID)
		follower.FleetHealth = redactedFleetString(follower.FleetHealth)
		follower.Drift = redactedFleetString(follower.Drift)
		follower.ExpectedBundleID = redactedFleetString(follower.ExpectedBundleID)
		follower.ExpectedBundleHash = redactedFleetString(follower.ExpectedBundleHash)
		follower.ExpectedMinPipelockVersion = redactedFleetString(follower.ExpectedMinPipelockVersion)
		follower.BatchID = redactedFleetString(follower.BatchID)
		follower.EnvelopeHash = redactedFleetString(follower.EnvelopeHash)
		follower.SignerKeyID = redactedFleetString(follower.SignerKeyID)
		follower.ActiveBundleID = redactedFleetString(follower.ActiveBundleID)
		follower.ActiveBundleHash = redactedFleetString(follower.ActiveBundleHash)
		follower.ActiveBundleMinPipelockVersion = redactedFleetString(follower.ActiveBundleMinPipelockVersion)
		follower.PipelockVersion = redactedFleetString(follower.PipelockVersion)
		follower.GitCommit = redactedFleetString(follower.GitCommit)
		follower.BuildDate = redactedFleetString(follower.BuildDate)
		follower.LastApplyErrorCode = redactedFleetString(follower.LastApplyErrorCode)
		follower.LastApplyErrorMessage = redactedFleetString(follower.LastApplyErrorMessage)
		out[i] = follower
	}
	return out
}

func hashedFleetValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fleetEmptyDash
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

func redactedFleetString(value string) string {
	if strings.TrimSpace(value) == "" {
		return fleetEmptyDash
	}
	return fleetRedacted
}

func (f FleetFollowerView) InstanceDisplay() string {
	return displayFleetString(f.InstanceID)
}

func (f FleetFollowerView) EnvironmentDisplay() string {
	return displayFleetString(f.Environment)
}

func (f FleetFollowerView) AuditKeyDisplay() string {
	return displayFleetString(f.AuditKeyID)
}

func (f FleetFollowerView) DriftDisplay() string {
	return displayFleetString(f.Drift)
}

func (f FleetFollowerView) HealthDisplay() string {
	return displayFleetString(f.FleetHealth)
}

func (f FleetFollowerView) SourceLabel() string {
	if f.SignedStatePresent && f.Verified {
		return fleetStatusVerified
	}
	if f.SignedStatePresent {
		return fleetStatusSignedOnly
	}
	if f.RuntimeReported {
		return fleetStatusUnsigned
	}
	return "No applied-state report"
}

func (f FleetFollowerView) SourceClass() string {
	if f.SignedStatePresent && f.Verified {
		return "verified"
	}
	if f.SignedStatePresent {
		return "signed-unverified"
	}
	if f.RuntimeReported {
		return "unsigned"
	}
	return "missing"
}

func (f FleetFollowerView) EnrollmentLabel() string {
	if f.Active {
		return "active"
	}
	return "inactive"
}

func (f FleetFollowerView) EnrolledAtDisplay() string {
	return displayFleetTime(f.EnrolledAt)
}

func (f FleetFollowerView) RuntimeSeenDisplay() string {
	return displayFleetTime(f.RuntimeSeenAt)
}

func (f FleetFollowerView) ObservedAtDisplay() string {
	return displayFleetTime(f.ObservedAt)
}

func (f FleetFollowerView) VerifiedAtDisplay() string {
	return displayFleetTime(f.VerifiedAt)
}

func (f FleetFollowerView) LastPolicyPollDisplay() string {
	return displayFleetTime(f.LastPolicyPollAt)
}

func (f FleetFollowerView) LastSuccessfulApplyDisplay() string {
	return displayFleetTime(f.LastSuccessfulApplyAt)
}

func (f FleetFollowerView) ActiveBundleVersionDisplay() string {
	if f.ActiveBundleVersion == 0 {
		return fleetEmptyDash
	}
	return fmt.Sprintf("%d", f.ActiveBundleVersion)
}

func (f FleetFollowerView) ExpectedBundleVersionDisplay() string {
	if f.ExpectedBundleVersion == 0 {
		return fleetEmptyDash
	}
	return fmt.Sprintf("%d", f.ExpectedBundleVersion)
}

func (f FleetFollowerView) ActiveBundleDisplay() string {
	return displayBundle(f.ActiveBundleID, f.ActiveBundleHash)
}

func (f FleetFollowerView) ExpectedBundleDisplay() string {
	return displayBundle(f.ExpectedBundleID, f.ExpectedBundleHash)
}

func (f FleetFollowerView) MinVersionDisplay() string {
	return displayFleetString(f.ActiveBundleMinPipelockVersion)
}

func (f FleetFollowerView) ExpectedMinVersionDisplay() string {
	return displayFleetString(f.ExpectedMinPipelockVersion)
}

func (f FleetFollowerView) PipelockVersionDisplay() string {
	return displayFleetString(f.PipelockVersion)
}

func (f FleetFollowerView) GitCommitDisplay() string {
	return displayFleetString(f.GitCommit)
}

func (f FleetFollowerView) BuildDateDisplay() string {
	return displayFleetString(f.BuildDate)
}

func (f FleetFollowerView) SignerKeyDisplay() string {
	return displayFleetString(f.SignerKeyID)
}

func (f FleetFollowerView) BatchIDDisplay() string {
	return displayFleetString(f.BatchID)
}

func (f FleetFollowerView) EnvelopeHashDisplay() string {
	return displayFleetString(f.EnvelopeHash)
}

func (f FleetFollowerView) LastApplyErrorCodeDisplay() string {
	return displayFleetString(f.LastApplyErrorCode)
}

func (f FleetFollowerView) LastApplyErrorMessageDisplay() string {
	return displayFleetString(f.LastApplyErrorMessage)
}

func displayBundle(id, hash string) string {
	id = strings.TrimSpace(id)
	hash = strings.TrimSpace(hash)
	switch {
	case id != "" && hash != "":
		return id + " / " + hash
	case id != "":
		return id
	case hash != "":
		return hash
	default:
		return fleetEmptyDash
	}
}

func displayFleetString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fleetEmptyDash
	}
	return value
}

func displayFleetTime(value time.Time) string {
	if value.IsZero() {
		return fleetEmptyDash
	}
	return value.UTC().Format(time.RFC3339)
}
