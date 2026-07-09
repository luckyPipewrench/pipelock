//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	fleetTestOrgID          = "org-test"
	fleetTestFleetID        = "fleet-test"
	fleetTestInstanceID     = "instance-sensitive-alpha"
	fleetTestEnvironment    = "env-sensitive-prod"
	fleetTestAuditKeyID     = "audit-key-sensitive"
	fleetTestHealth         = "health-sensitive"
	fleetTestDrift          = "drift-sensitive"
	fleetTestExpectedID     = "expected-bundle-sensitive"
	fleetTestExpectedHash   = "expected-hash-sensitive"
	fleetTestExpectedMin    = "expected-min-sensitive"
	fleetTestActiveID       = "active-bundle-sensitive"
	fleetTestActiveHash     = "active-hash-sensitive"
	fleetTestActiveMin      = "active-min-sensitive"
	fleetTestVersion        = "pipelock-version-sensitive"
	fleetTestSignerKeyID    = "signer-key-sensitive"
	fleetTestEnvelopeHash   = "envelope-sensitive-hash"
	fleetTestBatchID        = "batch-sensitive-id"
	fleetTestGitCommit      = "git-sensitive-commit"
	fleetTestBuildDate      = "build-sensitive-date"
	fleetTestApplyErrorCode = "apply-code-sensitive"
	fleetTestApplyError     = "apply failed on internal host"
)

type fakeFleetSource struct {
	followers []FleetFollowerView
	err       error
	gotOrgID  string
	gotFleet  string
}

func (f *fakeFleetSource) ListFleetFollowers(_ context.Context, orgID, fleetID string) ([]FleetFollowerView, error) {
	f.gotOrgID = orgID
	f.gotFleet = fleetID
	if f.err != nil {
		return nil, f.err
	}
	out := make([]FleetFollowerView, len(f.followers))
	copy(out, f.followers)
	return out, nil
}

func TestFleetOverview_Gating(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		hasFeature func(string) bool
		wantStatus int
	}{
		{
			name:       "nil_feature",
			hasFeature: nil,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "agents_only_wrong_tier",
			hasFeature: func(feature string) bool {
				return feature == license.FeatureAgents
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "fleet_only_allowed",
			hasFeature: func(feature string) bool {
				return feature == license.FeatureFleet
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "enterprise_allowed",
			hasFeature: func(feature string) bool {
				return feature == license.FeatureAgents || feature == license.FeatureFleet
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := New(Options{
				ReceiptDir:   t.TempDir(),
				HasFeature:   tt.hasFeature,
				FleetSource:  &fakeFleetSource{},
				AuthorizeRaw: allowRawAccess,
			})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "Fleet Overview") {
				t.Fatal("forbidden response leaked fleet body")
			}
		})
	}
}

func TestFleetOverview_CrossTierGating(t *testing.T) {
	t.Parallel()

	agentTierPaths := []string{
		"/",
		"/exemptions",
		"/agents",
		"/agent/example",
		"/session/example",
		"/session/example/receipt/0",
	}
	fleetOnly := New(Options{
		ReceiptDir: t.TempDir(),
		HasFeature: func(feature string) bool {
			return feature == license.FeatureFleet
		},
		FleetSource: &fakeFleetSource{},
	})
	for _, path := range agentTierPaths {
		rec := httptest.NewRecorder()
		fleetOnly.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("fleet-only path %s status = %d, want %d; body=%s", path, rec.Code, http.StatusForbidden, rec.Body.String())
		}
	}

	agentsOnly := New(Options{
		ReceiptDir: t.TempDir(),
		HasFeature: func(feature string) bool {
			return feature == license.FeatureAgents
		},
		FleetSource: &fakeFleetSource{},
	})
	rec := httptest.NewRecorder()
	agentsOnly.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("agents-only /fleet status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestFleetOverview_NilSourceRendersEmptyState(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		ReceiptDir: t.TempDir(),
		HasFeature: allowFleetFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"No conductor fleet source configured", "Other dashboard views do not depend on that source"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestFleetOverview_RendersSignedUnsignedAndHonestyWording(t *testing.T) {
	t.Parallel()

	source := &fakeFleetSource{followers: testFleetFollowers()}
	handler := New(Options{
		ReceiptDir:   t.TempDir(),
		HasFeature:   allowFleetFeature,
		FleetSource:  source,
		AuthorizeRaw: allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/fleet?org_id="+fleetTestOrgID+"&fleet_id="+fleetTestFleetID,
		nil,
	))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if source.gotOrgID != fleetTestOrgID || source.gotFleet != fleetTestFleetID {
		t.Fatalf("source scope = (%q, %q), want (%q, %q)", source.gotOrgID, source.gotFleet, fleetTestOrgID, fleetTestFleetID)
	}

	body := rec.Body.String()
	for _, want := range []string{
		fleetCompletenessClaim,
		fleetCompletenessNonClaim,
		`<span class="chip verified">Verified</span>`,
		`<span class="chip signed-unverified">Signed, not verified</span>`,
		`<span class="chip unsigned">Unsigned/self-reported</span>`,
		"Unsigned rows are self-reported runtime status",
		"active v<span class=\"mono\">7</span>",
		fleetTestVersion,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
	if strings.Count(body, `<span class="chip verified">Verified</span>`) != 1 {
		t.Fatalf("Verified badge count = %d, want 1; body=%s", strings.Count(body, `<span class="chip verified">Verified</span>`), body)
	}
}

func TestFleetOverview_RedactsMetadataView(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		ReceiptDir:  t.TempDir(),
		HasFeature:  allowFleetFeature,
		FleetSource: &fakeFleetSource{followers: testFleetFollowers()[:1]},
		// No AuthorizeRaw: metadata view must fail closed.
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{
		fleetTestInstanceID,
		fleetTestEnvironment,
		fleetTestAuditKeyID,
		fleetTestHealth,
		fleetTestDrift,
		fleetTestExpectedID,
		fleetTestExpectedHash,
		fleetTestExpectedMin,
		fleetTestActiveID,
		fleetTestActiveHash,
		fleetTestActiveMin,
		fleetTestVersion,
		fleetTestSignerKeyID,
		fleetTestEnvelopeHash,
		fleetTestBatchID,
		fleetTestGitCommit,
		fleetTestBuildDate,
		fleetTestApplyErrorCode,
		fleetTestApplyError,
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("metadata view leaked %q in body: %s", secret, body)
		}
	}
	for _, want := range []string{
		hashedFleetValue(fleetTestInstanceID),
		"Metadata view: instance IDs are hashed and raw follower",
		"health redacted",
		"drift redacted",
		"active v<span class=\"mono\">7</span>",
		"observed 2026-07-09T12:00:00Z",
		"verified at 2026-07-09T12:01:00Z",
		fleetRedacted,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metadata body missing %q: %s", want, body)
		}
	}
}

func TestFleetOverview_RawViewEscapesFollowerStrings(t *testing.T) {
	t.Parallel()

	follower := testFleetFollowers()[0]
	follower.InstanceID = hostileScript
	follower.Environment = hostileImage
	follower.ActiveBundleID = hostileScript
	follower.ActiveBundleHash = hostileImage
	follower.PipelockVersion = hostileScript
	follower.BatchID = hostileImage
	follower.LastApplyErrorMessage = hostileScript
	handler := New(Options{
		ReceiptDir:   t.TempDir(),
		HasFeature:   allowFleetFeature,
		FleetSource:  &fakeFleetSource{followers: []FleetFollowerView{follower}},
		AuthorizeRaw: allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, raw := range []string{hostileScript, hostileImage} {
		if strings.Contains(body, raw) {
			t.Fatalf("raw view rendered unescaped hostile value %q in body: %s", raw, body)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&#34;&gt;&lt;img src=x onerror=alert(1)&gt;"} {
		if !strings.Contains(body, escaped) {
			t.Fatalf("body missing escaped value %q: %s", escaped, body)
		}
	}
}

func TestFleetOverview_SourceErrorReturnsServerError(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		ReceiptDir:  t.TempDir(),
		HasFeature:  allowFleetFeature,
		FleetSource: &fakeFleetSource{err: errors.New("source unavailable")},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestFleetOverview_DisplayHelperBranches(t *testing.T) {
	t.Parallel()

	inactive := FleetFollowerView{}
	if got := inactive.EnrollmentLabel(); got != "inactive" {
		t.Fatalf("EnrollmentLabel() = %q, want inactive", got)
	}
	if got := inactive.SourceLabel(); got != "No applied-state report" {
		t.Fatalf("SourceLabel() = %q, want no-report label", got)
	}
	if got := inactive.SourceClass(); got != "missing" {
		t.Fatalf("SourceClass() = %q, want missing", got)
	}
	if got := redactedFleetString(" "); got != fleetEmptyDash {
		t.Fatalf("redactedFleetString(empty) = %q, want %q", got, fleetEmptyDash)
	}
	if got := hashedFleetValue(" "); got != fleetEmptyDash {
		t.Fatalf("hashedFleetValue(empty) = %q, want %q", got, fleetEmptyDash)
	}

	tests := []struct {
		name string
		id   string
		hash string
		want string
	}{
		{name: "id_only", id: "bundle-id", want: "bundle-id"},
		{name: "hash_only", hash: "bundle-hash", want: "bundle-hash"},
		{name: "empty", want: fleetEmptyDash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := displayBundle(tt.id, tt.hash); got != tt.want {
				t.Fatalf("displayBundle(%q, %q) = %q, want %q", tt.id, tt.hash, got, tt.want)
			}
		})
	}
}

func allowFleetFeature(feature string) bool {
	return feature == license.FeatureFleet
}

func testFleetFollowers() []FleetFollowerView {
	base := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	return []FleetFollowerView{
		{
			OrgID:                          fleetTestOrgID,
			FleetID:                        fleetTestFleetID,
			InstanceID:                     fleetTestInstanceID,
			Environment:                    fleetTestEnvironment,
			AuditKeyID:                     fleetTestAuditKeyID,
			EnrolledAt:                     base.Add(-24 * time.Hour),
			Active:                         true,
			FleetHealth:                    fleetTestHealth,
			Drift:                          fleetTestDrift,
			ExpectedBundleID:               fleetTestExpectedID,
			ExpectedBundleVersion:          7,
			ExpectedBundleHash:             fleetTestExpectedHash,
			ExpectedMinPipelockVersion:     fleetTestExpectedMin,
			RuntimeReported:                true,
			RuntimeSeenAt:                  base.Add(2 * time.Minute),
			SignedStatePresent:             true,
			Verified:                       true,
			SignerKeyID:                    fleetTestSignerKeyID,
			BatchID:                        fleetTestBatchID,
			EnvelopeHash:                   fleetTestEnvelopeHash,
			ObservedAt:                     base,
			VerifiedAt:                     base.Add(time.Minute),
			ActiveBundleID:                 fleetTestActiveID,
			ActiveBundleVersion:            7,
			ActiveBundleHash:               fleetTestActiveHash,
			ActiveBundleMinPipelockVersion: fleetTestActiveMin,
			PipelockVersion:                fleetTestVersion,
			GitCommit:                      fleetTestGitCommit,
			BuildDate:                      fleetTestBuildDate,
			LastPolicyPollAt:               base.Add(-time.Minute),
			LastSuccessfulApplyAt:          base.Add(-2 * time.Minute),
			LastApplyErrorCode:             fleetTestApplyErrorCode,
			LastApplyErrorMessage:          fleetTestApplyError,
		},
		{
			OrgID:              fleetTestOrgID,
			FleetID:            fleetTestFleetID,
			InstanceID:         "instance-beta",
			Environment:        "stage",
			Active:             true,
			FleetHealth:        "unknown",
			Drift:              "unknown",
			SignedStatePresent: true,
			Verified:           false,
			ObservedAt:         base.Add(-time.Hour),
		},
		{
			OrgID:               fleetTestOrgID,
			FleetID:             fleetTestFleetID,
			InstanceID:          "instance-gamma",
			Environment:         "dev",
			Active:              true,
			FleetHealth:         "stale",
			Drift:               "runtime-only",
			RuntimeReported:     true,
			RuntimeSeenAt:       base.Add(-30 * time.Minute),
			ActiveBundleVersion: 6,
			PipelockVersion:     "pipelock/1.2.2",
		},
	}
}
