//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/enrollmentclient"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

type statusReporterDoer struct {
	fn func(*http.Request) (*http.Response, error)
}

func (d statusReporterDoer) Do(req *http.Request) (*http.Response, error) {
	return d.fn(req)
}

func responseWithBody(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestConductorStatusEndpointValidation(t *testing.T) {
	got, err := conductorStatusEndpoint("https://conductor.example/")
	if err != nil {
		t.Fatalf("conductorStatusEndpoint(valid) error = %v", err)
	}
	if got != "https://conductor.example/api/v1/conductor/follower/status" {
		t.Fatalf("endpoint = %q", got)
	}

	for _, raw := range []string{
		"http://conductor.example",
		"https://conductor.example/base",
		"https://user@conductor.example",
		"https://conductor.example?x=1",
		"https://conductor.example#frag",
		":// bad",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := conductorStatusEndpoint(raw); err == nil {
				t.Fatalf("conductorStatusEndpoint(%q) error = nil, want error", raw)
			}
		})
	}
}

func TestNewConductorPolicyStatusReporterAndReport(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Conductor: config.Conductor{
		Enabled:           true,
		ConductorURL:      "https://conductor.example",
		OrgID:             "org-main",
		FleetID:           "prod",
		InstanceID:        "pl-prod-1",
		AuditSigningKeyID: "audit-key-main-1",
		BundleCacheDir:    dir,
	}}
	if err := writeConductorEnrollmentMarker(filepath.Join(dir, conductorEnrolledStateFileName), enrollmentclient.Response{
		OrgID:       cfg.Conductor.OrgID,
		FleetID:     cfg.Conductor.FleetID,
		InstanceID:  cfg.Conductor.InstanceID,
		Environment: "prod",
		AuditKeyID:  cfg.Conductor.AuditSigningKeyID,
		EnrolledAt:  time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("writeConductorEnrollmentMarker() error = %v", err)
	}

	var captured *http.Request
	var capturedBody []byte
	reporter, err := newConductorPolicyStatusReporter(cfg, statusReporterDoer{fn: func(req *http.Request) (*http.Response, error) {
		captured = req
		var readErr error
		capturedBody, readErr = io.ReadAll(req.Body)
		if readErr != nil {
			t.Fatalf("read request body: %v", readErr)
		}
		return responseWithBody(http.StatusOK, `{"status":"ok"}`), nil
	}}, nil)
	if err != nil {
		t.Fatalf("newConductorPolicyStatusReporter() error = %v", err)
	}
	if reporter == nil {
		t.Fatal("reporter = nil, want reporter")
	}

	pollAt := time.Date(2026, 5, 24, 12, 30, 0, 0, time.UTC)
	err = reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{
		PollAt:        pollAt,
		AppliedBundle: &conductor.PolicyBundle{BundleID: "bundle-1"},
		ApplyError:    applycache.ErrRollbackRequired,
	})
	if err != nil {
		t.Fatalf("ReportPolicyStatus() error = %v", err)
	}
	if captured == nil {
		t.Fatal("no request captured")
	}
	if captured.Method != http.MethodPost || captured.URL.Path != controlplane.FollowerRuntimeStatusPath {
		t.Fatalf("request = %s %s, want POST %s", captured.Method, captured.URL.Path, controlplane.FollowerRuntimeStatusPath)
	}
	if captured.Header.Get("Content-Type") != "application/json" || captured.Header.Get("Accept") != "application/json" {
		t.Fatalf("headers = %v", captured.Header)
	}
	var payload struct {
		Status controlplane.FollowerRuntimeStatus `json:"status"`
	}
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("decode status payload: %v", err)
	}
	status := payload.Status
	if status.OrgID != "org-main" || status.FleetID != "prod" || status.InstanceID != "pl-prod-1" || status.Environment != "prod" {
		t.Fatalf("identity status = %+v", status)
	}
	if status.LastApplyErrorCode != "rollback_required" || !strings.Contains(status.LastApplyErrorMessage, applycache.ErrRollbackRequired.Error()) {
		t.Fatalf("apply error status = code %q message %q", status.LastApplyErrorCode, status.LastApplyErrorMessage)
	}
	if !status.LastPolicyPollAt.Equal(pollAt) || !status.LastSuccessfulApplyAt.Equal(pollAt) || !status.LastSeenAt.Equal(pollAt) {
		t.Fatalf("status times = poll %s success %s seen %s, want %s", status.LastPolicyPollAt, status.LastSuccessfulApplyAt, status.LastSeenAt, pollAt)
	}
}

func TestConductorPolicyStatusReporterErrorPaths(t *testing.T) {
	baseConfig := func(dir string) *config.Config {
		return &config.Config{Conductor: config.Conductor{
			Enabled:           true,
			ConductorURL:      "https://conductor.example",
			OrgID:             "org-main",
			FleetID:           "prod",
			InstanceID:        "pl-prod-1",
			AuditSigningKeyID: "audit-key-main-1",
			BundleCacheDir:    dir,
		}}
	}

	t.Run("nil config", func(t *testing.T) {
		reporter, err := newConductorPolicyStatusReporter(nil, statusReporterDoer{}, nil)
		if err != nil || reporter != nil {
			t.Fatalf("reporter = (%v, %v), want nil nil", reporter, err)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		if _, err := newConductorPolicyStatusReporter(&config.Config{Conductor: config.Conductor{Enabled: true}}, nil, nil); err == nil {
			t.Fatal("newConductorPolicyStatusReporter(nil client) error = nil, want error")
		}
	})

	t.Run("missing marker", func(t *testing.T) {
		reporter, err := newConductorPolicyStatusReporter(baseConfig(t.TempDir()), statusReporterDoer{}, nil)
		if err != nil || reporter != nil {
			t.Fatalf("reporter = (%v, %v), want nil nil", reporter, err)
		}
	})

	t.Run("malformed marker", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, conductorEnrolledStateFileName), []byte(`{`), 0o600); err != nil {
			t.Fatalf("write malformed marker: %v", err)
		}
		reporter, err := newConductorPolicyStatusReporter(baseConfig(dir), statusReporterDoer{}, nil)
		if err != nil || reporter != nil {
			t.Fatalf("reporter = (%v, %v), want nil nil", reporter, err)
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		if err := (*conductorPolicyStatusReporter)(nil).ReportPolicyStatus(context.Background(), policysync.StatusEvent{}); err != nil {
			t.Fatalf("ReportPolicyStatus() error = %v", err)
		}
	})

	t.Run("bad endpoint", func(t *testing.T) {
		reporter := &conductorPolicyStatusReporter{endpoint: ":// bad", client: statusReporterDoer{}}
		if err := reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{}); err == nil || !strings.Contains(err.Error(), "build conductor runtime status request") {
			t.Fatalf("ReportPolicyStatus() error = %v, want build request error", err)
		}
	})

	t.Run("client error", func(t *testing.T) {
		wantErr := errors.New("dial failed")
		reporter := &conductorPolicyStatusReporter{
			endpoint: "https://conductor.example" + controlplane.FollowerRuntimeStatusPath,
			client: statusReporterDoer{fn: func(*http.Request) (*http.Response, error) {
				return nil, wantErr
			}},
		}
		if err := reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{}); !errors.Is(err, wantErr) {
			t.Fatalf("ReportPolicyStatus() = %v, want %v", err, wantErr)
		}
	})

	t.Run("non-200 response", func(t *testing.T) {
		reporter := &conductorPolicyStatusReporter{
			endpoint: "https://conductor.example" + controlplane.FollowerRuntimeStatusPath,
			client: statusReporterDoer{fn: func(*http.Request) (*http.Response, error) {
				return responseWithBody(http.StatusConflict, "bad\n"+strings.Repeat("x", 300)), nil
			}},
		}
		err := reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{})
		if err == nil || !strings.Contains(err.Error(), "HTTP 409") {
			t.Fatalf("ReportPolicyStatus() error = %v, want HTTP 409", err)
		}
		if strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), strings.Repeat("x", 300)) {
			t.Fatalf("non-200 error was not sanitized/truncated: %q", err.Error())
		}
	})
}

func TestApplyErrorCodeMapsKnownErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{err: applycache.ErrUnsupportedMinVersion, want: "unsupported_min_version"},
		{err: conductor.ErrAudienceMismatch, want: "audience_mismatch"},
		{err: conductor.ErrSignatureVerification, want: "signature_verification"},
		{err: applycache.ErrRollbackRequired, want: "rollback_required"},
		{err: applycache.ErrEntitlementLost, want: "entitlement_lost"},
		{err: errors.New("reload failed"), want: "apply_failed"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if got := applyErrorCode(tc.err); got != tc.want {
				t.Fatalf("applyErrorCode(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
