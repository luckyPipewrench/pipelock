//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/cli/conductor"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	wbTestOrgID        = "org-test"
	wbTestFleetID      = "fleet-test"
	wbTestArtifactHash = "sha256:abc123"
	wbSensitiveHash    = "sha256:sensitive-artifact"
	wbSensitiveResult  = "sha256:sensitive-result"
	wbSensitiveReason  = "reason-sensitive-detail"
)

// fakeConductorSource is a read-only ConductorDecisionSource. It records the
// arguments it saw and how many times it was called so tests can assert that
// mutating HTTP methods never reach it (the never-authority invariant).
type fakeConductorSource struct {
	view    DecisionReplayView
	found   bool
	err     error
	calls   atomic.Int64
	gotHash string
}

func (f *fakeConductorSource) ReplayDecision(_ context.Context, scope DecisionScope) (DecisionReplayView, bool, error) {
	f.calls.Add(1)
	f.gotHash = scope.ArtifactHash
	if f.err != nil {
		return DecisionReplayView{}, false, f.err
	}
	return f.view, f.found, nil
}

func testReplayView() DecisionReplayView {
	return DecisionReplayView{
		ActionKind:        actionKindRollback,
		ArtifactHash:      wbSensitiveHash,
		ResultVersion:     42,
		ResultHash:        wbSensitiveResult,
		UsedStateSnapshot: false,
		ReplayedAt:        time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		Valid:             true,
		Conflict:          "",
		Divergence:        true,
		DivergenceReason:  wbSensitiveReason,
		RecordedPresent:   true,
		RecordedAccepted:  true,
		RecordedHash:      wbSensitiveResult,
		RecordedAt:        time.Date(2026, 7, 9, 11, 0, 0, 0, time.UTC),
	}
}

func wbReplayTarget() string {
	return "/workbench?org_id=" + wbTestOrgID + "&fleet_id=" + wbTestFleetID + "&artifact_hash=" + wbTestArtifactHash
}

func TestWorkbench_Gating(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		hasFeature func(string) bool
		wantStatus int
	}{
		{name: "nil_feature", hasFeature: nil, wantStatus: http.StatusForbidden},
		{
			name:       "agents_only_wrong_tier",
			hasFeature: func(f string) bool { return f == license.FeatureAgents },
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "fleet_only_allowed",
			hasFeature: func(f string) bool { return f == license.FeatureFleet },
			wantStatus: http.StatusOK,
		},
		{
			name:       "enterprise_allowed",
			hasFeature: func(f string) bool { return f == license.FeatureAgents || f == license.FeatureFleet },
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := New(Options{
				TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: tt.hasFeature,
			})
			for _, path := range []string{"/workbench", "/incident"} {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
				if rec.Code != tt.wantStatus {
					t.Fatalf("%s status = %d, want %d; body=%s", path, rec.Code, tt.wantStatus, rec.Body.String())
				}
			}
		})
	}
}

// TestWorkbench_NoStateMutatingRoute proves the never-authority invariant: the
// workbench and incident page-set expose no state-mutating route. Every
// non-GET method on every route returns 405 BEFORE any model/source call, so no
// write path is reachable, and the only conductor seam wired is read-only.
//
// A reviewer neutralizes this by adding a mutating handler: e.g. register a
// POST route in New(), or delete the requireGet guard in handleWorkbench /
// handleIncident. The test then fails because a mutating method returns 200
// instead of 405 (or the fake source's mutating-call counter fires).
func TestWorkbench_NoStateMutatingRoute(t *testing.T) {
	t.Parallel()

	source := &fakeConductorSource{view: testReplayView(), found: true}
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowFleetFeature,
		ConductorSource:     source,
		FleetSource:         &fakeFleetSource{},
		AuthorizeRaw:        allowRawAccess,
		AuthorizeFleetScope: allowFleetScope,
	})
	paths := []string{"/workbench", wbReplayTarget(), "/incident", "/incident?org_id=" + wbTestOrgID + "&fleet_id=" + wbTestFleetID + "&artifact_hash=" + wbTestArtifactHash}
	mutating := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, path := range paths {
		for _, method := range mutating {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader("body=payload")))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s status = %d, want %d (no mutating route may exist); body=%s",
					method, path, rec.Code, http.StatusMethodNotAllowed, rec.Body.String())
			}
		}
	}
	if got := source.calls.Load(); got != 0 {
		t.Fatalf("read-only source was invoked %d times by mutating requests; a mutating method reached the model", got)
	}
}

func TestWorkbench_FailClosedScopeAuthorization(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		authorize func(*http.Request, DecisionScope, bool) error
	}{
		{name: "missing_authorizer", authorize: nil},
		{name: "denied_authorizer", authorize: func(*http.Request, DecisionScope, bool) error {
			return errors.New("wrong fleet")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			source := &fakeConductorSource{view: testReplayView(), found: true}
			handler := New(Options{
				TrustedOuterAuth:    true,
				ReceiptDir:          t.TempDir(),
				HasFeature:          allowFleetFeature,
				ConductorSource:     source,
				AuthorizeFleetScope: tt.authorize,
			})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
			if got := source.calls.Load(); got != 0 {
				t.Fatalf("source calls = %d, want 0 before scope authorization", got)
			}
		})
	}
}

func TestWorkbench_ScopeAuditRedactsIdentifiers(t *testing.T) {
	t.Parallel()

	var audit strings.Builder
	source := &fakeConductorSource{view: testReplayView(), found: true}
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowFleetFeature,
		ConductorSource:     source,
		AuthorizeFleetScope: allowFleetScope,
		AuditWriter:         &audit,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	log := audit.String()
	for _, secret := range []string{wbTestOrgID, wbTestFleetID, wbTestArtifactHash, wbSensitiveReason} {
		if strings.Contains(log, secret) {
			t.Fatalf("scope audit leaked %q: %s", secret, log)
		}
	}
	for _, want := range []string{
		"pipelock-dashboard scope",
		"org_sha256=",
		"fleet_sha256=",
		"artifact_sha256=",
		"decision_source=true",
		"decision_found=true",
		"divergence=true",
		`conflict="-"`,
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("scope audit missing %q: %s", want, log)
		}
	}
}

// TestWorkbench_FailClosedLicense is the gating proof: with NO fleet license the
// workbench/incident routes refuse (403) AND the free agent-tier detection pages
// still render; with the fleet license they render (200).
//
// Neutralize by changing d.fleetGate to d.gate (FeatureAgents) on the workbench
// route in New(): the agents-only case then renders 200 instead of 403.
func TestWorkbench_FailClosedLicense(t *testing.T) {
	t.Parallel()

	noFleet := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       func(f string) bool { return f == license.FeatureAgents },
	})
	for _, path := range []string{"/workbench", "/incident"} {
		rec := httptest.NewRecorder()
		noFleet.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("no-fleet-license %s = %d, want 403; body=%s", path, rec.Code, rec.Body.String())
		}
	}
	// The free agent-tier detection page is unaffected by the fleet gate.
	rec := httptest.NewRecorder()
	noFleet.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("agents-tier /agents with agents license = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	withFleet := New(Options{
		TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature,
	})
	for _, path := range []string{"/workbench", "/incident"} {
		rec := httptest.NewRecorder()
		withFleet.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("fleet-license %s = %d, want 200; body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestWorkbench_PrepareGuidanceAndNeverAuthority(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/workbench", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		workbenchNeverAuthority,
		"pipelock conductor publish",
		"pipelock conductor kill",
		"pipelock conductor rollback",
		"No conductor decision source configured",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("workbench body missing %q: %s", want, body)
		}
	}
	// Bounded claims: no aggregate "all clear" / green language.
	for _, banned := range []string{"all clear", "everything verified", "fully compliant", "all green"} {
		if strings.Contains(strings.ToLower(body), banned) {
			t.Fatalf("workbench leaked aggregate-green wording %q", banned)
		}
	}
}

func TestWorkbench_ReplayRawView(t *testing.T) {
	t.Parallel()

	source := &fakeConductorSource{view: testReplayView(), found: true}
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowFleetFeature,
		ConductorSource:     source,
		AuthorizeRaw:        allowRawAccess,
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if source.gotHash != wbTestArtifactHash {
		t.Fatalf("source got hash %q, want %q", source.gotHash, wbTestArtifactHash)
	}
	body := rec.Body.String()
	for _, want := range []string{"Rollback", "Divergence", wbSensitiveHash, wbSensitiveResult, wbSensitiveReason, "42"} {
		if !strings.Contains(body, want) {
			t.Fatalf("raw replay body missing %q: %s", want, body)
		}
	}
}

func TestWorkbench_ReplayMetadataViewRedacts(t *testing.T) {
	t.Parallel()

	view := testReplayView()
	view.Valid = false
	view.Conflict = "source error for " + wbSensitiveHash
	source := &fakeConductorSource{view: view, found: true}
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowFleetFeature,
		ConductorSource:  source,
		// No AuthorizeRaw: metadata view must fail closed.
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{wbSensitiveHash, wbSensitiveResult, wbSensitiveReason, "source error", ">42<"} {
		if strings.Contains(body, secret) {
			t.Fatalf("metadata view leaked %q: %s", secret, body)
		}
	}
	// Computed status is kept even in the redacted view.
	for _, want := range []string{"Rollback", "Divergence", "Would be rejected: unknown", fleetRedacted} {
		if !strings.Contains(body, want) {
			t.Fatalf("metadata replay body missing %q: %s", want, body)
		}
	}
}

func TestWorkbench_ReplayRawEscapesHostileStrings(t *testing.T) {
	t.Parallel()

	view := testReplayView()
	view.ArtifactHash = hostileScript
	view.ResultHash = hostileImage
	view.DivergenceReason = hostileScript
	source := &fakeConductorSource{view: view, found: true}
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowFleetFeature,
		ConductorSource:     source,
		AuthorizeRaw:        allowRawAccess,
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, raw := range []string{hostileScript, hostileImage} {
		if strings.Contains(body, raw) {
			t.Fatalf("raw view rendered unescaped hostile value %q: %s", raw, body)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("body missing escaped hostile value: %s", body)
	}
}

func TestWorkbench_ReplayNotFound(t *testing.T) {
	t.Parallel()

	source := &fakeConductorSource{found: false}
	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature, ConductorSource: source, AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "No recorded decision matched") {
		t.Fatalf("body missing not-found state: %s", rec.Body.String())
	}
}

func TestWorkbench_ReplayNotFoundMetadataRedactsScope(t *testing.T) {
	t.Parallel()

	source := &fakeConductorSource{found: false}
	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature, ConductorSource: source, AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{wbTestOrgID, wbTestFleetID} {
		if strings.Contains(body, secret) {
			t.Fatalf("metadata not-found view leaked scope %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, "org <span class=\"mono\">"+fleetRedacted+"</span> / fleet <span class=\"mono\">"+fleetRedacted+"</span>") {
		t.Fatalf("metadata not-found view missing redacted scope: %s", body)
	}
}

func TestWorkbench_SourceErrorReturnsServerError(t *testing.T) {
	t.Parallel()

	source := &fakeConductorSource{err: errors.New("source unavailable")}
	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature, ConductorSource: source, AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, wbReplayTarget(), nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

func TestWorkbench_RejectsInvalidScope(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature, ConductorSource: &fakeConductorSource{}, AuthorizeFleetScope: allowFleetScope,
	})
	for _, target := range []string{
		"/workbench?artifact_hash=" + wbTestArtifactHash,                            // hash without org/fleet
		"/workbench?org_id=" + wbTestOrgID + "&artifact_hash=" + wbTestArtifactHash, // missing fleet
		"/workbench?org_id=../prod&fleet_id=" + wbTestFleetID + "&artifact_hash=" + wbTestArtifactHash,
		"/workbench?org_id=" + wbTestOrgID + "&fleet_id=" + wbTestFleetID + "&artifact_hash=bad%0Ahash",
		"/workbench?org_id=" + wbTestOrgID, // scope without hash
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestWorkbench_RejectsNonExactPath(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature,
	})
	for _, path := range []string{"/workbench/extra", "/incident/extra"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404; body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestWorkbench_ReplayViewHelperBranches(t *testing.T) {
	t.Parallel()

	unknown := normalizeReplayView(DecisionReplayView{ActionKind: "wat"})
	if unknown.ActionKind != actionKindUnknown {
		t.Fatalf("ActionKind = %q, want unknown", unknown.ActionKind)
	}
	if got := unknown.KindLabel(); got != "Unknown action" {
		t.Fatalf("KindLabel = %q", got)
	}
	rejected := DecisionReplayView{Valid: false, Conflict: "stale_counter"}
	if got := rejected.VerdictLabel(); got != "Would be rejected: stale_counter" {
		t.Fatalf("VerdictLabel = %q", got)
	}
	if got := (DecisionReplayView{}).VerdictLabel(); got != "Would be rejected" {
		t.Fatalf("VerdictLabel empty = %q", got)
	}
	if got := (DecisionReplayView{}).RecordedLabel(); got != "no recorded decision" {
		t.Fatalf("RecordedLabel = %q", got)
	}
	present := DecisionReplayView{RecordedPresent: true}
	if got := present.RecordedLabel(); got != "recorded (not accepted)" {
		t.Fatalf("RecordedLabel present = %q", got)
	}
	if got := (DecisionReplayView{}).ResultVersionDisplay(); got != fleetEmptyDash {
		t.Fatalf("ResultVersionDisplay(0) = %q", got)
	}
	if got := (DecisionReplayView{ResultVersion: 3}).ResultVersionDisplay(); got != "3" {
		t.Fatalf("ResultVersionDisplay(3) = %q", got)
	}
	if got := (DecisionReplayView{Divergence: false}).DivergenceClass(); got != "verified" {
		t.Fatalf("DivergenceClass = %q", got)
	}
}

// TestPrepareSteps_TemplatesReferenceRealConductorFlags is a drift guard: every
// --flag in a workbench prepare template must exist on the matching shipped
// conductor subcommand. Without it, a flag rename in conductor publish/kill/
// rollback silently leaves the dashboard telling operators to run a command
// that no longer parses (the exact defect this replaced: rollback used the
// nonexistent --to-version, and publish/kill omitted mandatory auth/TLS flags).
func TestPrepareSteps_TemplatesReferenceRealConductorFlags(t *testing.T) {
	kindToSubcommand := map[string]string{
		actionKindPublish:    "publish",
		actionKindRemoteKill: "kill",
		actionKindRollback:   "rollback",
	}

	root := conductor.Cmd()
	subcommands := make(map[string]*cobra.Command)
	for _, c := range root.Commands() {
		subcommands[c.Name()] = c
	}

	for _, step := range prepareSteps() {
		step := step
		t.Run(step.Kind, func(t *testing.T) {
			name, ok := kindToSubcommand[step.Kind]
			if !ok {
				t.Fatalf("prepare step kind %q has no conductor subcommand mapping", step.Kind)
			}
			sub, ok := subcommands[name]
			if !ok {
				t.Fatalf("conductor has no %q subcommand", name)
			}
			flags := prepareTemplateFlags(step.Command)
			if len(flags) == 0 {
				t.Fatalf("template for %q defines no flags: %q", step.Kind, step.Command)
			}
			for _, flag := range flags {
				if sub.Flag(flag) == nil {
					t.Errorf("template for %q references --%s, which conductor %s does not define",
						step.Kind, flag, name)
				}
			}
		})
	}
}

// prepareTemplateFlags extracts the long-flag names ("--foo bar" -> "foo") from
// a shell command template. Placeholders (<...>, '*') are ignored because they
// are not flags.
func prepareTemplateFlags(command string) []string {
	var flags []string
	for _, token := range strings.Fields(command) {
		if !strings.HasPrefix(token, "--") {
			continue
		}
		name := strings.TrimPrefix(token, "--")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			flags = append(flags, name)
		}
	}
	return flags
}
