//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	hostileScript = "<script>alert(1)</script>"
	hostileImage  = "\"><img src=x onerror=alert(1)>"
	hostileJSURL  = "javascript:alert(1)"
	hostileJSON   = `</script><script>alert("json")</script>`
)

func TestAuditLogValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"empty", "", "-"},
		{"trimmed empty", " \t\n ", "-"},
		{"printable", " operator-1 ", "operator-1"},
		{"control characters", "operator\nadmin\trole", "operator?admin?role"},
		{"only non printable", "\x01\x02", "??"},
		{"non ascii", "role-\u2603", "role-?"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AuditLogValue(tc.value); got != tc.want {
				t.Fatalf("AuditLogValue(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestHandler_Gating(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: dir,
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("nil HasFeature status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), "Scorecard") {
		t.Fatal("forbidden response should not contain evidence body")
	}

	handler = New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		HasFeature: func(string) bool {
			return false
		},
	})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("false HasFeature status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("false HasFeature /session status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("false HasFeature /exemptions status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandler_AllowedRendersScorecard(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Scorecard") {
		t.Fatal("allowed response should render scorecard")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("CSP = %q, want %q", got, contentSecurityPolicy)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestHandler_RequiresExplicitAuthBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		opts       Options
		wantStatus int
	}{
		{
			name: "nil auth callbacks deny",
			opts: Options{
				ReceiptDir: t.TempDir(),
				HasFeature: allowAgentsFeature,
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "trusted outer auth explicit opt in",
			opts: Options{
				ReceiptDir:       t.TempDir(),
				HasFeature:       allowAgentsFeature,
				TrustedOuterAuth: true,
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "handler auth callback configured",
			opts: Options{
				ReceiptDir: t.TempDir(),
				HasFeature: allowAgentsFeature,
				Authorize:  func(*http.Request) error { return nil },
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "permission auth callback configured",
			opts: Options{
				ReceiptDir: t.TempDir(),
				HasFeature: allowAgentsFeature,
				AuthorizePermission: func(*http.Request, Permission) error {
					return nil
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "raw callback alone denies",
			opts: Options{
				ReceiptDir:   t.TempDir(),
				HasFeature:   allowAgentsFeature,
				AuthorizeRaw: allowRawAccess,
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "fleet scope callback alone denies",
			opts: Options{
				ReceiptDir: t.TempDir(),
				HasFeature: allowAgentsFeature,
				AuthorizeFleetScope: func(*http.Request, DecisionScope, bool) error {
					return nil
				},
			},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			handler := New(test.opts)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, test.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestHandler_ExemptionsAllowedRendersInventory(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		ResponseScanning: config.ResponseScanning{
			Enabled:       false,
			ExemptDomains: []string{"api.vendor.example"},
		},
	}
	var audit strings.Builder
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		Config:           cfg,
		HasFeature:       allowAgentsFeature,
		Authorize:        func(*http.Request) error { return nil },
		AuditWriter:      &audit,
		AuthorizeRaw:     allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Exemptions inventory", "api.vendor.example", "inert", "not tracked"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("CSP = %q, want %q", got, contentSecurityPolicy)
	}
	if !strings.Contains(audit.String(), "path=\"/exemptions\"") {
		t.Fatalf("audit should record exemptions path; got %q", audit.String())
	}
}

func TestHandler_HostileEvidenceRenderEscapesReceiptFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	r.ActionRecord.Target = hostileScript
	r.ActionRecord.Pattern = hostileImage
	r.ActionRecord.Verdict = hostileScript
	r.ActionRecord.Intent = hostileJSON
	r.ActionRecord.RequestID = hostileJSURL
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys: map[string]TrustedKey{
			keyHex: {Source: trustedKeySource},
		},
		HasFeature: allowAgentsFeature,
		// Grant raw so the signed payload + destination render and their
		// auto-escaping is exercised; escaping must hold in the raw view.
		AuthorizeRaw: allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, hostileScript) {
		t.Fatal("response contains raw script tag")
	}
	if strings.Contains(body, hostileImage) {
		t.Fatal("response contains raw image injection")
	}
	if strings.Contains(body, hostileJSON) {
		t.Fatal("response contains raw script-breaking JSON payload")
	}
	if strings.Contains(body, `href="javascript:`) {
		t.Fatal("response contains javascript URL in href attribute")
	}
	for _, rawAttr := range []string{
		`="` + hostileJSURL + `"`,
		`='` + hostileJSURL + `'`,
		`=` + hostileJSURL,
	} {
		if strings.Contains(body, rawAttr) {
			t.Fatalf("response contains raw javascript URL in attribute context: %q", rawAttr)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("response should contain HTML-escaped script text")
	}
	if !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatal("response should contain HTML-escaped image injection text")
	}
	if !strings.Contains(body, "\\u003c/script\\u003e") {
		t.Fatal("response should contain JSON-escaped closing script token in signed payload")
	}
	escapedRequestID := "&#34;request_id&#34;: &#34;" + hostileJSURL + "&#34;"
	if !strings.Contains(body, escapedRequestID) {
		t.Fatal("javascript URL field should render only as escaped text in the signed payload")
	}
}

func TestHandler_MethodAndPathRejection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		HasFeature:       allowAgentsFeature,
	})

	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "post index", method: http.MethodPost, path: "/", want: http.StatusMethodNotAllowed},
		{name: "post exemptions", method: http.MethodPost, path: "/exemptions", want: http.StatusMethodNotAllowed},
		{name: "nested session path", method: http.MethodGet, path: "/session/foo/bar", want: http.StatusNotFound},
		{name: "nested exemptions path", method: http.MethodGet, path: "/exemptions/extra", want: http.StatusNotFound},
		{name: "unknown path", method: http.MethodGet, path: "/nope", want: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("%s %s status = %d, want %d; body=%s", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestHandler_RouteSpecsDeclarePermissions(t *testing.T) {
	t.Parallel()

	seen := map[string]struct{}{}
	for _, spec := range dashboardRouteSpecs() {
		if spec.pattern == "" {
			t.Fatal("dashboard route spec has empty pattern")
		}
		if spec.feature == "" {
			t.Fatalf("dashboard route %q has empty feature", spec.pattern)
		}
		if spec.forbiddenMessage == "" {
			t.Fatalf("dashboard route %q has empty forbidden message", spec.pattern)
		}
		if spec.permission == "" {
			t.Fatalf("dashboard route %q has empty permission", spec.pattern)
		}
		if spec.handler == nil {
			t.Fatalf("dashboard route %q has nil handler", spec.pattern)
		}
		if _, ok := seen[spec.pattern]; ok {
			t.Fatalf("dashboard route %q is registered twice", spec.pattern)
		}
		seen[spec.pattern] = struct{}{}
	}
}

func TestHandler_RoutePermissionFailsClosed(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowAllDashboardFeatures,
		Authorize:        func(*http.Request) error { return nil },
		AuthorizeRaw:     allowRawAccess,
		AuthorizePermission: func(*http.Request, Permission) error {
			return errors.New("permission denied")
		},
	})

	for _, path := range []string{
		"/",
		"/exemptions",
		"/session/" + testSessionID,
		"/session/" + testSessionID + "/receipt/0",
		"/agents",
		"/agent/agent-one",
		"/budgets",
		"/trust-keys",
		"/fleet",
		"/workbench",
		"/incident",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s status = %d, want %d; body=%s", path, rec.Code, http.StatusForbidden, rec.Body.String())
			}
		})
	}
}

func TestHandler_RoutePermissionUsesSpecificPermission(t *testing.T) {
	t.Parallel()

	var got []Permission
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowAllDashboardFeatures,
		Authorize:        func(*http.Request) error { return nil },
		AuthorizePermission: func(_ *http.Request, permission Permission) error {
			got = append(got, permission)
			return nil
		},
	})

	tests := []struct {
		path string
		want Permission
	}{
		{path: "/", want: PermissionEvidenceRead},
		{path: "/exemptions", want: PermissionExemptionsRead},
		{path: "/session/" + testSessionID, want: PermissionEvidenceRead},
		{path: "/agents", want: PermissionAgentsRead},
		{path: "/budgets", want: PermissionBudgetsRead},
		{path: "/trust-keys", want: PermissionTrustKeysRead},
		{path: "/fleet", want: PermissionFleetRead},
		{path: "/workbench", want: PermissionSignedActionRead},
		{path: "/incident", want: PermissionIncidentRead},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			handler.ServeHTTP(rec, req)
			if len(got) == 0 || got[len(got)-1] != tc.want {
				t.Fatalf("%s permission = %v, want last permission %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestHandler_RawViewShownWhenRawPermissionGranted(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          dir,
		TrustedKeys:         trusted,
		HasFeature:          allowAgentsFeature,
		Authorize:           func(*http.Request) error { return nil },
		AuthorizeRaw:        allowRawAccess,
		AuthorizePermission: func(*http.Request, Permission) error { return nil },
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, testTarget) {
		t.Fatalf("raw view should show the destination %q when %s is granted", testTarget, PermissionRawRead)
	}
	if strings.Contains(body, redactedDestination) {
		t.Fatal("raw view should not show the redaction placeholder when raw permission is granted")
	}
}

func TestHandler_AllPermissionsCoversRouteSpecs(t *testing.T) {
	t.Parallel()

	all := map[Permission]struct{}{}
	for _, permission := range AllPermissions() {
		if permission == "" {
			t.Fatal("AllPermissions returned an empty permission")
		}
		if _, ok := all[permission]; ok {
			t.Fatalf("AllPermissions returned duplicate permission %q", permission)
		}
		all[permission] = struct{}{}
	}
	if _, ok := all[PermissionRawRead]; !ok {
		t.Fatalf("AllPermissions must include %s", PermissionRawRead)
	}
	for _, spec := range dashboardRouteSpecs() {
		if _, ok := all[spec.permission]; !ok {
			t.Fatalf("route %q permission %q missing from AllPermissions", spec.pattern, spec.permission)
		}
	}
}

func TestHandler_RawViewRequiresRawPermission(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
		Authorize:        func(*http.Request) error { return nil },
		AuthorizeRaw:     allowRawAccess,
		AuthorizePermission: func(_ *http.Request, permission Permission) error {
			if permission == PermissionRawRead {
				return errors.New("raw denied")
			}
			return nil
		},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, testTarget) {
		t.Fatalf("raw destination leaked without %s", PermissionRawRead)
	}
	if !strings.Contains(body, redactedDestination) {
		t.Fatal("metadata view should show the redaction placeholder when raw permission is denied")
	}
}

func TestHandler_ReadLimitWarning(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 4))

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		ReceiptReadLimit: 2,
		TimelineLimit:    1,
		TrustedKeys: map[string]TrustedKey{
			keyHex: {Source: trustedKeySource},
		},
		HasFeature: allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Dashboard read limit reached",
		"2+ receipts",
		"Showing first 1 of 2+ loaded receipts.",
		"Partial",
		"Prefix only",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestHandler_AbsenceRender(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeZeroReceiptSessionFile(t, dir, zeroSessionID)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+zeroSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{"No receipts", "NO independent evidence", "ABSENT"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestHandler_AuthorizeFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	// A rejecting authorizer must fail closed even when the feature is present.
	denied := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		HasFeature:       allowAgentsFeature,
		Authorize:        func(*http.Request) error { return errors.New("no principal") },
	})
	rec := httptest.NewRecorder()
	denied.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rejecting Authorize status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), "Scorecard") {
		t.Fatal("forbidden response must not contain evidence body")
	}

	// An accepting authorizer reaches the handler.
	allowed := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		HasFeature:       allowAgentsFeature,
		Authorize:        func(*http.Request) error { return nil },
	})
	rec = httptest.NewRecorder()
	allowed.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("accepting Authorize status = %d, want %d", rec.Code, http.StatusOK)
	}

	rec = httptest.NewRecorder()
	denied.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rejecting Authorize /exemptions status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func allowAgentsFeature(feature string) bool {
	return feature == license.FeatureAgents
}

func allowAllDashboardFeatures(feature string) bool {
	return feature == license.FeatureAgents || feature == license.FeatureFleet
}

// allowRawAccess is an AuthorizeRaw that grants every request the raw view.
func allowRawAccess(*http.Request) error { return nil }

func TestHandler_RedactsRawByDefault(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	// No AuthorizeRaw configured => raw is redacted for everyone (fail closed).
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, testTarget) {
		t.Errorf("metadata view leaked the raw destination %q", testTarget)
	}
	if !strings.Contains(body, redactedDestination) {
		t.Errorf("metadata view should show the redaction placeholder")
	}
	if strings.Contains(body, `"action_id"`) || strings.Contains(body, "Signed JSON payload") {
		t.Errorf("metadata view leaked the raw signed payload")
	}
	if !strings.Contains(body, "Metadata view") {
		t.Errorf("metadata view should show the redaction banner")
	}
	// The scorecard (the actual proof) must still render without the raw fields.
	if !strings.Contains(body, "Scorecard") {
		t.Errorf("scorecard must render in the metadata view")
	}
}

func TestRedactRawRemovesTemplateReceiptPayload(t *testing.T) {
	t.Parallel()
	_, priv := generateDashboardKey(t)
	rec := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	ev := sessionEvidence(testSessionID, []receipt.Receipt{rec}, nil, false, dashboardReceiptReadLimit, dashboardTimelineLimit)

	redacted := redactRaw(ev)
	if redacted.ReceiptCount != 1 {
		t.Fatalf("ReceiptCount = %d, want 1", redacted.ReceiptCount)
	}
	if redacted.Receipts != nil {
		t.Fatalf("metadata view must not carry raw receipts into template data")
	}
	if redacted.Timeline[0].Destination != redactedDestination {
		t.Fatalf("Destination = %q, want redacted placeholder", redacted.Timeline[0].Destination)
	}
	if redacted.Timeline[0].RawJSON != "" {
		t.Fatalf("RawJSON should be stripped, got %q", redacted.Timeline[0].RawJSON)
	}
}

func TestHandler_RawAccessShowsDetail(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
		AuthorizeRaw:     allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, testTarget) {
		t.Errorf("raw view should show the destination %q", testTarget)
	}
	if !strings.Contains(body, "Signed JSON payload") {
		t.Errorf("raw view should show the signed payload")
	}
	if strings.Contains(body, redactedDestination) {
		t.Errorf("raw view should not show the redaction placeholder")
	}
	if strings.Contains(body, "Metadata view") {
		t.Errorf("raw view should not show the metadata redaction banner")
	}
}

func TestHandler_RawAccessDecisionIsCachedPerRequest(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	var calls int
	var audit strings.Builder
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
		AuthorizeRaw: func(*http.Request) error {
			calls++
			if calls == 1 {
				return nil
			}
			return errors.New("raw authorizer called more than once")
		},
		AuditWriter: &audit,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("AuthorizeRaw calls = %d, want 1", calls)
	}
	if !strings.Contains(rec.Body.String(), "Signed JSON payload") {
		t.Fatalf("cached raw decision should drive render; body=%s", rec.Body.String())
	}
	if !strings.Contains(audit.String(), "role=raw") {
		t.Fatalf("cached raw decision should drive audit role; audit=%q", audit.String())
	}
}

func TestHandler_AuditWriterRecordsAccess(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	t.Run("metadata_role_and_path_session", func(t *testing.T) {
		var meta strings.Builder
		metaHandler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir, TrustedKeys: trusted, HasFeature: allowAgentsFeature,
			AuditWriter: &meta,
		})
		metaHandler.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
		if !strings.Contains(meta.String(), "role=metadata") {
			t.Errorf("audit log should record metadata role; got %q", meta.String())
		}
		if !strings.Contains(meta.String(), "session=\""+testSessionID+"\"") {
			t.Errorf("audit log should record the session; got %q", meta.String())
		}
		if !strings.Contains(meta.String(), "session_sha256=") {
			t.Errorf("audit log should record the session hash; got %q", meta.String())
		}
	})

	t.Run("query_param_session", func(t *testing.T) {
		var q strings.Builder
		qHandler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir, TrustedKeys: trusted, HasFeature: allowAgentsFeature,
			AuditWriter: &q,
		})
		qHandler.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?session="+testSessionID, nil))
		if !strings.Contains(q.String(), "session=\""+testSessionID+"\"") {
			t.Errorf("audit log should record the query-param session; got %q", q.String())
		}
	})

	t.Run("empty_session", func(t *testing.T) {
		var none strings.Builder
		noneHandler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir, TrustedKeys: trusted, HasFeature: allowAgentsFeature,
			AuditWriter: &none,
		})
		noneHandler.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/", nil))
		if !strings.Contains(none.String(), "session=\"-\"") {
			t.Errorf("audit log should record '-' for an empty session; got %q", none.String())
		}
	})

	t.Run("raw_role", func(t *testing.T) {
		var raw strings.Builder
		rawHandler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir, TrustedKeys: trusted, HasFeature: allowAgentsFeature,
			AuthorizeRaw: allowRawAccess, AuditWriter: &raw,
		})
		rawHandler.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
		if !strings.Contains(raw.String(), "role=raw") {
			t.Errorf("audit log should record raw role; got %q", raw.String())
		}
	})
}

func TestAuditSessionFieldNormalizesAndBoundsDisplay(t *testing.T) {
	t.Parallel()
	weird := "session\n\u202ereversed" + strings.Repeat("a", auditSessionMaxBytes+20)

	display, hash := auditSessionField(weird)
	if len(display) > auditSessionMaxBytes {
		t.Fatalf("display length = %d, want <= %d", len(display), auditSessionMaxBytes)
	}
	if strings.ContainsAny(display, "\n\r\t") || strings.Contains(display, "\u202e") {
		t.Fatalf("display should not carry control or confusing Unicode: %q", display)
	}
	if !strings.HasSuffix(display, "...") {
		t.Fatalf("long display should be visibly truncated: %q", display)
	}
	if len(hash) != 64 {
		t.Fatalf("hash length = %d, want 64", len(hash))
	}

	display, hash = auditSessionField("")
	if display != "-" {
		t.Fatalf("empty display = %q, want '-'", display)
	}
	if len(hash) != 64 {
		t.Fatalf("empty hash length = %d, want 64", len(hash))
	}
}

func TestHandler_AuditWriterSerializesConcurrentRequests(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	var audit strings.Builder
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
		AuditWriter:      &audit,
		AuthorizeRaw:     allowRawAccess,
	})

	const requests = 25
	var wg sync.WaitGroup
	wg.Add(requests)
	for i := 0; i < requests; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec,
				httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
		}()
	}
	wg.Wait()

	if got := strings.Count(audit.String(), "pipelock-dashboard access"); got != requests {
		t.Fatalf("audit lines = %d, want %d; log=%q", got, requests, audit.String())
	}
}

func TestHandler_AuditNotWrittenForUnauthorized(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	var buf strings.Builder
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir, TrustedKeys: trusted, HasFeature: allowAgentsFeature,
		Authorize:   func(*http.Request) error { return errors.New("denied") },
		AuditWriter: &buf,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if buf.Len() != 0 {
		t.Errorf("denied request must not be audited as access; got %q", buf.String())
	}
}

func TestHandler_AuditWrittenForPermissionDenied(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	var buf strings.Builder
	handler := New(Options{
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
		AuthorizePermission: func(*http.Request, Permission) error {
			return errors.New("permission denied")
		},
		AuditWriter: &buf,
	})
	ctx := WithAuthAuditInfo(context.Background(), AuthAuditInfo{
		Method:  "mtls",
		Subject: "spki-sha256",
		Roles:   []string{"metadata"},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	log := buf.String()
	for _, want := range []string{
		"pipelock-dashboard denied",
		"permission=\"dashboard:evidence:read\"",
		"auth_method=mtls",
		"auth_subject=\"spki-sha256\"",
		"auth_roles=\"metadata\"",
		"reason=permission_denied",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("permission-denied audit missing %q: %s", want, log)
		}
	}
	if strings.Contains(log, "pipelock-dashboard access") {
		t.Fatalf("permission-denied request must not be audited as access: %s", log)
	}
}

func TestHandler_AuditWrittenForPermissionDeniedWithoutAuthInfo(t *testing.T) {
	t.Parallel()
	dir, trusted := writeTrustedHandlerSession(t)

	var buf strings.Builder
	handler := New(Options{
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
		AuthorizePermission: func(*http.Request, Permission) error {
			return errors.New("permission denied")
		},
		AuditWriter: &buf,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	log := buf.String()
	for _, want := range []string{
		"pipelock-dashboard denied",
		"auth_method=-",
		"auth_subject=\"-\"",
		"auth_roles=\"-\"",
		"reason=permission_denied",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("permission-denied audit missing %q: %s", want, log)
		}
	}
	if strings.Contains(log, "pipelock-dashboard access") {
		t.Fatalf("permission-denied request must not be audited as access: %s", log)
	}
}

func signAlteredReceipt(r receipt.Receipt, priv ed25519.PrivateKey) (receipt.Receipt, error) {
	return receipt.Sign(r.ActionRecord, priv)
}

func writeTrustedHandlerSession(t *testing.T) (string, map[string]TrustedKey) {
	t.Helper()
	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 2))
	return dir, map[string]TrustedKey{
		keyHex: {Source: trustedKeySource},
	}
}
