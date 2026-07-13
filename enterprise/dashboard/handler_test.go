//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/evidence", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Scorecard") {
		t.Fatal("allowed response should render scorecard")
	}
	for _, want := range []string{
		"scrollbar-color:rgba(0,229,160,0.45) transparent",
		"*::-webkit-scrollbar{width:10px;height:10px;}",
		"*::-webkit-scrollbar-thumb{background:rgba(0,229,160,0.35);border-radius:8px;}",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("shared dashboard header missing %q", want)
		}
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, contentSecurityPolicy) || !strings.Contains(got, "script-src 'self' 'nonce-") {
		t.Fatalf("CSP = %q, want dashboard base policy plus script nonce", got)
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

func TestHandler_FaviconServedWithoutDashboardRoute404(t *testing.T) {
	t.Parallel()

	handler := New(Options{})
	t.Run("get", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/favicon.ico", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("favicon status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != contentTypeSVG {
			t.Fatalf("favicon content type = %q, want %q", got, contentTypeSVG)
		}
		for _, want := range []string{`<svg xmlns="http://www.w3.org/2000/svg"`, `viewBox="0 0 64 64"`, `#00ffc8`} {
			if !strings.Contains(rec.Body.String(), want) {
				t.Fatalf("favicon body missing %q: %s", want, rec.Body.String())
			}
		}
	})
	t.Run("head", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/favicon.ico", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("favicon HEAD status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("favicon HEAD body length = %d, want 0", rec.Body.Len())
		}
	})
	t.Run("post", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/favicon.ico", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("favicon POST status = %d, want 405; body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Fatalf("favicon POST Allow = %q, want %q", got, http.MethodGet)
		}
	})
}

func TestHandler_FaviconUsesEmbeddedBrandAsset(t *testing.T) {
	t.Parallel()

	asset, err := os.ReadFile(filepath.Join("..", "..", "assets", "pipelock-favicon.svg"))
	if err != nil {
		t.Fatal(err)
	}
	if string(dashboardFaviconSVG) != string(asset) {
		t.Fatal("embedded dashboard favicon does not match assets/pipelock-favicon.svg")
	}
	if !strings.HasPrefix(dashboardFaviconDataURL, "data:image/svg+xml;base64,") {
		t.Fatalf("favicon data URL = %q", dashboardFaviconDataURL)
	}
	if !strings.Contains(contentSecurityPolicy, "img-src 'self' data:") {
		t.Fatalf("CSP does not allow embedded SVG favicon: %q", contentSecurityPolicy)
	}
}

func TestDashboardTemplatesIncludeEmbeddedBrandFavicon(t *testing.T) {
	t.Parallel()

	entries, err := templateFS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".tmpl.html") || name == "nav.tmpl.html" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			data, err := templateFS.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `{{template "dashboardFavicon" .}}`) {
				t.Fatalf("%s does not include dashboardFavicon", name)
			}
		})
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
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, contentSecurityPolicy) || !strings.Contains(got, "script-src 'self' 'nonce-") {
		t.Fatalf("CSP = %q, want dashboard base policy plus script nonce", got)
	}
	if !strings.Contains(audit.String(), "path=\"/exemptions\"") {
		t.Fatalf("audit should record exemptions path; got %q", audit.String())
	}
}

func TestHandler_EvidenceNoSessionsExplainsReceiptSource(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/evidence", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Evidence proves receipt ordering, signer trust, and per-session decisions",
		"No recorder sessions are loaded",
		"--receipt-dir",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("evidence no-sessions body missing %q: %s", want, body)
		}
	}
}

func TestHandler_RootRendersOverviewNotEvidence(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Operator Overview",
		"Where do I need to look, and what can I prove?",
		"No aggregate score.",
		`class="active" aria-current="page">Overview</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("root overview body missing %q: %s", want, body)
		}
	}
	for _, notWant := range []string{
		"Evidence proves receipt ordering, signer trust, and per-session decisions",
		"Receipt Timeline",
		"Evidence Scorecard",
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("root rendered evidence content %q: %s", notWant, body)
		}
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

func TestHandler_NavSpecsUseTopLevelRouteSpecs(t *testing.T) {
	t.Parallel()

	routes := map[string]routeSpec{}
	for _, spec := range dashboardRouteSpecs() {
		routes[spec.pattern] = spec
	}
	seen := map[string]struct{}{}
	for i, navSpec := range dashboardNavRouteSpecs {
		if i == 0 && navSpec.key != "overview" {
			t.Fatalf("first nav route = %q, want overview", navSpec.key)
		}
		if navSpec.key == "" || navSpec.label == "" || navSpec.pattern == "" {
			t.Fatalf("invalid dashboard nav spec: %+v", navSpec)
		}
		if strings.HasSuffix(navSpec.pattern, "/") && navSpec.pattern != "/" {
			t.Fatalf("nav spec %q points at detail-prefix route %q", navSpec.key, navSpec.pattern)
		}
		route, ok := routes[navSpec.pattern]
		if !ok {
			t.Fatalf("nav spec %q points at unregistered route %q", navSpec.key, navSpec.pattern)
		}
		if route.permission == "" || route.feature == "" {
			t.Fatalf("nav route %q has incomplete gate data: %+v", navSpec.pattern, route)
		}
		if _, ok := seen[navSpec.pattern]; ok {
			t.Fatalf("nav route %q is registered twice", navSpec.pattern)
		}
		seen[navSpec.pattern] = struct{}{}
	}
	if len(seen) != 9 {
		t.Fatalf("nav route count = %d, want 9", len(seen))
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
		"/evidence",
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
		{path: "/evidence", want: PermissionEvidenceRead},
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
			got = nil
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			handler.ServeHTTP(rec, req)
			if len(got) == 0 || got[0] != tc.want {
				t.Fatalf("%s permission = %v, want first permission %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestHandler_SharedNavReachabilityFromRenderedViews(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          dir,
		TrustedKeys:         trusted,
		HasFeature:          allowAllDashboardFeatures,
		AuthorizeFleetScope: allowFleetScope,
	})
	tests := []struct {
		path      string
		activeKey string
	}{
		{path: "/", activeKey: "overview"},
		{path: "/evidence", activeKey: "evidence"},
		{path: "/session/" + testSessionID, activeKey: "evidence"},
		{path: "/session/" + testSessionID + "/receipt/0", activeKey: "evidence"},
		{path: "/exemptions", activeKey: "exemptions"},
		{path: "/agents", activeKey: "agents"},
		{path: "/agent/" + testActor, activeKey: "agents"},
		{path: "/budgets", activeKey: "budgets"},
		{path: "/trust-keys", activeKey: "trust-keys"},
		{path: "/fleet", activeKey: "fleet"},
		{path: "/workbench", activeKey: "workbench"},
		{path: "/incident", activeKey: "incident"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200; body=%s", tc.path, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			assertSharedNavLinksExactly(t, body, dashboardNavRouteSpecs)
			assertActiveNavLink(t, body, tc.activeKey)
		})
	}
}

func TestHandler_SharedHeaderCSSSingleSourcedAcrossRenderedViews(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          dir,
		TrustedKeys:         trusted,
		HasFeature:          allowAllDashboardFeatures,
		AuthorizeFleetScope: allowFleetScope,
	})

	overview := renderDashboardPath(t, handler, "/overview")
	wantStyle := extractDashboardHeaderStyle(t, overview)
	for _, path := range []string{
		"/",
		"/evidence",
		"/session/" + testSessionID,
		"/session/" + testSessionID + "/receipt/0",
		"/exemptions",
		"/agents",
		"/agent/" + testActor,
		"/budgets",
		"/trust-keys",
		"/fleet",
		"/workbench",
		"/incident",
	} {
		if got := extractDashboardHeaderStyle(t, renderDashboardPath(t, handler, path)); got != wantStyle {
			t.Fatalf("shared dashboard header CSS differs between %s and /overview\n--- %s ---\n%s\n--- overview ---\n%s", path, path, got, wantStyle)
		}
	}
	if !strings.Contains(overview, `<div class="brand"><a href="/overview">Pipelock</a>`) {
		t.Fatalf("overview brand wordmark does not link to /overview: %s", overview)
	}
	assertActiveNavLink(t, overview, "overview")
	assertActiveNavLink(t, renderDashboardPath(t, handler, "/"), "overview")
	assertActiveNavLink(t, renderDashboardPath(t, handler, "/evidence"), "evidence")
}

func TestHandler_SharedNavMatchesRouteGateAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		hasFeature func(string) bool
		permission func(Permission) bool
	}{
		{
			name:       "no license",
			hasFeature: func(string) bool { return false },
		},
		{
			name:       "agents only",
			hasFeature: allowAgentsFeature,
		},
		{
			name:       "fleet entitled",
			hasFeature: allowAllDashboardFeatures,
		},
		{
			name:       "fleet feature only",
			hasFeature: func(feature string) bool { return feature == license.FeatureFleet },
		},
	}
	for _, navSpec := range dashboardNavRouteSpecs {
		route := routeSpecForPattern(t, navSpec.pattern)
		permission := route.permission
		tests = append(tests, struct {
			name       string
			hasFeature func(string) bool
			permission func(Permission) bool
		}{
			name:       "permission " + string(permission),
			hasFeature: allowAllDashboardFeatures,
			permission: func(got Permission) bool {
				return got == permission
			},
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &dashboardHandler{
				hasFeature:       tc.hasFeature,
				trustedOuterAuth: tc.permission == nil,
			}
			if tc.permission != nil {
				d.authorizePermission = func(_ *http.Request, permission Permission) error {
					if tc.permission(permission) {
						return nil
					}
					return errors.New("permission denied")
				}
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?ignored=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
			want := expectedNavRouteSpecsForGate(t, d, req)
			got := d.navContext(req, &routeAuthorizationCache{}, "test-nonce")
			assertNavContextMatchesSpecs(t, got, want, "agents")
		})
	}
}

func TestHandler_SharedNavFiltersUnauthorizedRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		handler    http.Handler
		gate       *dashboardHandler
		entryPath  string
		wantStatus int
	}{
		{
			name: "agents-only evidence page",
			handler: New(Options{
				TrustedOuterAuth: true,
				ReceiptDir:       t.TempDir(),
				HasFeature:       allowAgentsFeature,
			}),
			gate: &dashboardHandler{
				hasFeature:       allowAgentsFeature,
				trustedOuterAuth: true,
			},
			entryPath:  "/",
			wantStatus: http.StatusOK,
		},
		{
			name: "fleet-permission denied from evidence page",
			handler: New(Options{
				TrustedOuterAuth:    true,
				ReceiptDir:          t.TempDir(),
				HasFeature:          allowAllDashboardFeatures,
				AuthorizePermission: allowAgentsNavPermissions,
			}),
			gate: &dashboardHandler{
				hasFeature:          allowAllDashboardFeatures,
				authorizePermission: allowAgentsNavPermissions,
			},
			entryPath:  "/",
			wantStatus: http.StatusOK,
		},
		{
			name: "agents-permission denied from fleet page",
			handler: New(Options{
				TrustedOuterAuth:    true,
				ReceiptDir:          t.TempDir(),
				HasFeature:          allowAllDashboardFeatures,
				AuthorizePermission: allowFleetNavPermissions,
				AuthorizeFleetScope: allowFleetScope,
			}),
			gate: &dashboardHandler{
				hasFeature:          allowAllDashboardFeatures,
				authorizePermission: allowFleetNavPermissions,
			},
			entryPath:  "/fleet",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.entryPath, nil)
			tc.handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s status = %d, want %d; body=%s", tc.entryPath, rec.Code, tc.wantStatus, rec.Body.String())
			}
			body := rec.Body.String()

			want := expectedNavRouteSpecsForGate(t, tc.gate, req)
			assertSharedNavLinksExactly(t, body, want)
			for _, spec := range want {
				rec := httptest.NewRecorder()
				tc.handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, spec.pattern, nil))
				if rec.Code != http.StatusOK {
					t.Fatalf("shown nav route %s status = %d, want 200; body=%s", spec.pattern, rec.Code, rec.Body.String())
				}
			}
			for _, spec := range deniedNavRouteSpecs(t, want) {
				rec := httptest.NewRecorder()
				tc.handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, spec.pattern, nil))
				if rec.Code != http.StatusForbidden {
					t.Fatalf("hidden nav route %s status = %d, want 403; body=%s", spec.pattern, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

func TestLicenseTierAccessMatrix(t *testing.T) {
	t.Parallel()
	assertLicenseTierRouteSpecIntent(t)

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	dir, trusted := writeTrustedHandlerSession(t)
	allowEveryPermission := func(*http.Request, Permission) error { return nil }
	newMatrixHandler := func(hasFeature func(string) bool, fleetSource *fakeFleetSource) http.Handler {
		return New(Options{
			TrustedOuterAuth:    true,
			ReceiptDir:          dir,
			TrustedKeys:         trusted,
			HasFeature:          hasFeature,
			FleetSource:         fleetSource,
			DefaultFleetScope:   DecisionScope{OrgID: fleetTestOrgID, FleetID: fleetTestFleetID},
			AuthorizeFleetScope: allowFleetScope,
			AuthorizePermission: allowEveryPermission,
			Now:                 func() time.Time { return now },
		})
	}

	agentsFleetSource := &fakeFleetSource{followers: overviewFleetFollowers(now)}
	enterpriseFleetSource := &fakeFleetSource{followers: overviewFleetFollowers(now)}
	tiers := []struct {
		name       string
		handler    http.Handler
		hasFeature func(string) bool
	}{
		{
			name:       "agentsOnly",
			handler:    newMatrixHandler(allowAgentsFeature, agentsFleetSource),
			hasFeature: allowAgentsFeature,
		},
		{
			name:       "enterprise",
			handler:    newMatrixHandler(allowAllDashboardFeatures, enterpriseFleetSource),
			hasFeature: allowAllDashboardFeatures,
		},
	}

	for _, tier := range tiers {
		t.Run(tier.name+"/routes", func(t *testing.T) {
			for _, spec := range dashboardRouteSpecs() {
				spec := spec
				t.Run(spec.pattern, func(t *testing.T) {
					target := licenseTierMatrixRequestPath(t, spec)
					rec := httptest.NewRecorder()
					req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
					tier.handler.ServeHTTP(rec, req)

					wantAllowed := tier.hasFeature(spec.feature)
					if !wantAllowed {
						if rec.Code != http.StatusForbidden {
							t.Fatalf("%s %s feature %q status = %d, want 403; body=%s", tier.name, target, spec.feature, rec.Code, rec.Body.String())
						}
						return
					}
					if rec.Code == http.StatusForbidden {
						t.Fatalf("%s %s feature %q was license-denied; body=%s", tier.name, target, spec.feature, rec.Body.String())
					}
					if licenseTierMatrixRouteMustRenderOK(spec) && rec.Code != http.StatusOK {
						t.Fatalf("%s %s feature %q status = %d, want 200; body=%s", tier.name, target, spec.feature, rec.Code, rec.Body.String())
					}
				})
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/compliance", nil)
			tier.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s /compliance status = %d, want 404; body=%s", tier.name, rec.Code, rec.Body.String())
			}
		})

		t.Run(tier.name+"/nav", func(t *testing.T) {
			body := renderDashboardPath(t, tier.handler, "/overview")
			wantNav := licenseTierExpectedNavSpecs(t, tier.hasFeature)
			assertSharedNavLinksExactly(t, body, wantNav)
			assertLicenseTierFleetNavVisibility(t, body, tier.hasFeature(license.FeatureFleet))
		})
	}

	agentsOverview := renderDashboardPath(t, tiers[0].handler, "/overview")
	for _, leaked := range []string{"Scope " + fleetTestOrgID, "4 accepted follower rows", "verified applied"} {
		if strings.Contains(agentsOverview, leaked) {
			t.Fatalf("agents-only overview rendered fleet follower data %q: %s", leaked, agentsOverview)
		}
	}
	assertLicenseTierFleetSurfaceLinks(t, agentsOverview, false)
	if agentsFleetSource.gotOrgID != "" || agentsFleetSource.gotFleet != "" || agentsFleetSource.gotLimit != 0 {
		t.Fatalf("agents-only matrix queried fleet source: org=%q fleet=%q limit=%d",
			agentsFleetSource.gotOrgID, agentsFleetSource.gotFleet, agentsFleetSource.gotLimit)
	}

	enterpriseOverview := renderDashboardPath(t, tiers[1].handler, "/overview")
	for _, want := range []string{"Scope redacted / redacted", "4 accepted follower rows", "verified applied"} {
		if !strings.Contains(enterpriseOverview, want) {
			t.Fatalf("enterprise overview missing fleet posture %q: %s", want, enterpriseOverview)
		}
	}
	assertLicenseTierFleetSurfaceLinks(t, enterpriseOverview, true)
}

func TestHandler_SharedNavDoesNotReflectRequestPayloads(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowAllDashboardFeatures,
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, `/agents?agent=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E`, nil)
	req.Header.Set("X-Dashboard-Nav", hostileImage)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, hostile := range []string{hostileScript, hostileImage, hostileJSON} {
		if strings.Contains(body, hostile) {
			t.Fatalf("dashboard nav response reflected hostile input %q without escaping: %s", hostile, body)
		}
	}
	assertActiveNavLink(t, body, "agents")

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, `/agent/%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E`, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("hostile path status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), hostileScript) || strings.Contains(rec.Body.String(), hostileImage) {
		t.Fatalf("not-found path reflected hostile input: %s", rec.Body.String())
	}
	if key := activeNavKey(`/agent/%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E`); key != "agents" {
		t.Fatalf("active key for hostile agents subpath = %q, want agents", key)
	}
	if label := navLabel(activeNavKey(`/"><script>alert(1)</script>`)); label != "Dashboard" {
		t.Fatalf("hostile unknown path label = %q, want Dashboard", label)
	}
}

func TestHandler_AgentsFilterBoundsAgentInput(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowAllDashboardFeatures,
	})
	bounded := strings.Repeat("a", agentFilterMaxRunes)
	oversized := bounded + `"><script>alert(1)</script>`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?agent="+url.QueryEscape(oversized), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="agent" value="`+bounded+`" maxlength="128"`) {
		t.Fatalf("agents filter did not render the bounded value with maxlength: %s", body)
	}
	if strings.Contains(body, html.EscapeString(oversized[len(bounded):])) {
		t.Fatal("agents filter rendered the truncated suffix")
	}
}

func expectedNavRouteSpecsForGate(t *testing.T, d *dashboardHandler, req *http.Request) []navRouteSpec {
	t.Helper()
	var specs []navRouteSpec
	cache := &routeAuthorizationCache{}
	for _, navSpec := range dashboardNavRouteSpecs {
		route := routeSpecForPattern(t, navSpec.pattern)
		if d.authorizeRoute(req, route, cache).allowed() {
			specs = append(specs, navSpec)
		}
	}
	return specs
}

func assertLicenseTierRouteSpecIntent(t *testing.T) {
	t.Helper()
	for _, spec := range dashboardRouteSpecs() {
		switch spec.feature {
		case license.FeatureAgents, license.FeatureFleet:
		default:
			t.Fatalf("dashboard route %q has unsupported license feature %q", spec.pattern, spec.feature)
		}
		if licenseTierFleetSurfacePattern(spec.pattern) && spec.feature != license.FeatureFleet {
			t.Fatalf("fleet surface %q is tagged %q, want %q", spec.pattern, spec.feature, license.FeatureFleet)
		}
	}
	for _, navSpec := range dashboardNavRouteSpecs {
		route := routeSpecForPattern(t, navSpec.pattern)
		if licenseTierFleetSurfacePattern(navSpec.pattern) && route.feature != license.FeatureFleet {
			t.Fatalf("fleet nav route %q is tagged %q, want %q", navSpec.pattern, route.feature, license.FeatureFleet)
		}
	}
}

func licenseTierFleetSurfacePattern(pattern string) bool {
	return pattern == "/fleet" || strings.HasPrefix(pattern, "/fleet/") ||
		pattern == "/workbench" || strings.HasPrefix(pattern, "/workbench/") ||
		pattern == "/incident" || strings.HasPrefix(pattern, "/incident/")
}

func licenseTierMatrixRequestPath(t *testing.T, spec routeSpec) string {
	t.Helper()
	switch spec.pattern {
	case "/session/":
		return "/session/" + testSessionID
	case "/agent/":
		return "/agent/" + testActor
	case "/fleet/", "/workbench/", "/incident/":
		return spec.pattern + "extra"
	default:
		return spec.pattern
	}
}

func licenseTierMatrixRouteMustRenderOK(spec routeSpec) bool {
	switch spec.pattern {
	case "/fleet/", "/workbench/", "/incident/":
		return false
	default:
		return true
	}
}

func licenseTierExpectedNavSpecs(t *testing.T, hasFeature func(string) bool) []navRouteSpec {
	t.Helper()
	var specs []navRouteSpec
	for _, navSpec := range dashboardNavRouteSpecs {
		route := routeSpecForPattern(t, navSpec.pattern)
		if hasFeature(route.feature) {
			specs = append(specs, navSpec)
		}
	}
	return specs
}

func assertLicenseTierFleetNavVisibility(t *testing.T, body string, wantVisible bool) {
	t.Helper()
	nav := extractDashboardNav(t, body)
	for _, navSpec := range dashboardNavRouteSpecs {
		route := routeSpecForPattern(t, navSpec.pattern)
		if route.feature != license.FeatureFleet {
			continue
		}
		has := strings.Contains(nav, fmt.Sprintf(`href="%s"`, navSpec.pattern))
		switch {
		case wantVisible && !has:
			t.Fatalf("enterprise nav missing fleet route %q: %s", navSpec.pattern, body)
		case !wantVisible && has:
			t.Fatalf("agents-only nav rendered fleet route %q: %s", navSpec.pattern, body)
		}
	}
}

func assertLicenseTierFleetSurfaceLinks(t *testing.T, body string, wantVisible bool) {
	t.Helper()
	nav := extractDashboardNav(t, body)
	bodyWithoutNav := strings.Replace(body, nav, "", 1)
	for _, navSpec := range dashboardNavRouteSpecs {
		route := routeSpecForPattern(t, navSpec.pattern)
		if route.feature != license.FeatureFleet {
			continue
		}
		has := strings.Contains(bodyWithoutNav, fmt.Sprintf(`href="%s"`, navSpec.pattern))
		switch {
		case wantVisible && !has && navSpec.pattern == "/workbench":
			t.Fatalf("enterprise overview missing body attention link to %q: %s", navSpec.pattern, body)
		case !wantVisible && has:
			t.Fatalf("agents-only overview rendered body link to fleet route %q: %s", navSpec.pattern, body)
		}
	}
}

func allowAgentsNavPermissions(_ *http.Request, permission Permission) error {
	switch permission {
	case PermissionEvidenceRead, PermissionExemptionsRead, PermissionAgentsRead, PermissionBudgetsRead, PermissionTrustKeysRead:
		return nil
	default:
		return errors.New("permission denied")
	}
}

func allowFleetNavPermissions(_ *http.Request, permission Permission) error {
	switch permission {
	case PermissionFleetRead, PermissionSignedActionRead, PermissionIncidentRead:
		return nil
	default:
		return errors.New("permission denied")
	}
}

func routeSpecForPattern(t *testing.T, pattern string) routeSpec {
	t.Helper()
	for _, spec := range dashboardRouteSpecs() {
		if spec.pattern == pattern {
			return spec
		}
	}
	t.Fatalf("route spec %q not registered", pattern)
	return routeSpec{}
}

func assertNavContextMatchesSpecs(t *testing.T, nav NavContext, specs []navRouteSpec, activeKey string) {
	t.Helper()
	if nav.Active != activeKey {
		t.Fatalf("active nav key = %q, want %q", nav.Active, activeKey)
	}
	if nav.ActiveLabel != navLabel(activeKey) {
		t.Fatalf("active nav label = %q, want %q", nav.ActiveLabel, navLabel(activeKey))
	}
	if len(nav.Entries) != len(specs) {
		t.Fatalf("nav entries = %+v, want specs %+v", nav.Entries, specs)
	}
	for i, spec := range specs {
		entry := nav.Entries[i]
		if entry.Key != spec.key || entry.Label != spec.label || entry.Path != spec.pattern {
			t.Fatalf("nav entry[%d] = %+v, want %+v", i, entry, spec)
		}
		if entry.Active != (spec.key == activeKey) {
			t.Fatalf("nav entry[%d] active = %t, want %t", i, entry.Active, spec.key == activeKey)
		}
	}
}

func deniedNavRouteSpecs(t *testing.T, allowed []navRouteSpec) []navRouteSpec {
	t.Helper()
	allowedByPattern := make(map[string]struct{}, len(allowed))
	for _, spec := range allowed {
		allowedByPattern[spec.pattern] = struct{}{}
	}
	var denied []navRouteSpec
	for _, spec := range dashboardNavRouteSpecs {
		if _, ok := allowedByPattern[spec.pattern]; !ok {
			denied = append(denied, spec)
		}
	}
	return denied
}

func assertSharedNavLinksExactly(t *testing.T, body string, specs []navRouteSpec) {
	t.Helper()
	nav := extractDashboardNav(t, body)
	if !strings.Contains(nav, `aria-label="Dashboard navigation"`) {
		t.Fatalf("response missing shared dashboard nav: %s", body)
	}
	wantByPattern := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		wantByPattern[spec.pattern] = struct{}{}
	}
	for _, spec := range dashboardNavRouteSpecs {
		has := strings.Contains(nav, fmt.Sprintf(`href="%s"`, spec.pattern))
		_, want := wantByPattern[spec.pattern]
		switch {
		case want && !has:
			t.Fatalf("shared nav missing %s link %q: %s", spec.label, spec.pattern, body)
		case !want && has:
			t.Fatalf("shared nav rendered unauthorized %s link %q: %s", spec.label, spec.pattern, body)
		}
	}
}

func renderDashboardPath(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s status = %d, want 200; body=%s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func extractDashboardHeaderStyle(t *testing.T, body string) string {
	t.Helper()
	topbar := strings.Index(body, ".topbar{")
	if topbar < 0 {
		t.Fatalf("response missing shared dashboard header style block: %s", body)
	}
	start := strings.LastIndex(body[:topbar], "<style>")
	if start < 0 {
		t.Fatalf("shared dashboard header style block missing open tag: %s", body)
	}
	rest := body[start:]
	end := strings.Index(rest, "</style>")
	if end < 0 {
		t.Fatalf("shared dashboard header style block missing close tag: %s", body)
	}
	return rest[:end+len("</style>")]
}

func extractDashboardNav(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<nav class="nav" aria-label="Dashboard navigation">`)
	if start < 0 {
		t.Fatalf("response missing shared dashboard nav: %s", body)
	}
	rest := body[start:]
	end := strings.Index(rest, "</nav>")
	if end < 0 {
		t.Fatalf("shared dashboard nav missing close tag: %s", body)
	}
	return rest[:end+len("</nav>")]
}

func assertActiveNavLink(t *testing.T, body, activeKey string) {
	t.Helper()
	for _, spec := range dashboardNavRouteSpecs {
		if spec.key != activeKey {
			continue
		}
		want := fmt.Sprintf(`href="%s" class="active" aria-current="page">%s</a>`, spec.pattern, html.EscapeString(spec.label))
		if !strings.Contains(body, want) {
			t.Fatalf("active nav link = missing %q in body: %s", want, body)
		}
		return
	}
	t.Fatalf("unknown active nav key %q", activeKey)
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
