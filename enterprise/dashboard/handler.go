//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
	contentTypeHTML       = "text/html; charset=utf-8"
	contentTypeSVG        = "image/svg+xml; charset=utf-8"
	contentTypeText       = "text/plain; charset=utf-8"
	auditSessionMaxBytes  = 128
)

const (
	dashboardFaviconSVGBase64 = `PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgNDgwIiBmaWxsPSJub25lIj4KICA8ZGVmcz4KICAgIDxsaW5lYXJHcmFkaWVudCBpZD0ic2hhY2tsZS1ncmFkIiB4MT0iMjAwIiB5MT0iNDAiIHgyPSIyMDAiIHkyPSIxODAiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KICAgICAgPHN0b3Agb2Zmc2V0PSIwJSIgc3RvcC1jb2xvcj0iIzAwZmZjOCIvPgogICAgICA8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0b3AtY29sb3I9IiMwMGI4OTQiLz4KICAgIDwvbGluZWFyR3JhZGllbnQ+CiAgICA8bGluZWFyR3JhZGllbnQgaWQ9ImJvZHktZ3JhZCIgeDE9IjIwMCIgeTE9IjE2MCIgeDI9IjIwMCIgeTI9IjM0MCIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgogICAgICA8c3RvcCBvZmZzZXQ9IjAlIiBzdG9wLWNvbG9yPSIjMWExYTJlIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMTAwJSIgc3RvcC1jb2xvcj0iIzBmMGYxYSIvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICAgIDxmaWx0ZXIgaWQ9Imdsb3ciPgogICAgICA8ZmVHYXVzc2lhbkJsdXIgc3RkRGV2aWF0aW9uPSI2IiByZXN1bHQ9ImJsdXIiLz4KICAgICAgPGZlTWVyZ2U+CiAgICAgICAgPGZlTWVyZ2VOb2RlIGluPSJibHVyIi8+CiAgICAgICAgPGZlTWVyZ2VOb2RlIGluPSJTb3VyY2VHcmFwaGljIi8+CiAgICAgIDwvZmVNZXJnZT4KICAgIDwvZmlsdGVyPgogICAgPGZpbHRlciBpZD0iZ2xvdy10ZXh0Ij4KICAgICAgPGZlR2F1c3NpYW5CbHVyIHN0ZERldmlhdGlvbj0iMyIgcmVzdWx0PSJibHVyIi8+CiAgICAgIDxmZU1lcmdlPgogICAgICAgIDxmZU1lcmdlTm9kZSBpbj0iYmx1ciIvPgogICAgICAgIDxmZU1lcmdlTm9kZSBpbj0iU291cmNlR3JhcGhpYyIvPgogICAgICA8L2ZlTWVyZ2U+CiAgICA8L2ZpbHRlcj4KICA8L2RlZnM+CgogIDwhLS0gU2hhY2tsZSAocGlwZS1zdHlsZSkgLS0+CiAgPHBhdGggZD0iTTEzMCAxODAgTDEzMCAxMTAgQzEzMCA2NSAxNjAgNDAgMjAwIDQwIEMyNDAgNDAgMjcwIDY1IDI3MCAxMTAgTDI3MCAxODAiCiAgICAgICAgc3Ryb2tlPSJ1cmwoI3NoYWNrbGUtZ3JhZCkiIHN0cm9rZS13aWR0aD0iMjgiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgZmlsbD0ibm9uZSIgZmlsdGVyPSJ1cmwoI2dsb3cpIi8+CgogIDwhLS0gUGlwZSBqb2ludHMgb24gc2hhY2tsZSBlbmRzIC0tPgogIDxyZWN0IHg9IjExNCIgeT0iMTY1IiB3aWR0aD0iMzIiIGhlaWdodD0iMTYiIHJ4PSIzIiBmaWxsPSIjMDBmZmM4IiBvcGFjaXR5PSIwLjciLz4KICA8cmVjdCB4PSIyNTQiIHk9IjE2NSIgd2lkdGg9IjMyIiBoZWlnaHQ9IjE2IiByeD0iMyIgZmlsbD0iIzAwZmZjOCIgb3BhY2l0eT0iMC43Ii8+CgogIDwhLS0gTG9jayBib2R5IC0tPgogIDxyZWN0IHg9IjkwIiB5PSIxODAiIHdpZHRoPSIyMjAiIGhlaWdodD0iMTYwIiByeD0iMTYiIGZpbGw9InVybCgjYm9keS1ncmFkKSIKICAgICAgICBzdHJva2U9IiMwMGZmYzgiIHN0cm9rZS13aWR0aD0iMi41IiBmaWx0ZXI9InVybCgjZ2xvdykiLz4KCiAgPCEtLSBCb2R5IGlubmVyIGJvcmRlciBhY2NlbnQgLS0+CiAgPHJlY3QgeD0iMTAwIiB5PSIxOTAiIHdpZHRoPSIyMDAiIGhlaWdodD0iMTQwIiByeD0iMTAiIGZpbGw9Im5vbmUiCiAgICAgICAgc3Ryb2tlPSIjMDBmZmM4IiBzdHJva2Utd2lkdGg9IjAuNSIgb3BhY2l0eT0iMC4yIi8+CgogIDwhLS0gS2V5aG9sZSAtLT4KICA8Y2lyY2xlIGN4PSIyMDAiIGN5PSIyNDgiIHI9IjE4IiBmaWxsPSIjMDBmZmM4IiBvcGFjaXR5PSIwLjkiIGZpbHRlcj0idXJsKCNnbG93KSIvPgogIDxjaXJjbGUgY3g9IjIwMCIgY3k9IjI0OCIgcj0iMTAiIGZpbGw9IiMwZjBmMWEiLz4KICA8cmVjdCB4PSIxOTYiIHk9IjI1NiIgd2lkdGg9IjgiIGhlaWdodD0iMjQiIHJ4PSIzIiBmaWxsPSIjMDBmZmM4IiBvcGFjaXR5PSIwLjkiLz4KICA8cmVjdCB4PSIxOTYiIHk9IjI1NiIgd2lkdGg9IjgiIGhlaWdodD0iMjQiIHJ4PSIzIiBmaWxsPSIjMGYwZjFhIiBvcGFjaXR5PSIwLjQiLz4KCiAgPCEtLSBQaXBlIHRocmVhZCBsaW5lcyBvbiBib2R5IHNpZGVzIC0tPgogIDxsaW5lIHgxPSI5NSIgeTE9IjIxMCIgeDI9Ijk1IiB5Mj0iMjE1IiBzdHJva2U9IiMwMGZmYzgiIHN0cm9rZS13aWR0aD0iMSIgb3BhY2l0eT0iMC4zIi8+CiAgPGxpbmUgeDE9Ijk1IiB5MT0iMjIyIiB4Mj0iOTUiIHkyPSIyMjciIHN0cm9rZT0iIzAwZmZjOCIgc3Ryb2tlLXdpZHRoPSIxIiBvcGFjaXR5PSIwLjMiLz4KICA8bGluZSB4MT0iOTUiIHkxPSIyMzQiIHgyPSI5NSIgeTI9IjIzOSIgc3Ryb2tlPSIjMDBmZmM4IiBzdHJva2Utd2lkdGg9IjEiIG9wYWNpdHk9IjAuMyIvPgogIDxsaW5lIHgxPSIzMDUiIHkxPSIyMTAiIHgyPSIzMDUiIHkyPSIyMTUiIHN0cm9rZT0iIzAwZmZjOCIgc3Ryb2tlLXdpZHRoPSIxIiBvcGFjaXR5PSIwLjMiLz4KICA8bGluZSB4MT0iMzA1IiB5MT0iMjIyIiB4Mj0iMzA1IiB5Mj0iMjI3IiBzdHJva2U9IiMwMGZmYzgiIHN0cm9rZS13aWR0aD0iMSIgb3BhY2l0eT0iMC4zIi8+CiAgPGxpbmUgeDE9IjMwNSIgeTE9IjIzNCIgeDI9IjMwNSIgeTI9IjIzOSIgc3Ryb2tlPSIjMDBmZmM4IiBzdHJva2Utd2lkdGg9IjEiIG9wYWNpdHk9IjAuMyIvPgoKICA8IS0tICJQSVBFTE9DSyIgdGV4dCAtLT4KICA8dGV4dCB4PSIyMDAiIHk9IjQyMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1mYW1pbHk9IidKZXRCcmFpbnMgTW9ubycsICdGaXJhIENvZGUnLCAnQ291cmllciBOZXcnLCBtb25vc3BhY2UiCiAgICAgICAgZm9udC1zaXplPSI1MiIgZm9udC13ZWlnaHQ9IjcwMCIgbGV0dGVyLXNwYWNpbmc9IjYiIGZpbGw9IiMwMGZmYzgiIGZpbHRlcj0idXJsKCNnbG93LXRleHQpIj5QSVBFTE9DSzwvdGV4dD4KCiAgPCEtLSBTdWJ0bGUgdGFnbGluZSAtLT4KICA8dGV4dCB4PSIyMDAiIHk9IjQ1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1mYW1pbHk9IidJbnRlcicsICdIZWx2ZXRpY2EgTmV1ZScsIHNhbnMtc2VyaWYiCiAgICAgICAgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjQiIGZpbGw9IiM5NGEzYjgiIHRleHQtdHJhbnNmb3JtPSJ1cHBlcmNhc2UiPkFHRU5UIEZJUkVXQUxMPC90ZXh0Pgo8L3N2Zz4K`
	dashboardFaviconDataURL   = "data:image/svg+xml;base64," + dashboardFaviconSVGBase64
)

var dashboardFaviconSVG = mustDecodeDashboardFavicon()

//go:embed nav.tmpl.html overview.tmpl.html evidence.tmpl.html exemptions.tmpl.html agents.tmpl.html investigator.tmpl.html fleetoverview.tmpl.html workbench.tmpl.html incident.tmpl.html budgets.tmpl.html trustkeys.tmpl.html
var templateFS embed.FS

var (
	overviewTemplate      = parseDashboardTemplate("overview.tmpl.html")
	evidenceTemplate      = parseDashboardTemplate("evidence.tmpl.html")
	exemptionsTemplate    = parseDashboardTemplate("exemptions.tmpl.html")
	agentsTemplate        = parseDashboardTemplate("agents.tmpl.html")
	investigatorTemplate  = parseDashboardTemplate("investigator.tmpl.html")
	fleetoverviewTemplate = parseDashboardTemplate("fleetoverview.tmpl.html")
	workbenchTemplate     = parseDashboardTemplate("workbench.tmpl.html")
	incidentTemplate      = parseDashboardTemplate("incident.tmpl.html")
	budgetsTemplate       = parseDashboardTemplate("budgets.tmpl.html")
	trustKeysTemplate     = parseDashboardTemplate("trustkeys.tmpl.html")
)

func parseDashboardTemplate(name string) *template.Template {
	return template.Must(template.New(name).ParseFS(templateFS, name, "nav.tmpl.html"))
}

func mustDecodeDashboardFavicon() []byte {
	data, err := base64.StdEncoding.DecodeString(dashboardFaviconSVGBase64)
	if err != nil {
		panic(fmt.Sprintf("decode dashboard favicon: %v", err))
	}
	return data
}

type pageData struct {
	Nav             NavContext
	Sessions        []SessionSummary
	SelectedSession string
	Evidence        SessionEvidence
	HasEvidence     bool
	RawAllowed      bool
	Operability     OperabilityHealth
}

type exemptionsPageData struct {
	Nav       NavContext
	Inventory ExemptionInventory
}

// NavContext is the shared, authorization-filtered dashboard navigation state.
type NavContext struct {
	Active      string
	ActiveLabel string
	Entries     []NavEntry
	ScriptNonce string
}

// NavEntry is one top-level dashboard link the current request is allowed to
// follow.
type NavEntry struct {
	Key    string
	Label  string
	Path   string
	Active bool
}

// Permission is the bounded dashboard route/action vocabulary consumed by the
// RBAC seam. Keep these stable: external auth adapters map identities to these
// strings, while handlers stay unaware of user/role storage.
type Permission string

const (
	PermissionEvidenceRead     Permission = "dashboard:evidence:read"
	PermissionRawRead          Permission = "dashboard:raw:read"
	PermissionExemptionsRead   Permission = "dashboard:exemptions:read"
	PermissionAgentsRead       Permission = "dashboard:agents:read"
	PermissionBudgetsRead      Permission = "dashboard:budgets:read"
	PermissionFleetRead        Permission = "dashboard:fleet:read"
	PermissionSignedActionRead Permission = "dashboard:signed_action:read"
	PermissionIncidentRead     Permission = "dashboard:incident:read"
	PermissionTrustKeysRead    Permission = "dashboard:trust_keys:read"
)

const (
	agentsFeatureForbidden = "Pipelock Enterprise agents feature required\n"
	fleetFeatureForbidden  = "Pipelock Enterprise fleet feature required\n"
)

type routeSpec struct {
	pattern          string
	feature          string
	forbiddenMessage string
	permission       Permission
	handler          func(*dashboardHandler) http.Handler
}

type navRouteSpec struct {
	key     string
	label   string
	pattern string
}

var dashboardNavRouteSpecs = []navRouteSpec{
	{key: "overview", label: "Overview", pattern: "/overview"},
	{key: "evidence", label: "Evidence", pattern: "/"},
	{key: "exemptions", label: "Exemptions", pattern: "/exemptions"},
	{key: "agents", label: "Agents", pattern: "/agents"},
	{key: "budgets", label: "Budgets", pattern: "/budgets"},
	{key: "trust-keys", label: "Trust & Keys", pattern: "/trust-keys"},
	{key: "fleet", label: "Fleet", pattern: "/fleet"},
	{key: "workbench", label: "Workbench", pattern: "/workbench"},
	{key: "incident", label: "Incident", pattern: "/incident"},
}

var (
	dashboardRouteSpecList = []routeSpec{
		{
			pattern:          "/overview",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionEvidenceRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleOverview)
			},
		},
		{
			pattern:          "/",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionEvidenceRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleIndex)
			},
		},
		{
			pattern:          "/exemptions",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionExemptionsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleExemptions)
			},
		},
		{
			pattern:          "/session/",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionEvidenceRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleSession)
			},
		},
		{
			pattern:          "/agents",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionAgentsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleAgents)
			},
		},
		{
			pattern:          "/agent/",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionAgentsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleAgent)
			},
		},
		{
			pattern:          "/budgets",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionBudgetsRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleBudgets)
			},
		},
		{
			pattern:          "/trust-keys",
			feature:          license.FeatureAgents,
			forbiddenMessage: agentsFeatureForbidden,
			permission:       PermissionTrustKeysRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleTrustKeys)
			},
		},
		{
			pattern:          "/fleet",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionFleetRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleFleetOverview)
			},
		},
		{
			pattern:          "/fleet/",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionFleetRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleFleetOverview)
			},
		},
		{
			pattern:          "/workbench",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionSignedActionRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleWorkbench)
			},
		},
		{
			pattern:          "/workbench/",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionSignedActionRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleWorkbench)
			},
		},
		{
			pattern:          "/incident",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionIncidentRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleIncident)
			},
		},
		{
			pattern:          "/incident/",
			feature:          license.FeatureFleet,
			forbiddenMessage: fleetFeatureForbidden,
			permission:       PermissionIncidentRead,
			handler: func(d *dashboardHandler) http.Handler {
				return http.HandlerFunc(d.handleIncident)
			},
		},
	}
	dashboardRouteSpecsByPattern = routeSpecsByPattern(dashboardRouteSpecList)
)

func routeSpecsByPattern(specs []routeSpec) map[string]routeSpec {
	out := make(map[string]routeSpec, len(specs))
	for _, spec := range specs {
		out[spec.pattern] = spec
	}
	return out
}

func dashboardRouteSpecs() []routeSpec {
	return dashboardRouteSpecList
}

// AllPermissions returns the complete bounded permission vocabulary: every
// permission referenced by a dashboard route plus the raw-view elevation.
// Derived from the route specs so it cannot drift from what handlers actually
// require; auth adapters use it to prove their mapping covers every permission
// (an unmapped permission fails closed and disables its route).
func AllPermissions() []Permission {
	seen := map[Permission]struct{}{PermissionRawRead: {}}
	all := []Permission{PermissionRawRead}
	for _, spec := range dashboardRouteSpecList {
		if _, ok := seen[spec.permission]; ok {
			continue
		}
		seen[spec.permission] = struct{}{}
		all = append(all, spec.permission)
	}
	return all
}

// New returns a read-only HTTP handler for the Enterprise Evidence dashboard.
//
// SECURITY: this handler serves sensitive evidence (signed receipt payloads,
// destinations, block reasons, signer fingerprints, session IDs). The
// license-feature check is NOT authentication. Mount this handler ONLY on an
// authenticated, admin-only listener, and never on the agent-reachable proxy
// port. Set Options.Authorize to enforce an authenticated principal per
// request; it fails closed when it returns an error. When both Authorize and
// AuthorizePermission are nil, set Options.TrustedOuterAuth only if the
// surrounding router provides the authentication boundary.
func New(opts Options) http.Handler {
	model := NewReadModel(opts)
	mux := http.NewServeMux()
	d := &dashboardHandler{
		model:               model,
		hasFeature:          opts.HasFeature,
		authorize:           opts.Authorize,
		authorizePermission: opts.AuthorizePermission,
		authorizeRaw:        opts.AuthorizeRaw,
		authorizeFleetScope: opts.AuthorizeFleetScope,
		trustedOuterAuth:    opts.TrustedOuterAuth,
		auditWriter:         opts.AuditWriter,
		defaultFleetScope:   normalizeDecisionScope(opts.DefaultFleetScope),
	}
	mux.HandleFunc("/favicon.ico", handleFavicon)
	for _, spec := range dashboardRouteSpecList {
		mux.Handle(spec.pattern, d.routeGate(spec, spec.handler(d)))
	}
	return mux
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", contentTypeSVG)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(dashboardFaviconSVG)
}

type dashboardHandler struct {
	model               *ReadModel
	hasFeature          func(string) bool
	authorize           func(*http.Request) error
	authorizePermission func(*http.Request, Permission) error
	authorizeRaw        func(*http.Request) error
	authorizeFleetScope func(*http.Request, DecisionScope, bool) error
	trustedOuterAuth    bool
	auditWriter         io.Writer
	auditMu             sync.Mutex
	// defaultFleetScope is the org/fleet the fleet view falls back to when a
	// request supplies neither org_id nor fleet_id (a plain "Fleet" nav click).
	// Only a fully-empty scope is defaulted; a partial scope stays an error.
	defaultFleetScope DecisionScope
}

type rawAllowedContextKey struct{}

type navContextKey struct{}

type authAuditInfoContextKey struct{}

type routeAuthorizationCache struct {
	identityChecked bool
	identityErr     error
	permissions     map[Permission]error
}

type routeAccessResult struct {
	status           int
	body             string
	permissionDenied bool
}

func (r routeAccessResult) allowed() bool {
	return r.status == 0
}

// AuthAuditInfo is the bounded identity metadata appended to dashboard access
// logs. Callers must pass only sanitized values, never bearer tokens or raw
// claims.
type AuthAuditInfo struct {
	Method        string
	Subject       string
	Roles         []string
	FailureReason string
}

// WithAuthAuditInfo attaches dashboard authentication metadata to a request
// context for access logging.
func WithAuthAuditInfo(ctx context.Context, info AuthAuditInfo) context.Context {
	info.Roles = append([]string(nil), info.Roles...)
	return context.WithValue(ctx, authAuditInfoContextKey{}, info)
}

// rawAllowed reports whether this request may see the raw view (destinations
// and full signed payloads). Fail closed: raw is shown only when an authorizer
// is configured and accepts the request.
func (d *dashboardHandler) rawAllowed(r *http.Request) bool {
	if d.authorizeRaw == nil || d.authorizeRaw(r) != nil {
		return false
	}
	if d.authorizePermission != nil {
		return d.authorizePermission(r, PermissionRawRead) == nil
	}
	return true
}

func rawAllowedFromContext(r *http.Request) bool {
	raw, _ := r.Context().Value(rawAllowedContextKey{}).(bool)
	return raw
}

func navFromContext(r *http.Request) NavContext {
	nav, _ := r.Context().Value(navContextKey{}).(NavContext)
	return nav
}

func authAuditInfoFromRequest(r *http.Request) AuthAuditInfo {
	info, _ := r.Context().Value(authAuditInfoContextKey{}).(AuthAuditInfo)
	info.Method = AuditLogValue(info.Method)
	info.Subject = AuditLogValue(info.Subject)
	if len(info.Roles) == 0 {
		info.Roles = []string{"-"}
	}
	for i, role := range info.Roles {
		info.Roles[i] = AuditLogValue(role)
	}
	info.FailureReason = AuditLogValue(info.FailureReason)
	return info
}

// recordAudit writes one access-log line for an authenticated request. Viewing
// evidence is itself an audited action. No-op when no writer is configured.
func (d *dashboardHandler) recordAudit(r *http.Request, raw bool, permission Permission) {
	if d.auditWriter == nil {
		return
	}
	role := "metadata"
	if raw {
		role = "raw"
	}
	session := sessionFromRequest(r)
	sessionDisplay, sessionHash := auditSessionField(session)
	auth := authAuditInfoFromRequest(r)
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	_, _ = fmt.Fprintf(d.auditWriter, "%s pipelock-dashboard access role=%s permission=%q method=%s path=%q session=%q session_sha256=%s org_sha256=%s fleet_sha256=%s artifact_sha256=%s auth_method=%s auth_subject=%q auth_roles=%q remote=%s\n",
		time.Now().UTC().Format(time.RFC3339), role, permission, r.Method, r.URL.Path, sessionDisplay, sessionHash,
		auditHashField(r.URL.Query().Get("org_id")), auditHashField(r.URL.Query().Get("fleet_id")),
		auditHashField(r.URL.Query().Get("artifact_hash")), auth.Method, auth.Subject, strings.Join(auth.Roles, ","), r.RemoteAddr)
}

func (d *dashboardHandler) recordPermissionDeniedAudit(r *http.Request, permission Permission) {
	if d.auditWriter == nil {
		return
	}
	session := sessionFromRequest(r)
	sessionDisplay, sessionHash := auditSessionField(session)
	auth := authAuditInfoFromRequest(r)
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	_, _ = fmt.Fprintf(d.auditWriter, "%s pipelock-dashboard denied permission=%q method=%s path=%q session=%q session_sha256=%s auth_method=%s auth_subject=%q auth_roles=%q reason=permission_denied remote=%s\n",
		time.Now().UTC().Format(time.RFC3339), permission, r.Method, r.URL.Path,
		sessionDisplay, sessionHash, auth.Method, auth.Subject, strings.Join(auth.Roles, ","), r.RemoteAddr)
}

func sessionFromRequest(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "-"
	}
	if session := r.URL.Query().Get("session"); session != "" {
		return session
	}
	if !strings.HasPrefix(r.URL.Path, "/session/") {
		return "-"
	}
	// Trim to the session ID for the audit field. The investigator path is
	// /session/<id>/receipt/<seq>, so cut at the first "/" to log <id>
	// rather than the full sub-path.
	rest := strings.TrimPrefix(r.URL.Path, "/session/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "-"
	}
	return rest
}

func auditSessionField(session string) (display, hash string) {
	sum := sha256.Sum256([]byte(session))
	hash = hex.EncodeToString(sum[:])

	var b strings.Builder
	truncated := false
	for _, r := range session {
		if b.Len() >= auditSessionMaxBytes {
			truncated = true
			break
		}
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('?')
	}
	display = b.String()
	if truncated && len(display) > 3 {
		display = display[:auditSessionMaxBytes-3] + "..."
	}
	if display == "" {
		display = "-"
	}
	return display, hash
}

func auditHashField(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// AuditLogValue normalizes untrusted values before they are written to dashboard audit logs.
func AuditLogValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('?')
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func (d *dashboardHandler) recordDecisionScopeAudit(r *http.Request, raw bool, scope DecisionScope, page any) {
	if d.auditWriter == nil {
		return
	}
	role := "metadata"
	if raw {
		role = "raw"
	}
	var decisionSource, fleetSource, decisionFound, fleetFound, divergence bool
	conflict := "-"
	switch p := page.(type) {
	case WorkbenchPage:
		decisionSource = p.SourceConfigured
		decisionFound = p.HasReplay
		divergence = p.HasReplay && p.Replay.Divergence
		if p.HasReplay && p.Replay.Conflict != "" {
			conflict = p.Replay.Conflict
		}
	case IncidentPage:
		decisionSource = p.DecisionSourceConfigured
		fleetSource = p.FleetSourceConfigured
		decisionFound = p.HasDecision
		fleetFound = p.HasFleet
		divergence = p.HasDecision && p.Decision.Divergence
		if p.HasDecision && p.Decision.Conflict != "" {
			conflict = p.Decision.Conflict
		}
	}
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	_, _ = fmt.Fprintf(d.auditWriter, "%s pipelock-dashboard scope role=%s method=%s path=%q org_sha256=%s fleet_sha256=%s artifact_sha256=%s decision_source=%t fleet_source=%t decision_found=%t fleet_found=%t divergence=%t conflict=%q remote=%s\n",
		time.Now().UTC().Format(time.RFC3339), role, r.Method, r.URL.Path,
		auditHashField(scope.OrgID), auditHashField(scope.FleetID), auditHashField(scope.ArtifactHash),
		decisionSource, fleetSource, decisionFound, fleetFound, divergence, conflict, r.RemoteAddr)
}

func (d *dashboardHandler) authorizeFleetScopeRequest(w http.ResponseWriter, r *http.Request, scope DecisionScope, sourceConfigured bool, raw bool) bool {
	if !sourceConfigured {
		return true
	}
	if d.authorizeFleetScope == nil {
		http.Error(w, "fleet scope authorization required", http.StatusForbidden)
		return false
	}
	if err := d.authorizeFleetScope(r, normalizeDecisionScope(scope), raw); err != nil {
		http.Error(w, "fleet scope not authorized", http.StatusForbidden)
		return false
	}
	return true
}

func (d *dashboardHandler) routeGate(spec routeSpec, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scriptNonce, err := newDashboardScriptNonce()
		if err != nil {
			http.Error(w, "could not initialize dashboard response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Security-Policy", dashboardContentSecurityPolicy(scriptNonce))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		authCache := &routeAuthorizationCache{}
		access := d.authorizeRoute(r, spec, authCache)
		if !access.allowed() {
			if access.permissionDenied {
				d.recordPermissionDeniedAudit(r, spec.permission)
			}
			w.Header().Set("Content-Type", contentTypeText)
			w.WriteHeader(access.status)
			_, _ = w.Write([]byte(access.body))
			return
		}
		raw := d.rawAllowed(r)
		nav := d.navContext(r, authCache, scriptNonce)
		d.recordAudit(r, raw, spec.permission)
		ctx := context.WithValue(r.Context(), rawAllowedContextKey{}, raw)
		ctx = context.WithValue(ctx, navContextKey{}, nav)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newDashboardScriptNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(nonce[:]), nil
}

func dashboardContentSecurityPolicy(scriptNonce string) string {
	if scriptNonce == "" {
		return contentSecurityPolicy
	}
	return contentSecurityPolicy + "; script-src 'self' 'nonce-" + scriptNonce + "'"
}

func (d *dashboardHandler) authorizeRoute(r *http.Request, spec routeSpec, cache *routeAuthorizationCache) routeAccessResult {
	if !knownPermission(spec.permission) {
		return routeAccessResult{status: http.StatusForbidden, body: "forbidden\n"}
	}
	if d.hasFeature == nil || !d.hasFeature(spec.feature) {
		return routeAccessResult{status: http.StatusForbidden, body: spec.forbiddenMessage}
	}
	if d.authorize == nil && d.authorizePermission == nil && !d.trustedOuterAuth {
		return routeAccessResult{status: http.StatusForbidden, body: "dashboard authentication required\n"}
	}
	if d.authorize != nil {
		if cache != nil && cache.identityChecked {
			if cache.identityErr != nil {
				return routeAccessResult{status: http.StatusForbidden, body: "forbidden\n"}
			}
		} else {
			err := d.authorize(r)
			if cache != nil {
				cache.identityChecked = true
				cache.identityErr = err
			}
			if err != nil {
				return routeAccessResult{status: http.StatusForbidden, body: "forbidden\n"}
			}
		}
	}
	if d.authorizePermission != nil {
		err, ok := error(nil), false
		if cache != nil {
			if cache.permissions == nil {
				cache.permissions = make(map[Permission]error)
			}
			err, ok = cache.permissions[spec.permission]
		}
		if !ok {
			err = d.authorizePermission(r, spec.permission)
			if cache != nil {
				cache.permissions[spec.permission] = err
			}
		}
		if err != nil {
			return routeAccessResult{status: http.StatusForbidden, body: "forbidden\n", permissionDenied: true}
		}
	}
	return routeAccessResult{}
}

func (d *dashboardHandler) navContext(r *http.Request, cache *routeAuthorizationCache, scriptNonce string) NavContext {
	active := activeNavKey(r.URL.Path)
	nav := NavContext{
		Active:      active,
		ActiveLabel: navLabel(active),
		ScriptNonce: scriptNonce,
	}
	for _, navSpec := range dashboardNavRouteSpecs {
		route, ok := dashboardRouteSpecsByPattern[navSpec.pattern]
		if !ok || !d.authorizeRoute(r, route, cache).allowed() {
			continue
		}
		nav.Entries = append(nav.Entries, NavEntry{
			Key:    navSpec.key,
			Label:  navSpec.label,
			Path:   navSpec.pattern,
			Active: navSpec.key == active,
		})
	}
	return nav
}

func activeNavKey(path string) string {
	switch {
	case path == "/overview":
		return "overview"
	case path == "/", strings.HasPrefix(path, "/session/"):
		return "evidence"
	case path == "/exemptions":
		return "exemptions"
	case path == "/agents", strings.HasPrefix(path, "/agent/"):
		return "agents"
	case path == "/budgets":
		return "budgets"
	case path == "/trust-keys":
		return "trust-keys"
	case path == "/fleet", strings.HasPrefix(path, "/fleet/"):
		return "fleet"
	case path == "/workbench", strings.HasPrefix(path, "/workbench/"):
		return "workbench"
	case path == "/incident", strings.HasPrefix(path, "/incident/"):
		return "incident"
	default:
		return ""
	}
}

func navLabel(key string) string {
	for _, spec := range dashboardNavRouteSpecs {
		if spec.key == key {
			return spec.label
		}
	}
	return "Dashboard"
}

func knownPermission(permission Permission) bool {
	for _, known := range AllPermissions() {
		if permission == known {
			return true
		}
	}
	return false
}

func (d *dashboardHandler) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/overview" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	scope := d.model.defaultFleetScope
	if d.hasFeature != nil && d.hasFeature(license.FeatureFleet) &&
		d.model.fleetSource != nil && scope.OrgID != "" && scope.FleetID != "" {
		if !d.authorizeFleetScopeRequest(w, r, scope, true, rawAllowedFromContext(r)) {
			return
		}
	}
	page, err := d.model.Overview(r.Context(), rawAllowedFromContext(r))
	if err != nil {
		http.Error(w, "could not build overview", http.StatusInternalServerError)
		return
	}
	page.Nav = navFromContext(r)
	var buf bytes.Buffer
	if err := overviewTemplate.Execute(&buf, page); err != nil {
		http.Error(w, "could not render overview", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}

	sessions, err := d.model.Sessions()
	if err != nil {
		http.Error(w, "could not read evidence sessions", http.StatusInternalServerError)
		return
	}

	selected := r.URL.Query().Get("session")
	if selected == "" && len(sessions) > 0 {
		selected = sessions[0].ID
	}
	d.render(w, r, sessions, selected, rawAllowedFromContext(r))
}

func (d *dashboardHandler) handleExemptions(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/exemptions" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	inventory := d.model.Exemptions()
	// Exemption scopes/attributes are a map of internal destinations, IP
	// allowlists, addresses, and enforcement exceptions — as sensitive as the
	// evidence view's raw destinations. Fail closed: strip them in Go unless
	// this request is authorized for raw, so raw values never reach a
	// metadata-only response.
	if !rawAllowedFromContext(r) {
		inventory = redactExemptions(inventory)
	}
	data := exemptionsPageData{Nav: navFromContext(r), Inventory: inventory}
	var buf bytes.Buffer
	if err := exemptionsTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render exemptions", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func requireGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

type agentsPageData struct {
	Nav        NavContext
	Groups     []evidenceview.AgentGroup
	Filter     FilterSpec
	RawAllowed bool
}

type investigatorPageData struct {
	Nav         NavContext
	SessionID   string
	Seq         uint64
	Explanation evidenceview.DecisionExplanation
	RawAllowed  bool
}

func (d *dashboardHandler) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/agents" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	filter := d.model.ResolveFilter(r)
	groups, err := d.model.Agents(filter)
	if err != nil {
		http.Error(w, "could not read agent evidence", http.StatusInternalServerError)
		return
	}
	data := agentsPageData{
		Nav:        navFromContext(r),
		Groups:     groups,
		Filter:     filter,
		RawAllowed: rawAllowedFromContext(r),
	}
	var buf bytes.Buffer
	if err := agentsTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render agents view", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleAgent(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/agent/")
	if rest == "" || strings.Contains(rest, "/") {
		http.NotFound(w, r)
		return
	}
	agentID := rest
	filter := d.model.ResolveFilter(r)
	group, found, err := d.model.Agent(agentID, filter)
	if err != nil {
		http.Error(w, "could not read agent evidence", http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	data := agentsPageData{
		Nav:        navFromContext(r),
		Groups:     []evidenceview.AgentGroup{group},
		Filter:     filter,
		RawAllowed: rawAllowedFromContext(r),
	}
	var buf bytes.Buffer
	if err := agentsTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render agent view", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleFleetOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/fleet" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	q := r.URL.Query()
	orgID := q.Get("org_id")
	fleetID := q.Get("fleet_id")
	// A plain "Fleet" nav click carries no scope. When neither is supplied,
	// fall back to the operator-configured default (the conductor org/fleet the
	// dashboard reads) so the view resolves instead of 400ing. A partial scope
	// (only one supplied) is deliberately NOT defaulted; it stays an explicit
	// error so a half-specified request never silently reads a different fleet.
	if orgID == "" && fleetID == "" {
		orgID = d.defaultFleetScope.OrgID
		fleetID = d.defaultFleetScope.FleetID
	}
	if err := validateFleetScope(orgID, fleetID, d.model.fleetSource != nil); err != nil {
		http.Error(w, "invalid fleet scope", http.StatusBadRequest)
		return
	}
	if !d.authorizeFleetScopeRequest(w, r, DecisionScope{OrgID: orgID, FleetID: fleetID}, d.model.fleetSource != nil, rawAllowedFromContext(r)) {
		return
	}
	overview, err := d.model.FleetOverview(r.Context(), orgID, fleetID, rawAllowedFromContext(r))
	if err != nil {
		if errors.Is(err, errInvalidFleetScope) {
			http.Error(w, "invalid fleet scope", http.StatusBadRequest)
			return
		}
		http.Error(w, "could not read fleet overview", http.StatusInternalServerError)
		return
	}
	overview.Nav = navFromContext(r)
	var buf bytes.Buffer
	if err := fleetoverviewTemplate.Execute(&buf, overview); err != nil {
		http.Error(w, "could not render fleet overview", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

type decisionScopePageOptions struct {
	path             string
	tmpl             *template.Template
	buildErr         string
	renderErr        string
	sourceConfigured func(*ReadModel) bool
	build            func(context.Context, DecisionScope, bool) (any, error)
}

func (d *dashboardHandler) serveDecisionScopePage(w http.ResponseWriter, r *http.Request, opts decisionScopePageOptions) {
	if r.URL.Path != opts.path {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	scope := decisionScopeFromRequest(r)
	if err := validateDecisionScope(scope); err != nil {
		http.Error(w, "invalid decision scope", http.StatusBadRequest)
		return
	}
	raw := rawAllowedFromContext(r)
	sourceConfigured := scope.ArtifactHash != "" && opts.sourceConfigured != nil && opts.sourceConfigured(d.model)
	if !d.authorizeFleetScopeRequest(w, r, scope, sourceConfigured, raw) {
		return
	}
	page, err := opts.build(r.Context(), scope, raw)
	if err != nil {
		http.Error(w, opts.buildErr, http.StatusInternalServerError)
		return
	}
	if scope.ArtifactHash != "" {
		d.recordDecisionScopeAudit(r, raw, scope, page)
	}
	page = withNavContext(page, navFromContext(r))
	var buf bytes.Buffer
	if err := opts.tmpl.Execute(&buf, page); err != nil {
		http.Error(w, opts.renderErr, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func withNavContext(page any, nav NavContext) any {
	switch p := page.(type) {
	case WorkbenchPage:
		p.Nav = nav
		return p
	case IncidentPage:
		p.Nav = nav
		return p
	default:
		return page
	}
}

// handleWorkbench serves the read-only Signed Action Workbench. It is GET-only
// and reaches no write path: it renders static prepare guidance and, when a
// conductor decision source is wired and an artifact hash is supplied, the
// read-only replay of that past decision.
func (d *dashboardHandler) handleWorkbench(w http.ResponseWriter, r *http.Request) {
	d.serveDecisionScopePage(w, r, decisionScopePageOptions{
		path:      "/workbench",
		tmpl:      workbenchTemplate,
		buildErr:  "could not build workbench view",
		renderErr: "could not render workbench",
		sourceConfigured: func(m *ReadModel) bool {
			return m.conductorSource != nil
		},
		build: func(ctx context.Context, scope DecisionScope, raw bool) (any, error) {
			return d.model.Workbench(ctx, scope, raw)
		},
	})
}

// handleIncident serves the read-only Incident Cockpit. It is GET-only and
// reaches no write path: it correlates a conductor decision replay with the
// bounded fleet applied-state summary.
func (d *dashboardHandler) handleIncident(w http.ResponseWriter, r *http.Request) {
	d.serveDecisionScopePage(w, r, decisionScopePageOptions{
		path:      "/incident",
		tmpl:      incidentTemplate,
		buildErr:  "could not build incident view",
		renderErr: "could not render incident view",
		sourceConfigured: func(m *ReadModel) bool {
			return m.conductorSource != nil || m.fleetSource != nil
		},
		build: func(ctx context.Context, scope DecisionScope, raw bool) (any, error) {
			return d.model.Incident(ctx, scope, raw)
		},
	})
}

func decisionScopeFromRequest(r *http.Request) DecisionScope {
	q := r.URL.Query()
	return DecisionScope{
		OrgID:        q.Get("org_id"),
		FleetID:      q.Get("fleet_id"),
		ArtifactHash: q.Get("artifact_hash"),
	}
}

func (d *dashboardHandler) handleBudgets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/budgets" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	overview, err := d.model.Budgets(r.Context(), rawAllowedFromContext(r))
	if err != nil {
		http.Error(w, "could not read agent budgets", http.StatusInternalServerError)
		return
	}
	overview.Nav = navFromContext(r)
	var buf bytes.Buffer
	if err := budgetsTemplate.Execute(&buf, overview); err != nil {
		http.Error(w, "could not render budgets", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleTrustKeys(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/trust-keys" {
		http.NotFound(w, r)
		return
	}
	if !requireGet(w, r) {
		return
	}
	page, err := d.model.TrustKeys()
	if err != nil {
		http.Error(w, "could not audit trust and keys", http.StatusInternalServerError)
		return
	}
	page.Nav = navFromContext(r)
	var buf bytes.Buffer
	if err := trustKeysTemplate.Execute(&buf, page); err != nil {
		http.Error(w, "could not render trust and keys", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) handleSession(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/session/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	// Handle /session/<id>/receipt/<seq> — the investigator route.
	if strings.Contains(rest, "/") {
		d.handleSessionReceipt(w, r, rest)
		return
	}
	selected := rest
	sessions, err := d.model.Sessions()
	if err != nil {
		http.Error(w, "could not read evidence sessions", http.StatusInternalServerError)
		return
	}
	d.render(w, r, sessions, selected, rawAllowedFromContext(r))
}

func (d *dashboardHandler) handleSessionReceipt(w http.ResponseWriter, r *http.Request, rest string) {
	// Expected: <sessionID>/receipt/<seq>
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[1] != "receipt" || parts[0] == "" || parts[2] == "" {
		http.NotFound(w, r)
		return
	}
	sessionID := parts[0]
	// Reject path traversal.
	if strings.Contains(sessionID, "..") || strings.Contains(sessionID, "/") {
		http.NotFound(w, r)
		return
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	explanation, found, err := d.model.ReceiptDetail(sessionID, seq)
	if err != nil {
		http.Error(w, "could not read receipt detail", http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	raw := rawAllowedFromContext(r)
	if !raw {
		explanation = evidenceview.RedactExplanation(explanation)
	}
	data := investigatorPageData{
		Nav:         navFromContext(r),
		SessionID:   sessionID,
		Seq:         seq,
		Explanation: explanation,
		RawAllowed:  raw,
	}
	var buf bytes.Buffer
	if err := investigatorTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render investigator view", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}

func (d *dashboardHandler) render(w http.ResponseWriter, r *http.Request, sessions []SessionSummary, selected string, raw bool) {
	data := pageData{
		Nav:             navFromContext(r),
		Sessions:        sessions,
		SelectedSession: selected,
		RawAllowed:      raw,
		Operability:     d.model.OperabilityHealth(),
	}
	if selected != "" {
		evidence, err := d.model.Session(selected)
		if err != nil {
			http.Error(w, "could not read selected evidence", http.StatusInternalServerError)
			return
		}
		// Fail closed: strip destinations and signed payloads in Go before
		// templating unless this request is authorized for raw, so the raw
		// bytes never reach the response.
		if !raw {
			evidence = redactRaw(evidence)
		}
		data.Evidence = evidence
		data.HasEvidence = true
	}

	var buf bytes.Buffer
	if err := evidenceTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "could not render evidence", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeHTML)
	_, _ = w.Write(buf.Bytes())
}
